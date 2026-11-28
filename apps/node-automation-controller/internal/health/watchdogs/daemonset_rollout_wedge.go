// daemonset_rollout_wedge.go — the daemonset-rollout-wedge check:
// detects DaemonSets whose RollingUpdate is pinned short of
// desiredNumberScheduled because the maxUnavailable budget is being
// consumed by pods that can never come Ready on their own.
//
// A DaemonSet roll replaces pods node-by-node within the
// maxUnavailable budget. Two pod shapes silently hold that budget
// hostage:
//
//   - a pod stuck Terminating on a node that went NotReady /
//     disappeared — the kubelet is gone so the graceful delete never
//     completes and the controller cannot retire the old pod;
//   - a pod that is not Ready (ImagePullBackOff, CrashLoopBackOff,
//     CreateContainerError, ...) sitting on a cordoned node — the
//     cordon guarantees no replacement can schedule, so the pod sits
//     unready forever while the roll waits on it.
//
// The wedge signature — RollingUpdate DS with
// updatedNumberScheduled < desiredNumberScheduled AND
// numberUnavailable >= maxUnavailable — must hold continuously for
// >= 30m (FirstSeenLedger) before the check flags it; a normal slow
// roll or a briefly-cordoned node never qualifies.
//
// Each wedged DaemonSet emits
// node_automation_daemonset_rollout_wedged{namespace,daemonset}=1.
// When NODE_AUTOMATION_DAEMONSET_ROLLOUT_HEAL_ENABLED is on (default)
// the check deletes ONE blocking pod per DaemonSet per 30m — a live
// pod through heal.DeletePod, an already-Terminating pod ONLY on a
// vanished/out-of-service-fenced node through heal.ForceDeletePod
// (grace=0; a plain delete on a terminating pod is an apiserver
// no-op). A plain NotReady node is never force-deleted, and a pod
// claiming a PVC or already on the new revision is skipped. The gate is
// HealAllowedClusterWideOnly: the wedge exists because a node is
// cordoned/dead and the classic mutex holds on exactly that signal,
// so only a cluster-wide maintenance hold defers the heal.
package watchdogs

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

const (
	// CheckNameDaemonSetRolloutWedge is the kuberhealthy_check label
	// and the check's registry Name.
	CheckNameDaemonSetRolloutWedge = "daemonset-rollout-wedge"

	// dsWedgeMinAge is the continuous-wedge window — 30m so a normal
	// multi-node roll or a brief cordon never flags.
	dsWedgeMinAge = 30 * time.Minute
	// dsWedgeHealCooldown bounds deletes to one pod per DaemonSet
	// per window.
	dsWedgeHealCooldown = 30 * time.Minute
)

// nodeRolloutState is the per-node census row the wedge check needs:
// exists (in the live node list), notReady (Ready condition != True),
// cordoned (spec.unschedulable or actively cordoned), and node (the
// live object, so the force-delete gate can prove an out-of-service
// fence rather than settling for a plain NotReady condition).
type nodeRolloutState struct {
	exists, notReady, cordoned bool
	node                       *corev1.Node
}

// dsRolloutWedgeCheck detects DaemonSet rollout wedges.
type dsRolloutWedgeCheck struct {
	*probefw.Deps

	// healEnabled gates the pod delete
	// (NODE_AUTOMATION_DAEMONSET_ROLLOUT_HEAL_ENABLED, resolved once
	// at construction); false leaves detect+gauge only.
	healEnabled bool

	// wedgeSeen tracks "<ns>/<ds>" first sightings for the 30m
	// wedge window; pruned each complete sweep.
	wedgeSeen state.FirstSeenLedger
	// wedgeEmitted is the gauge ledger for the emitted series.
	wedgeEmitted state.GaugeLedger[string]
}

// NewDaemonSetRolloutWedgeCheck builds the check.
func NewDaemonSetRolloutWedgeCheck(d *probefw.Deps) probefw.Check {
	return &dsRolloutWedgeCheck{
		Deps:        d,
		healEnabled: envx.Gate("NODE_AUTOMATION_DAEMONSET_ROLLOUT_HEAL_ENABLED", true),
	}
}

var (
	// node_automation_daemonset_rollout_wedged — 1 per DaemonSet
	// whose roll has been pinned >=30m by a budget-consuming pod.
	dsRolloutWedgedGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_daemonset_rollout_wedged",
		Help: "1 while a DaemonSet RollingUpdate has been pinned >=30m short of desired by a terminating-on-dead-node or unready-on-cordoned-node pod — daemonset-rollout-wedge.",
	}, []string{"namespace", "daemonset"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(dsRolloutWedgedGauge)
}

// Run sweeps the DaemonSet census for rollout wedges.
func (p *dsRolloutWedgeCheck) Run(ctx context.Context) probefw.Result {
	p.wedgeEmitted.Begin()
	log := logf.FromContext(ctx)
	now := p.Now()
	var rep probefw.SweepReport

	dsList, err := p.AllDaemonSets(ctx)
	if err != nil {
		rep.InfraErr(err)
		return rep.Verdict("daemonset rollout wedge: ", "; ")
	}
	podList, err := p.AllPods(ctx)
	if err != nil {
		rep.InfraErr(err)
		return rep.Verdict("daemonset rollout wedge: ", "; ")
	}
	nodeList, err := p.AllNodes(ctx)
	if err != nil {
		rep.InfraErr(err)
		return rep.Verdict("daemonset rollout wedge: ", "; ")
	}

	// Node census once: name → (exists, notReady, cordoned).
	nodes := map[string]nodeRolloutState{}
	for i := range nodeList {
		n := &nodeList[i]
		st := nodeRolloutState{exists: true, node: n}
		for _, c := range n.Status.Conditions {
			if c.Type == corev1.NodeReady {
				st.notReady = c.Status != corev1.ConditionTrue
			}
		}
		st.cordoned = n.Spec.Unschedulable || kube.NodeActivelyCordoned(n, now)
		nodes[n.Name] = st
	}

	// Index DS-owned pods once.
	podsByDS := map[string][]*corev1.Pod{}
	for i := range podList {
		pod := &podList[i]
		ref := metav1.GetControllerOf(pod)
		if ref == nil || ref.Kind != "DaemonSet" || ref.Name == "" {
			continue
		}
		key := pod.Namespace + "/" + ref.Name
		podsByDS[key] = append(podsByDS[key], pod)
	}

	seen := map[string]bool{}
	healed := map[string]bool{}
	for i := range dsList {
		ds := &dsList[i]
		if !dsRolloutWedged(ds, now) {
			continue
		}
		key := ds.Namespace + "/" + ds.Name
		first, tracked := p.wedgeSeen.Observe(key, now)
		seen[key] = true
		if !tracked || now.Sub(first) < dsWedgeMinAge {
			continue
		}
		rep.Set(dsRolloutWedgedGauge, 1, key,
			[]string{ds.Namespace, ds.Name})
		rep.Find("daemonset " + key + " rollout wedged")
		if blocker := p.blockingPod(ctx, ds, podsByDS[key], nodes); blocker != nil {
			p.maybeHealPod(ctx, log, now, &rep, ds, blocker, healed)
		}
	}

	p.wedgeSeen.Prune(func(key string) bool { return seen[key] })
	rep.Close(&p.wedgeEmitted, dsRolloutWedgedGauge.DeleteLabelValues)
	return rep.Verdict("daemonset rollout wedge: ", "; ")
}

// dsRolloutWedged reports the budget-pinned signature: a RollingUpdate
// DaemonSet with updated pods still short of desired AND the
// unavailable count at or above the effective maxUnavailable budget.
func dsRolloutWedged(ds *appsv1.DaemonSet, now time.Time) bool {
	if ds.Spec.UpdateStrategy.Type != appsv1.RollingUpdateDaemonSetStrategyType {
		return false
	}
	if ds.Status.UpdatedNumberScheduled >= ds.Status.DesiredNumberScheduled {
		return false
	}
	maxUnavail := int32(1) // DaemonSet default when unset
	if ru := ds.Spec.UpdateStrategy.RollingUpdate; ru != nil &&
		ru.MaxUnavailable != nil {
		v, err := intstr.GetScaledValueFromIntOrPercent(
			ru.MaxUnavailable, int(ds.Status.DesiredNumberScheduled), true)
		if err == nil {
			maxUnavail = int32(v)
		}
	}
	if maxUnavail <= 0 {
		maxUnavail = 1
	}
	return ds.Status.NumberUnavailable >= maxUnavail
}

// newRevisionHashes returns the controller-revision-hash values that
// belong to the DaemonSet's TARGET revision. The target is derived from
// object metadata ONLY — never inferred from PodReadyCond — so an old
// pod that happens to be Ready can never poison the set into disabling
// healing, and an unready new pod (ImagePullBackOff) can never be
// misclassified as old and deleted.
//
// The bool says whether the target revision is KNOWN. An empty but
// known set means "no pod can be proven to be on the new revision"
// (roll not started, UpdatedNumberScheduled == 0) — every candidate
// is old. An UNKNOWN set means the sources were unavailable: the
// caller must fail closed, because treating "no hashes" as "all old"
// would force-delete a brand-new pod whose revision we simply could
// not read.
func (p *dsRolloutWedgeCheck) newRevisionHashes(ctx context.Context,
	ds *appsv1.DaemonSet, pods []*corev1.Pod) (map[string]bool, bool) {

	hashes := map[string]bool{}
	// No pod of the new template is scheduled yet — every pod in the
	// census belongs to the old revision. Do NOT look at Ready here:
	// the classic wedge is old pods all Ready pinning the budget.
	if ds.Status.UpdatedNumberScheduled == 0 {
		return hashes, true
	}
	// Primary source: the DaemonSet controller stamps every pod with
	// pod-template-generation = ds.Generation when it creates it from
	// the current template. Only trust it once the DS status has
	// observed that generation (otherwise Generation may have advanced
	// past what the running pods reflect).
	if ds.Status.ObservedGeneration == ds.Generation {
		gen := strconv.FormatInt(ds.Generation, 10)
		for _, pod := range pods {
			if pod.Labels["pod-template-generation"] != gen {
				continue
			}
			if h := pod.Labels["controller-revision-hash"]; h != "" {
				hashes[h] = true
			}
		}
	}
	if len(hashes) > 0 {
		return hashes, true
	}
	// Fallback: ControllerRevision objects owned by this DS. The one
	// with the largest .Revision is the target the controller is
	// rolling toward, and its controller-revision-hash label (falling
	// back to Name with the "<ds.Name>-" prefix stripped) is what the
	// controller stamps into pods' controller-revision-hash. Listing
	// needs an RBAC grant some installs do not give us — on denial
	// (or no matching CR) the target is UNKNOWN, so the caller must
	// skip the heal rather than risk deleting a pod on the new
	// revision.
	crs, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: probefw.HealthListPageSize, ResourceVersion: "0"},
		func(ctx context.Context, opts metav1.ListOptions) ([]appsv1.ControllerRevision, string, error) {
			l, lerr := p.CS.AppsV1().ControllerRevisions(ds.Namespace).List(ctx, opts)
			if lerr != nil {
				return nil, "", lerr
			}
			return l.Items, l.Continue, nil
		})
	if err != nil {
		return nil, false
	}
	var target *appsv1.ControllerRevision
	for i := range crs {
		cr := &crs[i]
		ref := metav1.GetControllerOf(cr)
		if ref == nil || ref.Kind != "DaemonSet" || ref.Name != ds.Name {
			continue
		}
		if target == nil || cr.Revision > target.Revision {
			target = cr
		}
	}
	if target == nil || target.Name == "" {
		return nil, false
	}
	h := target.Labels["controller-revision-hash"]
	if h == "" {
		h = strings.TrimPrefix(target.Name, ds.Name+"-")
	}
	if h == "" {
		return nil, false
	}
	hashes[h] = true
	return hashes, true
}

// blockingPod picks the single pod holding the maxUnavailable budget:
// prefers a Terminating pod on a vanished/fenced node (the kubelet can
// never finish the delete), then an unready error-state pod on a
// cordoned node (no replacement can ever schedule). Returns nil when
// no owned pod matches — the wedge is then a scheduler/quota problem
// the heal must not touch.
//
// The force-delete preconditions live HERE, not in maybeHealPod: a
// plain NotReady node is NOT a fence (its kubelet may come back),
// a PVC-claiming pod must never lose its API object at grace=0, and
// a pod already on the new revision cannot advance the roll when
// recreated. Only a blocker that passes all three is handed to the
// heal path.
func (p *dsRolloutWedgeCheck) blockingPod(ctx context.Context, ds *appsv1.DaemonSet,
	pods []*corev1.Pod, nodes map[string]nodeRolloutState) *corev1.Pod {

	sorted := slices.Clone(pods)
	slices.SortFunc(sorted, func(a, b *corev1.Pod) int {
		if c := strings.Compare(a.Namespace, b.Namespace); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
	// The target revision comes from metadata, NOT from which pods are
	// Ready: an old-but-Ready pod must not disable healing, and an
	// unready new pod must not be deleted as if it were an old blocker.
	newHashes, revisionKnown := p.newRevisionHashes(ctx, ds, sorted)
	if !revisionKnown {
		// Without a proven target revision there is no safe pod to
		// delete: "no hashes" is NOT the same as "all pods are old"
		// once a roll has actually started.
		logf.FromContext(ctx).V(1).Info(
			"skip daemonset wedge heal: target revision unresolvable",
			"daemonset", ds.Namespace+"/"+ds.Name,
			"updated", ds.Status.UpdatedNumberScheduled)
		return nil
	}
	oldRevision := func(pod *corev1.Pod) bool {
		h := pod.Labels["controller-revision-hash"]
		return h != "" && !newHashes[h]
	}
	noPVC := func(pod *corev1.Pod) bool {
		return len(kube.PodClaimedPVCs(pod)) == 0
	}

	var cordonedErr *corev1.Pod
	for _, pod := range sorted {
		if pod.DeletionTimestamp != nil {
			// An unscheduled pod has no node to be dead or fenced on.
			// Without this guard nodes[""] reads as "node vanished" and
			// an unbound Terminating pod gets force-deleted at grace=0.
			if pod.Spec.NodeName == "" {
				continue
			}
			st := nodes[pod.Spec.NodeName]
			// ABSOLUTE gate: only a vanished node or an explicit
			// out-of-service fence authorizes force-delete. A plain
			// NotReady node must NEVER be force-deleted.
			if (!st.exists || kube.NodeHasOutOfServiceTaint(st.node)) &&
				noPVC(pod) && oldRevision(pod) {
				return pod // terminating on a dead/fenced node — top priority
			}
			continue
		}
		if kube.PodReadyCond(pod) || !podInWedgeState(pod) ||
			!noPVC(pod) || !oldRevision(pod) {
			continue
		}
		st, ok := nodes[pod.Spec.NodeName]
		if !ok {
			continue
		}
		if st.cordoned && cordonedErr == nil {
			cordonedErr = pod
		}
	}
	return cordonedErr
}

// dsWedgeTargetKey is the per-target circuit key for a DaemonSet wedge
// heal: (namespace, daemonset, node) — NOT the pod name, which the DS
// controller regenerates on every recreate (resetting the circuit each
// cycle). All three segments are DNS-1123 labels/subdomains, so the key
// is also a legal prefix for the circuit-open Event name built in
// shared/healwire.go; a "ns/pod" key produced an invalid Event name.
func dsWedgeTargetKey(ds *appsv1.DaemonSet, pod *corev1.Pod) string {
	return ds.Namespace + "." + ds.Name + "." + pod.Spec.NodeName
}

// maybeHealPod deletes the blocking pod — one per DaemonSet per
// cooldown window through the shared cluster-wide-only heal gate:
// the wedge exists BECAUSE a node is cordoned/dead, so the classic
// mutex (which holds on any active cordon) would deadlock the heal
// for the whole cordon window; only a cluster-wide hold defers.
func (p *dsRolloutWedgeCheck) maybeHealPod(ctx context.Context,
	log logr.Logger, now time.Time, rep *probefw.SweepReport,
	ds *appsv1.DaemonSet, pod *corev1.Pod,
	healed map[string]bool) {

	if !p.healEnabled {
		return
	}
	dsKey := ds.Namespace + "/" + ds.Name
	if healed[dsKey] {
		return
	}
	healKey := probefw.SelfHealKey(CheckNameDaemonSetRolloutWedge, dsKey)
	proceed, unverifiable := p.HealAllowedClusterWideOnly(ctx, log, &p.Heals,
		healKey, dsWedgeHealCooldown, now)
	switch {
	case unverifiable:
		metrics.IncError(p.Name)
		return
	case !proceed:
		return
	}
	// Per-target non-convergent circuit breaker: a node that keeps
	// wedging the same DS roll after repeated deletes is a deeper
	// failure — re-deleting every sweep is churn. The PVC/old-revision
	// and dead-node proof were already applied by blockingPod; here
	// the grant buys the mutation, so refund it on a circuit denial.
	targetKey := dsWedgeTargetKey(ds, pod)
	if allowed, reason := heal.TryAcquireTarget(
		CheckNameDaemonSetRolloutWedge, targetKey, now); !allowed {
		heal.RefundGrant(now)
		log.Info("DEFER: heal target circuit open — daemonset wedge pod delete skipped",
			"daemonset", dsKey, "pod", targetKey, "reason", reason)
		return
	}
	var deleted bool
	var err error
	if pod.DeletionTimestamp != nil {
		// Already Terminating on a vanished/fenced node — a plain
		// delete is an apiserver no-op, so the force path (grace=0)
		// is required. blockingPod proved no PVC and no live kubelet.
		deleted, err = heal.ForceDeletePod(ctx, p.CS, &p.Heals, healKey, pod, now)
	} else {
		deleted, err = heal.DeletePod(ctx, p.CS, &p.Heals, healKey, pod, now)
	}
	if err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "daemonset wedge pod delete failed",
			"daemonset", dsKey, "pod", pod.Namespace+"/"+pod.Name)
		return
	}
	if !deleted {
		// Clean deferral (L1 hold, quorum reservation, 404/409, PVC
		// guard) — no mutation executed; hand the grant back once.
		heal.RefundGrant(now)
		return
	}
	healed[dsKey] = true
	rep.Find("healed: deleted wedging pod " + pod.Namespace + "/" +
		pod.Name + " on " + dsKey)
	log.Info("ACTION: deleted wedging DaemonSet pod to unstick rollout",
		"daemonset", dsKey, "pod", pod.Namespace+"/"+pod.Name)
}
