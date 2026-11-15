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
// pod through heal.DeletePod, an already-Terminating pod on a dead
// node through heal.ForceDeletePod (grace=0; a plain delete on a
// terminating pod is an apiserver no-op). The gate is
// HealAllowedClusterWideOnly: the wedge exists because a node is
// cordoned/dead and the classic mutex holds on exactly that signal,
// so only a cluster-wide maintenance hold defers the heal.
package watchdogs

import (
	"context"
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
// cordoned (spec.unschedulable or actively cordoned).
type nodeRolloutState struct {
	exists, notReady, cordoned bool
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
		st := nodeRolloutState{exists: true}
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
		if blocker := p.blockingPod(ds, podsByDS[key], nodes); blocker != nil {
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
	return ds.Status.NumberUnavailable >= maxUnavail
}

// blockingPod picks the single pod holding the maxUnavailable budget:
// prefers a Terminating pod on a dead/NotReady node (the kubelet can
// never finish the delete), then an unready error-state pod on a
// cordoned node (no replacement can ever schedule). Returns nil when
// no owned pod matches — the wedge is then a scheduler/quota problem
// the heal must not touch.
func (p *dsRolloutWedgeCheck) blockingPod(ds *appsv1.DaemonSet,
	pods []*corev1.Pod, nodes map[string]nodeRolloutState) *corev1.Pod {

	var cordonedErr *corev1.Pod
	for _, pod := range pods {
		if pod.DeletionTimestamp != nil {
			st, ok := nodes[pod.Spec.NodeName]
			if !ok || st.notReady {
				return pod // terminating on a dead node — top priority
			}
			continue
		}
		if kube.PodReadyCond(pod) || !podInWedgeState(pod) {
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
	proceed, unverifiable := p.HealAllowedClusterWideOnly(ctx, log, &p.Heals,
		dsKey, dsWedgeHealCooldown, now)
	switch {
	case unverifiable:
		metrics.IncError(p.Name)
		return
	case !proceed:
		return
	}
	var deleted bool
	var err error
	if pod.DeletionTimestamp != nil {
		// Already Terminating on a dead/unreachable node — a plain
		// delete is an apiserver no-op, so the force path (grace=0,
		// PVC-guarded inside heal.ForceDeletePod) is required.
		if len(kube.PodClaimedPVCs(pod)) > 0 {
			log.Info("daemonset wedge: force-delete refused — pod claims PVC",
				"daemonset", dsKey, "pod", pod.Namespace+"/"+pod.Name)
			heal.RefundGrant(now)
			return
		}
		deleted, err = heal.ForceDeletePod(ctx, p.CS, &p.Heals, dsKey, pod, now)
	} else {
		deleted, err = heal.DeletePod(ctx, p.CS, &p.Heals, dsKey, pod, now)
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
