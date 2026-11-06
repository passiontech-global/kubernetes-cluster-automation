// statefulset-ondelete-roller — C2, the opt-in sequential Pod
// updater for StatefulSets that deliberately use
// spec.updateStrategy.type=OnDelete.
//
// OnDelete exists so stateful workloads (databases, clustered
// middleware) only restart one member at a time under operator
// control — but it also means `k0s`/Flux template changes land and
// then sit forever: status.updateRevision diverges from
// status.currentRevision and NOTHING reconciles it until someone
// deletes a pod by hand. Clusters have carried stale STS revisions
// for weeks this way.
//
// Opt-in only: the module only touches StatefulSets annotated
// passiontech.dev/auto-roll-ondelete="true" — an unannotated OnDelete set is
// a deliberate manual-roll policy, not a forgotten one.
//
// Per 10m sweep, for each opted-in StatefulSet:
//
//   - Track when status.updateRevision != status.currentRevision
//     began in an in-memory ledger; act only after >= 30m of
//     CONTINUOUS drift (a flux apply that reverts itself, a
//     mid-rollout status flap, or an operator restart all re-arm
//     the window — the conservative side is intentional).
//   - Safety gates, ALL required before any delete:
//     1. every Node Ready=True and none spec.unschedulable;
//     2. every PodDisruptionBudget in the namespace matching the
//     candidate pod's labels has status.disruptionsAllowed >= 1
//     (eviction would refuse the disruption anyway — a 0 means
//     the workload is already mid-maintenance or misconfigured,
//     so hands off);
//     3. every Pod the StatefulSet owns is Ready=True and the
//     newest pod has been Ready continuously for >= 5m (a fresh
//     replacement that just came up must settle before the next
//     member goes down).
//   - Then delete exactly ONE pod: the highest ordinal still
//     carrying the OLD controller-revision-hash — ordinal order
//     mirrors StatefulSet's own update order (highest first) and
//     one-at-a-time keeps the disruption inside any sane PDB.
//
// Deleting increments
// node_automation_statefulset_ondelete_pods_rolled_total{namespace,
// statefulset}.
package statefulsetroller

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

const (
	stsOnDeleteRollerInterval = 10 * time.Minute
	// stsAutoRollAnno is the opt-in switch — only annotated
	// StatefulSets are ever rolled.
	stsAutoRollAnno = kube.AnnoAutoRollOnDelete
	// stsOnDeleteDriftMin: updateRevision must differ from
	// currentRevision continuously for this long before the roller
	// acts — a self-correcting apply or a slow-but-working rollout
	// never triggers a pod delete.
	stsOnDeleteDriftMin = 30 * time.Minute
	// stsOnDeleteStableMin: the newest pod must have held
	// Ready=True this long before the next member may go down —
	// the post-replacement settle window.
	stsOnDeleteStableMin = 5 * time.Minute
	// stsRevisionHashLabel is the pod label the StatefulSet
	// controller stamps with the owning ControllerRevision.
	stsRevisionHashLabel = "controller-revision-hash"
)

type statefulSetOnDeleteRoller struct {
	cs kubernetes.Interface
	// dyn feeds the maintenance mutex's autopilot-Plan signal —
	// live-pod evictions defer while a k0s upgrade is in flight.
	dyn dynamic.Interface
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the periodic's name and every IncError label
	// come from one place.
	queue string
	// now is the clock seam — tests pin it so the 30m drift and
	// 5m stability windows are deterministic. nil → time.Now.
	now shared.Clock
	// verdict memoizes the maintenance-mutex evaluation so a sweep
	// of several due StatefulSets pays one set of API reads instead
	// of three per target.
	verdict kube.Verdict
	// driftSince records when each "ns/name" StatefulSet's
	// updateRevision != currentRevision drift was FIRST observed —
	// any cycle where the revisions agree, the set leaves, or the
	// opt-in annotation drops prunes the entry, restarting the 30m
	// window (same first-seen convention as pdb-deadlock-watchdog).
	driftSince state.FirstSeenLedger
}

// Setup registers the 10-minute sweep.
// Disabled clusters (STATEFULSET_ONDELETE_ROLLER_ENABLED=false —
// resolved by setupModules into Deps.Disabled) skip registration
// entirely — same contract as cert-drift-auditor.
func Setup(d shared.Deps) error {
	return shared.SetupNoConfig(d, func() error {
		r := &statefulSetOnDeleteRoller{cs: d.CS, dyn: d.Dyn, queue: d.Name, now: shared.SystemClock}
		return shared.AddPeriodic(d.Mgr, r.queue, stsOnDeleteRollerInterval, r.run)
	})
}

func (r *statefulSetOnDeleteRoller) run(ctx context.Context) error {
	log := logf.FromContext(ctx)

	// Page the cluster-wide list — an unbounded List forces etcd to
	// serialize every StatefulSet into one response; 500-per-page
	// keeps each request cheap at fleet scale.
	stsItems, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.StatefulSets(r.cs, metav1.NamespaceAll))
	if err != nil {
		return fmt.Errorf("list statefulsets: %w", err)
	}

	now := r.now.Now()
	// drifting collects the "ns/name" keys whose revision drift held
	// THIS cycle — the prune pass below treats anything else in
	// driftSince as settled, gone, or de-opted.
	drifting := map[string]bool{}
	type candidate struct {
		idx int
		key string
	}
	var due []candidate
	for i := range stsItems {
		sts := &stsItems[i]
		key := sts.Namespace + "/" + sts.Name
		if sts.Spec.UpdateStrategy.Type != "OnDelete" ||
			!stsAutoRollOptedIn(sts) ||
			sts.Status.UpdateRevision == "" ||
			sts.Status.UpdateRevision == sts.Status.CurrentRevision {
			continue // not opted in, not OnDelete, or no drift
		}
		drifting[key] = true
		first, tracked := r.driftSince.Observe(key, now)
		if !tracked {
			// First sighting — the ledger just opened the
			// continuity window; the roller waits out the full
			// 30m before acting.
			continue
		}
		if now.Sub(first) >= stsOnDeleteDriftMin {
			due = append(due, candidate{idx: i, key: key})
		}
	}
	r.driftSince.Prune(func(k string) bool { return drifting[k] })
	if len(due) == 0 {
		log.Info("sweep done — no opted-in StatefulSet past the drift window")
		return nil
	}

	// Gate 1 is cluster-wide — evaluate once for every due
	// StatefulSet (a cluster failing it skips them all anyway).
	nodes, err := kube.ListNodes(ctx, r.cs)
	if err != nil {
		return fmt.Errorf("list nodes (safety gate): %w", err)
	}
	nodesSafe := len(nodes) > 0
	for i := range nodes {
		if !kube.NodeReady(&nodes[i]) ||
			kube.NodeActivelyCordoned(&nodes[i], now) {
			nodesSafe = false
			break
		}
	}
	if !nodesSafe {
		log.Info("cluster not safe for pod deletes — deferring all OnDelete rolls",
			"due", len(due))
		return nil
	}

	rolled := 0
	for _, d := range due {
		sts := &stsItems[d.idx]
		if err := r.rollOne(ctx, sts, now, log); err != nil {
			// Per-STS failures must not starve the rest — tolerated
			// sub-operation failure, counted here so the nil return
			// still leaves a trace.
			log.Error(err, "ondelete roll failed", "statefulset", d.key)
			metrics.IncError(r.queue)
			continue
		}
		rolled++
	}
	log.Info("sweep done", "due", len(due), "rolled", rolled)
	return nil
}

// rollOne applies gates 2+3 to one StatefulSet and deletes exactly
// one stale pod when they hold. A gate failure is a skip, not an
// error — only API/validation failures return one.
func (r *statefulSetOnDeleteRoller) rollOne(ctx context.Context,
	sts *appsv1.StatefulSet, now time.Time, log logr.Logger) error {

	pods, err := r.ownedPods(ctx, sts)
	if err != nil {
		return err
	}
	if len(pods) == 0 {
		return nil // nothing to roll
	}

	// Membership gate (BUG-C3): the full desired set must be present
	// AND Ready before the next eviction — ownedPods already drops
	// terminating pods, so a pod still Terminating or not yet
	// recreated makes len(pods) < spec.replicas and blocks the roll
	// (evicting mid-replacement would take two members down at once).
	if sts.Spec.Replicas == nil ||
		len(pods) != int(*sts.Spec.Replicas) ||
		sts.Status.ReadyReplicas != *sts.Spec.Replicas {
		log.Info("skip: statefulset membership incomplete — previous pod still Terminating or not yet recreated",
			"statefulset", sts.Namespace+"/"+sts.Name,
			"pods", len(pods),
			"specReplicas", ptr.Deref(sts.Spec.Replicas, -1),
			"readyReplicas", sts.Status.ReadyReplicas)
		return nil
	}

	// Gate 3: every owned pod Ready, the newest one stable >= 5m —
	// the settle window that keeps a slow-Ready replacement from
	// collapsing the set one delete after another.
	newest := pods[0]
	for _, p := range pods {
		if !podReadySince(p, now, 0) {
			log.Info("skip: owned pod not Ready",
				"statefulset", sts.Namespace+"/"+sts.Name,
				"pod", p.Name)
			return nil
		}
		if p.CreationTimestamp.After(newest.CreationTimestamp.Time) {
			newest = p
		}
	}
	if !podReadySince(newest, now, stsOnDeleteStableMin) {
		log.Info("skip: newest pod not yet stable",
			"statefulset", sts.Namespace+"/"+sts.Name,
			"pod", newest.Name,
			"stableFor", stsOnDeleteStableMin)
		return nil
	}

	// Find the highest-ordinal pod still on the OLD revision — the
	// StatefulSet controller's own update order runs ordinals from
	// highest down to 0.
	var candidate *corev1.Pod
	candidateOrd := -1
	for _, p := range pods {
		if p.Labels[stsRevisionHashLabel] == sts.Status.UpdateRevision {
			continue // already on the new revision
		}
		ord, ok := podOrdinal(sts.Name, p.Name)
		if !ok {
			continue
		}
		if ord > candidateOrd {
			candidate, candidateOrd = p, ord
		}
	}
	if candidate == nil {
		return nil // every pod already on the new revision — status lags
	}

	// Gate 2: every PDB in the namespace selecting this pod must
	// allow a disruption — a 0 means the workload is already at its
	// floor and eviction would refuse the delete anyway. Paged like
	// the StatefulSet list above.
	pdbItems, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.PodDisruptionBudgets(r.cs, sts.Namespace))
	if err != nil {
		return fmt.Errorf("list poddisruptionbudgets in %s (safety gate): %w",
			sts.Namespace, err)
	}
	for i := range pdbItems {
		pdb := &pdbItems[i]
		sel, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
		if err != nil {
			log.Info("WARN: PDB selector unparseable — treating as matching (fail closed)",
				"pdb", pdb.Namespace+"/"+pdb.Name, "error", err)
			sel = labels.Everything()
		}
		if !sel.Matches(labels.Set(candidate.Labels)) {
			continue
		}
		if pdb.Status.DisruptionsAllowed < 1 {
			log.Info("skip: matching PDB allows no disruption",
				"statefulset", sts.Namespace+"/"+sts.Name,
				"pdb", pdb.Name,
				"disruptionsAllowed", pdb.Status.DisruptionsAllowed)
			return nil
		}
	}

	// Maintenance mutex — the cluster-wide cordon/kured/autopilot
	// signal gate 1 does not cover (a static-cordon-tolerant Ready
	// check vs. the fail-closed maintenance signals): a drain or k0s
	// upgrade in flight must not race a live-pod eviction.
	// heal.AllowedV runs with a nil heals ledger — this module's
	// pacing is the 30m drift window, not a CooldownSet — and shares
	// r.verdict so the sweep pays one mutex evaluation.
	proceed, unverifiable := heal.AllowedV(ctx, log, &r.verdict,
		r.cs, r.dyn, nil, sts.Namespace+"/"+sts.Name, 0, now)
	if unverifiable {
		// The check itself failed — a defer, not a returned run
		// error, so count it here (same shape as every other
		// unverifiable-mutex skip: fail closed, never evict blind).
		metrics.IncError(r.queue)
		return nil
	}
	if !proceed {
		return nil
	}

	log.Info("EVICT: roll OnDelete StatefulSet — highest stale ordinal",
		"statefulset", sts.Namespace+"/"+sts.Name,
		"pod", candidate.Name,
		"updateRevision", sts.Status.UpdateRevision,
		"currentRevision", sts.Status.CurrentRevision)
	// Evict through the policy/v1 subresource, NOT a raw pod delete:
	// the apiserver enforces the PDB budget and consumes a disruption
	// slot atomically — the gate-2 pre-check above stays as a
	// fast-path skip, and a refused eviction just errors this STS's
	// roll (retried next sweep, no pod lost). The UID precondition
	// closes the TOCTOU between the owned-pods snapshot and the
	// evict — a same-named pod recreated in between is a fresh
	// member already on its own schedule, not ours to roll.
	ev := &policyv1.Eviction{
		ObjectMeta: metav1.ObjectMeta{
			Name: candidate.Name, Namespace: sts.Namespace},
		DeleteOptions: ptr.To(kube.UIDDeleteOptions(candidate.UID, "")),
	}
	if err := r.cs.PolicyV1().Evictions(sts.Namespace).
		Evict(ctx, ev); err != nil {
		return fmt.Errorf("evict pod %s/%s: %w", sts.Namespace, candidate.Name, err)
	}
	metrics.StatefulSetOnDeletePodsRolledTotal.
		WithLabelValues(sts.Namespace, sts.Name).Inc()
	return nil
}

// stsAutoRollOptedIn reports the opt-in: passiontech.dev/auto-roll-ondelete
// on the StatefulSet itself OR on its pod template — operators like
// dragonfly-operator propagate CR spec.annotations into the pod
// template only, so the STS object never carries the annotation even
// though the workload opted in (2.1.6).
func stsAutoRollOptedIn(sts *appsv1.StatefulSet) bool {
	return sts.Annotations[stsAutoRollAnno] == "true" ||
		sts.Spec.Template.Annotations[stsAutoRollAnno] == "true"
}

// ownedPods lists the pods the StatefulSet controls — the apiserver
// pre-filters by the STS's own spec.selector (without it every STS
// would drag the whole namespace's pod list across the wire per
// sweep), then the controller ownerReference decides (name+kind, not
// UID: fake clients and hand-built fixtures rarely carry matching
// UIDs). A selector that fails to parse fails CLOSED — an error
// skips this STS rather than rolling it on an unfiltered pod list.
// Pods already terminating are excluded: they are never delete
// candidates (the delete is already in flight) and they must not
// block the all-Ready gate either — a member wedged in Terminating
// (finalizer, lost node) would pin the roll forever, while a real
// mid-deletion disruption is still caught by the PDB gate's
// disruptionsAllowed.
func (r *statefulSetOnDeleteRoller) ownedPods(ctx context.Context,
	sts *appsv1.StatefulSet) ([]*corev1.Pod, error) {
	sel, err := metav1.LabelSelectorAsSelector(sts.Spec.Selector)
	if err != nil {
		return nil, fmt.Errorf("parse selector of statefulset %s/%s: %w",
			sts.Namespace, sts.Name, err)
	}
	list, err := r.cs.CoreV1().Pods(sts.Namespace).List(ctx,
		metav1.ListOptions{LabelSelector: sel.String()})
	if err != nil {
		return nil, fmt.Errorf("list pods in %s: %w", sts.Namespace, err)
	}
	var out []*corev1.Pod
	for i := range list.Items {
		p := &list.Items[i]
		if !p.DeletionTimestamp.IsZero() {
			continue
		}
		ref := metav1.GetControllerOf(p)
		if ref != nil && ref.Kind == "StatefulSet" && ref.Name == sts.Name {
			out = append(out, p)
		}
	}
	return out, nil
}

// podOrdinal parses the trailing ordinal out of "<stsName>-<N>".
func podOrdinal(stsName, podName string) (int, bool) {
	suffix := strings.TrimPrefix(podName, stsName+"-")
	if suffix == podName {
		return 0, false
	}
	n, err := strconv.Atoi(suffix)
	if err != nil {
		return 0, false
	}
	return n, true
}

// podReadySince reports whether the pod's Ready condition is True AND
// has been so for at least minAge. A missing or timestamp-less Ready
// condition reports false — an unverifiable age is not a settled pod.
func podReadySince(p *corev1.Pod, now time.Time, minAge time.Duration) bool {
	for _, c := range p.Status.Conditions {
		if c.Type != corev1.PodReady {
			continue
		}
		if c.Status != corev1.ConditionTrue || c.LastTransitionTime.IsZero() {
			return false
		}
		return now.Sub(c.LastTransitionTime.Time) >= minAge
	}
	return false
}
