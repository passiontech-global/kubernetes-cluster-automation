// statefulset_rollout_unstick.go — the statefulset-rollout-unstick
// check: breaks StatefulSet RollingUpdate deadlocks where one old-
// revision pod wedges in a container-error state and the
// statefulset-controller can never retire it.
//
// A RollingUpdate StatefulSet advances by deleting the highest-
// ordinal old-revision pod and recreating it at updateRevision. When
// that pod lands in CrashLoopBackOff / ImagePullBackOff /
// CreateContainerConfigError and stays Ready=False, the controller
// waits for it to come up before touching the next ordinal — the
// whole set sits mid-rollout indefinitely.
//
// The kubernetes/kubernetes#67250 shape needs care: after a template
// ROLLBACK (roll v1→v2, pod crashloops on v2, operator reverts the
// template to v1) status.currentRevision and status.updateRevision
// converge back to the SAME revision while the failed pod still
// carries the v2 controller-revision-hash — so "revisions differ" is
// NOT a valid in-flight test. The per-pod hash check below is the
// real detector: any owned pod whose revision hash differs from
// updateRevision, sits at ordinal >= spec...partition (canary pods
// below the partition intentionally keep the old revision), is not
// Ready, and has a container waiting in a hard-error reason
// (CrashLoopBackOff, ImagePullBackOff, ErrImagePull,
// CreateContainerConfigError, CreateContainerError,
// InvalidImageName) for >= 15m continuously (FirstSeenLedger — a pod
// that recovers or a roll that completes re-arms the window) is
// wedged.
//
// Each wedged pod emits
// node_automation_statefulset_rollout_wedged{namespace,statefulset,
// pod}=1. When NODE_AUTOMATION_STATEFULSET_ROLLOUT_HEAL_ENABLED is on
// (default) the check deletes exactly the flagged pod through
// heal.DeletePod (UID-preconditioned, cooldown + heal budget via
// Deps.HealAllowedClusterWideOnly — the classic mutex would defer on
// the very cordon a wedged rollout often coincides with) — the
// controller recreates it at updateRevision and the roll resumes.
// One delete per StatefulSet per 30m keeps a multi-pod wedge from
// becoming a mass eviction.
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
	// CheckNameStatefulSetRolloutUnstick is the kuberhealthy_check
	// label and the check's registry Name.
	CheckNameStatefulSetRolloutUnstick = "statefulset-rollout-unstick"

	// stsUnstickMinAge is the continuous-wedge window before a pod
	// counts as rollout-blocking — long enough that a normal
	// crash-restart cycle or a slow image pull never qualifies.
	stsUnstickMinAge = 15 * time.Minute
	// stsUnstickHealCooldown bounds deletes per StatefulSet — one
	// wedged member per window keeps a correlated failure (bad image
	// on every ordinal) from evicting the whole set.
	stsUnstickHealCooldown = 30 * time.Minute
)

// stsRolloutUnstickCheck detects and un-wedges StatefulSet
// RollingUpdate stalls.
type stsRolloutUnstickCheck struct {
	*probefw.Deps

	// healEnabled gates the pod delete; false leaves the check
	// detect+gauge only (NODE_AUTOMATION_STATEFULSET_ROLLOUT_HEAL_
	// ENABLED, resolved once at construction).
	healEnabled bool

	// wedgeSeen tracks "<ns>/<sts>/<pod>" first sightings — the
	// 15m continuous-wedge window; pruned each complete sweep to the
	// still-flagged set.
	wedgeSeen state.FirstSeenLedger
	// wedgeEmitted is the gauge ledger for the emitted series.
	wedgeEmitted state.GaugeLedger[string]
}

// NewStatefulSetRolloutUnstickCheck builds the check.
func NewStatefulSetRolloutUnstickCheck(d *probefw.Deps) probefw.Check {
	return &stsRolloutUnstickCheck{
		Deps:        d,
		healEnabled: envx.Gate("NODE_AUTOMATION_STATEFULSET_ROLLOUT_HEAL_ENABLED", true),
	}
}

var (
	// node_automation_statefulset_rollout_wedged — 1 per pod that has
	// blocked a StatefulSet RollingUpdate for >= 15m.
	stsRolloutWedgedGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_statefulset_rollout_wedged",
		Help: "1 while a StatefulSet RollingUpdate is blocked >=15m by an old-revision pod stuck in a container-error state — statefulset-rollout-unstick.",
	}, []string{"namespace", "statefulset", "pod"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(stsRolloutWedgedGauge)
}

// stsWedgeErrReasons is the container waiting-reason set that marks
// a pod as unrecoverable-by-waiting: kubelet backoff loops and
// config/image errors a delete-and-recreate is the standard remedy
// for. Transient reasons (ContainerCreating, PodInitializing) are
// deliberately absent — a slow start is not a wedge.
var stsWedgeErrReasons = map[string]bool{
	"CrashLoopBackOff":           true,
	"ImagePullBackOff":           true,
	"ErrImagePull":               true,
	"CreateContainerConfigError": true,
	"CreateContainerError":       true,
	"InvalidImageName":           true,
}

// Run sweeps the StatefulSet census for rollout wedges.
func (p *stsRolloutUnstickCheck) Run(ctx context.Context) probefw.Result {
	p.wedgeEmitted.Begin()
	log := logf.FromContext(ctx)
	now := p.Now()
	var rep probefw.SweepReport

	stsList, err := p.AllStatefulSets(ctx)
	if err != nil {
		rep.InfraErr(err)
		return rep.Verdict("statefulset rollout unstick: ", "; ")
	}
	podList, err := p.AllPods(ctx)
	if err != nil {
		rep.InfraErr(err)
		return rep.Verdict("statefulset rollout unstick: ", "; ")
	}

	// Index owned pods once: controller ref (Kind=StatefulSet,
	// Name=<set>) — the census already scopes the namespace.
	podsBySTS := map[string][]*corev1.Pod{}
	for i := range podList {
		pod := &podList[i]
		ref := metav1.GetControllerOf(pod)
		if ref == nil || ref.Kind != "StatefulSet" || ref.Name == "" {
			continue
		}
		key := pod.Namespace + "/" + ref.Name
		podsBySTS[key] = append(podsBySTS[key], pod)
	}

	seen := map[string]bool{}
	healed := map[string]bool{} // sts keys already healed this sweep
	for i := range stsList {
		sts := &stsList[i]
		if !stsUnstickApplies(ctx, sts) {
			continue
		}
		pods := podsBySTS[sts.Namespace+"/"+sts.Name]
		for _, pod := range p.stsWedgeCandidates(sts, pods, now, seen) {
			lv := []string{sts.Namespace, sts.Name, pod.Name}
			rep.Set(stsRolloutWedgedGauge, 1,
				sts.Namespace+"/"+sts.Name+"/"+pod.Name, lv)
			rep.Find("statefulset " + sts.Namespace + "/" + sts.Name +
				" rollout wedged by pod " + pod.Name)
			p.maybeHealPod(ctx, log, now, &rep, sts, pod, healed)
		}
	}

	// Prune ledgers to the live signature set — only on a complete
	// sweep (both lists succeeded above).
	p.wedgeSeen.Prune(func(key string) bool { return seen[key] })
	rep.Close(&p.wedgeEmitted, stsRolloutWedgedGauge.DeleteLabelValues)
	return rep.Verdict("statefulset rollout unstick: ", "; ")
}

// stsUnstickApplies reports whether the set is a RollingUpdate
// OrderedReady StatefulSet with an update revision to roll toward —
// the only shape the unstick applies to (OnDelete is the roller
// module's job, Parallel sets do not serialize on pod health the
// same way). An explicit spec.replicas=0 is skipped — no roll can be
// in flight. currentRevision == updateRevision is deliberately NOT
// required: the #67250 rollback converges both revisions while a
// stale-hash pod remains wedged — the per-pod hash check in
// stsWedgeCandidates is the detector, this gate only proves the set
// can roll at all.
func stsUnstickApplies(ctx context.Context, sts *appsv1.StatefulSet) bool {
	if sts.Spec.Replicas != nil && *sts.Spec.Replicas == 0 {
		return false // nothing to roll — no pod can be a rollout blocker
	}
	// Read annotations through the sweep overlay so a downscaler
	// stamp recorded earlier in this sweep is visible here too.
	return sts.Spec.UpdateStrategy.Type == appsv1.RollingUpdateStatefulSetStrategyType &&
		sts.Spec.PodManagementPolicy == appsv1.OrderedReadyPodManagement &&
		sts.Status.UpdateRevision != "" &&
		!kube.IsIntentionallyDownscaled(kube.EffectiveAnnos(ctx, sts), sts.Spec.Replicas)
}

// stsPodOrdinal extracts the StatefulSet ordinal from an owned pod
// name — "<set>-<ordinal>" is the controller's naming contract. ok=false
// when the suffix is missing or non-numeric: an unparseable ordinal
// cannot prove the pod sits outside the canary partition, so the
// caller fails closed and skips it.
func stsPodOrdinal(stsName, podName string) (int64, bool) {
	suffix := strings.TrimPrefix(podName, stsName+"-")
	if suffix == podName {
		return 0, false
	}
	n, err := strconv.ParseInt(suffix, 10, 64)
	return n, err == nil && n >= 0
}

// stsPodOrdinalCompare is the strict weak ordering for wedged pods:
// highest parseable ordinal first, parseable before unparseable,
// name descending as the final tie-break. The parseable/unparseable
// split MUST be decided before the name tie-break — falling through
// when only one side parses breaks transitivity against pairs where
// both parse (a name can sort between two ordinals). Split out so
// that property is directly unit-testable.
func stsPodOrdinalCompare(stsName string, a, b *corev1.Pod) int {
	oa, oka := stsPodOrdinal(stsName, a.Name)
	ob, okb := stsPodOrdinal(stsName, b.Name)
	if oka != okb {
		if oka {
			return -1
		}
		return 1
	}
	if oka && oa != ob {
		// The controller retires the largest ordinal first.
		if oa > ob {
			return -1
		}
		return 1
	}
	return strings.Compare(b.Name, a.Name)
}

// stsWedgeCandidates returns the owned pods whose old-revision
// container-error signature has held >= stsUnstickMinAge, in name
// order for a deterministic single-pick heal. Observing into
// wedgeSeen happens here so `seen` collects every live key for the
// end-of-sweep prune.
func (p *stsRolloutUnstickCheck) stsWedgeCandidates(
	sts *appsv1.StatefulSet, pods []*corev1.Pod, now time.Time,
	seen map[string]bool) []*corev1.Pod {

	sorted := slices.Clone(pods)
	slices.SortFunc(sorted, func(a, b *corev1.Pod) int {
		return stsPodOrdinalCompare(sts.Name, a, b)
	})
	// Canary partition: pods with ordinal < partition intentionally
	// keep the old revision — deleting one would break the canary
	// contract, so they are never wedge candidates.
	var partition int64
	if ru := sts.Spec.UpdateStrategy.RollingUpdate; ru != nil &&
		ru.Partition != nil {
		partition = int64(*ru.Partition)
	}
	var out []*corev1.Pod
	for _, pod := range sorted {
		if pod.DeletionTimestamp != nil || kube.PodReadyCond(pod) {
			continue
		}
		if pod.Labels["controller-revision-hash"] == "" ||
			pod.Labels["controller-revision-hash"] == sts.Status.UpdateRevision {
			continue
		}
		ord, ok := stsPodOrdinal(sts.Name, pod.Name)
		if !ok || ord < partition {
			continue
		}
		if !podInWedgeState(pod) {
			continue
		}
		key := sts.Namespace + "/" + sts.Name + "/" + pod.Name
		first, tracked := p.wedgeSeen.Observe(key, now)
		seen[key] = true
		if !tracked || now.Sub(first) < stsUnstickMinAge {
			continue
		}
		out = append(out, pod)
	}
	return out
}

// podInWedgeState reports whether any container (init, regular or
// ephemeral) is waiting in a hard-error reason — the signature a
// delete-and-recreate is meant to clear.
func podInWedgeState(pod *corev1.Pod) bool {
	for _, cs := range pod.Status.InitContainerStatuses {
		if cs.State.Waiting != nil && stsWedgeErrReasons[cs.State.Waiting.Reason] {
			return true
		}
	}
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.State.Waiting != nil && stsWedgeErrReasons[cs.State.Waiting.Reason] {
			return true
		}
	}
	for _, cs := range pod.Status.EphemeralContainerStatuses {
		if cs.State.Waiting != nil && stsWedgeErrReasons[cs.State.Waiting.Reason] {
			return true
		}
	}
	return false
}

// maybeHealPod deletes one wedged pod per StatefulSet per cooldown
// window. The HealAllowed gate (cooldown → maintenance mutex → heal
// budget) runs before the delete; a clean deferral or a denied gate
// leaves the pod for the next sweep.
func (p *stsRolloutUnstickCheck) maybeHealPod(ctx context.Context,
	log logr.Logger, now time.Time, rep *probefw.SweepReport,
	sts *appsv1.StatefulSet, pod *corev1.Pod,
	healed map[string]bool) {

	if !p.healEnabled {
		return
	}
	stsKey := sts.Namespace + "/" + sts.Name
	if healed[stsKey] {
		return // one delete per set per sweep — the 30m cooldown
		// enforces the same bound across sweeps.
	}
	proceed, unverifiable := p.HealAllowedClusterWideOnly(ctx, log, &p.Heals,
		stsKey, stsUnstickHealCooldown, now)
	switch {
	case unverifiable:
		// Tolerated sub-failure: the sweep continues and the run
		// does not fail — IncError keeps the queue-health metric
		// honest about the unverifiable gate.
		metrics.IncError(p.Name)
		return
	case !proceed:
		return
	}
	deleted, err := heal.DeletePod(ctx, p.CS, &p.Heals, stsKey, pod, now)
	if err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "statefulset unstick pod delete failed",
			"statefulset", stsKey, "pod", pod.Namespace+"/"+pod.Name)
		return
	}
	if !deleted {
		// Clean deferral (L1 hold, quorum reservation, 404/409) — no
		// mutation executed; hand the grant back exactly once.
		heal.RefundGrant(now)
		return
	}
	healed[stsKey] = true
	p.InvalidatePods(ctx)
	rep.Find("healed: deleted wedged pod " + pod.Namespace + "/" +
		pod.Name + " on " + stsKey)
	log.Info("ACTION: deleted wedged StatefulSet pod to unstick rollout",
		"statefulset", stsKey, "pod", pod.Namespace+"/"+pod.Name)
}
