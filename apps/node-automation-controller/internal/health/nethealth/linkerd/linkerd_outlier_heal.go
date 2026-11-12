// linkerd_outlier_heal.go — the gated-eviction half of the
// linkerd-outlier check: the six safety gates and the PDB
// pre-check, split from linkerd_outlier_guard.go (the cohort-math
// detection half) to keep both under ~500 LOC.
package linkerd

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// maybeEvictOutlier walks the six gates for one confirmed outlier.
// The detection verdict is already recorded by the caller — this
// only decides whether the pod is recreated.
func (p *linkerdOutlierGuardCheck) maybeEvictOutlier(ctx context.Context,
	log logr.Logger, now time.Time, s outlierSample, pod *corev1.Pod,
	readyByOwner map[types.UID]int) {

	podKey := pod.Namespace + "/" + pod.Name
	// Gate 6 first — detection ran either way; the kill switch only
	// gates the actuation half.
	if !p.Cfg.Linkerd.OutlierEvictEnabled {
		return
	}
	// Gate 1 — persistence + pod age: the signature must hold the
	// full 5m window (>=2 sweep cycles) and the pod must outlive
	// startup churn before it can be called gray-failed.
	if pod.Status.Phase != corev1.PodRunning ||
		now.Sub(pod.CreationTimestamp.Time) < linkerdOutlierPodMinAge {
		return
	}
	if !probefw.Persisted(&p.seen,
		s.ns+"/"+s.pod+"/"+string(pod.UID), now,
		linkerdOutlierPersistence, log) {
		return
	}
	// Gate 2 — a genuinely separate Ready sibling must survive the
	// evict; ReadySiblings discounts the outlier itself when it
	// still reports Ready (the gray failure keeps probes green).
	if probefw.ReadySiblings(readyByOwner, pod) < 1 {
		log.Info("skip outlier evict: no Ready sibling replica — evict would blackhole the workload",
			"pod", podKey)
		return
	}
	// Gate 4 FIRST — the PDB pre-check (every matching PDB must allow
	// a disruption) runs BEFORE the cooldown/mutex/budget preamble:
	// a workload at its replica floor must not burn a heal-budget
	// token (nor consume its 30m cooldown) on an evict the budget
	// would refuse anyway. The policy/v1 Eviction re-enforces the
	// budget atomically server-side; the UID precondition closes the
	// TOCTOU between the census and the kill — a same-named recreate
	// is not ours to evict.
	allowed, err := p.pdbAllows(ctx, pod)
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: outlier evict — PDB gate unverifiable (fail closed)",
			"pod", podKey, "error", err)
		return
	}
	if !allowed {
		log.Info("skip outlier evict: matching PDB allows no disruption",
			"pod", podKey)
		return
	}
	// Gates 3+5 — the controller-scoped 30m cooldown, the
	// maintenance mutex and the global heal budget ride one
	// AllowedV call (fail closed: unverifiable counts as held and
	// IncErrors the queue).
	ck := probefw.SelfHealKey(CheckNameLinkerdOutlierGuard,
		kube.PodControllerKey(pod))
	proceed, unverifiable := p.HealAllowed(ctx, log,
		&p.Heals, ck, linkerdOutlierHealCool, now)
	if unverifiable {
		metrics.IncError(p.Name)
		return
	}
	if !proceed {
		return
	}
	// The kill rides heal.EvictPod — the shared UID-preconditioned
	// policy/v1 Eviction every pod heal uses: the apiserver enforces
	// the PDB and consumes a disruption slot atomically, the sweep
	// overlay's local-remediation hold and one-disruption-per-
	// workload reservation apply, the pod's UID is tombstoned for
	// the rest of the sweep, and the heals ledger stamps only on a
	// DELIVERED eviction. The PDB pre-check above stays as the
	// fast-path skip ahead of the budget gate.
	evicted, refused, err := heal.EvictPod(ctx, p.CS, &p.Heals, ck, pod, now)
	switch {
	case err != nil:
		metrics.IncError(p.Name)
		log.Error(err, "linkerd outlier pod eviction failed", "pod", podKey)
		return
	case refused:
		// PDB 429, a local-remediation hold, or the sweep's
		// one-disruption reservation — every refused shape delivered
		// no heal, so the AllowedV gate's grant goes back (a
		// PDB-held sweep must not burn the fleet budget every
		// cycle).
		heal.RefundGrant(now)
		log.Info("DEFER: outlier eviction refused — keeping pod alive",
			"pod", podKey)
		return
	case !evicted:
		return
	}
	metrics.ControlPlanePodHealsTotal.WithLabelValues(CheckNameLinkerdOutlierGuard).Inc()
	log.Info("EVICT: linkerd outlier pod — gray-failed replica recreated",
		"pod", podKey, "deployment", s.deploy)
}

// pdbAllows reports whether every PodDisruptionBudget in the pod's
// namespace selecting it allows at least one disruption — the
// pre-check half of gate 4 (the Eviction subresource stays the
// atomic arbiter). A selector that fails to parse treats as
// matching — unverifiable fails closed.
func (p *linkerdOutlierGuardCheck) pdbAllows(ctx context.Context,
	pod *corev1.Pod) (bool, error) {

	// Cluster-wide PDB census, namespace-filtered client-side —
	// the sweep snapshot pays ONE list for every check that needs
	// PDBs instead of a per-pod-namespace LIST here.
	all, err := p.AllPDBs(ctx)
	if err != nil {
		return false, err
	}
	for i := range all {
		pdb := &all[i]
		if pdb.Namespace != pod.Namespace {
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
		if err != nil {
			sel = labels.Everything() // unparseable — fail closed
		}
		if !sel.Matches(labels.Set(pod.Labels)) {
			continue
		}
		if pdb.Status.DisruptionsAllowed < 1 {
			return false, nil
		}
	}
	return true, nil
}
