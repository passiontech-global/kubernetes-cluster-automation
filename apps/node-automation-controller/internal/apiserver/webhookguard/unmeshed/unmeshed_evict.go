// unmeshed_evict.go — the audit's remediation half: once the census
// produced candidates, the three fail-closed gates (the hot-reload
// remediation kill-switch, the injector-health proof, the
// maintenance-mutex + heal-budget Gate) and the bounded EvictV1 loop
// that recreates unmeshed pods meshed. Split from unmeshed_audit.go
// — Sweep orchestrates, this file holds the destructive half.
package unmeshed

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// remediate runs the bounded eviction pass over the census's
// candidates. Every gate fails closed: the ops kill-switch
// (UNMESHED_POD_REMEDIATION_ENABLED — re-read every run), the
// injector provably healthy again (webhook not circuit-broken, its
// declared Fail policy intact, >= 1 Ready endpoint behind its
// Service — a wrong "healthy" verdict deletes pods that would only
// be recreated unmeshed again), and the shared heal preamble
// (heal.Gate = the maintenance mutex + the fleet-wide heal budget;
// the mutex evaluation is memoized through the Guard verdict,
// sharing one check with the breaker's bounce passes).
func (a *Auditor) remediate(ctx context.Context, snap *guardstate.Snapshot,
	candidates []corev1.Pod, unmeshed int, now time.Time, log logr.Logger) {
	g := snap.G
	if !RemediationEnabled() {
		log.Info("unmeshed remediation disabled (UNMESHED_POD_REMEDIATION_ENABLED=false)",
			"candidates", len(candidates))
		return
	}

	healthy, err := guardstate.InjectorHealthy(snap)
	if err != nil {
		metrics.IncError(g.Queue)
		log.Info("WARN: injector health unverifiable — remediation skipped (fail closed)",
			"error", err, "candidates", len(candidates))
		return
	}
	if !healthy {
		log.Info("injector webhook not healthy — remediation deferred",
			"candidates", len(candidates))
		return
	}

	// unmeshed-pod-auditor — the shared heal preamble gates the evictions
	// (killing pods mid-drain/upgrade is exactly what the mutex
	// exists to prevent).
	proceed, unverifiable := heal.Gate(ctx, log, g.Verdict, g.CS, g.Dyn,
		"unmeshed-pod-evict", now)
	if unverifiable {
		metrics.IncError(g.Queue)
		log.Info("WARN: maintenance check unverifiable — "+
			"DEFER: unmeshed remediation skipped (fail closed)",
			"candidates", len(candidates))
		return
	}
	if !proceed {
		log.Info("DEFER: maintenance active or heal budget spent — unmeshed remediation skipped",
			"candidates", len(candidates))
		return
	}

	a.evictCandidates(ctx, g, candidates, unmeshed, now, log)
}

// evictCandidates issues the policy/v1 Evictions in deterministic
// order (the cap must pick the same pods every cycle) bounded by
// both successful deletes (unmeshedDeleteCap — the owner controller
// recreates each pod, so slow rolling beats a sweep-wide burst) and
// attempts (unmeshedDeleteAttempts — a persistently failing delete
// retried for every candidate would turn the sweep into an API
// storm).
func (a *Auditor) evictCandidates(ctx context.Context, g *guardstate.Guard,
	candidates []corev1.Pod, unmeshed int, now time.Time, log logr.Logger) {
	slices.SortFunc(candidates, func(a, b corev1.Pod) int {
		return strings.Compare(a.Namespace+"/"+a.Name, b.Namespace+"/"+b.Name)
	})
	deleted, attempts, errs := 0, 0, 0
	for i := range candidates {
		p := &candidates[i]
		if deleted >= unmeshedDeleteCap || attempts >= unmeshedDeleteAttempts {
			break
		}
		attempts++
		log.Info("EVICT: unmeshed pod — owner controller recreates it meshed",
			"pod", p.Namespace+"/"+p.Name,
			"age", now.Sub(p.CreationTimestamp.Time).Truncate(time.Second))
		// The kill goes through the policy/v1 Eviction API, NOT a raw
		// Delete (unmeshed-pod-auditor): the apiserver enforces PodDisruptionBudgets
		// and consumes a disruption slot atomically, so an already
		// degraded workload cannot lose its last replica to a
		// cosmetic fix. The UID precondition closes the TOCTOU
		// window between the audit snapshot and the evict — a
		// same-named pod recreated in between was admitted after
		// the injector recovered and is not ours to reap.
		uid := p.UID
		deleteOpts := kube.UIDDeleteOptions(uid, "")
		eviction := &policyv1.Eviction{
			ObjectMeta: metav1.ObjectMeta{
				Name:      p.Name,
				Namespace: p.Namespace,
			},
			DeleteOptions: &deleteOpts,
		}
		if err := g.CS.CoreV1().Pods(p.Namespace).EvictV1(ctx, eviction); err != nil {
			if apierrors.IsTooManyRequests(err) {
				// HTTP 429 — a PDB with disruptionsAllowed==0
				// refused the eviction. That is a deferral, not a
				// failure: the workload is already at its replica
				// floor and killing this pod would finish the
				// outage. Keep it, count no error, move on.
				log.Info("DEFER: PDB refused eviction of unmeshed pod — keeping pod alive",
					"pod", p.Namespace+"/"+p.Name)
				continue
			}
			if apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
				// The pod was deleted under us or recreated since
				// the audit — either way there is nothing of ours
				// left to evict; a raced outcome is not an error.
				log.Info("SKIP: unmeshed pod eviction raced — pod gone or recreated",
					"pod", p.Namespace+"/"+p.Name,
					"notFound", apierrors.IsNotFound(err),
					"conflict", apierrors.IsConflict(err))
				continue
			}
			log.Error(err, "unmeshed pod eviction failed", "pod", p.Namespace+"/"+p.Name)
			metrics.IncError(g.Queue)
			errs++
			continue
		}
		metrics.UnmeshedPodsRecreatedTotal.WithLabelValues(p.Namespace).Inc()
		deleted++
	}
	// The pass delivered no heal when NOTHING evicted and no
	// actuation even errored — every attempt PDB-refused, or the
	// candidate list was empty so no eviction ran at all. The
	// up-front heal.Gate grant then goes back (the same refund
	// contract heal.EvictPodV applies per pod): a workload wedged
	// behind a PodDisruptionBudget at its replica floor — or a
	// pass with nothing to do — must not burn a fleet-wide budget
	// token every sweep. A pass with even one landed eviction — or
	// one real API failure, which counts as a spent grant like
	// everywhere else — keeps it.
	if deleted == 0 && errs == 0 {
		heal.RefundGrant(now)
	}
	log.Info("unmeshed audit done", "unmeshed", unmeshed,
		"candidates", len(candidates), "deleted", deleted)
}
