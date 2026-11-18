// unmeshed_evict.go — the audit's remediation half: once the census
// produced candidates, the three fail-closed gates (the hot-reload
// remediation kill-switch, the injector-health proof, the
// maintenance-mutex + heal-budget Gate) and the bounded EvictV1 loop
// that recreates unmeshed pods meshed. Split from unmeshed_audit.go
// — Sweep orchestrates, this file holds the destructive half.
package unmeshed

import (
	"context"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
)

// unmeshedRSHashRe mirrors kube/disruptionKey's ReplicaSet normalization:
// a Deployment rollout runs two ReplicaSets at once, so keying the
// per-workload cooldown on "<rs>-<hash>" would hand each RS its own
// slot and evict one pod from each mid-rollout — the same 2-replica
// Deployment drained twice inside one 30m window. Fold both onto
// "<ns>/Deployment/<deploy>" (wave3.2/rs-cooldown-key). A hand-named
// RS without a hash-shaped tail keeps its own identity.
var unmeshedRSHashRe = regexp.MustCompile(`^(.+)-[a-z0-9]{1,12}$`)

// unmeshedWorkloadKey is the per-workload cooldown identity for a pod:
// ReplicaSet owners normalize to their Deployment, every other
// controller keeps its Kind/Name, and a bare pod gets "" (no shared
// workload slot).
func unmeshedWorkloadKey(p *corev1.Pod) string {
	owner := metav1.GetControllerOf(p)
	if owner == nil {
		return ""
	}
	kind, name := owner.Kind, owner.Name
	if kind == "ReplicaSet" {
		if m := unmeshedRSHashRe.FindStringSubmatch(name); m != nil {
			kind, name = "Deployment", m[1]
		}
	}
	return p.Namespace + "/" + kind + "/" + name
}

// remediate runs the bounded eviction pass over the census's
// candidates. Every gate fails closed: the ops kill-switch
// (UNMESHED_POD_REMEDIATION_ENABLED — re-read every run), the
// injector provably healthy again (webhook not circuit-broken, its
// declared Fail policy intact, >= 1 Ready endpoint behind its
// Service — a wrong "healthy" verdict deletes pods that would only
// be recreated unmeshed again), and — per pod, in evictCandidates —
// the shared heal preamble (heal.Gate = maintenance mutex + fleet
// heal budget; the mutex evaluation is memoized through the Guard
// verdict, sharing one check with the breaker's bounce passes).
// The gate is taken ONCE PER EVICTION, not once for the batch: every
// pod this pass kills spends its own grant, so a large batch cannot
// bypass the fleet-wide ceiling with a single token.
func (a *Auditor) remediate(ctx context.Context, snap *guardstate.Snapshot,
	candidates []corev1.Pod, unmeshed int, now time.Time, log logr.Logger) {
	g := snap.G
	if !RemediationEnabled() {
		log.Info("unmeshed remediation disabled (UNMESHED_POD_REMEDIATION_ENABLED=false)",
			"candidates", len(candidates))
		return
	}

	// wave3.2/gate-order: drop in-cooldown candidates BEFORE taking the
	// fleet heal grant. A sweep whose every candidate is still inside
	// its workload cooldown has nothing to act on — it must not spend
	// (then refund) a budget token, nor be blocked by a spent budget
	// it did not need for this pass.
	eligible := make([]corev1.Pod, 0, len(candidates))
	for i := range candidates {
		p := &candidates[i]
		wlKey := unmeshedWorkloadKey(p)
		if wlKey != "" && a.evictCooldown.CooledDown(wlKey,
			unmeshedWorkloadCooldown, now) {
			log.Info("DEFER: workload inside unmeshed cooldown — skipping eviction",
				"pod", p.Namespace+"/"+p.Name, "workload", wlKey)
			continue
		}
		eligible = append(eligible, *p)
	}
	if len(eligible) == 0 {
		log.Info("DEFER: all unmeshed candidates inside cooldown — no heal gate taken",
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

	a.evictCandidates(ctx, g, eligible, unmeshed, now, log)
}

// evictCandidates issues the policy/v1 Evictions in deterministic
// order (the cap must pick the same pods every cycle) bounded by
// both successful deletes (unmeshedDeleteCap — the owner controller
// recreates each pod, so slow rolling beats a sweep-wide burst) and
// attempts (unmeshedDeleteAttempts — a persistently failing delete
// retried for every candidate would turn the sweep into an API
// storm). Every attempted pod takes its OWN heal.Gate grant; a
// clean refusal refunds that pod's grant exactly once, so a fleet
// budget of N grants can unlock at most N evictions this sweep.
func (a *Auditor) evictCandidates(ctx context.Context, g *guardstate.Guard,
	candidates []corev1.Pod, unmeshed int, now time.Time, log logr.Logger) {
	slices.SortFunc(candidates, func(a, b corev1.Pod) int {
		return strings.Compare(a.Namespace+"/"+a.Name, b.Namespace+"/"+b.Name)
	})
	deleted, attempts := 0, 0
	for i := range candidates {
		p := &candidates[i]
		if deleted >= unmeshedDeleteCap || attempts >= unmeshedDeleteAttempts {
			break
		}
		// Per-workload cooldown: pods sharing a controller share one
		// stamp — a workload churning unmeshed recreates is paced to
		// one eviction per window instead of one per pod per sweep.
		// ReplicaSet owners normalize to their Deployment so both
		// ReplicaSets of a rollout share the slot (wave3.2/rs-cooldown-key).
		wlKey := unmeshedWorkloadKey(p)
		if wlKey != "" && a.evictCooldown.CooledDown(wlKey,
			unmeshedWorkloadCooldown, now) {
			log.Info("DEFER: workload inside unmeshed cooldown — skipping eviction",
				"pod", p.Namespace+"/"+p.Name, "workload", wlKey)
			continue
		}

		// unmeshed-pod-auditor — the shared heal preamble gates EACH
		// pod (killing pods mid-drain/upgrade is exactly what the
		// mutex exists to prevent), consuming one fleet grant per
		// eviction. The verdict is memoized per sweep by Guard, so
		// the mutex API reads stay shared; only the budget token is
		// per pod. A held mutex or a spent window defers every
		// remaining candidate alike — break instead of logging once
		// per pod and re-reading an immutable verdict.
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
			log.Info("DEFER: maintenance active or heal budget spent — "+
				"unmeshed remediation skipped",
				"pod", p.Namespace+"/"+p.Name, "candidates", len(candidates))
			break
		}

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
		_, refused, notFound, err := heal.EvictPodNotFound(ctx, g.CS, nil, "", p, now)
		if refused {
			// No mutation executed, so this pod's grant goes back —
			// exactly once, symmetric with heal.EvictPodV's per-pod
			// refund. Real API failures keep their grant (an
			// attempted write is not a free retry).
			heal.RefundGrant(now)
			if notFound {
				// The pod vanished between census and evict — an
				// ordinary race, not a PDB/L1/quorum refusal. Keep
				// the pod (it is gone) and stay quiet: no misleading
				// "eviction refused" line for a stale candidate.
				continue
			}
			log.Info("DEFER: eviction refused — keeping pod alive",
				"pod", p.Namespace+"/"+p.Name)
			continue
		}
		attempts++
		if err != nil {
			// A real API failure is an absorbed sub-failure —
			// metered, never returned; its grant stays spent.
			log.Error(err, "unmeshed pod eviction failed", "pod", p.Namespace+"/"+p.Name)
			metrics.IncError(g.Queue)
			continue
		}
		metrics.UnmeshedPodsRecreatedTotal.WithLabelValues(p.Namespace).Inc()
		deleted++
		if wlKey != "" {
			a.evictCooldown.Stamp(wlKey, now)
		}
	}
	log.Info("unmeshed audit done", "unmeshed", unmeshed,
		"candidates", len(candidates), "deleted", deleted)
}
