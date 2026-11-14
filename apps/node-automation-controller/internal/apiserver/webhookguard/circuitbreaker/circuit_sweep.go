// circuit_sweep.go — the per-sweep phases of Breaker.sweep: the
// input census (ready-endpoint rollup + the two webhook-config
// lists), the per-config job build (the patch closures are the only
// true MWC/VWC difference — the evaluation loop is shared by both
// kinds, so a kind-specific edit lands in exactly one place) and
// the circuitPatch → patch → metrics loop. The streak-ledger prune
// defers and the brokenEmitted carry-forward contract stay in
// circuit_breaker.go's sweep.
package circuitbreaker

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
)

// circuitSweep carries one Breaker.sweep's working state — the armed
// keep-sets the deferred streak prunes read, the per-config jobs and
// the names whose patch failed (joined into the sweep's error).
type circuitSweep struct {
	b     *Breaker
	g     *guardstate.Guard
	snap  *guardstate.Snapshot
	log   logr.Logger
	now   time.Time
	ready guardstate.EndpointCensus
	// seen marks the deadSince keys still under evaluation — streaks
	// for entries gone since the last sweep are pruned below.
	seen map[string]bool
	// recoverSeen marks the recover-confirmation streaks Hit this
	// sweep — the prune's keep set (Hit and defer land together, so
	// every live streak key appears here each sweep).
	recoverSeen map[string]bool
	allowTrips  bool
	failed      []string
	jobs        []guardstate.WebhookConfigView
}

// loadInputs runs the sweep's census half: the shared
// ready-endpoint rollup (a census failure aborts — the breaker
// cannot tell dead from unmeasured) and the two webhook-config list
// errors the snapshot recorded.
func (s *circuitSweep) loadInputs() error {
	ready, err := s.snap.ReadyCounts()
	if err != nil {
		return err
	}
	s.ready = ready
	if s.snap.MWCErr != nil {
		return fmt.Errorf("list mutatingwebhookconfigurations — circuit breaker skipped: %w", s.snap.MWCErr)
	}
	if s.snap.VWCErr != nil {
		return fmt.Errorf("list validatingwebhookconfigurations — circuit breaker skipped: %w", s.snap.VWCErr)
	}
	return nil
}

// buildJobs projects both webhook-config lists into the shared job
// list — the kind-specific patch closure refreshes the snapshot's
// cached list so later duties in the same run see the patched state.
func (s *circuitSweep) buildJobs() {
	s.jobs = nil
	s.snap.ForEachWebhookConfig(func(cfg guardstate.WebhookConfigView) {
		s.jobs = append(s.jobs, cfg)
	})
}

// runJobs evaluates every config's circuitPatch verdict and lands
// the payload. A nil payload needs no write — the still-broken
// re-asserts read verified live state, so the series emits without a
// landed patch. A failed patch carries the config's last-emitted
// tuples forward (the annotation may still list them) and joins the
// sweep's error; the stale-annotation drops release their series
// only after the patch lands — the annotation is the SSOT.
func (s *circuitSweep) runJobs(ctx context.Context) {
	for _, job := range s.jobs {
		payload, trips, recovered, stillBroken, dropped := s.b.circuitPatch(s.log, s.g.Queue,
			job.Kind, job.Name, job.Anno, job.Hooks, s.ready, s.now, s.seen, s.recoverSeen,
			s.allowTrips)
		if payload == nil {
			circuitMetrics(&s.b.brokenEmitted, job.Kind, job.Name, nil, nil, stillBroken)
			continue
		}
		// SSA ping-pong defense: a Git-owned config (a HelmRelease-
		// applied webhook with driftDetection) re-asserts the Git
		// failurePolicy every reconcile — re-flipping it past the
		// loop threshold is the Heal-Revert Loop. Skip + report; the
		// window drains before one probe patch re-arms. The series
		// state carries forward untouched (the annotation, the SSOT,
		// still lists whatever it listed).
		//
		// P0-4: the gate applies ONLY to the recovery direction
		// (Ignore -> Fail). A payload flipping any hook TO Ignore is
		// the breaker's emergency actuation — a Fail-closed webhook on
		// a dead backend keeps paralyzing kube-apiserver until it is
		// tripped, so it must never sit behind the loop window (a
		// blocked trip also left carryBrokenForward reporting a
		// circuit that was never actually broken). The ping-pong
		// rate-limit still guards Ignore -> Fail recoveries; a mixed
		// payload rides the emergency write since its trips need it
		// anyway.
		if !emergencyPatch(payload) &&
			!heal.FluxPatchGate(job.Kind, job.Object,
				job.Kind+"/"+job.Name, s.now) {
			s.b.carryBrokenForward(job.Kind, job.Name, job.Hooks)
			s.log.Info("skip heal: Flux Heal-Revert Loop detected — circuit patch deferred",
				"kind", job.Kind, "config", job.Name)
			continue
		}
		if err := job.Patch(ctx, types.StrategicMergePatchType, payload); err != nil {
			// The post-patch annotation state is unverifiable —
			// carry the config's last-emitted tuples forward so
			// the sweep-end prune does not flap a still-broken
			// series off (the annotation may well still list it).
			// Liveness-aware: a tuple whose sub-webhook is no
			// longer in the config's snapshot views is not
			// carried, so the sweep-end prune forgets its series
			// instead of re-pinning it while patches keep failing.
			s.b.carryBrokenForward(job.Kind, job.Name, job.Hooks)
			s.log.Error(err, "circuit breaker patch failed",
				"kind", job.Kind, "config", job.Name)
			s.failed = append(s.failed, job.Name)
			continue
		}
		// The patch landed — the stale-annotation drops are durable,
		// so their series are released only here (a failed patch
		// keeps the annotation, the SSOT, listing those names).
		for _, name := range dropped {
			metrics.WebhookCircuitBroken.DeleteLabelValues(job.Kind, job.Name, name)
		}
		circuitMetrics(&s.b.brokenEmitted, job.Kind, job.Name, trips, recovered, stillBroken)
	}
}

// emergencyPatch reports whether the circuit patch flips any
// sub-webhook's failurePolicy TO Ignore — the breaker's emergency
// Fail -> Ignore actuation, which bypasses the Flux heal-revert
// gate (see runJobs). Annotation-only payloads and pure
// Ignore -> Fail recoveries return false and stay gated. An
// undecodable payload fails closed to gated: the write is skipped
// either way only when the gate also denies, and a corrupt payload
// would fail the Patch call regardless.
func emergencyPatch(payload []byte) bool {
	var doc struct {
		Webhooks []struct {
			FailurePolicy string `json:"failurePolicy"`
		} `json:"webhooks"`
	}
	if err := json.Unmarshal(payload, &doc); err != nil {
		return false
	}
	for _, w := range doc.Webhooks {
		if w.FailurePolicy == string(admissionv1.Ignore) {
			return true
		}
	}
	return false
}
