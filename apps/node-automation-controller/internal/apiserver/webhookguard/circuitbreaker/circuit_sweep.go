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
	"fmt"
	"time"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
)

// circuitJob is one webhook configuration's per-sweep work: the
// kind-independent fields the breaker evaluates plus the
// kind-specific patch-and-refresh closure.
type circuitJob struct {
	kind  string
	name  string
	anno  string
	views []hookView
	patch func(context.Context, []byte) error
}

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
	jobs        []circuitJob
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
	g := s.g
	patchMutating := func(cfg *admissionv1.MutatingWebhookConfiguration) func(context.Context, []byte) error {
		return func(ctx context.Context, payload []byte) error {
			patched, err := g.CS.AdmissionregistrationV1().MutatingWebhookConfigurations().
				Patch(ctx, cfg.Name, types.StrategicMergePatchType, payload, metav1.PatchOptions{})
			if err != nil {
				return err
			}
			s.snap.SetMWC(patched)
			return nil
		}
	}
	patchValidating := func(cfg *admissionv1.ValidatingWebhookConfiguration) func(context.Context, []byte) error {
		return func(ctx context.Context, payload []byte) error {
			patched, err := g.CS.AdmissionregistrationV1().ValidatingWebhookConfigurations().
				Patch(ctx, cfg.Name, types.StrategicMergePatchType, payload, metav1.PatchOptions{})
			if err != nil {
				return err
			}
			s.snap.SetVWC(patched)
			return nil
		}
	}
	mwcs, vwcs := s.snap.MWC, s.snap.VWC
	s.jobs = make([]circuitJob, 0, len(mwcs.Items)+len(vwcs.Items))
	for i := range mwcs.Items {
		cfg := &mwcs.Items[i]
		s.jobs = append(s.jobs, circuitJob{
			kind: guardstate.KindMutating, name: cfg.Name,
			anno:  cfg.Annotations[guardstate.CircuitBrokenAnno],
			views: mutHookViews(cfg.Webhooks), patch: patchMutating(cfg),
		})
	}
	for i := range vwcs.Items {
		cfg := &vwcs.Items[i]
		s.jobs = append(s.jobs, circuitJob{
			kind: guardstate.KindValidating, name: cfg.Name,
			anno:  cfg.Annotations[guardstate.CircuitBrokenAnno],
			views: valHookViews(cfg.Webhooks), patch: patchValidating(cfg),
		})
	}
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
			job.kind, job.name, job.anno, job.views, s.ready, s.now, s.seen, s.recoverSeen,
			s.allowTrips)
		if payload == nil {
			circuitMetrics(&s.b.brokenEmitted, job.kind, job.name, nil, nil, stillBroken)
			continue
		}
		if err := job.patch(ctx, payload); err != nil {
			// The post-patch annotation state is unverifiable —
			// carry the config's last-emitted tuples forward so
			// the sweep-end prune does not flap a still-broken
			// series off (the annotation may well still list it).
			// Liveness-aware: a tuple whose sub-webhook is no
			// longer in the config's snapshot views is not
			// carried, so the sweep-end prune forgets its series
			// instead of re-pinning it while patches keep failing.
			s.b.carryBrokenForward(job.kind, job.name, job.views)
			s.log.Error(err, "circuit breaker patch failed",
				"kind", job.kind, "config", job.name)
			s.failed = append(s.failed, job.name)
			continue
		}
		// The patch landed — the stale-annotation drops are durable,
		// so their series are released only here (a failed patch
		// keeps the annotation, the SSOT, listing those names).
		for _, name := range dropped {
			metrics.WebhookCircuitBroken.DeleteLabelValues(job.kind, job.name, name)
		}
		circuitMetrics(&s.b.brokenEmitted, job.kind, job.name, trips, recovered, stillBroken)
	}
}
