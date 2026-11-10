// crd_conversion_sweep.go — the per-sweep phases of
// Breaker.SweepCRDConversionBackends: the carry-forward/inputs gates
// (an unverifiable sweep keeps last verdict alive — "can't tell" is
// not "clean"), the per-CRD backend verdict eval with the
// per-Service existence cache, and the wedged-pod bounce dispatch.
// The gauge, reasons and the exported Sweep entry stay in
// crd_conversion.go.
package circuitbreaker

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
)

// crdConversionSweep carries one SweepCRDConversionBackends run's
// working state — the armed inputs, the per-Service existence cache
// (a single conversion server commonly backs an operator's whole API
// group, so re-Getting the same Service per CRD is pure apiserver
// churn) and the dedup'd hung-service bounce list.
type crdConversionSweep struct {
	b    *Breaker
	g    *guardstate.Guard
	snap *guardstate.Snapshot
	log  logr.Logger
	now  time.Time

	ready      guardstate.EndpointCensus
	blind      bool // probe source itself suspect — see probeBlind
	hung       []string
	bounceSeen map[string]bool

	svcVerdicts map[string]bool // svcKey -> confirmed present
	svcMissing  map[string]bool // svcKey -> confirmed NotFound
}

// carryForward re-asserts last sweep's tuples when this sweep
// cannot measure the surface. Liveness-aware when the CRD list
// succeeded: live holds the CRD names snap.CRDs carries, so a
// tuple whose CRD left the list is NOT re-asserted — the Prune
// below forgets its series instead of re-pinning it while
// reads keep failing. nil live (the CRD list itself failed)
// carries everything — no liveness evidence exists to filter on.
func (s *crdConversionSweep) carryForward(live map[string]bool) {
	for k, lv := range s.b.crdUnhealthyEmitted.Last() {
		if live == nil || live[k.crd] {
			s.b.crdUnhealthyEmitted.Emit(k, lv...)
		}
	}
	s.b.crdUnhealthyEmitted.Prune(CRDConversionWebhookUnhealthy.DeleteLabelValues)
}

// loadInputs runs the sweep's fail-closed gates. proceed=false means
// the sweep ends here — either with err (surfaced to the facade) or
// cleanly (the breaker's own census failure already reported it and
// the kill-switch is on, so re-reporting would double-count).
func (s *crdConversionSweep) loadInputs() (proceed bool, err error) {
	if s.snap.CRDErr != nil {
		// API flap — "can't read the surface" fails closed: carry
		// the series forward and surface the error.
		s.carryForward(nil)
		return false, fmt.Errorf("list customresourcedefinitions — conversion webhook health skipped: %w", s.snap.CRDErr)
	}
	ready, err := s.snap.ReadyCounts()
	if err != nil {
		// The breaker reports the same census failure as ITS error —
		// re-reporting it here would double-count. Defer quietly and
		// keep the last verdict alive — UNLESS the breaker is
		// levered off this cycle, in which case nobody else reports
		// it and the failure would be invisible.
		//
		// The CRD list DID succeed here, so snap.CRDs is live
		// evidence: only its CRDs' tuples carry forward.
		live := make(map[string]bool, len(s.snap.CRDs))
		for i := range s.snap.CRDs {
			live[s.snap.CRDs[i].GetName()] = true
		}
		s.carryForward(live)
		if !Enabled() {
			return false, fmt.Errorf("endpoint/node census — conversion webhook health skipped: %w", err)
		}
		return false, nil
	}
	s.ready = ready
	return true, nil
}

// svcExists answers whether the conversion backend Service exists,
// memoized per sweep. Inconclusive gets (flap, timeout) are NOT
// cached: a transient error must not freeze the verdict for the
// rest of the sweep.
func (s *crdConversionSweep) svcExists(ctx context.Context, svcKey, ns, name string) (missing, exists bool, err error) {
	if s.svcVerdicts[svcKey] {
		return false, true, nil
	}
	if s.svcMissing[svcKey] {
		return true, false, nil
	}
	_, gerr := s.g.CS.CoreV1().Services(ns).Get(ctx, name, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(gerr):
		s.svcMissing[svcKey] = true
		return true, false, nil
	case gerr != nil:
		return false, false, gerr
	}
	s.svcVerdicts[svcKey] = true
	return false, true, nil
}

// evalCRDs walks every CRD with a webhook conversion to an
// in-cluster Service and emits the unhealthy tuple for each
// measurable dead-backend signature — missing_service,
// zero_endpoints, tls_probe_failed. An unverifiable read (Service
// get flap, monitor-blind probe source) carries that CRD's last
// verdict forward instead of flapping.
func (s *crdConversionSweep) evalCRDs(ctx context.Context) {
	// probeBlind — the same fleet-blind gate as the admission path:
	// when every probed backend failed the handshake the monitor is
	// the likely culprit, so the tls_probe_failed verdict must not
	// emit fresh or drive a bounce (the apiserver-truth reasons —
	// missing_service, zero_endpoints — stay live).
	s.blind = probeBlind(s.ready)
	for i := range s.snap.CRDs {
		crd := &s.snap.CRDs[i]
		svcKey, svcNS, svcName, ok := guardstate.CRDConversionServiceKey(crd)
		if !ok {
			continue // no webhook conversion or a URL backend — unmeasurable
		}
		reason := ""
		missing, _, err := s.svcExists(ctx, svcKey, svcNS, svcName)
		switch {
		case missing:
			reason = CRDReasonMissingService
			s.log.Info("UNHEALTHY: CRD conversion webhook backend Service missing",
				"crd", crd.GetName(), "service", svcKey)
		case err != nil:
			// Can't verify — carry this CRD's last verdict forward
			// rather than flap; absorbed sub-failure, sweep
			// continues.
			metrics.IncError(s.g.Queue)
			s.log.Error(err, "conversion webhook backend Service get failed",
				"crd", crd.GetName(), "service", svcKey)
			s.carryCRD(crd.GetName())
			continue
		case s.ready.Effective[svcKey] == 0:
			reason = CRDReasonZeroEndpoints
			s.log.Info("UNHEALTHY: CRD conversion webhook backend has 0 effective-ready endpoints",
				"crd", crd.GetName(), "service", svcKey)
		case s.ready.Probed[svcKey] && !s.ready.Responsive[svcKey]:
			if s.blind {
				// Monitor-blind — the handshake verdict is
				// unverifiable from this vantage point: carry the
				// CRD's last tuple forward ("can't tell", the same
				// contract as the Service-get flap above) instead of
				// emitting a fresh tls_probe_failed or queueing a
				// bounce against possibly healthy pods.
				s.carryCRD(crd.GetName())
				continue
			}
			reason = CRDReasonTLSProbeFailed
			s.log.Info("UNHEALTHY: CRD conversion webhook backend fails TCP+TLS probe on every endpoint — pods wedged",
				"crd", crd.GetName(), "service", svcKey)
			if !s.bounceSeen[svcKey] {
				s.bounceSeen[svcKey] = true
				s.hung = append(s.hung, svcKey)
			}
		}
		if reason == "" {
			continue
		}
		k := crdConversionKey{crd: crd.GetName(), service: svcKey, reason: reason}
		s.b.crdUnhealthyEmitted.Set(CRDConversionWebhookUnhealthy, 1,
			k, k.crd, k.service, k.reason)
	}
	s.b.crdUnhealthyEmitted.Prune(CRDConversionWebhookUnhealthy.DeleteLabelValues)
}

// carryCRD re-asserts one CRD's last-emitted tuples — the per-CRD
// half of carryForward for the in-loop "can't verify" paths.
func (s *crdConversionSweep) carryCRD(crdName string) {
	for k, lv := range s.b.crdUnhealthyEmitted.Last() {
		if k.crd == crdName {
			s.b.crdUnhealthyEmitted.Emit(k, lv...)
		}
	}
}

// bounceHung dispatches the stage-1 heal for each wedged backend
// Service: confirm a live bounce target BEFORE the heal preamble (a
// stale census ref must not spend a budget grant — or open the
// per-service cooldown — on a pod that no longer exists), then the
// UID-preconditioned pod delete. The shared preamble (BounceCooldown
// + maintenance mutex, fail closed, &g.Verdict memoized across
// services and shared with the admission bounce + unmeshed paths)
// rides inside deleteBouncePod's heal.EvictPodV call, so a PDB
// refusal refunds the grant it consumed instead of burning one fleet
// grant per sweep.
func (s *crdConversionSweep) bounceHung(ctx context.Context) {
	for _, svcKey := range s.hung {
		target := s.b.oldestLiveBackingPod(ctx, s.snap, svcKey,
			s.ready.BackingPods[svcKey], s.now)
		if target == nil {
			s.log.Info("conversion bounce: no live Ready backing pod found — endpoint refs are stale",
				"service", svcKey)
			continue
		}
		s.b.deleteBouncePod(ctx, s.snap, svcKey, target, s.now)
	}
}
