// circuit_breaker_test.go — unit coverage for the breaker's
// test-seam threshold selection and the per-config patch verdicts'
// unmeasurable-ref freeze; the sweep-level coverage lives in the
// facade's webhook_guard_test.go, which drives run() end to end.
package circuitbreaker

import (
	"testing"
	"time"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admissionregistration/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
)

// tripThreshold picks the faster partition window only when raw
// Ready endpoints remain (all of them stranded on bad nodes); a truly
// empty backend keeps the full dead threshold. Field overrides win
// over the package defaults.
func TestTripThresholdSelection(t *testing.T) {
	b := &Breaker{}
	if got := b.tripThreshold(0); got != DeadThreshold {
		t.Fatalf("raw=0 threshold = %s, want %s", got, DeadThreshold)
	}
	if got := b.tripThreshold(3); got != PartitionedThreshold {
		t.Fatalf("raw>0 threshold = %s, want %s", got, PartitionedThreshold)
	}
	b = &Breaker{
		zeroThreshold:          7 * time.Minute,
		partitionZeroThreshold: 42 * time.Second}
	if got := b.tripThreshold(0); got != 7*time.Minute {
		t.Fatalf("zeroThreshold override ignored: %s", got)
	}
	if got := b.tripThreshold(1); got != 42*time.Second {
		t.Fatalf("partitionZeroThreshold override ignored: %s", got)
	}
}

// A broken entry whose Service ref became unmeasurable — rewritten to
// a URL (svc nil), or carrying a Service ref with an empty
// namespace/name — must NEVER auto-recover: the recover branch runs
// only on measurable, non-zero census evidence, so -1 freezes the
// entry in evalStillBroken no matter how many sweeps pass. The
// pre-fix shape (`svcEffective != 0` admitted the -1 sentinel) let
// the streak advance and flipped failurePolicy back to Fail after
// RecoverConfirmSweeps with zero evidence a backend was ever probed —
// un-fail-closing a live outage. evalStillBroken also clears the
// streak, so a streak half-advanced before the rewrite dies with it.
func TestCircuitPatchUnmeasurableRefFreezesRecovery(t *testing.T) {
	b := &Breaker{}
	kind, cfg := guardstate.KindMutating, "mwc-url"
	urlHook, noRefHook := "rewired.example.com", "noref.example.com"
	ignore := wgFP(admissionv1.Ignore) // the tripped state, externally re-asserted
	views := []hookView{
		// URL clientConfig — no Service ref at all.
		{name: urlHook, fp: ignore},
		// Service ref with an empty namespace — unmeasurable the same
		// way (svcEffective/svcRaw stay -1).
		{name: noRefHook, fp: ignore,
			svc: &admissionv1.ServiceReference{Name: "svc"}},
	}
	ready := guardstate.EndpointCensus{
		Raw: map[string]int{}, Effective: map[string]int{}}
	annoVal := urlHook + "," + noRefHook
	seen := map[string]bool{}
	recoverSeen := map[string]bool{}
	now := time.Unix(1_700_000_000, 0)

	for i := range RecoverConfirmSweeps + 2 {
		payload, trips, recovered, stillBroken, dropped := b.circuitPatch(
			logr.Discard(), "webhook-guard", kind, cfg, annoVal,
			views, ready, now, seen, recoverSeen, true)
		if len(trips) != 0 || len(recovered) != 0 || len(dropped) != 0 {
			t.Fatalf("sweep %d: unmeasurable refs tripped/recovered/dropped = (%v,%v,%v)",
				i+1, trips, recovered, dropped)
		}
		if len(stillBroken) != 2 {
			t.Fatalf("sweep %d: unmeasurable entries must stay still-broken, got %v",
				i+1, stillBroken)
		}
		if payload != nil {
			// Both entries already carry failurePolicy=Ignore, so the
			// freeze writes nothing — a patch here would be the
			// recover flip to Fail the freeze exists to prevent.
			t.Fatalf("sweep %d: frozen entries must not patch, got %s",
				i+1, payload)
		}
	}
	if n := b.recoverStreak.Count(kind + "/" + cfg + "/" + urlHook); n != 0 {
		t.Fatalf("URL-ref entry's recover streak = %d, want 0 (never advances)", n)
	}
	if n := b.recoverStreak.Count(kind + "/" + cfg + "/" + noRefHook); n != 0 {
		t.Fatalf("malformed-ref entry's recover streak = %d, want 0 (never advances)", n)
	}
}

func TestEmergencyPatch(t *testing.T) {
	// Fail -> Ignore trips are the emergency actuation: the payload
	// must bypass the Flux heal-revert gate. Pure Ignore -> Fail
	// recoveries and annotation-only payloads stay gated.
	for _, tc := range []struct {
		name    string
		payload string
		want    bool
	}{
		{"trip to Ignore", `{"webhooks":[{"name":"h","failurePolicy":"Ignore"}]}`, true},
		{"mixed payload", `{"webhooks":[{"name":"a","failurePolicy":"Fail"},{"name":"b","failurePolicy":"Ignore"}]}`, true},
		{"recover to Fail", `{"webhooks":[{"name":"h","failurePolicy":"Fail"}]}`, false},
		{"annotation only", `{"metadata":{"annotations":{"x":"y"}}}`, false},
		{"undecodable", `not json`, false},
	} {
		if got := emergencyPatch([]byte(tc.payload)); got != tc.want {
			t.Errorf("%s: emergencyPatch = %v, want %v", tc.name, got, tc.want)
		}
	}
}
