// flux_conflict_test.go — the SSA ping-pong gate: manager detection
// across managedFields spellings, the loop threshold (3 repeats in
// window → skip + hook), window expiry re-arming, and the inert
// (unconfigured) posture.
package heal

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func objWithManager(manager string) *metav1.PartialObjectMetadata {
	return &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{
		Name: "webhook-thing", Namespace: "linkerd",
		ManagedFields: []metav1.ManagedFieldsEntry{
			{Manager: manager, Operation: "Update"},
		},
	}}
}

func TestFluxManagerOf(t *testing.T) {
	cases := []struct {
		manager string
		want    string
	}{
		{"helm-controller", "helm-controller"},
		{"kustomize-controller", "kustomize-controller"},
		// Flux versions suffix the manager with the release name —
		// the contains match must catch the spelling.
		{"helm-controller-linkerd-control-plane", "helm-controller-linkerd-control-plane"},
		{"kustomize-controller-infra-deployments", "kustomize-controller-infra-deployments"},
		{"kube-controller-manager", ""}, // substring bait: NOT a flux manager
		{"kured", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := FluxManagerOf(objWithManager(c.manager)); got != c.want {
			t.Fatalf("FluxManagerOf(%q) = %q, want %q", c.manager, got, c.want)
		}
	}
}

func TestFluxPatchGateInertWithoutConfig(t *testing.T) {
	ConfigureFluxConflictLoop(0, 0) // knob off
	defer ConfigureFluxConflictLoop(0, 0)
	obj := objWithManager("helm-controller")
	for range 10 {
		if !FluxPatchGate("webhook config", obj, "mwc/linkerd", time.Now()) {
			t.Fatalf("gate denied with the knob off — it must compile away")
		}
	}
}

func TestFluxPatchGateLoopTripAndExpiry(t *testing.T) {
	ConfigureFluxConflictLoop(3, 30*time.Minute)
	defer ConfigureFluxConflictLoop(0, 0)
	var fired []FluxConflictSignal
	SetFluxConflictHook(func(sig FluxConflictSignal) { fired = append(fired, sig) })
	defer SetFluxConflictHook(nil)

	now := time.Now()
	flux := objWithManager("kustomize-controller")
	key := "webhook config/linkerd/webhook-thing"

	// Plain (non-Git-owned) objects never gate — and clear any stale
	// loop history for the key.
	if !FluxPatchGate("webhook config", objWithManager("kube-controller-manager"), key, now) {
		t.Fatal("non-flux object denied")
	}
	// First two repeats proceed — below the loop threshold.
	if !FluxPatchGate("webhook config", flux, key, now.Add(time.Minute)) {
		t.Fatal("first repeat denied before the loop threshold")
	}
	if !FluxPatchGate("webhook config", flux, key, now.Add(2*time.Minute)) {
		t.Fatal("second repeat denied before the loop threshold")
	}
	// Third repeat IS the Heal-Revert Loop — deny + fire the hook.
	if FluxPatchGate("webhook config", flux, key, now.Add(3*time.Minute)) {
		t.Fatal("third repeat allowed — the ping-pong patch was not skipped")
	}
	if len(fired) != 1 {
		t.Fatalf("hook fired %d times, want 1", len(fired))
	}
	sig := fired[0]
	if sig.Manager != "kustomize-controller" || sig.Kind != "webhook config" ||
		sig.Namespace != "linkerd" || sig.Name != "webhook-thing" || sig.Key != key {
		t.Fatalf("hook signal = %+v", sig)
	}
	// Still inside the window: every further patch stays skipped (the
	// loop is reported, not fought).
	if FluxPatchGate("webhook config", flux, key, now.Add(4*time.Minute)) {
		t.Fatal("fourth repeat allowed inside the loop window")
	}
	if len(fired) != 2 {
		t.Fatalf("hook fired %d times after the fourth repeat, want 2", len(fired))
	}
	// The window drains — one probe patch re-arms the ledger.
	if !FluxPatchGate("webhook config", flux, key, now.Add(45*time.Minute)) {
		t.Fatal("patch denied after the window expired — loop never re-arms")
	}
}

func TestFluxPatchGateForgetsWhenFluxLeaves(t *testing.T) {
	ConfigureFluxConflictLoop(3, 30*time.Minute)
	defer ConfigureFluxConflictLoop(0, 0)
	SetFluxConflictHook(nil)

	now := time.Now()
	key := "csv/olm/argocd-operator.v9.9"
	flux := objWithManager("helm-controller")
	_ = FluxPatchGate("csv", flux, key, now)
	_ = FluxPatchGate("csv", flux, key, now.Add(time.Minute))
	// GitOps moved off the object — the loop history must drop, or a
	// later re-managed write would trip on stale counts.
	if !FluxPatchGate("csv", objWithManager("olm-operator"), key, now.Add(2*time.Minute)) {
		t.Fatal("non-flux object denied")
	}
	if !FluxPatchGate("csv", flux, key, now.Add(3*time.Minute)) {
		t.Fatal("stale loop history survived the manager change")
	}
}

func TestFluxPatchGateNilHookAndConcurrentAllow(t *testing.T) {
	ConfigureFluxConflictLoop(3, 30*time.Minute)
	defer ConfigureFluxConflictLoop(0, 0)
	SetFluxConflictHook(nil)

	now := time.Now()
	flux := objWithManager("helm-controller")
	const key = "mwc/linkerd/nil-hook"
	// Must not panic when hook is explicitly cleared with nil before tripping.
	var allowed atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if FluxPatchGate("mwc", flux, key, now) {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := allowed.Load(); got != 2 {
		t.Fatalf("concurrent allowed = %d, want exactly 2 (max=3)", got)
	}
}
