// budget_test.go — the global heal budget: grant counting inside the
// sliding window, expiry of old grants, the AllowedV integration
// (exhausted budget defers like a held mutex), and the denial hook.
package heal

import (
	"testing"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/client-go/kubernetes/fake"
)

// resetBudget restores the inert (unconfigured) gate after a test —
// the package-global budget is boot-time state, so every test that
// installs one must not leak it into the next.
func resetBudget(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		ConfigureBudget(0, 0)
		SetBudgetExhaustedHook(nil)
	})
}

func TestBudgetAllowCapsAndExpires(t *testing.T) {
	b := NewBudget(2, time.Minute)
	now := time.Now()
	if !b.Allow(now) || !b.Allow(now) {
		t.Fatal("first two grants denied under the cap")
	}
	if b.Allow(now) {
		t.Fatal("third grant allowed past the cap")
	}
	// A fourth at now+30s is still inside the window — denied.
	if b.Allow(now.Add(30 * time.Second)) {
		t.Fatal("grant inside the window allowed past the cap")
	}
	// Past the window the early grants expire and room opens.
	if !b.Allow(now.Add(61 * time.Second)) {
		t.Fatal("grant after window expiry still denied")
	}
}

// An exhausted budget defers AllowedV exactly like a held mutex:
// (false, false) — fail closed, no IncError owed by the caller.
func TestAllowedVBudgetExhaustedDefers(t *testing.T) {
	resetBudget(t)
	denials := 0
	SetBudgetExhaustedHook(func() { denials++ })
	ConfigureBudget(1, time.Hour)

	cs := fake.NewSimpleClientset()
	now := time.Now()
	proceed, unverifiable := AllowedV(ctx, logr.Discard(), nil, cs,
		planAwareDyn(), nil, "k", 0, now)
	if !proceed || unverifiable {
		t.Fatalf("first heal = (%v,%v), want (true,false)",
			proceed, unverifiable)
	}
	proceed, unverifiable = AllowedV(ctx, logr.Discard(), nil, cs,
		planAwareDyn(), nil, "k2", 0, now)
	if proceed || unverifiable {
		t.Fatalf("budget-exhausted heal = (%v,%v), want (false,false)",
			proceed, unverifiable)
	}
	if denials != 1 {
		t.Fatalf("denial hook fired %d times, want 1", denials)
	}
	// The cooled-down path must not consume budget: a cooled key
	// defers before the gate is even consulted.
	var cooled bool
	SetBudgetExhaustedHook(func() { cooled = true })
	proceed, _ = AllowedV(ctx, logr.Discard(), nil, cs,
		planAwareDyn(), nil, "k3", 0, now)
	if proceed || !cooled {
		t.Fatalf("still-exhausted heal = (%v, hook=%v)", proceed, cooled)
	}
}

// No configured budget is the legacy inert gate — every clear-mutex
// preamble proceeds.
func TestAllowedVNoBudgetIsInert(t *testing.T) {
	resetBudget(t)
	cs := fake.NewSimpleClientset()
	for i := 0; i < 3; i++ {
		proceed, unverifiable := AllowedV(ctx, logr.Discard(), nil, cs,
			planAwareDyn(), nil, "k", 0, time.Now())
		if !proceed || unverifiable {
			t.Fatalf("call %d = (%v,%v) with no budget, want (true,false)",
				i, proceed, unverifiable)
		}
	}
}
