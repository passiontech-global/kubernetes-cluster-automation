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

// ---------------------------------------------------------------------------
// Per-target non-convergent circuit breaker (W18-4).
// ---------------------------------------------------------------------------

// resetTargetBreaker restores the inert (unconfigured) breaker after
// a test — the package-global breaker is boot-time state, same rule
// as resetBudget. ConfigureTargetBreaker(0,0) drops the instance and
// with it any wired hook.
func resetTargetBreaker(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { ConfigureTargetBreaker(0, 0) })
}

// The boot defaults are the breaker's contract — 3 heals per 3h —
// pinned so a silent retune cannot widen the blast radius.
func TestTargetBreakerDefaults(t *testing.T) {
	if TargetBreakerLimit != 3 || TargetBreakerWindow != 3*time.Hour {
		t.Fatalf("defaults = %d/%s, want 3/3h",
			TargetBreakerLimit, TargetBreakerWindow)
	}
}

// Three heals pass, the 4th is rejected with the breaker's reason
// string; the open transition fires the hook exactly once per
// episode and rejections never extend the history.
func TestTargetBreakerOpensOnFourthGrant(t *testing.T) {
	b := NewTargetBreaker(TargetBreakerLimit, TargetBreakerWindow)
	opens := 0
	b.SetOpenHook(func(module, target, reason string) {
		opens++
		if module != "kubelet-liveness-reaper" || target != "n1" {
			t.Errorf("hook got %s/%s, want kubelet-liveness-reaper/n1",
				module, target)
		}
		if reason != ReasonTargetNonConvergentCircuitOpen {
			t.Errorf("hook reason = %q", reason)
		}
	})
	now := time.Now()
	for i := range TargetBreakerLimit {
		if ok, reason := b.TryAcquireTarget("kubelet-liveness-reaper", "n1", now); !ok {
			t.Fatalf("grant %d denied (%q) inside the cap", i+1, reason)
		}
	}
	// The pinned contract string — the modules log and the K8s event
	// carries this spelling.
	ok, reason := b.TryAcquireTarget("kubelet-liveness-reaper", "n1", now)
	if ok || reason != "target_non_convergent_circuit_open" {
		t.Fatalf("4th grant = (%v,%q), want (false,target_non_convergent_circuit_open)",
			ok, reason)
	}
	if opens != 1 {
		t.Fatalf("open hook fired %d times, want 1", opens)
	}
	// A rejection while already open stays silent and leaves the
	// stamps untouched — the window still expires from the last GRANT.
	if _, r := b.TryAcquireTarget("kubelet-liveness-reaper", "n1",
		now.Add(time.Minute)); r != ReasonTargetNonConvergentCircuitOpen || opens != 1 {
		t.Fatalf("rejection while open = reason %q, opens %d (want %q, 1)",
			r, opens, ReasonTargetNonConvergentCircuitOpen)
	}
}

// RecordTargetHealthy clears the target's history immediately: an
// open circuit grants again right after the healthy call.
func TestTargetBreakerHealthyResets(t *testing.T) {
	b := NewTargetBreaker(TargetBreakerLimit, TargetBreakerWindow)
	now := time.Now()
	for range TargetBreakerLimit {
		b.TryAcquireTarget("m", "n", now)
	}
	if ok, _ := b.TryAcquireTarget("m", "n", now); ok {
		t.Fatal("4th grant allowed before the healthy reset")
	}
	b.RecordTargetHealthy("m", "n")
	if ok, reason := b.TryAcquireTarget("m", "n", now.Add(time.Minute)); !ok || reason != "" {
		t.Fatalf("grant after healthy reset = (%v,%q), want (true,\"\")",
			ok, reason)
	}
}

// History expires 3h after the last grant: still open just inside
// the window, granting again right after it.
func TestTargetBreakerWindowExpiry(t *testing.T) {
	b := NewTargetBreaker(TargetBreakerLimit, TargetBreakerWindow)
	now := time.Now()
	for range TargetBreakerLimit {
		b.TryAcquireTarget("m", "n", now)
	}
	if ok, _ := b.TryAcquireTarget("m", "n",
		now.Add(TargetBreakerWindow-time.Second)); ok {
		t.Fatal("grant inside the window allowed past the cap")
	}
	if ok, reason := b.TryAcquireTarget("m", "n",
		now.Add(TargetBreakerWindow+time.Second)); !ok || reason != "" {
		t.Fatalf("grant after window expiry = (%v,%q), want (true,\"\")",
			ok, reason)
	}
}

// Targets are isolated both ways: by targetKey and by module — no
// target's open circuit may leak into another's grants.
func TestTargetBreakerIsolatesTargets(t *testing.T) {
	b := NewTargetBreaker(TargetBreakerLimit, TargetBreakerWindow)
	now := time.Now()
	for range TargetBreakerLimit {
		b.TryAcquireTarget("m", "n1", now)
	}
	if ok, _ := b.TryAcquireTarget("m", "n1", now); ok {
		t.Fatal("n1 4th grant allowed")
	}
	if ok, _ := b.TryAcquireTarget("m", "n2", now); !ok {
		t.Fatal("n2 denied by n1's open circuit")
	}
	if ok, _ := b.TryAcquireTarget("m2", "n1", now); !ok {
		t.Fatal("another module denied by m's open circuit")
	}
}

// No configured breaker is the inert gate — every request proceeds
// and the healthy call is a harmless no-op.
func TestTryAcquireTargetNoBreakerIsInert(t *testing.T) {
	resetTargetBreaker(t)
	for i := 0; i < 5; i++ {
		if ok, reason := TryAcquireTarget("m", "n", time.Now()); !ok || reason != "" {
			t.Fatalf("unconfigured breaker denied grant %d (%q)", i, reason)
		}
	}
	RecordTargetHealthy("m", "n") // must not panic
}

// The package-global wiring: the open transition fires the boot hook
// once, and RecordTargetHealthy on the global breaker resets the
// target for real.
func TestTryAcquireTargetGlobalOpenFiresHook(t *testing.T) {
	resetTargetBreaker(t)
	fired := 0
	ConfigureTargetBreaker(TargetBreakerLimit, TargetBreakerWindow)
	SetTargetCircuitOpenHook(func(module, target, reason string) {
		fired++
		if reason != ReasonTargetNonConvergentCircuitOpen {
			t.Errorf("hook reason = %q", reason)
		}
	})
	now := time.Now()
	for range TargetBreakerLimit + 1 {
		TryAcquireTarget("m", "n", now)
	}
	if fired != 1 {
		t.Fatalf("open hook fired %d times, want 1", fired)
	}
	RecordTargetHealthy("m", "n")
	if ok, _ := TryAcquireTarget("m", "n", now.Add(time.Minute)); !ok {
		t.Fatal("grant denied after global healthy reset")
	}
}
