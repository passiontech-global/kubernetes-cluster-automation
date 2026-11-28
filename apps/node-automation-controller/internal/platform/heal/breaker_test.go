// breaker_test.go — unit tests for TargetBreaker.Refund and heal.RefundTarget.
package heal

import (
	"testing"
	"time"
)

func TestTargetBreakerRefundPreventsPrematureOpen(t *testing.T) {
	b := NewTargetBreaker(TargetBreakerLimit, TargetBreakerWindow)
	opens := 0
	b.SetOpenHook(func(string, string, string) { opens++ })

	base := time.Now()
	for i := range TargetBreakerLimit + 2 {
		at := base.Add(time.Duration(i) * time.Minute)
		ok, reason := b.TryAcquireTarget("partition-pod-evictor", "p1", at)
		if !ok || reason != "" {
			t.Fatalf("attempt %d denied (%v, %q) after prior refunds", i+1, ok, reason)
		}
		b.Refund("partition-pod-evictor", "p1", at)
	}
	if opens != 0 {
		t.Fatalf("open hook fired %d times across refunded attempts, want 0", opens)
	}
	if _, exists := b.targets[breakerTarget{module: "partition-pod-evictor", target: "p1"}]; exists {
		t.Fatal("target entry survived after all stamps were refunded")
	}

	// Real non-refunded grants still hit TargetBreakerLimit and open on limit+1.
	t0 := base.Add(10 * time.Minute)
	for i := range TargetBreakerLimit {
		if ok, _ := b.TryAcquireTarget("partition-pod-evictor", "p1", t0.Add(time.Duration(i)*time.Second)); !ok {
			t.Fatalf("real grant %d denied inside cap", i+1)
		}
	}
	if ok, reason := b.TryAcquireTarget("partition-pod-evictor", "p1", t0.Add(time.Minute)); ok || reason != ReasonTargetNonConvergentCircuitOpen {
		t.Fatalf("4th real grant = (%v,%q), want open circuit", ok, reason)
	}
	if opens != 1 {
		t.Fatalf("open hook fired %d times, want 1", opens)
	}
}

func TestTargetBreakerRefundPreservesPriorStamps(t *testing.T) {
	b := NewTargetBreaker(TargetBreakerLimit, TargetBreakerWindow)
	t0 := time.Now()
	t1 := t0.Add(time.Minute)
	t2 := t0.Add(2 * time.Minute)

	if ok, _ := b.TryAcquireTarget("m", "n1", t0); !ok {
		t.Fatal("grant 1 denied")
	}
	if ok, _ := b.TryAcquireTarget("m", "n1", t1); !ok {
		t.Fatal("grant 2 denied")
	}
	if ok, _ := b.TryAcquireTarget("m", "n1", t2); !ok {
		t.Fatal("grant 3 denied")
	}
	// Refund only the 3rd stamp; t0 and t1 must remain.
	b.Refund("m", "n1", t2)
	// Double refund of t2 must be a no-op and must not eat t0 or t1.
	b.Refund("m", "n1", t2)

	h := b.targets[breakerTarget{module: "m", target: "n1"}]
	if h == nil || len(h.stamps) != 2 || !h.stamps[0].Equal(t0) || !h.stamps[1].Equal(t1) {
		t.Fatalf("remaining stamps = %+v, want [%v %v]", h, t0, t1)
	}

	// One more grant fits (3rd), next opens.
	if ok, _ := b.TryAcquireTarget("m", "n1", t0.Add(3*time.Minute)); !ok {
		t.Fatal("3rd grant after refund denied")
	}
	if ok, _ := b.TryAcquireTarget("m", "n1", t0.Add(4*time.Minute)); ok {
		t.Fatal("4th grant allowed — prior stamps were not preserved")
	}
}

func TestTargetBreakerRefundNilMissingAndMismatchSafe(t *testing.T) {
	var nilBreaker *TargetBreaker
	nilBreaker.Refund("m", "n1", time.Now()) // must not panic

	b := NewTargetBreaker(TargetBreakerLimit, TargetBreakerWindow)
	forgets := 0
	b.SetForgetHook(func(string, string) { forgets++ })

	now := time.Now()
	// Missing target/module is a silent no-op.
	b.Refund("m", "missing", now)

	if ok, _ := b.TryAcquireTarget("m", "n1", now); !ok {
		t.Fatal("grant denied")
	}
	// Mismatched timestamp or sibling module/target leaves stamps intact.
	b.Refund("m", "n1", now.Add(time.Second))
	b.Refund("other-mod", "n1", now)
	b.Refund("m", "other-node", now)
	h := b.targets[breakerTarget{module: "m", target: "n1"}]
	if h == nil || len(h.stamps) != 1 {
		t.Fatalf("mismatch/sibling refund altered stamps: %+v", h)
	}

	// Refunding the sole stamp cleans up the map entry without firing forgetHook.
	b.Refund("m", "n1", now)
	if _, exists := b.targets[breakerTarget{module: "m", target: "n1"}]; exists {
		t.Fatal("empty non-open entry not removed from targets map")
	}
	if forgets != 0 {
		t.Fatalf("forget hook fired %d times on Refund, want 0", forgets)
	}
}

func TestTargetBreakerRefundDoesNotClearOpenCircuitOrFireForgetHook(t *testing.T) {
	b := NewTargetBreaker(TargetBreakerLimit, TargetBreakerWindow)
	opens, forgets := 0, 0
	b.SetOpenHook(func(string, string, string) { opens++ })
	b.SetForgetHook(func(string, string) { forgets++ })

	t0 := time.Now()
	for i := range TargetBreakerLimit {
		if ok, _ := b.TryAcquireTarget("m", "n1", t0.Add(time.Duration(i)*time.Second)); !ok {
			t.Fatalf("grant %d denied", i+1)
		}
	}
	rejectedAt := t0.Add(time.Minute)
	if ok, _ := b.TryAcquireTarget("m", "n1", rejectedAt); ok {
		t.Fatal("4th grant should open circuit")
	}

	// Refunding a rejected attempt's timestamp must not clear the open circuit.
	b.Refund("m", "n1", rejectedAt)
	if ok, reason := b.TryAcquireTarget("m", "n1", rejectedAt.Add(time.Second)); ok || reason != ReasonTargetNonConvergentCircuitOpen {
		t.Fatalf("circuit cleared after mismatched refund: (%v,%q)", ok, reason)
	}
	if opens != 1 || forgets != 0 {
		t.Fatalf("hooks = (opens=%d, forgets=%d), want (1, 0)", opens, forgets)
	}

	// When an entry is already marked open and its stamps empty out, !h.open
	// keeps the entry from being silently deleted or firing forgetHook.
	b1 := NewTargetBreaker(1, TargetBreakerWindow)
	forgets1 := 0
	b1.SetForgetHook(func(string, string) { forgets1++ })
	if ok, _ := b1.TryAcquireTarget("m", "n1", t0); !ok {
		t.Fatal("grant denied")
	}
	if ok, _ := b1.TryAcquireTarget("m", "n1", t0.Add(time.Second)); ok {
		t.Fatal("2nd grant should open circuit")
	}
	b1.Refund("m", "n1", t0)
	h := b1.targets[breakerTarget{module: "m", target: "n1"}]
	if h == nil || !h.open {
		t.Fatalf("open entry cleared by Refund: %+v", h)
	}
	if forgets1 != 0 {
		t.Fatalf("forget hook fired %d times on Refund, want 0", forgets1)
	}
}

func TestRefundTargetGlobal(t *testing.T) {
	resetTargetBreaker(t)
	now := time.Now()
	// Unconfigured global breaker: safe no-op.
	RefundTarget("partition-pod-evictor", "p1", now)

	ConfigureTargetBreaker(1, time.Hour)
	if ok, _ := TryAcquireTarget("partition-pod-evictor", "p1", now); !ok {
		t.Fatal("initial global acquire denied")
	}
	RefundTarget("partition-pod-evictor", "p1", now)
	if ok, reason := TryAcquireTarget("partition-pod-evictor", "p1", now.Add(time.Minute)); !ok || reason != "" {
		t.Fatalf("global acquire after RefundTarget = (%v,%q), want (true,\"\")", ok, reason)
	}
}

func TestWithTargetBreaker(t *testing.T) {
	resetTargetBreaker(t)
	ConfigureTargetBreaker(1, time.Hour)
	now := time.Now()

	// Returning keepGrant=false refunds so next attempt still succeeds.
	allowed, _, err := WithTargetBreaker("mod", "t1", now, func() (bool, error) {
		return false, nil
	})
	if !allowed || err != nil {
		t.Fatalf("first WithTargetBreaker = (%v, %v), want (true, nil)", allowed, err)
	}
	allowed, _, _ = WithTargetBreaker("mod", "t1", now.Add(time.Minute), func() (bool, error) {
		return true, nil
	})
	if !allowed {
		t.Fatal("second WithTargetBreaker should succeed after refund")
	}
	// Limit=1 is now exhausted — circuit must block without calling fn.
	called := false
	allowed, reason, _ := WithTargetBreaker("mod", "t1", now.Add(2*time.Minute), func() (bool, error) {
		called = true
		return true, nil
	})
	if allowed || reason == "" || called {
		t.Fatalf("circuit open = (%v, %q, called=%v), want (false, non-empty, false)", allowed, reason, called)
	}
}
