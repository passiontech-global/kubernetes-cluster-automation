// budget_test.go — the global heal budget: grant counting inside the
// sliding window, expiry of old grants, the AllowedV integration
// (exhausted budget defers like a held mutex), and the denial hook.
package heal

import (
	"fmt"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
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
// Refund — the refused-eviction counterpart of the grant gate.
// ---------------------------------------------------------------------------

// Refund returns exactly the grant Allow consumed: the window's
// remaining grant count is restored to its pre-Allow value, a refund
// for an instant that consumed no grant removes nothing (it can
// never eat a sibling grant), and the cap still holds after a
// refund-and-refill.
func TestBudgetRefundRestoresWindowExactly(t *testing.T) {
	b := NewBudget(2, time.Minute)
	now := time.Now()
	if !b.Allow(now) || !b.Allow(now) {
		t.Fatal("grants denied under the cap")
	}
	if b.Allow(now.Add(time.Second)) {
		t.Fatal("third grant allowed past the cap")
	}
	// Refunding one consumed stamp re-opens exactly one slot.
	b.Refund(now)
	if !b.Allow(now.Add(time.Second)) {
		t.Fatal("grant denied after a refund — window not restored")
	}
	if b.Allow(now.Add(2 * time.Second)) {
		t.Fatal("more grants allowed than the cap after refund")
	}
	// A refund for an instant that never consumed a grant must not
	// eat the OTHER stamp: the window stays full, the cap holds.
	b.Refund(now.Add(time.Hour))
	if b.Allow(now.Add(2 * time.Second)) {
		t.Fatal("over-refund freed a slot no refund earned")
	}
}

// A double refund is a no-op — the second finds no stamp Equal(now)
// and cannot push the count below the grants actually consumed — and
// a refund for a stamp that already expired out of the window is
// equally inert.
func TestBudgetRefundDoubleAndExpiredInert(t *testing.T) {
	b := NewBudget(1, time.Minute)
	now := time.Now()
	if !b.Allow(now) {
		t.Fatal("first grant denied under the cap")
	}
	if b.Allow(now) {
		t.Fatal("second grant allowed past the cap")
	}
	b.Refund(now)
	b.Refund(now) // double refund — nothing left to remove
	if !b.Allow(now) {
		t.Fatal("grant denied after a double refund")
	}
	if b.Allow(now) {
		t.Fatal("cap lost after double refund — count went negative")
	}
	// Past the window the stamp expires out; refunding that instant
	// must not conjure room by removing a LIVE stamp (none Equal(now)
	// exists — the newest grant at now+61s must survive).
	b2 := NewBudget(1, time.Minute)
	t0 := time.Now()
	if !b2.Allow(t0) {
		t.Fatal("grant denied under the cap")
	}
	b2.Refund(t0.Add(-2 * time.Minute)) // never granted
	b2.Refund(t0.Add(2 * time.Minute))  // a stamp that exists but at the wrong instant
	if !b2.Allow(t0.Add(61 * time.Second)) {
		t.Fatal("expired stamp's instant refunded a live sibling grant")
	}
}

// A PDB-refused EvictPodV hands its budget grant back: consecutive
// refused sweeps never drain the window — the pre-fix split shape
// (AllowedV at the caller, EvictPod at the delete) burned one grant
// per sweep on a PDB-hung target and starved every other heal-gated
// module. refused stays a deferral: (proceed, !unverifiable, false,
// refused=true, nil) both times.
func TestEvictPodVRefusalRefundsGrant(t *testing.T) {
	resetBudget(t)
	ConfigureBudget(1, time.Hour)
	p := pod("ns1", "op-abc-1", "uid-1", corev1.PodRunning, time.Now())
	cs := fake.NewSimpleClientset(p)
	cs.PrependReactor("create", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			ca, ok := a.(ktesting.CreateAction)
			if !ok || ca.GetSubresource() != "eviction" {
				return false, nil, nil
			}
			return true, nil, apierrors.NewTooManyRequests(
				"pdb allows no disruptions", 0)
		})
	now := time.Now()
	for i := range 2 {
		proceed, unverifiable, evicted, refused, err := EvictPodV(ctx,
			logr.Discard(), nil, cs, planAwareDyn(), nil,
			fmt.Sprintf("k%d", i), 0, p, now)
		if !proceed || unverifiable || evicted || !refused || err != nil {
			t.Fatalf("refused sweep %d = (%v,%v,%v,%v,%v), want (true,false,false,true,nil)",
				i+1, proceed, unverifiable, evicted, refused, err)
		}
	}
	// Both grants were refunded: exactly ONE slot is free again — the
	// window is restored, not over-credited.
	b := defaultBudget.Load()
	if b == nil {
		t.Fatal("budget not configured")
	}
	if !b.Allow(now.Add(time.Second)) {
		t.Fatal("window not restored after two refused evictions")
	}
	if b.Allow(now.Add(2 * time.Second)) {
		t.Fatal("refund over-credited the window")
	}
}

// Refusal then delivery: the refusal's grant is returned and the
// DELIVERED eviction consumes and KEEPS its own — one grant per
// delivered heal stays the accounting (the contract the linkerd
// endpoint-sync sweep pins at its call site), so a third key defers
// once the window's single grant is spent for real.
func TestEvictPodVRefusalThenDeliveryAccounting(t *testing.T) {
	resetBudget(t)
	ConfigureBudget(1, time.Hour)
	now := time.Now()
	p := pod("ns1", "op-abc-1", "uid-1", corev1.PodRunning, now)
	refusing := fake.NewSimpleClientset(p)
	refusing.PrependReactor("create", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			ca, ok := a.(ktesting.CreateAction)
			if !ok || ca.GetSubresource() != "eviction" {
				return false, nil, nil
			}
			return true, nil, apierrors.NewTooManyRequests(
				"pdb allows no disruptions", 0)
		})
	proceed, unverifiable, evicted, refused, err := EvictPodV(ctx, logr.Discard(),
		nil, refusing, planAwareDyn(), nil, "k", 0, p, now)
	if !proceed || unverifiable || evicted || !refused || err != nil {
		t.Fatalf("refusal = (%v,%v,%v,%v,%v), want (true,false,false,true,nil)",
			proceed, unverifiable, evicted, refused, err)
	}
	// The delivered bounce rides a PDB-free clientset one minute later.
	delivering := fake.NewSimpleClientset(p)
	proceed, unverifiable, evicted, refused, err = EvictPodV(ctx, logr.Discard(),
		nil, delivering, planAwareDyn(), nil, "k2", 0, p, now.Add(time.Minute))
	if !proceed || unverifiable || !evicted || refused || err != nil {
		t.Fatalf("delivery = (%v,%v,%v,%v,%v), want (true,false,true,false,nil)",
			proceed, unverifiable, evicted, refused, err)
	}
	// The delivered grant stays spent — a third key defers (fail
	// closed, no error owed).
	proceed, unverifiable = AllowedV(ctx, logr.Discard(), nil,
		delivering, planAwareDyn(), nil, "k3", 0, now.Add(2*time.Minute))
	if proceed || unverifiable {
		t.Fatalf("post-delivery grant = (%v,%v), want (false,false) — delivered heal must keep its grant",
			proceed, unverifiable)
	}
}

// ---------------------------------------------------------------------------
// Per-target non-convergent circuit breaker (target-circuit-breaker).
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

// The forget hook fires once per history drop — the healthy reset,
// the inline expiry GC inside the next consult, and the bulk prune —
// and stays silent for a healthy call with no history to drop. This
// is the series-prune bridge's contract: a target the breaker no
// longer tracks must be reported exactly once per forget.
func TestTargetBreakerForgetHookFiresPerDrop(t *testing.T) {
	b := NewTargetBreaker(TargetBreakerLimit, TargetBreakerWindow)
	var forgot []string
	b.SetForgetHook(func(module, target string) {
		forgot = append(forgot, module+"/"+target)
	})
	now := time.Now()
	// Healthy reset with NO history: silent.
	b.RecordTargetHealthy("m", "n0")
	if len(forgot) != 0 {
		t.Fatalf("healthy clear without history fired the forget hook: %v", forgot)
	}
	// Open an episode, then converge: exactly one forget.
	for range TargetBreakerLimit {
		b.TryAcquireTarget("m", "n1", now)
	}
	b.RecordTargetHealthy("m", "n1")
	if len(forgot) != 1 || forgot[0] != "m/n1" {
		t.Fatalf("healthy reset forgets = %v, want [m/n1]", forgot)
	}
	// Expiry GC: grants fully expire, the next consult GCs the entry
	// and fires the hook once — while still GRANTING (fresh history).
	for range TargetBreakerLimit {
		b.TryAcquireTarget("m", "n2", now)
	}
	if ok, _ := b.TryAcquireTarget("m", "n2", now.Add(TargetBreakerWindow+time.Second)); !ok {
		t.Fatal("grant denied after expiry GC")
	}
	if len(forgot) != 2 || forgot[1] != "m/n2" {
		t.Fatalf("expiry GC forgets = %v, want append m/n2", forgot)
	}
	// The consult after the GC starts a fresh history — no second
	// forget for the same drop.
	if _, r := b.TryAcquireTarget("m", "n2", now.Add(TargetBreakerWindow+2*time.Second)); r != "" {
		t.Fatalf("fresh history rejected: %q", r)
	}
	if len(forgot) != 2 {
		t.Fatalf("forget re-fired for a live history: %v", forgot)
	}
}

// The bulk prune past the 64-entry soft cap: once the target map
// grows past the cap, the next consult drops every entry whose
// grant history has fully expired and fires the forget hook once
// per dropped key — while an entry holding even one in-window
// stamp keeps its history and stays silent. Without this the map
// would accumulate one entry per healed pod for the process
// lifetime.
func TestTargetBreakerBulkPruneDropsExpiredEntries(t *testing.T) {
	b := NewTargetBreaker(100, 10*time.Minute)
	var forgot []string
	b.SetForgetHook(func(module, target string) {
		forgot = append(forgot, module+"/"+target)
	})
	now := time.Now()
	// 70 distinct targets — past the 64-entry cap so every later
	// consult runs pruneLocked. All granted inside the window.
	for i := range 70 {
		if ok, _ := b.TryAcquireTarget("m", fmt.Sprintf("t%02d", i), now); !ok {
			t.Fatalf("grant %d denied inside the cap", i)
		}
	}
	// t00 earns two more grants deep inside the window — at the
	// final consult its [now, now+8m, now+9m] history straddles the
	// cut (the `now` stamp expired, the fresh ones did not), which
	// is the keep-branch pruneLocked must not drop.
	for _, at := range []time.Time{now.Add(8 * time.Minute), now.Add(9 * time.Minute)} {
		if ok, _ := b.TryAcquireTarget("m", "t00", at); !ok {
			t.Fatal("t00 re-grant denied inside the cap")
		}
	}
	if len(forgot) != 0 {
		t.Fatalf("prune fired forgets with nothing expired: %v", forgot)
	}
	// A consult for a NEW target at now+11m: the cut (now+1m) leaves
	// every single-stamp entry fully expired — 69 bulk drops — while
	// t00's mixed history survives untouched.
	if ok, _ := b.TryAcquireTarget("m", "new", now.Add(11*time.Minute)); !ok {
		t.Fatal("new target denied after the prune")
	}
	if len(forgot) != 69 {
		t.Fatalf("forget fired %d times, want 69 (one per expired entry): %v",
			len(forgot), forgot)
	}
	seen := map[string]bool{}
	for _, f := range forgot {
		if f == "m/t00" || f == "m/new" {
			t.Fatalf("live entry %q was forgotten", f)
		}
		if seen[f] {
			t.Fatalf("forget re-fired for %q", f)
		}
		seen[f] = true
	}
	// The kept entry still holds all three stamps — pruneLocked
	// drops whole entries, it never trims a survivor's history.
	keep := b.targets[breakerTarget{module: "m", target: "t00"}]
	if keep == nil || len(keep.stamps) != 3 {
		t.Fatalf("t00 history = %+v, want 3 surviving stamps", keep)
	}
	if b.targets[breakerTarget{module: "m", target: "t01"}] != nil {
		t.Fatal("expired entry t01 survived the bulk prune")
	}
	if b.targets[breakerTarget{module: "m", target: "new"}] == nil {
		t.Fatal("new target missing after its grant")
	}
	// The map is back under the cap — the next consult pays no
	// prune and fires no further forgets.
	if ok, _ := b.TryAcquireTarget("m", "another", now.Add(12*time.Minute)); !ok {
		t.Fatal("post-prune grant denied")
	}
	if len(forgot) != 69 {
		t.Fatalf("forget re-fired after the map dropped under the cap: %v", forgot)
	}
}

// The package-global forget wiring mirrors the open hook: wired on
// the configured breaker, dropped with the instance on reconfigure.
func TestTargetBreakerGlobalForgetHook(t *testing.T) {
	resetTargetBreaker(t)
	fired := 0
	ConfigureTargetBreaker(TargetBreakerLimit, TargetBreakerWindow)
	SetTargetCircuitForgetHook(func(module, target string) { fired++ })
	now := time.Now()
	for range TargetBreakerLimit {
		TryAcquireTarget("m", "n", now)
	}
	RecordTargetHealthy("m", "n")
	if fired != 1 {
		t.Fatalf("global forget hook fired %d times, want 1", fired)
	}
	// Unset before a breaker exists: the package-level setter is a
	// no-op, not a panic.
	ConfigureTargetBreaker(0, 0)
	SetTargetCircuitForgetHook(func(module, target string) { fired++ })
}

// RefundGrant returns the grant Gate consumed when a batch-gated
// caller's post-Gate eviction pass lands 0 deletes (e.g. every
// candidate was PDB-refused).
func TestRefundGrantGlobalRestoresSlot(t *testing.T) {
	resetBudget(t)
	ConfigureBudget(1, time.Hour)
	cs := fake.NewSimpleClientset()
	now := time.Now()

	proceed, unverifiable := Gate(ctx, logr.Discard(), nil, cs, planAwareDyn(), "k1", now)
	if !proceed || unverifiable {
		t.Fatalf("first Gate = (%v,%v), want (true,false)", proceed, unverifiable)
	}
	RefundGrant(now)
	proceed, unverifiable = Gate(ctx, logr.Discard(), nil, cs, planAwareDyn(), "k2", now)
	if !proceed || unverifiable {
		t.Fatalf("Gate after RefundGrant = (%v,%v), want (true,false)", proceed, unverifiable)
	}
}
