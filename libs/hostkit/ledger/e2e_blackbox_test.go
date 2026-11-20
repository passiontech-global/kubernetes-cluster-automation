package ledger_test

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/ledger"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

func TestE2ETier1_CooldownSet(t *testing.T) {
	var c ledger.CooldownSet
	t0 := time.Unix(1_700_000_000, 0).UTC()

	if c.CooledDown("a", time.Minute, t0) {
		t.Fatal("unstamped key must not be cooled down")
	}
	if _, ok := c.Last("a"); ok {
		t.Fatal("unstamped key must not exist in Last")
	}
	if got := c.Entries(); len(got) != 0 {
		t.Fatalf("empty ledger Entries len = %d, want 0", len(got))
	}

	c.Stamp("a", t0)
	c.Stamp("b", t0.Add(10*time.Second))

	if !c.CooledDown("a", time.Minute, t0.Add(30*time.Second)) {
		t.Fatal("key 'a' must be cooled down inside 1m window")
	}
	// Boundary: elapsed == cooldown is NOT inside the cooldown window.
	if c.CooledDown("a", time.Minute, t0.Add(time.Minute)) {
		t.Fatal("key 'a' at exact cooldown boundary must be uncooled")
	}
	if c.CooledDown("a", time.Minute, t0.Add(2*time.Minute)) {
		t.Fatal("key 'a' past cooldown window must be uncooled")
	}

	lastA, ok := c.Last("a")
	if !ok || !lastA.Equal(t0) {
		t.Fatalf("Last(a) = (%v, %v), want (%v, true)", lastA, ok, t0)
	}

	// Entries() must return a defensive copy.
	entries := c.Entries()
	if len(entries) != 2 {
		t.Fatalf("Entries() len = %d, want 2", len(entries))
	}
	entries["injected"] = t0
	delete(entries, "a")
	if _, ok := c.Last("injected"); ok {
		t.Fatal("mutating Entries() affected internal ledger")
	}
	if _, ok := c.Last("a"); !ok {
		t.Fatal("deleting from Entries() removed key from internal ledger")
	}

	// Forget drops only target key.
	c.Forget("a")
	if _, ok := c.Last("a"); ok {
		t.Fatal("Forget(a) did not drop key 'a'")
	}
	if !c.CooledDown("b", time.Minute, t0.Add(30*time.Second)) {
		t.Fatal("Forget(a) unexpectedly affected key 'b'")
	}

	// Prune keeps only matching keys.
	c.Stamp("keep-1", t0.Add(20*time.Second))
	c.Stamp("drop-1", t0.Add(25*time.Second))
	pruned := c.Prune(func(key string, _ time.Time) bool {
		return key == "keep-1"
	})
	if pruned != 2 {
		t.Fatalf("Prune() = %d, want 2", pruned)
	}
	if len(c.Entries()) != 1 {
		t.Fatalf("Entries() after Prune len = %d, want 1", len(c.Entries()))
	}

	// PruneExpired drops entries strictly older than maxAge.
	c.Stamp("fresh", t0.Add(100*time.Second))
	evicted := c.PruneExpired(t0.Add(105*time.Second), 30*time.Second)
	if evicted != 1 {
		t.Fatalf("PruneExpired() = %d, want 1", evicted)
	}
	if _, ok := c.Last("keep-1"); ok {
		t.Fatal("expired key 'keep-1' still present after PruneExpired")
	}
	if _, ok := c.Last("fresh"); !ok {
		t.Fatal("fresh key missing after PruneExpired")
	}
}

func TestE2ETier1_FirstSeenLedger(t *testing.T) {
	var l ledger.FirstSeenLedger
	t0 := time.Unix(1_700_000_000, 0).UTC()

	if age, ok := l.Seen("x", t0); ok || age != 0 {
		t.Fatalf("Seen on untracked key = (%v, %v), want (0, false)", age, ok)
	}
	if first, seen := l.Observe("x", t0); seen || !first.Equal(t0) {
		t.Fatalf("first Observe = (%v, %v), want (%v, false)", first, seen, t0)
	}
	if first, seen := l.Observe("x", t0.Add(15*time.Second)); !seen || !first.Equal(t0) {
		t.Fatalf("second Observe = (%v, %v), want (%v, true)", first, seen, t0)
	}
	if age, ok := l.Seen("x", t0.Add(45*time.Second)); !ok || age != 45*time.Second {
		t.Fatalf("Seen = (%v, %v), want (45s, true)", age, ok)
	}

	// Seed only moves stamp earlier; later seed does not rejuvenate.
	l.Seed("x", t0.Add(20*time.Second))
	if age, _ := l.Seen("x", t0.Add(45*time.Second)); age != 45*time.Second {
		t.Fatalf("later Seed changed age to %v, want 45s", age)
	}
	l.Seed("x", t0.Add(-30*time.Second))
	if age, _ := l.Seen("x", t0.Add(45*time.Second)); age != 75*time.Second {
		t.Fatalf("earlier Seed gave age %v, want 75s", age)
	}

	l.Seed("y", t0)
	l.Forget("x")
	if _, ok := l.Seen("x", t0); ok {
		t.Fatal("Forget did not remove x")
	}
	if dropped := l.Prune(func(string) bool { return false }); dropped != 1 {
		t.Fatalf("Prune() = %d, want 1", dropped)
	}
}

func TestE2ETier1_SeenSetAndStreakLedger(t *testing.T) {
	var seen ledger.SeenSet
	if !seen.Add("n1") {
		t.Fatal("first Add(n1) must return true")
	}
	if seen.Add("n1") {
		t.Fatal("duplicate Add(n1) must return false")
	}
	if !seen.Has("n1") || seen.Has("missing") {
		t.Fatal("SeenSet.Has contract failed")
	}
	seen.Add("n2")
	seen.Forget("n1")
	if seen.Has("n1") || !seen.Add("n1") {
		t.Fatal("Forget did not allow re-Add")
	}
	if dropped := seen.Prune(func(k string) bool { return k == "n2" }); dropped != 1 || seen.Has("n1") {
		t.Fatalf("SeenSet.Prune dropped=%d, Has(n1)=%v", dropped, seen.Has("n1"))
	}

	var streak ledger.StreakLedger
	if got := streak.Hit("p1"); got != 1 {
		t.Fatalf("first Hit = %d, want 1", got)
	}
	if got := streak.Hit("p1"); got != 2 {
		t.Fatalf("second Hit = %d, want 2", got)
	}
	streak.Set("p2", 5)
	if streak.Max() != 5 || streak.Len() != 2 || streak.Count("p2") != 5 {
		t.Fatalf("StreakLedger state mismatch: max=%d len=%d p2=%d", streak.Max(), streak.Len(), streak.Count("p2"))
	}
	streak.Set("p2", 0)
	if streak.Count("p2") != 0 || streak.Len() != 1 {
		t.Fatalf("Set(p2, 0) should drop p2: count=%d len=%d", streak.Count("p2"), streak.Len())
	}
	streak.Reset("p1")
	if streak.Len() != 0 || streak.Max() != 0 {
		t.Fatalf("Reset did not clear p1: len=%d max=%d", streak.Len(), streak.Max())
	}
	streak.Hit("p3")
	streak.Clear()
	if streak.Len() != 0 {
		t.Fatalf("Clear left len=%d", streak.Len())
	}
	streak.Hit("keep")
	streak.Hit("drop")
	if dropped := streak.Prune(func(k string) bool { return k == "keep" }); dropped != 1 || streak.Len() != 1 {
		t.Fatalf("Prune dropped=%d len=%d", dropped, streak.Len())
	}
}

func TestE2ETier2_ClockBackwardStepAndNegativeDelta(t *testing.T) {
	tFuture := time.Unix(2_000_000_000, 0).UTC()
	tPast := time.Unix(1_700_000_000, 0).UTC()

	cur := tFuture
	cell := timex.NewCell(timex.NewClock(func() time.Time { return cur }))

	var c ledger.CooldownSet
	c.Stamp("node-1", cell.Now())

	// Step wall clock backward by ~9.5 years via timex.Cell (delta < -1m):
	// Option A self-heals c.last[key] = now and holds cooldown for ONE window.
	cur = tPast
	if !c.CooledDown("node-1", 5*time.Minute, cell.Now()) {
		t.Fatal("backward clock step (delta < -1m) must self-heal and hold cooldown for one window (true)")
	}
	// After advancing past 1 cooldown window from tPast, it must expire (never lock for 9.5 years).
	cur = tPast.Add(5*time.Minute + time.Second)
	if c.CooledDown("node-1", 5*time.Minute, cell.Now()) {
		t.Fatal("self-healed cooldown must expire after 1 cooldown window, not remain locked until tFuture")
	}

	// Direct time.Unix negative delta (-500s, < -1m): self-heals to t1 and expires after cooldown.
	var c2 ledger.CooldownSet
	c2.Stamp("node-2", time.Unix(2000, 0))
	tBack500 := time.Unix(1500, 0)
	if !c2.CooledDown("node-2", 5*time.Minute, tBack500) {
		t.Fatal("CooledDown with -500s delta must hold cooldown for one window (true)")
	}
	if c2.CooledDown("node-2", 5*time.Minute, tBack500.Add(5*time.Minute+time.Second)) {
		t.Fatal("CooledDown after -500s self-heal must expire once cooldown elapses from tBack500")
	}

	// Small jitter (-1m <= delta < 0): holds cooldown WITHOUT mutating Last(k)
	// and expires relative to tBase, whereas delta < -1m self-heals Last(k) to now.
	tBase := time.Unix(1_700_000_000, 0).UTC()
	const win = 5 * time.Minute

	for _, tc := range []struct {
		name string
		skew time.Duration
	}{
		{"minus_30s", -30 * time.Second},
		{"minus_59s", -59 * time.Second},
		{"minus_60s_exact_boundary", -60 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cs ledger.CooldownSet
			cs.Stamp("k", tBase)
			now := tBase.Add(tc.skew)
			if !cs.CooledDown("k", win, now) {
				t.Fatalf("%s: expected CooledDown=true", tc.name)
			}
			last, ok := cs.Last("k")
			if !ok || !last.Equal(tBase) {
				t.Fatalf("%s: Last(k) = (%v, %v), want unmutated %v", tc.name, last, ok, tBase)
			}
			// Must still be cooled just before tBase+win and expire at tBase+win.
			if !cs.CooledDown("k", win, tBase.Add(win-time.Second)) {
				t.Fatalf("%s: expected cooled at tBase+win-1s", tc.name)
			}
			if cs.CooledDown("k", win, tBase.Add(win)) {
				t.Fatalf("%s: expected expired at tBase+win", tc.name)
			}
		})
	}

	t.Run("minus_61s_self_heals_last", func(t *testing.T) {
		var cs ledger.CooldownSet
		cs.Stamp("k61", tBase)
		now := tBase.Add(-61 * time.Second)
		if !cs.CooledDown("k61", win, now) {
			t.Fatal("expected CooledDown=true on -61s self-heal")
		}
		last, ok := cs.Last("k61")
		if !ok || !last.Equal(now) {
			t.Fatalf("Last(k61) = (%v, %v), want self-healed %v", last, ok, now)
		}
		// Must still be cooled just before now+win, and expire at now+win (before tBase+win!).
		if !cs.CooledDown("k61", win, now.Add(win-time.Second)) {
			t.Fatal("expected cooled at now+win-1s")
		}
		if cs.CooledDown("k61", win, now.Add(win)) {
			t.Fatal("expected expired at now+win (61s before tBase+win)")
		}
	})

	t.Run("prune_expired_future_skew_boundary", func(t *testing.T) {
		var cs ledger.CooldownSet
		cs.Stamp("f59", tBase.Add(59*time.Second))
		cs.Stamp("f60", tBase.Add(60*time.Second))
		cs.Stamp("f61", tBase.Add(61*time.Second))
		cs.Stamp("f9y", tBase.Add(9*365*24*time.Hour))

		evicted := cs.PruneExpired(tBase, time.Hour)
		if evicted != 2 {
			t.Fatalf("PruneExpired = %d, want 2 (+61s and +9y evicted)", evicted)
		}
		if _, ok := cs.Last("f59"); !ok {
			t.Fatal("+59s future stamp should be retained")
		}
		if _, ok := cs.Last("f60"); !ok {
			t.Fatal("+60s exact boundary stamp should be retained")
		}
		if _, ok := cs.Last("f61"); ok {
			t.Fatal("+61s future stamp should be evicted")
		}
		if _, ok := cs.Last("f9y"); ok {
			t.Fatal("+9y future stamp should be evicted")
		}
	})

	t.Run("non_positive_cooldown_returns_false", func(t *testing.T) {
		var cs ledger.CooldownSet
		cs.Stamp("k0", tBase)
		if cs.CooledDown("k0", 0, tBase) {
			t.Fatal("cooldown=0 must return false")
		}
		if cs.CooledDown("k0", -time.Second, tBase) {
			t.Fatal("cooldown=-1s must return false")
		}
	})

	// Re-stamping at an earlier timestamp arms cooldown normally from tPast.
	c.Stamp("node-1", tPast)
	if !c.CooledDown("node-1", 5*time.Minute, tPast.Add(2*time.Minute)) {
		t.Fatal("re-stamping after backward clock step failed to arm cooldown")
	}
	if c.CooledDown("node-1", 5*time.Minute, tPast.Add(5*time.Minute)) {
		t.Fatal("re-stamped cooldown did not expire after 5m")
	}
}

func TestE2ETier2_MonotonicClockDelta(t *testing.T) {
	var c ledger.CooldownSet
	t1 := time.Now() // carries monotonic clock reading
	c.Stamp("mono", t1)

	// Monotonic advance within cooldown window.
	t2 := t1.Add(20 * time.Second)
	if !c.CooledDown("mono", time.Minute, t2) {
		t.Fatal("monotonic t1.Add(20s) must be inside 1m cooldown")
	}
	// Monotonic advance past cooldown window.
	t3 := t1.Add(61 * time.Second)
	if c.CooledDown("mono", time.Minute, t3) {
		t.Fatal("monotonic t1.Add(61s) must be outside 1m cooldown")
	}

	// Stripped wall-clock timestamp (Round(0)) still computes delta safely.
	tWall := t1.Round(0).Add(10 * time.Second)
	if !c.CooledDown("mono", time.Minute, tWall) {
		t.Fatal("wall-only t1.Round(0).Add(10s) must be inside 1m cooldown")
	}
}

func TestE2ETier2_FirstSeenSeedZeroTimeGuard(t *testing.T) {
	var l ledger.FirstSeenLedger
	validNow := time.Unix(1_700_000_000, 0).UTC()

	// Already-tracked key: Seed(k, time.Time{}) must be a no-op.
	l.Observe("tracked", validNow)
	l.Seed("tracked", time.Time{})
	age, ok := l.Seen("tracked", validNow.Add(30*time.Second))
	if !ok {
		t.Fatal("tracked key disappeared after zero-time Seed")
	}
	if age != 30*time.Second {
		t.Fatalf("zero-time Seed corrupted age on tracked key: got %v (~%v years), want 30s", age, age/(365*24*time.Hour))
	}

	// Untracked key: Seed(k, time.Time{}) must be a no-op (must NOT insert zero time).
	l.Seed("untracked", time.Time{})
	if age, ok := l.Seen("untracked", validNow); ok || age != 0 {
		t.Fatalf("zero-time Seed created entry for untracked key: age=%v ok=%v", age, ok)
	}

	// Valid earlier Seed after a zero-time Seed must still win.
	earlier := validNow.Add(-5 * time.Minute)
	l.Seed("tracked", earlier)
	age, ok = l.Seen("tracked", validNow.Add(30*time.Second))
	if !ok || age != 5*time.Minute+30*time.Second {
		t.Fatalf("valid earlier Seed after zero-time Seed gave (%v, %v), want (5m30s, true)", age, ok)
	}

	// Zero-time Seed BEFORE Observe must NOT mark key as seen.
	l.Seed("zero-before-observe", time.Time{})
	first, seen := l.Observe("zero-before-observe", validNow)
	if seen || !first.Equal(validNow) {
		t.Fatalf("Observe after zero-time Seed = (%v, %v), want (%v, false)", first, seen, validNow)
	}

	// Valid earlier Seed BEFORE Observe must mark key as seen with seeded timestamp.
	l.Seed("valid-before-observe", earlier)
	first, seen = l.Observe("valid-before-observe", validNow)
	if !seen || !first.Equal(earlier) {
		t.Fatalf("Observe after valid Seed = (%v, %v), want (%v, true)", first, seen, earlier)
	}
}

func TestE2ETier2_EmptyMapDrainInvariants(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()

	// Drain CooldownSet via Forget, Prune, and PruneExpired.
	var c ledger.CooldownSet
	for i := range 200 {
		c.Stamp(fmt.Sprintf("k-%d", i), t0)
	}
	for i := range 50 {
		c.Forget(fmt.Sprintf("k-%d", i))
	}
	if got := c.Prune(func(key string, _ time.Time) bool {
		return key >= "k-9" // keep subset
	}); got == 0 {
		t.Fatal("expected Prune to drop entries")
	}
	if len(c.Entries()) == 0 {
		t.Fatal("expected remaining entries before full drain")
	}
	remaining := len(c.Entries())
	if evicted := c.PruneExpired(t0.Add(2*time.Hour), time.Hour); evicted != remaining {
		t.Fatalf("PruneExpired evicted %d, want %d", evicted, remaining)
	}
	if len(c.Entries()) != 0 {
		t.Fatalf("Entries() after full drain = %d, want 0", len(c.Entries()))
	}
	if _, ok := c.Last("k-0"); ok {
		t.Fatal("Last() after drain must return false")
	}

	// Drain via Forget down to 0 and re-stamp.
	c.Stamp("solo", t0)
	c.Forget("solo")
	if len(c.Entries()) != 0 {
		t.Fatalf("Entries() after solo Forget = %d, want 0", len(c.Entries()))
	}
	c.Stamp("solo", t0.Add(time.Minute))
	if !c.CooledDown("solo", time.Minute, t0.Add(90*time.Second)) {
		t.Fatal("re-stamping after empty-map drain failed")
	}

	// Drain FirstSeenLedger, SeenSet, and StreakLedger + churn check.
	var fs ledger.FirstSeenLedger
	var ss ledger.SeenSet
	var sl ledger.StreakLedger
	for i := range 2000 {
		k := fmt.Sprintf("ephemeral-%d", i)
		fs.Observe(k, t0)
		ss.Add(k)
		sl.Hit(k)
	}
	if got := fs.Prune(func(string) bool { return false }); got != 2000 {
		t.Fatalf("FirstSeenLedger.Prune = %d, want 2000", got)
	}
	if got := ss.Prune(func(string) bool { return false }); got != 2000 {
		t.Fatalf("SeenSet.Prune = %d, want 2000", got)
	}
	if got := sl.Prune(func(string) bool { return false }); got != 2000 || sl.Len() != 0 {
		t.Fatalf("StreakLedger.Prune = %d, Len = %d", got, sl.Len())
	}

	// Ensure post-drain re-use works cleanly across all ledger types.
	fs.Observe("fresh", t0)
	if !ss.Add("fresh") || sl.Hit("fresh") != 1 {
		t.Fatal("post-drain reuse failed")
	}

	// Heap reclamation verification across 60,000 ephemeral keys in CooldownSet.
	const churnKeys = 60_000
	var memLedger ledger.CooldownSet
	for i := range churnKeys {
		memLedger.Stamp(fmt.Sprintf("ephemeral-heap-%d", i), t0)
	}
	runtime.GC()
	var msPeak, msAfter runtime.MemStats
	runtime.ReadMemStats(&msPeak)

	if evicted := memLedger.PruneExpired(t0.Add(2*time.Hour), time.Hour); evicted != churnKeys {
		t.Fatalf("PruneExpired churn evicted %d, want %d", evicted, churnKeys)
	}
	if len(memLedger.Entries()) != 0 {
		t.Fatalf("Entries() after churn drain = %d, want 0", len(memLedger.Entries()))
	}
	runtime.GC()
	runtime.ReadMemStats(&msAfter)
	runtime.KeepAlive(&memLedger)
	if msAfter.HeapAlloc >= msPeak.HeapAlloc/2 {
		t.Fatalf("expected heap reclamation after full CooldownSet drain: peak=%d after=%d", msPeak.HeapAlloc, msAfter.HeapAlloc)
	}
}

func TestE2ETier4_CooldownSetConcurrencyStress(t *testing.T) {
	var c ledger.CooldownSet
	base := time.Unix(1_700_000_000, 0).UTC()
	cell := timex.NewCell(timex.NewClock(func() time.Time { return base }))

	const workers = 8
	const iters = 300
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := range iters {
				k := fmt.Sprintf("k-%d", (id+i)%16)
				now := cell.Now().Add(time.Duration(i) * time.Millisecond)
				if i%10 == 0 {
					// Periodically exercise backward timestamps concurrently.
					now = base.Add(-time.Duration(i) * time.Millisecond)
				}
				c.CooledDown(k, 50*time.Millisecond, now)
				c.Stamp(k, now)
				c.Last(k)
				if i%25 == 0 {
					_ = c.Entries()
					c.PruneExpired(now.Add(time.Second), 500*time.Millisecond)
				}
				if i%40 == 0 {
					c.Forget(k)
				}
			}
		}(w)
	}
	wg.Wait()
}
