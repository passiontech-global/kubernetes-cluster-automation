// logx_test.go — For must bind the CURRENT slog.Default() per call.
package logx

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

// For resolves slog.With at call time so a handler installed later by
// main() (the JSON handler) still sees the "logger" attribute — a
// package-level cache would freeze the pre-main default instead.
func TestForTagsLoggerAttribute(t *testing.T) {
	old := slog.Default()
	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(old)

	For("probe").Info("hello")
	line := buf.String()
	if !strings.Contains(line, "logger=probe") {
		t.Fatalf("For output missing logger=probe: %q", line)
	}
	if !strings.Contains(line, "msg=hello") {
		t.Fatalf("For output missing msg=hello: %q", line)
	}
}

// For's snapshot cache must survive concurrent hammering without
// losing identity: repeated For(name) with an unchanged default always
// returns the SAME *slog.Logger — including when several goroutines
// race the same name's first build through the rebuild path (the
// publish re-checks the snapshot under forMu, so only one *slog.Logger
// per (default, name) can ever exist). Run under -race.
func TestForConcurrentIdentity(t *testing.T) {
	old := slog.Default()
	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })

	known := []string{"envx", "fsx", "httpx"}
	pre := make(map[string]*slog.Logger, len(known))
	for _, n := range known {
		pre[n] = For(n)
	}

	const (
		workers  = 8
		hotIters = 5000 // hits on the cached names — the atomic fast path
		// Fresh names exercise the copy-on-write rebuild path. The
		// distinct-name total must stay UNDER forCacheCap: past the
		// cap For serves an uncached logger per call (identity is
		// only guaranteed for cached names — see TestForCacheCap).
		newIters = 20 // 8*20+3 = 163 < 256
	)
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := range hotIters {
				name := known[(w+i)%len(known)]
				if got := For(name); got != pre[name] {
					t.Errorf("For(%q) identity changed: %p != %p", name, got, pre[name])
				}
			}
			for i := range newIters {
				name := fmt.Sprintf("race-new-%d-%d", w, i)
				if a, b := For(name), For(name); a != b {
					t.Errorf("racing first builds of %q produced two loggers", name)
				}
			}
		}(w)
	}
	wg.Wait()

	// Post-hammer identity: every concurrent rebuild kept the original
	// binding instead of dropping it (the miss path copies the latest
	// snapshot before publishing).
	for _, n := range known {
		if got := For(n); got != pre[n] {
			t.Errorf("post-hammer For(%q) identity changed", n)
		}
	}
}

// slog.SetDefault swaps race For's snapshot swap-out in production
// (main() installs the JSON handler while startup logs are already
// flowing): readers keep resolving while another goroutine flips the
// default. Mid-swap identity is NOT asserted — it legitimately changes
// with the default — but the run must stay race-clean, and once the
// swaps stop, identity is stable and the final default's handler emits
// the logger attribute.
func TestForConcurrentDefaultSwap(t *testing.T) {
	old := slog.Default()
	var bufA bytes.Buffer
	hA := slog.New(slog.NewTextHandler(&bufA, nil))
	hB := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	t.Cleanup(func() { slog.SetDefault(old) })

	names := []string{"envx", "fsx", "swap-new"}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 500 {
			if i%2 == 0 {
				slog.SetDefault(hA)
			} else {
				slog.SetDefault(hB)
			}
		}
	}()
	for w := range 4 {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := range 500 {
				For(names[i%len(names)])
				For(fmt.Sprintf("swap-%d-%d", w, i))
			}
		}(w)
	}
	wg.Wait()

	// Swaps stopped: the surviving default owns the cache, identity is
	// stable, and its handler emits the tagged records.
	slog.SetDefault(hA)
	if l1, l2 := For("envx"), For("envx"); l1 != l2 {
		t.Fatal("identity unstable after SetDefault swaps stopped")
	}
	For("envx").Info("after-swap")
	if line := bufA.String(); !strings.Contains(line, "logger=envx") ||
		!strings.Contains(line, "msg=after-swap") {
		t.Fatalf("final default did not emit the tagged record: %q", line)
	}
}

// forCacheCap bounds the per-name table: past it For must still hand
// back a WORKING logger (correct "logger" attribute, current default)
// without growing the snapshot — and without breaking identity for
// the names already cached.
func TestForCacheCap(t *testing.T) {
	old := slog.Default()
	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })

	// Fill the cache exactly to the cap.
	first := For("cap-first")
	for i := 1; i < forCacheCap; i++ {
		For(fmt.Sprintf("cap-fill-%d", i))
	}
	s := forSnap.Load()
	if s == nil || len(s.loggers) != forCacheCap {
		t.Fatalf("snapshot holds %d loggers, want %d", len(s.loggers), forCacheCap)
	}

	// Overflow names resolve correctly but stay uncached: two calls
	// return distinct loggers and the table size is unchanged.
	over := For("cap-overflow")
	over.Info("overflow-line")
	if over2 := For("cap-overflow"); over2 == over {
		t.Fatal("overflow name was cached past forCacheCap")
	}
	if s2 := forSnap.Load(); len(s2.loggers) != forCacheCap {
		t.Fatalf("overflow grew the table to %d", len(s2.loggers))
	}
	if !strings.Contains(buf.String(), "logger=cap-overflow") {
		t.Fatalf("overflow logger did not emit its attribute: %q", buf.String())
	}

	// Cached names keep their identity and stay warm.
	if got := For("cap-first"); got != first {
		t.Fatal("cached name lost identity after overflow resolves")
	}
}
