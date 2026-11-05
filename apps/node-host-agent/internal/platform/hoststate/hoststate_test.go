package hoststate

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type testClock struct{ now time.Time }

func (c *testClock) fn() time.Time { return c.now }

func newTestStore(t *testing.T) (*Store, *testClock, string) {
	t.Helper()
	dir := t.TempDir()
	clk := &testClock{now: time.Unix(1700000000, 0)}
	logFile := filepath.Join(dir, "watchdog.log")
	s := New(dir, logFile, clk.fn, nil)
	return s, clk, logFile
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func TestEnterCreatesLatchAndLogs(t *testing.T) {
	s, clk, logFile := newTestStore(t)

	s.Enter("kubelet-stall", "sig1")

	p := s.Path("kubelet-stall")
	if got := readFile(t, p); got != "1700000000\n" {
		t.Fatalf("latch content = %q", got)
	}
	if !s.Exists("kubelet-stall") {
		t.Fatal("Exists false after Enter")
	}
	log := readFile(t, logFile)
	if !strings.Contains(log, "STATE-ENTER: kubelet-stall sig1") {
		t.Fatalf("log missing STATE-ENTER: %q", log)
	}
	if !strings.Contains(log, clk.now.Format(time.RFC3339)) {
		t.Fatalf("log missing rfc3339 ts: %q", log)
	}
}

func TestEnterRefreshesMtimeNotContent(t *testing.T) {
	s, clk, _ := newTestStore(t)

	s.Enter("overloaded", "")
	p := s.Path("overloaded")
	first := readFile(t, p)

	// Advance the clock; a held latch keeps its ORIGINAL epoch
	// content but gets its mtime refreshed to the clock (BUG-H6 —
	// the janitor reaps on mtime).
	clk.now = clk.now.Add(time.Hour)
	s.Enter("overloaded", "")

	if got := readFile(t, p); got != first {
		t.Fatalf("latch content changed on re-enter: %q → %q", first, got)
	}
	after, _ := os.Stat(p)
	if !after.ModTime().Equal(clk.now) {
		t.Fatalf("mtime = %v, want clock %v", after.ModTime(), clk.now)
	}
}

func TestExitRemovesAndLogs(t *testing.T) {
	s, _, logFile := newTestStore(t)

	s.Enter("stall", "")
	var cleaned bool
	s.Exit("stall", func() { cleaned = true })

	if s.Exists("stall") {
		t.Fatal("latch still present after Exit")
	}
	if !cleaned {
		t.Fatal("cleanup hook not run")
	}
	if !strings.Contains(readFile(t, logFile), "STATE-EXIT: stall") {
		t.Fatal("log missing STATE-EXIT")
	}
}

func TestExitAbsentIsNoop(t *testing.T) {
	s, _, logFile := newTestStore(t)
	s.Exit("never-entered", func() { t.Fatal("cleanup ran") })
	if b, err := os.ReadFile(logFile); err == nil && len(b) != 0 {
		t.Fatalf("unexpected log: %q", b)
	}
}

func TestRateOKSpendLifecycle(t *testing.T) {
	s, clk, _ := newTestStore(t)

	if !s.RateOK("last-restart", time.Hour) {
		t.Fatal("fresh budget should be OK")
	}
	s.RateSpend("last-restart")
	if s.RateOK("last-restart", time.Hour) {
		t.Fatal("just-spent budget should not be OK")
	}
	clk.now = clk.now.Add(30 * time.Minute)
	if s.RateOK("last-restart", time.Hour) {
		t.Fatal("half-window budget should still be blocked")
	}
	clk.now = clk.now.Add(31 * time.Minute)
	if !s.RateOK("last-restart", time.Hour) {
		t.Fatal("expired budget should be OK")
	}
}

func TestRateOKGarbageIsOK(t *testing.T) {
	s, _, _ := newTestStore(t)
	p := filepath.Join(s.Dir, "last-x")
	if err := os.WriteFile(p, []byte("garbage\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !s.RateOK("last-x", time.Hour) {
		t.Fatal("garbage budget should read as unspent")
	}
}

func TestRateTrySpendSerializes(t *testing.T) {
	s, _, _ := newTestStore(t)
	if !s.RateTrySpend("last-restart", time.Hour) {
		t.Fatal("first try-spend should win")
	}
	if s.RateTrySpend("last-restart", time.Hour) {
		t.Fatal("second try-spend inside window should lose")
	}
}

func TestIncrCounter(t *testing.T) {
	s, _, _ := newTestStore(t)
	if got := s.Incr("consecutive-x"); got != 1 {
		t.Fatalf("first incr = %d, want 1", got)
	}
	if got := s.Incr("consecutive-x"); got != 2 {
		t.Fatalf("second incr = %d, want 2", got)
	}
	if got := s.Counter("consecutive-x"); got != 2 {
		t.Fatalf("counter = %d, want 2", got)
	}
	// Garbage reads as 0 → next incr is 1.
	if err := os.WriteFile(filepath.Join(s.Dir, "consecutive-y"),
		[]byte("junk\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := s.Incr("consecutive-y"); got != 1 {
		t.Fatalf("incr over garbage = %d, want 1", got)
	}
	s.ResetCounter("consecutive-x")
	if got := s.Counter("consecutive-x"); got != 0 {
		t.Fatalf("counter after reset = %d", got)
	}
}

func TestSuspectLogThrottles(t *testing.T) {
	s, clk, logFile := newTestStore(t)

	s.SuspectLog("k", "first", time.Hour)
	s.SuspectLog("k", "second", time.Hour)
	if n := strings.Count(readFile(t, logFile), "first"); n != 1 {
		t.Fatalf("first logged %d times", n)
	}
	if strings.Contains(readFile(t, logFile), "second") {
		t.Fatal("throttled line leaked into log")
	}
	clk.now = clk.now.Add(61 * time.Minute)
	s.SuspectLog("k", "third", time.Hour)
	if !strings.Contains(readFile(t, logFile), "third") {
		t.Fatal("cadence-expired reminder missing")
	}
}

func TestHeartbeatSeedsAndRefreshes(t *testing.T) {
	s, clk, _ := newTestStore(t)

	s.Heartbeat()
	installed := filepath.Join(s.Dir, "installed")
	lastRun := filepath.Join(s.Dir, "last-run")
	if readFile(t, installed) != "1700000000\n" {
		t.Fatal("installed not seeded")
	}

	// last-run refreshes every call; installed keeps baseline.
	clk.now = clk.now.Add(time.Hour)
	s.Heartbeat()
	if readFile(t, lastRun) != strconv.FormatInt(clk.now.Unix(), 10)+"\n" {
		t.Fatal("last-run not refreshed")
	}
	if readFile(t, installed) != "1700000000\n" {
		t.Fatal("installed baseline moved")
	}
}

func TestInitHeartbeatFilesOnlySeedsAbsent(t *testing.T) {
	s, clk, _ := newTestStore(t)

	if err := s.InitHeartbeatFiles(); err != nil {
		t.Fatal(err)
	}
	clk.now = clk.now.Add(time.Hour)
	if err := s.InitHeartbeatFiles(); err != nil {
		t.Fatal(err)
	}
	// last-run must NOT be refreshed by the init variant.
	if got := s.Epoch(filepath.Join(s.Dir, "last-run")); got != 1700000000 {
		t.Fatalf("init refreshed last-run: %d", got)
	}
}

func TestStampLastRunNoInstalled(t *testing.T) {
	s, _, _ := newTestStore(t)
	s.StampLastRun()
	if _, err := os.Stat(filepath.Join(s.Dir, "installed")); !os.IsNotExist(err) {
		t.Fatal("StampLastRun must not seed installed")
	}
	if s.Epoch(filepath.Join(s.Dir, "last-run")) != 1700000000 {
		t.Fatal("last-run not stamped")
	}
}

func TestTmpNameStaysOutOfStateScan(t *testing.T) {
	s, _, _ := newTestStore(t)
	// A failed write must not strand a "state-x.tmp"-shaped file —
	// the .tmp-<base> convention keeps staging invisible to the
	// hostmetrics state-* scan either way.
	s.WriteEpochFile(s.Path("probe"), 1)
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "state-") &&
			strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("tmp file visible to state-* scan: %s", e.Name())
		}
	}
}
