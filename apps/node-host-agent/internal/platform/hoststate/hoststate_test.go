package hoststate

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
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

func TestEnterCreatesLatchAndLogs(t *testing.T) {
	s, clk, logFile := newTestStore(t)

	s.Enter("kubelet-stall", "sig1")

	p := s.Path("kubelet-stall")
	if got := testutil.ReadFile(t, p); got != "1700000000\n" {
		t.Fatalf("latch content = %q", got)
	}
	if !s.Exists("kubelet-stall") {
		t.Fatal("Exists false after Enter")
	}
	log := testutil.ReadFile(t, logFile)
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
	first := testutil.ReadFile(t, p)

	// Advance the clock; a held latch keeps its ORIGINAL epoch
	// content but gets its mtime refreshed to the clock (BUG-H6 —
	// the janitor reaps on mtime).
	clk.now = clk.now.Add(time.Hour)
	s.Enter("overloaded", "")

	if got := testutil.ReadFile(t, p); got != first {
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
	if !strings.Contains(testutil.ReadFile(t, logFile), "STATE-EXIT: stall") {
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

// TestRateOKFutureStampStaysCooled: a stamp from a stepped-back clock
// (NTP correction, manual set) sits in the future — its age is
// negative. RateOKIn clamps negative age to 0 so a future stamp is
// exactly "not expired yet" (fail-closed), never an early gate: the
// verdict no longer depends on the sign accident of
// (negative-age >= interval) surviving every interval comparison.
// RateTrySpend's check branch rides the same clamp (it checks via
// RateOK).
func TestRateOKFutureStampStaysCooled(t *testing.T) {
	s, clk, _ := newTestStore(t)

	// Stamp one hour in the future — the clock stepped back after
	// the spend.
	s.WriteEpochFile(filepath.Join(s.Dir, "last-stepped"),
		clk.now.Add(time.Hour).Unix())

	if s.RateOK("last-stepped", time.Hour) {
		t.Fatal("future stamp must stay cooled, not open the gate")
	}
	if s.RateTrySpend("last-stepped", time.Hour) {
		t.Fatal("RateTrySpend must inherit the clamp through its RateOK check")
	}
	// The budget was NOT spent by the losing try-spend — the stamp
	// still reads future. Once the clock passes the stamp the budget
	// expires normally.
	clk.now = clk.now.Add(2 * time.Hour)
	if !s.RateOK("last-stepped", time.Hour) {
		t.Fatal("expired stamp must be OK again after the clock catches up")
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
	if n := strings.Count(testutil.ReadFile(t, logFile), "first"); n != 1 {
		t.Fatalf("first logged %d times", n)
	}
	if strings.Contains(testutil.ReadFile(t, logFile), "second") {
		t.Fatal("throttled line leaked into log")
	}
	clk.now = clk.now.Add(61 * time.Minute)
	s.SuspectLog("k", "third", time.Hour)
	if !strings.Contains(testutil.ReadFile(t, logFile), "third") {
		t.Fatal("cadence-expired reminder missing")
	}
}

func TestHeartbeatSeedsAndRefreshes(t *testing.T) {
	s, clk, _ := newTestStore(t)

	s.Heartbeat()
	installed := filepath.Join(s.Dir, "installed")
	lastRun := filepath.Join(s.Dir, "last-run")
	if testutil.ReadFile(t, installed) != "1700000000\n" {
		t.Fatal("installed not seeded")
	}

	// last-run refreshes every call; installed keeps baseline.
	clk.now = clk.now.Add(time.Hour)
	s.Heartbeat()
	if testutil.ReadFile(t, lastRun) != strconv.FormatInt(clk.now.Unix(), 10)+"\n" {
		t.Fatal("last-run not refreshed")
	}
	if testutil.ReadFile(t, installed) != "1700000000\n" {
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

// TestOwnerLatchSharedHold: a multi-owner latch survives the FIRST
// owner's exit — pod-teardown's "nothing wedged" must not delete a
// latch ctr-tasks still holds for an unkillable orphan shim. The
// file leaves only when the last owner releases, with exactly one
// STATE-ENTER and one STATE-EXIT for the whole episode.
func TestOwnerLatchSharedHold(t *testing.T) {
	s, _, logFile := newTestStore(t)

	s.EnterFrom("wedged", "ctr-tasks", "shim pid=9 state=D")
	s.ExitFrom("wedged", "pod-teardown", nil)

	if !s.Exists("wedged") {
		t.Fatal("latch cleared while ctr-tasks still holds it")
	}
	log := testutil.ReadFile(t, logFile)
	if strings.Contains(log, "STATE-EXIT: wedged") {
		t.Fatalf("STATE-EXIT logged while an owner still holds: %q", log)
	}
	if n := strings.Count(log, "STATE-ENTER: wedged"); n != 1 {
		t.Fatalf("STATE-ENTER logged %d times want 1", n)
	}

	// The surviving owner's hold releases → the file goes + one
	// STATE-EXIT total.
	s.ExitFrom("wedged", "ctr-tasks", nil)
	if s.Exists("wedged") {
		t.Fatal("latch still present after last owner released")
	}
	log = testutil.ReadFile(t, logFile)
	if n := strings.Count(log, "STATE-EXIT: wedged"); n != 1 {
		t.Fatalf("STATE-EXIT logged %d times want 1", n)
	}
}

// TestOwnerLatchExitWithoutHold: an ExitFrom from an owner that
// never held — and with no other owner recorded (post-restart, or
// a latch minted through plain Enter) — falls back to legacy
// single-owner semantics and removes the file, so stale latches
// still clear instead of waiting for the janitor's 24h reap.
func TestOwnerLatchExitWithoutHold(t *testing.T) {
	s, _, _ := newTestStore(t)
	s.Enter("wedged", "") // plain Enter — no owner recorded
	s.ExitFrom("wedged", "pod-teardown", nil)
	if s.Exists("wedged") {
		t.Fatal("owner-less latch survived an ExitFrom")
	}
}

// TestOwnerLatchSecondOwnerJoins: a second owner joining an already-
// held latch must not re-log STATE-ENTER (file already present) —
// the log contract stays one line per episode.
func TestOwnerLatchSecondOwnerJoins(t *testing.T) {
	s, _, logFile := newTestStore(t)
	s.EnterFrom("wedged", "ctr-tasks", "")
	s.EnterFrom("wedged", "pod-teardown", "")
	if n := strings.Count(testutil.ReadFile(t, logFile),
		"STATE-ENTER: wedged"); n != 1 {
		t.Fatalf("STATE-ENTER logged %d times want 1", n)
	}
	// First owner releases — file stays for the second.
	s.ExitFrom("wedged", "ctr-tasks", nil)
	if !s.Exists("wedged") {
		t.Fatal("latch cleared while pod-teardown still holds")
	}
	s.ExitFrom("wedged", "pod-teardown", nil)
	if s.Exists("wedged") {
		t.Fatal("latch present after all owners released")
	}
}

// TestOwnerLatchLegacyFile: a latch file minted OUTSIDE the owner
// API (plain Enter, or a pre-restart EnterFrom) is treated as held
// by every DECLARED owner of a shared latch — the first ExitFrom
// seeds the remaining owners, so a check that never held it can't
// clear it; once every declared owner has released, the file exits.
// "wedged" here must be the real shared latch so SharedOwners
// resolves its declared set.
func TestOwnerLatchLegacyFile(t *testing.T) {
	s, _, _ := newTestStore(t)
	name := latchdefs.LatchPodTeardownWedged
	s.Enter(name, "") // legacy file — no recorded owners

	// One owner's release must NOT clear the file — the seed
	// treats the legacy file as held by every declared owner, so
	// ctr-tasks' hold remains (a check that never EnterFrom'ed
	// can't kill another owner's latch — the
	// TestListFailureKeepsLatch scenario).
	s.ExitFrom(name, "pod-teardown", nil)
	if !s.Exists(name) {
		t.Fatal("legacy shared latch cleared after one owner's release")
	}
	// Every declared owner has now released → the stale latch
	// exits on the SAME cycle, not the janitor's 24h reap.
	s.ExitFrom(name, "ctr-tasks", nil)
	if s.Exists(name) {
		t.Fatal("legacy shared latch kept after all declared owners released")
	}
}

// TestAppendLogRotates: past watchdogLogMaxBytes the log is renamed
// to <file>.1 and the new line lands in a fresh file — the shrink
// is what nodereporter's offset reset keys on.
func TestAppendLogRotates(t *testing.T) {
	s, _, logFile := newTestStore(t)
	big := strings.Repeat("x", int(watchdogLogMaxBytes))
	if err := os.WriteFile(logFile, []byte(big), 0o644); err != nil {
		t.Fatal(err)
	}
	s.AppendLog("after-rotation")
	if got := testutil.ReadFile(t, logFile); !strings.Contains(got, "after-rotation") ||
		len(got) > 1024 {
		t.Fatalf("fresh log = %d bytes, want just the new line", len(got))
	}
	rotated, err := os.ReadFile(logFile + ".1")
	if err != nil || len(rotated) != len(big) {
		t.Fatalf("rotated .1 = %d bytes err=%v, want %d",
			len(rotated), err, len(big))
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
