package hoststate

import (
	"log/slog"
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

// TestClearBudgetDropsRamMirror: a bare file delete leaves the
// lastSpent RAM mirror alive and RateOKIn verdicts on
// max(disk, ram) — the cooldown would survive the file's removal
// for the rest of the process. ClearBudget must drop both halves.
func TestClearBudgetDropsRamMirror(t *testing.T) {
	s, _, _ := newTestStore(t)

	s.RateSpend("wedged-seen-abc")
	if s.RateOK("wedged-seen-abc", time.Hour) {
		t.Fatal("just-spent budget should be blocked")
	}
	// Simulate the old raw os.Remove: file gone, RAM mirror stays.
	if err := os.Remove(filepath.Join(s.Dir, "wedged-seen-abc")); err != nil {
		t.Fatal(err)
	}
	if s.RateOK("wedged-seen-abc", time.Hour) {
		t.Fatal("phantom cooldown: RAM lastSpent outlived the file")
	}
	// ClearBudget on the mirror-only state still clears it.
	s.ClearBudget("wedged-seen-abc")
	if !s.RateOK("wedged-seen-abc", time.Hour) {
		t.Fatal("ClearBudget must drop the RAM mirror")
	}
	// File+mirror together: the normal dynamic-marker path.
	s.RateSpend("veth-seen-cali1")
	s.ClearBudget("veth-seen-cali1")
	if !s.RateOK("veth-seen-cali1", time.Hour) {
		t.Fatal("ClearBudget must clear file and mirror together")
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "veth-seen-cali1")); !os.IsNotExist(err) {
		t.Fatal("budget file still present after ClearBudget")
	}
	// Absent file is already clear — no error, mirror still dropped.
	s.ClearBudget("never-spent")
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

// TestSharedStoreSharesSyncStatePerDir: Shared hands every caller a
// Store whose SYNC STATE (owners registry + mutex) is the per-dir
// singleton, while the Store's LogFile/Now/Log stay the CALLER'S OWN
// — the first construction must not impose its logger/clock/log
// file on later subsystems (hostmetrics used to win the subsystem
// label for every later package's watchdog lines; nodereporter's
// readers-only empty LogFile used to mute the shared handle).
func TestSharedStoreSharesSyncStatePerDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "wd")
	logA := filepath.Join(t.TempDir(), "a-watchdog.log")

	a := Shared(dir, logA, nil, nil)
	// Same dir, differently spelled — the canonical key collapses it.
	b := Shared(filepath.Join(dir, "..", filepath.Base(dir)), "", nil, nil)

	// Per-caller config: b's empty logFile must NOT inherit a's —
	// nodereporter (LogFile "") and an appending subsystem coexist.
	if a.LogFile != logA {
		t.Fatalf("a.LogFile = %q, want its own %q", a.LogFile, logA)
	}
	if b.LogFile != "" {
		t.Fatalf("b.LogFile = %q, want the caller's own empty handle", b.LogFile)
	}
	// Per-caller Now: each store stamps with its OWN clock.
	clkA := &testClock{now: time.Unix(1700000000, 0)}
	clkB := &testClock{now: time.Unix(1700005000, 0)}
	sa := Shared(dir, "", clkA.fn, nil)
	sb := Shared(dir, "", clkB.fn, nil)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	sa.StampLastRun()
	if got := sb.Epoch(filepath.Join(sb.Dir, "last-run")); got != 1700000000 {
		t.Fatalf("sb observed sa's stamp as %d — Now must stay per-caller", got)
	}
	// Per-caller Log: each store resolves its own logger func.
	useA := false
	c := Shared(dir, "", nil, func() *slog.Logger {
		useA = true
		return slog.Default()
	})
	c.AppendLog("via-c")
	if !useA {
		t.Fatal("AppendLog must resolve the store's OWN Log func")
	}

	// SHARED sync state: an owner registered through a must be
	// visible to b — the multi-owner latch outlives a release that
	// goes through a DIFFERENT Store instance over the same dir.
	name := "shared-latch"
	a.EnterFrom(name, "workerhygiene", "")
	b.ExitFrom(name, "workerhygiene", nil)
	if a.Exists(name) {
		t.Fatal("b's release did not see a's registered hold — owners registry not shared")
	}

	// A different dir is its own sync state.
	other := Shared(filepath.Join(t.TempDir(), "kinedb-guard"), "", nil, nil)
	other.EnterFrom("shared-latch", "pod-teardown", "")
	if a.shared == other.shared {
		t.Fatal("a different dir must not share the sync state")
	}
	// New() stays private: two New copies over one dir do NOT share.
	p1, p2 := New(dir, "", nil, nil), New(dir, "", nil, nil)
	if p1.shared == p2.shared {
		t.Fatal("hand-built New stores must keep private sync cores")
	}
}

// TestJournalLatchOwnerIsolationAcrossHygienes: the REAL shared
// latch contract — workerhygiene's release must not delete the latch
// controllerhygiene is still failing under, and vice versa; the file
// leaves only when BOTH owners released (fresh or seeded holds), so
// one hygiene's healthy journal read can never clear the other's
// blindness episode. This is the Store-level mechanism
// wdeps.NoteJournalRead and cdeps.noteJournalRead drive through
// EnterFrom/ExitFrom with journalwatch's owner ids and the
// latchdefs.Owners declaration for journal-unreadable.
func TestJournalLatchOwnerIsolationAcrossHygienes(t *testing.T) {
	s, _, logFile := newTestStore(t)
	name := latchdefs.LatchJournalUnreadable

	// controllerhygiene latches mid-episode (its journal blind).
	s.EnterFrom(name, "controllerhygiene", "journald-wide empty reply")
	// workerhygiene joins the episode with its own enter edge.
	s.EnterFrom(name, "workerhygiene", "k0sworker snapshot empty")

	// workerhygiene recovers first — the latch MUST survive for the
	// still-blind controller.
	s.ExitFrom(name, "workerhygiene", nil)
	if !s.Exists(name) {
		t.Fatal("worker's healthy read deleted controller's live episode")
	}
	if strings.Contains(testutil.ReadFile(t, logFile), "STATE-EXIT: "+name) {
		t.Fatal("STATE-EXIT logged while controllerhygiene still holds")
	}

	// The surviving owner re-asserts its hold each blind read (mtime
	// refresh path) — still no exit.
	s.EnterFrom(name, "controllerhygiene", "still blind")
	if !s.Exists(name) {
		t.Fatal("re-assert lost the latch")
	}

	// Controller recovers — the last release exits exactly once.
	s.ExitFrom(name, "controllerhygiene", nil)
	if s.Exists(name) {
		t.Fatal("latch stuck after the last owner released")
	}
	if n := strings.Count(testutil.ReadFile(t, logFile),
		"STATE-EXIT: "+name); n != 1 {
		t.Fatalf("STATE-EXIT logged %d times want 1", n)
	}
}

// TestJournalLatchLegacyFileSeed: after an AGENT RESTART the latch
// file exists with an empty owner registry — ExitFrom must seed the
// declared owners so the FIRST releaser cannot clear a latch the
// other hygiene may still be failing under (the pre-owner-scoping
// bug this store contract exists to kill).
func TestJournalLatchLegacyFileSeed(t *testing.T) {
	s, _, _ := newTestStore(t)
	name := latchdefs.LatchJournalUnreadable
	s.Enter(name, "") // pre-restart file, no recorded owners

	// Worker comes back healthy and releases first.
	s.ExitFrom(name, "workerhygiene", nil)
	if !s.Exists(name) {
		t.Fatal("first post-restart release cleared the shared latch")
	}
	// Controller's next blind read re-asserts; its later release is
	// the last one and exits.
	s.EnterFrom(name, "controllerhygiene", "still blind")
	s.ExitFrom(name, "controllerhygiene", nil)
	if s.Exists(name) {
		t.Fatal("latch stuck after every declared owner released")
	}
}

// TestRegisterActiveOwnerPostRestartSeed: RegisterActiveOwner is what
// keeps a post-restart ExitFrom from seeding phantom holds for
// producers that never run on this node. journal-unreadable declares
// {workerhygiene, controllerhygiene}; on a worker-only node only
// workerhygiene registers, so the legacy-file seed intersects down to
// the live set and the worker's release exits the latch instead of
// leaving a controllerhygiene hold nothing will ever release.
func TestRegisterActiveOwnerPostRestartSeed(t *testing.T) {
	name := latchdefs.LatchJournalUnreadable

	t.Run("worker-only node releases cleanly", func(t *testing.T) {
		s, _, _ := newTestStore(t)
		s.RegisterActiveOwner("workerhygiene")
		s.Enter(name, "") // pre-restart file, no recorded owners

		s.ExitFrom(name, "workerhygiene", nil)
		if s.Exists(name) {
			t.Fatal("phantom controllerhygiene hold kept the latch " +
				"past the last live owner's release")
		}
	})

	t.Run("both producers keep staged holds", func(t *testing.T) {
		s, _, _ := newTestStore(t)
		s.RegisterActiveOwner("workerhygiene")
		s.RegisterActiveOwner("controllerhygiene")
		s.Enter(name, "")

		// Worker's release leaves the seeded controllerhygiene hold —
		// the intersected set is stored back as the owner registry.
		s.ExitFrom(name, "workerhygiene", nil)
		if !s.Exists(name) {
			t.Fatal("latch cleared while registered controllerhygiene holds")
		}
		s.ExitFrom(name, "controllerhygiene", nil)
		if s.Exists(name) {
			t.Fatal("latch stuck after every registered owner released")
		}
	})

	t.Run("unregistered owner cannot release", func(t *testing.T) {
		s, _, _ := newTestStore(t)
		s.RegisterActiveOwner("workerhygiene")
		s.Enter(name, "")

		// A controllerhygiene release on a node where it never
		// registered must not touch the worker's seeded hold.
		s.ExitFrom(name, "controllerhygiene", nil)
		if !s.Exists(name) {
			t.Fatal("unregistered owner's release cleared the latch")
		}
		s.ExitFrom(name, "workerhygiene", nil)
		if s.Exists(name) {
			t.Fatal("registered owner's release did not exit the latch")
		}
	})
}

// TestRegisterActiveOwnerSharedAcrossHandles: the active-producer set
// lives on the per-dir sharedState, so a registration through one
// Shared handle is visible to every other handle over the same dir —
// production wires stores through subframe.StoreAt/Shared, never New.
func TestRegisterActiveOwnerSharedAcrossHandles(t *testing.T) {
	dir := t.TempDir()
	clk := &testClock{now: time.Unix(1700000000, 0)}
	a := Shared(dir, "", clk.fn, nil)
	b := Shared(dir, "", clk.fn, nil)
	name := latchdefs.LatchJournalUnreadable

	a.RegisterActiveOwner("workerhygiene")
	a.Enter(name, "")

	// b never registered anything itself — the release still seeds
	// only the live producers because a's registration is shared.
	b.ExitFrom(name, "workerhygiene", nil)
	if a.Exists(name) {
		t.Fatal("registration through handle a not visible to handle b")
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

// RateOKIn/RateSpendIn with dir="" fall back to the Store's own Dir —
// the same default RateOK/RateSpend carry (controllerhygiene's
// rateOK(dir,...) parity for budgets outside Dir).
func TestRateSpendInEmptyDirUsesStoreDir(t *testing.T) {
	s, _, _ := newTestStore(t)
	s.RateSpendIn("", "budget-x")
	if got := testutil.ReadFile(t, filepath.Join(s.Dir, "budget-x")); got != "1700000000\n" {
		t.Fatalf("budget content = %q", got)
	}
	if s.RateOKIn("", "budget-x", time.Hour) {
		t.Fatal("just-spent budget must not be ok")
	}
	// An explicit dir stays independent of the fallback.
	if !s.RateOKIn(t.TempDir(), "budget-x", time.Hour) {
		t.Fatal("budget absent in an explicit dir must be ok")
	}
}

// StampLastRun no-ops on an empty Dir — the path helpers produce bare
// filenames there and a watchdog-less host must not stamp CWD.
func TestStampLastRunEmptyDirNoop(t *testing.T) {
	s := New("", "", nil, nil)
	s.StampLastRun() // must not panic or write
}

// Incr returns 0 when the epoch write fails — the streak is lost,
// never invented (ctr_inc parity).
func TestIncrWriteFailureReturnsZero(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "missing"), "", nil, nil)
	if got := s.Incr("consecutive-x"); got != 0 {
		t.Fatalf("Incr = %d want 0 on unwritable dir", got)
	}
}

// Heartbeat/InitHeartbeatFiles on a Dir that cannot be created:
// Heartbeat warns and returns (best-effort, same contract as the
// MkdirAll-fail branch in appendFile), InitHeartbeatFiles
// propagates the mkdir error.
func TestHeartbeatMkdirFailure(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	clk := &testClock{now: time.Unix(1700000000, 0)}
	s := New(filepath.Join(blocker, "sub"), "", clk.fn, nil)
	s.Heartbeat() // must not panic
	if err := s.InitHeartbeatFiles(); err == nil ||
		!strings.Contains(err.Error(), "mkdir") {
		t.Fatalf("InitHeartbeatFiles err = %v, want mkdir failure", err)
	}
}

// A latch path that cannot be removed (a non-empty dir squatting on
// state-<name>) reports the exit as not-taken — no STATE-EXIT line.
func TestExitRemoveFailureKeepsLatch(t *testing.T) {
	s, _, logFile := newTestStore(t)
	s.Enter("real", "") // seed the log so absence is assertable
	p := s.Path("squat")
	if err := os.MkdirAll(filepath.Join(p, "inner"), 0o755); err != nil {
		t.Fatal(err)
	}
	if s.Exit("squat", nil) {
		t.Fatal("Exit reported removal of an unremovable latch")
	}
	if strings.Contains(testutil.ReadFile(t, logFile), "STATE-EXIT: squat") {
		t.Fatal("STATE-EXIT logged for a latch that survived removal")
	}
}

// ExitFrom on a latch whose file vanished underneath (removed
// out-of-band before the last owner released) exits quietly: no
// STATE-EXIT line, no cleanup run.
func TestExitFromMissingLatchFile(t *testing.T) {
	s, _, logFile := newTestStore(t)
	s.EnterFrom("wedged", "a", "")
	if err := os.Remove(s.Path("wedged")); err != nil {
		t.Fatal(err)
	}
	var cleaned bool
	s.ExitFrom("wedged", "a", func() { cleaned = true })
	if cleaned {
		t.Fatal("cleanup ran on a vanished latch")
	}
	if strings.Contains(testutil.ReadFile(t, logFile), "STATE-EXIT: wedged") {
		t.Fatal("STATE-EXIT logged for a latch that was already gone")
	}
}

// ExitFrom passes the cleanup hook through on a real exit — the
// journal wiring drops its suspect budgets through it.
func TestExitFromRunsCleanup(t *testing.T) {
	s, _, logFile := newTestStore(t)
	s.EnterFrom("wedged", "a", "")
	var cleaned bool
	s.ExitFrom("wedged", "a", func() { cleaned = true })
	if !cleaned {
		t.Fatal("cleanup hook not run")
	}
	if !strings.Contains(testutil.ReadFile(t, logFile), "STATE-EXIT: wedged") {
		t.Fatal("STATE-EXIT missing after the last owner released")
	}
}
