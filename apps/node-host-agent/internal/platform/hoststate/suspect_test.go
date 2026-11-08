// suspect_test.go — the last-suspect-<key> dedupe budgets: the Exit
// + clear wrappers, the family-wide clear, and the budget-file
// contract SuspectLog already pins elsewhere.

package hoststate

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// suspectBudgetPath is the on-disk budget file for a key.
func suspectBudgetPath(s *Store, key string) string {
	return filepath.Join(s.Dir, SuspectBudgetPrefix+key)
}

// TestExitClearSuspectGatedOnExit: the budget only goes when Exit
// actually removed the latch — a no-op exit (nothing on disk) must
// leave the throttle untouched. (Multi-owner latches never ride this
// wrapper: the journal wiring releases through Store.ExitFrom with a
// cleanup hook, whose owner-gated exit is pinned in hoststate_test.)
func TestExitClearSuspectGatedOnExit(t *testing.T) {
	s, _, _ := newTestStore(t)

	// No latch on disk → Exit false → the budget survives.
	s.SuspectLog("blind", "still blind", time.Hour)
	s.ExitClearSuspect("blind")
	if _, err := os.Stat(suspectBudgetPath(s, "blind")); err != nil {
		t.Fatalf("no-op exit must not clear the budget: %v", err)
	}

	// A real exit clears the budget with it.
	s.Enter("blind", "")
	s.ExitClearSuspect("blind")
	if _, err := os.Stat(suspectBudgetPath(s, "blind")); !os.IsNotExist(err) {
		t.Fatalf("true exit must clear the budget: %v", err)
	}
}

// TestExitClearSuspect: the wrapper is Exit plus removal of THIS
// latch's dedupe budget — a cleared condition must not suppress the
// first line of a re-incident under a stale epoch.
func TestExitClearSuspect(t *testing.T) {
	s, _, logFile := newTestStore(t)

	s.Enter("egress-blackhole", "")
	s.SuspectLog("egress-blackhole", "still blackholed", time.Hour)
	if _, err := os.Stat(suspectBudgetPath(s, "egress-blackhole")); err != nil {
		t.Fatalf("SuspectLog should have spent a budget: %v", err)
	}

	s.ExitClearSuspect("egress-blackhole")

	if s.Exists("egress-blackhole") {
		t.Fatal("latch still present after ExitClearSuspect")
	}
	if _, err := os.Stat(suspectBudgetPath(s, "egress-blackhole")); !os.IsNotExist(err) {
		t.Fatal("dedupe budget must be dropped on latch exit")
	}
	if !strings.Contains(testutil.ReadFile(t, logFile), "STATE-EXIT: egress-blackhole") {
		t.Fatal("ExitClearSuspect must log the STATE-EXIT transition")
	}

	// The re-incident's first line logs immediately (no stale epoch).
	s.SuspectLog("egress-blackhole", "re-incident", time.Hour)
	if !strings.Contains(testutil.ReadFile(t, logFile), "re-incident") {
		t.Fatal("cleared budget still suppressed the re-incident's first line")
	}
}

// TestExitClearAllSuspects: a latch exit IS an incident boundary —
// the WHOLE last-suspect-* family goes, including NON-latch keys
// (egress-probe-<ip> & co.) that have no state-* twin to exit with.
func TestExitClearAllSuspects(t *testing.T) {
	s, _, _ := newTestStore(t)

	s.Enter("overlay-egress", "")
	s.RateSpend(SuspectBudgetPrefix + "overlay-egress")
	s.RateSpend(SuspectBudgetPrefix + "egress-probe-10.0.0.1")
	s.RateSpend(SuspectBudgetPrefix + "conntrack-parse")
	// An unrelated budget family must survive the clear.
	s.RateSpend("last-restart")

	s.ExitClearAllSuspects("overlay-egress")

	if s.Exists("overlay-egress") {
		t.Fatal("latch still present after ExitClearAllSuspects")
	}
	ents, err := os.ReadDir(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), SuspectBudgetPrefix) {
			t.Fatalf("suspect budget survived the family clear: %s", e.Name())
		}
	}
	if s.RateOK("last-restart", time.Hour) {
		t.Fatal("non-suspect budget must survive ExitClearAllSuspects")
	}
}

// TestClearSuspect: an absent budget is already clear (no-op, no
// error surfacing), a spent one is removed so the next SuspectLog
// logs immediately.
func TestClearSuspect(t *testing.T) {
	s, _, _ := newTestStore(t)

	s.ClearSuspect("never-spent") // must not panic or log a failure

	s.RateSpend(SuspectBudgetPrefix + "conntrack-parse")
	if s.RateOK(SuspectBudgetPrefix+"conntrack-parse", time.Hour) {
		t.Fatal("budget should be spent")
	}
	s.ClearSuspect("conntrack-parse")
	if !s.RateOK(SuspectBudgetPrefix+"conntrack-parse", time.Hour) {
		t.Fatal("cleared budget must read as unspent")
	}
}

// TestSuspectLogAtomicCheckSpend: SuspectLog's check+spend must be
// one atomic step (RateTrySpend) — goroutines racing the same key in
// one cadence window must not all pass the check-then-spend gap and
// each emit a line. Exactly ONE line lands; the budget is spent once.
func TestSuspectLogAtomicCheckSpend(t *testing.T) {
	s, _, logFile := newTestStore(t)

	const racers = 32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			s.SuspectLog("conntrack-parse", "deduped line", time.Hour)
		}()
	}
	close(start)
	wg.Wait()

	if got := strings.Count(testutil.ReadFile(t, logFile), "deduped line"); got != 1 {
		t.Fatalf("SuspectLog emitted %d lines under the race, want exactly 1", got)
	}
	if _, err := os.Stat(suspectBudgetPath(s, "conntrack-parse")); err != nil {
		t.Fatalf("the single spend must leave the budget stamped: %v", err)
	}
}

// TestClearAllSuspects: every last-suspect-* file goes, other files
// in the dir stay.
func TestClearAllSuspects(t *testing.T) {
	s, _, _ := newTestStore(t)

	s.RateSpend(SuspectBudgetPrefix + "a")
	s.RateSpend(SuspectBudgetPrefix + "b")
	latch := s.Path("held-latch")
	s.Enter("held-latch", "")

	s.ClearAllSuspects()

	if _, err := os.Stat(suspectBudgetPath(s, "a")); !os.IsNotExist(err) {
		t.Fatal("budget a survived")
	}
	if _, err := os.Stat(suspectBudgetPath(s, "b")); !os.IsNotExist(err) {
		t.Fatal("budget b survived")
	}
	if !s.Exists("held-latch") || testutil.ReadFile(t, latch) == "" {
		t.Fatal("non-suspect state files must survive the clear")
	}
}
