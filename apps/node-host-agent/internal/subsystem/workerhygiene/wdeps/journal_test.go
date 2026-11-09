// journal_test.go — the journal-unreadable accounting: the latch
// fires once per episode over the Needed streak (only while journal
// storage exists), re-establishes after external removal, exits on
// the first healthy read and logs exactly one suspect line per
// entry.
package wdeps_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/journalwatch"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// TestNoteJournalReadStreakLatches — 4 failing reads arm nothing
// (Needed=5), the 5th enters the latch with one suspect line and the
// journald-integrity counter, further failing reads stay quiet, the
// latch re-establishes after an external file removal without a new
// line, and a healthy read exits.
func TestNoteJournalReadStreakLatches(t *testing.T) {
	e := fixture(t)
	latch := e.D.State.Path(wdeps.StateJournalUnreadable)
	// The fixture's journal dir exists — the storage gate is open.

	for range 4 {
		e.D.NoteJournalRead(false, "journalctl -u k0sworker: empty")
	}
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatalf("latch fired early: %v", err)
	}
	if strings.Contains(e.LogLines(t), "journal-unreadable") {
		t.Fatalf("suspect line before the streak:\n%s", e.LogLines(t))
	}

	e.D.NoteJournalRead(false, "journalctl -u k0sworker: empty")
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("latch file missing after the Needed streak: %v", err)
	}
	log := e.LogLines(t)
	if strings.Count(log, "suspect: journal-unreadable") != 1 {
		t.Fatalf("suspect lines=%d want 1:\n%s",
			strings.Count(log, "suspect: journal-unreadable"), log)
	}
	if got := promtestutil.ToFloat64(
		e.D.Cycles.WithLabelValues(wdeps.CheckJournald, "journal_unreadable")); got != 1 {
		t.Fatalf("journal_unreadable counter=%d want 1", int(got))
	}

	// More blind reads: latched, no new suspect line, no counter bump.
	for range 2 {
		e.D.NoteJournalRead(false, "still blind")
	}
	if strings.Count(e.LogLines(t), "suspect: journal-unreadable") != 1 {
		t.Fatalf("entry must log once:\n%s", e.LogLines(t))
	}
	if got := promtestutil.ToFloat64(
		e.D.Cycles.WithLabelValues(wdeps.CheckJournald, "journal_unreadable")); got != 1 {
		t.Fatalf("counter re-bumped: %d", int(got))
	}

	// The latch file vanishes under the tracker (janitor reap, rm) —
	// the next blind read re-establishes the latch, still without a
	// new line (the once-per-episode edge already fired).
	if err := os.Remove(latch); err != nil {
		t.Fatal(err)
	}
	e.D.NoteJournalRead(false, "after reap")
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("latch not re-established: %v", err)
	}
	if strings.Count(e.LogLines(t), "suspect: journal-unreadable") != 1 {
		t.Fatalf("re-establish must stay silent:\n%s", e.LogLines(t))
	}

	// A healthy read exits the latch.
	e.D.NoteJournalRead(true, "journal back")
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatalf("healthy read must exit the latch: %v", err)
	}
	if !strings.Contains(e.LogLines(t), "STATE-EXIT: journal-unreadable") {
		t.Fatalf("missing STATE-EXIT:\n%s", e.LogLines(t))
	}
}

// TestNoteJournalReadNoStorage — a host with no journald storage
// never fires: failing reads are configuration, not blindness.
func TestNoteJournalReadNoStorage(t *testing.T) {
	e := fixture(t)
	e.D.JournalReads = journalwatch.NewUnreadableTrackerForOwner(
		e.D.State, []string{filepath.Join(t.TempDir(), "no-journal")}, 2,
		journalwatch.OwnerWorkerHygiene)
	for range 5 {
		e.D.NoteJournalRead(false, "read fails")
	}
	if _, err := os.Stat(e.D.State.Path(wdeps.StateJournalUnreadable)); !os.IsNotExist(err) {
		t.Fatal("latch fired without journal storage")
	}
	if strings.Contains(e.LogLines(t), "journal-unreadable") {
		t.Fatalf("storage-less host logged:\n%s", e.LogLines(t))
	}
}

// TestNoteJournalReadHealthyQuiet — healthy reads on a healthy host
// leave no trace at all.
func TestNoteJournalReadHealthyQuiet(t *testing.T) {
	e := fixture(t)
	e.D.NoteJournalRead(true, "ok window")
	if e.LogLines(t) != "" {
		t.Fatalf("healthy read logged:\n%s", e.LogLines(t))
	}
	if _, err := os.Stat(e.D.State.Path(wdeps.StateJournalUnreadable)); !os.IsNotExist(err) {
		t.Fatal("healthy read latched")
	}
}
