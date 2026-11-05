// journal_test.go — journal-unreadable blindness latch (journalwatch tracker).

package controllerhygiene

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

// --- journal-unreadable blindness latch (journalwatch tracker) ---
// Field incident: journald broken on a cicd controller — journalctl
// killed/empty although journal files exist — every journal-grep
// check silently saw "0 hits" with no persistent signal.

func TestJournalUnreadableLatchesAfterConsecFails(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()
	e.jerr = errors.New("signal: killed") // journalctl dies every read
	for i := 0; i < defaultJournalUnreadableNeeded-1; i++ {
		e.h.Cycle(ctx)
		if e.hasState(stateJournalUnreadable) {
			t.Fatalf("latched early at cycle %d", i+1)
		}
	}
	e.h.Cycle(ctx)
	if !e.hasState(stateJournalUnreadable) {
		t.Fatal("state-journal-unreadable not latched after Needed failed reads")
	}
	if n := countLogLines(t, e, "suspect: journal-unreadable"); n != 1 {
		t.Fatalf("suspect lines=%d want 1 on latch entry", n)
	}
	// Held latch: no repeat inside the cadence window.
	for i := 0; i < 3; i++ {
		e.h.Cycle(ctx)
	}
	if n := countLogLines(t, e, "suspect: journal-unreadable"); n != 1 {
		t.Fatalf("suspect repeated while latch held: %d", n)
	}
}

func TestJournalUnreadableClearsOnRecovery(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()
	e.jerr = errors.New("signal: killed")
	for i := 0; i < defaultJournalUnreadableNeeded; i++ {
		e.h.Cycle(ctx)
	}
	if !e.hasState(stateJournalUnreadable) {
		t.Fatal("precondition: latch should be held")
	}
	e.jerr = nil
	e.journal = "Oct 01 node k0s: healthy line\n"
	e.h.Cycle(ctx)
	if e.hasState(stateJournalUnreadable) {
		t.Fatal("latch not cleared on first healthy read")
	}
	if n := countLogLines(t, e, "STATE-EXIT: journal-unreadable"); n != 1 {
		t.Fatalf("STATE-EXIT lines=%d want 1", n)
	}
}

func TestJournalUnreadableNoFireWithoutJournalDir(t *testing.T) {
	e := fixture(t)
	// No journal storage at all — journald legitimately absent is a
	// config, not a failure: reads failing forever must never latch.
	e.h.journalReads.Dirs = []string{filepath.Join(t.TempDir(), "missing")}
	e.jerr = errors.New("signal: killed")
	for i := 0; i < defaultJournalUnreadableNeeded+2; i++ {
		e.h.Cycle(context.Background())
	}
	if e.hasState(stateJournalUnreadable) {
		t.Fatal("latched without any journal storage — must not fire")
	}
	if n := countLogLines(t, e, "suspect: journal-unreadable"); n != 0 {
		t.Fatalf("suspect lines=%d want 0", n)
	}
}

func TestJournalUnreadableEmptyWindowQuietUnitNoFire(t *testing.T) {
	e := fixture(t)
	// Empty unit window BUT the unfiltered probe answers — a quiet
	// unit on a healthy journald must never count as blindness.
	e.journal = ""
	e.jany = "-- No entries --\n"
	for i := 0; i < defaultJournalUnreadableNeeded+2; i++ {
		e.h.Cycle(context.Background())
	}
	if e.hasState(stateJournalUnreadable) {
		t.Fatal("quiet unit on healthy journald must not latch")
	}
}

func TestJournalUnreadableEmptyWindowSilentJournaldFires(t *testing.T) {
	e := fixture(t)
	// Empty unit window AND the unfiltered journald probe returns
	// literally nothing — journald-level blindness.
	e.journal = ""
	e.jany = ""
	for i := 0; i < defaultJournalUnreadableNeeded; i++ {
		e.h.Cycle(context.Background())
	}
	if !e.hasState(stateJournalUnreadable) {
		t.Fatal("journald-wide silence should latch journal-unreadable")
	}
}

func TestJournalUnreadableFilesGoneMarkerFires(t *testing.T) {
	e := fixture(t)
	// journalctl ran but reports it cannot open the journal storage.
	e.journal = "No journal files were found.\n"
	for i := 0; i < defaultJournalUnreadableNeeded; i++ {
		e.h.Cycle(context.Background())
	}
	if !e.hasState(stateJournalUnreadable) {
		t.Fatal("'No journal files' reads should latch journal-unreadable")
	}
}
