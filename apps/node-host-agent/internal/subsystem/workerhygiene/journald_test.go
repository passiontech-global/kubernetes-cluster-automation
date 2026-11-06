// journald_test.go — A5 journald integrity (corruption/empty-journal
// rotate+vacuum) and the journal-unreadable blindness latch.
package workerhygiene

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// --- A5: journald integrity ---

func TestJournaldCorruptionRotates(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.journal = "File corruption detected at /var/log/journal/x.journal"
	for i := 0; i < 2; i++ {
		e.h.Cycle(context.Background())
	}
	if !e.sdRan("journalctl --rotate --vacuum-time=3d") {
		t.Fatal("corrupt journal should trigger rotate --vacuum-time=3d")
	}
}

func TestJournaldEmptyWhileActiveRotates(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.journal = "" // abnormally empty
	// …and the unfiltered `journalctl -n 1` probe errors too (no
	// sdReply → ENOENT) — journald itself is anomalous, so the
	// empty k0sworker window counts as corruption evidence.
	for i := 0; i < 2; i++ {
		e.h.Cycle(context.Background())
	}
	if !e.sdRan("journalctl --rotate --vacuum-time=3d") {
		t.Fatal("empty journal for active unit should trigger rotate")
	}
}

// TestJournaldEmptyAndUnfilteredEmptyRotates: same remediation when
// the second probe answers but the whole journal is silent.
func TestJournaldEmptyAndUnfilteredEmptyRotates(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.journal = ""
	e.sdReply["journalctl -n 1"] = "" // journald answers — with nothing
	for i := 0; i < 2; i++ {
		e.h.Cycle(context.Background())
	}
	if !e.sdRan("journalctl --rotate --vacuum-time=3d") {
		t.Fatal("journald-wide silence should trigger rotate")
	}
}

// TestJournaldQuietUnitHealthyJournaldNoRotate is the false-
// positive guard: an empty k0sworker window is only corruption
// evidence when journald ITSELF is anomalous. A healthy-but-quiet
// unit (journald returns real entries unfiltered) must NOT spend
// the rotate+vacuum remedy every cooldown.
func TestJournaldQuietUnitHealthyJournaldNoRotate(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.journal = "" // no k0sworker lines in 10m — just a quiet unit
	e.sdReply["journalctl -n 1"] =
		"May 01 12:00:00 node-a systemd[1]: Started Daily Cleanup.\n"
	for i := 0; i < 2; i++ {
		e.h.Cycle(context.Background())
	}
	if e.sdRan("journalctl --rotate --vacuum-time=3d") {
		t.Fatal("quiet unit on a healthy journald must not trigger rotate+vacuum")
	}
	if !e.sdRan("journalctl -n 1 --no-pager") {
		t.Fatal("the unfiltered journald probe should have run for the empty case")
	}
}

// TestJournaldExecErrorNoVacuum: an exec-level read failure
// (nsenter/journalctl timeout) is journal-UNREADABLE, not corruption
// — it must never spend the rotate+vacuum remedy.
func TestJournaldExecErrorNoVacuum(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.journalErr = errors.New("exec timeout")
	for i := 0; i < 3; i++ {
		e.h.Cycle(context.Background())
	}
	if e.sdRan("journalctl --rotate --vacuum-time=3d") {
		t.Fatal("rotate+vacuum spent on a transient exec failure")
	}
}

// --- journal-unreadable blindness latch (journalwatch tracker) ---
// A broken journald (killed journalctl, "No journal files", or a
// journald-wide empty reply) blinds the 05/06 signature greps AND
// the A5 probe itself — this must surface as state-journal-unreadable,
// not just rotate+vacuum cooldowns.

func TestJournalUnreadableLatchesAfterConsecFails(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.journalErr = errors.New("signal: killed") // journalctl dies every read
	// Each cycle feeds up to two reads into the tracker (the lazy
	// journalOnce snapshot + the A5 probe) — one cycle is a streak
	// below Needed, three must have latched.
	e.h.Cycle(context.Background())
	if e.h.State.Exists(stateJournalUnreadable) {
		t.Fatal("latched before the streak reached Needed")
	}
	for i := 0; i < 2; i++ {
		e.h.Cycle(context.Background())
	}
	if !e.h.State.Exists(stateJournalUnreadable) {
		t.Fatal("state-journal-unreadable not latched after persistent read failures")
	}
	if n := strings.Count(logLines(t, e), "suspect: journal-unreadable"); n != 1 {
		t.Fatalf("suspect lines=%d want 1 on latch entry", n)
	}
	// Held latch: no repeat lines on later cycles.
	for i := 0; i < 3; i++ {
		e.h.Cycle(context.Background())
	}
	if n := strings.Count(logLines(t, e), "suspect: journal-unreadable"); n != 1 {
		t.Fatalf("suspect repeated while latch held: %d", n)
	}
}

func TestJournalUnreadableClearsOnRecovery(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.journalErr = errors.New("signal: killed")
	for i := 0; i < defaultJournalUnreadableNeeded; i++ {
		e.h.Cycle(context.Background())
	}
	if !e.h.State.Exists(stateJournalUnreadable) {
		t.Fatal("precondition: latch should be held")
	}
	e.journalErr = nil
	e.journal = "Oct 01 node k0sworker: healthy line\n"
	e.h.Cycle(context.Background())
	if e.h.State.Exists(stateJournalUnreadable) {
		t.Fatal("latch not cleared on first healthy read")
	}
	if n := strings.Count(logLines(t, e), "STATE-EXIT: journal-unreadable"); n != 1 {
		t.Fatalf("STATE-EXIT lines=%d want 1", n)
	}
}

func TestJournalUnreadableNoFireWithoutJournalDir(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	// No journal storage at all — journald legitimately absent is a
	// config, not a failure: reads failing forever must never latch.
	e.h.JournalReads.Dirs = []string{filepath.Join(t.TempDir(), "missing")}
	e.journalErr = errors.New("signal: killed")
	for i := 0; i < defaultJournalUnreadableNeeded+2; i++ {
		e.h.Cycle(context.Background())
	}
	if e.h.State.Exists(stateJournalUnreadable) {
		t.Fatal("latched without any journal storage — must not fire")
	}
	if n := strings.Count(logLines(t, e), "suspect: journal-unreadable"); n != 0 {
		t.Fatalf("suspect lines=%d want 0", n)
	}
}

func TestJournalUnreadableEmptyWindowSilentJournaldFires(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.journal = ""                    // empty 10m k0sworker window
	e.sdReply["journalctl -n 1"] = "" // …and journald-wide silence
	for i := 0; i < defaultJournalUnreadableNeeded; i++ {
		e.h.Cycle(context.Background())
	}
	if !e.h.State.Exists(stateJournalUnreadable) {
		t.Fatal("journald-wide silence should latch journal-unreadable")
	}
}

func TestJournalUnreadableQuietUnitNoFire(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.journal = "" // quiet k0sworker window…
	e.sdReply["journalctl -n 1"] =
		"Oct 01 node systemd[1]: Started Daily Cleanup.\n" // …but journald answers
	for i := 0; i < defaultJournalUnreadableNeeded+2; i++ {
		e.h.Cycle(context.Background())
	}
	if e.h.State.Exists(stateJournalUnreadable) {
		t.Fatal("quiet unit on healthy journald must not latch")
	}
}

func TestJournalUnreadableFilesGoneMarkerFires(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.journal = "No journal files were found.\n"
	for i := 0; i < defaultJournalUnreadableNeeded; i++ {
		e.h.Cycle(context.Background())
	}
	if !e.h.State.Exists(stateJournalUnreadable) {
		t.Fatal("'No journal files' reads should latch journal-unreadable")
	}
}
