// Package journalwatch is the shared consecutive-failure accounting
// behind the journal-unreadable blindness latch. Every subsystem
// that greps the systemd journal (controllerhygiene's k0scontroller
// windows, workerhygiene's k0sworker snapshot + A5 probe) classifies
// each read — usable journal data vs a read that produced nothing
// while journald should be answering — and reports the verdict here.
//
// Field incident 2026-11 (cicd controller 103.186.101.30): journald
// was broken — journalctl returned "No journal files"/empty (or was
// killed) although the journal files existed. Every journal-based
// check silently saw "0 hits": a dead journald masks the exact
// events the watchdog greps for, and NOTHING surfaced that the
// checks were blind. The tracker turns "reads keep producing
// nothing" into a single state-journal-unreadable latch + one
// suspect log line, and clears it when reads recover.
//
// The one deliberate NO-fire case: a host with no journal storage
// at all (no /var/log/journal, no /run/log/journal). There journald
// is legitimately absent — every read failing is configuration, not
// a fault.
package journalwatch

import (
	"os"
	"strings"
)

// DefaultNeeded is the consecutive-failed-read budget before the
// latch may enter — one bad read is a blip (timeout under load, a
// rotating journald), Needed in a row while journal storage exists
// is blindness.
const DefaultNeeded = 5

// Tracker accumulates consecutive journal-read failures and decides
// when the blindness is persistent enough to surface. It owns ONLY
// the counting + the journal-storage gate; the caller turns the
// transitions into its own state-* latch and log lines (per-
// subsystem conventions). Not goroutine-safe — one tracker per
// cycle loop.
type Tracker struct {
	// Needed is the consecutive-failure budget; <=0 → DefaultNeeded.
	Needed int
	// Dirs are the journal storage roots probed by Present — the
	// latch can only fire while at least one exists. Pass the
	// HOST-visible paths (/host/var/log/journal in a container,
	// /var/log/journal standalone), covering both persistent and
	// volatile (/run/log/journal) storage.
	Dirs []string
	// Stat probes dir existence; nil → os.Stat (test seam).
	Stat func(string) (os.FileInfo, error)

	fails   int
	latched bool
}

func (t *Tracker) needed() int {
	if t.Needed <= 0 {
		return DefaultNeeded
	}
	return t.Needed
}

// Present reports whether any configured journal storage dir
// exists — the "journald is installed" witness. With no dir the
// host legitimately has no journald: reads failing is config, not a
// fault, and the tracker must never fire.
func (t *Tracker) Present() bool {
	stat := t.Stat
	if stat == nil {
		stat = os.Stat
	}
	for _, d := range t.Dirs {
		if _, err := stat(d); err == nil {
			return true
		}
	}
	return false
}

// NoteRead records one journal-read verdict and reports the latch
// transitions:
//
//   - ok=false is a read that produced no usable journal data while
//     journald should be answering: nonzero exit / killed journalctl,
//     a "No journal files" notice, or a journald-wide empty reply
//     (the caller disambiguates a legitimately-quiet unit — e.g. via
//     an unfiltered `journalctl -n 1` probe — BEFORE reporting here).
//   - enter=true fires exactly once per episode, when the streak
//     reaches Needed AND journal storage exists — the caller latches
//     state-journal-unreadable + logs once.
//   - exit=true fires when a good read arrives while latched (or the
//     journal storage vanished while latched — the config changed,
//     not the blindness) — the caller clears the latch (STATE-EXIT).
func (t *Tracker) NoteRead(ok bool) (enter, exit bool) {
	if ok {
		t.fails = 0
		if t.latched {
			t.latched = false
			return false, true
		}
		return false, false
	}
	t.fails++
	if t.latched {
		if !t.Present() {
			t.latched = false
			return false, true
		}
		return false, false
	}
	if t.fails >= t.needed() && t.Present() {
		t.latched = true
		return true, false
	}
	return false, false
}

// Fails reports the current consecutive-failure streak (tests/debug).
func (t *Tracker) Fails() int { return t.fails }

// Latched reports whether the tracker currently holds the latched
// state (tests/debug — the on-disk latch is the caller's business).
func (t *Tracker) Latched() bool { return t.latched }

// FilesGone reports whether journalctl output carries its
// "No journal files were found." notice — journald cannot open the
// journal storage although journalctl itself ran. On a read that
// otherwise succeeded (rc=0) this text is the only blindness
// evidence; stderr must be folded into the output for it to be
// seen (the notice is a journald diagnostic, not journal content).
func FilesGone(out string) bool {
	return strings.Contains(strings.ToLower(out), "no journal files")
}
