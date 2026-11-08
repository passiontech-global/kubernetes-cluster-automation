// journal.go — the journal-unreadable accounting shared between
// Cycle's k0sworker snapshot and the A5 journald-integrity check:
// every journal read is classified through NoteJournalRead so the
// blindness latch fires once per episode whichever probe saw it.
package wdeps

import (
	"fmt"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
)

// journalWindow mirrors the runner's `journalctl -u k0sworker
// --since "-10 min"` shared snapshot.
const journalWindow = "-10 min"

// StateJournalUnreadable is the blindness latch the journal-read
// accounting sets: journald installed (journal storage exists) but
// every read produces nothing — the 05/06 signature greps and the
// nodereporter journal monitors are blind until it clears.
const StateJournalUnreadable = latchdefs.LatchJournalUnreadable

// NoteJournalRead feeds one classified journal read into the
// journal-unreadable tracker and drives the latch on transitions:
// enter → state-journal-unreadable + the suspect line, logged once
// per latch entry (the State.Exists gate — the latch dedupes the
// alert AND its first line, like the MTU check); exit → STATE-EXIT
// when a read finally returns journal data (or the journal storage
// vanished — config change, not blindness). The journalDir gate
// lives inside the tracker: a host with no journald storage never
// fires — every read failing is then configuration, not a fault.
func (d *Deps) NoteJournalRead(ok bool, detail string) {
	enter, exit := d.JournalReads.NoteRead(ok)
	if enter && !d.State.Exists(StateJournalUnreadable) {
		d.State.Enter(StateJournalUnreadable, detail)
		d.State.AppendLog(fmt.Sprintf(
			"suspect: journal-unreadable %s — %d consecutive journal "+
				"reads produced nothing while journal storage exists; "+
				"every journal-grep check is blind",
			detail, d.JournalReads.Fails()))
		d.CycleResult(CheckJournald, "journal_unreadable")
	} else if d.JournalReads.Latched() &&
		!d.State.Exists(StateJournalUnreadable) {
		// Re-establish after external removal: the latch file can
		// vanish while the tracker stays latched (janitor 24h reap,
		// manual rm) and `enter` is a once-per-episode edge that
		// won't fire again — without this the metric/condition go
		// dark mid-episode.
		d.State.Enter(StateJournalUnreadable, detail)
	}
	if exit {
		d.State.Exit(StateJournalUnreadable, nil)
	}
}
