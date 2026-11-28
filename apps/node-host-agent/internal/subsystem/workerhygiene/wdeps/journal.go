// journal.go — the journal-unreadable accounting shared between
// Cycle's k0sworker snapshot and the A5 journald-integrity check:
// every journal read is classified through NoteJournalRead so the
// blindness latch fires once per episode whichever probe saw it.
package wdeps

import (
	"context"
	"fmt"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/journalwatch"
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
// journal-unreadable tracker and drives the latch on transitions —
// through the STORE's multi-owner API under this subsystem's owner
// id (journalwatch.OwnerWorkerHygiene): every blind read registers
// the workerhygiene hold on the shared state-journal-unreadable
// latch, so controllerhygiene's episode can never be deleted by a
// healthy read here (and vice versa) — the file leaves only when
// BOTH hygienes have released.
//
// enter → state-journal-unreadable + the suspect line, logged once
// per latch entry (the State.Exists gate — the latch dedupes the
// alert AND its first line, like the MTU check). The journalDir gate
// lives inside the tracker: a host with no journald storage never
// fires — every read failing is then configuration, not a fault.
// Held blind reads keep asserting the hold, which also refreshes the
// latch mtime (the janitor's 24h reap must not retire a live
// episode).
func (d *Deps) journalBlindnessConfig(disambiguate func(context.Context) (bool, string)) journalwatch.BlindnessConfig {
	const owner = journalwatch.OwnerWorkerHygiene
	name := StateJournalUnreadable
	return journalwatch.BlindnessConfig{
		Tracker:           &d.JournalReads,
		Store:             d.State,
		Owner:             owner,
		Latch:             name,
		DisambiguateEmpty: disambiguate,
		OnBlind: func(enter, latched bool, detail string, fails int) {
			if enter && !d.State.Exists(name) {
				// This owner's streak crossed Needed and the latch file is
				// not on disk: enter + the one-shot suspect line + counter.
				d.State.EnterFrom(name, owner, detail)
				d.State.AppendLog(fmt.Sprintf(
					"suspect: journal-unreadable %s — %d consecutive journal "+
						"reads produced nothing while journal storage exists; "+
						"every journal-grep check is blind",
					detail, fails))
				d.CycleResult(CheckJournald, "journal_unreadable")
				return
			}
			if enter || latched {
				// Held: re-assert the hold every blind read.
				d.State.EnterFrom(name, owner, detail)
			}
		},
	}
}

func (d *Deps) NoteJournalRead(ok bool, detail string) {
	journalwatch.TrackRead(d.journalBlindnessConfig(nil), ok, detail)
}

// ClassifyAndTrackJournal classifies (out, err) via journalwatch.ClassifyAndTrack
// with optional ClassEmpty disambiguation, driving the shared blindness latch.
func (d *Deps) ClassifyAndTrackJournal(ctx context.Context, out string, err error,
	disambiguate func(context.Context) (bool, string)) {
	journalwatch.ClassifyAndTrack(ctx, d.journalBlindnessConfig(disambiguate), out, err)
}
