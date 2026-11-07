// journal.go — the journal-read plumbing: JournalText (a read error
// maps to empty output — `journalctl ... 2>/dev/null | grep -c` == 0
// parity) feeding the journal-unreadable blindness accounting
// (classifyJournalRead + noteJournalRead + journalwatch.Tracker).
//
// The journal readers themselves are Config seams (JournalFn /
// JournalAnyFn); their defaults route through the shared
// platform/systemd client — nsenter-wrapped to the HOST journald —
// in ApplyDefaults.
package cdeps

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/journalwatch"
)

// journalSinceLayout is the journalctl --since timestamp format —
// the "2006-01-02 15:04:05" wall-clock contract the shell probes and
// the systemd.Client.Journal argv share.
const journalSinceLayout = "2006-01-02 15:04:05"

// JournalText returns the unit journal since `since`, mapping errors
// to empty — `journalctl ... 2>/dev/null | grep -c` parity (a failed
// journal read counts as 0 hits, never as wedge evidence). Every
// read also feeds the journal-unreadable accounting: a journald that
// persistently answers nothing while journal storage exists blinds
// ALL journal-grep checks, and that blindness must latch+log, not
// stay a per-cycle warning line.
func (d *Deps) JournalText(ctx context.Context, since time.Time) string {
	out, err := d.Cfg.JournalFn(ctx, d.Cfg.JournalUnit, since)
	d.noteJournalRead(ctx, out, err)
	if err != nil {
		d.State.AppendLogWarn(fmt.Sprintf(
			"controllerhygiene: journal read failed (unit=%s): %v — journal checks see 0 hits",
			d.Cfg.JournalUnit, err))
		return ""
	}
	return out
}

// classifyJournalRead reduces one journal-read result to the
// readable/unreadable verdict the tracker counts. A legitimately
// quiet unit window (err==nil, empty output) is ambiguous, so the
// unfiltered `journalctl -n 1` probe disambiguates — journald
// answering ANY line (even "-- No entries --") means the empty
// window was a quiet unit, while an error, a files-gone notice or
// literally zero bytes is journald-level blindness.
func (d *Deps) classifyJournalRead(ctx context.Context, out string, err error) (bool, string) {
	switch {
	case err != nil:
		return false, fmt.Sprintf("read failed: %v", err)
	case journalwatch.FilesGone(out):
		return false, "journalctl reports no journal files"
	case strings.TrimSpace(out) == "":
		uout, uerr := d.Cfg.JournalAnyFn(ctx)
		switch {
		case uerr != nil:
			return false, fmt.Sprintf("unfiltered probe failed: %v", uerr)
		case journalwatch.FilesGone(uout):
			return false, "journalctl reports no journal files"
		case strings.TrimSpace(uout) == "":
			return false, "journald-wide empty reply"
		}
	}
	return true, ""
}

// noteJournalRead feeds one classified journal read into the
// journal-unreadable tracker and drives the latch on transitions:
// enter → state-journal-unreadable + the suspect line (suspectLog
// then re-reminds at most once per SuspectLogCadence while the
// latch stays held); exit → STATE-EXIT. The journalDir gate lives
// inside the tracker — a host with no journal storage never fires.
func (d *Deps) noteJournalRead(ctx context.Context, out string, err error) {
	ok, detail := d.classifyJournalRead(ctx, out, err)
	enter, exit := d.JournalReads.NoteRead(ok)
	// Re-establish after external removal: janitor's 24h reap or a
	// manual rm can delete the file while the tracker stays latched,
	// and `enter` won't fire twice per episode — without this the
	// latch/metric/condition go dark mid-episode.
	if enter || (d.JournalReads.Latched() &&
		!d.State.Exists(StateJournalUnreadable)) {
		d.State.Enter(StateJournalUnreadable, detail)
		if enter {
			d.Cycles.WithLabelValues(CheckJournal, "journal_unreadable").Inc()
		}
	}
	if !ok && d.JournalReads.Latched() {
		d.State.SuspectLog(StateJournalUnreadable, fmt.Sprintf(
			"suspect: journal-unreadable %s — %d consecutive journal "+
				"reads produced nothing while journal storage exists; "+
				"every journal-grep check is blind",
			detail, d.JournalReads.Fails()), d.Cfg.SuspectLogCadence)
	}
	if exit {
		d.StateExit(StateJournalUnreadable)
	}
}
