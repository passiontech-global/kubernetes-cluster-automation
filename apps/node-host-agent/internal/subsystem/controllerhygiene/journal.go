// journal.go — the journal-read plumbing: journalText (a read error
// maps to empty output — `journalctl ... 2>/dev/null | grep -c` == 0
// parity) feeding the journal-unreadable blindness accounting
// (classifyJournalRead + noteJournalRead + journalwatch.Tracker).
//
// The journal readers themselves are Config seams (journalFn /
// journalAnyFn); their defaults route through the shared
// platform/systemd client — nsenter-wrapped to the HOST journald —
// in applyDefaults.
package controllerhygiene

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/journalwatch"
)

// journalSinceLayout is the journalctl --since timestamp format —
// the "2006-01-02 15:04:05" wall-clock contract the shell probes and
// the systemd.Client.Journal argv share.
const journalSinceLayout = "2006-01-02 15:04:05"

// journalText returns the unit journal since `since`, mapping errors
// to empty — `journalctl ... 2>/dev/null | grep -c` parity (a failed
// journal read counts as 0 hits, never as wedge evidence). Every
// read also feeds the journal-unreadable accounting: a journald that
// persistently answers nothing while journal storage exists blinds
// ALL journal-grep checks, and that blindness must latch+log, not
// stay a per-cycle warning line.
func (h *Hygiene) journalText(ctx context.Context, since time.Time) string {
	out, err := h.cfg.journalFn(ctx, h.cfg.JournalUnit, since)
	h.noteJournalRead(ctx, out, err)
	if err != nil {
		h.state.AppendLogWarn(fmt.Sprintf(
			"controllerhygiene: journal read failed (unit=%s): %v — journal checks see 0 hits",
			h.cfg.JournalUnit, err))
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
func (h *Hygiene) classifyJournalRead(ctx context.Context, out string, err error) (bool, string) {
	switch {
	case err != nil:
		return false, fmt.Sprintf("read failed: %v", err)
	case journalwatch.FilesGone(out):
		return false, "journalctl reports no journal files"
	case strings.TrimSpace(out) == "":
		uout, uerr := h.cfg.journalAnyFn(ctx)
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
func (h *Hygiene) noteJournalRead(ctx context.Context, out string, err error) {
	ok, detail := h.classifyJournalRead(ctx, out, err)
	enter, exit := h.journalReads.NoteRead(ok)
	// Re-establish after external removal: janitor's 24h reap or a
	// manual rm can delete the file while the tracker stays latched,
	// and `enter` won't fire twice per episode — without this the
	// latch/metric/condition go dark mid-episode.
	if enter || (h.journalReads.Latched() &&
		!h.state.Exists(stateJournalUnreadable)) {
		h.state.Enter(stateJournalUnreadable, detail)
		if enter {
			h.cycles.WithLabelValues(checkJournal, "journal_unreadable").Inc()
		}
	}
	if !ok && h.journalReads.Latched() {
		h.state.SuspectLog(stateJournalUnreadable, fmt.Sprintf(
			"suspect: journal-unreadable %s — %d consecutive journal "+
				"reads produced nothing while journal storage exists; "+
				"every journal-grep check is blind",
			detail, h.journalReads.Fails()), h.cfg.SuspectLogCadence)
	}
	if exit {
		h.stateExit(stateJournalUnreadable)
	}
}
