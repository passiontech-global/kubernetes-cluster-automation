// journal.go — the journal-read plumbing: JournalText (a read error
// maps to empty output — `journalctl ... 2>/dev/null | grep -c` == 0
// parity) feeding the journal-unreadable blindness accounting
// (classifyJournalRead + noteJournalRead + journalwatch.Tracker).
//
// The journal readers ride the single HostExecFn seam now —
// journalRead/journalAnyRead build the journalctl argv; the seam's
// default routes through the shared platform/systemd client,
// nsenter-wrapped to the HOST journald (the old raw exec read the
// container's journal view, empty in the DaemonSet).
package cdeps

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/journalwatch"
)

// journalRead returns the unit journal window since `since` —
// `timeout 15 journalctl -u <unit> --since <ts> --no-pager` parity
// over the HostExecFn seam. stderr is folded in (combined=true) so
// journald's own corrupt/no-journal-files diagnostics stay visible
// to classifyJournalRead; hostexec's 16MiB capture cap is the old
// maxJournalBytes bound.
func (d *Deps) journalRead(ctx context.Context, unit string, since time.Time) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, defaultJournalTimeout)
	defer cancel()
	argv := journalwatch.UnitWindowArgv(unit,
		since.Format(journalwatch.SinceLayout))
	return d.Cfg.HostExecFn(cctx, true, 0, argv[0], argv[1:]...)
}

// journalAnyRead is the unfiltered second probe used to classify an
// empty unit-window read — `journalctl -n 1 --no-pager` with stderr
// folded in. A quiet unit on a healthy journald must NOT count as
// blindness; only when journald itself has nothing (or only "No
// journal files") to say does the empty window count.
func (d *Deps) journalAnyRead(ctx context.Context) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, defaultJournalTimeout)
	defer cancel()
	argv := journalwatch.AnyLineArgv()
	return d.Cfg.HostExecFn(cctx, true, 0, argv[0], argv[1:]...)
}

// JournalText returns the unit journal since `since`, mapping errors
// to empty — `journalctl ... 2>/dev/null | grep -c` parity (a failed
// journal read counts as 0 hits, never as wedge evidence). Every
// read also feeds the journal-unreadable accounting: a journald that
// persistently answers nothing while journal storage exists blinds
// ALL journal-grep checks, and that blindness must latch+log, not
// stay a per-cycle warning line.
func (d *Deps) JournalText(ctx context.Context, since time.Time) string {
	out, err := d.journalRead(ctx, d.Cfg.JournalUnit, since)
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
	class, detail := journalwatch.ClassifyRead(out, err)
	switch class {
	case journalwatch.ClassFailed, journalwatch.ClassFilesGone:
		return false, detail
	case journalwatch.ClassEmpty:
		uout, uerr := d.journalAnyRead(ctx)
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
// journal-unreadable tracker and drives the latch on transitions —
// through the STORE's multi-owner API under this subsystem's owner
// id (journalwatch.OwnerControllerHygiene): every blind read
// registers the controllerhygiene hold on the shared
// state-journal-unreadable latch, so workerhygiene's healthy read
// can never delete an episode this side is still failing under (and
// vice versa) — the file leaves only when BOTH hygienes have
// released.
//
// enter → STATE-ENTER + the suspect line (suspectLog then re-reminds
// at most once per SuspectLogCadence while the latch stays held).
// The journalDir gate lives inside the tracker — a host with no
// journal storage never fires. Held blind reads keep asserting the
// hold, which also refreshes the latch mtime (the janitor's 24h reap
// must not retire a live episode).
func (d *Deps) noteJournalRead(ctx context.Context, out string, err error) {
	const owner = journalwatch.OwnerControllerHygiene
	name := StateJournalUnreadable
	ok, detail := d.classifyJournalRead(ctx, out, err)
	if ok || !d.JournalReads.Present() {
		// A healthy read, or journald storage gone (config change,
		// not blindness): end this owner's streak, and release the
		// store hold REGARDLESS of the tracker's exit edge — an
		// owner that joined an episode it never reached Needed on
		// must still drop its hold; the store exits the FILE only
		// when no owner is left. The suspect budget clears with the
		// file (cleanup hook runs on the real exit only) so a
		// re-incident logs a fresh first line.
		_ = d.JournalReads.ExitFrom(owner, name)
		d.State.ExitFrom(name, owner,
			func() { d.State.ClearSuspect(name) })
		return
	}
	enter := d.JournalReads.EnterFrom(owner, name)
	if enter || d.JournalReads.Latched() {
		// Only while an episode is real (this read crossed Needed, or
		// the tracker already latched): the store hold + mtime
		// refresh. EnterFrom recreates a file the janitor's 24h reap
		// or a manual rm deleted mid-episode (the once-per-episode
		// enter edge alone would leave the latch/metric/condition
		// dark) and refreshes its mtime while held — and NEVER
		// pre-creates the latch for a streak that hasn't earned it.
		d.State.EnterFrom(name, owner, detail)
		if enter {
			d.Cycles.WithLabelValues(CheckJournal, "journal_unreadable").Inc()
		}
	}
	if d.JournalReads.Latched() {
		d.State.SuspectLog(name, fmt.Sprintf(
			"suspect: journal-unreadable %s — %d consecutive journal "+
				"reads produced nothing while journal storage exists; "+
				"every journal-grep check is blind",
			detail, d.JournalReads.Fails()), d.Cfg.SuspectLogCadence)
	}
}
