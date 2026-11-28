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
	"errors"
	"fmt"
	"os/exec"
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

// journalGrepRead is journalRead with a server-side MESSAGE filter —
// `--grep=<pattern>` (PCRE2, systemd ≥237) returns only matching
// entries, so a signature count pays for hits, not the whole unit
// window. Same stderr-fold + timeout contract.
func (d *Deps) journalGrepRead(ctx context.Context, unit string,
	since time.Time, pattern string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, defaultJournalTimeout)
	defer cancel()
	argv := journalwatch.UnitWindowGrepArgv(unit,
		since.Format(journalwatch.SinceLayout), pattern)
	out, err := d.Cfg.HostExecFn(cctx, true, 0, argv[0], argv[1:]...)
	// systemd >=255 `journalctl --grep=...` exits 1 with "-- No entries --"
	// when zero log lines match the filter (healthy state), unlike real read
	// errors or missing journal files. Treat it as a successful empty match
	// so healthy controllers do not trip state-journal-unreadable.
	if err != nil && isGrepNoEntries(out, err) {
		return out, nil
	}
	return out, err
}

func isGrepNoEntries(out string, err error) bool {
	if journalwatch.FilesGone(out) || !strings.Contains(strings.ToLower(out), "-- no entries --") {
		return false
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode() == 1
	}
	return err.Error() == "exit status 1"
}

// JournalTextGrep is JournalText's filtered sibling — the read error
// contract is identical (unreadable journal = inconclusive, never
// "0 hits"), only the returned window is pre-filtered to entries
// whose MESSAGE matches pattern.
func (d *Deps) JournalTextGrep(ctx context.Context, since time.Time,
	pattern string) (string, error) {
	out, err := d.journalGrepRead(ctx, d.Cfg.JournalUnit, since, pattern)
	d.noteJournalRead(ctx, out, err)
	if err != nil {
		d.State.AppendLogWarn(fmt.Sprintf(
			"controllerhygiene: journal read failed (unit=%s): %v — journal checks see 0 hits",
			d.Cfg.JournalUnit, err))
		return "", err
	}
	return out, nil
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

// JournalText returns the unit journal since `since` AND its read
// error — callers that gate latch clearing on journal evidence
// (kine_ttl) must see the failure: an unreadable journal is
// inconclusive, never "0 hits". Every read also feeds the
// journal-unreadable accounting: a journald that persistently
// answers nothing while journal storage exists blinds ALL
// journal-grep checks, and that blindness must latch+log, not stay
// a per-cycle warning line.
func (d *Deps) JournalText(ctx context.Context, since time.Time) (string, error) {
	out, err := d.journalRead(ctx, d.Cfg.JournalUnit, since)
	d.noteJournalRead(ctx, out, err)
	if err != nil {
		d.State.AppendLogWarn(fmt.Sprintf(
			"controllerhygiene: journal read failed (unit=%s): %v — journal checks see 0 hits",
			d.Cfg.JournalUnit, err))
		return "", err
	}
	return out, nil
}

// classifyJournalRead reduces one journal-read result to the
// readable/unreadable verdict the tracker counts via
// journalwatch.ClassifyReadWith.
func (d *Deps) classifyJournalRead(ctx context.Context, out string, err error) (bool, string) {
	return journalwatch.ClassifyReadWith(ctx, out, err, d.journalAnyRead)
}

// noteJournalRead feeds one classified journal read into the shared
// journalwatch.ClassifyAndTrack wrapper under OwnerControllerHygiene.
func (d *Deps) noteJournalRead(ctx context.Context, out string, err error) {
	const owner = journalwatch.OwnerControllerHygiene
	name := StateJournalUnreadable
	journalwatch.ClassifyAndTrack(ctx, journalwatch.BlindnessConfig{
		Tracker: &d.JournalReads,
		Store:   d.State,
		Owner:   owner,
		Latch:   name,
		DisambiguateEmpty: func(ctx context.Context) (bool, string) {
			return journalwatch.ClassifyReadWith(ctx, "", nil, d.journalAnyRead)
		},
		OnExit: func() { d.State.ClearSuspect(name) },
		OnBlind: func(enter, latched bool, detail string, fails int) {
			if enter || latched {
				d.State.EnterFrom(name, owner, detail)
				if enter {
					d.Cycles.WithLabelValues(CheckJournal, "journal_unreadable").Inc()
				}
			}
			if latched {
				d.State.SuspectLog(name, fmt.Sprintf(
					"suspect: journal-unreadable %s — %d consecutive journal "+
						"reads produced nothing while journal storage exists; "+
						"every journal-grep check is blind",
					detail, fails), d.Cfg.SuspectLogCadence)
			}
		},
	}, out, err)
}
