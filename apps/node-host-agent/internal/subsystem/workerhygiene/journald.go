package workerhygiene

import (
	"context"
	"fmt"
	"strings"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/journalwatch"
)

// noteJournalRead feeds one classified journal read into the
// journal-unreadable tracker and drives the latch on transitions:
// enter → state-journal-unreadable + the suspect line, logged once
// per latch entry (the stateExists gate — the latch dedupes the
// alert AND its first line, like checkCiliumMTU); exit → STATE-EXIT
// when a read finally returns journal data (or the journal storage
// vanished — config change, not blindness). The journalDir gate
// lives inside the tracker: a host with no journald storage never
// fires — every read failing is then configuration, not a fault.
func (h *Hygiene) noteJournalRead(ok bool, detail string) {
	enter, exit := h.journalReads.NoteRead(ok)
	if enter && !h.state.Exists(stateJournalUnreadable) {
		h.state.Enter(stateJournalUnreadable, detail)
		h.state.AppendLog(fmt.Sprintf(
			"suspect: journal-unreadable %s — %d consecutive journal "+
				"reads produced nothing while journal storage exists; "+
				"every journal-grep check is blind",
			detail, h.journalReads.Fails()))
		h.cycles.WithLabelValues(checkJournald, "journal_unreadable").Inc()
	} else if h.journalReads.Latched() &&
		!h.state.Exists(stateJournalUnreadable) {
		// Re-establish after external removal: the latch file can
		// vanish while the tracker stays latched (janitor 24h reap,
		// manual rm) and `enter` is a once-per-episode edge that
		// won't fire again — without this the metric/condition go
		// dark mid-episode.
		h.state.Enter(stateJournalUnreadable, detail)
	}
	if exit {
		h.state.Exit(stateJournalUnreadable, nil)
	}
}

// --- Check: journald integrity (A5) ---
// After a hard-reboot (SNR) journald's binary files corrupt at the
// tail: `journalctl -u k0sworker` prints "corrupt" or returns
// abnormally empty while the unit is active — which also blinds the
// 05/06 journal-signature checks. An exec-level read ERROR is not
// corruption evidence (journald never answered — the
// journal-unreadable tracker owns that signal). The remedy is the
// operator's rotate+vacuum, bounded by a rate budget.
//
// The same probes feed the journal-unreadable accounting: when
// journald cannot answer at all (read error, "No journal files", or
// a journald-wide empty unfiltered reply) for JournalUnreadableNeeded
// consecutive reads AND journal storage exists, the
// state-journal-unreadable latch marks the blindness — the
// rotate+vacuum remedy only covers the CORRUPT subset, a dead or
// mute journald needs surfacing, not vacuuming.

// journaldCheck is the A5 probe as a Check. It owns the
// corrupt/empty streak (ex-Hygiene.journaldFails); the
// journal-unreadable tracker stays on Hygiene — Cycle's shared
// journalOnce snapshot also feeds it through noteJournalRead.
type journaldCheck struct {
	h     *Hygiene
	fails int // consecutive corrupt/empty cycles (ConsecNeeded → remedy)
}

// Name returns the check label / WD_SIG key.
func (c *journaldCheck) Name() string { return checkJournald }

// Run executes one journald-integrity round.
func (c *journaldCheck) Run(ctx context.Context, e *cycleEnv) {
	if !e.workerActive {
		c.h.cycles.WithLabelValues(checkJournald, "gated").Inc()
		return
	}
	out, err := c.h.cfg.Seams.journalFn(ctx)
	// Only OUTPUT evidence counts as corruption: an exec-level error
	// (nsenter/journalctl timeout, transient host exec failure) means
	// journald never answered — that is journal-UNREADABLE, not
	// corrupt. Lumping err into "corrupt" ran the rotate+vacuum
	// remedy on every cooldown for a purely transient failure.
	// Journal() folds stderr in, so a corrupt-file notice survives
	// even a non-zero exit and still counts here.
	corrupt := strings.Contains(strings.ToLower(out), "corrupt")
	empty := err == nil && strings.TrimSpace(out) == ""
	var unfiltered string
	var uerr error
	if empty {
		// "No k0sworker lines in 10m" is ambiguous — a
		// healthy-but-quiet unit hits the same branch as real
		// corruption, and remediating it would rotate+vacuum every
		// cooldown forever. Second probe: the UNFILTERED journal.
		// Any line means journald is fine and the unit is just
		// silent; an error, an empty reply, or a "corrupt" warning
		// is journald-level anomaly — only then remediate.
		unfiltered, uerr = c.h.cfg.Seams.journalAnyFn(ctx)
		if uerr == nil && strings.TrimSpace(unfiltered) != "" &&
			!strings.Contains(strings.ToLower(unfiltered), "corrupt") {
			empty = false
		}
	}
	// journal-unreadable accounting: a "corrupt" notice means
	// journald ANSWERED (A5's remedy owns that path) — only a read
	// that produced literally nothing while journald should be
	// talking counts as blindness.
	unreadable := false
	udetail := ""
	switch {
	case err != nil:
		unreadable, udetail = true, fmt.Sprintf("read failed: %v", err)
	case journalwatch.FilesGone(out):
		unreadable, udetail = true, "journalctl reports no journal files"
	case empty:
		switch {
		case uerr != nil:
			unreadable, udetail = true,
				fmt.Sprintf("unfiltered probe failed: %v", uerr)
		case journalwatch.FilesGone(unfiltered):
			unreadable, udetail = true,
				"journalctl reports no journal files"
		case strings.TrimSpace(unfiltered) == "":
			unreadable, udetail = true, "journald-wide empty reply"
		}
	}
	c.h.noteJournalRead(!unreadable, udetail)
	switch {
	case corrupt, empty:
		c.fails++
		if c.fails < c.h.cfg.ConsecNeeded {
			c.h.state.AppendLog(fmt.Sprintf(
				"suspect: journald-integrity journal corrupt=%v empty=%v err=%v while k0sworker active (check %d/%d)",
				corrupt, empty, err, c.fails, c.h.cfg.ConsecNeeded))
			c.h.cycles.WithLabelValues(checkJournald, "ok").Inc()
			return
		}
	case err != nil:
		// Exec failure without corruption evidence — inconclusive
		// (the unreadable tracker owns this signal): keep the fail
		// streak intact but never grow it, and never vacuum.
		c.h.cycles.WithLabelValues(checkJournald, "abort").Inc()
		return
	default:
		c.fails = 0
		c.h.cycles.WithLabelValues(checkJournald, "ok").Inc()
		return
	}
	if c.h.cfg.Systemd == nil {
		c.h.cycles.WithLabelValues(checkJournald, "gated").Inc()
		return
	}
	if !c.h.state.RateTrySpend("last-journald-vacuum", journaldVacuumInterval) {
		c.h.state.AppendLog("suspect: journald-integrity confirmed but vacuum " +
			"cooldown active — skip")
		c.h.cycles.WithLabelValues(checkJournald, "ok").Inc()
		return
	}
	c.h.state.AppendLog(fmt.Sprintf(
		"ACTION: journalctl --rotate --vacuum-time=3d - journal corrupt=%v empty=%v err=%v for active k0sworker",
		corrupt, empty, err))
	if jout, jerr := c.h.cfg.Systemd.Exec(ctx,
		"journalctl", "--rotate", "--vacuum-time=3d"); jerr != nil {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: journalctl --rotate --vacuum-time=3d failed: %v (%s)",
			jerr, strings.TrimSpace(jout)))
	} else {
		c.h.actions.WithLabelValues(checkJournald, "rotate_vacuum").Inc()
	}
	c.fails = 0
	c.h.cycles.WithLabelValues(checkJournald, "ok").Inc()
}

// --- Check: cilium-envoy readiness + agent healthz (2.5 & B1) ---
// From cilium 1.16 the L7/xDS listener lives in a separate
// cilium-envoy container: an agent restart (sig9/15) can strand it
// holding a stale unix socket — L3/L4 still flows while Gateway API
// traffic 503s. The check probes the envoy admin port and reads the
// agent's /v1/healthz subsystem states for evidence; the kill fires
// when the agent was SIGKILLed this cycle or envoy stays unready
// for ConsecNeeded cycles.
