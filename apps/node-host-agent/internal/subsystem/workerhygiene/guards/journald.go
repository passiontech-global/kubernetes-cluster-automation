package guards

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/checkkit"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/journalwatch"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

const (
	// journaldVacuumAge is the --vacuum-time the A5 remedy passes.
	journaldVacuumAge = "3d"
	// journaldVacuumInterval bounds how often the A5 remedy runs —
	// journalctl --rotate is cheap but --vacuum-time does real IO.
	journaldVacuumInterval = 30 * time.Minute
)

// --- Check: journald integrity (A5) ---
// After a hard-reboot (SNR) journald's binary files corrupt at the
// tail: `journalctl -u k0sworker` prints "corrupt" or returns
// abnormally empty while the unit is active — which also blinds the
// 05/06 journal-signature checks. An exec-level read ERROR is not
// corruption evidence (journald never answered — the
// journal-unreadable tracker owns that signal). The remedy is the
// operator's rotate+vacuum, bounded by a rate budget.
//
// The classification + streak + budget + rotate pipeline lives in the
// shared journalwatch.Integrity helper; this check wires its seams
// (JournalFn/JournalAnyFn probes, Systemd remedy transport,
// last-journald-vacuum budget, the State.AppendLog lines) and keeps
// the journal-unreadable accounting bespoke — the same probes feed it
// through noteJournalRead: when journald cannot answer at all (read
// error, "No journal files", or a journald-wide empty unfiltered
// reply) for JournalUnreadableNeeded consecutive reads AND journal
// storage exists, the state-journal-unreadable latch marks the
// blindness — the rotate+vacuum remedy only covers the CORRUPT
// subset, a dead or mute journald needs surfacing, not vacuuming.

// JournaldCheck is the A5 probe as a Check. The corrupt/empty streak
// lives inside the shared integrity helper (ex-c.fails).
type JournaldCheck struct {
	d  *wdeps.Deps
	ig *journalwatch.Integrity
}

// newJournaldIntegrity wires the shared pipeline to this check's
// seams. The probe + disambiguation closures read the JournalFn /
// JournalAnyFn seams at CALL time (tests re-stub them after New);
// StreakNeeded and the remedy transport freeze at construction —
// ApplyDefaults has already filled both by the time initChecks runs.
func newJournaldIntegrity(d *wdeps.Deps) *journalwatch.Integrity {
	var remedy func(ctx context.Context, args ...string) (string, error)
	if d.Cfg.Systemd != nil {
		sd := d.Cfg.Systemd
		remedy = func(ctx context.Context, args ...string) (string, error) {
			return sd.Exec(ctx, "journalctl", args...)
		}
	}
	return journalwatch.NewIntegrity(journalwatch.IntegrityConfig{
		// The runner's shared -10min k0sworker snapshot (05/06):
		// `journalctl -u k0sworker.service --since "-10 min"
		// --no-pager` with stderr folded in by the seam, so a
		// corrupt-file notice survives even a non-zero exit and
		// still counts here.
		Probe: func(ctx context.Context) (string, error) {
			return d.Cfg.Seams.Host.JournalFn(ctx)
		},
		// Only OUTPUT evidence counts as corruption: an exec-level
		// error (nsenter/journalctl timeout, transient host exec
		// failure) means journald never answered — that is
		// journal-UNREADABLE, not corrupt. Lumping err into "corrupt"
		// ran the rotate+vacuum remedy on every cooldown for a purely
		// transient failure.
		Markers: []string{"corrupt"},
		// "No k0sworker lines in 10m" is ambiguous — a
		// healthy-but-quiet unit hits the same branch as real
		// corruption, and remediating it would rotate+vacuum every
		// cooldown forever. Second probe: the UNFILTERED journal.
		// Any answered line — including a "No journal files were
		// found." notice — means journald is fine and the unit is
		// just silent (EmptyQuiet): the pre-Integrity check cleared
		// the empty window on exactly this condition (non-blank, no
		// corrupt warning), so a files-gone notice stays a healthy
		// read, not a fault. An error, a literally empty reply or a
		// "corrupt" warning is journald-level anomaly (EmptyFault —
		// only then remediate). The detail feeds the unreadable
		// accounting below: the corrupt-warning case carries ""
		// because journald ANSWERED.
		DisambiguateEmpty: func(ctx context.Context) (journalwatch.EmptyClass, string) {
			unfiltered, uerr := d.Cfg.Seams.Host.JournalAnyFn(ctx)
			switch {
			case uerr != nil:
				return journalwatch.EmptyFault,
					fmt.Sprintf("unfiltered probe failed: %v", uerr)
			case strings.Contains(strings.ToLower(unfiltered), "corrupt"):
				return journalwatch.EmptyFault, ""
			case strings.TrimSpace(unfiltered) == "":
				return journalwatch.EmptyFault, "journald-wide empty reply"
			default:
				return journalwatch.EmptyQuiet, ""
			}
		},
		StreakNeeded: d.Cfg.ConsecNeeded,
		VacuumAge:    journaldVacuumAge,
		Remedy:       remedy,
		// Atomic try-and-spend: a confirmed streak without budget is
		// skipped (and logged) without burning a slot.
		SpendBudget: func() bool {
			return d.State.RateTrySpend("last-journald-vacuum", journaldVacuumInterval)
		},
		Sink: journalwatch.IntegritySink{
			StreakPending: func(v journalwatch.Verdict, n, needed int) {
				d.State.AppendLog(fmt.Sprintf(
					"suspect: journald-integrity journal corrupt=%v empty=%v err=%v while k0sworker active%s",
					v.Corrupt, v.Empty, v.Err, checkkit.Progress(n, needed)))
			},
			BudgetSkipped: func() {
				d.State.AppendLog("suspect: journald-integrity confirmed but vacuum " +
					"cooldown active — skip")
			},
			Action: func(v journalwatch.Verdict) {
				d.State.AppendLog(fmt.Sprintf(
					"ACTION: journalctl --rotate --vacuum-time=%s - journal corrupt=%v empty=%v err=%v for active k0sworker",
					journaldVacuumAge, v.Corrupt, v.Empty, v.Err))
			},
			RemedyFailed: func(out string, err error) {
				d.State.AppendLog(fmt.Sprintf(
					"suspect: journalctl --rotate --vacuum-time=%s failed: %v (%s)",
					journaldVacuumAge, err, strings.TrimSpace(out)))
			},
			RemedyDone: func() {
				d.Actions.WithLabelValues(wdeps.CheckJournald, "rotate_vacuum").Inc()
			},
		},
	})
}

// Name returns the check label / WD_SIG key.
func (c *JournaldCheck) Name() string { return wdeps.CheckJournald }

// Run executes one journald-integrity round.
func (c *JournaldCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckJournald) {
		return
	}
	v := c.ig.Classify(ctx)
	// journal-unreadable accounting: a "corrupt" notice means
	// journald ANSWERED (A5's remedy owns that path) — only a read
	// that produced literally nothing while journald should be
	// talking counts as blindness. A stood empty read is blindness
	// exactly when the disambiguation gave a reason (the "" detail is
	// the corrupt-warning answer — journald talked, A5 owns it).
	unreadable := false
	udetail := ""
	switch {
	case v.Err != nil:
		unreadable, udetail = true, fmt.Sprintf("read failed: %v", v.Err)
	case journalwatch.FilesGone(v.Out):
		unreadable, udetail = true, "journalctl reports no journal files"
	case v.Empty:
		unreadable, udetail = v.Detail != "", v.Detail
	}
	c.d.NoteJournalRead(!unreadable, udetail)
	switch c.ig.Act(ctx, v) {
	case journalwatch.OutcomePending, journalwatch.OutcomeHealthy,
		journalwatch.OutcomeBudget, journalwatch.OutcomeRemediated:
		// Pending = streak still below ConsecNeeded (progress line
		// logged by the sink); Budget = confirmed but in cooldown
		// (skip line logged by the sink). Both report ok.
		c.d.CycleResult(wdeps.CheckJournald, "ok")
	case journalwatch.OutcomeInconclusive:
		// Exec failure without corruption evidence — inconclusive
		// (the unreadable tracker owns this signal): the streak is
		// held but never grown, and never vacuumed.
		c.d.CycleResult(wdeps.CheckJournald, "abort")
	case journalwatch.OutcomeGated:
		// Confirmed but no remedy transport wired (nil Systemd).
		c.d.CycleResult(wdeps.CheckJournald, "gated")
	}
}

// --- Check: cilium-envoy readiness + agent healthz (2.5 & B1) ---
// From cilium 1.16 the L7/xDS listener lives in a separate
// cilium-envoy container: an agent restart (sig9/15) can strand it
// holding a stale unix socket — L3/L4 still flows while Gateway API
// traffic 503s. The check probes the envoy admin port and reads the
// agent's /v1/healthz subsystem states for evidence; the kill fires
// when the agent was SIGKILLed this cycle or envoy stays unready
// for ConsecNeeded cycles.
