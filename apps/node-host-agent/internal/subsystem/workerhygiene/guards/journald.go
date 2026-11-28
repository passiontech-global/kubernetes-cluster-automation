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
	// once is the cycle-shared k0sworker snapshot handle (05/06's
	// e.JournalOnce), swapped in at Run — nil (hand-built envs) falls
	// back to a direct JournalFn read.
	once func() string
}

// newJournaldIntegrity wires the shared pipeline to this check's
// seams. The probe + disambiguation closures read the JournalFn /
// JournalAnyFn seams at CALL time (tests re-stub them after New);
// StreakNeeded and the remedy transport freeze at construction —
// ApplyDefaults has already filled both by the time initChecks runs.
func newJournaldIntegrity(c *JournaldCheck) *journalwatch.Integrity {
	d := c.d
	var (
		remedy     func(ctx context.Context, args ...string) (string, error)
		deepRemedy func(ctx context.Context) (int, error)
	)
	if d.Cfg.Systemd != nil {
		sd := d.Cfg.Systemd
		remedy = func(ctx context.Context, args ...string) (string, error) {
			return sd.Exec(ctx, "journalctl", args...)
		}
		deepRemedy = func(ctx context.Context) (int, error) {
			if _, err := sd.Exec(ctx, "journalctl", "--rotate"); err != nil {
				return 0, err
			}
			// journalctl --verify exits non-zero whenever any corrupt file
			// is found and reports diagnostics on stderr+stdout; parse
			// verifyOut regardless of exit status.
			verifyOut, _ := sd.ExecCombined(ctx, "journalctl", "--verify")
			pruned, err := journalwatch.PruneCorruptJournalFiles(d.Cfg.HostRoot, verifyOut)
			if pruned > 0 {
				_, _ = sd.Exec(ctx, "journalctl", "--flush")
			}
			return pruned, err
		}
	}
	return journalwatch.NewIntegrity(journalwatch.IntegrityConfig{
		// The runner's shared -10min k0sworker snapshot (05/06) —
		// `journalctl -u k0sworker.service --since "-10 min"
		// --no-pager`, stderr folded in by the seam, so a
		// corrupt-file notice survives even a non-zero exit and
		// still counts here. Read through the CYCLE-SHARED handle
		// (Run swaps in e.JournalOnce) so 05/06 and this check
		// answer from ONE journald fork per cycle instead of two
		// identical ones — journald is slow on CPU-starved nodes
		// and two windows could disagree. A blank/failed snapshot
		// falls through to the direct seam read: the runner folds
		// exec errors away, and THIS check must still see them
		// (an exec failure reads as journal-unreadable/inconclusive,
		// never as a quiet unit or corruption evidence). A
		// hand-built env without the snapshot always direct-reads.
		Probe: func(ctx context.Context) (string, error) {
			if c.once != nil {
				if out := c.once(); strings.TrimSpace(out) != "" {
					return out, nil
				}
			}
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
		DeepRemedy:   deepRemedy,
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
			DeepAction: func(_ journalwatch.Verdict) {
				d.State.AppendLog("ACTION: journald deep-prune — rotating and removing corrupt archived journal files after rotate+vacuum failed to clear corruption")
			},
			DeepRemedyFailed: func(err error) {
				d.State.AppendLog(fmt.Sprintf("suspect: journald deep-prune failed: %v", err))
			},
			DeepRemedyDone: func(pruned int) {
				if pruned > 0 {
					d.State.AppendLog(fmt.Sprintf("ACTION: journald deep-prune removed %d corrupt archived file(s)", pruned))
					d.Actions.WithLabelValues(wdeps.CheckJournald, "prune_corrupt").Inc()
				} else {
					d.State.AppendLog("ACTION: journald deep-prune — no corrupt archived files found")
				}
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
	// Bind THIS cycle's shared k0sworker snapshot (05/06's
	// e.JournalOnce) — nil in hand-built envs keeps the direct seam
	// read.
	c.once = e.JournalOnce
	v := c.ig.Classify(ctx)
	// journal-unreadable accounting: a "corrupt" notice means
	// journald ANSWERED (A5's remedy owns that path) — only a read
	// that produced literally nothing while journald should be
	// talking counts as blindness. A stood empty read is blindness
	// exactly when the disambiguation gave a reason (the "" detail is
	// the corrupt-warning answer — journald talked, A5 owns it).
	// Shared blindness tracking via journalwatch.ClassifyAndTrack:
	// exec-error and files-gone map directly; an empty read uses the
	// integrity classifier's disambiguated detail.
	c.d.ClassifyAndTrackJournal(ctx, v.Out, v.Err, func(context.Context) (bool, string) {
		if v.Empty && v.Detail != "" {
			return false, v.Detail
		}
		return true, ""
	})
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
