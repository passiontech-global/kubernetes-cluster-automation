// integrity.go — the shared journald corrupt/empty probe and its
// rotate+vacuum remedy, parameterized over the two call shapes that
// used to hand-roll it: workerhygiene's A5 JournaldCheck (unit-scoped
// `journalctl -u k0sworker --since "-10 min"` probe, ConsecNeeded
// streak, last-journald-vacuum 30m budget) and hostconfig's
// journaldIntegrity (unfiltered `journalctl -n 5` host-wide probe,
// act-on-first-read, last-journald-rotate 1h budget). The helper
// classifies one read (marker set + empty disambiguation), holds the
// consecutive-fail streak and, once confirmed, runs the budget-gated
// `journalctl --rotate --vacuum-time=<age>` remedy — every site keeps
// its own thresholds, marker sets, budget names/windows, exec seams
// and log lines via the config + sink, so the differing behaviors are
// parameters, not merged constants.
//
// The stderr fold is the SEAM's job, not this file's: both probe
// transports (wdeps.JournalFn → systemd.Client.Journal, hostconfig's
// Runner) fold stderr into the returned output already, which is what
// makes the marker and FilesGone checks see journald's diagnostics.
//
// cdeps/journal.go stays bespoke on purpose: its classifyJournalRead
// + noteJournalRead plumbing over the controller-side journal windows
// is the documented divergence.
package journalwatch

import (
	"context"
	"strings"
)

// EmptyClass is the resolution of a blank, error-free probe read —
// "journalctl answered with nothing" is ambiguous (a quiet subject, a
// truncated journal, a writing-nowhere journald or a legitimately
// absent one), and each call site owns the tiebreak.
type EmptyClass int

const (
	// EmptyQuiet — the blank read is a healthy-but-quiet subject, not
	// a fault: no remedy evidence (guards' quiet-unit probe answer).
	EmptyQuiet EmptyClass = iota
	// EmptyFault — the blank read STANDS as journald-level fault
	// evidence: the streak counts it and the remedy path fires.
	// Detail carries the reason ("" means journald answered — the
	// reply itself carried the anomaly, e.g. a corrupt warning).
	EmptyFault
	// EmptyCorrupt — blank while journal files exist on disk:
	// corruption evidence (post-hard-reboot truncation). The verdict
	// escalates to Corrupt.
	EmptyCorrupt
	// EmptySilent — blank because journald is writing nowhere though
	// a storage root exists (rotate cannot create files): the verdict
	// carries Resolved=EmptySilent and the call site owns the restart
	// remedy; the helper never remedies it.
	EmptySilent
)

// Verdict is one classified probe read.
type Verdict struct {
	// Err is the probe exec error (nil on a read that ran). An error
	// is never corruption evidence on its own — the helper holds the
	// streak on it instead of growing or clearing.
	Err error
	// Out is the probe output with stderr folded in by the seam —
	// journald's own diagnostics ("File ... is corrupt", "No journal
	// files were found.") are visible here.
	Out string
	// Corrupt — the output carried one of the site's corruption
	// markers (or the empty read resolved to EmptyCorrupt).
	Corrupt bool
	// Empty — a blank, error-free read that its disambiguation left
	// standing as fault evidence (EmptyFault); a quiet or silent
	// blank read is NOT Empty.
	Empty bool
	// Detail is the disambiguation's fault reason when the blank read
	// stood (EmptyFault). "" with Empty set means the unfiltered
	// probe itself answered and carried the anomaly — the caller's
	// unreadable accounting treats that as "journald answered".
	Detail string
	// Resolved is the EmptyClass the disambiguation returned; only
	// meaningful when the raw read was blank and error-free. Call
	// sites key their bespoke branches off it (hostconfig's silent
	// restart fires on EmptySilent).
	Resolved EmptyClass
}

// IntegritySink receives the remedy lifecycle events. Every callback
// is optional (nil = silently skipped) and formats its own site's
// exact log lines / metric bumps — the helper owns sequencing, the
// sink owns wording.
type IntegritySink struct {
	// StreakPending fires on a confirmed-but-not-yet-streaked cycle:
	// n is the streak so far, needed the configured threshold (the
	// "(check n/needed)" progress shape).
	StreakPending func(v Verdict, n, needed int)
	// BudgetSkipped fires when the streak confirmed but the budget
	// seam refused — the remedy was not attempted.
	BudgetSkipped func()
	// Action fires right before the remedy exec (the "ACTION:" line,
	// the action metric bump).
	Action func(v Verdict)
	// RemedyFailed fires when the remedy exec returned an error, with
	// whatever output came back.
	RemedyFailed func(out string, err error)
	// RemedyDone fires on a successful remedy exec.
	RemedyDone func()
}

// IntegrityConfig parameterizes the probe + remedy per call site.
// Probe is a closure (not an argv-building exec) because the sites'
// test seams are fixed-argv by design — wdeps.JournalFn IS the
// unit/window carrier for guards and the hostconfig Runner wraps
// `-n 5`; passing them straight through keeps every existing test
// stub working and the argv byte-shapes untouched.
type IntegrityConfig struct {
	// Probe runs one journalctl read (`journalctl <site argv>` with
	// stderr folded in). Read through the seam at call time so test
	// re-stubs after construction still land.
	Probe func(ctx context.Context) (string, error)
	// DisambiguateEmpty resolves a blank, error-free read; nil keeps
	// every blank read standing as EmptyFault. The class decides the
	// verdict: EmptyQuiet clears it, EmptyFault keeps it (+Detail),
	// EmptyCorrupt escalates to Corrupt, EmptySilent hands the verdict
	// to the call site (Resolved only).
	DisambiguateEmpty func(ctx context.Context) (cls EmptyClass, detail string)
	// Markers are the lowercase substrings whose presence in the
	// probe output counts as corruption. Sites keep their own sets —
	// guards matches only "corrupt", hostconfig also matches
	// "invalid object" and "failed to open journal".
	Markers []string
	// StreakNeeded is the consecutive corrupt/empty cycles required
	// before the remedy may run. 1 = act on the first confirmed read
	// (hostconfig); guards passes its ConsecNeeded budget. Err-only
	// cycles HOLD the streak (never grow, never clear); healthy reads
	// reset it; the reset after a remedy attempt re-arms for the next
	// episode.
	StreakNeeded int
	// VacuumAge is the --vacuum-time value of the remedy — both sites
	// pass "3d", so the exec argv is exactly
	// `journalctl --rotate --vacuum-time=3d`.
	VacuumAge string
	// Remedy executes the rotate+vacuum. nil means no remedy
	// transport is wired: a confirmed streak reports OutcomeGated
	// (no budget spend, no action line) instead of attempting.
	Remedy func(ctx context.Context, args ...string) (string, error)
	// SpendBudget consumes one remedy slot; false = in cooldown —
	// the helper skips the remedy (BudgetSkipped) and keeps the
	// streak armed. Each site keeps its own budget name, window and
	// spend semantics (guards' atomic RateTrySpend vs hostconfig's
	// RateOK-then-RateSpend-on-attempt). nil = unlimited.
	SpendBudget func() bool
	// Sink receives the remedy lifecycle events.
	Sink IntegritySink
}

// Outcome reports how a remedy round concluded.
type Outcome int

const (
	// OutcomeHealthy — a clean read: the streak reset.
	OutcomeHealthy Outcome = iota
	// OutcomePending — corrupt/empty confirmed but below
	// StreakNeeded: the progress line fired, no remedy.
	OutcomePending
	// OutcomeInconclusive — an exec-level read error without output
	// evidence: the streak is held, never remedied (the journal-
	// unreadable accounting owns that signal).
	OutcomeInconclusive
	// OutcomeBudget — the streak confirmed but the budget refused;
	// the streak stays armed and retries next cycle.
	OutcomeBudget
	// OutcomeGated — the streak confirmed but no remedy transport is
	// wired (nil Remedy): nothing attempted, no budget spent.
	OutcomeGated
	// OutcomeRemediated — the remedy exec ran this cycle (success or
	// failure); the streak reset for the next episode.
	OutcomeRemediated
)

// Integrity runs the shared probe → classify → streak → budget →
// remedy pipeline for one call site. Not goroutine-safe — one value
// per check/cycle loop; the streak lives here (ex the checks'
// hand-rolled fails counters).
type Integrity struct {
	cfg   IntegrityConfig
	fails int
}

// NewIntegrity builds the pipeline. A StreakNeeded <= 0 means "act on
// the first confirmed read".
func NewIntegrity(cfg IntegrityConfig) *Integrity {
	if cfg.StreakNeeded <= 0 {
		cfg.StreakNeeded = 1
	}
	return &Integrity{cfg: cfg}
}

// Classify runs one probe read and classifies it: corruption markers
// against the site's set, then the site's empty disambiguation for a
// blank error-free read. The returned Verdict carries everything the
// caller's bespoke accounting needs (raw output, exec error,
// disambiguation detail and class).
func (ig *Integrity) Classify(ctx context.Context) Verdict {
	out, err := ig.cfg.Probe(ctx)
	v := Verdict{Err: err, Out: out}
	low := strings.ToLower(out)
	for _, m := range ig.cfg.Markers {
		if m != "" && strings.Contains(low, m) {
			v.Corrupt = true
			break
		}
	}
	blank := err == nil && strings.TrimSpace(out) == ""
	if blank && ig.cfg.DisambiguateEmpty != nil {
		cls, detail := ig.cfg.DisambiguateEmpty(ctx)
		v.Resolved, v.Detail = cls, detail
		switch cls {
		case EmptyQuiet, EmptySilent:
			// Not remedy evidence: a quiet subject, or the call
			// site's own silent branch (Resolved carries it).
			blank = false
		case EmptyCorrupt:
			// Blank while files exist — corruption evidence.
			v.Corrupt, blank = true, false
		case EmptyFault:
			// Stands — the blank read is the fault evidence.
		}
	}
	v.Empty = blank
	return v
}

// Act applies the streak + budget + remedy to a Classify verdict —
// split from Classify so call sites with between-half work (the
// unreadable accounting, hostconfig's silent restart) keep their
// exact per-cycle ordering. Check is the fused form.
func (ig *Integrity) Act(ctx context.Context, v Verdict) Outcome {
	switch {
	case v.Corrupt || v.Empty:
		ig.fails++
		if ig.fails < ig.cfg.StreakNeeded {
			if ig.cfg.Sink.StreakPending != nil {
				ig.cfg.Sink.StreakPending(v, ig.fails, ig.cfg.StreakNeeded)
			}
			return OutcomePending
		}
	case v.Err != nil:
		// Exec failure without output evidence — inconclusive: hold
		// the streak (never grow it, never clear it), never remedy.
		return OutcomeInconclusive
	default:
		ig.fails = 0
		return OutcomeHealthy
	}
	if ig.cfg.Remedy == nil {
		return OutcomeGated
	}
	if ig.cfg.SpendBudget != nil && !ig.cfg.SpendBudget() {
		if ig.cfg.Sink.BudgetSkipped != nil {
			ig.cfg.Sink.BudgetSkipped()
		}
		return OutcomeBudget
	}
	if ig.cfg.Sink.Action != nil {
		ig.cfg.Sink.Action(v)
	}
	jout, jerr := ig.cfg.Remedy(ctx, "--rotate", "--vacuum-time="+ig.cfg.VacuumAge)
	if jerr != nil {
		if ig.cfg.Sink.RemedyFailed != nil {
			ig.cfg.Sink.RemedyFailed(jout, jerr)
		}
	} else if ig.cfg.Sink.RemedyDone != nil {
		ig.cfg.Sink.RemedyDone()
	}
	ig.fails = 0
	return OutcomeRemediated
}

// Check is Classify + Act in one round — the shape call sites with no
// between-half work use.
func (ig *Integrity) Check(ctx context.Context) (Verdict, Outcome) {
	v := ig.Classify(ctx)
	return v, ig.Act(ctx, v)
}
