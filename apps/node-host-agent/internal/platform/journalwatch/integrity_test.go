// integrity_test.go — the shared corrupt/empty probe + rotate remedy:
// marker classification, the four empty resolutions, the streak
// semantics (grow / hold-on-error / reset), budget gating and the
// exact remedy argv, plus the Outcome mapping the two call sites'
// cycle results are keyed on.
package journalwatch

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func newTestIntegrity(t *testing.T, probeOut string, probeErr error,
	hook func(ctx context.Context) (EmptyClass, string),
	mutate func(*IntegrityConfig)) (*Integrity, *recorder) {
	t.Helper()
	rec := &recorder{budgetOK: true}
	cfg := IntegrityConfig{
		Probe: func(context.Context) (string, error) {
			return probeOut, probeErr
		},
		Markers:           []string{"corrupt"},
		StreakNeeded:      2,
		VacuumAge:         "3d",
		DisambiguateEmpty: hook,
		Remedy: func(_ context.Context, args ...string) (string, error) {
			rec.remedyArgv = append(rec.remedyArgv, strings.Join(args, " "))
			return rec.remedyOut, rec.remedyErr
		},
		SpendBudget: func() bool {
			rec.spent++
			return rec.budgetOK
		},
		Sink: IntegritySink{
			StreakPending: func(v Verdict, n, needed int) {
				rec.pending = append(rec.pending,
					rec.pendingLine(v, n, needed))
			},
			BudgetSkipped: func() { rec.skipped++ },
			Action: func(v Verdict) {
				rec.action = append(rec.action,
					rec.actionLine(v))
			},
			RemedyFailed: func(out string, err error) {
				rec.remedyFail = append(rec.remedyFail,
					rec.failLine(out, err))
			},
			RemedyDone: func() { rec.done++ },
		},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	return NewIntegrity(cfg), rec
}

// recorder collects every sink event + seam call so the assertions
// read like the watchdog log they stand in for.
type recorder struct {
	remedyArgv []string
	remedyOut  string
	remedyErr  error
	budgetOK   bool // flipped false only by the budget-skip test
	spent      int
	skipped    int
	done       int
	pending    []string
	action     []string
	remedyFail []string
}

func (r *recorder) pendingLine(v Verdict, n, needed int) string {
	return fmt.Sprintf(
		"suspect: journald-integrity journal corrupt=%v empty=%v err=%v "+
			"while k0sworker active (check %d/%d)",
		v.Corrupt, v.Empty, v.Err, n, needed)
}

func (r *recorder) actionLine(v Verdict) string {
	return fmt.Sprintf(
		"ACTION: journalctl --rotate --vacuum-time=3d - journal corrupt=%v "+
			"empty=%v err=%v for active k0sworker",
		v.Corrupt, v.Empty, v.Err)
}

func (r *recorder) failLine(out string, err error) string {
	// The guards sink trims the partial output (hostconfig passes it
	// raw into its structured error log) — mirror that shape.
	return fmt.Sprintf(
		"suspect: journalctl --rotate --vacuum-time=3d failed: %v (%s)",
		err, strings.TrimSpace(out))
}

func TestIntegrityMarkerClassifiedAndRemediatedOnStreak(t *testing.T) {
	ig, rec := newTestIntegrity(t,
		"File corruption detected at /var/log/journal/x.journal", nil, nil, nil)
	ctx := context.Background()
	v, o := ig.Check(ctx)
	if v.Corrupt != true || v.Empty != false || o != OutcomePending {
		t.Fatalf("cycle1: v=%+v o=%v want pending corrupt", v, o)
	}
	if len(rec.pending) != 1 || rec.pending[0] !=
		"suspect: journald-integrity journal corrupt=true empty=false "+
			"err=<nil> while k0sworker active (check 1/2)" {
		t.Fatalf("progress line = %q", rec.pending)
	}
	if rec.spent != 0 || len(rec.action) != 0 {
		t.Fatalf("remedy attempted before the streak: spent=%d action=%v",
			rec.spent, rec.action)
	}
	v, o = ig.Check(ctx)
	if o != OutcomeRemediated {
		t.Fatalf("cycle2 outcome=%v want remediated", o)
	}
	if len(rec.remedyArgv) != 1 || rec.remedyArgv[0] != "--rotate --vacuum-time=3d" {
		t.Fatalf("remedy argv=%v want [--rotate --vacuum-time=3d]", rec.remedyArgv)
	}
	if len(rec.action) != 1 || rec.action[0] !=
		"ACTION: journalctl --rotate --vacuum-time=3d - journal corrupt=true "+
			"empty=false err=<nil> for active k0sworker" {
		t.Fatalf("action line = %q", rec.action)
	}
	if rec.done != 1 || rec.skipped != 0 || rec.spent != 1 {
		t.Fatalf("remedy bookkeeping: done=%d skipped=%d spent=%d",
			rec.done, rec.skipped, rec.spent)
	}
	// The remedy reset the streak — a further corrupt cycle is 1/2 again.
	_, o = ig.Check(ctx)
	if o != OutcomePending {
		t.Fatalf("post-remedy cycle outcome=%v want pending (streak re-armed)", o)
	}
}

func TestIntegrityHealthyResetsStreak(t *testing.T) {
	corrupt := "corrupt tail"
	ig, _ := newTestIntegrity(t, corrupt, nil, nil, nil)
	ctx := context.Background()
	if _, o := ig.Check(ctx); o != OutcomePending {
		t.Fatalf("cycle1=%v want pending", o)
	}
	// Swap to a healthy read: the streak must clear, not confirm.
	ig.cfg.Probe = func(context.Context) (string, error) { return "ok line", nil }
	if _, o := ig.Check(ctx); o != OutcomeHealthy {
		t.Fatalf("cycle2=%v want healthy", o)
	}
	ig.cfg.Probe = func(context.Context) (string, error) { return corrupt, nil }
	if _, o := ig.Check(ctx); o != OutcomePending {
		t.Fatalf("cycle3=%v want pending (reset streak)", o)
	}
}

func TestIntegrityExecErrorHoldsStreakNeverRemedies(t *testing.T) {
	ig, rec := newTestIntegrity(t, "", errors.New("exec timeout"), nil, nil)
	ctx := context.Background()
	for i := range 5 {
		v, o := ig.Check(ctx)
		if o != OutcomeInconclusive || v.Corrupt || v.Empty {
			t.Fatalf("cycle%d: o=%v v=%+v want inconclusive", i+1, o, v)
		}
	}
	if rec.spent != 0 || len(rec.action) != 0 || len(rec.pending) != 0 {
		t.Fatalf("remedy/progress on inconclusive cycles: %v", rec)
	}
	// The hold neither grows nor clears: a corrupt cycle right after
	// the errors is 1/2 (the errors did not count), and one more
	// confirms — the streak picked up where the last real read left.
	ig.cfg.Probe = func(context.Context) (string, error) { return "corrupt", nil }
	if _, o := ig.Check(ctx); o != OutcomePending {
		t.Fatalf("post-error corrupt cycle=%v want pending (held, not grown)", o)
	}
	if _, o := ig.Check(ctx); o != OutcomeRemediated {
		t.Fatalf("second corrupt cycle=%v want remediated", o)
	}
}

func TestIntegrityEmptyDisambiguationClasses(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		cls     EmptyClass
		detail  string
		corrupt bool
		empty   bool
	}{
		// A quiet subject clears the blank read — healthy.
		{EmptyQuiet, "", false, false},
		// A fault reason stands — remedy evidence with the detail.
		{EmptyFault, "journald-wide empty reply", false, true},
		// Files on disk escalate to corruption.
		{EmptyCorrupt, "", true, false},
	}
	for i, tc := range cases {
		ig, _ := newTestIntegrity(t, "", nil,
			func(context.Context) (EmptyClass, string) {
				return tc.cls, tc.detail
			}, nil)
		v, o := ig.Check(ctx)
		wantO := OutcomePending
		if tc.cls == EmptyQuiet {
			wantO = OutcomeHealthy
		}
		if v.Corrupt != tc.corrupt || v.Empty != tc.empty ||
			v.Detail != tc.detail || v.Resolved != tc.cls || o != wantO {
			t.Fatalf("case%d: v=%+v o=%v want corrupt=%v empty=%v detail=%q o=%v",
				i, v, o, tc.corrupt, tc.empty, tc.detail, wantO)
		}
	}
	// EmptySilent never reaches the remedy — it is the call site's
	// verdict, surfaced only through Resolved.
	ig, rec := newTestIntegrity(t, "", nil,
		func(context.Context) (EmptyClass, string) {
			return EmptySilent, ""
		}, nil)
	v, o := ig.Check(ctx)
	if v.Corrupt || v.Empty || v.Resolved != EmptySilent || o != OutcomeHealthy {
		t.Fatalf("silent: v=%+v o=%v want untouched verdict for the call site", v, o)
	}
	if rec.spent != 0 {
		t.Fatal("silent verdict must not spend the budget")
	}
}

func TestIntegrityBudgetSkipKeepsStreakArmed(t *testing.T) {
	ig, rec := newTestIntegrity(t, "corrupt", nil, nil, nil)
	rec.budgetOK = false
	ctx := context.Background()
	if _, o := ig.Check(ctx); o != OutcomePending {
		t.Fatalf("cycle1=%v want pending", o)
	}
	if _, o := ig.Check(ctx); o != OutcomeBudget {
		t.Fatalf("cycle2=%v want budget", o)
	}
	if rec.skipped != 1 || rec.spent != 1 || len(rec.action) != 0 {
		t.Fatalf("budget bookkeeping: skipped=%d spent=%d action=%v",
			rec.skipped, rec.spent, rec.action)
	}
	// The streak is NOT reset on a skip — the next confirmed cycle
	// goes straight back to the budget gate.
	if _, o := ig.Check(ctx); o != OutcomeBudget || rec.spent != 2 {
		t.Fatalf("cycle3 o=%v spent=%d want re-gated", o, rec.spent)
	}
}

func TestIntegrityRemedyFailureLogsAndResets(t *testing.T) {
	ig, rec := newTestIntegrity(t, "corrupt", nil, nil, nil)
	rec.remedyErr = errors.New("journalctl vanished")
	rec.remedyOut = "partial\n"
	ctx := context.Background()
	if _, o := ig.Check(ctx); o != OutcomePending {
		t.Fatalf("cycle1=%v want pending", o)
	}
	if _, o := ig.Check(ctx); o != OutcomeRemediated {
		t.Fatalf("cycle2=%v want remediated", o)
	}
	if rec.done != 0 || len(rec.remedyFail) != 1 ||
		rec.remedyFail[0] != "suspect: journalctl --rotate --vacuum-time=3d "+
			"failed: journalctl vanished (partial)" {
		t.Fatalf("failure line = %v (done=%d)", rec.remedyFail, rec.done)
	}
	if _, o := ig.Check(ctx); o != OutcomePending {
		t.Fatalf("cycle3=%v want pending (streak reset after attempt)", o)
	}
}

func TestIntegrityNilRemedyGatesWithoutBudget(t *testing.T) {
	ig, rec := newTestIntegrity(t, "corrupt", nil, nil, nil)
	ig.cfg.Remedy = nil
	ctx := context.Background()
	if _, o := ig.Check(ctx); o != OutcomePending {
		t.Fatalf("cycle1=%v want pending", o)
	}
	if _, o := ig.Check(ctx); o != OutcomeGated {
		t.Fatalf("cycle2=%v want gated", o)
	}
	if rec.spent != 0 || len(rec.action) != 0 {
		t.Fatalf("gated path spent budget or logged action: %v", rec)
	}
}

func TestIntegrityStreakNeededOneActsImmediately(t *testing.T) {
	ig, rec := newTestIntegrity(t, "corrupt", nil, nil,
		func(cfg *IntegrityConfig) { cfg.StreakNeeded = 1 })
	ctx := context.Background()
	if _, o := ig.Check(ctx); o != OutcomeRemediated {
		t.Fatalf("o=%v want remediated on the first confirmed read", o)
	}
	if len(rec.pending) != 0 {
		t.Fatalf("progress lines on a threshold-1 site: %v", rec.pending)
	}
	// StreakNeeded <= 0 means the same thing.
	if _, o := NewIntegrity(IntegrityConfig{
		Probe:        func(context.Context) (string, error) { return "corrupt", nil },
		Markers:      []string{"corrupt"},
		StreakNeeded: 0,
		VacuumAge:    "3d",
		Remedy: func(_ context.Context, args ...string) (string, error) {
			return "", nil
		},
	}).Check(ctx); o != OutcomeRemediated {
		t.Fatalf("zero threshold o=%v want remediated", o)
	}
}
