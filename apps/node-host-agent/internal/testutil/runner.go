// runner.go — the shared fake for the `Run(ctx, name, args...)
// (string, error)` runner seam (converge.Runner — hostconfig's
// Runner alias is the main consumer). The hostconfig suite used to
// carry five private fakes over that seam — fakeRunner,
// scriptedRunner, hangRunner, budgetRunner, budgetProbe — each
// re-implementing the same jobs: record the joined "name args"
// call, answer a canned reply keyed on a substring of it, hang on
// ctx for the timeout tests, and note the ctx deadline each call
// ran under. FakeRunner is that fake.
//
// It deliberately does NOT import the converge package (testutil stays
// leaf): Run's signature matches the interface structurally, so
// `Runner: testutil.NewFakeRunner(...)` satisfies converge.Runner
// without the dependency. Reusing FakeExec was rejected — its
// `Run(ctx, argv []string)` shape does not match the name+args seam,
// and these callers assert on joined call lines, not argv slices.
package testutil

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// errScriptedFail is the placeholder error FailOn installs when the
// caller has no concrete error — Run re-wraps it with the actual
// command line so failures stay greppable (scriptedRunner parity).
var errScriptedFail = errors.New("scripted failure")

// RunnerRule is one canned outcome: a command whose joined
// "name args" line carries Substr answers Out, fails with Err, or
// blocks until ctx.Done() (Hang — the per-command-timeout tests).
// Out belongs on the reply list (On); Err/Hang on the fail list
// (FailOn/HangOn) — see lookup.
type RunnerRule struct {
	Substr string // matched with strings.Contains against the joined line
	Out    string // output to return
	Err    error  // non-nil → the command fails
	Hang   bool   // block until ctx.Done(), then fail with ctx.Err()
}

// FakeRunner records every call the subject ran and replies from two
// rule lists. A FAIL rule (Err or Hang) always beats a reply rule no
// matter which Substr is longer — the private fakes this replaces
// checked their error map before the reply map, so a broad canned
// reply must never un-fail a targeted failure. Within each list the
// LONGEST Substr wins (generic stubs must not shadow specific ones);
// equal lengths keep first-declared wins. A call no rule matches
// returns ("", Miss) — Miss defaults to nil, i.e. silent success.
//
// Run is safe for concurrent use and records under the lock BEFORE
// any hang — a Hang rule therefore never wedges Calls()/Count()
// assertions.
type FakeRunner struct {
	mu      sync.Mutex
	calls   []string
	dls     map[string]time.Duration
	replies []RunnerRule
	fails   []RunnerRule
	miss    error
}

// NewFakeRunner returns a recorder preloaded with rules: Err/Hang
// rules land on the fail list, plain Out rules on the reply list.
func NewFakeRunner(rules ...RunnerRule) *FakeRunner {
	f := &FakeRunner{}
	for _, r := range rules {
		if r.Err != nil || r.Hang {
			f.fails = append(f.fails, r)
		} else {
			f.replies = append(f.replies, r)
		}
	}
	return f
}

// On adds (or replaces) the canned success reply for commands
// carrying substr. Replacing keeps the rule's position.
func (f *FakeRunner) On(substr, out string) *FakeRunner {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.set(&f.replies, RunnerRule{Substr: substr, Out: out})
}

// FailOn adds (or replaces) the canned failure for commands carrying
// substr. A nil err installs the generic "scripted failure" — most
// callers only branch on non-nil.
func (f *FakeRunner) FailOn(substr string, err error) *FakeRunner {
	if err == nil {
		err = errScriptedFail
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.set(&f.fails, RunnerRule{Substr: substr, Err: err})
}

// HangOn adds (or replaces) the hang-until-ctx-done rule for
// commands carrying substr — the timeout/deadline tests' wedge.
func (f *FakeRunner) HangOn(substr string) *FakeRunner {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.set(&f.fails, RunnerRule{Substr: substr, Hang: true})
}

// Clear drops every rule (reply AND fail) keyed on substr.
func (f *FakeRunner) Clear(substr string) *FakeRunner {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.replies = dropSubstr(f.replies, substr)
	f.fails = dropSubstr(f.fails, substr)
	return f
}

// ClearFails drops every fail rule — replies stay (the
// `errs = map[string]bool{}` reset the scripted fixtures used).
func (f *FakeRunner) ClearFails() *FakeRunner {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fails = nil
	return f
}

// Reset drops every rule — the fake is back to "all misses".
func (f *FakeRunner) Reset() *FakeRunner {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.replies = nil
	f.fails = nil
	return f
}

// Miss sets the error returned for a command no rule matches
// (nil → silent success). Fluent for NewFakeRunner().Miss(...) chains.
func (f *FakeRunner) Miss(err error) *FakeRunner {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.miss = err
	return f
}

func (f *FakeRunner) set(list *[]RunnerRule, r RunnerRule) *FakeRunner {
	for i := range *list {
		if (*list)[i].Substr == r.Substr {
			(*list)[i] = r
			return f
		}
	}
	*list = append(*list, r)
	return f
}

func dropSubstr(list []RunnerRule, substr string) []RunnerRule {
	kept := list[:0]
	for _, r := range list {
		if r.Substr != substr {
			kept = append(kept, r)
		}
	}
	return kept
}

// lookup answers joined: longest matching fail rule first, then the
// longest matching reply rule, else the miss. Caller holds mu.
func (f *FakeRunner) lookup(joined string) RunnerRule {
	best := RunnerRule{}
	bestLen := -1
	for _, r := range f.fails {
		if len(r.Substr) > bestLen && strings.Contains(joined, r.Substr) {
			best, bestLen = r, len(r.Substr)
		}
	}
	if bestLen >= 0 {
		return best
	}
	best, bestLen = RunnerRule{}, -1
	for _, r := range f.replies {
		if len(r.Substr) > bestLen && strings.Contains(joined, r.Substr) {
			best, bestLen = r, len(r.Substr)
		}
	}
	if bestLen >= 0 {
		return best
	}
	return RunnerRule{Err: f.miss}
}

// Run is the converge.Runner drop-in: records the joined call line
// plus the ctx deadline the caller budgeted (DeadlineFor), then
// hangs or replies by rule. The record lands under the lock and the
// hang happens AFTER unlock so assertion accessors never block.
func (f *FakeRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	joined := name + " " + strings.Join(args, " ")
	f.mu.Lock()
	f.calls = append(f.calls, joined)
	if dl, ok := ctx.Deadline(); ok {
		if f.dls == nil {
			f.dls = map[string]time.Duration{}
		}
		f.dls[joined] = time.Until(dl)
	}
	r := f.lookup(joined)
	f.mu.Unlock()

	if r.Hang {
		<-ctx.Done()
		return "", ctx.Err()
	}
	if errors.Is(r.Err, errScriptedFail) {
		return "", fmt.Errorf("scripted failure for %q", joined)
	}
	if r.Err != nil {
		return "", r.Err
	}
	return r.Out, nil
}

// ClearLog drops the recorded call/deadline log — rules stay, so a
// test can assert "nothing ran since X" without rebuilding the fake.
func (f *FakeRunner) ClearLog() *FakeRunner {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = nil
	f.dls = nil
	return f
}

// Calls returns every recorded "name args" line in call order.
func (f *FakeRunner) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// CallsMatching returns the recorded lines carrying substr — the
// callsMatching helper every private fake carried.
func (f *FakeRunner) CallsMatching(substr string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if strings.Contains(c, substr) {
			out = append(out, c)
		}
	}
	return out
}

// Count is the number of calls recorded.
func (f *FakeRunner) Count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// Nth returns the i-th recorded call line ("" when out of range, so
// count assertions still fail clean).
func (f *FakeRunner) Nth(i int) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if i < 0 || i >= len(f.calls) {
		return ""
	}
	return f.calls[i]
}

// Last returns the most recent recorded call line.
func (f *FakeRunner) Last() string {
	return f.Nth(f.Count() - 1)
}

// Joined renders every recorded call one per line — the `calls=%v`
// dump fixtures print on failure, greppable as one string.
func (f *FakeRunner) Joined() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var b strings.Builder
	for _, c := range f.calls {
		b.WriteString(c)
		b.WriteByte('\n')
	}
	return b.String()
}

// Ran reports whether any recorded call carries substr.
func (f *FakeRunner) Ran(substr string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

// DeadlineFor returns the time-until-deadline the given joined call
// line observed (the budgetRunner/budgetProbe probes' job), and
// whether that call ran under a ctx deadline at all.
func (f *FakeRunner) DeadlineFor(joined string) (time.Duration, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.dls[joined]
	return d, ok
}
