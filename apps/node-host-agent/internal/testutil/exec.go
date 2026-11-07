// exec.go — the shared host-command recorder. Every suite that fakes
// hostexec.Config.RunCmd/RunCmdCombined (or a runner-shaped seam like
// kinedb's stdin-feeding runner) used to carry a private fake doing
// the same three things: log the argv, answer a canned reply keyed
// on a substring of the joined command line, and expose the log for
// assertions. FakeExec is that fake.
package testutil

import (
	"context"
	"strings"
	"sync"
)

// ExecRule is one canned reply: a command whose space-joined argv
// carries Substr answers Out/Err.
type ExecRule struct {
	Substr string // matched with strings.Contains against the joined argv
	Out    string // output to return
	Err    error  // non-nil → the command fails
}

// FakeExec records every command the subject ran and replies from an
// ordered rule list. When several rules match one command the
// LONGEST Substr wins — a generic stub ("rule list", "inspect") must
// not shadow the specific one ("rule list pref 1500") no matter the
// declaration order; equal lengths keep first-declared wins.
//
// Run matches the hostexec.Config.RunCmd / RunCmdCombined signature;
// RunStdin matches runner seams that also take an stdin string
// (kinedb). A command no rule matches returns ("", Miss) — Miss
// defaults to nil, i.e. silent success, so a fixture only stubs the
// calls it cares about.
type FakeExec struct {
	mu     sync.Mutex
	cmds   [][]string
	envs   [][]string
	stdins []string
	rules  []ExecRule
	miss   error
}

// NewFakeExec returns a recorder preloaded with rules.
func NewFakeExec(rules ...ExecRule) *FakeExec {
	return &FakeExec{rules: append([]ExecRule(nil), rules...)}
}

// On adds (or replaces) the canned success reply for commands
// carrying substr. Replacing keeps the rule's position.
func (f *FakeExec) On(substr, out string) *FakeExec {
	return f.set(ExecRule{Substr: substr, Out: out})
}

// FailOn adds (or replaces) the canned failure for commands carrying
// substr.
func (f *FakeExec) FailOn(substr string, err error) *FakeExec {
	return f.set(ExecRule{Substr: substr, Err: err})
}

// Clear drops every rule keyed on substr — the delete from the map-
// shaped fakes this replaces.
func (f *FakeExec) Clear(substr string) *FakeExec {
	f.mu.Lock()
	defer f.mu.Unlock()
	kept := f.rules[:0]
	for _, r := range f.rules {
		if r.Substr != substr {
			kept = append(kept, r)
		}
	}
	f.rules = kept
	return f
}

// Reset drops every rule — the fake is back to "all misses".
func (f *FakeExec) Reset() *FakeExec {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules = nil
	return f
}

// Miss sets the error returned for a command no rule matches
// (nil → silent success). Fluent for NewFakeExec().Miss(...) chains.
func (f *FakeExec) Miss(err error) *FakeExec {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.miss = err
	return f
}

func (f *FakeExec) set(r ExecRule) *FakeExec {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.rules {
		if f.rules[i].Substr == r.Substr {
			f.rules[i] = r
			return f
		}
	}
	f.rules = append(f.rules, r)
	return f
}

// lookup answers joined via the longest-matching rule. Caller holds mu.
func (f *FakeExec) lookup(joined string) (string, error) {
	best, bestLen := ExecRule{}, -1
	for _, r := range f.rules {
		if len(r.Substr) > bestLen && strings.Contains(joined, r.Substr) {
			best, bestLen = r, len(r.Substr)
		}
	}
	if bestLen < 0 {
		return "", f.miss
	}
	return best.Out, best.Err
}

// Run is the hostexec.Config.RunCmd/RunCmdCombined drop-in: logs argv
// and replies by rule.
func (f *FakeExec) Run(_ context.Context, argv []string) (string, error) {
	return f.record(nil, argv, "")
}

// RunStdin is the stdin-feeding runner variant (kinedb's runner
// seam — env is the secret channel: it reaches the child's
// environment, never argv).
func (f *FakeExec) RunStdin(_ context.Context, env, argv []string, stdin string) (string, error) {
	return f.record(env, argv, stdin)
}

func (f *FakeExec) record(env, argv []string, stdin string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cmds = append(f.cmds, append([]string(nil), argv...))
	f.envs = append(f.envs, append([]string(nil), env...))
	f.stdins = append(f.stdins, stdin)
	return f.lookup(strings.Join(argv, " "))
}

// ClearLog drops the recorded command/stdin log — rules stay, so a
// test can assert "nothing ran since X" without rebuilding the fake.
func (f *FakeExec) ClearLog() *FakeExec {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cmds = nil
	f.envs = nil
	f.stdins = nil
	return f
}

// Cmds returns every recorded argv in call order.
func (f *FakeExec) Cmds() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]string, len(f.cmds))
	for i, c := range f.cmds {
		out[i] = append([]string(nil), c...)
	}
	return out
}

// Envs returns every recorded child-env set in call order (nil for
// calls through Run — only RunStdin callers pass env).
func (f *FakeExec) Envs() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]string, len(f.envs))
	for i, e := range f.envs {
		out[i] = append([]string(nil), e...)
	}
	return out
}

// Count is the number of commands recorded.
func (f *FakeExec) Count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.cmds)
}

// Nth returns the space-joined argv of the i-th recorded command
// ("" when i is out of range, so count assertions still fail clean).
func (f *FakeExec) Nth(i int) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if i < 0 || i >= len(f.cmds) {
		return ""
	}
	return strings.Join(f.cmds[i], " ")
}

// Last returns the space-joined argv of the most recent command.
func (f *FakeExec) Last() string {
	return f.Nth(f.Count() - 1)
}

// Joined renders every recorded command one per line — the `cmds=%v`
// dump fixtures print on failure, greppable as one string.
func (f *FakeExec) Joined() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var b strings.Builder
	for _, c := range f.cmds {
		b.WriteString(strings.Join(c, " "))
		b.WriteByte('\n')
	}
	return b.String()
}

// Ran reports whether any recorded command carries substr.
func (f *FakeExec) Ran(substr string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.cmds {
		if strings.Contains(strings.Join(c, " "), substr) {
			return true
		}
	}
	return false
}

// LastStdin returns the most recent non-empty stdin the runner saw
// ("" when nothing was ever fed on stdin).
func (f *FakeExec) LastStdin() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.stdins) - 1; i >= 0; i-- {
		if f.stdins[i] != "" {
			return f.stdins[i]
		}
	}
	return ""
}
