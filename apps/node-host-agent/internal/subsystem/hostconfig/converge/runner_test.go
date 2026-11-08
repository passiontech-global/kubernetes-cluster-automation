// runner_test.go — RunBudget's deadline plumbing over a stub Runner
// (the production Nsenter/Direct runners are thin exec wrappers; the
// verbs are what carry behavior worth pinning).
package converge

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostexec"
)

// stubRunner records argv and the ctx deadline RunBudget applied,
// and replies with the canned out/err. Shared with systemd_test.go.
type stubRunner struct {
	out         string
	err         error
	cmds        [][]string
	deadline    time.Time
	hasDeadline bool
}

func (s *stubRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	s.cmds = append(s.cmds, append([]string{name}, args...))
	s.deadline, s.hasDeadline = ctx.Deadline()
	return s.out, s.err
}

func TestRunBudgetPassesThrough(t *testing.T) {
	r := &stubRunner{out: "the-out", err: nil}
	out, err := RunBudget(context.Background(), r, time.Second, "nft", "list", "ruleset")
	if err != nil {
		t.Fatal(err)
	}
	if out != "the-out" {
		t.Fatalf("out = %q", out)
	}
	if !slices.Equal(r.cmds[0], []string{"nft", "list", "ruleset"}) {
		t.Fatalf("argv = %v", r.cmds[0])
	}
}

func TestRunBudgetAppliesDeadline(t *testing.T) {
	r := &stubRunner{}
	before := time.Now()
	if _, err := RunBudget(context.Background(), r, time.Minute, "true"); err != nil {
		t.Fatal(err)
	}
	if !r.hasDeadline {
		t.Fatal("a positive budget must attach a ctx deadline")
	}
	// The deadline lands ~budget out — assert it brackets sanely.
	if r.deadline.Before(before.Add(50*time.Second)) || r.deadline.After(before.Add(2*time.Minute)) {
		t.Fatalf("deadline = %v, want ~now+1m", r.deadline)
	}
}

func TestRunBudgetNonPositiveLeavesCtxAlone(t *testing.T) {
	for _, budget := range []time.Duration{0, -time.Second} {
		r := &stubRunner{}
		if _, err := RunBudget(context.Background(), r, budget, "true"); err != nil {
			t.Fatal(err)
		}
		if r.hasDeadline {
			t.Fatalf("budget %v must not attach a deadline", budget)
		}
	}
}

func TestRunBudgetPropagatesError(t *testing.T) {
	want := errors.New("exec blew up")
	r := &stubRunner{out: "partial", err: want}
	out, err := RunBudget(context.Background(), r, time.Second, "false")
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
	if out != "partial" {
		t.Fatalf("out = %q — output must return alongside the error", out)
	}
}

// ---------- production adapters (Nsenter/Direct Run) ----------

// swapExecSeam points a production adapter at a recording fake exec —
// RunCmdCombined is hostexec's designed test seam, and the adapters
// are the fixed package-level values over it — restoring the original
// on cleanup. The fake observes the exact production argv, so the
// adapters' two owned behaviors (the NSAll wrap / its absence, and the
// trailing-newline trim) are pinned without execing anything.
func swapExecSeam(t *testing.T, slot **hostexec.Runner, hostRoot string,
	run func(ctx context.Context, argv []string) (string, error)) {
	t.Helper()
	old := *slot
	*slot = hostexec.New(hostexec.Config{
		HostRoot:       hostRoot,
		Timeout:        noStackTimeout,
		RunCmdCombined: run,
	})
	t.Cleanup(func() { *slot = old })
}

// TestNsenterRunnerWrapsArgvAndTrims — NsenterRunner must wrap with
// the full NSAll flag set (hostexec's declaration order -m -u -i -n
// -p), trim the trailing newline off combined output, and pass the
// exec error through alongside the (trimmed) partial output.
func TestNsenterRunnerWrapsArgvAndTrims(t *testing.T) {
	var gotArgv []string
	swapExecSeam(t, &nsenterAdapt, hostexec.DefaultHostRoot,
		func(ctx context.Context, argv []string) (string, error) {
			gotArgv = argv
			return "combined-out\n", nil
		})
	out, err := NsenterRunner{}.Run(context.Background(),
		"systemctl", "is-active", "k0sworker.service")
	if err != nil {
		t.Fatal(err)
	}
	if out != "combined-out" {
		t.Fatalf("out = %q — trailing newline must be trimmed", out)
	}
	want := []string{"nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p",
		"--", "systemctl", "is-active", "k0sworker.service"}
	if !slices.Equal(gotArgv, want) {
		t.Fatalf("argv = %v, want %v", gotArgv, want)
	}

	// error path: the error and the partial output survive together.
	wantErr := errors.New("exec blew up")
	swapExecSeam(t, &nsenterAdapt, hostexec.DefaultHostRoot,
		func(ctx context.Context, argv []string) (string, error) {
			return "partial\n", wantErr
		})
	out, err = NsenterRunner{}.Run(context.Background(), "false")
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
	if out != "partial" {
		t.Fatalf("out = %q — partial output must return alongside the error", out)
	}
}

// TestDirectRunnerRunsUnwrapped — DirectRunner (standalone, HostRoot
// "/") must run the bare argv — no nsenter prefix — with the same
// trim contract as the nsenter adapter.
func TestDirectRunnerRunsUnwrapped(t *testing.T) {
	var gotArgv []string
	swapExecSeam(t, &directAdapt, "/",
		func(ctx context.Context, argv []string) (string, error) {
			gotArgv = argv
			return "standalone-out\n", nil
		})
	out, err := DirectRunner{}.Run(context.Background(), "ip", "rule", "list")
	if err != nil {
		t.Fatal(err)
	}
	if out != "standalone-out" {
		t.Fatalf("out = %q — trailing newline must be trimmed", out)
	}
	if !slices.Equal(gotArgv, []string{"ip", "rule", "list"}) {
		t.Fatalf("argv = %v, want the bare unwrapped command", gotArgv)
	}
}
