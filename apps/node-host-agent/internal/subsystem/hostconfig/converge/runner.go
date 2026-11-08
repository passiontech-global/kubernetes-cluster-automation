// runner.go — the host-exec contract every converge verb runs over
// (Runner) plus the two production implementations and the budgeted
// Run helper. Tests substitute a fake Runner — the verbs never exec
// directly. The nsenter prefix itself lives ONLY in hostexec now: both
// production runners are thin adapters over hostexec.Runner (wrap
// decision, flag list, capped combined output and WaitDelay are its
// single definition); the adapters add the trailing-newline trim and
// the no-extra-timeout policy.
package converge

import (
	"context"
	"math"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostexec"
)

// Runner executes a command inside the HOST namespaces.
type Runner interface {
	// Run returns combined stdout ("" on error).
	Run(ctx context.Context, name string, args ...string) (string, error)
}

// noStackTimeout is the budget the adapters hand hostexec: the
// per-command deadline is RunBudget's job — it applies the budget to
// ctx BEFORE the runner sees it — and stacking a second cap here would
// silently clip deliberate remediation budgets (the apiserver wedge
// gate's `timeout 90 systemctl restart` runs under a 90s budget;
// hostexec's 30s default would win the WithTimeout race and kill it at
// 30s). hostexec's execBounded always installs a deadline, so the
// adapters pass the largest representable one (~292 years) — inert in
// practice, but it keeps the Runner quartet's contract.
const noStackTimeout = time.Duration(math.MaxInt64)

// The two production adapters share one exec shape: ExecCombined with
// NSAll — combined output because the verbs grep ansible-era combined
// stdout+stderr — and no timeout of their own (noStackTimeout).
// ExecCombined's seam defaults to hostexec.RunCombined, the same
// container-side helper the bespoke runners called directly, so the
// 16MiB output cap and the WaitDelay grandchild-pipe bound carry over
// unchanged.
var (
	// nsenterAdapt always wraps: HostRoot is pinned off "/" so
	// hostexec's wrap gate fires whatever the deployment — the value
	// itself is otherwise unused (the exec is container-side through
	// RunCombined, no chroot is involved).
	nsenterAdapt = hostexec.New(hostexec.Config{
		HostRoot: hostexec.DefaultHostRoot,
		Timeout:  noStackTimeout,
	})
	// directAdapt never wraps: HostRoot "/" lands in hostexec's
	// skip-wrap branch — the standalone systemd deployment is already
	// inside the host namespaces.
	directAdapt = hostexec.New(hostexec.Config{
		HostRoot: "/",
		Timeout:  noStackTimeout,
	})
)

// NsenterRunner enters PID 1 mount/uts/ipc/net/pid namespaces —
// the same access community.docker.nsenter gave the ansible pod. A
// thin adapter over hostexec.Runner: the `nsenter -t 1 <flags> --`
// prefix is hostexec's argv wrap for NSAll (one definition with every
// other host-exec call site), with the adapter-owned trim and
// no-stack timeout on top.
type NsenterRunner struct{}

func (NsenterRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := nsenterAdapt.ExecCombined(ctx, hostexec.NSAll, name, args...)
	return strings.TrimRight(out, "\n"), err
}

// DirectRunner runs commands unwrapped — the standalone systemd
// deployment (HostRoot "/") is already inside the host namespaces.
// Same adapter shape as NsenterRunner, minus the wrap (HostRoot "/"
// disables it inside hostexec).
type DirectRunner struct{}

func (DirectRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := directAdapt.ExecCombined(ctx, hostexec.NSAll, name, args...)
	return strings.TrimRight(out, "\n"), err
}

// RunBudget runs name through r under a per-command deadline: the
// converge ctx is long-lived, so a hung host binary must time out
// here rather than wedge the loop. A non-positive budget leaves the
// caller's ctx deadline alone. Failures are logged at Debug — the
// caller decides which deserve a Warn.
func RunBudget(ctx context.Context, r Runner, budget time.Duration, name string, args ...string) (string, error) {
	if budget > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, budget)
		defer cancel()
	}
	out, err := r.Run(ctx, name, args...)
	if err != nil {
		logger().Debug("converge: host command failed",
			"cmd", name+" "+strings.Join(args, " "), "out", out, "error", err)
	}
	return out, err
}
