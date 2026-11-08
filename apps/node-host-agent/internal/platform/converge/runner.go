// runner.go — the host-exec contract every converge verb runs over
// (Runner) plus the two production implementations and the budgeted
// Run helper. Tests substitute a fake Runner — the verbs never exec
// directly.
package converge

import (
	"context"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostexec"
)

// Runner executes a command inside the HOST namespaces.
type Runner interface {
	// Run returns combined stdout ("" on error).
	Run(ctx context.Context, name string, args ...string) (string, error)
}

// NsenterRunner enters PID 1 mount/uts/ipc/net/pid namespaces —
// the same access community.docker.nsenter gave the ansible pod.
// The flag list is hostexec.NSFlags(hostexec.NSAll) — one shared
// definition with the hostexec wrap (the flags cannot drift apart).
// It is still NOT routed through hostexec.Runner: that would stack
// its own Config.Timeout on top of the deadline RunBudget already
// applied to ctx — only the exec plumbing (capped output,
// WaitDelay) is shared, via hostexec.RunCombined.
type NsenterRunner struct{}

func (NsenterRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	argv := []string{"nsenter", "-t", "1"}
	argv = append(argv, hostexec.NSFlags(hostexec.NSAll)...)
	argv = append(argv, "--", name)
	argv = append(argv, args...)
	out, err := hostexec.RunCombined(ctx, argv...)
	return strings.TrimRight(out, "\n"), err
}

// DirectRunner runs commands unwrapped — the standalone systemd
// deployment (HostRoot "/") is already inside the host namespaces.
// Same hostexec.RunCombined container-side exec as NsenterRunner,
// minus the wrap.
type DirectRunner struct{}

func (DirectRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := hostexec.RunCombined(ctx,
		append([]string{name}, args...)...)
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
