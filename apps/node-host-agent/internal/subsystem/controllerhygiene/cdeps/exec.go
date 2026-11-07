// exec.go — the host-command/env plumbing shared by the Config seam
// defaults: the NOTIFY_SOCKET/WATCHDOG_* scrub (argv form for the
// shared platform/systemd client, env form for the rare in-container
// execs), the nil-tolerant systemd-client wrapper the HostExecFn
// default routes through, the sd_notify datagram sender's NotifyFn
// default, and the named host-command helpers the old per-command
// seams became (they build argv + parse over the one HostExecFn —
// methods do the munging, the seam does the I/O).
package cdeps

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/sdnotify"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
)

// defaultSystemctlBudget caps the query-shaped systemctl calls —
// shell `timeout 10` parity. The shared client adds its own
// Config.Timeout (30s default) inside every Exec — wrapping the ctx
// here keeps the tighter per-query budget the shell had.
const defaultSystemctlBudget = 10 * time.Second

// defaultRestartBudget is the remediate gate's `timeout 90` parity —
// a control-plane unit restart legitimately outlives the shared
// client's 30s default, so it goes through ExecBounded instead.
const defaultRestartBudget = 90 * time.Second

// ScrubSystemdEnv drops NOTIFY_SOCKET/WATCHDOG_* so child systemctl /
// journalctl processes cannot sd_notify back to our unit — the
// `env -u NOTIFY_SOCKET -u WATCHDOG_PID -u WATCHDOG_USEC` fix the
// feeder applies (systemd>=255 auto-sends EXIT_STATUS otherwise).
// Used by the container-side exec whose env the argv form cannot
// reach: kine_storage's sqlite3 passes the scrubbed environ through
// hostexec.RunCombinedEnv (etcdctl needs no scrub — it goes through
// hostexec.Run for the separate-stderr capture instead).
// Commands routed through the shared systemd client get the argv
// equivalent — scrubArgv.
func ScrubSystemdEnv(env []string) []string {
	out := env[:0]
	for _, e := range env {
		if strings.HasPrefix(e, "NOTIFY_SOCKET=") ||
			strings.HasPrefix(e, "WATCHDOG_PID=") ||
			strings.HasPrefix(e, "WATCHDOG_USEC=") {
			continue
		}
		out = append(out, e)
	}
	clear(env[len(out):]) // drop refs held by the filtered tail
	return out
}

// scrubArgv prefixes name+args with `env -u NOTIFY_SOCKET -u
// WATCHDOG_PID -u WATCHDOG_USEC --` — the ScrubSystemdEnv fix in argv
// form, for commands routed through systemd.Client/hostexec (their
// RunCmd seam carries no env slot). `env` resolves on the HOST inside
// the nsenter wrap, immediately before the real binary.
func scrubArgv(name string, args ...string) []string {
	argv := make([]string, 0, len(args)+9)
	argv = append(argv, "env",
		"-u", "NOTIFY_SOCKET",
		"-u", "WATCHDOG_PID",
		"-u", "WATCHDOG_USEC",
		"--", name)
	return append(argv, args...)
}

// hostExecCtxBounded runs name args... on the host through the
// shared systemd client — the HostExecFn production default.
// nsenter-wrapped to host PID 1's namespaces inside the DaemonSet,
// so systemctl/journalctl/ss act on the host's systemd, journal and
// network namespace (the raw container-side execs this replaces saw
// the pod's empty journal view and had no dbus socket). combined
// selects ExecCombined — stderr folded into the returned output,
// required for probes whose evidence lives off stdout (journalctl
// prints "No journal files were found." / "File ... is corrupt" on
// stderr). A nil client reports the unwired wiring instead of
// returning empty output: a fake empty journal read would feed the
// journal-unreadable tracker a bogus "journald-wide empty reply"
// verdict (workerhygiene parity). budget >0 is the per-call
// ExecBounded override for remediations whose shell budget was
// longer than the shared client's 30s Config.Timeout (the apiserver
// wedge gate's `timeout 90 systemctl restart`); <=0 keeps the
// client default.
func hostExecCtxBounded(ctx context.Context, sd *systemd.Client,
	combined bool, budget time.Duration,
	name string, args ...string) (string, error) {

	if sd == nil {
		return "", errors.New("no systemd client wired")
	}
	argv := scrubArgv(name, args...)
	if combined {
		return sd.ExecCombinedBounded(ctx, budget, argv[0], argv[1:]...)
	}
	return sd.ExecBounded(ctx, budget, argv[0], argv[1:]...)
}

// --- named host commands over the HostExecFn seam ---
// The per-command xxxFn fields collapsed into the one exec seam:
// these methods carry the fixed argv + output munging each command
// had (the ctx budgets stay caller-side so a stubbed seam still
// sees the shell's `timeout N` contract).

// Restart restarts unit on the HOST systemd — `timeout 90
// systemctl restart <unit>` parity. The 90s budget goes through the
// seam's ExecBounded arg rather than a ctx wrap: a tighter wrap
// SIGKILLed a slow restart mid-flight while systemd finished
// asynchronously and the gate logged FAIL. Routing through the host
// exec is what lets the restart reach the HOST systemd — the old
// raw exec had no dbus socket inside the DaemonSet and could never
// work.
func (d *Deps) Restart(ctx context.Context, unit string) error {
	_, err := d.Cfg.HostExecFn(ctx, true, defaultRestartBudget,
		"systemctl", "restart", unit)
	return err
}

// UnitProp reads one `systemctl show <unit> -p <prop> --value`
// property — `timeout 10` parity, output trimmed.
func (d *Deps) UnitProp(ctx context.Context, unit, prop string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, defaultSystemctlBudget)
	defer cancel()
	out, err := d.Cfg.HostExecFn(cctx, false, 0,
		"systemctl", "show", unit, "-p", prop, "--value")
	return strings.TrimSpace(out), err
}

// UnitActiveState is `systemctl is-active <unit>` — the output is
// the verdict, never the error (is-active exits non-zero for
// inactive; shell `|| true` parity — an exec failure reads as ""
// the same way an absent unit does).
func (d *Deps) UnitActiveState(ctx context.Context, unit string) string {
	cctx, cancel := context.WithTimeout(ctx, defaultSystemctlBudget)
	defer cancel()
	out, _ := d.Cfg.HostExecFn(cctx, false, 0,
		"systemctl", "is-active", unit)
	return strings.TrimSpace(out)
}

// SSKill runs `ss -K sport = :6443` — kills the apiserver's hung
// HTTP/2 watch streams in the host network namespace before a wedge
// restart (W8-CP1), so the restart (and the post-restart reconnect)
// starts clean. It goes through the shared client (host ss binary +
// host netns) rather than relying on an ss binary inside the agent
// image — the old raw exec only worked because the pod is
// hostNetwork AND happened to carry ss.
func (d *Deps) SSKill(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := d.Cfg.HostExecFn(cctx, true, 0,
		"ss", "-K", "sport", "=", ":6443")
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(out))
	}
	return nil
}

// sdNotify sends msg as a datagram to the sd_notify unix socket —
// `systemd-notify WATCHDOG=1` parity without the binary. A thin
// wrapper over the shared platform/sdnotify one-shot sender: the
// feeder re-dials per message rather than holding a conn open
// (agent's self-watchdog holds one conn instead), and the (sock,
// msg) shape is what config.go's NotifyFn default closes over.
func sdNotify(sock, msg string) error {
	return sdnotify.SendOnce(sock, msg)
}
