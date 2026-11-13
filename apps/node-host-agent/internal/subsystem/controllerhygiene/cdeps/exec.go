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
	"strconv"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostexec"
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
// The implementation lives in platform/hostexec (the runners apply
// it natively via Config.ScrubSystemdEnv — the argv `env -u` prefix
// it replaced cost a fork per call); kept here as the named entry
// point the env-form callers (kine_storage's sqlite3 via
// hostexec.RunCombinedEnv) already spell.
func ScrubSystemdEnv(env []string) []string {
	return hostexec.ScrubSystemdEnv(env)
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
	// No argv-level env scrub here anymore: the production client
	// is built with ScrubSystemdEnv (the runners strip
	// NOTIFY_SOCKET/WATCHDOG_* from the child environ natively),
	// so argv reaches the client verbatim — `env -u ... --` used to
	// cost one extra fork per call.
	if combined {
		return sd.ExecCombinedBounded(ctx, budget, name, args...)
	}
	return sd.ExecBounded(ctx, budget, name, args...)
}

// --- named host commands over the HostExecFn seam ---
// The per-command xxxFn fields collapsed into the one exec seam:
// these methods carry the fixed argv + output munging each command
// had (the ctx budgets stay caller-side so a stubbed seam still
// sees the shell's `timeout N` contract).

// HoldEmergencyHeal is the fail-open counterpart for controller
// self-heal paths (apiserver/etcd/pki restarts): it holds only on
// positively-known maintenance so an unreachable apiserver can
// never deadlock the very heals that un-wedge the control plane.
// Nil Coord → false.
func (d *Deps) HoldEmergencyHeal(ctx context.Context) bool {
	return d.Cfg.Coord != nil && d.Cfg.Coord.HoldEmergencyHeal(ctx)
}

// Restart restarts unit on the HOST systemd — `timeout 90
// systemctl restart <unit>` parity. The 90s budget goes through the
// seam's ExecBounded arg rather than a ctx wrap: a tighter wrap
// SIGKILLed a slow restart mid-flight while systemd finished
// asynchronously and the gate logged FAIL. Routing through the host
// exec is what lets the restart reach the HOST systemd — the old
// raw exec had no dbus socket inside the DaemonSet and could never
// work.
func (d *Deps) Restart(ctx context.Context, unit string) error {
	// StampLocalRemediation is best-effort attribution: the cluster
	// side yields remote remediation while L1 self-heals. Nil Coord
	// → no-op; a stamp failure must not block the restart itself.
	if d.Cfg.Coord != nil {
		if err := d.Cfg.Coord.StampLocalRemediation(ctx); err != nil {
			d.State.AppendLogWarn(fmt.Sprintf(
				"suspect: nodecoord remediation stamp failed (attribution hint only): %v", err))
		}
	}
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

// MainPID reads the unit's main process pid — systemctl show -p
// MainPID parity, 0 = not running/absent. Zero-fork first: the
// shared systemd client's D-Bus property read (its own systemctl
// fallback fires only on connection-level failure). An unwired
// client or a failed D-Bus probe falls back to the same
// `systemctl show` argv UnitProp carries over the HostExecFn seam.
// The feeder loop polls it per cycle; forking `systemctl show` per
// poll bought nothing the D-Bus property read doesn't answer.
func (d *Deps) MainPID(ctx context.Context, unit string) (uint32, error) {
	cctx, cancel := context.WithTimeout(ctx, defaultSystemctlBudget)
	defer cancel()
	if d.Cfg.Systemd != nil {
		if pid, err := d.Cfg.Systemd.MainPID(cctx, unit); err == nil {
			return pid, nil
		}
	}
	out, err := d.Cfg.HostExecFn(cctx, false, 0,
		"systemctl", "show", unit, "-p", "MainPID", "--value")
	out = strings.TrimSpace(out)
	pid, perr := strconv.ParseUint(out, 10, 32)
	if perr != nil {
		if err != nil {
			return 0, err
		}
		return 0, fmt.Errorf("%s: unparsable MainPID %q", unit, out)
	}
	return uint32(pid), nil
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

// SSKill drops the apiserver's hung HTTP/2 watch streams in the
// host network namespace before a wedge restart
// (cp-component-restart), so the restart (and the post-restart
// reconnect) starts clean. It rides the netlinkx SOCK_DESTROY path
// (platform SockDestroyFn seam) — the in-process `ss -K sport =
// :6443` replacement that needs no ss binary and no fork.
func (d *Deps) SSKill(ctx context.Context) error {
	_, err := d.Cfg.SockDestroyFn(6443)
	return err
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
