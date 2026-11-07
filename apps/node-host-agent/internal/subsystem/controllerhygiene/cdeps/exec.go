// exec.go — the host-command/env plumbing shared by the Config seam
// defaults: the NOTIFY_SOCKET/WATCHDOG_* scrub (argv form for the
// shared platform/systemd client, env form for the rare in-container
// execs), the nil-tolerant systemd-client wrapper every host command
// routes through, and the sd_notify datagram sender's NotifyFn seam.
package cdeps

import (
	"context"
	"errors"
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

// hostExecCtx runs name args... on the host through the shared
// systemd client — nsenter-wrapped to host PID 1's namespaces inside
// the DaemonSet, so systemctl/journalctl/ss act on the host's systemd,
// journal and network namespace (the raw container-side execs this
// replaces saw the pod's empty journal view and had no dbus socket).
// combined selects ExecCombined — stderr folded into the returned
// output, required for probes whose evidence lives off stdout
// (journalctl prints "No journal files were found." / "File ... is
// corrupt" on stderr). A nil client reports the unwired wiring
// instead of returning empty output: a fake empty journal read would
// feed the journal-unreadable tracker a bogus "journald-wide empty
// reply" verdict (workerhygiene parity).
func hostExecCtx(ctx context.Context, sd *systemd.Client,
	combined bool, name string, args ...string) (string, error) {
	return hostExecCtxBounded(ctx, sd, combined, 0, name, args...)
}

// hostExecCtxBounded is hostExecCtx with a per-call budget replacing
// the shared client's Config.Timeout — for remediations whose shell
// budget was longer than 30s (the apiserver wedge gate's `timeout
// 90 systemctl restart`). budget <= 0 keeps the client default.
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

// sdNotify sends msg as a datagram to the sd_notify unix socket —
// `systemd-notify WATCHDOG=1` parity without the binary. A thin
// wrapper over the shared platform/sdnotify one-shot sender: the
// feeder re-dials per message rather than holding a conn open
// (agent's self-watchdog holds one conn instead), and the (sock,
// msg) shape is what config.go's NotifyFn default closes over.
func sdNotify(sock, msg string) error {
	return sdnotify.SendOnce(sock, msg)
}
