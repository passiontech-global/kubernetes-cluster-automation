// helpers.go — watchdog file helpers and the shared host helpers
// (nsenter `ip`, unit probes, state-dir listing). Split out of
// nethealth.go.
package nethealth

import (
	"context"
	"path/filepath"
)

// --- watchdog file helpers (lib.sh parity) ---
//
// The on-disk contract itself lives in platform/hoststate — n.state
// is the single Store implementation of state_enter/state_exit,
// rate_ok/rate_spend, the last-suspect-* dedupe budgets, the
// watchdog log append and the last-run stamp (BUG-H1). Atomic file
// writes go through platform/hostutil.

// stateExit removes state-<name> if present and logs the
// transition — clears the NPD permanent condition — plus the
// nethealth divergence, named on the Store:
// Store.ExitClearSuspect drops the latch's OWN last-suspect-<name>
// file, and only when the latch actually exited (it returns false —
// no clear — while another owner still holds a multi-owner latch).
// The NON-latch keys (egress-probe-<ip>, conntrack-parse,
// clock-adjtimex, ...) have no state-* twin to exit with, so a
// cleared condition would otherwise suppress the first line of a
// re-incident for up to suspectLogCadence — a latch exit IS an
// incident boundary; a still-held condition pays at most one early
// re-log line.
func (n *NetHealth) stateExit(name string) {
	n.state.ExitClearSuspect(name)
}

// --- shared helpers ---

// ip runs the host `ip` tool through the runner seam. Failures are
// debug-logged here so the many best-effort callers that drop the
// error (rule adds/dels during drift heal, probe-window swaps) still
// leave a diagnostic trail — the callers that handle the error get
// it returned as before.
func (n *NetHealth) ip(ctx context.Context, args ...string) (string, error) {
	out, err := n.cfg.runHostCmd(ctx, append([]string{"ip"}, args...))
	if err != nil {
		logger().Debug("nethealth: host ip command failed",
			"args", args,
			"output", trimRunErr(out), "error", err)
	}
	return out, err
}

// egressFiles lists state-dir files matching any prefix.
func (n *NetHealth) egressFiles(prefixes ...string) []string {
	var out []string
	for _, p := range prefixes {
		files, err := filepath.Glob(filepath.Join(n.cfg.WatchdogStateDir, p+"*"))
		if err == nil {
			out = append(out, files...)
		}
	}
	return out
}

// unitActive mirrors `systemctl is-enabled + is-active` — the
// runner's overlay-active probes (WD_NEBULA_ACTIVE/WD_TINC_ACTIVE).
func (n *NetHealth) unitEnabledActive(ctx context.Context, unit string) bool {
	if n.cfg.Systemd == nil {
		return false
	}
	return n.cfg.Systemd.IsEnabled(ctx, unit) && n.cfg.Systemd.IsActive(ctx, unit)
}
