// routeguard_restore.go — the restore path: locate and gate on
// /etc/nebula/<net>/nebula-up.sh (host mount-ns view, the
// `systemctl is-active nebula@<net>` check, the watchdog kill
// switch), then re-run the script through the runMountCmd nsenter
// seam — the bash guard's restore() per debounced delete burst.
package nethealth

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
)

// nebulaUpScript is the restore path as seen from the HOST mount
// namespace — the same path systemd's ExecStartPost ran.
func nebulaUpScript(net string) string {
	return "/etc/nebula/" + net + "/nebula-up.sh"
}

// nebulaUpExists stats the restore script through HostRoot — the
// no-op gate for plain workers without a converged nebula mesh.
func (n *NetHealth) nebulaUpExists(wd *watchdogconf.Config) bool {
	if wd.NebulaNet == "" {
		return false
	}
	fi, err := os.Stat(filepath.Join(n.cfg.HostRoot,
		"etc/nebula", wd.NebulaNet, "nebula-up.sh"))
	return err == nil && fi.Mode().IsRegular()
}

// restoreRouteGuard re-runs /etc/nebula/<net>/nebula-up.sh — the
// restore() the bash guard ran per burst. The script is idempotent
// and reads the overlay state file itself, so it only writes ip
// rules when nebula actually owns the dataplane (no rule stomping
// while overlay=tinc).
func (n *NetHealth) restoreRouteGuard(ctx context.Context) {
	wd := n.watchdogConf()
	if !wd.SignalEnabled(checkRouteGuard) {
		logger().Debug("route-guard: restore skipped — kill switch off " +
			"(WD_SIG_ROUTE_GUARD=off)")
		return
	}
	if !n.nebulaUpExists(wd) {
		logger().Debug("route-guard: restore skipped — nebula-up.sh gone "+
			"mid-run", "net", wd.NebulaNet)
		return
	}
	// bash gate: restore only while `systemctl is-active
	// nebula@<net>` says active — a deliberately stopped unit must
	// not be resurrected by its own delete events (inactive,
	// deactivating AND no-systemd all count as down; activating is
	// the unit's own ExecStartPost job).
	if n.cfg.Systemd == nil {
		logger().Debug("route-guard: restore skipped — no systemd client",
			"unit", "nebula@"+wd.NebulaNet)
		return
	}
	active, err := n.cfg.Systemd.Active(ctx, "nebula@"+wd.NebulaNet)
	if err != nil {
		// Fail closed: an unanswerable probe (dbus down, systemctl
		// missing) must not resurrect a possibly-stopped unit —
		// skip the restore this cycle.
		logger().Warn("route-guard: restore skipped — is-active probe "+
			"failed (fail closed)",
			"unit", "nebula@"+wd.NebulaNet,
			"error", err)
		return
	}
	if !active {
		logger().Debug("route-guard: restore skipped — nebula unit not "+
			"active",
			"unit", "nebula@"+wd.NebulaNet)
		return
	}
	script := nebulaUpScript(wd.NebulaNet)
	// runMountCmd = nsenter -t 1 -m -n -- : the script gets the host
	// mount+net namespaces (host iptables/nft/sysctl, host /etc
	// files) — identical environment to the unit's ExecStartPost.
	if out, err := n.cfg.runMountCmd(ctx, []string{script}); err != nil {
		n.cycles.WithLabelValues(checkRouteGuard, "restore_error").Inc()
		n.state.AppendLog(fmt.Sprintf("route-guard: %s failed: %v (%s)",
			script, err, trimRunErr(out)))
		return
	}
	n.actions.WithLabelValues(checkRouteGuard, "restored").Inc()
	n.state.AppendLog("ACTION: route-guard re-ran nebula-up.sh after netlink delete")
}
