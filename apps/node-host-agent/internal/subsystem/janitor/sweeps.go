// sweeps.go — the three cleanup bodies the janitor's Sweep runs in
// order: A (stale state-latch reaper), B (ghost systemd units +
// orphan `ip monitor` reaper) and the /proc + legacy-name inventory
// they share.
package janitor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
)

// The registry of currently-producible state-<name> latch names
// (exact names + the parameterized families whose suffix is minted
// per target at write time) lives in internal/latchdefs —
// latchdefs.LatchDefs / latchdefs.KnownLatchName, cross-checked
// against every latch-write site. The janitor only consumes it: a
// reaped latch is classified rule=max-age for a registered name and
// rule=unknown for anything else.

// legacyUnitNames — the retired shell-watchdog units, mirroring
// hostconfig's legacyWatchdogUnits list (hostconfig owns the unit
// FILES; the janitor owns the systemd RUNTIME records — kept as a
// separate list so neither side's edit is coupled).
var legacyUnitNames = map[string]bool{
	"node-watchdog.timer":                    true,
	"node-watchdog.service":                  true,
	"node-watchdog-failed.service":           true,
	"node-watchdog-failed@.service":          true,
	"k0sworker-watchdog.service":             true,
	"k0sworker-watchdog-restart.service":     true,
	"k0scontroller-watchdog.service":         true,
	"k0scontroller-watchdog-restart.service": true,
	"k0s-apiserver-wedge-probe.timer":        true,
	"k0s-apiserver-wedge-probe.service":      true,
	"k0s-kine-pool-probe.timer":              true,
	"k0s-kine-pool-probe.service":            true,
	"k0s-oomloop-probe.timer":                true,
	"k0s-oomloop-probe.service":              true,
	"nebula-route-guard.service":             true,
	"api-backend-guard.timer":                true,
	"api-backend-guard.service":              true,
	"kine-db-probe.timer":                    true,
	"kine-db-probe.service":                  true,
	"kine-compact-guard.timer":               true,
	"kine-compact-guard.service":             true,
	"kine-db-maint.timer":                    true,
	"kine-db-maint.service":                  true,
}

// legacyUnitPrefixes — legacy families listed by pattern: instantiated
// templates and the retired ansible-era node-config-agent units.
var legacyUnitPrefixes = []string{
	"node-watchdog-failed@", // instantiated template units
	"node-config-agent.",    // node-config-agent.service/.timer/...
}

// isLegacyUnit reports whether a unit name belongs to the retired
// watchdog/node-config-agent stack — the only names the janitor is
// allowed to reset-failed or stop.
func isLegacyUnit(unit string) bool {
	if legacyUnitNames[unit] {
		return true
	}
	for _, p := range legacyUnitPrefixes {
		if strings.HasPrefix(unit, p) {
			return true
		}
	}
	return false
}

// legacyProcMarkers — cmdline substrings identifying a process as a
// leftover of the retired shell stack (the route guard's monitor loop
// and the watchdog scripts it pruned).
var legacyProcMarkers = []string{
	"route-guard",
	"node-watchdog",
}

// --- A: stale state-latch reaper ---

// sweepLatches removes state-* files past LatchMaxAge — known latch
// names (owner gone/renamed) and unknown registry names alike (the
// age floor keeps a live foreign-schema writer's latch from
// flapping; see the package doc). last-* budgets, marker files and
// everything without the state- prefix are never touched.
func (j *Janitor) sweepLatches() {
	entries, err := os.ReadDir(j.cfg.WatchdogStateDir)
	if err != nil {
		j.cycles.WithLabelValues(checkLatchReaper, "abort").Inc()
		j.state.AppendLog(fmt.Sprintf(
			"janitor: state dir %s unreadable: %v — latch sweep skipped",
			j.cfg.WatchdogStateDir, err))
		return
	}
	now := j.cfg.Clock.Now()
	for _, e := range entries {
		key, ok := strings.CutPrefix(e.Name(), latchdefs.LatchFilePrefix)
		if !ok {
			continue
		}
		if e.IsDir() {
			j.state.AppendLog(fmt.Sprintf(
				"suspect: state dir entry %s is a directory — skipped", e.Name()))
			continue
		}
		// age starts at -1 for "Info() failed": unknown-age entries
		// are skipped (fail closed — no reaping on a guess), so by
		// the reap below age is always a real duration.
		age := time.Duration(-1)
		if fi, err := e.Info(); err == nil {
			age = now.Sub(fi.ModTime())
		}
		var rule string
		switch {
		case age < 0 || age <= j.cfg.LatchMaxAge:
			continue
		case !latchdefs.KnownLatchName(key):
			rule = "unknown"
		default:
			rule = "max-age"
		}
		p := filepath.Join(j.cfg.WatchdogStateDir, e.Name())
		if err := os.Remove(p); err != nil {
			j.state.AppendLog(fmt.Sprintf(
				"suspect: rm stale latch %s failed: %v", e.Name(), err))
			continue
		}
		j.state.AppendLog(fmt.Sprintf(
			"ACTION: reaped stale latch %s (age=%.1fh, rule=%s)",
			e.Name(), age.Hours(), rule))
		j.actions.WithLabelValues(checkLatchReaper, "reap").Inc()
	}
	j.cycles.WithLabelValues(checkLatchReaper, "ok").Inc()
}

// --- B: ghost systemd units + orphan `ip monitor` ---

// sweepLegacyUnits parses ONE `systemctl list-units --all` and heals
// the retired-unit records systemd keeps after their files are gone:
// Active=failed → reset-failed; LoadState=not-found but still
// active/activating → stop (retired code still running) + reset-failed.
// Only names on the legacy list are touched.
func (j *Janitor) sweepLegacyUnits(ctx context.Context) {
	if j.cfg.Systemd == nil {
		j.cycles.WithLabelValues(checkLegacyUnits, "gated").Inc()
		return
	}
	out, err := j.cfg.Systemd.Exec(ctx, "systemctl", "list-units",
		"--all", "--no-legend", "--no-pager", "--plain")
	if err != nil {
		j.cycles.WithLabelValues(checkLegacyUnits, "abort").Inc()
		j.state.AppendLog(fmt.Sprintf(
			"janitor: systemctl list-units failed: %v (%s)",
			err, strings.TrimSpace(out)))
		return
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		// UNIT LOAD ACTIVE SUB DESCRIPTION — the first four fields
		// are what we need; DESCRIPTION may contain spaces.
		if len(f) < 4 {
			continue
		}
		unit, load, active := f[0], f[1], f[2]
		if !isLegacyUnit(unit) {
			continue
		}
		switch {
		case active == "failed":
			j.resetFailedUnit(ctx, unit, load, active)
		case load == "not-found" && (active == "active" || active == "activating"):
			// Ghost still running retired code — stop it, then
			// clear any residual failure state.
			if sout, serr := j.cfg.Systemd.Exec(ctx,
				"systemctl", "stop", unit); serr != nil {
				j.state.AppendLog(fmt.Sprintf(
					"suspect: stop ghost unit %s failed: %v (%s)",
					unit, serr, strings.TrimSpace(sout)))
				continue
			}
			j.state.AppendLog(fmt.Sprintf(
				"ACTION: stopped ghost unit %s (load=%s active=%s)",
				unit, load, active))
			j.actions.WithLabelValues(checkLegacyUnits, "stop").Inc()
			j.resetFailedUnit(ctx, unit, load, active)
		}
	}
	j.cycles.WithLabelValues(checkLegacyUnits, "ok").Inc()
}

func (j *Janitor) resetFailedUnit(ctx context.Context, unit, load, active string) {
	if out, err := j.cfg.Systemd.Exec(ctx,
		"systemctl", "reset-failed", unit); err != nil {
		j.state.AppendLog(fmt.Sprintf(
			"suspect: reset-failed %s failed: %v (%s)",
			unit, err, strings.TrimSpace(out)))
		return
	}
	j.state.AppendLog(fmt.Sprintf(
		"ACTION: reset-failed ghost unit %s (load=%s active=%s)",
		unit, load, active))
	j.actions.WithLabelValues(checkLegacyUnits, "reset_failed").Inc()
}

// sweepIPMonitors kills stray `ip [-flags] monitor` processes left by
// the retired nebula-route-guard.service. The live route guard is
// in-agent (netlink socket, no forked monitor), so a standalone
// monitor is orphaned or foreign — killed only when ppid==1
// (reparented orphan) or the parent is itself a retired-script
// process; anything else is logged `suspect:` and skipped.
func (j *Janitor) sweepIPMonitors() {
	for _, pid := range j.procPIDs() {
		argv := j.proc.Cmdline(pid)
		if !isIPMonitorArgv(argv) {
			continue
		}
		cmdline := strings.Join(argv, " ")
		ppid, ok := j.proc.PPID(pid)
		if !ok {
			j.state.AppendLog(fmt.Sprintf(
				"suspect: ip monitor pid=%d (%s) — ppid unreadable, skipping",
				pid, cmdline))
			continue
		}
		if ppid == 1 {
			j.killIPMonitor(pid, cmdline, "reparented to init")
			continue
		}
		parent := strings.Join(j.proc.Cmdline(ppid), " ")
		switch {
		case parent == "":
			// Parent exited mid-scan — the kernel reparents the
			// monitor to init; the NEXT sweep reaps it as ppid==1.
			j.state.AppendLog(fmt.Sprintf(
				"suspect: ip monitor pid=%d ppid=%d vanished mid-scan — skipping",
				pid, ppid))
		case strings.Contains(parent, "node-host-agent"):
			// Should be impossible (the guard is in-process) — if a
			// future agent ever forks a monitor, this stays hands-off.
			j.state.AppendLog(fmt.Sprintf(
				"suspect: ip monitor pid=%d parented by agent pid=%d — skipping",
				pid, ppid))
		case isLegacyProcCmdline(parent):
			// Retired script still looping (e.g. the unit was torn
			// down but the shell survived): kill the loop first so
			// the monitor can't be respawned, then the monitor.
			j.state.AppendLog(fmt.Sprintf(
				"ACTION: kill legacy script pid=%d (%s)", ppid, parent))
			if err := j.cfg.killFn(ppid, syscall.SIGKILL); err != nil {
				j.state.AppendLog(fmt.Sprintf(
					"suspect: kill legacy script pid=%d failed: %v", ppid, err))
			}
			j.actions.WithLabelValues(checkIPMonitor, "kill").Inc()
			j.killIPMonitor(pid, cmdline,
				fmt.Sprintf("legacy parent pid=%d", ppid))
		default:
			j.state.AppendLog(fmt.Sprintf(
				"suspect: ip monitor pid=%d has non-legacy parent pid=%d (%s) — skipping",
				pid, ppid, parent))
		}
	}
	j.cycles.WithLabelValues(checkIPMonitor, "ok").Inc()
}

func (j *Janitor) killIPMonitor(pid int, cmdline, why string) {
	j.state.AppendLog(fmt.Sprintf(
		"ACTION: killed orphan ip monitor pid=%d (%s) cmdline=%q",
		pid, why, cmdline))
	if err := j.cfg.killFn(pid, syscall.SIGKILL); err != nil {
		j.state.AppendLog(fmt.Sprintf(
			"suspect: kill orphan ip monitor pid=%d failed: %v", pid, err))
	}
	j.actions.WithLabelValues(checkIPMonitor, "kill").Inc()
}

// isIPMonitorArgv matches a standalone iproute2 monitor:
// `<...>/ip [-flags...] monitor [objects...]`. Requiring the FIRST
// non-flag argument to be exactly "monitor" keeps `ip netns monitor`,
// `ip link show` etc. out — only the long-running event watcher
// matches.
func isIPMonitorArgv(argv []string) bool {
	if len(argv) < 2 || filepath.Base(argv[0]) != "ip" {
		return false
	}
	for _, a := range argv[1:] {
		if strings.HasPrefix(a, "-") {
			continue // -ts/-t/-s/-4/-o/-d flags precede the subcommand
		}
		return a == "monitor"
	}
	return false
}

// isLegacyProcCmdline reports whether a parent cmdline belongs to the
// retired watchdog/route-guard shell stack.
func isLegacyProcCmdline(cmdline string) bool {
	for _, m := range legacyProcMarkers {
		if strings.Contains(cmdline, m) {
			return true
		}
	}
	return false
}

// --- /proc helpers (hostPID: pod /proc == host /proc) ---
// The reads themselves live in platform/procfs (j.proc); only the
// logging wrapper below remains.

// procPIDs lists the numeric pid dirs under ProcRoot via procfs.
// An unreadable root is logged — a silent nil would make the
// monitor sweep no-op invisibly.
func (j *Janitor) procPIDs() []int {
	pids, err := j.proc.PIDs()
	if err != nil {
		j.state.AppendLog(fmt.Sprintf(
			"janitor: proc root %s unreadable: %v — ip monitor sweep skipped",
			j.cfg.ProcRoot, err))
		return nil
	}
	return pids
}
