// The watchdog-state janitor — a self-healing sweep for the two
// cleanup classes the shell→Go port left behind (field findings,
// 2026-11). It lives in its own package (extracted from
// workerhygiene, whose checks produce most of the latches it
// guards): the conventions it guards are the node-watchdog
// state-dir contract, not workerhygiene internals, and it is
// registered as its OWN agent subsystem (not gated on k0sworker):
// the state dir is shared by workerhygiene, nethealth,
// controllerhygiene, hostmetrics and apiprober, and ghost units
// exist on controllers and standalone hubs too.
//
// A. Stale state latches — state-* files are latch memory: presence
// suppresses repeat alerts and drives gates (NPD conditions,
// remediate G3/G6, hostmetrics watchdog_state series). A latch only
// clears when its condition's STATE-EXIT path runs — a latch left by
// a removed/renamed check, or orphaned when a condition resolved
// under a crashed/old binary, sits forever (real case:
// state-node-overloaded ~11h stale on a healthy worker). The reaper
// removes a state-* file once its mtime is older than LatchMaxAge
// (24h) — a still-active latch's owner re-enters within one check
// cycle, so the worst case is one duplicated STATE-ENTER per day
// per latch. The age floor applies to UNKNOWN registry names too:
// a different-schema writer on the same host (a retired legacy
// watchdog unit still looping, an older agent binary) rewrites its
// latch right after a reap, so instant reaping turned into a
// delete/rewrite flap every sweep — while that writer lives its own
// writes keep the mtime fresh, and 24h after it dies the orphan is
// reaped like any stale latch.
// last-* rate-limit budgets and every non-state-* file are NEVER
// touched — deleting a last-* file would silently bypass cooldowns.
//
// B. Legacy/ghost systemd units — pruneLegacyWatchdog
// (internal/subsystem/hostconfig) removes the retired shell-watchdog unit
// FILES, but systemd keeps runtime records: `Loaded: not-found
// Active: failed` ghosts that never age out, and the occasional
// not-found-but-active ghost still running retired code (the stray
// `ip -ts monitor` watcher from before the route guard moved
// in-agent). One `systemctl list-units --all` per sweep finds the
// ghosts; matching units get reset-failed (and stopped when still
// active). Separately, a `…/ip [-flags] monitor` process is killed
// ONLY when ownership is verified: ppid 1 = a reparented orphan, or
// a parent whose cmdline is a retired watchdog/route-guard script.
// The agent's own route guard runs INSIDE the agent process as a
// netlink socket (nethealth/routeguard.go) — it never forks an `ip
// monitor` child — but anything ambiguous is logged `suspect:` and
// skipped rather than killed.
package janitor

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/cycle"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/systemd"
)

const (
	defaultJanitorInterval = 10 * time.Minute
	// latchMaxAge is the reap age for every state-* latch: since
	// BUG-H6 a live latch's mtime is refreshed by its owner's
	// stateEnter every cycle the condition still holds, so an
	// aged-out file is an abandoned latch — its owner stopped
	// evaluating it. 24h bounds
	// the stale window while keeping false-reaps (a genuinely
	// long-held latch re-enters next cycle, one duplicate alert)
	// rare — and keeps a foreign-schema writer's latch from being
	// flapped by instant reaping (see the package doc).
	latchMaxAge = 24 * time.Hour
)

// Host-fs defaults — duplicated from workerhygiene (which owns the
// same watchdog-state contract). They only apply when the wiring
// layer leaves the dep empty; cmd/agent always passes the resolved
// /host-prefixed paths, so drift between the two copies can't change
// observable behavior.
const (
	defaultWatchdogStateDir = "/host/var/lib/node-watchdog"
	defaultWatchdogLogFile  = "/host/var/log/node-watchdog.log"
	defaultProcRoot         = "/proc" // hostPID:true makes pod /proc == host /proc
)

// Janitor check names — prometheus `check` label + log context.
const (
	checkLatchReaper = "latch-reaper"
	checkLegacyUnits = "legacy-units"
	checkIPMonitor   = "ip-monitor"
)

// The registry of currently-producible state-<name> latch names
// (exact names + the parameterized families whose suffix is minted
// per target at write time) lives in platform/hoststate —
// hoststate.LatchDefs / hoststate.KnownLatchName, cross-checked
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

// JanitorConfig carries the janitor knobs — all test-injectable.
type JanitorConfig struct {
	Enabled          bool          // false → Run idles until ctx done
	Interval         time.Duration // sweep cadence
	WatchdogStateDir string        // the shared node-watchdog state dir
	WatchdogLogFile  string        // appended watchdog log (NPD filelog)
	ProcRoot         string        // host /proc (hostPID pod or host)
	// LatchMaxAge is the reap age for every state-* latch — known
	// AND unknown registry names (unknowns get the same floor so a
	// foreign-schema writer can't be flapped). <=0 → latchMaxAge.
	LatchMaxAge time.Duration
	// Systemd runs the list-units probe and the reset-failed/stop
	// remedies (nsenter-wrapped inside the container). nil → the
	// units sweep degrades to "gated" each cycle.
	Systemd *systemd.Client

	// killFn delivers signals — seam for tests (SIGKILL on orphan
	// monitors).
	killFn func(pid int, sig syscall.Signal) error
	// nowFn supplies the current time — seam for tests.
	nowFn func() time.Time
}

func (c *JanitorConfig) applyDefaults() {
	if c.Interval <= 0 {
		c.Interval = defaultJanitorInterval
	}
	if c.WatchdogStateDir == "" {
		c.WatchdogStateDir = defaultWatchdogStateDir
	}
	if c.WatchdogLogFile == "" {
		c.WatchdogLogFile = defaultWatchdogLogFile
	}
	if c.ProcRoot == "" {
		c.ProcRoot = defaultProcRoot
	}
	if c.LatchMaxAge <= 0 {
		c.LatchMaxAge = latchMaxAge
	}
	if c.killFn == nil {
		c.killFn = func(pid int, sig syscall.Signal) error {
			return syscall.Kill(pid, sig)
		}
	}
	if c.nowFn == nil {
		c.nowFn = time.Now
	}
}

// Janitor runs the state-dir + systemd ghost sweeps on one ticker.
type Janitor struct {
	cfg     JanitorConfig
	proc    procfs.FS              // /proc view bound to cfg.ProcRoot
	state   *hoststate.Store       // shared watchdog-state contract (log appends)
	cycles  *prometheus.CounterVec // check, result
	actions *prometheus.CounterVec // check, action
}

// NewJanitor returns a Janitor and registers its metrics on reg.
func NewJanitor(cfg JanitorConfig, reg prometheus.Registerer) (*Janitor, error) {
	cfg.applyDefaults()
	j := &Janitor{cfg: cfg, proc: procfs.New(cfg.ProcRoot)}
	// Now closes over the live config field — tests re-stub
	// j.cfg.nowFn after NewJanitor returns (hoststate.New doc).
	// The Log func keeps the "subsystem"="janitor" slog attr the old
	// appendLog attached to every mirror line.
	j.state = hoststate.New(cfg.WatchdogStateDir, cfg.WatchdogLogFile,
		func() time.Time { return j.cfg.nowFn() },
		func() *slog.Logger { return logger().With("subsystem", "janitor") })
	j.cycles = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_janitor_cycles_total",
		Help: "Janitor sweep cycles by check and result (ok|abort|gated).",
	}, []string{"check", "result"})
	j.actions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_janitor_actions_total",
		Help: "Janitor remediation actions by check and action " +
			"(reap|reset_failed|stop|kill).",
	}, []string{"check", "action"})
	if reg != nil {
		for _, c := range []prometheus.Collector{j.cycles, j.actions} {
			if err := reg.Register(c); err != nil {
				return nil, fmt.Errorf("register janitor metrics: %w", err)
			}
		}
	}
	return j, nil
}

// Name identifies the subsystem for logging.
func (j *Janitor) Name() string { return "janitor" }

// Run sweeps immediately, then every Interval until ctx is cancelled.
func (j *Janitor) Run(ctx context.Context) {
	if !j.cfg.Enabled {
		// Constructed but disabled — idle instead of returning: the
		// agent restarts a returned Run in a hot loop.
		cycle.Idle(ctx)
		return
	}
	cycle.Every("janitor", j.cfg.Interval, j.Sweep).Run(ctx)
}

// Sweep runs one round of all three cleanups. Order matters: the
// units sweep runs BEFORE the monitor sweep so a still-active ghost
// unit is stopped first — its `ip monitor` child then shows up
// reparented to init on a later sweep and gets killed cleanly.
func (j *Janitor) Sweep(ctx context.Context) {
	j.sweepLatches()
	j.sweepLegacyUnits(ctx)
	j.sweepIPMonitors()
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
	now := j.cfg.nowFn()
	for _, e := range entries {
		key, ok := strings.CutPrefix(e.Name(), hoststate.LatchFilePrefix)
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
		case !hoststate.KnownLatchName(key):
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
