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
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/cycle"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
)

const (
	defaultInterval = 10 * time.Minute
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

// Config carries the janitor knobs — all test-injectable.
type Config struct {
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

func (c *Config) applyDefaults() {
	if c.Interval <= 0 {
		c.Interval = defaultInterval
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
	cfg     Config
	proc    procfs.FS              // /proc view bound to cfg.ProcRoot
	state   *hoststate.Store       // shared watchdog-state contract (log appends)
	cycles  *prometheus.CounterVec // check, result
	actions *prometheus.CounterVec // check, action
}

// New returns a Janitor and registers its metrics on reg.
func New(cfg Config, reg prometheus.Registerer) (*Janitor, error) {
	cfg.applyDefaults()
	j := &Janitor{cfg: cfg, proc: procfs.New(cfg.ProcRoot)}
	// Now closes over the live config field — tests re-stub
	// j.cfg.nowFn after New returns (hoststate.New doc).
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
