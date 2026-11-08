// Package subframe is the shared "periodic watchdog subsystem"
// skeleton every internal/subsystem periodic checker used to
// re-declare by hand: the dep-spliced Config block (Base + FromDeps),
// the single hoststate.Store construction (StoreAt/Store), the
// register-with-rollback metric plumbing (RegisterAll + the
// conventional cycles/actions CounterVec pair), and the per-cycle
// watchdogconf refresh + WD_SIG_* kill-switch preamble (BeginCycle).
//
// A subsystem Config embeds Base so ConfigFromEnv collapses the
// per-field d.X→cfg.X copy into one `cfg.Base = FromDeps(d.Deps)`
// splice and the promoted field names (cfg.WatchdogStateDir,
// cfg.Systemd, cfg.Clock, …) keep working unchanged. Subsystems
// whose state dir is NOT the shared WatchdogStateDir (kinedb's
// GuardStateDir, hostconfig's hp()-joined dir) or whose clock lives
// outside Base (workerhygiene's Seams.Host.Clock) call the
// explicit-argument StoreAt form instead of the Base method — the
// helpers exist so hoststate.New has exactly one call site per
// shape, not to force-fit every config.
package subframe

import (
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostctx"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

// Base is the shared watchdog-subsystem config block — embed it in
// each periodic subsystem's Config so ConfigFromEnv needs the one
// FromDeps splice instead of a per-field copy, and the hoststate /
// BeginCycle helpers resolve straight off the Config. Field reads
// and writes promote through the embedding (cfg.WatchdogStateDir,
// applyDefaults' c.Interval = …); only composite literals change —
// a moved field is set via Config{Base: subframe.Base{…}}.
//
// Interval and ProcRoot are Base fields but NOT dep-spliced: they
// are env-resolved knobs (NODE_HOST_AGENT_*_INTERVAL /
// NODE_HOST_AGENT_PROC_ROOT), so FromDeps leaves them for each
// subsystem's envx table.
type Base struct {
	Interval         time.Duration // check cadence
	WatchdogStateDir string        // shared node-watchdog state dir (state-*/last-* files)
	WatchdogLogFile  string        // appended watchdog log (NPD filelog contract)
	HostRoot         string        // host fs root — "/" = already on host (no nsenter)
	ProcRoot         string        // host /proc (hostPID pod or host binary)
	Systemd          *systemd.Client
	// Watchdog is the parsed node-watchdog.conf — the middle layer
	// of every env → conf → package-default chain. Nil → every
	// WD_SIG_* check runs (pre-conf behaviour).
	Watchdog *watchdogconf.Config
	// WatchdogSrc, when set, re-reads the conf every Cycle so
	// hostconfig rewrites (WD_SIG_* kill switches, API_BACKENDS,
	// OVERLAY_*) apply live instead of only at agent start.
	WatchdogSrc *watchdogconf.Reloader
	// Clock supplies the current time — the shared settable
	// timex.Cell seam (one cell per process via hostctx.Deps).
	Clock *timex.Cell
}

// FromDeps splices the shared hostctx bundle into the Base — the
// one line every ConfigFromEnv's d.X→cfg.X copy collapses into.
// Deps fields a subsystem does not consume stay harmlessly carried
// (a promoted field nothing reads), same as the old copy left them
// unset.
func FromDeps(d hostctx.Deps) Base {
	return Base{
		WatchdogStateDir: d.WatchdogStateDir,
		WatchdogLogFile:  d.WatchdogLogFile,
		HostRoot:         d.HostRoot,
		Systemd:          d.Systemd,
		Watchdog:         d.Watchdog,
		WatchdogSrc:      d.WatchdogSrc,
		Clock:            d.Clock,
	}
}

// StoreAt returns the shared watchdog-state Store over an explicit
// dir/logFile pair — the single hoststate construction call shape
// every subsystem's New repeats. The store is the PROCESS-WIDE
// instance for the canonical dir (hoststate.Shared): workerhygiene
// and controllerhygiene share the state-journal-unreadable latch
// through ONE multi-owner registry, and every subsystem appending
// the watchdog log shares one rotation mutex. Dir may name a
// subsystem-private state dir (kinedb's GuardStateDir, hostconfig's
// HostRoot-joined dir) — the key is the canonical dir, so a private
// dir still gets its own instance. logFile "" on a later call
// inherits whatever the first construction named (nodereporter/
// hostconfig only READ the log via cfg — they pass ""). clock may
// be nil (hoststate falls back to system time); pass the cell the
// subsystem actually reads — the method value binds the cell
// POINTER so a post-New Clock.Set is observed by the store
// (hoststate.Store.Now contract). The clock/logger of the FIRST
// construction for a dir win — production wiring passes the one
// shared hostctx cell everywhere.
func StoreAt(dir, logFile string, clock *timex.Cell,
	log func() *slog.Logger) *hoststate.Store {

	var now timex.Clock
	if clock != nil {
		now = clock.Now
	}
	return hoststate.Shared(dir, logFile, now, log)
}

// Store is StoreAt over the Base's own WatchdogStateDir +
// WatchdogLogFile + Clock — the shape the eight shared-state-dir
// subsystems use.
func (b *Base) Store(log func() *slog.Logger) *hoststate.Store {
	return b.StoreAt(b.WatchdogStateDir, b.WatchdogLogFile, log)
}

// StoreAt is the method form of the package StoreAt for a Base
// whose dir/logFile are NOT the WatchdogStateDir/WatchdogLogFile
// pair but whose clock IS Base.Clock.
func (b *Base) StoreAt(dir, logFile string,
	log func() *slog.Logger) *hoststate.Store {

	return StoreAt(dir, logFile, b.Clock, log)
}

// RegisterAll registers each collector on reg, unwinding the ones
// already registered when one fails so a retried New() does not
// hit duplicate-registration on the collectors that landed — the
// rollback kinedb's collectors() loop used to hand-roll, made
// universal. A nil reg is a no-op (the bare-construction test
// contract every subsystem keeps).
func RegisterAll(reg prometheus.Registerer,
	collectors ...prometheus.Collector) error {

	if reg == nil {
		return nil
	}
	var done []prometheus.Collector
	for _, c := range collectors {
		if err := reg.Register(c); err != nil {
			for _, r := range done {
				reg.Unregister(r)
			}
			return err
		}
		done = append(done, c)
	}
	return nil
}

// Counters builds the conventional cycles/actions CounterVec pair
// every Dispatch-style subsystem carries —
// node_host_agent_<subsystem>_{cycles,actions}_total with
// {check,result}/{check,action} labels. Construction only: the
// caller registers them via RegisterAll together with any extra
// collectors so one failure unwinds the whole set.
func Counters(subsystem, cyclesHelp, actionsHelp string) (cycles, actions *prometheus.CounterVec) {
	cycles = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_" + subsystem + "_cycles_total",
		Help: cyclesHelp,
	}, []string{"check", "result"})
	actions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_" + subsystem + "_actions_total",
		Help: actionsHelp,
	}, []string{"check", "action"})
	return cycles, actions
}

// BeginCycle is the per-cycle preamble the Dispatch-style
// subsystems repeat: refresh Watchdog from WatchdogSrc when a
// reloader is wired (hostconfig rewrites /etc/node-watchdog.conf
// mid-run — the runner re-sourced it every run), then return the
// freshest conf plus the sigOn kill-switch predicate
// checks.Dispatch consumes: nil conf → every check runs (the
// documented pre-conf contract). The returned sigOn captures the
// conf at refresh time — checks run synchronously on the calling
// goroutine, so no conf change can interleave mid-dispatch.
//
// cfg.Watchdog is written by the Cycle goroutine alone: off-Cycle
// goroutines (nethealth's route guard, workerhygiene's feeder)
// must keep reading through the mutexed reloader themselves and
// never through this helper.
func (b *Base) BeginCycle() (*watchdogconf.Config, func(string) bool) {
	if b.WatchdogSrc != nil {
		b.Watchdog = b.WatchdogSrc.Get()
	}
	wd := b.Watchdog
	sigOn := func(name string) bool {
		return wd == nil || wd.SignalEnabled(name)
	}
	return wd, sigOn
}
