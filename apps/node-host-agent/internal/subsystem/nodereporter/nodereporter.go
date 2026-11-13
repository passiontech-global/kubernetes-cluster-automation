// Package nodereporter syncs node-watchdog state into Kubernetes —
// it replaces the two watchdog monitors that used to run inside
// node-problem-detector (watchdog-state-monitor.json custom plugin +
// watchdog-filelog-monitor.json filelog):
//
//   - Permanent NodeConditions: every Interval the watchdog
//     conditions are evaluated from the latch files under
//     WatchdogStateDir (state-<key> files, plus the installed/last-run
//     heartbeat pair for WatchdogStale — the reporter only
//     INITIALIZES the pair once at startup when absent; the periodic
//     last-run refresh belongs to the hygiene Cycle()s —
//     workerhygiene/controllerhygiene/nethealth — otherwise the
//     staleness probe could never trip, BUG-H1) and
//     merged into status.conditions on this Node — same Type/Reason/Message
//     contract as the removed NPD JSON so the NHC→SNR remediation
//     chain keeps working unchanged.
//   - Kubernetes Events: it tails the node-watchdog log
//     (WatchdogLogFile) the way the filelog monitor did — each new
//     line matching one of the ported rule patterns emits an
//     events.k8s.io/v1 Event attached to this Node. Identical
//     reason+message inside EventDedupTTL aggregates into the
//     existing Event's series (count/lastObservedTime) instead of
//     creating new objects.
//   - Prometheus: problem_gauge{type,reason} and
//     problem_counter{reason} keep the exact NPD metric names/labels
//     so the existing PrometheusRules (passiontech-node-watchdog-alerts
//     et al.) keep working unchanged.
//
// Zero-churn: the node status is PATCHed (strategic merge, per-type
// merge on conditions) only when the Status or Reason of at least one
// of the 9 conditions differs from the live object — a fresh GET each
// cycle doubles as the post-restart seed and self-heals drift.
// Kube API errors are logged and retried next cycle, never fatal.
//
// The knobs/defaults live in config.go; the env surface in
// config_env.go; the condition/event sync internals in
// conditions.go / events*.go; the NPD monitor family in npd/.
package nodereporter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/cycle"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/subframe"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/nodereporter/npd"
)

// Reporter implements agent.Subsystem.
type Reporter struct {
	cfg Config

	// state is the shared watchdog-state contract handle (hoststate):
	// the one-time installed/last-run seed and the state-<key> latch
	// paths. The reporter never APPENDS to the watchdog log (it only
	// tails WatchdogLogFile for events) so LogFile stays "". Now is
	// r.cfg.Clock.Now — the method value binds the shared timex.Cell,
	// so a post-New Clock.Set lands here.
	state *hoststate.Store

	// NPD-compatible metric names — PrometheusRules query these exact
	// series (problem_gauge{type=...} == 1, increase(problem_counter{reason=...})).
	problemGauge   *prometheus.GaugeVec   // labels: type, reason
	problemCounter *prometheus.CounterVec // labels: reason
	cycles         *prometheus.CounterVec // labels: result

	// Log tail bookkeeping: byte offset into WatchdogLogFile plus a
	// carry buffer for a line split across two reads. logScanned marks
	// whether the lookback-replay pass has completed. logFi is the
	// last successful scan's stat — os.SameFile against it detects a
	// rename rotation even when the fresh file already grew past the
	// old offset (a size shrink would never be seen).
	logOffset   int64
	logPending  []byte
	logScanned  bool
	logFi       os.FileInfo
	evSeq       atomic.Uint64            // event-name uniqueness suffix
	emittedEvts map[string]*emittedEvent // dedup key → created/aggregated Event

	// monitors is the NPD-monitor family (kernel/kmsg, kubelet
	// journald, readonly mounts) — own subpackage, wired through
	// npd.Deps + npdSink. It holds the kmsg Tailer handle, the
	// journald cursors and the monitor-computed condition latches;
	// Run's defer releases the kmsg fd it lazily opens.
	monitors *npd.Monitor

	// heartbeatInit marks the one-time installed/last-run
	// initialization — periodic refreshes are the hygiene
	// subsystems' job (BUG-H1), the reporter only reads them.
	heartbeatInit bool
}

// New returns a Reporter and registers its metrics on reg. A nil
// Client or empty NodeName is a configuration error (the subsystem
// has nothing to report to) — runtime API failures are NOT fatal,
// they retry each cycle.
func New(cfg Config, reg prometheus.Registerer) (*Reporter, error) {
	cfg.applyDefaults()
	if cfg.Client == nil {
		return nil, errors.New("nodereporter: Client is required")
	}
	if cfg.NodeName == "" {
		return nil, errors.New("nodereporter: NodeName is required")
	}
	r := &Reporter{cfg: cfg, emittedEvts: map[string]*emittedEvent{}}
	// The reporter never APPENDS to the watchdog log (it only tails
	// WatchdogLogFile for events) so LogFile stays "".
	r.state = cfg.StoreAt(cfg.WatchdogStateDir, "", logger)
	// The NPD monitor family — Deps are late-bound over r.cfg so
	// post-New cfg/test re-points (journalFetch stub, KmsgFile
	// re-point) still land inside the monitor.
	r.monitors = npd.New(r.npdDeps())

	r.problemGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "problem_gauge",
		Help: "Permanent node problem condition (NPD-compatible): 1 while " +
			"the watchdog latch is active for type+reason.",
	}, []string{"type", "reason"})
	r.problemCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "problem_counter",
		Help: "Watchdog log event count (NPD-compatible), one increment " +
			"per matched log line per reason.",
	}, []string{"reason"})
	r.cycles = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_nodereporter_cycles_total",
		// "started" counts every Cycle entry — started minus
		// (ok+error) is the in-flight/wedged count, so a Cycle that
		// never returns (the 2026-11-06 ~17h fleet wedge, this time
		// stuck on a non-ctx-aware call the deadline can't preempt)
		// is visible in metrics even though nothing logs.
		Help: "nodereporter sync cycles by result (started|ok|error).",
	}, []string{"result"})

	if err := subframe.RegisterAll(reg,
		r.problemGauge, r.problemCounter, r.cycles); err != nil {
		return nil, fmt.Errorf("register nodereporter metrics: %w", err)
	}
	return r, nil
}

// Name identifies the subsystem for logging.
func (r *Reporter) Name() string { return "nodereporter" }

// npdDeps wires the npd monitor family's inputs — every field is a
// late-bound closure over r.cfg (the kernelfail Deps precedent), so
// a test stub swapped onto the Config after New still lands.
func (r *Reporter) npdDeps() npd.Deps {
	return npd.Deps{
		Cfg: func() npd.Config {
			return npd.Config{
				KmsgFile:           r.cfg.KmsgFile,
				HostRoot:           r.cfg.HostRoot,
				ProcMountsFile:     r.cfg.ProcMountsFile,
				ProcUptimeFile:     r.cfg.ProcUptimeFile,
				KubeletJournalUnit: r.cfg.KubeletJournalUnit,
				ReadonlyTargets:    r.cfg.ReadonlyTargets,
				ReadonlyFSTypes:    r.cfg.ReadonlyFSTypes,
				LogLookback:        r.cfg.LogLookback,
			}
		},
		JournalFetch: func(ctx context.Context, args ...string) (string, error) {
			return r.cfg.journalFetch(ctx, args...)
		},
		Now: func() time.Time { return r.cfg.Clock.Now() },
	}
}

// npdSink adapts the reporter's event/counter/latch sinks to the
// npd.Sink contract — kept as an adapter so the monitor package
// never reaches back into Reporter internals.
type npdSink struct{ r *Reporter }

func (s npdSink) EmitEvent(ctx context.Context, reason, note string) error {
	return s.r.emitEvent(ctx, reason, note, "Warning")
}

func (s npdSink) BumpCounter(reason string) {
	s.r.problemCounter.WithLabelValues(reason).Inc()
}

// EnterLatch routes through the shared watchdog-state Store — it
// carries an empty LogFile, so the STATE-ENTER never circles back
// into the filelog rules this same reporter tails.
func (s npdSink) EnterLatch(name, evidence string) {
	s.r.state.Enter(name, evidence)
}

// Run syncs immediately, then every Interval until ctx is cancelled.
// The lazily-opened kmsg handle inside the monitor family is the one
// file the Reporter holds — it is released when the subsystem stops.
func (r *Reporter) Run(ctx context.Context) {
	defer r.monitors.Close()
	if r.cfg.ownedSD != nil {
		defer r.cfg.ownedSD.Close()
	}
	cycle.Every("nodereporter", r.cfg.Interval, r.runCycle).Run(ctx)
}

// runCycle executes one Cycle under the per-cycle deadline
// (Config.CycleTimeout) — controllerhygiene's runCycle parity.
// The ticker loop calls Cycle synchronously, so without the bound a
// single hung child — a kube API call with no effective deadline
// during an apiserver flap, a journald fetch that never returns —
// starves the sync for as long as it hangs (the ~17h 2026-11-06
// wedge: all six agents silent mid-Cycle while subsystem_up stayed
// 1). Hitting the deadline is a degraded cycle, not a failure — the
// Warn line keeps a silently-starved reporter visible.
func (r *Reporter) runCycle(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, r.cfg.CycleTimeout)
	defer cancel()
	r.Cycle(cctx)
	if errors.Is(cctx.Err(), context.DeadlineExceeded) {
		logger().Warn("nodereporter: cycle deadline exceeded — "+
			"stalled sync aborted, retrying next cycle",
			"node", r.cfg.NodeName, "timeout", r.cfg.CycleTimeout)
	}
}

// Cycle runs one sync round: one-time heartbeat initialization,
// conditions+gauges, then log→events. Each step reports its own
// error so a failing piece never starves the others; all feed the
// cycles{result} counter.
func (r *Reporter) Cycle(ctx context.Context) {
	r.cycles.WithLabelValues("started").Inc()
	ok := true
	// BUG-H1: the reporter must NOT refresh last-run — the
	// staleness probe reads exactly this file, and a self-heartbeat
	// made WatchdogStale permanently blind. Periodic refreshes
	// belong to the hygiene Cycle()s; the reporter only
	// INITIALIZES the pair when absent (new envs and unit tests
	// where no hygiene subsystem has run yet).
	if !r.heartbeatInit {
		// initHeartbeatFiles seeds the installed/last-run pair ONCE —
		// only for files that don't already exist (BUG-H1). The shell
		// watchdog's prom_emit trap owned the periodic last-run
		// refresh; on agent nodes the hygiene Cycle()s
		// (workerhygiene/controllerhygiene/nethealth) own it now. The
		// reporter still needs the pair on a fresh state dir — a
		// missing `installed` disables the staleness gate entirely
		// and a missing `last-run` reads as epoch 0 — so it
		// initializes them at startup for new envs and unit tests
		// where no hygiene subsystem has run yet.
		//
		// `installed` is created only when absent (ansible force:false
		// parity — presence activates the probe's gate, content is the
		// baseline epoch used when last-run doesn't exist yet);
		// `last-run` is likewise created only when absent, atomically
		// via tmp+rename so a reader never observes a truncated epoch.
		if err := r.state.InitHeartbeatFiles(); err != nil {
			logger().Error("nodereporter: watchdog heartbeat init failed",
				"node", r.cfg.NodeName, "dir", r.cfg.WatchdogStateDir, "error", err)
			ok = false
		} else {
			r.heartbeatInit = true
		}
	}
	// One Node GET + at most one merged status PATCH per cycle —
	// syncConditions covers the watchdog latch conditions AND the
	// two NPD monitor conditions (the former split issued a
	// GET+PATCH each). It runs FIRST, right after heartbeatInit:
	// 2026-11-07 a Cycle wedged before ever reaching it (stuck in
	// one of the monitor steps below on a call the CycleTimeout
	// can't preempt) left every managed condition a frozen zombie —
	// KubeletPLEGUnhealthy stayed True ~20min after the latch
	// cleared until it was patched by hand. Latch→condition truth
	// and heartbeat freshness are the critical path consumers like
	// node-hang-precordon rely on; the NPD monitor conditions
	// (kernelDeadlock/readonlyFS) now ship the PREVIOUS cycle's
	// computed state — one Interval of lag, an acceptable trade for
	// a sync that a sick monitor can't starve.
	if err := r.syncConditions(ctx); err != nil {
		logger().Error("nodereporter: condition sync failed",
			"node", r.cfg.NodeName, "error", err)
		ok = false
	}
	if err := r.syncLogEvents(ctx); err != nil {
		logger().Error("nodereporter: event sync failed",
			"node", r.cfg.NodeName, "error", err)
		ok = false
	}
	// NPD monitor ports — each reports its own error so one sick
	// source never starves the others; the conditions they produce
	// are shipped by next cycle's syncConditions.
	sink := npdSink{r}
	if err := r.monitors.SyncKubeletJournal(ctx, sink); err != nil {
		logger().Error("nodereporter: kubelet-stale journal scan failed",
			"node", r.cfg.NodeName, "error", err)
		ok = false
	}
	if err := r.monitors.SyncKernelMonitor(ctx, sink); err != nil {
		logger().Error("nodereporter: kernel monitor failed",
			"node", r.cfg.NodeName, "error", err)
		ok = false
	}
	if err := r.monitors.SyncReadonlyMounts(ctx, sink); err != nil {
		logger().Error("nodereporter: readonly filesystem check failed",
			"node", r.cfg.NodeName, "error", err)
		ok = false
	}
	result := "ok"
	if !ok {
		result = "error"
	}
	r.cycles.WithLabelValues(result).Inc()
}
