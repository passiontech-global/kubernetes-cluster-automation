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
package nodereporter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/cycle"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/subframe"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/nodereporter/npd"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

// Defaults mirror the removed NPD config and the DaemonSet host mounts.
const (
	defaultInterval = 30 * time.Second
	// defaultStaleThreshold is check-watchdog-fresh.sh's 1200s: the
	// watchdog run timer is dead / hangs when last-run is older.
	defaultStaleThreshold = 20 * time.Minute
	// defaultLogLookback is the NPD filelog "lookback": 5m" — on the
	// first scan after (re)start only lines newer than this are
	// replayed, so deploy gaps don't silently lose ACTION events while
	// ancient history isn't re-emitted.
	defaultLogLookback = 5 * time.Minute
	// defaultEventDedupTTL bounds the series-aggregation window —
	// roughly the apiserver event TTL (1h). After it, an identical
	// reason+message creates a fresh Event object.
	defaultEventDedupTTL = time.Hour

	defaultWatchdogStateDir = "/host/var/lib/node-watchdog"
	defaultWatchdogLogFile  = "/host/var/log/node-watchdog.log"
	defaultEventNamespace   = "default" // node events conventionally land in default

	// defaultCycleTimeout is the per-Cycle hard bound Run applies —
	// controllerhygiene's runCycle parity. The ticker loop calls
	// Cycle synchronously, so without the bound one hung child
	// freezes the reporter forever: 2026-11-06 all six agents wedged
	// mid-Cycle during an apiserver flap (subsystem_up stayed 1,
	// logs stopped, NodeCondition lastHeartbeatTime froze ~17h; only
	// a pod delete recovered). Every kube/journal call in Cycle is
	// ctx-aware, so the deadline actually interrupts the stall;
	// host file reads can't be, but they were never the wedge.
	defaultCycleTimeout = 5 * time.Minute
	// defaultHeartbeatInterval is how often syncConditions
	// re-patches lastHeartbeatTime on its NodeConditions even when
	// nothing else changed — the heartbeat is the reporter-liveness
	// signal cluster-side checks trust (node-hang-precordon refuses
	// a condition whose heartbeat froze). ~4 cycles at the default
	// Interval keeps the stamp fresh while staying well under the
	// controller's 10m staleness window.
	defaultHeartbeatInterval = 2 * time.Minute

	// NPD-monitor port defaults — see the npd subpackage. The
	// DaemonSet runs hostPID and bind-mounts host /dev/kmsg at
	// /dev/kmsg, so /proc/1/mounts and /proc/uptime are already the
	// HOST tables (a container procfs would only see the pod's
	// mount ns).
	defaultHostRoot           = "/host" // nsenter boundary for journalctl
	defaultKmsgFile           = "/dev/kmsg"
	defaultProcMountsFile     = "/proc/1/mounts"
	defaultProcUptimeFile     = "/proc/uptime"
	defaultKubeletJournalUnit = "k0sworker.service"
)

// defaultReadonlyTargets are the host mountpoints the
// readonly-monitor port watches; defaultReadonlyFSTypes restricts
// the check to real disk filesystems.
var (
	defaultReadonlyTargets = []string{"/", "/var", "/var/lib/k0s", "/var/openebs"}
	defaultReadonlyFSTypes = []string{"ext4", "xfs", "btrfs"}
)

// Config carries the reporter knobs — all test-injectable.
type Config struct {
	// Base is the shared watchdog-subsystem block — sync cadence,
	// the host latch dir (state-*, installed, last-run), the
	// appended node-watchdog log the filelog monitor tails
	// (filelog parity), the host fs root and the clock cell
	// splice (subframe.FromDeps).
	subframe.Base
	NodeName string // this node (spec.nodeName) — conditions + events attach here
	Client   kubernetes.Interface

	// CycleTimeout is the per-Cycle deadline Run applies around each
	// Cycle: Run calls Cycle synchronously inside the ticker loop,
	// so a kube/journal call that ignores the client timeout would
	// otherwise stall the reporter indefinitely (the 2026-11-06
	// ~17h fleet wedge). <=0 → defaultCycleTimeout (5m).
	CycleTimeout time.Duration
	// HeartbeatInterval is how often lastHeartbeatTime on the
	// reporter's NodeConditions is refreshed even when Status and
	// Reason are unchanged — the stamp is the reporter-liveness
	// evidence consumers like node-hang-precordon use to distrust a
	// condition whose writer may be dead. <=0 →
	// defaultHeartbeatInterval (2m).
	HeartbeatInterval time.Duration
	EventNamespace    string        // ns the Events are created in
	StaleThreshold    time.Duration // last-run age → WatchdogStale=True
	LogLookback       time.Duration // first-scan replay window (NPD lookback parity)
	EventDedupTTL     time.Duration // series-aggregation window per reason+message

	// --- NPD monitor port (the npd subpackage) ---
	KmsgFile           string   // kernel ring source; <HostRoot>/dev/kmsg is the fallback
	ProcMountsFile     string   // host mount table (hostPID → /proc/1/mounts)
	ProcUptimeFile     string   // host uptime for the kmsg first-scan lookback
	KubeletJournalUnit string   // journald unit the kubelet-stale monitor tails
	ReadonlyTargets    []string // mountpoints watched for unexpected ro
	ReadonlyFSTypes    []string // fstypes the ro check applies to

	// journalFetch runs `journalctl <args>` on the host (nsenter
	// wrapper when HostRoot != "/") — nil builds the default via the
	// systemd package; tests substitute a fake.
	journalFetch func(ctx context.Context, args ...string) (string, error)
}

func (c *Config) applyDefaults() {
	if c.Interval <= 0 {
		c.Interval = defaultInterval
	}
	if c.CycleTimeout <= 0 {
		c.CycleTimeout = defaultCycleTimeout
	}
	if c.HeartbeatInterval <= 0 {
		c.HeartbeatInterval = defaultHeartbeatInterval
	}
	if c.WatchdogStateDir == "" {
		c.WatchdogStateDir = defaultWatchdogStateDir
	}
	if c.WatchdogLogFile == "" {
		c.WatchdogLogFile = defaultWatchdogLogFile
	}
	if c.EventNamespace == "" {
		c.EventNamespace = defaultEventNamespace
	}
	if c.StaleThreshold <= 0 {
		c.StaleThreshold = defaultStaleThreshold
	}
	if c.LogLookback <= 0 {
		c.LogLookback = defaultLogLookback
	}
	if c.EventDedupTTL <= 0 {
		c.EventDedupTTL = defaultEventDedupTTL
	}
	if c.HostRoot == "" {
		c.HostRoot = defaultHostRoot
	}
	if c.KmsgFile == "" {
		c.KmsgFile = defaultKmsgFile
	}
	if c.ProcMountsFile == "" {
		c.ProcMountsFile = defaultProcMountsFile
	}
	if c.ProcUptimeFile == "" {
		c.ProcUptimeFile = defaultProcUptimeFile
	}
	if c.KubeletJournalUnit == "" {
		c.KubeletJournalUnit = defaultKubeletJournalUnit
	}
	if len(c.ReadonlyTargets) == 0 {
		c.ReadonlyTargets = defaultReadonlyTargets
	}
	if len(c.ReadonlyFSTypes) == 0 {
		c.ReadonlyFSTypes = defaultReadonlyFSTypes
	}
	if c.journalFetch == nil {
		sd := systemd.New(systemd.Config{HostRoot: c.HostRoot})
		c.journalFetch = func(ctx context.Context, args ...string) (string, error) {
			return sd.Exec(ctx, "journalctl", args...)
		}
	}
	if c.Clock == nil {
		c.Clock = timex.NewCell(nil)
	}
}

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
