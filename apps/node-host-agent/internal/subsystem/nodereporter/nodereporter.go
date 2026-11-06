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
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/cycle"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/kmsg"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
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

	// NPD-monitor port defaults — see npd_monitors.go. The DaemonSet
	// runs hostPID and bind-mounts host /dev/kmsg at /dev/kmsg, so
	// /proc/1/mounts and /proc/uptime are already the HOST tables
	// (a container procfs would only see the pod's mount ns).
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
	NodeName string // this node (spec.nodeName) — conditions + events attach here
	Client   kubernetes.Interface

	WatchdogStateDir string        // host latch dir (state-*, installed, last-run)
	WatchdogLogFile  string        // appended node-watchdog log (filelog parity)
	Interval         time.Duration // sync cadence
	EventNamespace   string        // ns the Events are created in
	StaleThreshold   time.Duration // last-run age → WatchdogStale=True
	LogLookback      time.Duration // first-scan replay window (NPD lookback parity)
	EventDedupTTL    time.Duration // series-aggregation window per reason+message

	// --- NPD monitor port (npd_monitors.go) ---
	HostRoot           string   // host fs root mount; "/" = running on the host
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
	if c.nowFn == nil {
		c.nowFn = time.Now
	}
}

// Reporter implements agent.Subsystem.
type Reporter struct {
	cfg Config

	// state is the shared watchdog-state contract handle (hoststate):
	// the one-time installed/last-run seed and the state-<key> latch
	// paths. The reporter never APPENDS to the watchdog log (it only
	// tails WatchdogLogFile for events) so LogFile stays "". Now is a
	// closure over r.cfg.nowFn — tests re-stub the clock after New().
	state *hoststate.Store

	// NPD-compatible metric names — PrometheusRules query these exact
	// series (problem_gauge{type=...} == 1, increase(problem_counter{reason=...})).
	problemGauge   *prometheus.GaugeVec   // labels: type, reason
	problemCounter *prometheus.CounterVec // labels: reason
	cycles         *prometheus.CounterVec // labels: result

	// Log tail bookkeeping: byte offset into WatchdogLogFile plus a
	// carry buffer for a line split across two reads. logScanned marks
	// whether the lookback-replay pass has completed.
	logOffset   int64
	logPending  []byte
	logScanned  bool
	evSeq       atomic.Uint64            // event-name uniqueness suffix
	emittedEvts map[string]*emittedEvent // dedup key → created/aggregated Event

	// NPD-monitor port state (npd_kernel.go/npd_journal.go). Journal
	// cursors are µs wall timestamps — 0 bounds the first fetch to
	// LogLookback.
	kubeletJournalUS int64        // kubelet-stale monitor cursor
	kernelJournalUS  int64        // journalctl -k fallback cursor
	kmsgJournalMode  bool         // permanent fallback once kmsg can't be opened
	kmsgTail         *kmsg.Tailer // the /dev/kmsg tail — handle, carry, backlog gates
	kmsgScanned      bool         // mirrors the tail's caught-up flag (kernelLines)

	// heartbeatInit marks the one-time installed/last-run
	// initialization — periodic refreshes are the hygiene
	// subsystems' job (BUG-H1), the reporter only reads them.
	heartbeatInit bool

	// Permanent-condition bookkeeping for the NPD monitors —
	// KernelDeadlock latches True for the process lifetime (NPD
	// permanent parity); ReadonlyFilesystem follows the live mounts.
	kernelDeadlock    bool
	kernelDeadlockMsg string
	readonlyFS        bool
	readonlyFSMsg     string
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
	r.state = hoststate.New(cfg.WatchdogStateDir, "",
		func() time.Time { return r.cfg.nowFn() }, logger)
	// The kernel monitor's /dev/kmsg tail (npd_kernel.go). Paths are
	// re-evaluated per (re)open so cfg/test re-points stay live.
	r.kmsgTail = kmsg.NewTailer(kmsg.TailerOptions{
		Paths: func() []string {
			return kmsg.DevicePaths(r.cfg.KmsgFile, r.cfg.HostRoot)
		},
		DrainCap:   maxKmsgReadBytes,
		PendingCap: maxLogPendingBytes,
		// A never-terminated record keeps its tail — same carry
		// policy as the watchdog filelog tail.
		PendingTrimTail: true,
	})

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
		Help: "nodereporter sync cycles by result (ok|error).",
	}, []string{"result"})

	if reg != nil {
		for _, c := range []prometheus.Collector{r.problemGauge, r.problemCounter, r.cycles} {
			if err := reg.Register(c); err != nil {
				return nil, fmt.Errorf("register nodereporter metrics: %w", err)
			}
		}
	}
	return r, nil
}

// Name identifies the subsystem for logging.
func (r *Reporter) Name() string { return "nodereporter" }

// Run syncs immediately, then every Interval until ctx is cancelled.
// The lazily-opened kmsg handle is the one file the Reporter holds —
// it is released when the subsystem stops.
func (r *Reporter) Run(ctx context.Context) {
	defer r.kmsgTail.Close()
	cycle.Every("nodereporter", r.cfg.Interval, r.Cycle).Run(ctx)
}

// Cycle runs one sync round: one-time heartbeat initialization,
// conditions+gauges, then log→events. Each step reports its own
// error so a failing piece never starves the others; all feed the
// cycles{result} counter.
func (r *Reporter) Cycle(ctx context.Context) {
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
	// source never starves the others; syncNPDConditions runs last so
	// it ships whatever state the monitors computed this cycle.
	if err := r.syncKubeletJournal(ctx); err != nil {
		logger().Error("nodereporter: kubelet-stale journal scan failed",
			"node", r.cfg.NodeName, "error", err)
		ok = false
	}
	if err := r.syncKernelMonitor(ctx); err != nil {
		logger().Error("nodereporter: kernel monitor failed",
			"node", r.cfg.NodeName, "error", err)
		ok = false
	}
	if err := r.syncReadonlyMounts(ctx); err != nil {
		logger().Error("nodereporter: readonly filesystem check failed",
			"node", r.cfg.NodeName, "error", err)
		ok = false
	}
	if err := r.syncNPDConditions(ctx); err != nil {
		logger().Error("nodereporter: npd condition sync failed",
			"node", r.cfg.NodeName, "error", err)
		ok = false
	}
	result := "ok"
	if !ok {
		result = "error"
	}
	r.cycles.WithLabelValues(result).Inc()
}
