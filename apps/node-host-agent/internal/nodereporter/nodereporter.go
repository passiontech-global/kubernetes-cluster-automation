// Package nodereporter syncs node-watchdog state into Kubernetes —
// it replaces the two watchdog monitors that used to run inside
// node-problem-detector (watchdog-state-monitor.json custom plugin +
// watchdog-filelog-monitor.json filelog):
//
//   - Permanent NodeConditions: every Interval the 9 watchdog
//     conditions are evaluated from the latch files under
//     WatchdogStateDir (state-<key> files, plus the installed/last-run
//     heartbeat pair for WatchdogStale — the reporter writes those
//     itself once per cycle since it owns the staleness probe) and
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
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/client-go/kubernetes"
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
	if c.nowFn == nil {
		c.nowFn = time.Now
	}
}

// Reporter implements agent.Subsystem.
type Reporter struct {
	cfg Config

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
}

// New returns a Reporter and registers its metrics on reg. A nil
// Client or empty NodeName is a configuration error (the subsystem
// has nothing to report to) — runtime API failures are NOT fatal,
// they retry each cycle.
func New(cfg Config, reg prometheus.Registerer) (*Reporter, error) {
	cfg.applyDefaults()
	if cfg.Client == nil {
		return nil, fmt.Errorf("nodereporter: Client is required")
	}
	if cfg.NodeName == "" {
		return nil, fmt.Errorf("nodereporter: NodeName is required")
	}
	r := &Reporter{cfg: cfg, emittedEvts: map[string]*emittedEvent{}}

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
func (r *Reporter) Run(ctx context.Context) {
	r.Cycle(ctx)
	t := time.NewTicker(r.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.Cycle(ctx)
		}
	}
}

// Cycle runs one sync round: watchdog heartbeat, conditions+gauges,
// then log→events. Each step reports its own error so a failing piece
// never starves the others; all feed the cycles{result} counter.
func (r *Reporter) Cycle(ctx context.Context) {
	ok := true
	// Heartbeat first: the staleness probe evaluated below reads the
	// last-run file this writes.
	if err := r.writeHeartbeat(); err != nil {
		slog.Error("nodereporter: watchdog heartbeat failed",
			"node", r.cfg.NodeName, "dir", r.cfg.WatchdogStateDir, "error", err)
		ok = false
	}
	if err := r.syncConditions(ctx); err != nil {
		slog.Error("nodereporter: condition sync failed",
			"node", r.cfg.NodeName, "error", err)
		ok = false
	}
	if err := r.syncLogEvents(ctx); err != nil {
		slog.Error("nodereporter: event sync failed",
			"node", r.cfg.NodeName, "error", err)
		ok = false
	}
	result := "ok"
	if !ok {
		result = "error"
	}
	r.cycles.WithLabelValues(result).Inc()
}
