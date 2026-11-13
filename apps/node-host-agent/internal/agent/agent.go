// Package agent implements the node-host-agent runtime: a per-node
// DaemonSet process exposing node-local Prometheus metrics and
// health probes.
//
// The agent owns one prometheus.Registry shared by every subsystem
// (sweeper, apiprober, hostmetrics). Subsystems implement the
// Subsystem interface (blocking Run loop); pure metrics exporters
// register prometheus.Collectors on Agent.Registry() and need no
// goroutine — they collect at scrape time.
//
// The HTTP surface + Run lifecycle live in serve.go; the /healthz
// wedged-loop detector in liveness.go; the supervisor restart loop
// in supervisor.go; sd_notify in sdnotify.go.
package agent

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Subsystem is a long-running periodic component of the agent. Run
// must block until ctx is cancelled and must not return errors — a
// subsystem that hits a transient failure logs and retries internally
// (fail-closed subsystems abort their cycle, never the agent).
type Subsystem interface {
	Name() string
	Run(ctx context.Context)
}

// Config carries everything the agent needs from the environment.
type Config struct {
	NodeName    string // spec.nodeName via the downward API (NODE_NAME)
	PodName     string // metadata.name via the downward API (POD_NAME)
	Namespace   string // metadata.namespace via the downward API (POD_NAMESPACE)
	Version     string // release version injected at build time
	MetricsAddr string // listen address for /metrics
	ProbeAddr   string // listen address for /healthz + /readyz
	// PprofAddr is the LOOPBACK-ONLY listen address for
	// /debug/pprof — the profile endpoints used to share the
	// 0.0.0.0:9115 metrics port (roadmap item 1.2: every tenant pod
	// and VLAN neighbour could hit /debug/pprof/trace?seconds=30 of
	// the root daemon through the hostPort). main.go always resolves
	// it (default 127.0.0.1:9116, NODE_HOST_AGENT_PPROF_BIND_ADDRESS
	// override); an empty value skips the listener entirely (hand
	// construction in tests / legacy standalone units).
	PprofAddr string

	// Registry is the shared metrics registry; nil → a fresh
	// prometheus.NewRegistry(). Injected in tests to isolate
	// collectors.
	Registry *prometheus.Registry
	// Subsystems are started as goroutines when Run is called.
	Subsystems []Subsystem
}

// Agent serves the metrics and probe endpoints.
type Agent struct {
	cfg     Config
	reg     *prometheus.Registry
	started atomic.Int64 // unixnano — read by the scrape-time GaugeFunc
	ready   atomic.Bool
	// maxBackoffSubs counts subsystems pinned at the supervisor's
	// 5m restart-backoff cap (selfheal-alert-coverage) — supervisor.go maintains it.
	// /readyz reports 503 while it is non-zero so kube_pod_status_ready
	// reflects the degraded state; /healthz stays 200 so the pod is
	// not restarted and the healthy subsystems keep running.
	maxBackoffSubs atomic.Int64
	// beats is the per-subsystem liveness registry supervisor.go
	// maintains: name -> *subBeat. /healthz fails when an ACTIVE
	// subsystem's cycle heartbeat goes stale — a wedged loop is a
	// liveness failure kubelet (or systemd's watchdog standalone)
	// must recycle, unlike a crash-looping one which /readyz
	// reports without restarting healthy siblings.
	beats sync.Map
	// backoffInitial is the supervisor's first restart wait —
	// superviseBackoffInitial in production; tests shrink it so the
	// restart-backoff behavior doesn't cost real seconds.
	backoffInitial time.Duration
	// probeAddr caches the BOUND probe listener address — the
	// sd_notify self-probe dials the real bound addr (a ":0" or
	// rewritten bind can never be derived from cfg.ProbeAddr).
	probeAddr atomic.Value // string
	info      *prometheus.GaugeVec
	restarts  *prometheus.CounterVec
	subUp     *prometheus.GaugeVec
}

// New returns an Agent for cfg and registers the built-in identity
// metrics on cfg.Registry.
func New(cfg Config) *Agent {
	reg := cfg.Registry
	if reg == nil {
		reg = prometheus.NewRegistry()
	}
	a := &Agent{cfg: cfg, reg: reg, backoffInitial: superviseBackoffInitial}

	// Go runtime + process metrics (go_memstats_*, process_rss, fds,
	// network) on the shared registry — the memory-triage evidence for
	// the per-node scan bursts (GOMEMLIMIT sizing, DaemonSet limit).
	// The controller gets the same families from controller-runtime's
	// internal metrics init (plus its MetricsAll runtime extras);
	// this default GoCollector deliberately skips the ~80
	// go_gc_/go_sched_ series per node scrape while still covering
	// every triage series the sizing depends on (heap_inuse,
	// heap_sys, heap_released, RSS, fds).
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	a.info = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_host_agent_info",
		Help: "Static agent identity.",
	}, []string{"node", "pod", "namespace", "version", "go_version"})
	a.info.WithLabelValues(cfg.NodeName, cfg.PodName, cfg.Namespace,
		cfg.Version, runtime.Version()).Set(1)
	reg.MustRegister(a.info)

	// Supervisor health, labelled by subsystem name: restarts counts
	// every Run exit while ctx is live (panic-recovered included),
	// up is 1 inside Run and 0 during the restart backoff. The vecs
	// register once here and Run resolves WithLabelValues per
	// subsystem — duplicate subsystem names share a series, so a
	// MustRegister conflict is impossible.
	a.restarts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_subsystem_restarts_total",
		Help: "Subsystem Run exits while the context was live, restarted by the supervisor.",
	}, []string{"name"})
	a.subUp = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_host_agent_subsystem_up",
		Help: "1 while the subsystem's Run is executing; 0 during restart backoff.",
	}, []string{"name"})
	reg.MustRegister(a.restarts, a.subUp)

	reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "node_host_agent_uptime_seconds",
		Help: "Seconds since the agent started.",
	}, func() float64 {
		if t := a.started.Load(); t > 0 {
			return time.Since(time.Unix(0, t)).Seconds()
		}
		return 0
	}))
	return a
}

// Registry returns the agent's shared metrics registry — subsystems
// and scrape-time collectors register here before Run is called.
func (a *Agent) Registry() *prometheus.Registry { return a.reg }

// NodeName returns the name of the node the agent runs on.
func (a *Agent) NodeName() string { return a.cfg.NodeName }
