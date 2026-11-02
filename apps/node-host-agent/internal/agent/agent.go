// Package agent implements the node-host-agent runtime: a per-node
// DaemonSet process exposing node-local Prometheus metrics and
// health probes.
//
// The agent owns one prometheus.Registry shared by every subsystem
// (sweeper, apiprober, hostmetrics). Subsystems implement the
// Subsystem interface (blocking Run loop); pure metrics exporters
// register prometheus.Collectors on Agent.Registry() and need no
// goroutine — they collect at scrape time.
package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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
	started time.Time
	ready   atomic.Bool
	info    *prometheus.GaugeVec
}

// New returns an Agent for cfg and registers the built-in identity
// metrics on cfg.Registry.
func New(cfg Config) *Agent {
	reg := cfg.Registry
	if reg == nil {
		reg = prometheus.NewRegistry()
	}
	a := &Agent{cfg: cfg, reg: reg}

	a.info = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_host_agent_info",
		Help: "Static agent identity.",
	}, []string{"node", "pod", "namespace", "version", "go_version"})
	a.info.WithLabelValues(cfg.NodeName, cfg.PodName, cfg.Namespace,
		cfg.Version, runtime.Version()).Set(1)
	reg.MustRegister(a.info)

	reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "node_host_agent_uptime_seconds",
		Help: "Seconds since the agent started.",
	}, func() float64 {
		if a.started.IsZero() {
			return 0
		}
		return time.Since(a.started).Seconds()
	}))
	return a
}

// Registry returns the agent's shared metrics registry — subsystems
// and scrape-time collectors register here before Run is called.
func (a *Agent) Registry() *prometheus.Registry { return a.reg }

// NodeName returns the name of the node the agent runs on.
func (a *Agent) NodeName() string { return a.cfg.NodeName }

func (a *Agent) metricsMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(a.reg,
		promhttp.HandlerOpts{ErrorHandling: promhttp.ContinueOnError}))
	return mux
}

func (a *Agent) probeMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if a.ready.Load() {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	return mux
}

// Run starts the configured subsystems, binds both listeners, marks
// the agent ready, then blocks until ctx is cancelled or a server
// fails. Shutdown is graceful.
func (a *Agent) Run(ctx context.Context) error {
	a.started = time.Now()

	for _, sub := range a.cfg.Subsystems {
		sub := sub
		go func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("subsystem panicked — stopped until agent restart",
						"subsystem", sub.Name(), "panic", r)
				}
			}()
			slog.Info("subsystem started", "name", sub.Name())
			sub.Run(ctx)
		}()
	}

	metricsLn, err := net.Listen("tcp", a.cfg.MetricsAddr)
	if err != nil {
		return fmt.Errorf("metrics listener: %w", err)
	}
	probeLn, err := net.Listen("tcp", a.cfg.ProbeAddr)
	if err != nil {
		metricsLn.Close()
		return fmt.Errorf("probe listener: %w", err)
	}
	a.ready.Store(true)

	errCh := make(chan error, 2)
	serve := func(name string, ln net.Listener, h http.Handler) {
		srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			<-ctx.Done()
			srv.Shutdown(context.Background())
		}()
		go func() {
			slog.Info("listening", "server", name, "addr", ln.Addr().String())
			if err := srv.Serve(ln); err != http.ErrServerClosed {
				errCh <- fmt.Errorf("%s server: %w", name, err)
			}
		}()
	}
	serve("metrics", metricsLn, a.metricsMux())
	serve("probe", probeLn, a.probeMux())

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}
