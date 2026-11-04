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
	"errors"
	"fmt"
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
	started atomic.Int64 // unixnano — read by the scrape-time GaugeFunc
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
	a.started.Store(time.Now().UnixNano())

	for _, sub := range a.cfg.Subsystems {
		sub := sub
		go func() {
			logger().Info("subsystem started", "name", sub.Name())
			// Restart backoff doubles per early exit (5s → 5m cap) so
			// a subsystem that returns instantly can't spam a restart
			// + error log every cycle; a run that outlived the
			// current backoff counts as healthy and resets it.
			backoff := 5 * time.Second
			for {
				began := time.Now()
				func() {
					defer func() {
						if r := recover(); r != nil {
							logger().Error("subsystem panicked — restarting",
								"subsystem", sub.Name(), "panic", r)
						}
					}()
					sub.Run(ctx)
				}()
				if ctx.Err() != nil {
					return
				}
				if time.Since(began) >= backoff {
					backoff = 5 * time.Second
				}
				// Run returned while ctx is live (panic recovered, or
				// a silent early return) — restart after backoff
				// instead of letting the subsystem die invisibly.
				logger().Error("subsystem exited unexpectedly — restarting",
					"subsystem", sub.Name(), "backoff", backoff)
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
				}
				if backoff *= 2; backoff > 5*time.Minute {
					backoff = 5 * time.Minute
				}
			}
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
	// done releases the parked shutdown goroutines when Run returns —
	// without it they would linger until ctx cancel even on the errCh
	// path, then Shutdown a server the sibling Close() already tore
	// down (at best a no-op, at worst a misleading failure log).
	done := make(chan struct{})
	defer close(done)
	var servers []*http.Server
	serve := func(name string, ln net.Listener, h http.Handler) {
		// The metrics handler collects at scrape time and can block
		// on a hung filesystem — bound every phase so one wedged
		// connection can't pin the server.
		srv := &http.Server{
			Handler:           h,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		servers = append(servers, srv)
		go gracefulShutdown(ctx, done, name, srv.Shutdown)
		go func() {
			logger().Info("listening", "server", name, "addr", ln.Addr().String())
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
		// A listener died while ctx is live — drop the sibling server
		// too (Close is immediate; Shutdown could park on a wedged
		// handler) so nothing outlives Run returning the error.
		for _, srv := range servers {
			if cerr := srv.Close(); cerr != nil {
				logger().Error("sibling server close failed",
					"error", cerr)
			}
		}
		return err
	}
}

// gracefulShutdown parks until ctx is cancelled, then drains srv via
// shutdown. Run's done channel releases it early when Run exits on
// the error path — the sibling Close() already dropped those
// listeners, so a late Shutdown is at best a no-op and at worst a
// bogus "connections dropped" log. The ctx.Err() re-check (not just
// the select branch) keeps the graceful drain on ctx cancel even
// when done is already closed too — select picks randomly between
// ready cases. ErrServerClosed counts as the intended end state —
// a server torn down underneath us is not a shutdown failure.
func gracefulShutdown(ctx context.Context, done <-chan struct{},
	name string, shutdown func(context.Context) error) {
	select {
	case <-ctx.Done():
	case <-done:
	}
	if ctx.Err() == nil {
		// Woken by done while ctx is live: Run exited on the error
		// path — nothing left to drain.
		return
	}
	if err := shutdown(context.Background()); err != nil &&
		!errors.Is(err, http.ErrServerClosed) {
		logger().Error("server shutdown failed — connections dropped",
			"server", name, "error", err)
	}
}
