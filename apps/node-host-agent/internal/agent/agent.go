// Package agent implements the node-host-agent runtime: a per-node
// DaemonSet process exposing node-local Prometheus metrics and
// health probes.
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
)

// Config carries everything the agent needs from the environment.
type Config struct {
	NodeName    string // spec.nodeName via the downward API (NODE_NAME)
	PodName     string // metadata.name via the downward API (POD_NAME)
	Namespace   string // metadata.namespace via the downward API (POD_NAMESPACE)
	Version     string // release version injected at build time
	MetricsAddr string // listen address for /metrics
	ProbeAddr   string // listen address for /healthz + /readyz
}

// Agent serves the metrics and probe endpoints.
type Agent struct {
	cfg     Config
	started time.Time
	ready   atomic.Bool
}

// New returns an Agent for cfg.
func New(cfg Config) *Agent {
	return &Agent{cfg: cfg}
}

// NodeName returns the name of the node the agent runs on.
func (a *Agent) NodeName() string { return a.cfg.NodeName }

func (a *Agent) metricsMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprint(w, "# HELP node_host_agent_info Static agent identity.\n")
		fmt.Fprint(w, "# TYPE node_host_agent_info gauge\n")
		fmt.Fprintf(w, "node_host_agent_info{node=%q,pod=%q,namespace=%q,version=%q,go_version=%q} 1\n",
			a.cfg.NodeName, a.cfg.PodName, a.cfg.Namespace, a.cfg.Version, runtime.Version())
		fmt.Fprint(w, "# HELP node_host_agent_uptime_seconds Seconds since the agent started.\n")
		fmt.Fprint(w, "# TYPE node_host_agent_uptime_seconds counter\n")
		fmt.Fprintf(w, "node_host_agent_uptime_seconds %.3f\n", time.Since(a.started).Seconds())
	})
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

// Run binds both listeners, marks the agent ready, then blocks until
// ctx is cancelled or a server fails. Shutdown is graceful.
func (a *Agent) Run(ctx context.Context) error {
	a.started = time.Now()

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
