// node-host-agent — per-node agent (DaemonSet) for the
// kubernetes-node-automation stack. Runs on every cluster node and
// exposes node-local metrics plus health probes for
// node-automation-controller and external monitoring.
//
// Interface contract (same as node-automation-controller):
//   - Prometheus metrics on :9115/metrics.
//   - Health/readiness probes on :8081/healthz and :8081/readyz.
//   - Node identity via the downward API: NODE_NAME, POD_NAME,
//     POD_NAMESPACE.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/agent"
)

var version = "dev"

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	var metricsAddr, probeAddr string
	var showVersion bool
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":9115",
		"address the Prometheus metrics endpoint binds to")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081",
		"address the health/readiness probe endpoints bind to")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Println(version)
		return
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	a := agent.New(agent.Config{
		NodeName:    getenv("NODE_NAME", ""),
		PodName:     getenv("POD_NAME", ""),
		Namespace:   getenv("POD_NAMESPACE", ""),
		Version:     version,
		MetricsAddr: metricsAddr,
		ProbeAddr:   probeAddr,
	})

	slog.Info("starting node-host-agent",
		"version", version, "node", a.NodeName(), "pod", getenv("POD_NAME", ""))
	if err := a.Run(ctx); err != nil {
		slog.Error("agent exited", "error", err)
		os.Exit(1)
	}
}
