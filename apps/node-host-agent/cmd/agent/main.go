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
//
// Subsystems (all paths/intervals env-configurable):
//   - sweeper:    openebs orphan-dir cleanup. Enabled via
//     NODE_HOST_AGENT_ENABLE_SWEEPER (default true).
//   - apiprober:  apiserver watch-cache wedge guard for the api-local-lb
//     HAProxy sidecar — only meaningful on controller nodes.
//     NODE_HOST_AGENT_ENABLE_APIPROBER: true|false|auto
//     (default auto = enabled iff the HAProxy admin socket
//     exists at startup).
//   - hostmetrics: scrape-time collector for watchdog state latches,
//     nebula interface/route/cert-expiry, and k0s config drift.
//     Enabled via NODE_HOST_AGENT_ENABLE_HOSTMETRICS (default true).
//   - workerhygiene: worker-only watchdog checks (pod-teardown,
//     konnectivity IP drift, dns resolv drift). Enabled via
//     NODE_HOST_AGENT_ENABLE_HYGIENE (default true); needs a kube
//     client and a non-empty node name.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/agent"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/apiprober"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/hostmetrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/sweeper"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/workerhygiene"
)

var version = "dev"

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envBool parses a boolean env var; unset/empty → def. Accepts
// 1/0, true/false, yes/no, on/off.
func envBool(key string, def bool) bool {
	switch v := os.Getenv(key); v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}

func envInt(key string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil {
		return v
	}
	return def
}

func envInt64(key string, def int64) int64 {
	if v, err := strconv.ParseInt(os.Getenv(key), 10, 64); err == nil {
		return v
	}
	return def
}

// envDuration parses a Go duration ("1h", "30s"); a bare integer is
// treated as seconds for parity with the shell knobs it replaces.
func envDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	if n, err := strconv.Atoi(v); err == nil {
		return time.Duration(n) * time.Second
	}
	return def
}

// envList parses a comma-separated env var; unset/empty → nil (the
// consumer applies its own defaults).
func envList(key string) []string {
	v := os.Getenv(key)
	if v == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// kubeClient builds the in-cluster clientset (SA token), falling back
// to $KUBECONFIG for out-of-cluster runs. A var (not a plain func) so
// tests can stub the factory — csOnce's single-build behaviour is
// only observable through it.
var kubeClient = func() (kubernetes.Interface, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		if kc := os.Getenv("KUBECONFIG"); kc != "" {
			cfg, err = clientcmd.BuildConfigFromFlags("", kc)
		}
	}
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(cfg)
}

// buildAgentConfig wires the environment into an agent.Config: one
// shared registry plus the subsystem list in startup order (sweeper,
// apiprober). hostmetrics registers on the shared registry directly.
// The bool reports whether apiprober was enabled — it feeds the
// startup log line only.
func buildAgentConfig(nodeName, podName, namespace, version,
	metricsAddr, probeAddr string) (agent.Config, bool) {

	// Shared registry: subsystems + collectors register on it, the
	// agent serves it on /metrics.
	reg := prometheus.NewRegistry()
	var subsystems []agent.Subsystem

	// One clientset for the whole process: each NewForConfig builds
	// its own http.Transport + TLS pool, so sweeper and workerhygiene
	// share a lazily-built client instead of carrying two pools.
	var cs kubernetes.Interface
	var csErr error
	csOnce := func() (kubernetes.Interface, error) {
		if cs == nil && csErr == nil {
			cs, csErr = kubeClient()
		}
		return cs, csErr
	}

	// --- sweeper: openebs orphan pvc-* dir cleanup ---
	if envBool("NODE_HOST_AGENT_ENABLE_SWEEPER", true) {
		cs, err := csOnce()
		if err != nil {
			// Not fatal: the metrics/probe endpoints and other
			// subsystems still serve; the sweeper simply does not run.
			slog.Error("sweeper disabled: cannot build kubernetes client", "error", err)
		} else {
			sw, err := sweeper.New(sweeper.Config{
				BaseDir:        getenv("NODE_HOST_AGENT_SWEEP_BASE_DIR", "/var/openebs/local"),
				MinAge:         envDuration("NODE_HOST_AGENT_SWEEP_MIN_AGE", time.Hour),
				MaxDelete:      envInt("NODE_HOST_AGENT_SWEEP_MAX_DELETE", 10),
				Interval:       envDuration("NODE_HOST_AGENT_SWEEP_INTERVAL", time.Hour),
				MountsFile:     getenv("NODE_HOST_AGENT_MOUNTS_FILE", "/proc/1/mounts"),
				RequestTimeout: envDuration("NODE_HOST_AGENT_REQUEST_TIMEOUT", 30*time.Second),
				Client:         cs,
			}, reg)
			if err != nil {
				slog.Error("sweeper setup failed", "error", err)
			} else {
				subsystems = append(subsystems, sw)
			}
		}
	}

	// --- apiprober: apiserver watch-cache wedge guard ---
	// NODE_HOST_AGENT_ENABLE_APIPROBER: "auto" (default) = on — the
	// prober meters discover_fail cycles while the api-local-lb socket
	// is absent, so it only acts on workers carrying api-local-lb.
	apiproberSocket := getenv("NODE_HOST_AGENT_APIPROBER_SOCKET",
		"/run/api-local-lb-admin.sock")
	// "auto" (default) = enabled; a missing socket is NOT a startup
	// gate — the prober self-discovers each cycle and meters
	// discover_fail, so it also comes alive when api-local-lb is
	// installed after this pod started. "false" disables explicitly.
	apiproberEnabled := getenv("NODE_HOST_AGENT_ENABLE_APIPROBER", "auto") != "false"
	if apiproberEnabled {
		pb, err := apiprober.New(apiprober.Config{
			SocketPath:    apiproberSocket,
			BackendName:   getenv("NODE_HOST_AGENT_APIPROBER_BACKEND", "api_local_back"),
			Interval:      envDuration("NODE_HOST_AGENT_APIPROBER_INTERVAL", 30*time.Second),
			Mode:          getenv("NODE_HOST_AGENT_APIPROBER_MODE", apiprober.ModeDryRun),
			GapMin:        envInt64("NODE_HOST_AGENT_APIPROBER_GAP_MIN", 10000),
			FailCycles:    envInt("NODE_HOST_AGENT_APIPROBER_FAIL_CYCLES", 2),
			FrozenCycles:  envInt("NODE_HOST_AGENT_APIPROBER_FROZEN_CYCLES", 2),
			RecoverCycles: envInt("NODE_HOST_AGENT_APIPROBER_RECOVER_CYCLES", 3),
			TokenFile: getenv("NODE_HOST_AGENT_APIPROBER_TOKEN_FILE",
				"/var/run/secrets/kubernetes.io/serviceaccount/token"),
			CAFile: getenv("NODE_HOST_AGENT_APIPROBER_CA_FILE",
				"/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"),
			// Mirrors the shell version's `curl -sk` — apiserver certs
			// are not guaranteed to carry the backend IP in SANs.
			InsecureTLS: envBool("NODE_HOST_AGENT_APIPROBER_INSECURE_TLS", true),
			// Probe paths are overridable — the live path must be a
			// consistent read returning .metadata.resourceVersion
			// (swap to /api/v1/namespaces/default/services?limit=1
			// if the cluster doesn't serve leases under core/v1).
			LivePath: getenv("NODE_HOST_AGENT_APIPROBER_LIVE_PATH",
				"/api/v1/nodes?limit=1"),
			CachePath: getenv("NODE_HOST_AGENT_APIPROBER_CACHE_PATH",
				"/api/v1/nodes?limit=1&resourceVersion=0"),
			// Same env/dir hostmetrics uses — one shared watchdog
			// state dir mount for the whole pod.
			WatchdogStateDir: getenv("NODE_HOST_AGENT_WATCHDOG_STATE_DIR",
				"/host/var/lib/node-watchdog"),
		}, reg)
		if err != nil {
			slog.Error("apiprober setup failed", "error", err)
		} else {
			subsystems = append(subsystems, pb)
		}
	}

	// --- hostmetrics: scrape-time collector ---
	if envBool("NODE_HOST_AGENT_ENABLE_HOSTMETRICS", true) {
		reg.MustRegister(hostmetrics.New(hostmetrics.Config{
			NodeName:         nodeName,
			WatchdogStateDir: getenv("NODE_HOST_AGENT_WATCHDOG_STATE_DIR", "/host/var/lib/node-watchdog"),
			SysClassNet:      getenv("NODE_HOST_AGENT_SYS_CLASS_NET", "/sys/class/net"),
			NebulaIface:      getenv("NODE_HOST_AGENT_NEBULA_IFACE", "neb1"),
			RouteFile:        getenv("NODE_HOST_AGENT_HOST_ROUTE_FILE", "/proc/1/net/route"),
			K0sConfigFile:    getenv("NODE_HOST_AGENT_K0S_CONFIG", "/etc/k0s/k0s.yaml"),
			K0sUnitFile:      getenv("NODE_HOST_AGENT_K0S_UNIT", "/etc/systemd/system/k0scontroller.service"),
			NebulaCertFile:   getenv("NODE_HOST_AGENT_NEBULA_CERT", "/host/etc/nebula/interdc/host.crt"),
			ExpectedKCMArgs:  envList("NODE_HOST_AGENT_K0S_EXPECTED_KCM_ARGS"), // empty = defaults
		}))
	}

	// --- workerhygiene: worker-only watchdog checks ---
	// Needs a node name (pods are filtered by spec.nodeName) and a
	// kube client; either missing skips the subsystem — never aborts
	// the agent.
	if envBool("NODE_HOST_AGENT_ENABLE_HYGIENE", true) {
		// DaemonSet sets NODE_HOST_AGENT_NODE_NAME and NODE_NAME via
		// the downward API — prefer the explicit override env.
		hnode := getenv("NODE_HOST_AGENT_NODE_NAME", nodeName)
		switch {
		case hnode == "":
			slog.Error("workerhygiene disabled: node name empty " +
				"(NODE_HOST_AGENT_NODE_NAME/NODE_NAME unset)")
		default:
			cs, err := csOnce()
			if err != nil {
				slog.Error("workerhygiene disabled: cannot build kubernetes client",
					"error", err)
			} else {
				wh, err := workerhygiene.New(workerhygiene.Config{
					NodeName:           hnode,
					Enabled:            true,
					Interval:           envDuration("NODE_HOST_AGENT_HYGIENE_INTERVAL", 2*time.Minute),
					WatchdogStateDir:   getenv("NODE_HOST_AGENT_WATCHDOG_STATE_DIR", "/host/var/lib/node-watchdog"),
					WatchdogLogFile:    getenv("NODE_HOST_AGENT_WATCHDOG_LOG", "/host/var/log/node-watchdog.log"),
					ProcRoot:           getenv("NODE_HOST_AGENT_PROC_ROOT", "/proc"),
					CtrTaskRoot:        getenv("NODE_HOST_AGENT_CTR_TASK_ROOT", "/host/run/k0s/containerd/io.containerd.runtime.v2.task/k8s.io"),
					SandboxCtlRoot:     getenv("NODE_HOST_AGENT_SANDBOX_CTL_ROOT", "/host/run/k0s/containerd/io.containerd.sandbox.controller.v1.shim"),
					HostResolvConf:     getenv("NODE_HOST_AGENT_HOST_RESOLV_CONF", "/host/etc/resolv.conf"),
					K0sWorkerUnitFile:  getenv("NODE_HOST_AGENT_K0S_WORKER_UNIT", "/host/etc/systemd/system/k0sworker.service"),
					StuckDeleteAge:     envDuration("NODE_HOST_AGENT_HYGIENE_STUCK_DELETE_AGE", 15*time.Minute),
					StuckWedgeAge:      envDuration("NODE_HOST_AGENT_HYGIENE_STUCK_WEDGE_AGE", 30*time.Minute),
					MaxForceDelete:     envInt("NODE_HOST_AGENT_HYGIENE_MAX_FORCE_DELETE", 5),
					ConsecNeeded:       envInt("NODE_HOST_AGENT_HYGIENE_CONSEC_NEEDED", 2),
					MinRestartInterval: envDuration("NODE_HOST_AGENT_HYGIENE_MIN_RESTART_INTERVAL", 30*time.Minute),
					Client:             cs,
				}, reg)
				if err != nil {
					slog.Error("workerhygiene setup failed", "error", err)
				} else {
					subsystems = append(subsystems, wh)
				}
			}
		}
	}

	return agent.Config{
		NodeName:    nodeName,
		PodName:     podName,
		Namespace:   namespace,
		Version:     version,
		MetricsAddr: metricsAddr,
		ProbeAddr:   probeAddr,
		Registry:    reg,
		Subsystems:  subsystems,
	}, apiproberEnabled
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

	nodeName := getenv("NODE_NAME", "")
	podName := getenv("POD_NAME", "")
	namespace := getenv("POD_NAMESPACE", "")

	cfg, apiproberEnabled := buildAgentConfig(nodeName, podName,
		namespace, version, metricsAddr, probeAddr)
	a := agent.New(cfg)

	slog.Info("starting node-host-agent",
		"version", version, "node", a.NodeName(), "pod", podName,
		"apiprober", apiproberEnabled)
	if err := a.Run(ctx); err != nil {
		slog.Error("agent exited", "error", err)
		os.Exit(1)
	}
}
