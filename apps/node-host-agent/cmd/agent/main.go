// node-host-agent — per-node agent (DaemonSet) for the
// kubernetes-node-automation stack. Runs on every cluster node and
// exposes node-local metrics plus health probes for
// node-automation-controller and external monitoring.
//
// Interface contract (same as node-automation-controller):
//   - Prometheus metrics on :9115/metrics.
//   - Health/readiness probes on :8081/healthz and :8081/readyz.
//   - /debug/pprof on a LOOPBACK-only listener (default
//     127.0.0.1:9116, --pprof-bind-address /
//     NODE_HOST_AGENT_PPROF_BIND_ADDRESS) — never on the metrics
//     hostPort (roadmap item 1.2).
//   - Node identity via the downward API: NODE_NAME, POD_NAME,
//     POD_NAMESPACE.
//
// Subsystems are env-gated via NODE_HOST_AGENT_ENABLE_* — the
// registry and startup order live in cmd/agent/wiring.go
// (descriptors()); the full env surface is generated into ENV.md
// (`moon run node-host-agent:envdoc`).
//
// --standalone (NODE_HOST_AGENT_STANDALONE=1) is the on-host systemd
// mode the hubsync-converged targets run: hostRoot is forced to "/",
// the kube-client/pod-context subsystems (sweeper, concourse-cache,
// workerhygiene, nodereporter, hubsync) default OFF, the host-local
// ones (hostconfig, hostmetrics + the node-exporter textfile writer,
// nethealth, apiprober, janitor, controllerhygiene, kinedb) stay on —
// the env vars still override every default. --node-name supplies the
// node identity (NODE_HOST_AGENT_NODE_NAME/NODE_NAME envs win when
// set). /etc/api-backend-guard.conf feeds the apiprober fallback
// layer below the env vars on api-lb VMs.
//
// Multi-call binary: subcommands (converge-once, nebula-sign,
// purge-events, the check-*/rescue ops, the concourse init/runc
// shim) are dispatched before flag.Parse — the dispatch table, and
// therefore the usage text, lives in cli.go. An argv[0] basename of
// "runc" selects the runc wrapper, since /concourse-runc/runc is a
// copy of this binary.
//
// NODE_HOST_AGENT_HOST_ROOT (default "/host") prefixes every host
// path; set it to "/" when running as a standalone systemd binary on
// the host itself (API LB VMs, control-plane nodes). The kube client
// is built lazily — only when a subsystem that needs it (sweeper,
// workerhygiene, nodereporter, hubsync) is enabled.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/agent"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostctx"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

var version = "dev"

// kubeClient builds the in-cluster clientset (SA token), falling back
// to $KUBECONFIG for out-of-cluster runs. A var (not a plain func) so
// tests can stub the factory — csOnce's shared-build behaviour is
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
	// Every subsystem shares this client — a wedged apiserver must
	// not hang each kube API call forever, so the config carries the
	// same request-timeout knob the sweeper uses for its cycles.
	if cfg.Timeout <= 0 {
		cfg.Timeout = envx.Duration(envnames.EnvRequestTimeout,
			30*time.Second)
	}
	// Client budget + wire format — the fleet-wide posture the
	// controller's tuneClientConfig installs (cmd/manager/clients.go)
	// sized down for one node's traffic: client-go's QPS 5 / Burst 10
	// defaults throttled the worker Pod LIST every hygiene cycle;
	// 20/40 gives the node's handful of consumers headroom without a
	// controller-grade bucket. Protobuf cuts the LIST/watch payload
	// — worker Pods carry env specs, so JSON serialization is a real
	// bandwidth cost; JSON stays in AcceptContentTypes so the
	// apiserver can negotiate it for anything protobuf can't encode.
	cfg.QPS = 20
	cfg.Burst = 40
	cfg.AcceptContentTypes = "application/vnd.kubernetes.protobuf,application/json"
	cfg.ContentType = "application/vnd.kubernetes.protobuf"
	return kubernetes.NewForConfig(cfg)
}

// wireReport is the wire loop's per-descriptor outcome summary —
// the generalized form of the bool this signature used to return
// for apiprober alone. Off lists descriptors whose env flag/auto
// resolution said no; Skipped lists the ones that resolved ON but a
// needs-gate or Build failure kept out of Config.Subsystems. Both
// lists are in descriptor (startup) order. Standalone carries the
// RESOLVED mode (flag OR env) so the startup log reports what
// actually drove the enable-set inversion, not the raw --standalone
// switch.
type wireReport struct {
	Off        []string
	Skipped    []string
	Standalone bool
}

// buildAgentConfig wires the environment into an agent.Config: cfg
// arrives already carrying the identity/listener fields main resolved
// from flags+env (NodeName/PodName/Namespace/Version/MetricsAddr/
// ProbeAddr); the function fills in the shared registry plus the
// subsystem list in startup order and returns the completed Config.
// hostmetrics registers on the shared registry directly. The
// wireReport feeds only the startup log line — it answers the
// operator's second question (which subsystems did NOT wire up and
// why) alongside the constructed set. standaloneFlag is the
// --standalone CLI switch; the NODE_HOST_AGENT_STANDALONE env is
// OR-ed in so either spelling selects standalone mode — it is NOT a
// Config field because agent.Config is also the runtime's contract.
func buildAgentConfig(cfg agent.Config, standaloneFlag bool) (agent.Config, wireReport) {

	// Standalone = on-host systemd mode (API LB VMs, interdc hubs,
	// the kine DB VM): the enable-set inverts — every subsystem
	// needing the kube client or pod context defaults OFF, the
	// host-local ones stay ON. Implemented by flipping the DEFAULTS
	// of the same envx knobs, never by hard ifs, so the
	// env contract is intact (NODE_HOST_AGENT_ENABLE_HYGIENE=true
	// still forces workerhygiene on a standalone host).
	standalone := standaloneFlag ||
		envx.Bool(envnames.EnvStandalone, false)
	defKube := !standalone // default for kube/pod-context subsystems

	// Shared registry: subsystems + collectors register on it, the
	// agent serves it on /metrics.
	reg := prometheus.NewRegistry()

	// Host root: "/host" in the DaemonSet (host fs bind-mounted),
	// "/" for the standalone systemd binary on the host itself.
	hostRoot := strings.TrimRight(envx.String(envnames.EnvHostRoot, "/host"), "/")
	if hostRoot == "" || standalone {
		hostRoot = "/"
	}
	hostPath := func(p string) string {
		if hostRoot == "/" {
			return p
		}
		return hostRoot + p
	}

	// The systemd client drives every host unit action
	// (nsenter-wrapped in a container, direct on the host) — built
	// here because HostRoot, not env, is its input.
	sdClient := systemd.New(systemd.Config{HostRoot: hostRoot})

	// One clientset for the whole process: each NewForConfig builds
	// its own http.Transport + TLS pool, so sweeper, workerhygiene
	// and nodereporter share a lazily-built client instead of
	// carrying three pools. On standalone hosts no kube client is
	// built at all unless one of those subsystems is enabled.
	//
	// Mutex-guarded lazy init, NOT sync.OnceValue: only a
	// successful build is cached — a transient failure (token not
	// mounted yet, brief apiserver outage) must not disable every
	// kube consumer for the process lifetime, so a failed build is
	// retried on the next csOnce call.
	var (
		csMu sync.Mutex
		cs   kubernetes.Interface
	)
	csOnce := func() (kubernetes.Interface, error) {
		csMu.Lock()
		defer csMu.Unlock()
		if cs == nil {
			c, err := kubeClient()
			if err != nil {
				return nil, err
			}
			cs = c
		}
		return cs, nil
	}

	// The shared watchdog/host context every subsystem EnvDeps embeds
	// — the NODE_HOST_AGENT_* knobs (watchdog conf + reloader, state
	// dir, log file, journal dirs, vars/textfile dirs) resolve inside
	// hostctx.DepsFromEnv, symmetric with each subsystem's own
	// ConfigFromEnv; only the non-env inputs (hostPath/hostRoot from
	// the standalone flip, the resolved node name, the systemd
	// client) are passed in. Spliced verbatim into each Build
	// closure as EnvDeps{Deps: w.Deps, ...}.
	hc := hostctx.DepsFromEnv(hostctx.EnvParams{
		HostPath: hostPath,
		HostRoot: hostRoot,
		NodeName: cfg.NodeName,
		Systemd:  sdClient,
	})

	w := &wiring{
		reg:        reg,
		csOnce:     csOnce,
		Deps:       hc,
		standalone: standalone,
		defKube:    defKube,

		resolved: map[string]bool{},
		built:    map[string]bool{},

		podName: cfg.PodName,
	}

	// One Descriptor per subsystem, in the same order the sequential
	// blocks ran — w.subsystems startup order is unchanged.
	// resolveAndBuild records the resolved enable mode in w.resolved
	// and whether Build appended in w.built; the report below splits
	// the names that never wired up into off (flag/auto said no) vs
	// skipped (needs-gate or Build held them back), in descriptor
	// order so the startup log reads deterministically.
	names := []string{}
	for _, d := range w.descriptors() {
		names = append(names, d.Name)
		w.resolveAndBuild(d)
	}
	report := wireReport{Off: []string{}, Skipped: []string{},
		Standalone: standalone}
	for _, name := range names {
		if !w.resolved[name] {
			report.Off = append(report.Off, name)
		} else if !w.built[name] {
			report.Skipped = append(report.Skipped, name)
		}
	}

	cfg.Registry = reg
	cfg.Subsystems = w.subsystems
	return cfg, report
}

func main() {
	// Multi-call dispatch: subcommands (concourse init/runc shim,
	// converge-once, nebula-sign) and the argv[0] "runc" alias run
	// before flag parsing. Daemon flags pass through.
	if code, handled := dispatch(os.Args); handled {
		os.Exit(code)
	}

	var metricsAddr, probeAddr, pprofAddr, nodeNameFlag string
	var showVersion, standaloneFlag bool
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":9115",
		"address the Prometheus metrics endpoint binds to")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081",
		"address the health/readiness probe endpoints bind to")
	// Loopback-only default: /debug/pprof left 0.0.0.0:9115 in
	// roadmap item 1.2's audit — every tenant pod and VLAN
	// neighbour could profile the root daemon.
	// NODE_HOST_AGENT_PPROF_BIND_ADDRESS feeds the default so the
	// DaemonSet and the standalone units can override without
	// flags; the flag wins.
	flag.StringVar(&pprofAddr, "pprof-bind-address",
		envx.String(envnames.EnvPprofBindAddress, "127.0.0.1:9116"),
		"LOOPBACK-ONLY address the /debug/pprof endpoints bind to "+
			"(empty disables the listener; env "+
			envnames.EnvPprofBindAddress+" feeds the default)")
	flag.BoolVar(&standaloneFlag, "standalone", false,
		"standalone systemd mode: host root /, pod-context subsystems default off "+
			"(NODE_HOST_AGENT_STANDALONE=1 is equivalent)")
	flag.StringVar(&nodeNameFlag, "node-name", "",
		"node identity for standalone runs "+
			"(NODE_HOST_AGENT_NODE_NAME/NODE_NAME envs take precedence)")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Println(version)
		return
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	ctx, stop := signalContext()
	defer stop()

	// Precedence: NODE_HOST_AGENT_NODE_NAME > NODE_NAME > --node-name.
	// Standalone units pass --node-name (no downward API on the host).
	nodeName := hostctx.NodeName(nodeNameFlag)
	podName := envx.String("POD_NAME", "")
	namespace := envx.String("POD_NAMESPACE", "")

	cfg, report := buildAgentConfig(agent.Config{
		NodeName:    nodeName,
		PodName:     podName,
		Namespace:   namespace,
		Version:     version,
		MetricsAddr: metricsAddr,
		ProbeAddr:   probeAddr,
		PprofAddr:   pprofAddr,
	}, standaloneFlag)
	a := agent.New(cfg)

	// The enabled set is an operator's first question when a check
	// misbehaves — list every subsystem that actually wired up, and
	// answer the second question too: off = flag/auto resolved
	// disabled, skipped = resolved on but a needs-gate or Build
	// failure held it back (setup errors already logged above). The
	// old apiprober-only bool is subsumed by these two lists.
	subsystems := make([]string, 0, len(cfg.Subsystems))
	for _, s := range cfg.Subsystems {
		subsystems = append(subsystems, s.Name())
	}
	logger().Info("starting node-host-agent",
		"version", version, "node", a.NodeName(), "pod", podName,
		"standalone", report.Standalone, "metricsAddr", metricsAddr,
		"probeAddr", probeAddr, "pprofLoopbackAddr", pprofAddr,
		"subsystems", subsystems,
		"off", report.Off, "skipped", report.Skipped)
	if err := a.Run(ctx); err != nil {
		logger().Error("agent exited", "error", err)
		os.Exit(1)
	}
}
