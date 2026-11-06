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
//   - concourse-cache: native Go pruner for
//     /var/openebs/local/pvc-*/shared-cache (replaces the CronJob +
//     pods/exec janitor). NODE_HOST_AGENT_ENABLE_CONCOURSE_CACHE
//     (default true), cadence NODE_HOST_AGENT_CONCOURSE_CACHE_INTERVAL
//     (default 15m).
//   - apiprober:  apiserver watch-cache wedge guard for the api-local-lb
//     HAProxy sidecar. NODE_HOST_AGENT_ENABLE_APIPROBER:
//     true|false|auto (default auto).
//   - hostmetrics: scrape-time collector for watchdog state latches,
//     PSI/cpu-delivered, fail2ban, nebula + k0s config drift.
//     Enabled via NODE_HOST_AGENT_ENABLE_HOSTMETRICS (default true).
//   - workerhygiene: worker-only watchdog checks (pod-teardown,
//     konnectivity drift, kubelet stall/watch-wedge, ctr tasks,
//     cilium health/init-stuck). NODE_HOST_AGENT_ENABLE_HYGIENE
//     (default true); needs a kube client and a non-empty node name.
//   - nethealth: DNS fallback, coredns-stub, overlay egress relays,
//     nebula health, fail2ban (former watchdog modules 12/13/20/21/50).
//     NODE_HOST_AGENT_ENABLE_NETHEALTH (default true).
//   - janitor:  self-healing sweeps of the shared watchdog state dir
//     (reaps stale state-* latches no enabled check can produce, plus
//     known latches past 24h) and of retired shell-stack residue
//     (reset-failed/stop on not-found ghost units, kills orphaned
//     `ip monitor` watchers). No kube client — runs on every node
//     class. NODE_HOST_AGENT_ENABLE_JANITOR (default true).
//   - nodereporter: syncs watchdog state-* latches to NodeConditions,
//     K8s Events and problem_gauge/problem_counter (replaces the NPD
//     watchdog monitors). NODE_HOST_AGENT_ENABLE_REPORTER (default
//     true); needs a kube client and a node name.
//   - controllerhygiene: control-plane guards (apiserver wedge,
//     kine TTL/pool, oom-loop shield, systemd watchdog feeder).
//     NODE_HOST_AGENT_ENABLE_CONTROLLERHYGIENE: true|false|auto
//     (default auto = enabled iff k0scontroller.service exists).
//   - hostconfig: declarative host converger (sysctl, systemd
//     drop-ins, nebula, coredns stub, api-local-lb, fail2ban, sshd)
//     replacing the node-config-agent ansible DaemonSet.
//     NODE_HOST_AGENT_ENABLE_HOSTCONFIG: true|false|auto (default
//     auto = enabled iff the vars dir holds defaults.yaml).
//   - hubsync:  SSH converge of the standalone targets (interdc
//     hubs, infra/api-lb VMs) — the hub-converge CronJob port.
//     Pod-mode only; polls for the converge key at
//     NODE_HOST_AGENT_CONVERGE_SSH_KEY (default
//     /etc/node-converge-ssh/id_ed25519) — the secret mounts
//     optional:true and may land after pod start.
//   - kinedb:   kine DB VM probe/compact-guard/maintenance loops
//     (postgres+pgbouncer). NODE_HOST_AGENT_ENABLE_KINEDB:
//     true|false|auto (default auto = kinedb.Detect: the postgres
//     .env exists or a kine_db extra-host entry matches).
//
// --standalone (NODE_HOST_AGENT_STANDALONE=1) is the on-host systemd
// mode the hubsync-converged targets run: hostRoot is forced to "/",
// the kube-client/pod-context subsystems (sweeper, concourse-cache,
// workerhygiene, nodereporter, hubsync) default OFF, the host-local
// ones (hostconfig, hostmetrics + the node-exporter textfile writer,
// nethealth, apiprober, controllerhygiene, kinedb) stay on — the env
// vars still override every default. --node-name supplies the node
// identity (NODE_HOST_AGENT_NODE_NAME/NODE_NAME envs win when set).
// /etc/api-backend-guard.conf feeds the apiprober fallback layer
// below the env vars on api-lb VMs.
//
// Subcommands (dispatched before flag parsing; an argv[0] basename
// of "runc" also selects the wrapper, since /concourse-runc/runc is
// a copy of this binary):
//   - concourse-worker-init     — worker init-rm (btrfs cleanup,
//     shared-cache wipe/scaffold, runc wrapper install).
//   - concourse-runc-wrapper    — runc shim injecting the
//     /shared-cache bind mount, then execs runc.real.
//   - converge-once --vars-dir=DIR [--node-name=N] — one hostconfig
//     converge on the host, then exit.
//   - nebula-sign --vars-dir=DIR --ca-dir=DIR [--node=N] — sign
//     interdc host certs with the local CA (sign.yaml port).
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
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/agent"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostctx"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
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
		cfg.Timeout = envx.Duration("NODE_HOST_AGENT_REQUEST_TIMEOUT",
			30*time.Second)
	}
	return kubernetes.NewForConfig(cfg)
}

// agentParams bundles the inputs buildAgentConfig consumes — one
// field per former positional parameter so the call sites read by
// name. StandaloneFlag is the --standalone CLI switch; the
// NODE_HOST_AGENT_STANDALONE env is OR-ed in by buildAgentConfig so
// either spelling selects standalone mode.
type agentParams struct {
	nodeName       string
	podName        string
	namespace      string
	version        string
	metricsAddr    string
	probeAddr      string
	standaloneFlag bool
}

// wireReport is the wire loop's per-descriptor outcome summary —
// the generalized form of the bool this signature used to return
// for apiprober alone. Off lists descriptors whose env flag/auto
// resolution said no; Skipped lists the ones that resolved ON but a
// needs-gate or Build failure kept out of Config.Subsystems. Both
// lists are in descriptor (startup) order.
type wireReport struct {
	Off     []string
	Skipped []string
}

// buildAgentConfig wires the environment into an agent.Config: one
// shared registry plus the subsystem list in startup order.
// hostmetrics registers on the shared registry directly. The
// wireReport feeds only the startup log line — it answers the
// operator's second question (which subsystems did NOT wire up and
// why) alongside the constructed set.
func buildAgentConfig(p agentParams) (agent.Config, wireReport) {

	// Standalone = on-host systemd mode (API LB VMs, interdc hubs,
	// the kine DB VM): the enable-set inverts — every subsystem
	// needing the kube client or pod context defaults OFF, the
	// host-local ones stay ON. Implemented by flipping the DEFAULTS
	// of the same envx knobs, never by hard ifs, so the
	// env contract is intact (NODE_HOST_AGENT_ENABLE_HYGIENE=true
	// still forces workerhygiene on a standalone host).
	standalone := p.standaloneFlag ||
		envx.Bool("NODE_HOST_AGENT_STANDALONE", false)
	defKube := !standalone // default for kube/pod-context subsystems

	// Shared registry: subsystems + collectors register on it, the
	// agent serves it on /metrics.
	reg := prometheus.NewRegistry()

	// Host root: "/host" in the DaemonSet (host fs bind-mounted),
	// "/" for the standalone systemd binary on the host itself.
	hostRoot := strings.TrimRight(envx.String("NODE_HOST_AGENT_HOST_ROOT", "/host"), "/")
	if hostRoot == "" || standalone {
		hostRoot = "/"
	}
	hostPath := func(p string) string {
		if hostRoot == "/" {
			return p
		}
		return hostRoot + p
	}

	// Shared host-side inputs: the node-watchdog.conf parser feeds
	// API_BACKENDS / OVERLAY_* / DNS_FALLBACK_MAP into apiprober,
	// workerhygiene, nethealth and hostmetrics; the systemd client
	// drives every host unit action (nsenter-wrapped in a container,
	// direct on the host).
	wdConfPath := envx.String("NODE_HOST_AGENT_WATCHDOG_CONF",
		hostPath("/etc/node-watchdog.conf"))
	wdCfg, err := watchdogconf.Load(wdConfPath)
	if err != nil {
		logger().Error("watchdog conf parse failed — running on defaults",
			"path", wdConfPath, "error", err)
		wdCfg, _ = watchdogconf.Parse(nil)
	}
	// One shared reloader: hostconfig rewrites the conf every
	// converge, so conf-consuming subsystems re-read it per cycle
	// instead of pinning the startup parse (the runner re-sourced it
	// every run — API_BACKENDS / OVERLAY_* / WD_SIG_* changes land
	// next cycle).
	wdReloader := watchdogconf.NewReloader(wdConfPath, wdCfg)
	sdClient := systemd.New(systemd.Config{HostRoot: hostRoot})

	watchdogStateDir := envx.String("NODE_HOST_AGENT_WATCHDOG_STATE_DIR",
		hostPath("/var/lib/node-watchdog"))
	watchdogLogFile := envx.String("NODE_HOST_AGENT_WATCHDOG_LOG",
		hostPath("/var/log/node-watchdog.log"))
	hnode := envx.String("NODE_HOST_AGENT_NODE_NAME", p.nodeName)

	// Shared journald inputs for the journal-unreadable blindness
	// detector (workerhygiene + controllerhygiene): the storage dirs
	// are the "journald is installed" witness — a host with no
	// journald fails every read by config and must never latch.
	// hostPath() makes them unprefixed in standalone mode.
	journalDirs := envx.List("NODE_HOST_AGENT_JOURNAL_DIRS")
	if journalDirs == nil {
		journalDirs = []string{
			hostPath("/var/log/journal"), hostPath("/run/log/journal")}
	}
	journalUnreadableNeeded := envx.Int(
		"NODE_HOST_AGENT_JOURNAL_UNREADABLE_NEEDED", 5)

	// Shared vars/textfile dirs — hoisted out of the hostconfig
	// block: workerhygiene (systemd_watchdog_hosts), kinedb
	// (Detect), hubsync (VarsDir) and hostconfig itself all read the
	// same vars dir, and the textfile dir feeds both the standalone
	// prom writer and kinedb's prom files.
	varsDir := envx.String("NODE_HOST_AGENT_HOSTCONFIG_VARS_DIR", "/config/vars")
	textfileDir := envx.String("NODE_HOST_AGENT_TEXTFILE_DIR",
		hostPath("/var/lib/node-exporter/textfile"))

	// One clientset for the whole process: each NewForConfig builds
	// its own http.Transport + TLS pool, so sweeper, workerhygiene
	// and nodereporter share a lazily-built client instead of
	// carrying three pools. On standalone hosts no kube client is
	// built at all unless one of those subsystems is enabled.
	var cs kubernetes.Interface
	csOnce := func() (kubernetes.Interface, error) {
		if cs == nil {
			// Only a successful build is cached — a transient
			// failure (token not mounted yet, brief apiserver
			// outage) must not disable every kube consumer for
			// the process lifetime.
			c, err := kubeClient()
			if err != nil {
				return nil, err
			}
			cs = c
		}
		return cs, nil
	}

	// The shared watchdog/host context every subsystem EnvDeps embeds
	// — resolved once above, spliced verbatim into each Build closure
	// as EnvDeps{Deps: w.Deps, ...}.
	hc := hostctx.Deps{
		Watchdog:                wdCfg,
		WatchdogSrc:             wdReloader,
		WatchdogStateDir:        watchdogStateDir,
		WatchdogLogFile:         watchdogLogFile,
		HostPath:                hostPath,
		HostRoot:                hostRoot,
		Systemd:                 sdClient,
		JournalDirs:             journalDirs,
		JournalUnreadableNeeded: journalUnreadableNeeded,
		VarsDir:                 varsDir,
		TextfileDir:             textfileDir,
		NodeName:                hnode,
	}

	w := &wiring{
		reg:        reg,
		csOnce:     csOnce,
		Deps:       hc,
		standalone: standalone,
		defKube:    defKube,

		resolved: map[string]bool{},
		built:    map[string]bool{},

		podName: p.podName,
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
	report := wireReport{Off: []string{}, Skipped: []string{}}
	for _, name := range names {
		if !w.resolved[name] {
			report.Off = append(report.Off, name)
		} else if !w.built[name] {
			report.Skipped = append(report.Skipped, name)
		}
	}

	return agent.Config{
		NodeName:    p.nodeName,
		PodName:     p.podName,
		Namespace:   p.namespace,
		Version:     p.version,
		MetricsAddr: p.metricsAddr,
		ProbeAddr:   p.probeAddr,
		Registry:    reg,
		Subsystems:  w.subsystems,
	}, report
}

func main() {
	// Multi-call dispatch: subcommands (concourse init/runc shim,
	// converge-once, nebula-sign) and the argv[0] "runc" alias run
	// before flag parsing. Daemon flags pass through.
	if code, handled := dispatch(os.Args); handled {
		os.Exit(code)
	}

	var metricsAddr, probeAddr, nodeNameFlag string
	var showVersion, standaloneFlag bool
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":9115",
		"address the Prometheus metrics endpoint binds to")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081",
		"address the health/readiness probe endpoints bind to")
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
	nodeName := envx.String("NODE_HOST_AGENT_NODE_NAME",
		envx.String("NODE_NAME", nodeNameFlag))
	podName := envx.String("POD_NAME", "")
	namespace := envx.String("POD_NAMESPACE", "")

	cfg, report := buildAgentConfig(agentParams{
		nodeName:       nodeName,
		podName:        podName,
		namespace:      namespace,
		version:        version,
		metricsAddr:    metricsAddr,
		probeAddr:      probeAddr,
		standaloneFlag: standaloneFlag,
	})
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
		"standalone", standaloneFlag, "metricsAddr", metricsAddr,
		"probeAddr", probeAddr, "subsystems", subsystems,
		"off", report.Off, "skipped", report.Skipped)
	if err := a.Run(ctx); err != nil {
		logger().Error("agent exited", "error", err)
		os.Exit(1)
	}
}
