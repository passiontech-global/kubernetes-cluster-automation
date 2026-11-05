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
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/topology"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/subsystem/apiprober"
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

// envOr is the env → conf → consumer-default chain for string knobs:
// an unset env falls through to the conf value (which may itself be
// empty — the package default then applies).
func envOr(key, confVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return confVal
}

// orStr returns a unless empty — the conf → compiled-default tail of
// the fallback chains.
func orStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// envIntOr is env → conf-int → def for int knobs (conf ints are raw
// counts; 0 = unset).
func envIntOr(key string, confVal, def int) int {
	if os.Getenv(key) != "" {
		return envInt(key, def)
	}
	if confVal > 0 {
		return confVal
	}
	return def
}

// envInt64Or is env → conf-int64 → def for int64 knobs.
func envInt64Or(key string, confVal, def int64) int64 {
	if os.Getenv(key) != "" {
		return envInt64(key, def)
	}
	if confVal > 0 {
		return confVal
	}
	return def
}

// envDurOr is env → conf-seconds → def for duration knobs (conf
// carries bare seconds like the shell *_S knobs).
func envDurOr(key string, confSeconds int, def time.Duration) time.Duration {
	if os.Getenv(key) != "" {
		return envDuration(key, def)
	}
	if confSeconds > 0 {
		return time.Duration(confSeconds) * time.Second
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
	var d time.Duration
	if parsed, err := time.ParseDuration(v); err == nil {
		d = parsed
	} else if n, err := strconv.Atoi(v); err == nil {
		d = time.Duration(n) * time.Second
	} else {
		// Neither shape parsed — warn like the ≤0 path does: a typo'd
		// knob silently pinned to the default is impossible to spot
		// from the outside.
		logger().Warn("unparseable env duration ignored — using default",
			"env", key, "value", v, "default", def)
		return def
	}
	if d <= 0 {
		// A ≤0 interval would panic time.NewTicker inside the
		// subsystem and crash-loop the daemon — warn and keep the
		// default instead.
		logger().Warn("non-positive env duration ignored — using default",
			"env", key, "value", v, "default", def)
		return def
	}
	return d
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

// envIntList parses a comma-separated env var of ints; unset/empty →
// nil (the consumer applies its own defaults). Non-numeric entries
// are skipped.
func envIntList(key string) []int {
	var out []int
	for _, p := range envList(key) {
		n, err := strconv.Atoi(p)
		if err != nil {
			logger().Warn("non-numeric env list entry ignored",
				"env", key, "value", p)
			continue
		}
		out = append(out, n)
	}
	return out
}

// osExecutable is os.Executable as a var — tests stub it to exercise
// the "(deleted)"/missing-path fallbacks in resolveLocalBinary.
var osExecutable = os.Executable

// resolveLocalBinary finds the binary hubsync mirrors to targets.
// LocalBinary mirrors the running binary — the DaemonSet ships it at
// /node-host-agent, but resolving our own path keeps the mirror
// correct wherever the binary actually lives. Two failure shapes are
// normalised: os.Executable reports "<path> (deleted)" when the
// running image was replaced in place (sha256File would fail every
// cycle on that literal path), and a still-nonexistent resolved path
// falls back to the DS's fixed /node-host-agent.
func resolveLocalBinary() string {
	if v := os.Getenv("NODE_HOST_AGENT_HUBSYNC_LOCAL_BINARY"); v != "" {
		return v
	}
	const fallback = "/node-host-agent"
	exe, err := osExecutable()
	if err != nil {
		return fallback
	}
	exe = strings.TrimSuffix(exe, " (deleted)")
	if _, err := os.Stat(exe); err != nil {
		return fallback
	}
	return exe
}

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
		cfg.Timeout = envDuration("NODE_HOST_AGENT_REQUEST_TIMEOUT",
			30*time.Second)
	}
	return kubernetes.NewForConfig(cfg)
}

// periodic adapts a plain cycle func to the agent.Subsystem contract:
// run immediately, then every interval until ctx is cancelled.
type periodic struct {
	name     string
	interval time.Duration
	fn       func(ctx context.Context)
}

func (p periodic) Name() string { return p.name }

func (p periodic) Run(ctx context.Context) {
	p.fn(ctx)
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.fn(ctx)
		}
	}
}

// kubeletWatchdogHosts resolves workerhygiene's T15 opt-in list:
// NODE_HOST_AGENT_KUBELET_WATCHDOG_HOSTS → systemd_watchdog_hosts in
// cluster.yaml (topology.Load over the vars dir). A missing/broken
// vars dir yields nil — the feeder self-gates on k0sworker.service,
// so the list is advisory.
func kubeletWatchdogHosts(varsDir, nodeName string) []string {
	if l := envList("NODE_HOST_AGENT_KUBELET_WATCHDOG_HOSTS"); l != nil {
		return l
	}
	t, err := topology.Load(topology.Config{VarsDir: varsDir, NodeName: nodeName})
	if err != nil {
		return nil
	}
	return t.Vars.StrList("systemd_watchdog_hosts")
}

// proberInputs is the resolved env → guard.conf → default layer for
// the apiprober knobs the standalone conf may carry. Extracted so
// tests can assert the precedence chain without standing a prober up.
type proberInputs struct {
	socket     string
	backend    string
	companions []string
	static     []apiprober.StaticBackend
	mode       string
	tokenFile  string
	caFile     string
}

func resolveProberInputs(wdCfg *watchdogconf.Config,
	g apiprober.GuardDefaults) proberInputs {

	var static []apiprober.StaticBackend
	switch {
	case len(g.StaticBackends) > 0:
		static = g.StaticBackends
	default:
		for _, b := range wdCfg.APIBackends {
			static = append(static,
				apiprober.StaticBackend{Name: b.Name, Addr: b.Addr})
		}
	}
	companions := envList("NODE_HOST_AGENT_APIPROBER_COMPANION_BACKENDS")
	if companions == nil {
		companions = g.CompanionBackends
	}
	return proberInputs{
		socket: envOr("NODE_HOST_AGENT_APIPROBER_SOCKET",
			orStr(g.SocketPath, "/run/api-local-lb-admin.sock")),
		backend: envOr("NODE_HOST_AGENT_APIPROBER_BACKEND",
			orStr(g.BackendName, "api_local_back")),
		companions: companions,
		static:     static,
		mode: envOr("NODE_HOST_AGENT_APIPROBER_MODE",
			orStr(g.Mode, apiprober.ModeDryRun)),
		tokenFile: envOr("NODE_HOST_AGENT_APIPROBER_TOKEN_FILE",
			orStr(g.TokenFile, "/var/run/secrets/kubernetes.io/serviceaccount/token")),
		caFile: envOr("NODE_HOST_AGENT_APIPROBER_CA_FILE",
			orStr(g.CAFile, "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")),
	}
}

// buildAgentConfig wires the environment into an agent.Config: one
// shared registry plus the subsystem list in startup order.
// hostmetrics registers on the shared registry directly. The bool
// reports whether apiprober was enabled — it feeds the startup log
// line only. standaloneFlag is the --standalone CLI switch; the
// NODE_HOST_AGENT_STANDALONE env is OR-ed in here so either spelling
// selects standalone mode.
func buildAgentConfig(nodeName, podName, namespace, version,
	metricsAddr, probeAddr string, standaloneFlag bool) (agent.Config, bool) {

	// Standalone = on-host systemd mode (API LB VMs, interdc hubs,
	// the kine DB VM): the enable-set inverts — every subsystem
	// needing the kube client or pod context defaults OFF, the
	// host-local ones stay ON. Implemented by flipping the DEFAULTS
	// of the same envBool/getenv knobs, never by hard ifs, so the
	// env contract is intact (NODE_HOST_AGENT_ENABLE_HYGIENE=true
	// still forces workerhygiene on a standalone host).
	standalone := standaloneFlag ||
		envBool("NODE_HOST_AGENT_STANDALONE", false)
	defKube := !standalone // default for kube/pod-context subsystems

	// Shared registry: subsystems + collectors register on it, the
	// agent serves it on /metrics.
	reg := prometheus.NewRegistry()

	// Host root: "/host" in the DaemonSet (host fs bind-mounted),
	// "/" for the standalone systemd binary on the host itself.
	hostRoot := strings.TrimRight(getenv("NODE_HOST_AGENT_HOST_ROOT", "/host"), "/")
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
	wdConfPath := getenv("NODE_HOST_AGENT_WATCHDOG_CONF",
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

	watchdogStateDir := getenv("NODE_HOST_AGENT_WATCHDOG_STATE_DIR",
		hostPath("/var/lib/node-watchdog"))
	watchdogLogFile := getenv("NODE_HOST_AGENT_WATCHDOG_LOG",
		hostPath("/var/log/node-watchdog.log"))
	hnode := getenv("NODE_HOST_AGENT_NODE_NAME", nodeName)

	// Shared journald inputs for the journal-unreadable blindness
	// detector (workerhygiene + controllerhygiene): the storage dirs
	// are the "journald is installed" witness — a host with no
	// journald fails every read by config and must never latch.
	// hostPath() makes them unprefixed in standalone mode.
	journalDirs := envList("NODE_HOST_AGENT_JOURNAL_DIRS")
	if journalDirs == nil {
		journalDirs = []string{
			hostPath("/var/log/journal"), hostPath("/run/log/journal")}
	}
	journalUnreadableNeeded := envInt(
		"NODE_HOST_AGENT_JOURNAL_UNREADABLE_NEEDED", 5)

	// Shared vars/textfile dirs — hoisted out of the hostconfig
	// block: workerhygiene (systemd_watchdog_hosts), kinedb
	// (Detect), hubsync (VarsDir) and hostconfig itself all read the
	// same vars dir, and the textfile dir feeds both the standalone
	// prom writer and kinedb's prom files.
	varsDir := getenv("NODE_HOST_AGENT_HOSTCONFIG_VARS_DIR", "/config/vars")
	textfileDir := getenv("NODE_HOST_AGENT_TEXTFILE_DIR",
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

	w := &wiring{
		reg:        reg,
		csOnce:     csOnce,
		wdCfg:      wdCfg,
		wdReloader: wdReloader,
		sdClient:   sdClient,
		hostRoot:   hostRoot,
		hostPath:   hostPath,
		standalone: standalone,
		defKube:    defKube,

		watchdogStateDir:        watchdogStateDir,
		watchdogLogFile:         watchdogLogFile,
		hnode:                   hnode,
		journalDirs:             journalDirs,
		journalUnreadableNeeded: journalUnreadableNeeded,
		varsDir:                 varsDir,
		textfileDir:             textfileDir,
		podName:                 podName,
	}

	// One wire* call per subsystem, in the same order the sequential
	// blocks ran — w.subsystems startup order is unchanged.
	w.wireSweeper()
	w.wireConcourseCache()
	apiproberEnabled := w.wireApiprober()
	w.wireHostmetrics()
	w.wireWorkerHygiene()
	w.wireNethealth()
	w.wireJanitor()
	w.wireNodereporter()
	w.wireControllerHygiene()
	w.wireHostconfig()
	w.wireHubsync()
	w.wireKinedb()

	return agent.Config{
		NodeName:    nodeName,
		PodName:     podName,
		Namespace:   namespace,
		Version:     version,
		MetricsAddr: metricsAddr,
		ProbeAddr:   probeAddr,
		Registry:    reg,
		Subsystems:  w.subsystems,
	}, apiproberEnabled
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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Precedence: NODE_HOST_AGENT_NODE_NAME > NODE_NAME > --node-name.
	// Standalone units pass --node-name (no downward API on the host).
	nodeName := getenv("NODE_HOST_AGENT_NODE_NAME",
		getenv("NODE_NAME", nodeNameFlag))
	podName := getenv("POD_NAME", "")
	namespace := getenv("POD_NAMESPACE", "")

	cfg, apiproberEnabled := buildAgentConfig(nodeName, podName,
		namespace, version, metricsAddr, probeAddr, standaloneFlag)
	a := agent.New(cfg)

	// The enabled set is an operator's first question when a check
	// misbehaves — list every subsystem that actually wired up
	// (env/auto gates resolved, setup errors already logged above).
	subsystems := make([]string, 0, len(cfg.Subsystems))
	for _, s := range cfg.Subsystems {
		subsystems = append(subsystems, s.Name())
	}
	logger().Info("starting node-host-agent",
		"version", version, "node", a.NodeName(), "pod", podName,
		"standalone", standaloneFlag, "metricsAddr", metricsAddr,
		"probeAddr", probeAddr, "subsystems", subsystems,
		"apiprober", apiproberEnabled)
	if err := a.Run(ctx); err != nil {
		logger().Error("agent exited", "error", err)
		os.Exit(1)
	}
}
