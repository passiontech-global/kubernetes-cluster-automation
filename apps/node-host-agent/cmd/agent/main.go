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
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/apiprober"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/controllerhygiene"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/hostconfig"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/hostmetrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/hubsync"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/kinedb"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/nethealth"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/nodereporter"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/sweeper"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/systemd"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/topology"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/watchdogconf"
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
	var subsystems []agent.Subsystem

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
		slog.Error("watchdog conf parse failed — running on defaults",
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
	var csErr error
	csOnce := func() (kubernetes.Interface, error) {
		if cs == nil && csErr == nil {
			cs, csErr = kubeClient()
		}
		return cs, csErr
	}

	// --- sweeper: openebs orphan pvc-* dir cleanup ---
	if envBool("NODE_HOST_AGENT_ENABLE_SWEEPER", defKube) {
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

	// --- concourse-cache: native shared-cache pruner ---
	// Pure host-fs work — no kube client — but it only makes sense on
	// nodes running concourse workers, so standalone hosts default it
	// off. Replaces the old CronJob + pods/exec path.
	if envBool("NODE_HOST_AGENT_ENABLE_CONCOURSE_CACHE", defKube) {
		pr, err := sweeper.NewConcourseCachePruner(sweeper.ConcourseCacheConfig{}, reg)
		if err != nil {
			slog.Error("concourse-cache pruner setup failed", "error", err)
		} else {
			cacheRoot := getenv("NODE_HOST_AGENT_SWEEP_BASE_DIR", "/var/openebs/local")
			subsystems = append(subsystems, periodic{
				name:     "concourse-cache",
				interval: envDuration("NODE_HOST_AGENT_CONCOURSE_CACHE_INTERVAL", sweeper.DefaultConcourseCacheInterval),
				fn: func(ctx context.Context) {
					if err := pr.Sweep(ctx, cacheRoot); err != nil {
						slog.Error("concourse cache sweep failed", "error", err)
					}
				},
			})
		}
	}

	// --- apiprober: apiserver watch-cache wedge guard ---
	// "auto" (default) = enabled; a missing socket is NOT a startup
	// gate — the prober self-gates each cycle (cycles{no_socket},
	// logged once per state-change) so it stays quiet on
	// controllers and still comes alive when api-local-lb is
	// installed after this pod started. "false" disables explicitly.
	// /etc/api-backend-guard.conf is rendered by hostconfig on
	// api-lb VMs — the fallback layer below the env vars for the
	// socket/backend/backends/mode/token/ca knobs (env → guard.conf
	// → compiled default). Absent elsewhere — zero value.
	guardConfPath := getenv("NODE_HOST_AGENT_API_GUARD_CONF",
		"/etc/api-backend-guard.conf")
	guardConf, gerr := apiprober.LoadGuardConf(guardConfPath)
	if gerr != nil {
		slog.Error("api-backend-guard.conf parse failed — running on defaults",
			"path", guardConfPath, "error", gerr)
		guardConf = apiprober.GuardDefaults{}
	}
	apiproberEnabled := getenv("NODE_HOST_AGENT_ENABLE_APIPROBER", "auto") != "false"
	if apiproberEnabled {
		pi := resolveProberInputs(wdCfg, guardConf)
		pb, err := apiprober.New(apiprober.Config{
			SocketPath:        pi.socket,
			BackendName:       pi.backend,
			CompanionBackends: pi.companions,
			StaticBackends:    pi.static,
			Interval:          envDuration("NODE_HOST_AGENT_APIPROBER_INTERVAL", 30*time.Second),
			Mode:              pi.mode,
			GapMin:            envInt64("NODE_HOST_AGENT_APIPROBER_GAP_MIN", 10000),
			FailCycles:        envInt("NODE_HOST_AGENT_APIPROBER_FAIL_CYCLES", 2),
			FrozenCycles:      envInt("NODE_HOST_AGENT_APIPROBER_FROZEN_CYCLES", 2),
			RecoverCycles:     envInt("NODE_HOST_AGENT_APIPROBER_RECOVER_CYCLES", 3),
			TokenFile:         pi.tokenFile,
			CAFile:            pi.caFile,
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
			WatchdogStateDir: watchdogStateDir,
			WatchdogSrc:      wdReloader,
		}, reg)
		if err != nil {
			slog.Error("apiprober setup failed", "error", err)
		} else {
			subsystems = append(subsystems, pb)
		}
	}

	// --- hostmetrics: scrape-time collector ---
	if envBool("NODE_HOST_AGENT_ENABLE_HOSTMETRICS", true) {
		hm := hostmetrics.New(hostmetrics.Config{
			NodeName:         hnode,
			WatchdogStateDir: watchdogStateDir,
			SysClassNet:      getenv("NODE_HOST_AGENT_SYS_CLASS_NET", "/sys/class/net"),
			NebulaIface:      getenv("NODE_HOST_AGENT_NEBULA_IFACE", "neb1"),
			RouteFile:        getenv("NODE_HOST_AGENT_HOST_ROUTE_FILE", "/proc/1/net/route"),
			K0sConfigFile:    getenv("NODE_HOST_AGENT_K0S_CONFIG", "/etc/k0s/k0s.yaml"),
			K0sUnitFile:      getenv("NODE_HOST_AGENT_K0S_UNIT", hostPath("/etc/systemd/system/k0scontroller.service")),
			NebulaCertFile:   getenv("NODE_HOST_AGENT_NEBULA_CERT", hostPath("/etc/nebula/"+wdCfg.NebulaNet+"/host.crt")),
			ExpectedKCMArgs:  envList("NODE_HOST_AGENT_K0S_EXPECTED_KCM_ARGS"), // empty = defaults
			PSIFile:          getenv("NODE_HOST_AGENT_PSI_FILE", "/proc/pressure/cpu"),
			EgressRelays:     wdCfg.OverlayEgressRelays,
			FilesystemTargets: func() []string {
				if l := envList("NODE_HOST_AGENT_FILESYSTEM_TARGETS"); l != nil {
					return l
				}
				return []string{hostPath("/etc"), hostPath("/var/lib/k0s"), "/var/openebs/local"}
			}(),
			CPUDeliveredInterval: envDuration(
				"NODE_HOST_AGENT_CPU_DELIVERED_INTERVAL", 2*time.Minute),
		})
		reg.MustRegister(hm)
		// Standalone hosts have no Prometheus scrape — the legacy
		// prom_emit contract is kept by rendering the same series
		// into the node-exporter textfile dir on a ticker.
		if standalone {
			subsystems = append(subsystems, periodic{
				name: "hostmetrics-textfile",
				interval: envDuration("NODE_HOST_AGENT_TEXTFILE_INTERVAL",
					30*time.Second),
				fn: func(ctx context.Context) {
					if err := hm.WriteTextfile(textfileDir); err != nil {
						slog.Error("hostmetrics textfile write failed",
							"dir", textfileDir, "error", err)
					}
				},
			})
		}
	}

	// --- workerhygiene: worker-only watchdog checks ---
	// Needs a node name (pods are filtered by spec.nodeName) and a
	// kube client; either missing skips the subsystem — never aborts
	// the agent.
	if envBool("NODE_HOST_AGENT_ENABLE_HYGIENE", defKube) {
		// DaemonSet sets NODE_HOST_AGENT_NODE_NAME and NODE_NAME via
		// the downward API — prefer the explicit override env.
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
					NodeName:          hnode,
					Enabled:           true,
					Interval:          envDuration("NODE_HOST_AGENT_HYGIENE_INTERVAL", 2*time.Minute),
					WatchdogStateDir:  watchdogStateDir,
					WatchdogLogFile:   watchdogLogFile,
					ProcRoot:          getenv("NODE_HOST_AGENT_PROC_ROOT", "/proc"),
					CtrTaskRoot:       getenv("NODE_HOST_AGENT_CTR_TASK_ROOT", hostPath("/run/k0s/containerd/io.containerd.runtime.v2.task/k8s.io")),
					SandboxCtlRoot:    getenv("NODE_HOST_AGENT_SANDBOX_CTL_ROOT", hostPath("/run/k0s/containerd/io.containerd.sandbox.controller.v1.shim")),
					HostResolvConf:    getenv("NODE_HOST_AGENT_HOST_RESOLV_CONF", hostPath("/etc/resolv.conf")),
					K0sWorkerUnitFile: getenv("NODE_HOST_AGENT_K0S_WORKER_UNIT", hostPath("/etc/systemd/system/k0sworker.service")),
					KubeletPodsDir:    getenv("NODE_HOST_AGENT_KUBELET_PODS_DIR", hostPath("/var/lib/k0s/kubelet/pods")),
					CiliumSocket:      getenv("NODE_HOST_AGENT_CILIUM_SOCKET", hostPath("/run/cilium/cilium.sock")),
					Systemd:           sdClient,
					Watchdog:          wdCfg,
					WatchdogSrc:       wdReloader,
					APIBackends:       wdCfg.APIBackendIPs(),
					// T15 opt-in host list: env override →
					// systemd_watchdog_hosts out of the vars dir
					// (cluster.yaml). Absent vars dir is not an error —
					// the feeder self-gates on k0sworker.service anyway.
					KubeletWatchdogHosts:    kubeletWatchdogHosts(varsDir, hnode),
					StuckDeleteAge:          envDuration("NODE_HOST_AGENT_HYGIENE_STUCK_DELETE_AGE", 15*time.Minute),
					StuckWedgeAge:           envDuration("NODE_HOST_AGENT_HYGIENE_STUCK_WEDGE_AGE", 30*time.Minute),
					MaxForceDelete:          envInt("NODE_HOST_AGENT_HYGIENE_MAX_FORCE_DELETE", 5),
					ConsecNeeded:            envInt("NODE_HOST_AGENT_HYGIENE_CONSEC_NEEDED", 2),
					MinRestartInterval:      envDuration("NODE_HOST_AGENT_HYGIENE_MIN_RESTART_INTERVAL", 30*time.Minute),
					JournalDirs:             journalDirs,
					JournalUnreadableNeeded: journalUnreadableNeeded,
					Client:                  cs,
				}, reg)
				if err != nil {
					slog.Error("workerhygiene setup failed", "error", err)
				} else {
					subsystems = append(subsystems, wh)
				}
			}
		}
	}

	// --- nethealth: DNS/overlay/nebula/fail2ban watchdog modules ---
	// Runs on workers AND hub nodes; no kube client needed.
	if envBool("NODE_HOST_AGENT_ENABLE_NETHEALTH", true) {
		nh, err := nethealth.New(nethealth.Config{
			Enabled:          true,
			Interval:         envDuration("NODE_HOST_AGENT_NETHEALTH_INTERVAL", 2*time.Minute),
			WatchdogStateDir: watchdogStateDir,
			WatchdogLogFile:  watchdogLogFile,
			HostResolvConf:   getenv("NODE_HOST_AGENT_HOST_RESOLV_CONF", hostPath("/etc/resolv.conf")),
			HostsFile:        getenv("NODE_HOST_AGENT_HOSTS_FILE", hostPath("/etc/hosts")),
			ProcNetUDP:       getenv("NODE_HOST_AGENT_PROC_NET_UDP", "/proc/1/net/udp"),
			ProcNetUDP6:      getenv("NODE_HOST_AGENT_PROC_NET_UDP6", "/proc/1/net/udp6"),
			UptimeFile:       getenv("NODE_HOST_AGENT_UPTIME_FILE", "/proc/uptime"),
			HostRoot:         hostRoot,
			Watchdog:         wdCfg,
			WatchdogSrc:      wdReloader,
			Systemd:          sdClient,
			ConsecNeeded:     envInt("NODE_HOST_AGENT_NETHEALTH_CONSEC_NEEDED", 2),
			MinRestart:       envDuration("NODE_HOST_AGENT_NETHEALTH_MIN_RESTART", 30*time.Minute),
		}, reg)
		if err != nil {
			slog.Error("nethealth setup failed", "error", err)
		} else {
			subsystems = append(subsystems, nh)
		}
	}

	// --- janitor: watchdog-state latch reaper + retired-unit sweep ---
	// Pure host-fs/systemd work — runs on every node class (workers,
	// controllers, standalone hubs): the shared state dir accumulates
	// latches from every subsystem and ghost unit records outlive the
	// pruned unit files. No kube client needed.
	if envBool("NODE_HOST_AGENT_ENABLE_JANITOR", true) {
		jn, err := workerhygiene.NewJanitor(workerhygiene.JanitorConfig{
			Enabled:          true,
			Interval:         envDuration("NODE_HOST_AGENT_JANITOR_INTERVAL", 10*time.Minute),
			WatchdogStateDir: watchdogStateDir,
			WatchdogLogFile:  watchdogLogFile,
			ProcRoot:         getenv("NODE_HOST_AGENT_PROC_ROOT", "/proc"),
			LatchMaxAge:      envDuration("NODE_HOST_AGENT_JANITOR_LATCH_MAX_AGE", 24*time.Hour),
			Systemd:          sdClient,
		}, reg)
		if err != nil {
			slog.Error("janitor setup failed", "error", err)
		} else {
			subsystems = append(subsystems, jn)
		}
	}

	// --- nodereporter: state latches → NodeConditions/Events ---
	// Replaces the NPD watchdog-state/filelog monitors; needs the
	// kube client and a node name.
	if envBool("NODE_HOST_AGENT_ENABLE_REPORTER", defKube) {
		switch {
		case hnode == "":
			slog.Error("nodereporter disabled: node name empty " +
				"(NODE_HOST_AGENT_NODE_NAME/NODE_NAME unset)")
		default:
			cs, err := csOnce()
			if err != nil {
				slog.Error("nodereporter disabled: cannot build kubernetes client",
					"error", err)
			} else {
				nr, err := nodereporter.New(nodereporter.Config{
					NodeName:         hnode,
					Client:           cs,
					WatchdogStateDir: watchdogStateDir,
					WatchdogLogFile:  watchdogLogFile,
					Interval:         envDuration("NODE_HOST_AGENT_REPORTER_INTERVAL", 30*time.Second),
					EventNamespace:   getenv("NODE_HOST_AGENT_EVENT_NAMESPACE", "default"),
				}, reg)
				if err != nil {
					slog.Error("nodereporter setup failed", "error", err)
				} else {
					subsystems = append(subsystems, nr)
				}
			}
		}
	}

	// --- controllerhygiene: control-plane guards ---
	// "auto" (default): enabled iff this host runs k0scontroller —
	// workers and bare API LB VMs self-disable.
	chMode := getenv("NODE_HOST_AGENT_ENABLE_CONTROLLERHYGIENE", "auto")
	if chMode == "true" || (chMode == "auto" && controllerhygiene.ShouldRun(hostRoot)) {
		ch, err := controllerhygiene.New(controllerhygiene.Config{
			Enabled:               true,
			Interval:              envDuration("NODE_HOST_AGENT_CONTROLLER_INTERVAL", time.Minute),
			WatchdogStateDir:      watchdogStateDir,
			WatchdogLogFile:       watchdogLogFile,
			ProcRoot:              getenv("NODE_HOST_AGENT_PROC_ROOT", "/proc"),
			K0sControllerUnitFile: hostPath("/etc/systemd/system/k0scontroller.service"),
			// env → wdCfg → package defaults; SelfAPI stays EMPTY
			// when neither is set (the solo/dead-fallback fences gate
			// on non-empty — a made-up identity would crown every
			// unconfigured controller first-hub).
			SelfAPI:     envOr("NODE_HOST_AGENT_API_SELF", wdCfg.APISelf),
			PeerAPI:     envOr("NODE_HOST_AGENT_API_PEER", wdCfg.APIPeer),
			KineDBProbe: envOr("NODE_HOST_AGENT_KINE_DB_PROBE", wdCfg.KineDBProbe),
			Sig13Mode:   envOr("NODE_HOST_AGENT_SIG13_AUTOFIX", wdCfg.Sig13Autofix),
			StaleMinErrs: envIntOr("NODE_HOST_AGENT_STALE_MIN_ERRS",
				wdCfg.Sig13StaleMinErrs, 15),
			GapMin: envInt64Or("NODE_HOST_AGENT_GAP_MIN",
				wdCfg.Sig13GapMin, 10000),
			GapCycles: envIntOr("NODE_HOST_AGENT_GAP_CYCLES",
				wdCfg.Sig13GapCycles, 2),
			FrozenCycles: envIntOr("NODE_HOST_AGENT_FROZEN_CYCLES",
				wdCfg.Sig13FrozenCycles, 2),
			SoloCycles: envIntOr("NODE_HOST_AGENT_SOLO_CYCLES",
				wdCfg.Sig13SoloCycles, 8),
			MinRestartInterval: envDurOr("NODE_HOST_AGENT_SIG13_MIN_RESTART_S",
				wdCfg.Sig13MinRestartS, 2*time.Hour),
			KineTTLMode: envOr("NODE_HOST_AGENT_KINE_TTL_AUTOFIX", wdCfg.KineTTLAutofix),
			KineTTLMinRestart: envDurOr("NODE_HOST_AGENT_KINE_TTL_MIN_RESTART_S",
				wdCfg.KineTTLMinRestartS, 30*time.Minute),
			KineTTLCtlRestart: envDurOr("NODE_HOST_AGENT_KINE_TTL_CTL_RESTART_S",
				wdCfg.KineTTLCtlRestartS, 2*time.Hour),
			KineTTLRewedgeCycles: envIntOr("NODE_HOST_AGENT_KINE_TTL_REWEDGE_CYCLES",
				wdCfg.KineTTLRewedgeCycle, 2),
			KinePoolMode: envOr("NODE_HOST_AGENT_KINE_POOL_AUTOFIX", wdCfg.KinePoolAutofix),
			KinePoolMaxConns: envIntOr("NODE_HOST_AGENT_KINE_POOL_MAX_CONNS",
				wdCfg.KinePoolMaxConns, 72),
			KinePoolCycles: envIntOr("NODE_HOST_AGENT_KINE_POOL_CYCLES",
				wdCfg.KinePoolCycles, 3),
			KinePoolMinRestart: envDurOr("NODE_HOST_AGENT_KINE_POOL_MIN_RESTART_S",
				wdCfg.KinePoolMinRestartS, 20*time.Minute),
			OOMLoopMode: envOr("NODE_HOST_AGENT_OOMLOOP_AUTOFIX", wdCfg.OOMLoopAutofix),
			OOMLoopMinKills: envIntOr("NODE_HOST_AGENT_OOMLOOP_MIN_KILLS",
				wdCfg.OOMLoopMinKills, 3),
			OOMLoopWindow: envDurOr("NODE_HOST_AGENT_OOMLOOP_WINDOW_S",
				wdCfg.OOMLoopWindowS, time.Hour),
			AdminKubeconfig:         hostPath("/var/lib/k0s/pki/admin.conf"),
			AdminCert:               hostPath("/var/lib/k0s/pki/admin.crt"),
			AdminKey:                hostPath("/var/lib/k0s/pki/admin.key"),
			AdminCA:                 hostPath("/var/lib/k0s/pki/ca.crt"),
			InsecureTLS:             envBool("NODE_HOST_AGENT_CONTROLLER_INSECURE_TLS", true),
			CGroupEventsFile:        hostPath("/sys/fs/cgroup/system.slice/k0scontroller.service/memory.events"),
			FeederEnabled:           envBool("NODE_HOST_AGENT_ENABLE_FEEDER", true),
			NotifySocket:            os.Getenv("NOTIFY_SOCKET"),
			FeederStateDir:          hostPath("/var/lib/k0s-systemd-watchdog"),
			RemediatePeerFile:       hostPath("/etc/default/k0scontroller-watchdog"),
			K0sDir:                  getenv("NODE_HOST_AGENT_K0S_DIR", hostPath("/var/lib/k0s")),
			EtcdEndpoint:            getenv("NODE_HOST_AGENT_ETCD_ENDPOINT", "https://127.0.0.1:2379"),
			EtcdDBSizeLimit:         envInt64("NODE_HOST_AGENT_ETCD_DB_SIZE_LIMIT", 0),
			JournalDirs:             journalDirs,
			JournalUnreadableNeeded: journalUnreadableNeeded,
		}, reg)
		if err != nil {
			slog.Error("controllerhygiene setup failed", "error", err)
		} else {
			subsystems = append(subsystems, ch)
		}
	}

	// --- hostconfig: declarative host converger ---
	// "auto" (default): enabled iff the vars dir actually carries
	// defaults.yaml — pods without the node-config-vars mount and
	// standalone hosts without config self-disable.
	hcMode := getenv("NODE_HOST_AGENT_ENABLE_HOSTCONFIG", "auto")
	_, varsErr := os.Stat(varsDir + "/defaults.yaml")
	if hcMode == "true" || (hcMode == "auto" && varsErr == nil) {
		hostname, _ := os.Hostname()
		var runner hostconfig.Runner = hostconfig.NsenterRunner{}
		if hostRoot == "/" {
			runner = hostconfig.DirectRunner{}
		}
		hc, err := hostconfig.New(hostconfig.Config{
			Enabled:            true,
			NodeName:           hnode,
			Hostname:           hostname,
			HostRoot:           hostRoot,
			VarsDir:            varsDir,
			NebulaCertsDir:     getenv("NODE_HOST_AGENT_NEBULA_CERTS_DIR", "/config/nebula-certs"),
			WatchdogScriptsDir: getenv("NODE_HOST_AGENT_WATCHDOG_SCRIPTS_DIR", "/config/watchdog"),
			Interval:           envDuration("NODE_HOST_AGENT_HOSTCONFIG_INTERVAL", 30*time.Minute),
			Runner:             runner,
			// Vars/cert changes converge on the next poll instead of
			// waiting out the full interval.
			Watcher: &hostconfig.DirWatcher{Dirs: []string{
				varsDir,
				getenv("NODE_HOST_AGENT_NEBULA_CERTS_DIR", "/config/nebula-certs"),
			}},
		}, reg)
		if err != nil {
			slog.Error("hostconfig setup failed", "error", err)
		} else {
			subsystems = append(subsystems, hc)
		}
	}

	// --- hubsync: SSH converge of standalone targets ---
	// Pod-mode only (it IS the converge fleet's client side — a
	// standalone target never converges other targets). The Syncer is
	// wired unconditionally: the DS mounts the converge secret
	// optional:true so the key may land after pod start — Enabled()
	// is the startup fast-path log only, and the Syncer re-checks the
	// key on every trigger until it materializes.
	convergeKey := getenv("NODE_HOST_AGENT_CONVERGE_SSH_KEY",
		"/etc/node-converge-ssh/id_ed25519")
	if !standalone {
		switch {
		case podName == "":
			slog.Error("hubsync disabled: pod name empty (POD_NAME unset)")
		default:
			cs, err := csOnce()
			if err != nil {
				slog.Error("hubsync disabled: cannot build kubernetes client",
					"error", err)
			} else {
				if !hubsync.Enabled(convergeKey) {
					slog.Info("hubsync: converge key not mounted yet — polling until it appears",
						"path", convergeKey)
				}
				hs, err := hubsync.New(hubsync.Config{
					Client:         cs,
					Identity:       podName,
					VarsDir:        varsDir,
					NebulaCertsDir: getenv("NODE_HOST_AGENT_NEBULA_CERTS_DIR", "/config/nebula-certs"),
					SSHKeyPath:     convergeKey,
					LocalBinary:    resolveLocalBinary(),
				}, reg)
				if err != nil {
					slog.Error("hubsync setup failed", "error", err)
				} else {
					subsystems = append(subsystems, hs)
				}
			}
		}
	}

	// --- kinedb: kine DB VM probe/compact-guard/maintenance ---
	// "auto" (default): Detect() — the postgres .env exists under
	// hostRoot or a kine_db:true extra-host entry names this host.
	kinedbMode := getenv("NODE_HOST_AGENT_ENABLE_KINEDB", "auto")
	if kinedbMode == "true" ||
		(kinedbMode == "auto" && kinedb.Detect(hostRoot, varsDir)) {
		kd, err := kinedb.New(kinedb.Config{
			Enabled:     true,
			EnvFile:     getenv("NODE_HOST_AGENT_KINEDB_ENV_FILE", hostPath("/opt/apps/postgres/.env")),
			TextfileDir: textfileDir,
			GuardStateDir: getenv("NODE_HOST_AGENT_KINEDB_GUARD_STATE_DIR",
				hostPath("/var/lib/kine-compact-guard")),
		}, reg)
		if err != nil {
			slog.Error("kinedb setup failed", "error", err)
		} else {
			subsystems = append(subsystems, kd)
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
	nodeName := getenv("NODE_NAME", nodeNameFlag)
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
	slog.Info("starting node-host-agent",
		"version", version, "node", a.NodeName(), "pod", podName,
		"standalone", standaloneFlag, "metricsAddr", metricsAddr,
		"probeAddr", probeAddr, "subsystems", subsystems,
		"apiprober", apiproberEnabled)
	if err := a.Run(ctx); err != nil {
		slog.Error("agent exited", "error", err)
		os.Exit(1)
	}
}
