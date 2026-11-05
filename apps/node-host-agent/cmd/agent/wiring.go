// wiring.go — the per-subsystem blocks of buildAgentConfig, one
// wire* method each, run in the same order the sequential code used
// to. Every method reads the shared inputs off *wiring (computed once
// in buildAgentConfig) and appends to w.subsystems — the startup
// order of that slice is unchanged.
package main

import (
	"context"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/agent"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/subsystem/apiprober"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/subsystem/controllerhygiene"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/subsystem/hostconfig"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/subsystem/hostmetrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/subsystem/hubsync"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/subsystem/kinedb"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/subsystem/nethealth"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/subsystem/nodereporter"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/subsystem/sweeper"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/subsystem/workerhygiene"
)

// wiring carries the shared inputs buildAgentConfig computes once —
// the registry the subsystems register on, the lazy shared kube
// clientset, the watchdog conf + its per-cycle reloader, the systemd
// client, and every resolved host path/dir/env-derived knob — so each
// wire* method reads them instead of re-deriving.
type wiring struct {
	reg        *prometheus.Registry
	subsystems []agent.Subsystem

	csOnce     func() (kubernetes.Interface, error)
	wdCfg      *watchdogconf.Config
	wdReloader *watchdogconf.Reloader
	sdClient   *systemd.Client

	hostRoot string
	hostPath func(string) string

	standalone bool
	defKube    bool

	watchdogStateDir        string
	watchdogLogFile         string
	hnode                   string
	journalDirs             []string
	journalUnreadableNeeded int
	varsDir                 string
	textfileDir             string
	podName                 string
}

// --- sweeper: openebs orphan pvc-* dir cleanup ---
func (w *wiring) wireSweeper() {
	if envBool("NODE_HOST_AGENT_ENABLE_SWEEPER", w.defKube) {
		cs, err := w.csOnce()
		if err != nil {
			// Not fatal: the metrics/probe endpoints and other
			// subsystems still serve; the sweeper simply does not run.
			logger().Error("sweeper disabled: cannot build kubernetes client", "error", err)
		} else {
			sw, err := sweeper.New(sweeper.Config{
				BaseDir:        getenv("NODE_HOST_AGENT_SWEEP_BASE_DIR", "/var/openebs/local"),
				MinAge:         envDuration("NODE_HOST_AGENT_SWEEP_MIN_AGE", time.Hour),
				MaxDelete:      envInt("NODE_HOST_AGENT_SWEEP_MAX_DELETE", 10),
				Interval:       envDuration("NODE_HOST_AGENT_SWEEP_INTERVAL", time.Hour),
				MountsFile:     getenv("NODE_HOST_AGENT_MOUNTS_FILE", "/proc/1/mounts"),
				RequestTimeout: envDuration("NODE_HOST_AGENT_REQUEST_TIMEOUT", 30*time.Second),
				Client:         cs,
			}, w.reg)
			if err != nil {
				logger().Error("sweeper setup failed", "error", err)
			} else {
				w.subsystems = append(w.subsystems, sw)
			}
		}
	}
}

// --- concourse-cache: native shared-cache pruner ---
// Pure host-fs work — no kube client — but it only makes sense on
// nodes running concourse workers, so standalone hosts default it
// off. Replaces the old CronJob + pods/exec path.
func (w *wiring) wireConcourseCache() {
	if envBool("NODE_HOST_AGENT_ENABLE_CONCOURSE_CACHE", w.defKube) {
		pr, err := sweeper.NewConcourseCachePruner(sweeper.ConcourseCacheConfig{}, w.reg)
		if err != nil {
			logger().Error("concourse-cache pruner setup failed", "error", err)
		} else {
			cacheRoot := getenv("NODE_HOST_AGENT_SWEEP_BASE_DIR", "/var/openebs/local")
			w.subsystems = append(w.subsystems, periodic{
				name:     "concourse-cache",
				interval: envDuration("NODE_HOST_AGENT_CONCOURSE_CACHE_INTERVAL", sweeper.DefaultConcourseCacheInterval),
				fn: func(ctx context.Context) {
					if err := pr.Sweep(ctx, cacheRoot); err != nil {
						logger().Error("concourse cache sweep failed", "error", err)
					}
				},
			})
		}
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
//
// Returns the enabled flag for the startup log line.
func (w *wiring) wireApiprober() bool {
	guardConfPath := getenv("NODE_HOST_AGENT_API_GUARD_CONF",
		"/etc/api-backend-guard.conf")
	guardConf, gerr := apiprober.LoadGuardConf(guardConfPath)
	if gerr != nil {
		logger().Error("api-backend-guard.conf parse failed — running on defaults",
			"path", guardConfPath, "error", gerr)
		guardConf = apiprober.GuardDefaults{}
	}
	apiproberEnabled := getenv("NODE_HOST_AGENT_ENABLE_APIPROBER", "auto") != "false"
	if apiproberEnabled {
		pi := resolveProberInputs(w.wdCfg, guardConf)
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
			WatchdogStateDir: w.watchdogStateDir,
			WatchdogSrc:      w.wdReloader,
		}, w.reg)
		if err != nil {
			logger().Error("apiprober setup failed", "error", err)
		} else {
			w.subsystems = append(w.subsystems, pb)
		}
	}
	return apiproberEnabled
}

// --- hostmetrics: scrape-time collector ---
func (w *wiring) wireHostmetrics() {
	if envBool("NODE_HOST_AGENT_ENABLE_HOSTMETRICS", true) {
		hm := hostmetrics.New(hostmetrics.Config{
			NodeName:         w.hnode,
			WatchdogStateDir: w.watchdogStateDir,
			Standalone:       w.standalone,
			KeyUsersFile: getenv("NODE_HOST_AGENT_KEY_USERS_FILE",
				"/proc/key-users"),
			LatchInterval: envDuration("NODE_HOST_AGENT_LATCH_INTERVAL",
				30*time.Second),
			SysClassNet:     getenv("NODE_HOST_AGENT_SYS_CLASS_NET", "/sys/class/net"),
			NebulaIface:     getenv("NODE_HOST_AGENT_NEBULA_IFACE", "neb1"),
			RouteFile:       getenv("NODE_HOST_AGENT_HOST_ROUTE_FILE", "/proc/1/net/route"),
			K0sConfigFile:   getenv("NODE_HOST_AGENT_K0S_CONFIG", "/etc/k0s/k0s.yaml"),
			K0sUnitFile:     getenv("NODE_HOST_AGENT_K0S_UNIT", w.hostPath("/etc/systemd/system/k0scontroller.service")),
			NebulaCertFile:  getenv("NODE_HOST_AGENT_NEBULA_CERT", w.hostPath("/etc/nebula/"+w.wdCfg.NebulaNet+"/host.crt")),
			ExpectedKCMArgs: envList("NODE_HOST_AGENT_K0S_EXPECTED_KCM_ARGS"), // empty = defaults
			PSIFile:         getenv("NODE_HOST_AGENT_PSI_FILE", "/proc/pressure/cpu"),
			EgressRelays:    w.wdCfg.OverlayEgressRelays,
			FilesystemTargets: func() []string {
				if l := envList("NODE_HOST_AGENT_FILESYSTEM_TARGETS"); l != nil {
					return l
				}
				return []string{w.hostPath("/etc"), w.hostPath("/var/lib/k0s"), "/var/openebs/local"}
			}(),
			CPUDeliveredInterval: envDuration(
				"NODE_HOST_AGENT_CPU_DELIVERED_INTERVAL", 2*time.Minute),
			// W7-H5/H6 telemetry files.
			ConntrackStatFile: getenv("NODE_HOST_AGENT_CONNTRACK_STAT_FILE",
				"/proc/net/stat/nf_conntrack"),
			ARPTableFile: getenv("NODE_HOST_AGENT_ARP_TABLE_FILE",
				"/proc/net/arp"),
			CgroupMemUnits: envList("NODE_HOST_AGENT_CGROUP_MEM_UNITS"),
		})
		w.reg.MustRegister(hm)
		// BUG-H5: the latch-maintenance ticker runs in BOTH modes —
		// on the DaemonSet Prometheus may not scrape for long
		// stretches, so latches can't ride Collect() alone.
		w.subsystems = append(w.subsystems, hm)
		// Standalone hosts have no Prometheus scrape — the legacy
		// prom_emit contract is kept by rendering the same series
		// into the node-exporter textfile dir on a ticker.
		if w.standalone {
			w.subsystems = append(w.subsystems, periodic{
				name: "hostmetrics-textfile",
				interval: envDuration("NODE_HOST_AGENT_TEXTFILE_INTERVAL",
					30*time.Second),
				fn: func(ctx context.Context) {
					if err := hm.WriteTextfile(w.textfileDir); err != nil {
						logger().Error("hostmetrics textfile write failed",
							"dir", w.textfileDir, "error", err)
					}
				},
			})
		}
	}
}

// --- workerhygiene: worker-only watchdog checks ---
// Needs a node name (pods are filtered by spec.nodeName) and a
// kube client; either missing skips the subsystem — never aborts
// the agent.
func (w *wiring) wireWorkerHygiene() {
	if envBool("NODE_HOST_AGENT_ENABLE_HYGIENE", w.defKube) {
		// DaemonSet sets NODE_HOST_AGENT_NODE_NAME and NODE_NAME via
		// the downward API — prefer the explicit override env.
		switch {
		case w.hnode == "":
			logger().Error("workerhygiene disabled: node name empty " +
				"(NODE_HOST_AGENT_NODE_NAME/NODE_NAME unset)")
		default:
			cs, err := w.csOnce()
			if err != nil {
				logger().Error("workerhygiene disabled: cannot build kubernetes client",
					"error", err)
			} else {
				wh, err := workerhygiene.New(workerhygiene.Config{
					NodeName:          w.hnode,
					Enabled:           true,
					Interval:          envDuration("NODE_HOST_AGENT_HYGIENE_INTERVAL", 2*time.Minute),
					WatchdogStateDir:  w.watchdogStateDir,
					WatchdogLogFile:   w.watchdogLogFile,
					ProcRoot:          getenv("NODE_HOST_AGENT_PROC_ROOT", "/proc"),
					CtrTaskRoot:       getenv("NODE_HOST_AGENT_CTR_TASK_ROOT", w.hostPath("/run/k0s/containerd/io.containerd.runtime.v2.task/k8s.io")),
					SandboxCtlRoot:    getenv("NODE_HOST_AGENT_SANDBOX_CTL_ROOT", w.hostPath("/run/k0s/containerd/io.containerd.sandbox.controller.v1.shim")),
					HostResolvConf:    getenv("NODE_HOST_AGENT_HOST_RESOLV_CONF", w.hostPath("/etc/resolv.conf")),
					K0sWorkerUnitFile: getenv("NODE_HOST_AGENT_K0S_WORKER_UNIT", w.hostPath("/etc/systemd/system/k0sworker.service")),
					KubeletPodsDir:    getenv("NODE_HOST_AGENT_KUBELET_PODS_DIR", w.hostPath("/var/lib/k0s/kubelet/pods")),
					CiliumSocket:      getenv("NODE_HOST_AGENT_CILIUM_SOCKET", w.hostPath("/run/cilium/cilium.sock")),
					// A4 probes: k0s puts the containerd socket at
					// /run/k0s/containerd.sock (not inside the state
					// dir); kubelet :10250 denies anonymous healthz,
					// so the syncloop probe authenticates with the
					// pod SA token.
					ContainerdSocket:   getenv("NODE_HOST_AGENT_CONTAINERD_SOCKET", w.hostPath("/run/k0s/containerd.sock")),
					KubeletSyncloopURL: getenv("NODE_HOST_AGENT_KUBELET_SYNCLOOP_URL", ""),
					KubeletTokenPath: envOr("NODE_HOST_AGENT_KUBELET_TOKEN_FILE",
						"/var/run/secrets/kubernetes.io/serviceaccount/token"),
					Systemd:     w.sdClient,
					Watchdog:    w.wdCfg,
					WatchdogSrc: w.wdReloader,
					APIBackends: w.wdCfg.APIBackendIPs(),
					// T15 opt-in host list: env override →
					// systemd_watchdog_hosts out of the vars dir
					// (cluster.yaml). Absent vars dir is not an error —
					// the feeder self-gates on k0sworker.service anyway.
					KubeletWatchdogHosts:    kubeletWatchdogHosts(w.varsDir, w.hnode),
					StuckDeleteAge:          envDuration("NODE_HOST_AGENT_HYGIENE_STUCK_DELETE_AGE", 15*time.Minute),
					StuckWedgeAge:           envDuration("NODE_HOST_AGENT_HYGIENE_STUCK_WEDGE_AGE", 30*time.Minute),
					MaxForceDelete:          envInt("NODE_HOST_AGENT_HYGIENE_MAX_FORCE_DELETE", 5),
					ConsecNeeded:            envInt("NODE_HOST_AGENT_HYGIENE_CONSEC_NEEDED", 2),
					MinRestartInterval:      envDuration("NODE_HOST_AGENT_HYGIENE_MIN_RESTART_INTERVAL", 30*time.Minute),
					JournalDirs:             w.journalDirs,
					JournalUnreadableNeeded: w.journalUnreadableNeeded,
					// W7 knobs — empty env → in-package defaults.
					DStateStormThreshold:      envInt("NODE_HOST_AGENT_DSTATE_STORM_THRESHOLD", 5),
					CiliumEnvoyAdminURL:       getenv("NODE_HOST_AGENT_CILIUM_ENVOY_ADMIN_URL", ""),
					LocalDNSProbeAddr:         getenv("NODE_HOST_AGENT_LOCALDNS_PROBE_ADDR", ""),
					LocalDNSProbeName:         getenv("NODE_HOST_AGENT_LOCALDNS_PROBE_NAME", ""),
					CalicoFelixReadyURL:       getenv("NODE_HOST_AGENT_CALICO_FELIX_READY_URL", ""),
					CalicoOrphanVethThreshold: envInt("NODE_HOST_AGENT_CALICO_ORPHAN_VETH_THRESHOLD", 50),
					Client:                    cs,
				}, w.reg)
				if err != nil {
					logger().Error("workerhygiene setup failed", "error", err)
				} else {
					w.subsystems = append(w.subsystems, wh)
				}
			}
		}
	}
}

// --- nethealth: DNS/overlay/nebula/fail2ban watchdog modules ---
// Runs on workers AND hub nodes; no kube client needed.
func (w *wiring) wireNethealth() {
	if envBool("NODE_HOST_AGENT_ENABLE_NETHEALTH", true) {
		nh, err := nethealth.New(nethealth.Config{
			Enabled:          true,
			Interval:         envDuration("NODE_HOST_AGENT_NETHEALTH_INTERVAL", 2*time.Minute),
			WatchdogStateDir: w.watchdogStateDir,
			WatchdogLogFile:  w.watchdogLogFile,
			HostResolvConf:   getenv("NODE_HOST_AGENT_HOST_RESOLV_CONF", w.hostPath("/etc/resolv.conf")),
			HostsFile:        getenv("NODE_HOST_AGENT_HOSTS_FILE", w.hostPath("/etc/hosts")),
			ProcNetUDP:       getenv("NODE_HOST_AGENT_PROC_NET_UDP", "/proc/1/net/udp"),
			ProcNetUDP6:      getenv("NODE_HOST_AGENT_PROC_NET_UDP6", "/proc/1/net/udp6"),
			UptimeFile:       getenv("NODE_HOST_AGENT_UPTIME_FILE", "/proc/uptime"),
			HostRoot:         w.hostRoot,
			Watchdog:         w.wdCfg,
			WatchdogSrc:      w.wdReloader,
			Systemd:          w.sdClient,
			ConsecNeeded:     envInt("NODE_HOST_AGENT_NETHEALTH_CONSEC_NEEDED", 2),
			MinRestart:       envDuration("NODE_HOST_AGENT_NETHEALTH_MIN_RESTART", 30*time.Minute),
			// W8: pref-1499 direct-underlay TCP bypass; empty →
			// the package default [22 6443 8132 9443 39901].
			NebulaDirectTCPPorts: envIntList("NODE_HOST_AGENT_NEBULA_DIRECT_TCP_PORTS"),
		}, w.reg)
		if err != nil {
			logger().Error("nethealth setup failed", "error", err)
		} else {
			w.subsystems = append(w.subsystems, nh)
		}
	}
}

// --- janitor: watchdog-state latch reaper + retired-unit sweep ---
// Pure host-fs/systemd work — runs on every node class (workers,
// controllers, standalone hubs): the shared state dir accumulates
// latches from every subsystem and ghost unit records outlive the
// pruned unit files. No kube client needed.
func (w *wiring) wireJanitor() {
	if envBool("NODE_HOST_AGENT_ENABLE_JANITOR", true) {
		jn, err := workerhygiene.NewJanitor(workerhygiene.JanitorConfig{
			Enabled:          true,
			Interval:         envDuration("NODE_HOST_AGENT_JANITOR_INTERVAL", 10*time.Minute),
			WatchdogStateDir: w.watchdogStateDir,
			WatchdogLogFile:  w.watchdogLogFile,
			ProcRoot:         getenv("NODE_HOST_AGENT_PROC_ROOT", "/proc"),
			LatchMaxAge:      envDuration("NODE_HOST_AGENT_JANITOR_LATCH_MAX_AGE", 24*time.Hour),
			Systemd:          w.sdClient,
		}, w.reg)
		if err != nil {
			logger().Error("janitor setup failed", "error", err)
		} else {
			w.subsystems = append(w.subsystems, jn)
		}
	}
}

// --- nodereporter: state latches → NodeConditions/Events ---
// Replaces the NPD watchdog-state/filelog monitors; needs the
// kube client and a node name.
func (w *wiring) wireNodereporter() {
	if envBool("NODE_HOST_AGENT_ENABLE_REPORTER", w.defKube) {
		switch {
		case w.hnode == "":
			logger().Error("nodereporter disabled: node name empty " +
				"(NODE_HOST_AGENT_NODE_NAME/NODE_NAME unset)")
		default:
			cs, err := w.csOnce()
			if err != nil {
				logger().Error("nodereporter disabled: cannot build kubernetes client",
					"error", err)
			} else {
				nr, err := nodereporter.New(nodereporter.Config{
					NodeName:         w.hnode,
					Client:           cs,
					WatchdogStateDir: w.watchdogStateDir,
					WatchdogLogFile:  w.watchdogLogFile,
					Interval:         envDuration("NODE_HOST_AGENT_REPORTER_INTERVAL", 30*time.Second),
					EventNamespace:   getenv("NODE_HOST_AGENT_EVENT_NAMESPACE", "default"),
				}, w.reg)
				if err != nil {
					logger().Error("nodereporter setup failed", "error", err)
				} else {
					w.subsystems = append(w.subsystems, nr)
				}
			}
		}
	}
}

// --- controllerhygiene: control-plane guards ---
// "auto" (default): enabled iff this host runs k0scontroller —
// workers and bare API LB VMs self-disable.
func (w *wiring) wireControllerHygiene() {
	chMode := getenv("NODE_HOST_AGENT_ENABLE_CONTROLLERHYGIENE", "auto")
	if chMode == "true" || (chMode == "auto" && controllerhygiene.ShouldRun(w.hostRoot)) {
		ch, err := controllerhygiene.New(controllerhygiene.Config{
			Enabled:               true,
			Interval:              envDuration("NODE_HOST_AGENT_CONTROLLER_INTERVAL", time.Minute),
			WatchdogStateDir:      w.watchdogStateDir,
			WatchdogLogFile:       w.watchdogLogFile,
			WatchdogSrc:           w.wdReloader,
			ProcRoot:              getenv("NODE_HOST_AGENT_PROC_ROOT", "/proc"),
			K0sControllerUnitFile: w.hostPath("/etc/systemd/system/k0scontroller.service"),
			// env → wdCfg → package defaults; SelfAPI stays EMPTY
			// when neither is set (the solo/dead-fallback fences gate
			// on non-empty — a made-up identity would crown every
			// unconfigured controller first-hub).
			SelfAPI:     envOr("NODE_HOST_AGENT_API_SELF", w.wdCfg.APISelf),
			PeerAPI:     envOr("NODE_HOST_AGENT_API_PEER", w.wdCfg.APIPeer),
			KineDBProbe: envOr("NODE_HOST_AGENT_KINE_DB_PROBE", w.wdCfg.KineDBProbe),
			Sig13Mode:   envOr("NODE_HOST_AGENT_SIG13_AUTOFIX", w.wdCfg.Sig13Autofix),
			StaleMinErrs: envIntOr("NODE_HOST_AGENT_STALE_MIN_ERRS",
				w.wdCfg.Sig13StaleMinErrs, 15),
			GapMin: envInt64Or("NODE_HOST_AGENT_GAP_MIN",
				w.wdCfg.Sig13GapMin, 10000),
			GapCycles: envIntOr("NODE_HOST_AGENT_GAP_CYCLES",
				w.wdCfg.Sig13GapCycles, 2),
			FrozenCycles: envIntOr("NODE_HOST_AGENT_FROZEN_CYCLES",
				w.wdCfg.Sig13FrozenCycles, 2),
			SoloCycles: envIntOr("NODE_HOST_AGENT_SOLO_CYCLES",
				w.wdCfg.Sig13SoloCycles, 8),
			MinRestartInterval: envDurOr("NODE_HOST_AGENT_SIG13_MIN_RESTART_S",
				w.wdCfg.Sig13MinRestartS, 2*time.Hour),
			KineTTLMode: envOr("NODE_HOST_AGENT_KINE_TTL_AUTOFIX", w.wdCfg.KineTTLAutofix),
			KineTTLMinRestart: envDurOr("NODE_HOST_AGENT_KINE_TTL_MIN_RESTART_S",
				w.wdCfg.KineTTLMinRestartS, 30*time.Minute),
			KineTTLCtlRestart: envDurOr("NODE_HOST_AGENT_KINE_TTL_CTL_RESTART_S",
				w.wdCfg.KineTTLCtlRestartS, 2*time.Hour),
			KineTTLRewedgeCycles: envIntOr("NODE_HOST_AGENT_KINE_TTL_REWEDGE_CYCLES",
				w.wdCfg.KineTTLRewedgeCycle, 2),
			KinePoolMode: envOr("NODE_HOST_AGENT_KINE_POOL_AUTOFIX", w.wdCfg.KinePoolAutofix),
			KinePoolMaxConns: envIntOr("NODE_HOST_AGENT_KINE_POOL_MAX_CONNS",
				w.wdCfg.KinePoolMaxConns, 72),
			KinePoolCycles: envIntOr("NODE_HOST_AGENT_KINE_POOL_CYCLES",
				w.wdCfg.KinePoolCycles, 3),
			KinePoolMinRestart: envDurOr("NODE_HOST_AGENT_KINE_POOL_MIN_RESTART_S",
				w.wdCfg.KinePoolMinRestartS, 20*time.Minute),
			OOMLoopMode: envOr("NODE_HOST_AGENT_OOMLOOP_AUTOFIX", w.wdCfg.OOMLoopAutofix),
			OOMLoopMinKills: envIntOr("NODE_HOST_AGENT_OOMLOOP_MIN_KILLS",
				w.wdCfg.OOMLoopMinKills, 3),
			OOMLoopWindow: envDurOr("NODE_HOST_AGENT_OOMLOOP_WINDOW_S",
				w.wdCfg.OOMLoopWindowS, time.Hour),
			AdminKubeconfig:         w.hostPath("/var/lib/k0s/pki/admin.conf"),
			AdminCert:               w.hostPath("/var/lib/k0s/pki/admin.crt"),
			AdminKey:                w.hostPath("/var/lib/k0s/pki/admin.key"),
			AdminCA:                 w.hostPath("/var/lib/k0s/pki/ca.crt"),
			InsecureTLS:             envBool("NODE_HOST_AGENT_CONTROLLER_INSECURE_TLS", true),
			CGroupEventsFile:        w.hostPath("/sys/fs/cgroup/system.slice/k0scontroller.service/memory.events"),
			FeederEnabled:           envBool("NODE_HOST_AGENT_ENABLE_FEEDER", true),
			NotifySocket:            os.Getenv("NOTIFY_SOCKET"),
			FeederStateDir:          w.hostPath("/var/lib/k0s-systemd-watchdog"),
			RemediatePeerFile:       w.hostPath("/etc/default/k0scontroller-watchdog"),
			K0sDir:                  getenv("NODE_HOST_AGENT_K0S_DIR", w.hostPath("/var/lib/k0s")),
			EtcdEndpoint:            getenv("NODE_HOST_AGENT_ETCD_ENDPOINT", "https://127.0.0.1:2379"),
			EtcdDBSizeLimit:         envInt64("NODE_HOST_AGENT_ETCD_DB_SIZE_LIMIT", 0),
			JournalDirs:             w.journalDirs,
			JournalUnreadableNeeded: w.journalUnreadableNeeded,
		}, w.reg)
		if err != nil {
			logger().Error("controllerhygiene setup failed", "error", err)
		} else {
			w.subsystems = append(w.subsystems, ch)
		}
	}
}

// --- hostconfig: declarative host converger ---
// "auto" (default): enabled iff the vars dir actually carries
// defaults.yaml — pods without the node-config-vars mount and
// standalone hosts without config self-disable.
func (w *wiring) wireHostconfig() {
	hcMode := getenv("NODE_HOST_AGENT_ENABLE_HOSTCONFIG", "auto")
	_, varsErr := os.Stat(w.varsDir + "/defaults.yaml")
	if hcMode == "true" || (hcMode == "auto" && varsErr == nil) {
		hostname, _ := os.Hostname()
		var runner hostconfig.Runner = hostconfig.NsenterRunner{}
		if w.hostRoot == "/" {
			runner = hostconfig.DirectRunner{}
		}
		hc, err := hostconfig.New(hostconfig.Config{
			Enabled:            true,
			NodeName:           w.hnode,
			Hostname:           hostname,
			HostRoot:           w.hostRoot,
			VarsDir:            w.varsDir,
			NebulaCertsDir:     getenv("NODE_HOST_AGENT_NEBULA_CERTS_DIR", "/config/nebula-certs"),
			WatchdogScriptsDir: getenv("NODE_HOST_AGENT_WATCHDOG_SCRIPTS_DIR", "/config/watchdog"),
			Interval:           envDuration("NODE_HOST_AGENT_HOSTCONFIG_INTERVAL", 30*time.Minute),
			Runner:             runner,
			// Vars/cert changes converge on the next poll instead of
			// waiting out the full interval.
			Watcher: &hostconfig.DirWatcher{Dirs: []string{
				w.varsDir,
				getenv("NODE_HOST_AGENT_NEBULA_CERTS_DIR", "/config/nebula-certs"),
			}},
		}, w.reg)
		if err != nil {
			logger().Error("hostconfig setup failed", "error", err)
		} else {
			w.subsystems = append(w.subsystems, hc)
		}
	}
}

// --- hubsync: SSH converge of standalone targets ---
// Pod-mode only (it IS the converge fleet's client side — a
// standalone target never converges other targets). The Syncer is
// wired unconditionally: the DS mounts the converge secret
// optional:true so the key may land after pod start — Enabled()
// is the startup fast-path log only, and the Syncer re-checks the
// key on every trigger until it materializes.
func (w *wiring) wireHubsync() {
	convergeKey := getenv("NODE_HOST_AGENT_CONVERGE_SSH_KEY",
		"/etc/node-converge-ssh/id_ed25519")
	if !w.standalone {
		switch {
		case w.podName == "":
			logger().Error("hubsync disabled: pod name empty (POD_NAME unset)")
		default:
			cs, err := w.csOnce()
			if err != nil {
				logger().Error("hubsync disabled: cannot build kubernetes client",
					"error", err)
			} else {
				if !hubsync.Enabled(convergeKey) {
					logger().Info("hubsync: converge key not mounted yet — polling until it appears",
						"path", convergeKey)
				}
				hs, err := hubsync.New(hubsync.Config{
					Client:         cs,
					Identity:       w.podName,
					VarsDir:        w.varsDir,
					NebulaCertsDir: getenv("NODE_HOST_AGENT_NEBULA_CERTS_DIR", "/config/nebula-certs"),
					SSHKeyPath:     convergeKey,
					LocalBinary:    resolveLocalBinary(),
				}, w.reg)
				if err != nil {
					logger().Error("hubsync setup failed", "error", err)
				} else {
					w.subsystems = append(w.subsystems, hs)
				}
			}
		}
	}
}

// --- kinedb: kine DB VM probe/compact-guard/maintenance ---
// "auto" (default): Detect() — the postgres .env exists under
// hostRoot or a kine_db:true extra-host entry names this host.
func (w *wiring) wireKinedb() {
	kinedbMode := getenv("NODE_HOST_AGENT_ENABLE_KINEDB", "auto")
	if kinedbMode == "true" ||
		(kinedbMode == "auto" && kinedb.Detect(w.hostRoot, w.varsDir)) {
		kd, err := kinedb.New(kinedb.Config{
			Enabled:     true,
			EnvFile:     getenv("NODE_HOST_AGENT_KINEDB_ENV_FILE", w.hostPath("/opt/apps/postgres/.env")),
			TextfileDir: w.textfileDir,
			GuardStateDir: getenv("NODE_HOST_AGENT_KINEDB_GUARD_STATE_DIR",
				w.hostPath("/var/lib/kine-compact-guard")),
			// W8-CP2: in-container postgres data dir for the
			// repack headroom gate; empty → package default.
			PGDataDir: getenv("NODE_HOST_AGENT_KINEDB_PG_DATA_DIR", ""),
		}, w.reg)
		if err != nil {
			logger().Error("kinedb setup failed", "error", err)
		} else {
			w.subsystems = append(w.subsystems, kd)
		}
	}
}
