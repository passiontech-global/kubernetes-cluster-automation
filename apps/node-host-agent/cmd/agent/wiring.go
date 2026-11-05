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
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/cycle"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/envx"
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
	if envx.Bool("NODE_HOST_AGENT_ENABLE_SWEEPER", w.defKube) {
		cs, err := w.csOnce()
		if err != nil {
			// Not fatal: the metrics/probe endpoints and other
			// subsystems still serve; the sweeper simply does not run.
			logger().Error("sweeper disabled: cannot build kubernetes client", "error", err)
		} else {
			sw, err := sweeper.New(sweeper.ConfigFromEnv(
				sweeper.EnvDeps{Client: cs}), w.reg)
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
	if envx.Bool("NODE_HOST_AGENT_ENABLE_CONCOURSE_CACHE", w.defKube) {
		knobs := sweeper.ConcourseCacheFromEnv()
		pr, err := sweeper.NewConcourseCachePruner(knobs.Config, w.reg)
		if err != nil {
			logger().Error("concourse-cache pruner setup failed", "error", err)
		} else {
			w.subsystems = append(w.subsystems, cycle.Every(
				"concourse-cache", knobs.Interval,
				func(ctx context.Context) {
					if err := pr.Sweep(ctx, knobs.CacheRoot); err != nil {
						logger().Error("concourse cache sweep failed", "error", err)
					}
				}))
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
	apiproberEnabled := envx.String("NODE_HOST_AGENT_ENABLE_APIPROBER", "auto") != "false"
	if apiproberEnabled {
		pb, err := apiprober.New(apiprober.ConfigFromEnv(apiprober.EnvDeps{
			Watchdog:         w.wdCfg,
			WatchdogSrc:      w.wdReloader,
			WatchdogStateDir: w.watchdogStateDir,
		}), w.reg)
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
	if envx.Bool("NODE_HOST_AGENT_ENABLE_HOSTMETRICS", true) {
		hm := hostmetrics.New(hostmetrics.ConfigFromEnv(hostmetrics.EnvDeps{
			NodeName:            w.hnode,
			WatchdogStateDir:    w.watchdogStateDir,
			Standalone:          w.standalone,
			OverlayEgressRelays: w.wdCfg.OverlayEgressRelays,
			NebulaNet:           w.wdCfg.NebulaNet,
			HostPath:            w.hostPath,
		}))
		w.reg.MustRegister(hm)
		// BUG-H5: the latch-maintenance ticker runs in BOTH modes —
		// on the DaemonSet Prometheus may not scrape for long
		// stretches, so latches can't ride Collect() alone.
		w.subsystems = append(w.subsystems, hm)
		// Standalone hosts have no Prometheus scrape — the legacy
		// prom_emit contract is kept by rendering the same series
		// into the node-exporter textfile dir on a ticker.
		if w.standalone {
			w.subsystems = append(w.subsystems, cycle.Every(
				"hostmetrics-textfile",
				envx.Duration("NODE_HOST_AGENT_TEXTFILE_INTERVAL",
					30*time.Second),
				func(ctx context.Context) {
					if err := hm.WriteTextfile(w.textfileDir); err != nil {
						logger().Error("hostmetrics textfile write failed",
							"dir", w.textfileDir, "error", err)
					}
				}))
		}
	}
}

// --- workerhygiene: worker-only watchdog checks ---
// Needs a node name (pods are filtered by spec.nodeName) and a
// kube client; either missing skips the subsystem — never aborts
// the agent.
func (w *wiring) wireWorkerHygiene() {
	if envx.Bool("NODE_HOST_AGENT_ENABLE_HYGIENE", w.defKube) {
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
				wh, err := workerhygiene.New(workerhygiene.ConfigFromEnv(
					workerhygiene.EnvDeps{
						Client:                  cs,
						NodeName:                w.hnode,
						Systemd:                 w.sdClient,
						Watchdog:                w.wdCfg,
						WatchdogSrc:             w.wdReloader,
						WatchdogStateDir:        w.watchdogStateDir,
						WatchdogLogFile:         w.watchdogLogFile,
						VarsDir:                 w.varsDir,
						JournalDirs:             w.journalDirs,
						JournalUnreadableNeeded: w.journalUnreadableNeeded,
						HostPath:                w.hostPath,
					}), w.reg)
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
	if envx.Bool("NODE_HOST_AGENT_ENABLE_NETHEALTH", true) {
		nh, err := nethealth.New(nethealth.ConfigFromEnv(nethealth.EnvDeps{
			WatchdogStateDir: w.watchdogStateDir,
			WatchdogLogFile:  w.watchdogLogFile,
			HostRoot:         w.hostRoot,
			Watchdog:         w.wdCfg,
			WatchdogSrc:      w.wdReloader,
			Systemd:          w.sdClient,
			HostPath:         w.hostPath,
		}), w.reg)
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
	if envx.Bool("NODE_HOST_AGENT_ENABLE_JANITOR", true) {
		jn, err := workerhygiene.NewJanitor(workerhygiene.JanitorConfigFromEnv(
			workerhygiene.EnvDeps{
				Systemd:          w.sdClient,
				WatchdogStateDir: w.watchdogStateDir,
				WatchdogLogFile:  w.watchdogLogFile,
				HostPath:         w.hostPath,
			}), w.reg)
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
	if envx.Bool("NODE_HOST_AGENT_ENABLE_REPORTER", w.defKube) {
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
				nr, err := nodereporter.New(nodereporter.ConfigFromEnv(
					nodereporter.EnvDeps{
						Client:           cs,
						NodeName:         w.hnode,
						WatchdogStateDir: w.watchdogStateDir,
						WatchdogLogFile:  w.watchdogLogFile,
					}), w.reg)
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
	chMode := envx.String("NODE_HOST_AGENT_ENABLE_CONTROLLERHYGIENE", "auto")
	if chMode == "true" || (chMode == "auto" && controllerhygiene.ShouldRun(w.hostRoot)) {
		ch, err := controllerhygiene.New(controllerhygiene.ConfigFromEnv(
			controllerhygiene.EnvDeps{
				Watchdog:                w.wdCfg,
				WatchdogSrc:             w.wdReloader,
				WatchdogStateDir:        w.watchdogStateDir,
				WatchdogLogFile:         w.watchdogLogFile,
				JournalDirs:             w.journalDirs,
				JournalUnreadableNeeded: w.journalUnreadableNeeded,
				HostPath:                w.hostPath,
			}), w.reg)
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
	hcMode := envx.String("NODE_HOST_AGENT_ENABLE_HOSTCONFIG", "auto")
	_, varsErr := os.Stat(w.varsDir + "/defaults.yaml")
	if hcMode == "true" || (hcMode == "auto" && varsErr == nil) {
		hostname, _ := os.Hostname()
		hc, err := hostconfig.New(hostconfig.ConfigFromEnv(hostconfig.EnvDeps{
			NodeName: w.hnode,
			Hostname: hostname,
			HostRoot: w.hostRoot,
			VarsDir:  w.varsDir,
		}), w.reg)
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
				hsCfg := hubsync.ConfigFromEnv(hubsync.EnvDeps{
					Client:      cs,
					Identity:    w.podName,
					VarsDir:     w.varsDir,
					LocalBinary: resolveLocalBinary(),
				})
				if !hubsync.Enabled(hsCfg.SSHKeyPath) {
					logger().Info("hubsync: converge key not mounted yet — polling until it appears",
						"path", hsCfg.SSHKeyPath)
				}
				hs, err := hubsync.New(hsCfg, w.reg)
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
	kinedbMode := envx.String("NODE_HOST_AGENT_ENABLE_KINEDB", "auto")
	if kinedbMode == "true" ||
		(kinedbMode == "auto" && kinedb.Detect(w.hostRoot, w.varsDir)) {
		kd, err := kinedb.New(kinedb.ConfigFromEnv(kinedb.EnvDeps{
			HostPath:    w.hostPath,
			TextfileDir: w.textfileDir,
		}), w.reg)
		if err != nil {
			logger().Error("kinedb setup failed", "error", err)
		} else {
			w.subsystems = append(w.subsystems, kd)
		}
	}
}
