// wiring.go — the subsystem registry: one Descriptor per subsystem,
// in the same startup order the sequential wiring blocks used to
// run. Every entry reads the shared inputs off *wiring (computed
// once in buildAgentConfig) and the wire loop appends to
// w.subsystems — the startup order of that slice is unchanged.
package main

import (
	"context"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/agent"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/cycle"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/apiprober"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/concoursecache"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/hostconfig"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/hostmetrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/hubsync"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/janitor"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/nethealth"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/nodereporter"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/sweeper"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// wiring carries the shared inputs buildAgentConfig computes once —
// the registry the subsystems register on, the lazy shared kube
// clientset, the watchdog conf + its per-cycle reloader, the systemd
// client, and every resolved host path/dir/env-derived knob — so each
// descriptor's Build closure reads them instead of re-deriving.
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

// Needs marks which shared inputs a descriptor's Build consumes —
// the wire loop gates on them before Build runs: an empty node/pod
// name or a kube-client build failure skips the subsystem (never
// fatal: the metrics/probe endpoints and other subsystems still
// serve), and PodModeOnly entries never run on standalone hosts.
type Needs struct {
	Kube        bool // lazily-built shared clientset via csOnce
	NodeName    bool // non-empty resolved node name
	PodName     bool // non-empty POD_NAME
	PodModeOnly bool // skipped when w.standalone
}

// Descriptor is one row of the subsystem registry: the env flag and
// its tri-state default, an optional auto-detect for the resolved
// ModeAuto, the shared-input gates, and the Build closure that
// constructs the subsystem. Build closures are the only place
// subsystem packages are referenced — the wire loop is generic.
type Descriptor struct {
	Name string
	// EnvFlag is the NODE_HOST_AGENT_ENABLE_* knob; empty means "no
	// env gate" (hubsync — pod mode + pod name + kube client only).
	EnvFlag string
	// Default is the mode an unset, empty, "auto" or unrecognised
	// flag resolves to; ModeAuto defers the decision to Auto.
	Default envx.Mode
	// Auto resolves a ModeAuto flag to enabled/disabled (nil → off).
	Auto  func(w *wiring) bool
	Needs Needs
	// Build constructs the subsystem; cs is the shared lazily-built
	// clientset and is non-nil only when Needs.Kube is set. A
	// non-nil error logs "<name> setup failed"; returning (nil, nil)
	// means the failure was already logged — append nothing.
	Build func(w *wiring, cs kubernetes.Interface) (agent.Subsystem, error)
	// Extra runs after a successful Build+append — for the one
	// subsystem that spawns a sibling (hostmetrics's standalone
	// textfile writer).
	Extra func(w *wiring, sub agent.Subsystem)
}

// onOff adapts a bool default (the standalone-flipped defKube) to the
// tri-state flag model.
func onOff(b bool) envx.Mode {
	if b {
		return envx.ModeOn
	}
	return envx.ModeOff
}

// descriptors is the subsystem registry — the ordered table the wire
// loop drives. The per-entry doc comments carry the rationale the old
// wire* methods documented; entry order IS the startup order.
func (w *wiring) descriptors() []Descriptor {
	return []Descriptor{
		// sweeper: openebs orphan pvc-* dir cleanup.
		{
			Name:    "sweeper",
			EnvFlag: "NODE_HOST_AGENT_ENABLE_SWEEPER",
			Default: onOff(w.defKube),
			Needs:   Needs{Kube: true},
			Build: func(w *wiring, cs kubernetes.Interface) (agent.Subsystem, error) {
				return sweeper.New(sweeper.ConfigFromEnv(
					sweeper.EnvDeps{Client: cs}), w.reg)
			},
		},
		// concourse-cache: native shared-cache pruner.
		// Pure host-fs work — no kube client — but it only makes
		// sense on nodes running concourse workers, so standalone
		// hosts default it off. Replaces the old CronJob + pods/exec
		// path.
		{
			Name:    "concourse-cache",
			EnvFlag: "NODE_HOST_AGENT_ENABLE_CONCOURSE_CACHE",
			Default: onOff(w.defKube),
			Build: func(w *wiring, _ kubernetes.Interface) (agent.Subsystem, error) {
				knobs := concoursecache.ConfigFromEnv()
				pr, err := concoursecache.New(knobs.Config, w.reg)
				if err != nil {
					logger().Error("concourse-cache pruner setup failed", "error", err)
					return nil, nil
				}
				return cycle.Every(
					"concourse-cache", knobs.Interval,
					func(ctx context.Context) {
						if err := pr.Sweep(ctx, knobs.CacheRoot); err != nil {
							logger().Error("concourse cache sweep failed", "error", err)
						}
					}), nil
			},
		},
		// apiprober: apiserver watch-cache wedge guard.
		// "auto" (default) = enabled; a missing socket is NOT a
		// startup gate — the prober self-gates each cycle
		// (cycles{no_socket}, logged once per state-change) so it
		// stays quiet on controllers and still comes alive when
		// api-local-lb is installed after this pod started. "false"
		// disables explicitly.
		// /etc/api-backend-guard.conf is rendered by hostconfig on
		// api-lb VMs — the fallback layer below the env vars for the
		// socket/backend/backends/mode/token/ca knobs (env →
		// guard.conf → compiled default). Absent elsewhere — zero
		// value.
		{
			Name:    "apiprober",
			EnvFlag: "NODE_HOST_AGENT_ENABLE_APIPROBER",
			Default: envx.ModeOn,
			Build: func(w *wiring, _ kubernetes.Interface) (agent.Subsystem, error) {
				return apiprober.New(apiprober.ConfigFromEnv(apiprober.EnvDeps{
					Watchdog:         w.wdCfg,
					WatchdogSrc:      w.wdReloader,
					WatchdogStateDir: w.watchdogStateDir,
				}), w.reg)
			},
		},
		// hostmetrics: scrape-time collector + latch-ticker
		// subsystem.
		// BUG-H5: the latch-maintenance ticker runs in BOTH modes —
		// on the DaemonSet Prometheus may not scrape for long
		// stretches, so latches can't ride Collect() alone; the
		// collector registers on the shared registry AND its Latches
		// half runs as the subsystem.
		{
			Name:    "hostmetrics",
			EnvFlag: "NODE_HOST_AGENT_ENABLE_HOSTMETRICS",
			Default: envx.ModeOn,
			Build: func(w *wiring, _ kubernetes.Interface) (agent.Subsystem, error) {
				hm := hostmetrics.New(hostmetrics.ConfigFromEnv(hostmetrics.EnvDeps{
					NodeName:            w.hnode,
					WatchdogStateDir:    w.watchdogStateDir,
					Standalone:          w.standalone,
					OverlayEgressRelays: w.wdCfg.OverlayEgressRelays,
					NebulaNet:           w.wdCfg.NebulaNet,
					HostPath:            w.hostPath,
				}))
				w.reg.MustRegister(hm)
				return hm.Latches(), nil
			},
			// Standalone hosts have no Prometheus scrape — the
			// legacy prom_emit contract is kept by rendering the
			// same series into the node-exporter textfile dir on a
			// ticker.
			Extra: func(w *wiring, sub agent.Subsystem) {
				if !w.standalone {
					return
				}
				hm := sub.(*hostmetrics.Latches).Collector()
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
			},
		},
		// workerhygiene: worker-only watchdog checks.
		// Needs a node name (pods are filtered by spec.nodeName) and
		// a kube client; either missing skips the subsystem — never
		// aborts the agent. The DaemonSet sets
		// NODE_HOST_AGENT_NODE_NAME and NODE_NAME via the downward
		// API — the explicit override env wins.
		{
			Name:    "workerhygiene",
			EnvFlag: "NODE_HOST_AGENT_ENABLE_HYGIENE",
			Default: onOff(w.defKube),
			Needs:   Needs{Kube: true, NodeName: true},
			Build: func(w *wiring, cs kubernetes.Interface) (agent.Subsystem, error) {
				return workerhygiene.New(workerhygiene.ConfigFromEnv(
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
			},
		},
		// nethealth: DNS/overlay/nebula/fail2ban watchdog modules.
		// Runs on workers AND hub nodes; no kube client needed.
		{
			Name:    "nethealth",
			EnvFlag: "NODE_HOST_AGENT_ENABLE_NETHEALTH",
			Default: envx.ModeOn,
			Build: func(w *wiring, _ kubernetes.Interface) (agent.Subsystem, error) {
				return nethealth.New(nethealth.ConfigFromEnv(nethealth.EnvDeps{
					WatchdogStateDir: w.watchdogStateDir,
					WatchdogLogFile:  w.watchdogLogFile,
					HostRoot:         w.hostRoot,
					Watchdog:         w.wdCfg,
					WatchdogSrc:      w.wdReloader,
					Systemd:          w.sdClient,
					HostPath:         w.hostPath,
				}), w.reg)
			},
		},
		// janitor: watchdog-state latch reaper + retired-unit sweep.
		// Pure host-fs/systemd work — runs on every node class
		// (workers, controllers, standalone hubs): the shared state
		// dir accumulates latches from every subsystem and ghost unit
		// records outlive the pruned unit files. No kube client
		// needed.
		{
			Name:    "janitor",
			EnvFlag: "NODE_HOST_AGENT_ENABLE_JANITOR",
			Default: envx.ModeOn,
			Build: func(w *wiring, _ kubernetes.Interface) (agent.Subsystem, error) {
				return janitor.New(janitor.ConfigFromEnv(
					janitor.EnvDeps{
						Systemd:          w.sdClient,
						WatchdogStateDir: w.watchdogStateDir,
						WatchdogLogFile:  w.watchdogLogFile,
						HostPath:         w.hostPath,
					}), w.reg)
			},
		},
		// nodereporter: state latches → NodeConditions/Events.
		// Replaces the NPD watchdog-state/filelog monitors; needs the
		// kube client and a node name.
		{
			Name:    "nodereporter",
			EnvFlag: "NODE_HOST_AGENT_ENABLE_REPORTER",
			Default: onOff(w.defKube),
			Needs:   Needs{Kube: true, NodeName: true},
			Build: func(w *wiring, cs kubernetes.Interface) (agent.Subsystem, error) {
				return nodereporter.New(nodereporter.ConfigFromEnv(
					nodereporter.EnvDeps{
						Client:           cs,
						NodeName:         w.hnode,
						WatchdogStateDir: w.watchdogStateDir,
						WatchdogLogFile:  w.watchdogLogFile,
					}), w.reg)
			},
		},
		// controllerhygiene: control-plane guards.
		// "auto" (default): enabled iff this host runs k0scontroller —
		// workers and bare API LB VMs self-disable.
		{
			Name:    "controllerhygiene",
			EnvFlag: "NODE_HOST_AGENT_ENABLE_CONTROLLERHYGIENE",
			Default: envx.ModeAuto,
			Auto: func(w *wiring) bool {
				return controllerhygiene.ShouldRun(w.hostRoot)
			},
			Build: func(w *wiring, _ kubernetes.Interface) (agent.Subsystem, error) {
				return controllerhygiene.New(controllerhygiene.ConfigFromEnv(
					controllerhygiene.EnvDeps{
						Watchdog:                w.wdCfg,
						WatchdogSrc:             w.wdReloader,
						Systemd:                 w.sdClient,
						WatchdogStateDir:        w.watchdogStateDir,
						WatchdogLogFile:         w.watchdogLogFile,
						JournalDirs:             w.journalDirs,
						JournalUnreadableNeeded: w.journalUnreadableNeeded,
						HostPath:                w.hostPath,
					}), w.reg)
			},
		},
		// hostconfig: declarative host converger.
		// "auto" (default): enabled iff the vars dir actually carries
		// defaults.yaml — pods without the node-config-vars mount and
		// standalone hosts without config self-disable.
		{
			Name:    "hostconfig",
			EnvFlag: "NODE_HOST_AGENT_ENABLE_HOSTCONFIG",
			Default: envx.ModeAuto,
			Auto: func(w *wiring) bool {
				_, err := os.Stat(w.varsDir + "/defaults.yaml")
				return err == nil
			},
			Build: func(w *wiring, _ kubernetes.Interface) (agent.Subsystem, error) {
				hostname, _ := os.Hostname()
				return hostconfig.New(hostconfig.ConfigFromEnv(hostconfig.EnvDeps{
					NodeName: w.hnode,
					Hostname: hostname,
					HostRoot: w.hostRoot,
					VarsDir:  w.varsDir,
				}), w.reg)
			},
		},
		// hubsync: SSH converge of standalone targets.
		// Pod-mode only (it IS the converge fleet's client side — a
		// standalone target never converges other targets). The
		// Syncer is wired unconditionally once its gates pass: the DS
		// mounts the converge secret optional:true so the key may
		// land after pod start — the key-missing info log is the
		// startup fast-path only, and the Syncer re-checks the key on
		// every trigger until it materializes.
		{
			Name:  "hubsync",
			Needs: Needs{Kube: true, PodName: true, PodModeOnly: true},
			Build: func(w *wiring, cs kubernetes.Interface) (agent.Subsystem, error) {
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
				return hubsync.New(hsCfg, w.reg)
			},
		},
		// kinedb: kine DB VM probe/compact-guard/maintenance.
		// "auto" (default): Detect() — the postgres .env exists under
		// hostRoot or a kine_db:true extra-host entry names this
		// host.
		{
			Name:    "kinedb",
			EnvFlag: "NODE_HOST_AGENT_ENABLE_KINEDB",
			Default: envx.ModeAuto,
			Auto: func(w *wiring) bool {
				return kinedb.Detect(w.hostRoot, w.varsDir)
			},
			Build: func(w *wiring, _ kubernetes.Interface) (agent.Subsystem, error) {
				return kinedb.New(kinedb.ConfigFromEnv(kinedb.EnvDeps{
					HostPath:    w.hostPath,
					TextfileDir: w.textfileDir,
				}), w.reg)
			},
		},
	}
}

// resolveAndBuild drives one descriptor: resolve the enable mode,
// apply the needs-gates, Build, append. The named result is the
// RESOLVED enable mode — needs-gate skips and Build failures still
// report it (it is not "subsystem constructed"), so the caller can
// report the apiprober flag on the startup log line even when
// construction failed.
func (w *wiring) resolveAndBuild(d Descriptor) (enabled bool) {
	enabled = true
	if d.EnvFlag != "" {
		switch mode := envx.ModeEnv(d.EnvFlag, d.Default); mode {
		case envx.ModeOff:
			enabled = false
		case envx.ModeAuto:
			enabled = d.Auto != nil && d.Auto(w)
		}
	}
	if !enabled {
		return enabled
	}
	if d.Needs.PodModeOnly && w.standalone {
		return enabled
	}
	if d.Needs.NodeName && w.hnode == "" {
		logger().Error(d.Name + " disabled: node name empty " +
			"(NODE_HOST_AGENT_NODE_NAME/NODE_NAME unset)")
		return enabled
	}
	if d.Needs.PodName && w.podName == "" {
		logger().Error(d.Name + " disabled: pod name empty (POD_NAME unset)")
		return enabled
	}
	var cs kubernetes.Interface
	if d.Needs.Kube {
		var err error
		if cs, err = w.csOnce(); err != nil {
			logger().Error(d.Name+" disabled: cannot build kubernetes client",
				"error", err)
			return enabled
		}
	}
	sub, err := d.Build(w, cs)
	if err != nil {
		logger().Error(d.Name+" setup failed", "error", err)
		return enabled
	}
	if sub == nil {
		return enabled // Build already logged its own failure
	}
	w.subsystems = append(w.subsystems, sub)
	if d.Extra != nil {
		d.Extra(w, sub)
	}
	return enabled
}
