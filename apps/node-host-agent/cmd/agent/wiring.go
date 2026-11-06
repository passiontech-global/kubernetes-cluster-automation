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
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostctx"
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
// clientset, and the hostctx.Deps watchdog/host-context bundle (the
// watchdog conf + its per-cycle reloader, the systemd client, and
// every resolved host path/dir/env-derived knob) — so each
// descriptor's Build closure reads them instead of re-deriving and
// splices w.Deps straight into the subsystem EnvDeps.
type wiring struct {
	reg        *prometheus.Registry
	subsystems []agent.Subsystem

	// Per-descriptor wire outcome, recorded by resolveAndBuild:
	// resolved is the RESOLVED enable mode (env flag vs default,
	// ModeAuto run through Auto) — true even when a needs-gate or
	// Build failure keeps the subsystem out of w.subsystems; built
	// marks only the descriptors that appended. The startup log
	// splits the missing names on the pair: resolved-off → "off",
	// resolved-on-but-not-built → "skipped".
	resolved map[string]bool
	built    map[string]bool

	csOnce func() (kubernetes.Interface, error)

	// Deps is the shared watchdog/host context — embedded so the
	// Build closures read w.Watchdog, w.HostPath(...), w.VarsDir
	// etc. directly and splice w.Deps into every EnvDeps.
	hostctx.Deps

	standalone bool
	defKube    bool

	podName string
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
	// Build constructs the subsystem(s) this descriptor contributes,
	// in append order; cs is the shared lazily-built clientset and
	// is non-nil only when Needs.Kube is set. Most descriptors
	// return exactly one subsystem — hostmetrics may return two
	// (the latch ticker plus the standalone textfile writer). A
	// non-nil error logs "<name> setup failed"; an empty slice with
	// a nil error means the failure was already logged — append
	// nothing.
	Build func(w *wiring, cs kubernetes.Interface) ([]agent.Subsystem, error)
}

// subsOf adapts a single-subsystem constructor result to the
// []agent.Subsystem Build shape — the generic lets each Build
// closure pass its New(...) call straight through instead of
// unwrapping the concrete (T, error) pair.
func subsOf[S agent.Subsystem](s S, err error) ([]agent.Subsystem, error) {
	if err != nil {
		return nil, err
	}
	return []agent.Subsystem{s}, nil
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
			Build: func(w *wiring, cs kubernetes.Interface) ([]agent.Subsystem, error) {
				return subsOf(sweeper.New(sweeper.ConfigFromEnv(
					sweeper.EnvDeps{Client: cs}), w.reg))
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
			Build: func(w *wiring, _ kubernetes.Interface) ([]agent.Subsystem, error) {
				knobs := concoursecache.ConfigFromEnv()
				pr, err := concoursecache.New(knobs.Config, w.reg)
				if err != nil {
					logger().Error("concourse-cache pruner setup failed", "error", err)
					return nil, nil
				}
				return []agent.Subsystem{cycle.Every(
					"concourse-cache", knobs.Interval,
					func(ctx context.Context) {
						if err := pr.Sweep(ctx, knobs.CacheRoot); err != nil {
							logger().Error("concourse cache sweep failed", "error", err)
						}
					})}, nil
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
			Build: func(w *wiring, _ kubernetes.Interface) ([]agent.Subsystem, error) {
				return subsOf(apiprober.New(apiprober.ConfigFromEnv(apiprober.EnvDeps{
					Deps: w.Deps,
				}), w.reg))
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
			Build: func(w *wiring, _ kubernetes.Interface) ([]agent.Subsystem, error) {
				hm := hostmetrics.New(hostmetrics.ConfigFromEnv(hostmetrics.EnvDeps{
					Deps:                w.Deps,
					Standalone:          w.standalone,
					OverlayEgressRelays: w.Watchdog.OverlayEgressRelays,
					NebulaNet:           w.Watchdog.NebulaNet,
				}))
				w.reg.MustRegister(hm)
				subs := []agent.Subsystem{hm.Latches()}
				// Standalone hosts have no Prometheus scrape — the
				// legacy prom_emit contract is kept by rendering the
				// same series into the node-exporter textfile dir on
				// a ticker (appended after the latch ticker, same as
				// the old Extra hook).
				if w.standalone {
					subs = append(subs, cycle.Every(
						"hostmetrics-textfile",
						envx.Duration("NODE_HOST_AGENT_TEXTFILE_INTERVAL",
							30*time.Second),
						func(ctx context.Context) {
							if err := hm.WriteTextfile(w.TextfileDir); err != nil {
								logger().Error("hostmetrics textfile write failed",
									"dir", w.TextfileDir, "error", err)
							}
						}))
				}
				return subs, nil
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
			Build: func(w *wiring, cs kubernetes.Interface) ([]agent.Subsystem, error) {
				return subsOf(workerhygiene.New(workerhygiene.ConfigFromEnv(
					workerhygiene.EnvDeps{
						Deps:   w.Deps,
						Client: cs,
					}), w.reg))
			},
		},
		// nethealth: DNS/overlay/nebula/fail2ban watchdog modules.
		// Runs on workers AND hub nodes; no kube client needed.
		{
			Name:    "nethealth",
			EnvFlag: "NODE_HOST_AGENT_ENABLE_NETHEALTH",
			Default: envx.ModeOn,
			Build: func(w *wiring, _ kubernetes.Interface) ([]agent.Subsystem, error) {
				return subsOf(nethealth.New(nethealth.ConfigFromEnv(nethealth.EnvDeps{
					Deps: w.Deps,
				}), w.reg))
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
			Build: func(w *wiring, _ kubernetes.Interface) ([]agent.Subsystem, error) {
				return subsOf(janitor.New(janitor.ConfigFromEnv(
					janitor.EnvDeps{
						Deps: w.Deps,
					}), w.reg))
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
			Build: func(w *wiring, cs kubernetes.Interface) ([]agent.Subsystem, error) {
				return subsOf(nodereporter.New(nodereporter.ConfigFromEnv(
					nodereporter.EnvDeps{
						Deps:   w.Deps,
						Client: cs,
					}), w.reg))
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
				return controllerhygiene.ShouldRun(w.HostRoot)
			},
			Build: func(w *wiring, _ kubernetes.Interface) ([]agent.Subsystem, error) {
				return subsOf(controllerhygiene.New(controllerhygiene.ConfigFromEnv(
					controllerhygiene.EnvDeps{
						Deps: w.Deps,
					}), w.reg))
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
				_, err := os.Stat(w.VarsDir + "/defaults.yaml")
				return err == nil
			},
			Build: func(w *wiring, _ kubernetes.Interface) ([]agent.Subsystem, error) {
				hostname, _ := os.Hostname()
				return subsOf(hostconfig.New(hostconfig.ConfigFromEnv(hostconfig.EnvDeps{
					Deps:     w.Deps,
					Hostname: hostname,
				}), w.reg))
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
			Build: func(w *wiring, cs kubernetes.Interface) ([]agent.Subsystem, error) {
				hsCfg := hubsync.ConfigFromEnv(hubsync.EnvDeps{
					Deps:        w.Deps,
					Client:      cs,
					Identity:    w.podName,
					LocalBinary: resolveLocalBinary(),
				})
				if !hubsync.Enabled(hsCfg.SSHKeyPath) {
					logger().Info("hubsync: converge key not mounted yet — polling until it appears",
						"path", hsCfg.SSHKeyPath)
				}
				return subsOf(hubsync.New(hsCfg, w.reg))
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
				return kinedb.Detect(w.HostRoot, w.VarsDir)
			},
			Build: func(w *wiring, _ kubernetes.Interface) ([]agent.Subsystem, error) {
				return subsOf(kinedb.New(kinedb.ConfigFromEnv(kinedb.EnvDeps{
					Deps: w.Deps,
				}), w.reg))
			},
		},
	}
}

// resolveAndBuild drives one descriptor: resolve the enable mode,
// apply the needs-gates, Build, append. The resolved mode lands in
// w.resolved BEFORE the gates run — a needs-gate skip or Build
// failure still counts as "resolved on" (it is not "subsystem
// constructed"), so the startup log can tell configured-off apart
// from wanted-but-held-back. w.built marks only the descriptors
// that actually appended a subsystem.
func (w *wiring) resolveAndBuild(d Descriptor) {
	resolved := true
	if d.EnvFlag != "" {
		switch mode := envx.ModeEnv(d.EnvFlag, d.Default); mode {
		case envx.ModeOff:
			resolved = false
		case envx.ModeAuto:
			resolved = d.Auto != nil && d.Auto(w)
		}
	}
	w.resolved[d.Name] = resolved
	if !resolved {
		return
	}
	if d.Needs.PodModeOnly && w.standalone {
		return
	}
	if d.Needs.NodeName && w.NodeName == "" {
		logger().Error(d.Name + " disabled: node name empty " +
			"(NODE_HOST_AGENT_NODE_NAME/NODE_NAME unset)")
		return
	}
	if d.Needs.PodName && w.podName == "" {
		logger().Error(d.Name + " disabled: pod name empty (POD_NAME unset)")
		return
	}
	var cs kubernetes.Interface
	if d.Needs.Kube {
		var err error
		if cs, err = w.csOnce(); err != nil {
			logger().Error(d.Name+" disabled: cannot build kubernetes client",
				"error", err)
			return
		}
	}
	subs, err := d.Build(w, cs)
	if err != nil {
		logger().Error(d.Name+" setup failed", "error", err)
		return
	}
	if len(subs) == 0 {
		return // Build already logged its own failure
	}
	w.subsystems = append(w.subsystems, subs...)
	w.built[d.Name] = true
}
