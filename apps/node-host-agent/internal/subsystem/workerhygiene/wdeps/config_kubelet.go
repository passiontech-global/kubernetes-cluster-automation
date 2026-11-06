// config_kubelet.go — the kubelet-domain knobs: KubeletConfig, its
// defaults and its NODE_HOST_AGENT_* env rows (pod dirs, secure-port
// probes, the T15 watchdog-feeder cadence/gates and host list).
package wdeps

import (
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// KubeletConfig groups the kubelet-side knobs: the 05/06 stall and
// watch-wedge pod dirs/probes, the A4 syncloop probe auth, and the
// T15 watchdog-feeder cadence/gates.
type KubeletConfig struct {
	PodsDir     string        // host kubelet pod dirs (05/06)
	HealthzURL  string        // kubelet :10250 probe (05)
	WatchMinAge time.Duration // pod age without pod dir → watch wedge (06)
	// WatchdogHosts is the cluster var systemd_watchdog_hosts —
	// the T15 opt-in host list the shell feeder unit gated on (wired
	// by main from the vars dir / env). The feeder activates when this
	// node is listed here OR by default on any worker node
	// (K0sWorkerUnitFile present) — in the agent port the T15 pilot
	// graduated fleet-wide, so an empty list never disables it.
	WatchdogHosts []string
	WdInterval    time.Duration // feeder probe cadence (15s)
	WdMaxFail     int           // consecutive fails → remediate gates (4 = ~60s)
	WdProbeURL    string        // kubelet :10248 healthz — body must be "ok"
	// WdReprobeGap is the sleep between the remediate Gate-0
	// re-probes — the shell's "probe twice 3s apart" self-correct
	// window before any gate runs.
	WdReprobeGap time.Duration
	// APIFallbackURL is the G4 last-resort /livez target when no
	// API backends are configured (worker-local api-local-lb :7443).
	APIFallbackURL string
	SyncloopURL    string // kubelet :10250 /healthz/syncloop (PLEG)
	// TokenPath is the bearer-token file attached to kubelet's
	// secure-port probes — kubelet denies anonymous /healthz access,
	// so the syncloop probe authenticates with the pod SA token
	// (requires get on nonResourceURL /healthz/syncloop). Empty or
	// unreadable → the probe runs unauthenticated and 401/403
	// answers mark the check inconclusive, not down.
	TokenPath string
	// MetricsURL is the kubelet :10250 /metrics endpoint the
	// syncloop check scrapes for the PLEG relist/last-seen series —
	// same bearer auth as the syncloop probe. No env row (the URL
	// is a wiring constant like APIFallbackURL).
	MetricsURL string
}

func (k *KubeletConfig) applyDefaults() {
	if k.PodsDir == "" {
		k.PodsDir = defaultKubeletPodsDir
	}
	if k.HealthzURL == "" {
		k.HealthzURL = DefaultKubeletHealthzURL
	}
	if k.WatchMinAge <= 0 {
		k.WatchMinAge = defaultKubeletWatchMinAge
	}
	if k.WdInterval <= 0 {
		k.WdInterval = defaultKubeletWdInterval
	}
	if k.WdMaxFail <= 0 {
		k.WdMaxFail = DefaultKubeletWdMaxFail
	}
	if k.WdProbeURL == "" {
		k.WdProbeURL = defaultKubeletWdProbeURL
	}
	if k.WdReprobeGap <= 0 {
		k.WdReprobeGap = defaultKubeletWdReprobeGap
	}
	if k.APIFallbackURL == "" {
		k.APIFallbackURL = defaultAPIFallbackURL
	}
	if k.SyncloopURL == "" {
		k.SyncloopURL = defaultKubeletSyncloopURL
	}
	if k.MetricsURL == "" {
		k.MetricsURL = defaultKubeletMetricsURL
	}
	if k.TokenPath == "" {
		k.TokenPath = DefaultKubeletTokenPath
	}
}

// envKnobs returns the kubelet domain's NODE_HOST_AGENT_* env rows —
// the pod dir + secure-port probe paths (hostPath defaults like the
// wiring rows) and the T15 watchdog-hosts resolution, which needs the
// EnvDeps vars dir / node name for the cluster.yaml fallback.
func (k *KubeletConfig) envKnobs(hostPath func(string) string,
	d EnvDeps) []envx.Knob {
	return []envx.Knob{
		envx.StringKnob("NODE_HOST_AGENT_KUBELET_PODS_DIR", &k.PodsDir,
			hostPath("/var/lib/k0s/kubelet/pods")),
		// A4 probes: kubelet :10250 denies anonymous healthz, so
		// the syncloop probe authenticates with the pod SA token.
		envx.StringKnob("NODE_HOST_AGENT_KUBELET_SYNCLOOP_URL", &k.SyncloopURL, ""),
		envx.OrKnob("NODE_HOST_AGENT_KUBELET_TOKEN_FILE", &k.TokenPath,
			DefaultKubeletTokenPath),
		// T15 opt-in host list: env override →
		// systemd_watchdog_hosts out of the vars dir
		// (cluster.yaml) — resolved by KubeletWatchdogHosts (env.go).
		// Absent vars dir is not an error — the feeder self-gates on
		// k0sworker.service anyway.
		{Name: "NODE_HOST_AGENT_KUBELET_WATCHDOG_HOSTS", Resolve: func(string) {
			k.WatchdogHosts = KubeletWatchdogHosts(d.VarsDir, d.NodeName)
		}},
	}
}
