package apiprober

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// EnvDeps carries the non-env inputs ConfigFromEnv needs — the values
// cmd/agent used to splice into Config directly: the startup
// node-watchdog.conf parse (its APIBackends are the StaticBackends
// fallback when api-backend-guard.conf carries none), the per-cycle
// conf reloader, and the shared watchdog state dir.
type EnvDeps struct {
	Watchdog         *watchdogconf.Config
	WatchdogSrc      *watchdogconf.Reloader
	WatchdogStateDir string
}

// proberInputs is the resolved env → guard.conf → compiled-default
// layer for the apiprober knobs api-backend-guard.conf may carry —
// ported verbatim from cmd/agent's resolveProberInputs so the
// precedence chain stays assertable without standing a prober up.
type proberInputs struct {
	socket     string
	backend    string
	companions []string
	static     []StaticBackend
	mode       string
	tokenFile  string
	caFile     string
}

// resolveProberInputs resolves the env → guard.conf → compiled-
// default chain for the conf-overlappable knobs. wd may be nil (no
// APIBackends static fallback).
func resolveProberInputs(wd *watchdogconf.Config,
	g GuardDefaults) proberInputs {

	var static []StaticBackend
	switch {
	case len(g.StaticBackends) > 0:
		static = g.StaticBackends
	default:
		if wd != nil {
			for _, b := range wd.APIBackends {
				static = append(static,
					StaticBackend{Name: b.Name, Addr: b.Addr})
			}
		}
	}
	pi := proberInputs{static: static}
	// The env → guard.conf → compiled-default surface, one row per
	// knob in declaration order.
	envx.Apply([]envx.Knob{
		envx.StrOrKnob("NODE_HOST_AGENT_APIPROBER_SOCKET", &pi.socket,
			g.SocketPath, defaultSocketPath),
		envx.StrOrKnob("NODE_HOST_AGENT_APIPROBER_BACKEND", &pi.backend,
			g.BackendName, defaultBackendName),
		// empty env → nil → the conf's companion set.
		{Name: "NODE_HOST_AGENT_APIPROBER_COMPANION_BACKENDS", Resolve: func(k string) {
			if l := envx.List(k); l != nil {
				pi.companions = l
			} else {
				pi.companions = g.CompanionBackends
			}
		}},
		envx.StrOrKnob("NODE_HOST_AGENT_APIPROBER_MODE", &pi.mode,
			g.Mode, ModeDryRun),
		envx.StrOrKnob("NODE_HOST_AGENT_APIPROBER_TOKEN_FILE", &pi.tokenFile,
			g.TokenFile, defaultTokenFile),
		envx.StrOrKnob("NODE_HOST_AGENT_APIPROBER_CA_FILE", &pi.caFile,
			g.CAFile, defaultCAFile),
	})
	return pi
}

// ConfigFromEnv resolves every NODE_HOST_AGENT_* knob apiprober
// reads — including the env → api-backend-guard.conf → compiled-
// default triple chain (resolveProberInputs; the conf path itself is
// NODE_HOST_AGENT_API_GUARD_CONF, default /etc/api-backend-guard.conf)
// — and returns a Config ready for New. The enable gate
// (NODE_HOST_AGENT_ENABLE_APIPROBER=true|false|auto) stays in the
// caller. GuardSrc is left nil so New auto-wires the per-cycle
// GuardReloader on the same conf path — a conf rendered by
// hostconfig after agent start still lands next cycle.
func ConfigFromEnv(d EnvDeps) Config {
	guardPath := guardConfPath()
	guardConf, gerr := LoadGuardConf(guardPath)
	if gerr != nil {
		logger().Error("api-backend-guard.conf parse failed — running on defaults",
			"path", guardPath, "error", gerr)
		guardConf = GuardDefaults{}
	}
	pi := resolveProberInputs(d.Watchdog, guardConf)
	cfg := Config{
		SocketPath:        pi.socket,
		BackendName:       pi.backend,
		CompanionBackends: pi.companions,
		StaticBackends:    pi.static,
		Mode:              pi.mode,
		TokenFile:         pi.tokenFile,
		CAFile:            pi.caFile,
		// Same env/dir hostmetrics uses — one shared watchdog
		// state dir mount for the whole pod.
		WatchdogStateDir: d.WatchdogStateDir,
		WatchdogSrc:      d.WatchdogSrc,
	}
	// The env surface beyond the guard.conf chain, one row per knob
	// in declaration order.
	envx.Apply([]envx.Knob{
		envx.DurationKnob("NODE_HOST_AGENT_APIPROBER_INTERVAL", &cfg.Interval, defaultInterval),
		envx.Int64Knob("NODE_HOST_AGENT_APIPROBER_GAP_MIN", &cfg.GapMin, defaultGapMin),
		envx.IntKnob("NODE_HOST_AGENT_APIPROBER_FAIL_CYCLES", &cfg.FailCycles, defaultFailCycles),
		envx.IntKnob("NODE_HOST_AGENT_APIPROBER_FROZEN_CYCLES", &cfg.FrozenCycles, defaultFrozenCycles),
		envx.IntKnob("NODE_HOST_AGENT_APIPROBER_RECOVER_CYCLES", &cfg.RecoverCycles, defaultRecoverCycles),
		// Mirrors the shell version's `curl -sk` — apiserver certs
		// are not guaranteed to carry the backend IP in SANs.
		envx.BoolKnob("NODE_HOST_AGENT_APIPROBER_INSECURE_TLS", &cfg.InsecureTLS, true),
		// Probe paths are overridable — the live path must be a
		// consistent read returning .metadata.resourceVersion
		// (swap to /api/v1/namespaces/default/services?limit=1
		// if the cluster doesn't serve leases under core/v1).
		envx.StringKnob("NODE_HOST_AGENT_APIPROBER_LIVE_PATH", &cfg.LivePath, defaultLivePath),
		envx.StringKnob("NODE_HOST_AGENT_APIPROBER_CACHE_PATH", &cfg.CachePath, defaultCachePath),
	})
	return cfg
}
