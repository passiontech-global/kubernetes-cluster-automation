package apiprober

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostctx"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/subframe"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// EnvDeps carries the non-env inputs ConfigFromEnv needs — the values
// cmd/agent used to splice into Config directly. It embeds the shared
// hostctx.Deps watchdog/host-context bundle (this subsystem consumes
// Watchdog — its APIBackends are the StaticBackends fallback when
// api-backend-guard.conf carries none — WatchdogSrc and
// WatchdogStateDir via field promotion).
type EnvDeps struct {
	hostctx.Deps
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
		envx.StrOrKnob(envnames.EnvApiproberSocket, &pi.socket,
			g.SocketPath, defaultSocketPath),
		envx.StrOrKnob(envnames.EnvApiproberBackend, &pi.backend,
			g.BackendName, defaultBackendName),
		// empty env → nil → the conf's companion set.
		{Name: envnames.EnvApiproberCompanionBackends, Resolve: func(k string) {
			if l := envx.List(k); l != nil {
				pi.companions = l
			} else {
				pi.companions = g.CompanionBackends
			}
		}},
		envx.StrOrKnob(envnames.EnvApiproberMode, &pi.mode,
			g.Mode, ModeDryRun),
		envx.StrOrKnob(envnames.EnvApiproberTokenFile, &pi.tokenFile,
			g.TokenFile, defaultTokenFile),
		envx.StrOrKnob(envnames.EnvApiproberCaFile, &pi.caFile,
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
		Base: subframe.FromDeps(d.Deps),
	}
	// The env surface beyond the guard.conf chain, one row per knob
	// in declaration order.
	envx.Apply([]envx.Knob{
		envx.DurationKnob(envnames.EnvApiproberInterval, &cfg.Interval, defaultInterval),
		envx.Int64Knob(envnames.EnvApiproberGapMin, &cfg.GapMin, defaultGapMin),
		envx.IntKnob(envnames.EnvApiproberFailCycles, &cfg.FailCycles, defaultFailCycles),
		envx.IntKnob(envnames.EnvApiproberFrozenCycles, &cfg.FrozenCycles, defaultFrozenCycles),
		envx.IntKnob(envnames.EnvApiproberRecoverCycles, &cfg.RecoverCycles, defaultRecoverCycles),
		// Mirrors the shell version's `curl -sk` — apiserver certs
		// are not guaranteed to carry the backend IP in SANs.
		envx.BoolKnob(envnames.EnvApiproberInsecureTLS, &cfg.InsecureTLS, true),
		// Probe paths are overridable — the live path must be a
		// consistent read returning .metadata.resourceVersion
		// (swap to /api/v1/namespaces/default/services?limit=1
		// if the cluster doesn't serve leases under core/v1).
		envx.StringKnob(envnames.EnvApiproberLivePath, &cfg.LivePath, defaultLivePath),
		envx.StringKnob(envnames.EnvApiproberCachePath, &cfg.CachePath, defaultCachePath),
	})
	// Record which conf-overlappable knobs env explicitly carried —
	// refreshGuard's per-cycle conf overlay must not shadow them
	// (env > guard.conf > default; the overlay used to shadow env
	// outright). Same "empty == unset" semantics as the envx knobs.
	cfg.envSet = guardEnvSet{
		socket:     envx.IsSet(envnames.EnvApiproberSocket),
		backend:    envx.IsSet(envnames.EnvApiproberBackend),
		companions: envx.IsSet(envnames.EnvApiproberCompanionBackends),
		mode:       envx.IsSet(envnames.EnvApiproberMode),
		tokenFile:  envx.IsSet(envnames.EnvApiproberTokenFile),
		caFile:     envx.IsSet(envnames.EnvApiproberCaFile),
		gapMin:     envx.IsSet(envnames.EnvApiproberGapMin),
		failCycles: envx.IsSet(envnames.EnvApiproberFailCycles),
		frozen:     envx.IsSet(envnames.EnvApiproberFrozenCycles),
		recoverC:   envx.IsSet(envnames.EnvApiproberRecoverCycles),
	}
	return cfg
}
