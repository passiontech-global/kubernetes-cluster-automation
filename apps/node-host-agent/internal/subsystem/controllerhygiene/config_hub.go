// config_hub.go — the apiserver-hub domain knobs: HubConfig (the
// API_SELF/API_PEER/KINE_DB_PROBE identity/probe group) and
// Sig13Config (the sig13 watch-cache wedge guard sharing the
// SIG13_AUTOFIX mode), with their applyDefaults blocks lifted out
// of config.go.
package controllerhygiene

import "time"

// HubConfig carries the apiserver-hub identity/probe knobs — the
// NODE_HOST_AGENT_API_SELF / API_PEER / KINE_DB_PROBE env →
// watchdogconf → (empty) chain. SelfAPI deliberately has NO default:
// it is the first-hub ordering identity — solo/dead-fallback restarts
// gate on it being non-empty, and inventing 127.0.0.1 here would make
// every unconfigured controller believe it is the first hub.
type HubConfig struct {
	// SelfEndpoint is the apiserver probed for rv_cache/rv_now —
	// always the local listener (SELF_EP=127.0.0.1:6443).
	SelfEndpoint string
	// SelfAPI is API_SELF: this hub's apiserver "ip:port" used only
	// for deterministic first-hub ordering vs PeerAPI.
	SelfAPI string
	// PeerAPI is API_PEER: the other hub's apiserver "ip:port"; empty
	// = single-hub cluster (self always first).
	PeerAPI string
	// KineDBProbe is KINE_DB_PROBE "host:port" — pg-wire probe used
	// by the dead-fallback; empty disables it (veto preserved).
	KineDBProbe string
}

// Sig13Config is the sig13 apiserver watch-cache wedge guard — also
// the shared SIG13_AUTOFIX mode cp_freeze_heal and pki_cert_drift
// restart under. Fields resolve env → watchdogconf → package default.
type Sig13Config struct {
	Mode         string        // SIG13_AUTOFIX for k0scontroller restarts
	StaleMinErrs int           // journal errs/6min → apiserver-cache-stale
	GapMin       int64         // rv_now - rv_cache wedge threshold
	GapCycles    int           // consecutive gap-over-threshold → wedge
	FrozenCycles int           // consecutive identical rv_cache → wedge
	SoloCycles   int           // wedge cycles before first-hub may act alone
	MinRestart   time.Duration // SIG13_MIN_RESTART_S restart budget
}

func (c *Config) applyHubDefaults() {
	if c.Hub.SelfEndpoint == "" {
		c.Hub.SelfEndpoint = defaultSelfEndpoint
	}
	// SelfAPI deliberately has NO loopback default: it is the
	// first-hub ordering identity — solo/dead-fallback restarts gate
	// on it being non-empty, and inventing 127.0.0.1 here would make
	// every unconfigured controller believe it is the first hub.
}

func (c *Config) applySig13Defaults() {
	if c.Sig13.Mode == "" {
		c.Sig13.Mode = ModeOff
	}
	if c.Sig13.StaleMinErrs <= 0 {
		c.Sig13.StaleMinErrs = defaultStaleMinErrs
	}
	if c.Sig13.GapMin <= 0 {
		c.Sig13.GapMin = defaultGapMin
	}
	if c.Sig13.GapCycles <= 0 {
		c.Sig13.GapCycles = defaultGapCycles
	}
	if c.Sig13.FrozenCycles <= 0 {
		c.Sig13.FrozenCycles = defaultFrozenCycles
	}
	if c.Sig13.SoloCycles <= 0 {
		c.Sig13.SoloCycles = defaultSoloCycles
	}
	if c.Sig13.MinRestart <= 0 {
		c.Sig13.MinRestart = defaultMinRestart
	}
}
