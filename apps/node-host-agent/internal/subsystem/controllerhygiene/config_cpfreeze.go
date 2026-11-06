// config_cpfreeze.go — the CPFreeze domain knobs: CPFreezeConfig
// (the W8-CP3 KCM/scheduler freeze auto-heal — no env wiring) and
// its applyDefaults block lifted out of config.go.
package controllerhygiene

import "time"

// CPFreezeConfig is the W8-CP3 KCM/scheduler freeze auto-heal. No env
// wiring — package defaults unless set programmatically.
type CPFreezeConfig struct {
	// KCMHealthURL/SchedHealthURL are the healthz endpoints of the
	// kube-controller-manager and kube-scheduler hosted inside
	// k0scontroller; KCMMetricsURL feeds the leader-without-workers
	// signal. Empty → the loopback defaults.
	KCMHealthURL   string
	SchedHealthURL string
	KCMMetricsURL  string
	Cycles         int           // consecutive healthz fails → act (default 3)
	QuietFor       time.Duration // KCM leader+idle grace (default 10m)
	MinRestart     time.Duration // last-cp-restart budget (default 2h)
}

func (c *Config) applyCPFreezeDefaults() {
	if c.CPFreeze.KCMHealthURL == "" {
		c.CPFreeze.KCMHealthURL = "https://127.0.0.1:10257/healthz"
	}
	if c.CPFreeze.SchedHealthURL == "" {
		c.CPFreeze.SchedHealthURL = "https://127.0.0.1:10259/healthz"
	}
	if c.CPFreeze.KCMMetricsURL == "" {
		c.CPFreeze.KCMMetricsURL = "https://127.0.0.1:10257/metrics"
	}
	if c.CPFreeze.Cycles <= 0 {
		c.CPFreeze.Cycles = defaultCPFreezeCycles
	}
	if c.CPFreeze.QuietFor <= 0 {
		c.CPFreeze.QuietFor = defaultCPFreezeQuietFor
	}
	if c.CPFreeze.MinRestart <= 0 {
		c.CPFreeze.MinRestart = defaultCPFreezeMinRestart
	}
}
