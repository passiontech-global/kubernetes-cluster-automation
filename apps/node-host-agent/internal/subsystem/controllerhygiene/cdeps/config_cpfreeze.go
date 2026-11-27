// config_cpfreeze.go — the CPFreeze domain knobs: CPFreezeConfig
// (the cp-freeze-heal KCM/scheduler freeze auto-heal plus the
// konnectivity-server goroutine/RSS leak guard) and its applyDefaults
// block lifted out of config.go.
package cdeps

import "time"

const (
	// DefaultKonnectivityMaxGoroutines is the default goroutine leak
	// threshold for konnectivity-server (0 = disabled).
	DefaultKonnectivityMaxGoroutines = 10000
	// DefaultKonnectivityMaxRSSMiB is the default RSS leak threshold
	// in MiB for konnectivity-server (0 = disabled).
	DefaultKonnectivityMaxRSSMiB = 512
)

// CPFreezeConfig is the cp-freeze-heal KCM/scheduler freeze auto-heal
// plus the konnectivity-server leak guard knobs.
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

	// KonnectivityMaxGoroutines / KonnectivityMaxRSSMiB cap
	// konnectivity-server goroutines and RSS (MiB) before sending
	// SIGTERM after 3 consecutive cycles; 0 disables each check.
	KonnectivityMaxGoroutines int
	KonnectivityMaxRSSMiB     int
	konnMaxGoroutinesSet      bool
	konnMaxRSSMiBSet          bool
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
	if !c.CPFreeze.konnMaxGoroutinesSet && c.CPFreeze.KonnectivityMaxGoroutines == 0 {
		c.CPFreeze.KonnectivityMaxGoroutines = DefaultKonnectivityMaxGoroutines
	}
	if !c.CPFreeze.konnMaxRSSMiBSet && c.CPFreeze.KonnectivityMaxRSSMiB == 0 {
		c.CPFreeze.KonnectivityMaxRSSMiB = DefaultKonnectivityMaxRSSMiB
	}
}
