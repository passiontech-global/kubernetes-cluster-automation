// config_oomloop.go — the OOMLoop domain knobs: OOMLoopConfig (the
// cgroup v2 OOM-loop detector + oom_score_adj shield) and its
// applyDefaults block lifted out of config.go.
package controllerhygiene

import "time"

// OOMLoopConfig is the cgroup v2 OOM-loop detector + oom_score_adj
// shield (K0S_OOMLOOP_AUTOFIX).
type OOMLoopConfig struct {
	Mode               string
	MinKills           int           // kills in window → loop
	Window             time.Duration // sliding window
	CGroupEventsFile   string        // cgroup v2 memory.events
	APIServerShieldAdj int           // kube-apiserver protection
	KineShieldAdj      int           // kine sacrifice ranking
}

func (c *Config) applyOOMLoopDefaults() {
	if c.OOMLoop.Mode == "" {
		c.OOMLoop.Mode = ModeOff
	}
	if c.OOMLoop.MinKills <= 0 {
		c.OOMLoop.MinKills = defaultOOMMinKills
	}
	if c.OOMLoop.Window <= 0 {
		c.OOMLoop.Window = defaultOOMWindow
	}
	if c.OOMLoop.CGroupEventsFile == "" {
		c.OOMLoop.CGroupEventsFile = defaultCGroupEvents
	}
	// Shield adjs are non-zero in both directions; an explicit 0
	// would mean "shield to neutral" which is never what the loop
	// wants — treat unset as unset.
	if c.OOMLoop.APIServerShieldAdj == 0 {
		c.OOMLoop.APIServerShieldAdj = defaultAPIServerAdj
	}
	if c.OOMLoop.KineShieldAdj == 0 {
		c.OOMLoop.KineShieldAdj = defaultKineAdj
	}
}
