// config_kine.go — the kine-domain knobs: KineTTLConfig (the TTL
// dead/rewedge-loop kill guard) and KinePoolConfig (the kine -> DB
// connection-spiral kill guard), with their applyDefaults blocks
// lifted out of config.go.
package controllerhygiene

import "time"

// KineTTLConfig is the kine TTL dead/rewedge-loop kill guard
// (KINE_TTL_AUTOFIX for kine process kills).
type KineTTLConfig struct {
	Mode          string
	MinRestart    time.Duration // fast-kill budget (KINE_TTL_MIN_RESTART_S)
	CtlRestart    time.Duration // rewedge-loop probe-kill cadence (KINE_TTL_CTL_RESTART_S)
	RewedgeCycles int           // distinct wedged pids → kine-ttl-loop
	MinProcAge    time.Duration // pid must outlive seed window
}

// KinePoolConfig is the kine -> DB connection-spiral kill guard
// (KINE_POOL_AUTOFIX for pool-spiral kills).
type KinePoolConfig struct {
	Mode           string
	MaxConns       int           // conns-to-DB spiral threshold
	Cycles         int           // consecutive over-threshold → kill
	MinRestart     time.Duration // kill budget (KINE_POOL_MIN_RESTART_S)
	DBPortFallback int           // DB port when --endpoint has none
}

func (c *Config) applyKineTTLDefaults() {
	if c.KineTTL.Mode == "" {
		c.KineTTL.Mode = ModeOff
	}
	if c.KineTTL.MinRestart <= 0 {
		c.KineTTL.MinRestart = defaultTTLMinRestart
	}
	if c.KineTTL.CtlRestart <= 0 {
		c.KineTTL.CtlRestart = defaultTTLCtlRestart
	}
	if c.KineTTL.RewedgeCycles <= 0 {
		c.KineTTL.RewedgeCycles = defaultTTLRewedgeCycles
	}
	if c.KineTTL.MinProcAge <= 0 {
		c.KineTTL.MinProcAge = defaultTTLMinProcAge
	}
}

func (c *Config) applyKinePoolDefaults() {
	if c.KinePool.Mode == "" {
		c.KinePool.Mode = ModeOff
	}
	if c.KinePool.MaxConns <= 0 {
		c.KinePool.MaxConns = defaultPoolMaxConns
	}
	if c.KinePool.Cycles <= 0 {
		c.KinePool.Cycles = defaultPoolCycles
	}
	if c.KinePool.MinRestart <= 0 {
		c.KinePool.MinRestart = defaultPoolMinRestart
	}
	if c.KinePool.DBPortFallback <= 0 {
		c.KinePool.DBPortFallback = defaultDBPortFallback
	}
}
