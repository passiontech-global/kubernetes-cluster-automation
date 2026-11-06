// config_etcd.go — the EtcdGuard domain knobs: EtcdGuardConfig
// (the embedded-etcd quota self-defence) and its applyDefaults
// block lifted out of config.go.
package controllerhygiene

import "time"

// EtcdGuardConfig is the embedded-etcd quota self-defence (k0s
// embedded-etcd controllers only — kine hosts no-op on the missing
// <K0sDir>/bin/etcdctl + pki/etcd/ca.crt). Trigger = NOSPACE alarm or
// dbSize >= DBSizeLimit → eventpurge + ONLINE-ONLY etcd rescue under the
// last-etcd-guard budget (the offline defrag stops k0scontroller and
// stays a manual action).
type EtcdGuardConfig struct {
	Endpoint    string // "" → https://127.0.0.1:2379
	DBSizeLimit int64  // dbSize trigger bytes; <=0 → 1.5 GiB
	// MinRun is the eventpurge+rescue rate budget; <=0 → 1h.
	MinRun time.Duration
}

func (c *Config) applyEtcdGuardDefaults() {
	if c.EtcdGuard.Endpoint == "" {
		c.EtcdGuard.Endpoint = defaultEtcdEndpoint
	}
	if c.EtcdGuard.DBSizeLimit <= 0 {
		c.EtcdGuard.DBSizeLimit = defaultEtcdDBSizeLimit
	}
	if c.EtcdGuard.MinRun <= 0 {
		c.EtcdGuard.MinRun = defaultEtcdGuardMinRun
	}
}
