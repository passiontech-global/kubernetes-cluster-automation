// config_etcd.go — the EtcdGuard domain knobs: EtcdGuardConfig
// (the embedded-etcd quota self-defence) and its applyDefaults
// block lifted out of config.go.
package cdeps

import "time"

// etcdguard knobs (embedded-etcd quota self-defence — cicd
// controllers; kine hosts lack <K0sDir>/bin/etcdctl and no-op).
const (
	DefaultEtcdEndpoint = "https://127.0.0.1:2379"
	// DefaultEtcdDBSizeLimit is the dbSize trigger bytes (1.5 GiB).
	DefaultEtcdDBSizeLimit = int64(1610612736)
	defaultEtcdGuardMinRun = time.Hour        // last-etcd-guard budget
	defaultEtcdctlBudget   = 60 * time.Second // ctx cap per etcdctl call
	etcdctlCmdTimeout      = "30s"            // etcdctl --command-timeout
	// DefaultEtcdGuardBudget bounds the whole eventpurge+rescue
	// remediation block: eventpurge is unbounded pagination + delete
	// work at the apiserver's pace and the rescue is ~12 sequential
	// etcdctl calls — driven by the process-lifetime ctx, a degraded
	// backend could stall one (synchronous) cycle for hours. Both
	// steps are idempotent and last-etcd-guard is spent up front, so
	// exhausting this only defers the remainder to the next
	// EtcdGuardMinRun window.
	DefaultEtcdGuardBudget = 10 * time.Minute
	// DefaultEtcdGuardCallTimeout caps each rescue-spawned command
	// far below etcdmaint's defaultCallTimeout (10m — sized for an
	// operator at a shell): ~12 sequential calls then stay near the
	// guard budget instead of ~2h.
	DefaultEtcdGuardCallTimeout = time.Minute
	// EventStaleAge is the apiserver's own 1h event TTL — anything
	// older is GC debt the purge may safely delete (fresh,
	// debuggable events survive the guard's eventpurge pass).
	EventStaleAge = time.Hour
	// defaultEtcdBackupDir is the second default snapshot scan dir —
	// the host's /var/backups/etcd. ConfigFromEnv PathJoin-derives
	// EtcdBackupDir from it so the DaemonSet reads
	// /host/var/backups/etcd; this literal is the standalone /
	// programmatic-Config fallback.
	defaultEtcdBackupDir = "/var/backups/etcd"
)

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
		c.EtcdGuard.Endpoint = DefaultEtcdEndpoint
	}
	if c.EtcdGuard.DBSizeLimit <= 0 {
		c.EtcdGuard.DBSizeLimit = DefaultEtcdDBSizeLimit
	}
	if c.EtcdGuard.MinRun <= 0 {
		c.EtcdGuard.MinRun = defaultEtcdGuardMinRun
	}
	if c.EtcdBackupDir == "" {
		c.EtcdBackupDir = defaultEtcdBackupDir
	}
}
