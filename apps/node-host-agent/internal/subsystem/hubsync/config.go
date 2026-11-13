// config.go — the hubsync knobs: path/interval defaults, the Watcher
// change-edge contract, the Config struct + applyDefaults and the
// Enabled() key-presence probe. Split out of hubsync.go so the
// Syncer/run file stays under the ~500-LOC bar.
package hubsync

import (
	"context"
	"log/slog"
	"os"
	"time"

	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/cycle"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/fileconf"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/logx"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

const (
	defaultVarsDir        = "/config/vars"
	defaultNebulaCertsDir = "/config/nebula-certs"
	defaultSSHKeyPath     = "/etc/node-converge-ssh/id_ed25519"
	defaultLocalBinary    = "/node-host-agent"
	defaultRemoteBinary   = "/usr/local/bin/node-host-agent"
	defaultRemoteVarsDir  = "/etc/node-host-agent/vars"
	defaultRemoteCertsDir = "/etc/node-host-agent/nebula-certs"
	defaultGuardDir       = "/etc/api-backend-guard"
	defaultUnitPath       = "/etc/systemd/system/node-host-agent.service"

	defaultLeaseNamespace = "node-ops"
	defaultLeaseName      = "node-host-agent-hubsync"
	defaultLeaseDuration  = 60 * time.Second
	defaultRenewInterval  = 15 * time.Second
	defaultSyncInterval   = 10 * time.Minute
	defaultWatchInterval  = 15 * time.Second

	defaultSSHPort       = 22
	defaultSSHTimeout    = 15 * time.Second
	defaultTargetTimeout = 3 * time.Minute

	defaultSecretNamespace = "kube-system"
	defaultSecretName      = "api-backend-guard-token"
)

// Watcher is the change-edge contract fileconf.DirWatcher implements —
// Changed reports whether the watched dirs' content fingerprint moved
// since the last call.
type Watcher interface {
	Changed() bool
}

// Config carries the hubsync knobs — all test-injectable.
type Config struct {
	// Client is the in-cluster clientset — serves the Lease and the
	// api-backend-guard token Secret. Required.
	Client kubernetes.Interface
	// Identity is the lease holder name — POD_NAME via the downward
	// API. Required.
	Identity string

	LeaseNamespace string        // default node-ops
	LeaseName      string        // default node-host-agent-hubsync
	LeaseDuration  time.Duration // advertised LeaseDurationSeconds
	RenewInterval  time.Duration // acquire/renew cadence

	SyncInterval  time.Duration // full converge cadence (default 10m)
	WatchInterval time.Duration // how often the dir fingerprint is polled
	// Watcher edges trigger an early cycle on vars/nebula-certs
	// content drift. Nil → a fileconf.DirWatcher over VarsDir +
	// NebulaCertsDir.
	Watcher Watcher

	VarsDir        string // default /config/vars
	NebulaCertsDir string // default /config/nebula-certs
	SSHKeyPath     string // default /etc/node-converge-ssh/id_ed25519
	LocalBinary    string // pod binary to mirror (default /node-host-agent)
	RemoteBinary   string // default /usr/local/bin/node-host-agent
	RemoteVarsDir  string // default /etc/node-host-agent/vars
	RemoteCertsDir string // default /etc/node-host-agent/nebula-certs
	GuardDir       string // default /etc/api-backend-guard
	UnitPath       string // default /etc/systemd/system/node-host-agent.service

	SecretNamespace string // default kube-system
	SecretName      string // default api-backend-guard-token

	SSHPort       int           // default 22
	SSHTimeout    time.Duration // dial+handshake deadline
	TargetTimeout time.Duration // per-target converge deadline
	// SSHHostKeyFingerprint pins the converge targets' expected SSH
	// host key ("SHA256:<base64>"). Empty + SSHAllowInsecureHostKey
	// unset → dials fail closed; empty + allow → the historical
	// audit-log-only acceptance for rotating-key infra VMs.
	SSHHostKeyFingerprint   string
	SSHAllowInsecureHostKey bool
	// StateDir parents the persistent TOFU host-key store
	// (<StateDir>/hubsync_known_hosts) — the shared watchdog state
	// dir via EnvDeps.WatchdogStateDir. Empty disables TOFU, so an
	// unpinned dial falls back to known_hosts or fails closed.
	StateDir string

	// Dialer overrides the real SSH dialer — the test seam
	// (fake exec/write recording conns).
	Dialer Dialer

	// SpawnFn overrides the supervised-goroutine spawner the lease
	// heartbeater starts through — default cycle.Spawn. Test seam
	// counting spawn calls across Run re-entries.
	SpawnFn func(ctx context.Context, name string, fn func(context.Context)) (stop func())

	// Clock supplies wall time — the shared timex.Cell seam.
	Clock *timex.Cell
	// Log overrides the default slog logger — seam for tests.
	Log *slog.Logger
}

func (c *Config) applyDefaults() {
	if c.LeaseNamespace == "" {
		c.LeaseNamespace = defaultLeaseNamespace
	}
	if c.LeaseName == "" {
		c.LeaseName = defaultLeaseName
	}
	if c.LeaseDuration <= 0 {
		c.LeaseDuration = defaultLeaseDuration
	}
	if c.RenewInterval <= 0 {
		c.RenewInterval = defaultRenewInterval
	}
	if c.SyncInterval <= 0 {
		c.SyncInterval = defaultSyncInterval
	}
	if c.WatchInterval <= 0 {
		c.WatchInterval = defaultWatchInterval
	}
	if c.VarsDir == "" {
		c.VarsDir = defaultVarsDir
	}
	if c.NebulaCertsDir == "" {
		c.NebulaCertsDir = defaultNebulaCertsDir
	}
	if c.SSHKeyPath == "" {
		c.SSHKeyPath = defaultSSHKeyPath
	}
	if c.LocalBinary == "" {
		c.LocalBinary = defaultLocalBinary
	}
	if c.RemoteBinary == "" {
		c.RemoteBinary = defaultRemoteBinary
	}
	if c.RemoteVarsDir == "" {
		c.RemoteVarsDir = defaultRemoteVarsDir
	}
	if c.RemoteCertsDir == "" {
		c.RemoteCertsDir = defaultRemoteCertsDir
	}
	if c.GuardDir == "" {
		c.GuardDir = defaultGuardDir
	}
	if c.UnitPath == "" {
		c.UnitPath = defaultUnitPath
	}
	if c.SecretNamespace == "" {
		c.SecretNamespace = defaultSecretNamespace
	}
	if c.SecretName == "" {
		c.SecretName = defaultSecretName
	}
	if c.SSHPort <= 0 {
		c.SSHPort = defaultSSHPort
	}
	if c.SSHTimeout <= 0 {
		c.SSHTimeout = defaultSSHTimeout
	}
	if c.TargetTimeout <= 0 {
		c.TargetTimeout = defaultTargetTimeout
	}
	if c.Clock == nil {
		c.Clock = timex.NewCell(nil)
	}
	if c.Log == nil {
		c.Log = logger()
	}
	if c.Watcher == nil {
		// The watcher's debug texts stay hostconfig-prefixed (grep
		// contract from the shared implementation's original home),
		// so it keeps logging under the hostconfig identity.
		c.Watcher = &fileconf.DirWatcher{
			Dirs: []string{c.VarsDir, c.NebulaCertsDir},
			Log:  logx.For("hostconfig"),
		}
	}
	if c.SpawnFn == nil {
		c.SpawnFn = cycle.Spawn
	}
}

// Enabled reports whether the converge SSH private key is mounted at
// keyPath. The integrator uses it for the startup fast-path log only
// — it must NOT permanently gate the subsystem: the DS mounts the
// secret optional:true so the key may land after pod start, and the
// Syncer's ensureKey poll picks it up without a restart.
func Enabled(keyPath string) bool {
	if keyPath == "" {
		keyPath = defaultSSHKeyPath
	}
	st, err := os.Stat(keyPath)
	return err == nil && !st.IsDir()
}

// Enabled reports whether this Syncer config is live (key present).
func (c Config) Enabled() bool { return Enabled(c.SSHKeyPath) }
