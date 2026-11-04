// Package hubsync replaces the SSH-based hub-converge CronJob
// (passiontech-fluxcd infrastructure/base/node-ops/node-config-agent/
// playbooks/hub_converge.yaml): it keeps `node-host-agent --standalone`
// installed, configured and running on every non-K8s target —
// interdc registry nodes with `agent: false` (k0s controllers /
// nebula hubs), `node_exporter_extra_hosts` infra VMs (db-vm carrying
// `kine_db`, api-lb-vm) and `api_lb_guard_vms` API LB VMs.
//
// The DaemonSet runs one pod per node, so convergence is singleton:
// a coordination.k8s.io Lease (node-ops/node-host-agent-hubsync) is
// held by exactly one pod; only the holder runs sync cycles. The loop
// renews per client-go lease conventions and re-acquires after expiry
// when the holder dies.
//
// Per cycle the holder SSHes to each target (port 22, user `ssh_user`
// with the ansible resolution chain ssh_user →
// interdc_ssh_user_by_site[site] → interdc_ssh_default_user → root,
// optional `ssh_proxyjump` bastion) and converges:
//
//   - /usr/local/bin/node-host-agent — sha256-compared with the pod
//     binary, uploaded to a staging path + chmod + atomic mv on drift
//     (then `systemctl restart` instead of `enable --now`).
//   - /config/vars/* → /etc/node-host-agent/vars/ on every target;
//     /config/nebula-certs/* → /etc/node-host-agent/nebula-certs/ on
//     interdc (agent:false) targets only — sha256-gated per file.
//   - api_lb_guard_vms targets get Secret kube-system/
//     api-backend-guard-token's data["token"] (0600) and
//     data["ca.crt"] (0600) under /etc/api-backend-guard/ — the
//     standalone apiprober's credentials (hub_converge api_lb_guard
//     parity).
//   - /etc/systemd/system/node-host-agent.service running the
//     standalone binary with NODE_HOST_AGENT_HOST_ROOT=/ and the
//     vars/certs dir env wiring.
//
// Cycles run at startup (once the lease is held), every SyncInterval
// (10m) and whenever the vars/nebula-certs mounts change (sha256 dir
// fingerprint — the same mechanism hostconfig uses).
//
// Enabled() reports whether the node-converge SSH private key is
// mounted — the startup fast-path log. The DaemonSet mounts the
// secret optional:true precisely because the ExternalSecret may not
// be synced at pod start, so the Syncer re-checks the key on every
// trigger (ensureKey) and starts converging as soon as it
// materializes instead of staying dead until a pod restart.
package hubsync

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/subsystem/hostconfig"
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

// Watcher is the change-edge contract hostconfig.DirWatcher
// implements — Changed reports whether the watched dirs' content
// fingerprint moved since the last call.
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
	// content drift. Nil → a hostconfig.DirWatcher over VarsDir +
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

	// Dialer overrides the real SSH dialer — the test seam
	// (fake exec/write recording conns).
	Dialer Dialer

	// NowFn supplies wall time — seam for tests.
	NowFn func() time.Time
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
	if c.NowFn == nil {
		c.NowFn = time.Now
	}
	if c.Log == nil {
		c.Log = logger()
	}
	if c.Watcher == nil {
		c.Watcher = &hostconfig.DirWatcher{
			Dirs: []string{c.VarsDir, c.NebulaCertsDir},
		}
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

// Syncer implements agent.Subsystem.
type Syncer struct {
	cfg    Config
	dialer Dialer
	lease  *lease

	// mu guards the lease/key bookkeeping — the dedicated lease
	// goroutine (BUG-H3) and the cycle driver touch it from two
	// goroutines now that renewal is decoupled from Cycle.
	mu              sync.Mutex
	held            bool // lease currently held
	syncedWhileHeld bool // a cycle already ran since the lease was acquired
	keyReady        bool // converge SSH key observed at least once (latched)
	// cycleCh signals "lease freshly held — converge now" from the
	// renew loop to the cycle driver (buffered 1, drop-when-full).
	cycleCh chan struct{}

	// lastTargets caches the target names of the last successful
	// loadTargets — a parse failure must drive every known
	// target_up{...} series to 0 instead of leaving stale 1s.
	lastTargets []string

	lastSuccess *prometheus.GaugeVec   // labels: target
	targetUp    *prometheus.GaugeVec   // labels: target
	cycles      *prometheus.CounterVec // labels: target, result
}

// New validates cfg, builds the SSH dialer and registers metrics on
// reg (nil reg → metrics unregistered, still updated).
func New(cfg Config, reg prometheus.Registerer) (*Syncer, error) {
	cfg.applyDefaults()
	if cfg.Client == nil {
		return nil, fmt.Errorf("hubsync: Client is required")
	}
	if cfg.Identity == "" {
		return nil, fmt.Errorf("hubsync: Identity is required")
	}

	s := &Syncer{cfg: cfg, cycleCh: make(chan struct{}, 1)}
	s.dialer = cfg.Dialer
	if s.dialer == nil {
		d, err := newSSHDialer(cfg.SSHKeyPath, cfg.SSHPort, cfg.SSHTimeout, cfg.Log)
		if err != nil {
			return nil, fmt.Errorf("hubsync: ssh key: %w", err)
		}
		s.dialer = d
	}
	s.lease = &lease{
		leases:   cfg.Client.CoordinationV1().Leases(cfg.LeaseNamespace),
		name:     cfg.LeaseName,
		identity: cfg.Identity,
		duration: cfg.LeaseDuration,
		now:      cfg.NowFn,
	}

	s.lastSuccess = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_host_agent_hubsync_last_success_seconds",
		Help: "Unix time of the last fully successful converge per target.",
	}, []string{"target"})
	s.targetUp = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_host_agent_hubsync_target_up",
		Help: "1 when the last converge of the target succeeded; 0 on failure or missing secret.",
	}, []string{"target"})
	s.cycles = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_hubsync_cycles_total",
		Help: "Converge cycles per target by result (ok|error|parse_error|parse_note|secret_error|unresolved).",
	}, []string{"target", "result"})

	if reg != nil {
		for _, c := range []prometheus.Collector{s.lastSuccess, s.targetUp, s.cycles} {
			if err := reg.Register(c); err != nil {
				return nil, fmt.Errorf("register hubsync metrics: %w", err)
			}
		}
	}
	return s, nil
}

// Name identifies the subsystem for logging.
func (s *Syncer) Name() string { return "hubsync" }

// Run is the agent.Subsystem entrypoint: acquire/renew the lease on
// RenewInterval, converge immediately when the lease is first held,
// then every SyncInterval and on every watcher change edge. A lost
// lease simply gates the next cycle — the process keeps trying to
// re-acquire so a dead holder's lease expiry promotes a live pod
// without a restart.
func (s *Syncer) Run(ctx context.Context) {
	// Seed the watcher baseline: the first Changed() against an empty
	// fingerprint always reports an edge, and the startup cycle below
	// already covers it — swallow it so a steady holder doesn't
	// double-converge on the first watch tick.
	if s.cfg.Watcher != nil {
		s.cfg.Watcher.Changed()
	}
	// BUG-H3: the lease heartbeater runs on its OWN goroutine. Before
	// this split the renew tick shared this select with Cycle — a
	// slow SSH/SCP converge (up to ~3min/target over WAN) starved it
	// past the 60s LeaseDurationSeconds, letting a second pod claim
	// the lease mid-cycle (two holders converging the same targets).
	go s.leaseLoop(ctx)
	syncT := time.NewTicker(s.cfg.SyncInterval)
	watch := time.NewTicker(s.cfg.WatchInterval)
	defer syncT.Stop()
	defer watch.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.cycleCh:
			// Freshly acquired (or re-acquired after a gap):
			// converge now rather than waiting out SyncInterval.
			if s.ensureKey() && s.leaseHeld() {
				s.Cycle(ctx)
			}
		case <-syncT.C:
			if s.leaseHeld() && s.ensureKey() {
				s.Cycle(ctx)
			}
		case <-watch.C:
			if s.ensureKey() && s.leaseHeld() && s.cfg.Watcher != nil && s.cfg.Watcher.Changed() {
				s.Cycle(ctx)
			}
		}
	}
}

// leaseLoop is the dedicated lease heartbeater (BUG-H3): acquire or
// renew every RenewInterval on its own goroutine, decoupled from
// Cycle, so a slow WAN sync can't drop the 60s lease. A fresh hold
// kicks an immediate converge through cycleCh.
func (s *Syncer) leaseLoop(ctx context.Context) {
	defer func() {
		// Same single-flight reasoning as the feeder panic-recovery
		// in controllerhygiene — a defect here must not kill the
		// daemon, and a dead renewer fails safe (the lease lapses
		// rather than two pods holding it).
		if r := recover(); r != nil {
			s.cfg.Log.Error("hubsync: lease loop panicked — heartbeats stop, lease will lapse",
				"panic", r)
		}
	}()
	for {
		if s.ensureKey() && s.renewLease(ctx) && s.freshHold() {
			select {
			case s.cycleCh <- struct{}{}:
			default:
			}
		}
		t := time.NewTimer(s.cfg.RenewInterval)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// leaseHeld reports the current hold state (mutexed).
func (s *Syncer) leaseHeld() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.held
}

// freshHold reports whether the lease is held but no cycle ran yet
// since acquisition — the "converge immediately" trigger.
func (s *Syncer) freshHold() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.held && !s.syncedWhileHeld
}

// markSynced records that a cycle ran while holding the lease.
func (s *Syncer) markSynced() {
	s.mu.Lock()
	s.syncedWhileHeld = true
	s.mu.Unlock()
}

// ensureKey re-checks the converge SSH key until it appears, then
// latches — the secret mounts optional:true and may land after pod
// start, so every trigger is a skip-cycle-and-poll until the key
// materializes. First detection is logged; a LATE key starts
// convergence on the next renew tick (<=RenewInterval).
func (s *Syncer) ensureKey() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keyReady {
		return true
	}
	if !Enabled(s.cfg.SSHKeyPath) {
		return false
	}
	s.keyReady = true
	s.cfg.Log.Info("hubsync: converge ssh key detected — sync enabled",
		"path", s.cfg.SSHKeyPath)
	return true
}
