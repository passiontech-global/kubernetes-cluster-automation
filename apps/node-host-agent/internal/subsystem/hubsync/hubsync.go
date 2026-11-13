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
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/cycle"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/subframe"
)

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
	// leaseExpiresAt is the wall-clock moment our claim lapses —
	// renew stamps it from the fresh RenewTime + the advertised
	// LeaseDurationSeconds. A bare `held` flag goes stale when the
	// renew path breaks (hung apiserver conn, crashed renewer):
	// the real Lease then lapses, a second pod takes over, and this
	// pod keeps converging — split-brain. leaseHeld() requires BOTH.
	leaseExpiresAt time.Time
	// cycleCh signals "lease freshly held — converge now" from the
	// renew loop to the cycle driver (buffered 1, drop-when-full).
	cycleCh chan struct{}

	// leaseArmed keeps the lease heartbeater single-flight: the
	// agent supervisor re-invokes Run on the SAME ctx after a Cycle
	// panic, and a bare `go s.leaseLoop(ctx)` stacked another
	// renewer per restart — two loops racing the same Lease update
	// (the resourceVersion-conflict loser reads it as lease loss →
	// spurious "lost lease" + an extra converge). CompareAndSwap
	// arming, never reset — the renewer outlives Run like the
	// SpawnFn child it starts (spawnRouteGuard's single-flight
	// shape; feederOnce parity in controllerhygiene).
	leaseArmed atomic.Bool

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
		return nil, errors.New("hubsync: Client is required")
	}
	if cfg.Identity == "" {
		return nil, errors.New("hubsync: Identity is required")
	}

	s := &Syncer{cfg: cfg, cycleCh: make(chan struct{}, 1)}
	s.dialer = cfg.Dialer
	if s.dialer == nil {
		d, err := newSSHDialer(cfg.SSHKeyPath, cfg.SSHPort, cfg.SSHTimeout,
			cfg.SSHHostKeyFingerprint, cfg.SSHAllowInsecureHostKey,
			cfg.StateDir, cfg.Log)
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
		now:      cfg.Clock.Now,
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

	if err := subframe.RegisterAll(reg,
		s.lastSuccess, s.targetUp, s.cycles); err != nil {
		return nil, fmt.Errorf("register hubsync metrics: %w", err)
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
	if s.leaseArmed.CompareAndSwap(false, true) {
		// Spawn's stop is DELIBERATELY never called: the supervisor
		// passes the same live ctx on every restart, so the renewer
		// already outlived Run — the CAS just stops re-entries
		// stacking duplicates. Tying its lifetime to Run would let a
		// crash-looping Cycle lapse the 60s Lease through the
		// restart backoff (5s doubling to 5m in agent.go) and hand
		// the converge singleton to a second pod mid-flap.
		s.cfg.SpawnFn(ctx, "hubsync lease renewer", s.leaseLoop)
	}
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
		// Liveness heartbeat fires on EVERY outer-loop iteration —
		// lease held or not, leader or follower. A non-leader pod
		// that only heartbeats while holding the Lease would look
		// wedged to /healthz and get the whole DaemonSet killed.
		cycle.Heartbeat(ctx)
	}
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
