// Package controllerhygiene ports the controller/hub-side
// node-watchdog pieces (passiontech-fluxcd
// infrastructure/base/node-watchdog/) into one agent subsystem. It
// replaces five shell units that ran on k0scontroller nodes:
//
//   - watchdog/modules/22-apiserver-hub.sh (5m module, WD_REQUIRES:
//     uptime unit:k0scontroller) — sig13 apiserver watch-cache
//     gap/frozen wedge detection with the peer-fence restart veto,
//     the kine-backend dead-fallback via pg_wire_ok, and the kine TTL
//     dead/rewedge-loop kill logic.
//   - scripts/k0s-apiserver-wedge-probe.sh (60s timer) — the sig13
//     accelerator; merged into the single 60s cycle (its frozen-rv
//     fast path is the module-22 frozen signal at the faster
//     cadence).
//   - scripts/k0s-kine-pool-probe.sh (60s timer) — kine -> DB TCP
//     connection spiral backstop.
//   - scripts/k0s-oomloop-probe.sh (60s timer) — cgroup v2 memcg OOM
//     loop detector + oom_score_adj shield.
//   - scripts/k0s-systemd-watchdog-feeder.sh +
//     scripts/k0scontroller-remediate.sh — the Option-D dedicated
//     watchdog unit: feed systemd-notify WATCHDOG=1 while the local
//     apiserver answers ANY HTTP code, and re-confirm through the
//     ordered gates (G1..G6) before restarting k0scontroller.
//
// This file is the orchestrator only — the checks live in
// per-domain packages under controllerhygiene/:
//
//   - storelocal/ — kinepool.go (pool-spiral backstop), kine_ttl.go
//     (module-22 TTL dead/rewedge tail), kine_storage.go (kine-storage
//     store health + WAL checkpoint; LOCAL controller sqlite
//     state.db — the external Kine-DB VM lives in kinedb)
//   - apiserver/ — apiserverhub.go (module-22 sig13 wedge guard +
//     dead-fallback), cp_freeze_heal.go (cp-freeze-heal KCM/scheduler freeze
//   - kcm-queue-stall workqueue stall + the APF queue-starvation probe)
//   - etcd/      — etcdguard.go (embedded-etcd quota self-defence +
//     backup-health snapshot verifier)
//   - pki/       — pki_cert_drift.go (pki-cert-drift reload drift + sa-pub-key-fingerprint
//     sa.pub fingerprint), kubeconfig_cert_expiry.go (kubeconfig-cert-expiry)
//   - oom/       — oomloop.go (memcg OOM-loop detector + shield)
//   - feeder/    — the sd_notify watchdog feeder + G1..G6 remediate
//   - cdeps/     — the shared dependency surface (Config/Seams, Deps,
//     Check, the journal blindness tracker, the mTLS kube client,
//     the textfile writer). The Config domain groups are split into
//     cdeps/config_<domain>.go.
//
// Behaviour-equivalent differences from the shell versions
// (documented, intentional):
//   - Single 60s cycle merges the 5m module and the three 60s timers;
//     the fast-probe's separate fast-*/wedged-by-fastprobe files
//     collapse into the one loop (frozen detection is unchanged, only
//     faster: FROZEN_CYCLES x 60s vs the module's 5m double-gate).
//   - The module-22 probe-staleness checks (apiserver-wedge-probe-
//     stale, kine-pool-probe-stale, oomloop-probe-stale) are dropped —
//     they existed to detect silently-dead systemd timers; the agent
//     IS the probe now and its own liveness is covered by the agent
//     /healthz + watchdog metrics.
//   - `ss -p` connection accounting is replaced by intersecting
//     /proc/<kine-pid>/fd socket inodes with the remote-port column of
//     /proc/<kine-pid>/net/tcp(6) — same "only kine's sockets to the
//     DB port" set, no ss dependency.
//   - journalctl greps go through the injectable host-exec seam; a
//     journal read error maps to empty output (grep -c == 0), the
//     same degraded behaviour as `timeout 15 journalctl ... || true`.
//     The default is the shared platform/systemd client —
//     nsenter-wrapped to the HOST journald, so the checks see real
//     journal data inside the DaemonSet (the pod's own journal view
//     is empty).
//   - systemctl/ss invocations share the same single injectable
//     host-exec seam (HostExecFn — the Deps methods build argv, the
//     seam does the I/O) defaulting to the shared platform/systemd
//     client — nsenter-wrapped host exec — with
//     NOTIFY_SOCKET/WATCHDOG_* scrubbed from the child env via an
//     `env -u` argv prefix (the journal-spam fix the shell feeder
//     applied; the shared exec seam carries no env slot).
//   - The feeder cannot "exit 1": on max-fail/notify-fail it runs the
//     remediate gates inline and re-arms — the in-agent equivalent of
//     unit failed -> OnFailure oneshot -> Restart=always.
//   - Counters/latches keep the on-disk lib.sh layout
//     (consecutive-*, last-*, ttl-last-wedged-pid, oomloop-*) — the
//     files double as the cross-process contract shared with any
//     still-deployed shell watchdog pieces (last-sig13-restart is the
//     shared restart budget).
package controllerhygiene

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/checks"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/cycle"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/journalwatch"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/subframe"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/feeder"
)

// Hygiene runs the controller guards on one ticker plus the feeder
// loop. It is the orchestrator only: everything the checks consume
// (config, procfs view, mTLS client, state store, journal tracker,
// rate mutex, metric vecs/gauges, cross-check shared state) lives
// on the embedded *cdeps.Deps — see cdeps/deps.go. The embed keeps
// the test contract compiling: h.Cfg, h.State, h.JournalReads,
// h.Cycles etc. promote through it.
type Hygiene struct {
	*cdeps.Deps

	// feederOnce keeps the feeder single-flight: the agent
	// supervisor re-invokes Run on the same ctx after a Cycle
	// panic, and without it every restart stacks another feeder —
	// duplicate sd_notify plus duplicate runRemediate passes
	// (routeGuardOnce parity, nethealth.go).
	feederOnce sync.Once

	// checks is the ordered check list initChecks fills — Check
	// walks it for the domain test packages (cdepstest.Check is
	// the typed path).
	checks []cdeps.Check

	// groups is the ordered per-Cycle dispatch table — initChecks
	// fills it; the ungated-then-uptime-gated grouping preserves
	// the shell timer/module split (only module 22 carried
	// WD_REQUIRES:uptime).
	groups []checks.Group

	// feeder is the sd_notify watchdog feeder — not a Check (it
	// runs on its own faster ticker Spawned from Run, outside the
	// dispatch list) but owned here so tests reach it through
	// Feeder().
	feeder *feeder.Feeder
}

// The subsystem-convention export surface cmd/agent wires against:
// Config and EnvDeps alias the canonical cdeps types so
// controllerhygiene.Config IS cdeps.Config (no drift possible), and
// ConfigFromEnv forwards to the env resolution that lives in cdeps
// beside the defaults it fills. The name stays here because the
// subsystem convention puts it next to New.
type (
	Config  = cdeps.Config
	EnvDeps = cdeps.EnvDeps
)

// ConfigFromEnv resolves every NODE_HOST_AGENT_* knob controllerhygiene
// reads — implementation lives in cdeps (it owns the Config
// defaults).
func ConfigFromEnv(d EnvDeps) Config { return cdeps.ConfigFromEnv(d) }

// ShouldRun reports whether hostRoot looks like a k0s controller
// host: the k0scontroller systemd unit file exists. hostRoot="" → "/"
// (host binary); the DaemonSet passes "/host".
func ShouldRun(hostRoot string) bool {
	if hostRoot == "" {
		hostRoot = "/"
	}
	_, err := os.Stat(filepath.Join(hostRoot,
		"etc/systemd/system/k0scontroller.service"))
	return err == nil
}

// New returns a Hygiene and registers its metrics on reg.
func New(cfg Config, reg prometheus.Registerer) (*Hygiene, error) {
	cfg.ApplyDefaults()
	d := &cdeps.Deps{Cfg: cfg, Proc: procfs.New(cfg.ProcRoot)}
	// The store binds the shared timex.Cell — a post-New
	// cfg.Clock.Set is observed by it
	// (hoststate.Store.Now contract).
	d.State = cfg.Store(logger)
	// Declare the journal-unreadable producer id this subsystem can
	// emit so a post-restart ExitFrom seeds only live owners (on a
	// controller node workerhygiene is absent — its phantom hold
	// must not pin the shared latch).
	d.State.RegisterActiveOwner(journalwatch.OwnerControllerHygiene)
	// Streak contract lives in journalwatch.NewUnreadableTrackerForOwner:
	// each hygiene persists its OWN consecutive-journal-unreadable-<owner>
	// streak file and holds the shared state-journal-unreadable latch
	// under its own id — one side's failed read never inflates or
	// resets the other's count, while the latch FILE still arbitrates
	// the single shared episode (Store's multi-owner ExitFrom).
	d.JournalReads = journalwatch.NewUnreadableTrackerForOwner(
		d.State, cfg.JournalDirs, cfg.JournalUnreadableNeeded,
		journalwatch.OwnerControllerHygiene)
	if cfg.HTTPClient != nil {
		d.Client = cfg.HTTPClient
	}

	d.Cycles, d.Actions = subframe.Counters("controllerhygiene",
		"Controller-hygiene cycles by check and result (ok|abort|gated).",
		"Remediation actions by check and action "+
			"(restart_controller|dryrun|kill_kine|shield|unshield|remediate).")
	d.RVGap = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_controllerhygiene_rv_gap",
		Help: "Last observed rv_now - rv_cache on the local apiserver.",
	})
	d.KineConns = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_controllerhygiene_kine_db_conns",
		Help: "Kine process TCP connections to the datastore port.",
	})
	d.KineStuckConns = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_controllerhygiene_kine_stuck_conns",
		Help: "Kine process DB-port sockets wedged in CLOSE_WAIT/" +
			"FIN_WAIT2 or retransmitting (kine-orphaned-conn-watch orphaned-conn " +
			"signature).",
	})
	d.OOMWindow = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_controllerhygiene_oom_kills_window",
		Help: "memcg OOM kills inside the sliding window.",
	})
	d.Feeding = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_controllerhygiene_feeder_feeding",
		Help: "1 while the feeder sends WATCHDOG=1 to systemd.",
	})
	d.EtcdDBSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_controllerhygiene_etcd_db_size_bytes",
		Help: "Embedded-etcd DB file size from the last etcdctl " +
			"endpoint status probe (embedded-etcd controllers only).",
	})
	d.EtcdDBUse = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_controllerhygiene_etcd_db_in_use_bytes",
		Help: "Embedded-etcd DB size in use from the last etcdctl " +
			"endpoint status probe (embedded-etcd controllers only).",
	})
	d.EtcdNospace = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_controllerhygiene_etcd_nospace_alarm",
		Help: "1 while the embedded etcd carries a NOSPACE alarm " +
			"(embedded-etcd controllers only).",
	})
	// CounterFunc parity with the textfile's TYPE counter — the
	// mirrored apiserver series is monotonic, and the registry must
	// report the same type as the node-agent-apiserver-apf.prom
	// file or the two expositions of this name disagree.
	d.TerminatedWatchers = prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "node_host_agent_apiserver_terminated_watchers",
		Help: "apiserver_terminated_watchers_total mirrored from the " +
			"local apiserver — 410-Gone relist storm signal (relist-storm).",
	}, func() float64 {
		return math.Float64frombits(d.TerminatedWatchersVal.Load())
	})
	d.EtcdSnapAge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_controllerhygiene_etcd_snapshot_age_seconds",
		Help: "Age of the newest etcd snapshot under the snapshot " +
			"dirs (embedded-etcd controllers only, backup-health).",
	})
	d.KonnReadyBackends = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_controllerhygiene_konnectivity_ready_backends",
		Help: "konnectivity-server ready backend connections " +
			"(-1 when the :8091 metrics scrape fails).",
	})

	h := &Hygiene{Deps: d}
	if err := subframe.RegisterAll(reg,
		d.Cycles, d.Actions, d.RVGap, d.KineConns, d.KineStuckConns,
		d.OOMWindow, d.Feeding,
		d.EtcdDBSize, d.EtcdDBUse, d.EtcdNospace,
		d.TerminatedWatchers, d.EtcdSnapAge, d.KonnReadyBackends); err != nil {
		return nil, fmt.Errorf("register controllerhygiene metrics: %w", err)
	}
	h.initChecks()
	h.feeder = feeder.New(d)
	return h, nil
}

// Name identifies the subsystem for logging.
func (h *Hygiene) Name() string { return "controllerhygiene" }

// Check returns the registered check with the given cdeps.Check*
// name, or nil. This is the exported path to check state — the
// domain test packages (package X_test beside the check) reach
// their check's streak/latch bookkeeping through it via
// cdepstest.Check.
func (h *Hygiene) Check(name string) cdeps.Check {
	for _, c := range h.checks {
		if c.Name() == name {
			return c
		}
	}
	return nil
}

// Feeder returns the sd_notify watchdog feeder — the exported path
// to it for the domain test packages (feeder_test drives Run and
// RunRemediate directly).
func (h *Hygiene) Feeder() *feeder.Feeder { return h.feeder }

// feederActive reports whether the sd_notify feeder loop should run:
// enabled AND a notify path exists (injected seam or NOTIFY_SOCKET).
func (h *Hygiene) feederActive() bool {
	return h.Cfg.Feeder.Enabled && h.Cfg.NotifyFn != nil
}

// Run starts the feeder goroutine (when active), checks immediately,
// then cycles every Interval until ctx is cancelled.
func (h *Hygiene) Run(ctx context.Context) {
	if h.feederActive() {
		h.feederOnce.Do(func() {
			// Spawn's stop is DELIBERATELY never called: the
			// feeder runs on the supervisor ctx and must outlive
			// a single Run — tying its lifetime to Run would let
			// a crash-looping Cycle starve WATCHDOG=1 through the
			// supervisor's restart backoff (5s doubling to 5m in
			// agent.go) until the unit's own watchdog fires.
			// The feeder dies only when ITSELF panics — the shell
			// exit-1 → OnFailure equivalence — or the supervisor
			// ctx is cancelled.
			cycle.Spawn(ctx, "controllerhygiene watchdog feeder",
				func(fctx context.Context) {
					// Keep the panic in the watchdog tail —
					// every other feeder line lands there —
					// then re-panic so Spawn's recover logs it
					// to the agent stream and swallows (its
					// recover is the daemon-safety net: agent.go
					// only wraps Run itself, not goroutines Run
					// spawned).
					defer func() {
						if r := recover(); r != nil {
							h.State.AppendLogWarn(fmt.Sprintf(
								"feeder: PANIC %v — feeder dead, WATCHDOG=1 stops (agent kept alive)", r))
							panic(r)
						}
					}()
					h.feeder.Run(fctx)
				})
		})
	}
	cycle.Every("controllerhygiene", h.Cfg.Interval, h.runCycle).Run(ctx)
}

// runCycle executes one Cycle under the per-cycle deadline
// (Config.CycleTimeout). Run calls Cycle synchronously inside the
// ticker loop, so without the bound a single hung child — a
// degraded apiserver/etcd, a dead network path — would starve the
// restart-critical wedge/TTL checks for as long as it hangs. Every
// spawned command and HTTP probe is CommandContext/request-ctx
// aware, so cancellation actually interrupts the stall. Hitting
// the deadline is a degraded cycle, not a failure — it is logged
// so a silently-starved guard shows up in the watchdog tail.
func (h *Hygiene) runCycle(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, h.Cfg.CycleTimeout)
	defer cancel()
	h.Cycle(cctx)
	if errors.Is(cctx.Err(), context.DeadlineExceeded) {
		h.State.AppendLogWarn(fmt.Sprintf(
			"controllerhygiene: cycle deadline %s exceeded — "+
				"stalled check(s) aborted", h.Cfg.CycleTimeout))
	}
}

// uptimeOK is the module-22 WD_REQUIRES:uptime group gate — a
// /proc read error opens it (the shell's numeric test on an empty
// UPTIME failed open the same way: the module ran).
func (h *Hygiene) uptimeOK() bool {
	up, err := h.Proc.UptimeSeconds()
	return err != nil || up >= cdeps.MinUptimeSeconds
}

// Cycle runs one round of every check in the declared dispatch
// table. The k0scontroller unit file gates everything
// (WD_REQUIRES: unit:k0scontroller). Each check must never panic
// and degrades to no-op on missing files.
func (h *Hygiene) Cycle(ctx context.Context) {
	// BUG-H1: refresh <state>/last-run every cycle — the liveness
	// stamp the watchdog-stalled alert reads (the alert keys on
	// mtime, which the atomic rename refreshes each cycle).
	// Deferred so even a gated/aborted cycle proves the loop is
	// alive; Store.StampLastRun no-ops on an empty state dir.
	defer h.State.StampLastRun()
	if _, err := os.Stat(h.Cfg.K0sControllerUnitFile); err != nil {
		h.Cycles.WithLabelValues("all", "gated").Inc()
		return
	}
	_ = os.MkdirAll(h.Cfg.WatchdogStateDir, 0o755)
	// BUG-H9: hostconfig rewrites /etc/node-watchdog.conf mid-run —
	// refresh the conf-derived knobs before the checks consume them.
	h.RefreshWatchdogConf()
	checks.Dispatch(ctx, nil, h.Cycles, h.groups)
}

// --- /proc helpers ---
// The /proc reads live in platform/procfs (h.Proc): pid-dir
// listing, cmdline/comm reads, stat parsing (pid age, PPID) and
// the pgrep -x | head -1 lowest-pid comm lookup.

// --- satellite packages ---
// cdeps/config*.go : the Config surface — the flat wiring knobs,
//                    the per-domain sub-config groups and
//                    ApplyDefaults
// cdeps/seams.go   : the injectable seam funcs (Probe/Host/Etcd)
// cdeps/env.go     : EnvDeps + ConfigFromEnv
// cdeps/state.go   : the on-disk bookkeeping helpers Store does not
//                    cover — StateExit's suspect-budget drop and the
//                    raw-text ReadState/WriteState for non-epoch files
// cdeps/journal.go : JournalText + the journal-unreadable blindness
//                    accounting
// cdeps/exec.go    : the host-exec/env plumbing — ScrubSystemdEnv,
//                    scrubArgv, hostExecCtxBounded, sdNotify and the
//                    named host commands over the one HostExecFn
// cdeps/probes.go  : PGWireOK + the TLSCertFn default dial
// cdeps/kubeclient.go : apiserver credential loading + the rv LIST
//                    probe (EnsureClient/ResolveRel/ListRV)
// cdeps/textfile.go   : the node-exporter textfile writer
// cdeps/refresh.go    : the BUG-H9 per-cycle watchdogconf re-apply
// All external interactions stay behind the Config seams — only the
// default implementations moved.
