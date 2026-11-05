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
//   - journalctl greps go through an injectable journal reader; a
//     journal read error maps to empty output (grep -c == 0), the
//     same degraded behaviour as `timeout 15 journalctl ... || true`.
//     The default reader is the shared platform/systemd client —
//     nsenter-wrapped to the HOST journald, so the checks see real
//     journal data inside the DaemonSet (the pod's own journal view
//     is empty).
//   - systemctl invocations go through injectable funcs defaulting to
//     the shared platform/systemd client — nsenter-wrapped host exec —
//     with NOTIFY_SOCKET/WATCHDOG_* scrubbed from the child env via an
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
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/checks"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/cycle"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/journalwatch"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
)

// Autofix modes — the shell *_AUTOFIX knobs are preserved verbatim:
// off = state + log only, dry-run = log "would ...", enforce = act.
const (
	ModeOff     = "off"
	ModeDryRun  = "dry-run"
	ModeEnforce = "enforce"
)

// Defaults mirror the shell scripts + the DaemonSet host mounts.
const (
	defaultInterval = 60 * time.Second // merged timer cadence
	// Per-cycle hard bound (Config.CycleTimeout): Run drives Cycle
	// synchronously inside the ticker loop, so without it one
	// stalled child starves the restart-critical wedge/TTL checks
	// for as long as the child hangs. Sized well above a normal
	// cycle (seconds) plus the etcdguard budget.
	defaultCycleTimeout = 15 * time.Minute
	minUptimeSeconds    = 1200 // WD_REQUIRES: uptime
	defaultStateDir     = "/host/var/lib/node-watchdog"
	defaultLogFile      = "/host/var/log/node-watchdog.log"
	defaultProcRoot     = "/proc" // hostPID:true makes pod /proc == host /proc
	defaultUnitFile     = "/host/etc/systemd/system/k0scontroller.service"
	defaultJournalUnit  = "k0scontroller"
	defaultRestartUnit  = "k0scontroller.service"
	defaultSelfEndpoint = "127.0.0.1:6443" // probe target, always loopback
	defaultKubeconfig   = "/host/var/lib/k0s/pki/admin.conf"
	defaultAdminCert    = "/host/var/lib/k0s/pki/admin.crt"
	defaultAdminKey     = "/host/var/lib/k0s/pki/admin.key"
	defaultAdminCA      = "/host/var/lib/k0s/pki/ca.crt"
	defaultAPIPath      = "/api/v1/namespaces/default/services"
	defaultQueryTimeout = 12 * time.Second // curl --max-time 12
	defaultStaleMinErrs = 15
	defaultGapMin       = int64(10000)
	defaultGapCycles    = 2
	defaultFrozenCycles = 2
	defaultSoloCycles   = 8
	defaultMinRestart   = 2 * time.Hour // SIG13_MIN_RESTART_S=7200

	// kine TTL (module 22 tail)
	defaultTTLMinRestart    = 30 * time.Minute // KINE_TTL_MIN_RESTART_S=1800
	defaultTTLCtlRestart    = 2 * time.Hour    // KINE_TTL_CTL_RESTART_S=7200
	defaultTTLRewedgeCycles = 2
	defaultTTLMinProcAge    = 300 * time.Second

	// kine pool (k0s-kine-pool-probe.sh)
	defaultPoolMaxConns   = 72
	defaultPoolCycles     = 3
	defaultPoolMinRestart = 20 * time.Minute // KINE_POOL_MIN_RESTART_S=1200
	defaultDBPortFallback = 6432             // pgbouncer chain default

	// OOM loop (k0s-oomloop-probe.sh)
	defaultOOMMinKills    = 3
	defaultOOMWindow      = time.Hour
	defaultCGroupEvents   = "/host/sys/fs/cgroup/system.slice/k0scontroller.service/memory.events"
	defaultAPIServerAdj   = -800
	defaultKineAdj        = 500
	defaultJournalTimeout = 15 * time.Second
	// defaultJournalUnreadableNeeded is the consecutive-failed-read
	// budget for the journal-unreadable blindness latch (incident:
	// broken journald on a cicd controller left every journal check
	// silently seeing "0 hits").
	defaultJournalUnreadableNeeded = 5

	// systemd watchdog feeder (k0s-systemd-watchdog-feeder.sh) +
	// remediation (k0scontroller-remediate.sh)
	defaultFeedInterval    = 15 * time.Second // WDFEED_CHECK_INTERVAL
	defaultFeedMaxFail     = 4                // WDFEED_MAX_FAIL
	defaultFeedGraceFails  = 8                // WDFEED_STARTUP_GRACE_FAILS
	defaultFeedProbeURL    = "https://127.0.0.1:6443/readyz"
	defaultFeedProbeTO     = 5 * time.Second // curl --max-time 5
	defaultFeederStateDir  = "/host/var/lib/k0s-systemd-watchdog"
	defaultRemediateMinRst = 30 * time.Minute // WDREM_MIN_RESTART_INTERVAL=1800
	defaultRemediateGrace  = 90 * time.Second // WDREM_FRESH_GRACE_S=90
	defaultPeerFile        = "/host/etc/default/k0scontroller-watchdog"

	// defaultK0sDir is the shared k0s data dir — etcdguard probes
	// under it and the PKI-drift default pairs derive from it.
	defaultK0sDir = "/host/var/lib/k0s" // DaemonSet host mount
	// defaultSuspectLogCadence is the re-reminder interval suspectLog
	// applies to suspect/hold lines whose latch stays held: STATE-
	// ENTER announces the transition and the raw line then repeats
	// at most this often — the field-verified failure mode was
	// kine-ttl-loop logging every 60s cycle for weeks on nonprod
	// (1600+ lines), drowning the watchdog tail.
	defaultSuspectLogCadence = time.Hour
)

// Check names — prometheus `check` label + log context.
const (
	checkHub      = "apiserver-hub"
	checkKineTTL  = "kine-ttl"
	checkKinePool = "kine-pool"
	checkOOMLoop  = "oomloop"
	checkFeeder   = "feeder"
	// checkJournal is the pseudo-check label the journal-unreadable
	// blindness accounting counts under — journald readability is a
	// cross-cutting witness, not one of the gated checks.
	checkJournal = "journal"
)

// State latch names — identical to the shell signal names (NPD +
// prom_emit contract, node_watchdog_state{signal=...}); the values
// come from the canonical hoststate latch registry.
const (
	stateCacheStale       = hoststate.LatchAPIServerCacheStale
	stateCacheWedged      = hoststate.LatchAPIServerCacheWedged
	stateKineUnreachable  = hoststate.LatchKineBackendUnreachable
	stateKinePoolRunaway  = hoststate.LatchKinePoolRunaway
	stateKineTTLDead      = hoststate.LatchKineTTLDead
	stateKineTTLLoop      = hoststate.LatchKineTTLLoop
	stateControllerOOMLop = hoststate.LatchK0sControllerOOMLoop
	// stateJournalUnreadable latches while journal reads keep
	// producing nothing although journal storage exists — every
	// journal-grep check is blind until it clears (suspectLog's
	// last-suspect- budget drops with the latch via stateExit).
	stateJournalUnreadable = hoststate.LatchJournalUnreadable
	// W8-CP3 latch: a KCM/scheduler component frozen while the peer
	// apiserver stays healthy.
	stateCPComponentFrozen = hoststate.LatchCPComponentFrozen
	// W8-CP4 latch: an on-disk PKI cert newer than what the live
	// socket presents — the daemon never reloaded the rotated cert.
	statePKIReloadStale = hoststate.LatchCPCertReloadStale
)

// On-disk bookkeeping file names under WatchdogStateDir — same names
// as the shell scripts so concurrent shell pieces share the budget.
const (
	fileRateRestart   = "last-sig13-restart" // shared restart budget
	fileRateTTLKill   = "last-ttl-restart"
	fileRatePoolKill  = "last-kinepool-kill"
	fileCtrGap        = "consecutive-sig13-gap"
	fileCtrFrozen     = "consecutive-sig13-frozen"
	fileCtrPeerFrozen = "consecutive-sig13-peer-frozen"
	fileCtrDead       = "consecutive-sig13-dead"
	fileCtrPool       = "consecutive-kine-pool"
	fileCtrTTLRewedge = "consecutive-ttl-rewedge"
	fileLastRVC       = "last-rvc"
	fileLastPRVC      = "last-prvc"
	fileTTLWedgedPID  = "ttl-last-wedged-pid"
	fileOOMSeen       = "oomloop-seen"
	fileOOMKills      = "oomloop-kills"
	fileOOMShielded   = "oomloop-shielded"
	fileFeederLastRst = "last-restart" // under FeederStateDir
	// W8-CP3 (KCM/scheduler freeze auto-heal) + W8-CP4 (PKI reload
	// drift) bookkeeping.
	fileRateCPRestart  = "last-cp-restart"
	fileRatePKIRestart = "last-cp-cert-restart"
	fileCtrCPFreeze    = "consecutive-cp-freeze"
	fileCtrKCMQuiet    = "consecutive-kcm-quiet"
	fileCtrPKIDriftPre = "consecutive-cp-cert-stale-"
	// W8-CP3 defaults: 3 consecutive healthz failures, or a KCM that
	// is leader yet carries zero queued work for >10m — while the
	// peer apiserver still answers — restarts k0scontroller under a
	// 2h budget.
	defaultCPFreezeCycles     = 3
	defaultCPFreezeQuietFor   = 10 * time.Minute
	defaultCPFreezeMinRestart = 2 * time.Hour
	// W8-CP4: an on-disk cert newer than the socket-presented cert
	// for 2 consecutive cycles → restart the owning unit (1h budget).
	defaultPKIDriftCycles     = 2
	defaultPKIRestartInterval = time.Hour
	// suspectLog dedupe budgets: hoststate.SuspectBudgetPrefix+<key>
	// epoch files spent at most once per SuspectLogCadence — the
	// same rateOK/last-* convention as the action budgets, applied
	// to log noise (h.state.SuspectLog). Latch-named keys are
	// dropped by stateExit so a latch re-entry logs a fresh first
	// line; logKeyDeadFallbk keys the dead-fallback hold lines,
	// which have no dedicated latch.
	logKeyDeadFallbk = "dead-fallback"
	clkTck           = 100.0 // getconf CLK_TCK on x86_64 Linux
	tcpStateListen   = "0A"
	pgAuthOK         = "RSNK"
)

// Regexes — 1:1 with the shell grep patterns.
var (
	// module 22 early-warning journal grep.
	cacheErrRe = regexp.MustCompile(
		`Cache consistency check error|required revision has been compacted|error while range on /registry`)
	// kine TTL-dead journal grep (pkg/ttl/ttl.go workqueue ShutDown).
	ttlErrRe = regexp.MustCompile(`TTL initial list failed|TTL event watch (failed|error)`)
	// --endpoint=postgres://...:PORT/db on the kine cmdline (the
	// sed 's/^--endpoint=.*:\([0-9][0-9]*\)\/[^/]*$/\1/p' of
	// k0s-kine-pool-probe.sh, applied per argv entry).
	endpointPortRe = regexp.MustCompile(`^--endpoint=.*:([0-9]+)/[^/]*$`)
	// socket:[<inode>] fd symlink targets.
	sockInodeRe = regexp.MustCompile(`^socket:\[([0-9]+)\]$`)
	// `oom_kill <n>` row of cgroup v2 memory.events.
	oomKillRe = regexp.MustCompile(`^oom_kill +([0-9]+)\s*$`)
	// PEER_APISERVER="https://ip:6443" in the remediate peer file.
	peerAPIServerRe = regexp.MustCompile(`(?m)^PEER_APISERVER=(.*)$`)
)

// Hygiene runs the controller guards on one ticker plus the feeder
// loop.
type Hygiene struct {
	cfg    Config
	proc   procfs.FS    // /proc view bound to cfg.ProcRoot
	client *http.Client // mTLS client for rv probes; nil when creds absent
	credFP string       // credential-file fingerprint the client was built from

	// state is the shared hoststate Store — every state-*/last-*/
	// consecutive-*/last-suspect-* file and the watchdog log append
	// goes through it (the single lib.sh-parity implementation).
	state *hoststate.Store

	// feederOnce keeps the feeder single-flight: the agent
	// supervisor re-invokes Run on the same ctx after a Cycle
	// panic, and without it every restart stacks another feeder —
	// duplicate sd_notify plus duplicate runRemediate passes
	// (routeGuardOnce parity, nethealth.go).
	feederOnce sync.Once
	// rateMu serialises the remediate G5 check + G6 budget spend:
	// the last-restart epoch file stays the cross-process contract,
	// but the in-process read-compare-write still needs a mutex or
	// two overlapping remediate passes can both see "allowed" in
	// the same window (TOCTOU double-restart). Held only around
	// the file check+mkdir+write, never across systemctl —
	// workerhygiene rateTrySpend parity.
	rateMu sync.Mutex

	// journalReads is the journal-unreadable accounting — every
	// journalText result is classified into it; the tracker fires the
	// state-journal-unreadable latch on persistent blindness.
	journalReads journalwatch.Tracker

	// wdApplied records the watchdogconf parse the conf-derived knobs
	// were last refreshed from — BUG-H9's "only move fields that still
	// carry the previous conf value" rule needs the previous parse.
	wdApplied *watchdogconf.Config
	// kcmQuietSince is the first cycle the KCM read leader+idle —
	// leader-without-workers only counts as frozen after
	// CPFreezeQuietFor (W8-CP3).
	kcmQuietSince time.Time

	// groups is the ordered per-Cycle dispatch table — initChecks
	// fills it; the ungated-then-uptime-gated grouping preserves
	// the shell timer/module split (only module 22 carried
	// WD_REQUIRES:uptime).
	groups []checks.Group

	cycles    *prometheus.CounterVec // check, result
	actions   *prometheus.CounterVec // check, action
	rvGap     prometheus.Gauge
	kineConns prometheus.Gauge
	oomWindow prometheus.Gauge
	feeding   prometheus.Gauge
	// etcdguard gauges — only set when <K0sDir>/bin/etcdctl +
	// pki/etcd/ca.crt exist (embedded-etcd controllers).
	etcdDBSize  prometheus.Gauge
	etcdDBUse   prometheus.Gauge
	etcdNospace prometheus.Gauge
}

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
	cfg.applyDefaults()
	h := &Hygiene{cfg: cfg, proc: procfs.New(cfg.ProcRoot)}
	// The Now closure must read h.cfg.nowFn at call time — tests
	// re-stub the clock after New() and the store has to observe it
	// (hoststate.Store.Now contract).
	h.state = hoststate.New(cfg.WatchdogStateDir, cfg.WatchdogLogFile,
		func() time.Time { return h.cfg.nowFn() }, logger)
	h.journalReads = journalwatch.Tracker{
		Needed: cfg.JournalUnreadableNeeded,
		Dirs:   cfg.JournalDirs,
	}
	if cfg.HTTPClient != nil {
		h.client = cfg.HTTPClient
	}

	h.cycles = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_controllerhygiene_cycles_total",
		Help: "Controller-hygiene cycles by check and result (ok|abort|gated).",
	}, []string{"check", "result"})
	h.actions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_controllerhygiene_actions_total",
		Help: "Remediation actions by check and action " +
			"(restart_controller|dryrun|kill_kine|shield|unshield|remediate).",
	}, []string{"check", "action"})
	h.rvGap = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_controllerhygiene_rv_gap",
		Help: "Last observed rv_now - rv_cache on the local apiserver.",
	})
	h.kineConns = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_controllerhygiene_kine_db_conns",
		Help: "Kine process TCP connections to the datastore port.",
	})
	h.oomWindow = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_controllerhygiene_oom_kills_window",
		Help: "memcg OOM kills inside the sliding window.",
	})
	h.feeding = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_controllerhygiene_feeder_feeding",
		Help: "1 while the feeder sends WATCHDOG=1 to systemd.",
	})
	h.etcdDBSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_controllerhygiene_etcd_db_size_bytes",
		Help: "Embedded-etcd DB file size from the last etcdctl " +
			"endpoint status probe (embedded-etcd controllers only).",
	})
	h.etcdDBUse = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_controllerhygiene_etcd_db_in_use_bytes",
		Help: "Embedded-etcd DB size in use from the last etcdctl " +
			"endpoint status probe (embedded-etcd controllers only).",
	})
	h.etcdNospace = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_controllerhygiene_etcd_nospace_alarm",
		Help: "1 while the embedded etcd carries a NOSPACE alarm " +
			"(embedded-etcd controllers only).",
	})

	if reg != nil {
		for _, c := range []prometheus.Collector{
			h.cycles, h.actions, h.rvGap, h.kineConns, h.oomWindow, h.feeding,
			h.etcdDBSize, h.etcdDBUse, h.etcdNospace,
		} {
			if err := reg.Register(c); err != nil {
				return nil, fmt.Errorf("register controllerhygiene metrics: %w", err)
			}
		}
	}
	h.initChecks()
	return h, nil
}

// Name identifies the subsystem for logging.
func (h *Hygiene) Name() string { return "controllerhygiene" }

// feederActive reports whether the sd_notify feeder loop should run:
// enabled AND a notify path exists (injected seam or NOTIFY_SOCKET).
func (h *Hygiene) feederActive() bool {
	return h.cfg.Feeder.Enabled && h.cfg.notifyFn != nil
}

// Run starts the feeder goroutine (when active), checks immediately,
// then cycles every Interval until ctx is cancelled.
func (h *Hygiene) Run(ctx context.Context) {
	if !h.cfg.Enabled {
		// Constructed but disabled — idle instead of returning: the
		// agent restarts a returned Run in a hot loop.
		cycle.Idle(ctx)
		return
	}
	if h.feederActive() {
		h.feederOnce.Do(func() {
			go func() {
				// agent.go's panic recovery only wraps sub.Run —
				// a panic in this spawned goroutine would take the
				// whole daemon down. Recover and die loudly
				// instead: WATCHDOG=1 stops, so the unit's own
				// watchdog fires (the shell exit-1 → OnFailure
				// equivalence).
				defer func() {
					if r := recover(); r != nil {
						h.state.AppendLogWarn(fmt.Sprintf(
							"feeder: PANIC %v — feeder dead, WATCHDOG=1 stops (agent kept alive)", r))
					}
				}()
				h.runFeeder(ctx)
			}()
		})
	}
	cycle.Every("controllerhygiene", h.cfg.Interval, h.runCycle).Run(ctx)
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
	cctx, cancel := context.WithTimeout(ctx, h.cfg.CycleTimeout)
	defer cancel()
	h.Cycle(cctx)
	if errors.Is(cctx.Err(), context.DeadlineExceeded) {
		h.state.AppendLogWarn(fmt.Sprintf(
			"controllerhygiene: cycle deadline %s exceeded — "+
				"stalled check(s) aborted", h.cfg.CycleTimeout))
	}
}

// initChecks builds the ordered dispatch table Cycle drives — the
// workerhygiene initChecks pattern. Order + grouping are
// load-bearing: the 60s-timer guards (kine pool, OOM loop) had no
// uptime gate in shell and run first; only the module-22 checks
// carried WD_REQUIRES: uptime. The controllerhygiene checks carry
// no WD_SIG kill switch (the shell timers had none) — Dispatch gets
// a nil sigOn and every entry runs.
func (h *Hygiene) initChecks() {
	h.groups = []checks.Group{
		{
			Entries: []checks.Entry{
				{Name: checkKinePool, Run: h.checkKinePool},
				{Name: checkOOMLoop, Run: h.checkOOMLoop},
				// etcdguard is in the ungated group like
				// kine-pool/oomloop — an embedded etcd that hit
				// quota during boot needs the guard BEFORE the
				// 20min wedge grace, and hosts without etcdctl
				// no-op.
				{Name: checkEtcd, Run: h.checkEtcdQuota},
				// W8-CP3/CP4 are ungated like the 60s-timer
				// guards: a frozen KCM/scheduler or a stale PKI
				// reload must not wait out the module-22 boot
				// grace — both probes are read-only until their
				// own consecutive-cycle + rate budgets pass.
				{Name: checkCPFreeze, Run: h.checkCPFreeze},
				{Name: checkPKIDrift, Run: h.checkPKIReloadDrift},
			},
		},
		{
			// WD_REQUIRES: uptime unit:k0scontroller — 20min
			// grace after boot before the destructive wedge/TTL
			// checks. The skip counts ONCE under checkHub —
			// the label the gated cycle always reported.
			GateOK:    h.uptimeOK,
			GateLabel: checkHub,
			Entries: []checks.Entry{
				{Name: checkHub, Run: h.checkApiserverHub},
				{Name: checkKineTTL, Run: h.checkKineTTL},
			},
		},
	}
}

// uptimeOK is the module-22 WD_REQUIRES:uptime group gate — a
// /proc read error opens it (the shell's numeric test on an empty
// UPTIME failed open the same way: the module ran).
func (h *Hygiene) uptimeOK() bool {
	up, err := h.proc.UptimeSeconds()
	return err != nil || up >= minUptimeSeconds
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
	defer h.state.StampLastRun()
	if _, err := os.Stat(h.cfg.K0sControllerUnitFile); err != nil {
		h.cycles.WithLabelValues("all", "gated").Inc()
		return
	}
	_ = os.MkdirAll(h.cfg.WatchdogStateDir, 0o755)
	// BUG-H9: hostconfig rewrites /etc/node-watchdog.conf mid-run —
	// refresh the conf-derived knobs before the checks consume them.
	h.refreshWatchdogConf()
	checks.Dispatch(ctx, nil, h.cycles, h.groups)
}

// refreshWatchdogConf re-applies the watchdogconf-derived knobs each
// cycle when WatchdogSrc is wired (BUG-H9 — nethealth's per-cycle
// WatchdogSrc.Get parity). The conf is one of several config sources:
// an env-set or programmatic knob must survive a conf rewrite, so a
// field only moves when it still carries the value the PREVIOUS conf
// parse produced (wdApplied). Empty conf keys derive to the package
// default — the same ${VAR:-def} fallback main's envOr chain applied
// at construction.
func (h *Hygiene) refreshWatchdogConf() {
	if h.cfg.WatchdogSrc == nil {
		return
	}
	wd := h.cfg.WatchdogSrc.Get()
	if wd == nil || wd == h.wdApplied {
		return
	}
	old := h.wdApplied
	if old == nil {
		old, _ = watchdogconf.Parse(nil)
	}
	// Each knob only moves when it still carries the previous
	// conf-derived value — a knob set from elsewhere (env wiring)
	// keeps its override.
	apply := func(prev, next string, set func(string), cur func() string) {
		if cur() == prev {
			set(next)
		}
	}
	// Strings.
	apply(old.APISelf, wd.APISelf, func(v string) { h.cfg.Hub.SelfAPI = v },
		func() string { return h.cfg.Hub.SelfAPI })
	apply(old.APIPeer, wd.APIPeer, func(v string) { h.cfg.Hub.PeerAPI = v },
		func() string { return h.cfg.Hub.PeerAPI })
	apply(old.KineDBProbe, wd.KineDBProbe, func(v string) { h.cfg.Hub.KineDBProbe = v },
		func() string { return h.cfg.Hub.KineDBProbe })
	apply(old.Sig13Autofix, wd.Sig13Autofix, func(v string) {
		if v != "" {
			h.cfg.Sig13.Mode = v
		}
	}, func() string { return h.cfg.Sig13.Mode })
	apply(old.KineTTLAutofix, wd.KineTTLAutofix, func(v string) {
		if v != "" {
			h.cfg.KineTTL.Mode = v
		}
	}, func() string { return h.cfg.KineTTL.Mode })
	apply(old.KinePoolAutofix, wd.KinePoolAutofix, func(v string) {
		if v != "" {
			h.cfg.KinePool.Mode = v
		}
	}, func() string { return h.cfg.KinePool.Mode })
	apply(old.OOMLoopAutofix, wd.OOMLoopAutofix, func(v string) {
		if v != "" {
			h.cfg.OOMLoop.Mode = v
		}
	}, func() string { return h.cfg.OOMLoop.Mode })
	// Ints — conf 0 derives to the package default.
	intOf := func(v, def int) int {
		if v > 0 {
			return v
		}
		return def
	}
	applyI := func(prevV, nextV int, set func(int), cur func() int) {
		if cur() == prevV {
			set(nextV)
		}
	}
	applyI(intOf(old.Sig13StaleMinErrs, defaultStaleMinErrs),
		intOf(wd.Sig13StaleMinErrs, defaultStaleMinErrs),
		func(v int) { h.cfg.Sig13.StaleMinErrs = v },
		func() int { return h.cfg.Sig13.StaleMinErrs })
	applyI(intOf(old.Sig13SoloCycles, defaultSoloCycles),
		intOf(wd.Sig13SoloCycles, defaultSoloCycles),
		func(v int) { h.cfg.Sig13.SoloCycles = v },
		func() int { return h.cfg.Sig13.SoloCycles })
	applyI(intOf(old.Sig13GapCycles, defaultGapCycles),
		intOf(wd.Sig13GapCycles, defaultGapCycles),
		func(v int) { h.cfg.Sig13.GapCycles = v },
		func() int { return h.cfg.Sig13.GapCycles })
	applyI(intOf(old.Sig13FrozenCycles, defaultFrozenCycles),
		intOf(wd.Sig13FrozenCycles, defaultFrozenCycles),
		func(v int) { h.cfg.Sig13.FrozenCycles = v },
		func() int { return h.cfg.Sig13.FrozenCycles })
	applyI(intOf(old.KineTTLRewedgeCycle, defaultTTLRewedgeCycles),
		intOf(wd.KineTTLRewedgeCycle, defaultTTLRewedgeCycles),
		func(v int) { h.cfg.KineTTL.RewedgeCycles = v },
		func() int { return h.cfg.KineTTL.RewedgeCycles })
	applyI(intOf(old.KinePoolMaxConns, defaultPoolMaxConns),
		intOf(wd.KinePoolMaxConns, defaultPoolMaxConns),
		func(v int) { h.cfg.KinePool.MaxConns = v },
		func() int { return h.cfg.KinePool.MaxConns })
	applyI(intOf(old.KinePoolCycles, defaultPoolCycles),
		intOf(wd.KinePoolCycles, defaultPoolCycles),
		func(v int) { h.cfg.KinePool.Cycles = v },
		func() int { return h.cfg.KinePool.Cycles })
	applyI(intOf(old.OOMLoopMinKills, defaultOOMMinKills),
		intOf(wd.OOMLoopMinKills, defaultOOMMinKills),
		func(v int) { h.cfg.OOMLoop.MinKills = v },
		func() int { return h.cfg.OOMLoop.MinKills })
	// int64.
	apply64 := func(prevV, nextV int64, set func(int64), cur func() int64) {
		if cur() == prevV {
			set(nextV)
		}
	}
	i64 := func(v int64, def int64) int64 {
		if v > 0 {
			return v
		}
		return def
	}
	apply64(i64(old.Sig13GapMin, defaultGapMin),
		i64(wd.Sig13GapMin, defaultGapMin),
		func(v int64) { h.cfg.Sig13.GapMin = v },
		func() int64 { return h.cfg.Sig13.GapMin })
	// Durations — conf seconds 0 derives to the package default.
	dur := func(v int, def time.Duration) time.Duration {
		if v > 0 {
			return time.Duration(v) * time.Second
		}
		return def
	}
	applyD := func(prevV, nextV time.Duration, set func(time.Duration), cur func() time.Duration) {
		if cur() == prevV {
			set(nextV)
		}
	}
	applyD(dur(old.Sig13MinRestartS, defaultMinRestart),
		dur(wd.Sig13MinRestartS, defaultMinRestart),
		func(v time.Duration) { h.cfg.Sig13.MinRestart = v },
		func() time.Duration { return h.cfg.Sig13.MinRestart })
	applyD(dur(old.KineTTLMinRestartS, defaultTTLMinRestart),
		dur(wd.KineTTLMinRestartS, defaultTTLMinRestart),
		func(v time.Duration) { h.cfg.KineTTL.MinRestart = v },
		func() time.Duration { return h.cfg.KineTTL.MinRestart })
	applyD(dur(old.KineTTLCtlRestartS, defaultTTLCtlRestart),
		dur(wd.KineTTLCtlRestartS, defaultTTLCtlRestart),
		func(v time.Duration) { h.cfg.KineTTL.CtlRestart = v },
		func() time.Duration { return h.cfg.KineTTL.CtlRestart })
	applyD(dur(old.KinePoolMinRestartS, defaultPoolMinRestart),
		dur(wd.KinePoolMinRestartS, defaultPoolMinRestart),
		func(v time.Duration) { h.cfg.KinePool.MinRestart = v },
		func() time.Duration { return h.cfg.KinePool.MinRestart })
	applyD(dur(old.OOMLoopWindowS, defaultOOMWindow),
		dur(wd.OOMLoopWindowS, defaultOOMWindow),
		func(v time.Duration) { h.cfg.OOMLoop.Window = v },
		func() time.Duration { return h.cfg.OOMLoop.Window })
	h.wdApplied = wd
}

// --- /proc helpers ---
// The /proc reads live in platform/procfs (h.proc): pid-dir
// listing, cmdline/comm reads, stat parsing (pid age, PPID) and
// the pgrep -x | head -1 lowest-pid comm lookup.

// --- satellite files ---
// config.go     : the Config surface — the flat wiring knobs, the
//                 per-domain sub-config groups (Hub/Sig13/KineTTL/
//                 KinePool/OOMLoop/Feeder/EtcdGuard/CPFreeze/
//                 PKIDrift) and applyDefaults (package defaults +
//                 the injectable seam defaults)
// state.go      : the on-disk bookkeeping helpers Store does not
//                 cover — stateExit's suspect-budget drop and the
//                 raw-text readState/writeState for non-epoch files
// journal.go    : journalText + the journal-unreadable blindness
//                 accounting (classifyJournalRead/noteJournalRead)
// exec.go       : the host-exec/env plumbing — scrubSystemdEnv,
//                 scrubArgv, hostExecCtx (the nil-tolerant
//                 systemd.Client wrapper every host command's seam
//                 default routes through), sdNotify
// probes.go     : pgWireOK (the HTTP probes moved to platform/probee)
// kubeclient.go : apiserver credential loading + the rv LIST probe
//                 (ensureClient/buildClient/loadCreds/resolveRel/
//                 credFingerprint/listRV)
// etcdguard.go  : embedded-etcd quota self-defence (checkEtcdQuota,
//                 etcdStatus, etcdNospaceArmed, guardLogWriter)
// All external interactions stay behind the Config seams — only the
// default implementations moved.
