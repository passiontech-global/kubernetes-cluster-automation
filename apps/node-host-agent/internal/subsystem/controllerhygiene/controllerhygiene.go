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
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/etcdmaint"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/eventpurge"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/cycle"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/journalwatch"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/probee"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/watchdogconf"
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

// Config carries the subsystem knobs — all test-injectable. The
// domain groups nest the knobs by their env-prefix family
// (ConfigFromEnv fills them); shared paths/transport, the watchdog
// conf reloader and the private test seams stay flat.
type Config struct {
	Enabled  bool          // false → Run idles until ctx done
	Interval time.Duration // guard cycle cadence (60s)
	// CycleTimeout is the per-Cycle deadline Run applies around each
	// Cycle: every spawned command and HTTP probe is ctx-aware, so
	// a stalled check is aborted instead of starving the
	// restart-critical guards past this bound on any tick.
	// <=0 → defaultCycleTimeout (15m).
	CycleTimeout time.Duration
	// WatchdogStateDir holds state-*/last-*/consecutive-*/oomloop-*
	// files — the shared node-watchdog state dir contract.
	WatchdogStateDir string
	// WatchdogLogFile receives the appended "<rfc3339> <msg>" lines
	// (NPD filelog tails it — message text is a contract).
	WatchdogLogFile string
	ProcRoot        string // host /proc (hostPID pod or host binary)
	// K0sControllerUnitFile gates ALL checks (WD_REQUIRES:
	// unit:k0scontroller) — workers/test envs are a silent no-op.
	K0sControllerUnitFile string
	JournalUnit           string // journalctl -u <unit>
	RestartUnit           string // unit restarted by the wedge guard
	// K0sDir is the k0s data dir — etcdguard probes under it and the
	// PKI-drift default pairs derive from it. "" → /host/var/lib/k0s.
	K0sDir string
	// AdminKubeconfig is the k0s admin.conf (embedded client creds);
	// AdminCert/AdminKey/AdminCA are the fallback client-cert triple.
	AdminKubeconfig string
	AdminCert       string
	AdminKey        string
	AdminCA         string
	// InsecureTLS mirrors `curl -sk`; CA pinning only applies when
	// false. (Upstream k0s apiserver certs ALWAYS carry IP SAN
	// 127.0.0.1, so verify works against the loopback endpoint —
	// the missing-SAN caveat applies to the kubelet serving cert,
	// see workerhygiene, not to this one.)
	InsecureTLS       bool
	APIPath           string        // LIST path returning .metadata.resourceVersion
	QueryTimeout      time.Duration // per-query deadline
	SuspectLogCadence time.Duration
	// HTTPClient, when set, is used for ALL apiserver queries (rv
	// probes) and overrides the credential files — test seam.
	HTTPClient *http.Client
	// Systemd drives every host command the seam defaults spawn —
	// journalctl (journalFn/journalAnyFn), systemctl restart/show/
	// is-active (restartFn/propFn/isActive) and `ss -K` (ssKillFn) —
	// nsenter-wrapped to host PID 1's namespaces inside the
	// DaemonSet, so they act on the host's systemd, journald and
	// network namespace instead of the pod's (a container-side
	// journalctl reads the pod's empty journal view; a
	// container-side systemctl has no dbus socket). nil → the seam
	// defaults report "no systemd client wired" and the dependent
	// checks degrade (workerhygiene parity).
	Systemd *systemd.Client

	// JournalDirs are the host journal storage roots — the
	// journal-unreadable latch may only fire while at least one
	// exists (a host with no journald at all fails every read by
	// configuration, not by fault).
	JournalDirs []string
	// JournalUnreadableNeeded is the consecutive-failed-read budget
	// before state-journal-unreadable latches; <=0 → 5.
	JournalUnreadableNeeded int

	// WatchdogSrc, when set, re-reads /etc/node-watchdog.conf every
	// Cycle and re-applies the conf-derived knobs (API_SELF/API_PEER,
	// KINE_DB_PROBE, SIG13_*, KINE_TTL_*, KINE_POOL_*, K0S_OOMLOOP_*)
	// — hostconfig rewrites land next cycle instead of needing an
	// agent restart (nethealth's WatchdogSrc parity; BUG-H9). A knob
	// set from elsewhere (env wiring) is preserved: only fields that
	// still carry the PREVIOUS conf-derived value move to the new
	// one.
	WatchdogSrc *watchdogconf.Reloader

	// --- env-prefix groups (ConfigFromEnv resolves these) ---
	// Hub carries the apiserver-hub identity/probe knobs
	// (NODE_HOST_AGENT_API_SELF/API_PEER/KINE_DB_PROBE).
	Hub HubConfig
	// Sig13 is the sig13 apiserver watch-cache wedge guard
	// (NODE_HOST_AGENT_SIG13_*/STALE_MIN_ERRS/GAP_*/FROZEN_*/SOLO_*).
	Sig13 Sig13Config
	// KineTTL is the kine TTL dead/rewedge-loop kill guard
	// (NODE_HOST_AGENT_KINE_TTL_*).
	KineTTL KineTTLConfig
	// KinePool is the kine -> DB connection-spiral guard
	// (NODE_HOST_AGENT_KINE_POOL_*).
	KinePool KinePoolConfig
	// OOMLoop is the cgroup OOM-loop detector + shield
	// (NODE_HOST_AGENT_OOMLOOP_*).
	OOMLoop OOMLoopConfig
	// Feeder is the systemd watchdog feeder + remediate gates
	// (NODE_HOST_AGENT_ENABLE_FEEDER, NOTIFY_SOCKET passthrough).
	Feeder FeederConfig
	// EtcdGuard is the embedded-etcd quota self-defence
	// (NODE_HOST_AGENT_ETCD_*).
	EtcdGuard EtcdGuardConfig
	// CPFreeze is the W8-CP3 KCM/scheduler freeze auto-heal — no env
	// wiring; package defaults unless set programmatically.
	CPFreeze CPFreezeConfig
	// PKIDrift is the W8-CP4 on-disk-vs-served PKI cert drift check —
	// no env wiring; package defaults unless set programmatically.
	PKIDrift PKIDriftConfig

	// --- injectable seams (defaults follow) ---
	nowFn     func() time.Time
	sleepFn   func(d time.Duration)
	killFn    func(pid int, sig syscall.Signal) error
	listRVFn  func(ctx context.Context, endpoint string, cached bool) (rv int64, ok bool)
	journalFn func(ctx context.Context, unit string, since time.Time) (string, error)
	pgWireFn  func(ctx context.Context, hostport string) bool
	restartFn func(ctx context.Context, unit string) error
	propFn    func(ctx context.Context, unit, prop string) (string, error)
	isActive  func(ctx context.Context, unit string) (string, error)
	notifyFn  func(msg string) error
	probeFn   func(ctx context.Context, url string) bool
	// etcdctlFn runs `<K0sDir>/bin/etcdctl <certs> <args>` — the
	// etcdguard probe seam (default adds the apiserver-etcd-client
	// cert triple + --endpoints + --command-timeout; stdout-only —
	// stderr captured separately so -w json parses).
	etcdctlFn func(ctx context.Context, args ...string) ([]byte, error)
	// evpurgeRunFn / etcdRescueFn are the guard's remediation seams —
	// nil → eventpurge.Run / etcdmaint.Run.
	evpurgeRunFn func(ctx context.Context, cfg eventpurge.Config,
		cutoff time.Time, out io.Writer) error
	etcdRescueFn func(ctx context.Context, cfg etcdmaint.Config,
		out io.Writer) error
	// journalAnyFn is the unfiltered second probe used to classify an
	// empty unit-window read — `journalctl -n 1 --no-pager` with
	// stderr folded in. A quiet unit on a healthy journald must NOT
	// count as blindness; only when journald itself has nothing (or
	// only "No journal files") to say does the empty window count.
	// nil → the shared systemd client (hostExecCtx, ExecCombined).
	journalAnyFn func(ctx context.Context) (string, error)

	// --- injectable seams for W8 additions (defaults follow) ---
	// ssKillFn runs `ss -K sport = :6443` — kills hung HTTP/2 watch
	// streams before a wedge restart (W8-CP1).
	ssKillFn func(ctx context.Context) error
	// cpHealthFn is the KCM/scheduler healthz probe: true on a 2xx
	// response. nil → probee.HTTP2xx.
	cpHealthFn func(ctx context.Context, url string) bool
	// kcmMetricsFn fetches the KCM /metrics body (leader-without-
	// workers evidence). nil → probee.HTTPBodyInsecure.
	kcmMetricsFn func(ctx context.Context, url string) (string, error)
	// tlsCertFn returns the leaf certificate a TLS listener
	// presents. nil → tlsDialCert (InsecureSkipVerify — only the
	// presented cert is wanted, chain trust is irrelevant).
	tlsCertFn func(ctx context.Context, addr string) (*x509.Certificate, error)
}

// PKIDriftPair is one W8-CP4 check row: the on-disk cert file, the
// TLS listener that must already serve it, and the systemd unit a
// detected drift restarts.
type PKIDriftPair struct {
	CertFile string
	Addr     string
	Unit     string
}

// HubConfig carries the apiserver-hub identity/probe knobs — the
// NODE_HOST_AGENT_API_SELF / API_PEER / KINE_DB_PROBE env →
// watchdogconf → (empty) chain. SelfAPI deliberately has NO default:
// it is the first-hub ordering identity — solo/dead-fallback restarts
// gate on it being non-empty, and inventing 127.0.0.1 here would make
// every unconfigured controller believe it is the first hub.
type HubConfig struct {
	// SelfEndpoint is the apiserver probed for rv_cache/rv_now —
	// always the local listener (SELF_EP=127.0.0.1:6443).
	SelfEndpoint string
	// SelfAPI is API_SELF: this hub's apiserver "ip:port" used only
	// for deterministic first-hub ordering vs PeerAPI.
	SelfAPI string
	// PeerAPI is API_PEER: the other hub's apiserver "ip:port"; empty
	// = single-hub cluster (self always first).
	PeerAPI string
	// KineDBProbe is KINE_DB_PROBE "host:port" — pg-wire probe used
	// by the dead-fallback; empty disables it (veto preserved).
	KineDBProbe string
}

// Sig13Config is the sig13 apiserver watch-cache wedge guard — also
// the shared SIG13_AUTOFIX mode cp_freeze_heal and pki_cert_drift
// restart under. Fields resolve env → watchdogconf → package default.
type Sig13Config struct {
	Mode         string        // SIG13_AUTOFIX for k0scontroller restarts
	StaleMinErrs int           // journal errs/6min → apiserver-cache-stale
	GapMin       int64         // rv_now - rv_cache wedge threshold
	GapCycles    int           // consecutive gap-over-threshold → wedge
	FrozenCycles int           // consecutive identical rv_cache → wedge
	SoloCycles   int           // wedge cycles before first-hub may act alone
	MinRestart   time.Duration // SIG13_MIN_RESTART_S restart budget
}

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

// FeederConfig is the systemd watchdog feeder — sd_notify WATCHDOG=1
// gated on apiserver liveness — plus the remediate ordered gates.
// Active only when Enabled AND (NotifySocket non-empty or a notifyFn
// seam is injected) — in a pod without NOTIFY_SOCKET the feeder is
// inert.
type FeederConfig struct {
	Enabled      bool
	NotifySocket string        // sd_notify datagram address (env NOTIFY_SOCKET)
	Interval     time.Duration // probe/feed cadence
	MaxFail      int           // consecutive fails → remediate
	GraceFails   int           // fail budget before first success
	ProbeURL     string        // readyz-ish endpoint; any HTTP code = alive
	ProbeTO      time.Duration
	// StateDir holds the remediate rate-limit file (shell
	// STATE_DIR=/var/lib/k0s-systemd-watchdog).
	StateDir            string
	RemediateMinRestart time.Duration // G5 budget
	RemediateFreshGrace time.Duration // G3 fresh-start grace
	RemediatePeerFile   string        // PEER_APISERVER= override file
}

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

// CPFreezeConfig is the W8-CP3 KCM/scheduler freeze auto-heal. No env
// wiring — package defaults unless set programmatically.
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
}

// PKIDriftConfig is the W8-CP4 on-disk-vs-served PKI cert drift check.
// No env wiring — package defaults unless set programmatically.
type PKIDriftConfig struct {
	// Pairs pairs an on-disk cert with the socket that must present
	// it and the unit restarted on drift; nil → the four defaults
	// (apiserver.crt→:6443, konnectivity-server.crt→:8132,
	// etcd/server.crt→:2379 — all k0scontroller.service —
	// and /etc/kine/pki/server.crt→:2379 → kine.service). Paths may
	// use the $K0SDIR placeholder, resolved against Config.K0sDir.
	Pairs []PKIDriftPair
	// Cycles is the consecutive-newer-cycle gate (default 2);
	// RestartInterval the last-cp-cert-restart budget (default 1h).
	Cycles          int
	RestartInterval time.Duration
	// KinePKIDir prefixes the default kine cert path ("" →
	// "/host/etc/kine/pki").
	KinePKIDir string
}

func (c *Config) applyDefaults() {
	if c.Interval <= 0 {
		c.Interval = defaultInterval
	}
	if c.CycleTimeout <= 0 {
		c.CycleTimeout = defaultCycleTimeout
	}
	if c.WatchdogStateDir == "" {
		c.WatchdogStateDir = defaultStateDir
	}
	if c.WatchdogLogFile == "" {
		c.WatchdogLogFile = defaultLogFile
	}
	if c.ProcRoot == "" {
		c.ProcRoot = defaultProcRoot
	}
	if c.K0sControllerUnitFile == "" {
		c.K0sControllerUnitFile = defaultUnitFile
	}
	if c.JournalUnit == "" {
		c.JournalUnit = defaultJournalUnit
	}
	if c.RestartUnit == "" {
		c.RestartUnit = defaultRestartUnit
	}
	if c.Hub.SelfEndpoint == "" {
		c.Hub.SelfEndpoint = defaultSelfEndpoint
	}
	// SelfAPI deliberately has NO loopback default: it is the
	// first-hub ordering identity — solo/dead-fallback restarts gate
	// on it being non-empty, and inventing 127.0.0.1 here would make
	// every unconfigured controller believe it is the first hub.
	if c.AdminKubeconfig == "" {
		c.AdminKubeconfig = defaultKubeconfig
	}
	if c.AdminCert == "" {
		c.AdminCert = defaultAdminCert
	}
	if c.AdminKey == "" {
		c.AdminKey = defaultAdminKey
	}
	if c.AdminCA == "" {
		c.AdminCA = defaultAdminCA
	}
	if c.APIPath == "" {
		c.APIPath = defaultAPIPath
	}
	if c.QueryTimeout <= 0 {
		c.QueryTimeout = defaultQueryTimeout
	}
	if c.Sig13.Mode == "" {
		c.Sig13.Mode = ModeOff
	}
	if c.Sig13.StaleMinErrs <= 0 {
		c.Sig13.StaleMinErrs = defaultStaleMinErrs
	}
	if c.Sig13.GapMin <= 0 {
		c.Sig13.GapMin = defaultGapMin
	}
	if c.Sig13.GapCycles <= 0 {
		c.Sig13.GapCycles = defaultGapCycles
	}
	if c.Sig13.FrozenCycles <= 0 {
		c.Sig13.FrozenCycles = defaultFrozenCycles
	}
	if c.Sig13.SoloCycles <= 0 {
		c.Sig13.SoloCycles = defaultSoloCycles
	}
	if c.Sig13.MinRestart <= 0 {
		c.Sig13.MinRestart = defaultMinRestart
	}
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
	if c.Feeder.Interval <= 0 {
		c.Feeder.Interval = defaultFeedInterval
	}
	if c.Feeder.MaxFail <= 0 {
		c.Feeder.MaxFail = defaultFeedMaxFail
	}
	if c.Feeder.GraceFails <= 0 {
		c.Feeder.GraceFails = defaultFeedGraceFails
	}
	if c.Feeder.ProbeURL == "" {
		c.Feeder.ProbeURL = defaultFeedProbeURL
	}
	if c.Feeder.ProbeTO <= 0 {
		c.Feeder.ProbeTO = defaultFeedProbeTO
	}
	if c.Feeder.StateDir == "" {
		c.Feeder.StateDir = defaultFeederStateDir
	}
	if c.Feeder.RemediateMinRestart <= 0 {
		c.Feeder.RemediateMinRestart = defaultRemediateMinRst
	}
	if c.Feeder.RemediateFreshGrace <= 0 {
		c.Feeder.RemediateFreshGrace = defaultRemediateGrace
	}
	if c.Feeder.RemediatePeerFile == "" {
		c.Feeder.RemediatePeerFile = defaultPeerFile
	}
	if c.Feeder.NotifySocket == "" {
		c.Feeder.NotifySocket = os.Getenv("NOTIFY_SOCKET")
	}
	if c.nowFn == nil {
		c.nowFn = time.Now
	}
	if c.sleepFn == nil {
		c.sleepFn = time.Sleep
	}
	if c.killFn == nil {
		c.killFn = func(pid int, sig syscall.Signal) error {
			return syscall.Kill(pid, sig)
		}
	}
	sd := c.Systemd
	if c.journalFn == nil {
		// `timeout 15 journalctl -u <unit> --since <ts> --no-pager` —
		// routed through the shared client: nsenter-wrapped to the
		// HOST journald (the previous raw exec read the container's
		// journal view, empty in the DaemonSet), stderr folded in so
		// the corrupt/no-journal-files diagnostics stay visible to
		// classifyJournalRead, env-scrubbed via `env -u` argv
		// (scrubArgv — scrubSystemdEnv parity; the exec seam carries
		// no env slot) and bounded at 16MiB by hostexec's capture
		// cap (the old maxJournalBytes).
		c.journalFn = func(ctx context.Context, unit string, since time.Time) (string, error) {
			cctx, cancel := context.WithTimeout(ctx, defaultJournalTimeout)
			defer cancel()
			return hostExecCtx(cctx, sd, true, "journalctl",
				"-u", unit, "--since",
				since.Format(journalSinceLayout), "--no-pager")
		}
	}
	if c.journalAnyFn == nil {
		// `timeout 15 journalctl -n 1 --no-pager` — same routing as
		// journalFn: stderr folded in so journald's own diagnostics
		// ("No journal files were found.", "File ... is corrupt")
		// are visible to the empty-window classifier.
		c.journalAnyFn = func(ctx context.Context) (string, error) {
			cctx, cancel := context.WithTimeout(ctx, defaultJournalTimeout)
			defer cancel()
			return hostExecCtx(cctx, sd, true,
				"journalctl", "-n", "1", "--no-pager")
		}
	}
	if c.pgWireFn == nil {
		c.pgWireFn = pgWireOK
	}
	if c.restartFn == nil {
		c.restartFn = func(ctx context.Context, unit string) error {
			// The remediate gate's `timeout 90` budget survives as a
			// per-call ExecBounded — a tighter wrap SIGKILLed a slow
			// restart mid-flight while systemd finished
			// asynchronously and the gate logged FAIL. Routed
			// through the host exec so the restart reaches the HOST
			// systemd — the old raw exec had no dbus socket inside
			// the DaemonSet and could never work.
			_, err := hostExecCtxBounded(ctx, sd, true,
				defaultRestartBudget, "systemctl", "restart", unit)
			return err
		}
	}
	if c.propFn == nil {
		c.propFn = func(ctx context.Context, unit, prop string) (string, error) {
			cctx, cancel := context.WithTimeout(ctx, defaultSystemctlBudget)
			defer cancel()
			out, err := hostExecCtx(cctx, sd, false, "systemctl",
				"show", unit, "-p", prop, "--value")
			return strings.TrimSpace(out), err
		}
	}
	if c.isActive == nil {
		c.isActive = func(ctx context.Context, unit string) (string, error) {
			// is-active exits non-zero for inactive — the output is
			// the value, not an error (shell `|| true` parity).
			cctx, cancel := context.WithTimeout(ctx, defaultSystemctlBudget)
			defer cancel()
			out, _ := hostExecCtx(cctx, sd, false, "systemctl", "is-active", unit)
			return strings.TrimSpace(out), nil
		}
	}
	if c.notifyFn == nil && c.Feeder.NotifySocket != "" {
		sock := c.Feeder.NotifySocket
		c.notifyFn = func(msg string) error { return sdNotify(sock, msg) }
	}
	if c.probeFn == nil {
		to := c.Feeder.ProbeTO
		c.probeFn = func(ctx context.Context, url string) bool {
			return probee.HTTPAnyCode(ctx, url, to)
		}
	}
	if c.K0sDir == "" {
		c.K0sDir = defaultK0sDir
	}
	if c.EtcdGuard.Endpoint == "" {
		c.EtcdGuard.Endpoint = defaultEtcdEndpoint
	}
	if c.EtcdGuard.DBSizeLimit <= 0 {
		c.EtcdGuard.DBSizeLimit = defaultEtcdDBSizeLimit
	}
	if c.EtcdGuard.MinRun <= 0 {
		c.EtcdGuard.MinRun = defaultEtcdGuardMinRun
	}
	if c.SuspectLogCadence <= 0 {
		c.SuspectLogCadence = defaultSuspectLogCadence
	}
	if c.etcdctlFn == nil {
		k0sDir, endpoint := c.K0sDir, c.EtcdGuard.Endpoint
		bin := filepath.Join(k0sDir, "bin", "etcdctl")
		certArgs := []string{
			// The apiserver's etcd client certs — the same triple
			// rescue-etcd.sh uses (not the etcd server certs).
			"--cacert=" + filepath.Join(k0sDir, "pki", "etcd", "ca.crt"),
			"--cert=" + filepath.Join(k0sDir, "pki", "apiserver-etcd-client.crt"),
			"--key=" + filepath.Join(k0sDir, "pki", "apiserver-etcd-client.key"),
			"--endpoints=" + endpoint,
			"--command-timeout=" + etcdctlCmdTimeout,
		}
		c.etcdctlFn = func(ctx context.Context, args ...string) ([]byte, error) {
			argv := append(append([]string{}, certArgs...), args...)
			cctx, cancel := context.WithTimeout(ctx, defaultEtcdctlBudget)
			defer cancel()
			// Deliberately container-side, NOT the shared host exec:
			// bin is a hostPath-prefixed path (<hostRoot>/var/lib/k0s/
			// bin/etcdctl) that only exists in the pod's mount view —
			// an nsenter -m wrap would look for "/host/..." on the
			// host fs where it does not exist — and stderr must stay
			// a separate stream (below), which the hostexec seam
			// cannot express. The endpoint is loopback, reachable
			// because the DaemonSet is hostNetwork.
			cmd := exec.CommandContext(cctx, bin, argv...)
			// etcdctl >=3.7 warns "unrecognized environment variable
			// ETCDCTL_API" on stderr — v3 is the default API anyway.
			// stderr is kept separate because -w json output must
			// parse; CombinedOutput would poison the payload.
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			if err != nil {
				return out, fmt.Errorf("%w: %s", err,
					strings.TrimSpace(stderr.String()))
			}
			return out, nil
		}
	}
	if c.evpurgeRunFn == nil {
		c.evpurgeRunFn = eventpurge.Run
	}
	if c.etcdRescueFn == nil {
		c.etcdRescueFn = etcdmaint.Run
	}
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
	if c.PKIDrift.KinePKIDir == "" {
		c.PKIDrift.KinePKIDir = "/host/etc/kine/pki"
	}
	if c.PKIDrift.Pairs == nil {
		k0s := c.K0sDir
		c.PKIDrift.Pairs = []PKIDriftPair{
			{filepath.Join(k0s, "pki", "apiserver.crt"),
				"127.0.0.1:6443", "k0scontroller.service"},
			{filepath.Join(k0s, "pki", "konnectivity-server.crt"),
				"127.0.0.1:8132", "k0scontroller.service"},
			{filepath.Join(k0s, "pki", "etcd", "server.crt"),
				"127.0.0.1:2379", "k0scontroller.service"},
			{filepath.Join(c.PKIDrift.KinePKIDir, "server.crt"),
				"127.0.0.1:2379", "kine.service"},
		}
	} else {
		for i := range c.PKIDrift.Pairs {
			c.PKIDrift.Pairs[i].CertFile = strings.ReplaceAll(
				c.PKIDrift.Pairs[i].CertFile, "$K0SDIR", c.K0sDir)
		}
	}
	if c.PKIDrift.Cycles <= 0 {
		c.PKIDrift.Cycles = defaultPKIDriftCycles
	}
	if c.PKIDrift.RestartInterval <= 0 {
		c.PKIDrift.RestartInterval = defaultPKIRestartInterval
	}
	if c.ssKillFn == nil {
		c.ssKillFn = func(ctx context.Context) error {
			// `ss -K sport = :6443` is a HOST command — it drops the
			// apiserver's hung HTTP/2 watch streams in the host
			// network namespace, so it goes through the shared
			// client (host ss binary + host netns) rather than
			// relying on an ss binary inside the agent image (the
			// old raw exec only worked because the pod is
			// hostNetwork AND happened to carry ss).
			cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			out, err := hostExecCtx(cctx, sd, true,
				"ss", "-K", "sport", "=", ":6443")
			if err != nil {
				return fmt.Errorf("%w: %s", err, strings.TrimSpace(out))
			}
			return nil
		}
	}
	if c.cpHealthFn == nil {
		c.cpHealthFn = func(ctx context.Context, url string) bool {
			return probee.HTTP2xx(ctx, url, 5*time.Second)
		}
	}
	if c.kcmMetricsFn == nil {
		c.kcmMetricsFn = func(ctx context.Context, url string) (string, error) {
			return probee.HTTPBodyInsecure(ctx, url, 8*time.Second)
		}
	}
	if c.tlsCertFn == nil {
		c.tlsCertFn = tlsDialCert
	}
}

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

// Cycle runs one round of all four guards. The k0scontroller unit
// file gates everything (WD_REQUIRES: unit:k0scontroller). Each check
// must never panic and degrades to no-op on missing files.
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
	// The 60s-timer guards (kine pool, OOM loop) had no uptime gate in
	// shell — they run immediately. Only the module-22 checks carried
	// WD_REQUIRES: uptime.
	h.checkKinePool(ctx)
	h.checkOOMLoop(ctx)
	// etcdguard is in the ungated group like kine-pool/oomloop — an
	// embedded etcd that hit quota during boot needs the guard
	// BEFORE the 20min wedge grace, and hosts without etcdctl no-op.
	h.checkEtcdQuota(ctx)
	// W8-CP3/CP4 are ungated like the 60s-timer guards: a frozen
	// KCM/scheduler or a stale PKI reload must not wait out the
	// module-22 boot grace — both probes are read-only until their
	// own consecutive-cycle + rate budgets pass.
	h.checkCPFreeze(ctx)
	h.checkPKIReloadDrift(ctx)
	// uptime gate (WD_REQUIRES: uptime unit:k0scontroller — 20min
	// grace after boot before the destructive wedge/TTL checks).
	if up, err := h.proc.UptimeSeconds(); err == nil && up < minUptimeSeconds {
		h.cycles.WithLabelValues(checkHub, "uptime_gate").Inc()
		return
	}
	h.checkApiserverHub(ctx)
	h.checkKineTTL(ctx)
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

// --- watchdog file helpers (lib.sh parity) ---
// state-<name>    : latch file, content = epoch of entry
// last-*          : rate-limit budget, content = epoch of last spend
// consecutive-*   : consecutive-fail counters (on-disk parity — the
//                   files are shared with still-deployed shell pieces)
// watchdog log    : "<rfc3339> <msg>" appended to WatchdogLogFile
//
// The on-disk contract itself lives in platform/hoststate — h.state
// is the single Store implementation of state_enter/state_exit,
// rate_ok/rate_spend, ctr_inc/ctr_read/ctr_reset, suspectLog's
// last-suspect-* budgets, the watchdog log append and the last-run
// stamp. The per-subsystem copies that used to live here are gone;
// what remains below is only what Store does not cover.

// stateExit removes state-<name> if present and logs the
// transition — the controllerhygiene divergence hoststate keeps
// behind Store.Exit's cleanup hook: the latch's last-suspect-<name>
// dedupe budget (hoststate.SuspectBudgetPrefix) is dropped with it,
// so a later re-entry logs a fresh first line instead of staying
// throttled by a stale epoch from the previous incident. The budget
// dir is the Store's own — the same dir h.state.SuspectLog spent it
// under.
func (h *Hygiene) stateExit(name string) {
	h.state.Exit(name, func() {
		_ = os.Remove(filepath.Join(h.state.Dir,
			hoststate.SuspectBudgetPrefix+name))
	})
}

// readState reads an arbitrary bookkeeping file under the Store's
// dir and returns its trimmed contents ("" on any error). Kept as a
// thin helper because Store has no "read raw text" equivalent —
// Store.Epoch collapses absent/garbage to int64 0, which would make
// an absent last-rvc/last-prvc file compare EQUAL to a real
// resourceVersion of 0; the string compare preserves the
// empty-vs-zero distinction the frozen-rv check needs.
func (h *Hygiene) readState(name string) string {
	data, err := os.ReadFile(filepath.Join(h.state.Dir, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// splitLines was removed: line iteration is done in place with
// strings.Cut at each call site — no intermediate []string on
// potentially multi-MiB journal/proc text.

// writeState writes "<content>\n" under the Store's dir, warn-only
// on error — kept for the one non-epoch bookkeeping file
// (oomloop-shielded, whose content is an empty line — Store only
// writes "<epoch>\n" via WriteEpochFile; epoch-valued files
// (last-rvc/last-prvc/ttl-last-wedged-pid/oomloop-seen) use
// h.state.WriteEpochFile directly).
func (h *Hygiene) writeState(name, content string) {
	p := filepath.Join(h.state.Dir, name)
	if err := os.WriteFile(p, []byte(content+"\n"), 0o644); err != nil {
		logger().Warn("controllerhygiene: state file write failed",
			"path", p, "error", err)
	}
}

// --- /proc helpers ---
// The /proc reads live in platform/procfs (h.proc): pid-dir
// listing, cmdline/comm reads, stat parsing (pid age, PPID) and
// the pgrep -x | head -1 lowest-pid comm lookup.

// --- satellite files ---
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
