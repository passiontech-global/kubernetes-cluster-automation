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
//   - systemctl invocations go through injectable funcs defaulting to
//     `systemctl` exec with NOTIFY_SOCKET/WATCHDOG_* scrubbed from the
//     child env (the journal-spam fix the shell feeder applied).
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
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/ops/etcdrescue"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/ops/evpurge"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/cycle"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/journalwatch"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/procfs"
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

	// etcdguard (embedded-etcd quota self-defence — cicd
	// controllers; kine hosts lack <K0sDir>/bin/etcdctl and no-op).
	defaultK0sDir          = "/host/var/lib/k0s" // DaemonSet host mount
	defaultEtcdEndpoint    = "https://127.0.0.1:2379"
	defaultEtcdDBSizeLimit = int64(1610612736) // 1.5 GiB
	defaultEtcdGuardMinRun = time.Hour         // last-etcd-guard budget
	defaultEtcdctlBudget   = 60 * time.Second  // ctx cap per etcdctl call
	etcdctlCmdTimeout      = "30s"             // etcdctl --command-timeout
	// Bound on the whole evpurge+rescue remediation block: evpurge
	// is unbounded pagination + delete work at the apiserver's pace
	// and the rescue is ~12 sequential etcdctl calls — driven by
	// the process-lifetime ctx, a degraded backend could stall one
	// (synchronous) cycle for hours. Both steps are idempotent and
	// last-etcd-guard is spent up front, so exhausting this only
	// defers the remainder to the next EtcdGuardMinRun window.
	defaultEtcdGuardBudget = 10 * time.Minute
	// Each rescue-spawned command gets a far shorter cap than
	// etcdrescue's defaultCallTimeout (10m — sized for an operator
	// at a shell): ~12 sequential calls then stay near the guard
	// budget instead of ~2h.
	defaultEtcdGuardCallTimeout = time.Minute
	// eventStaleAge is the apiserver's own 1h event TTL — anything
	// older is GC debt the purge may safely delete (fresh, debuggable
	// events survive the guard's evpurge pass).
	eventStaleAge = time.Hour
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
	checkEtcd     = "etcd-quota"
	// checkJournal is the pseudo-check label the journal-unreadable
	// blindness accounting counts under — journald readability is a
	// cross-cutting witness, not one of the gated checks.
	checkJournal = "journal"
)

// State latch names — identical to the shell signal names (NPD +
// prom_emit contract, node_watchdog_state{signal=...}).
const (
	stateCacheStale       = "apiserver-cache-stale"
	stateCacheWedged      = "apiserver-cache-wedged"
	stateKineUnreachable  = "kine-backend-unreachable"
	stateKinePoolRunaway  = "kine-pool-runaway"
	stateKineTTLDead      = "kine-ttl-dead"
	stateKineTTLLoop      = "kine-ttl-loop"
	stateControllerOOMLop = "k0scontroller-oom-loop"
	// stateJournalUnreadable latches while journal reads keep
	// producing nothing although journal storage exists — every
	// journal-grep check is blind until it clears (suspectLog's
	// last-suspect- budget drops with the latch via stateExit).
	stateJournalUnreadable = "journal-unreadable"
	// W8-CP3 latch: a KCM/scheduler component frozen while the peer
	// apiserver stays healthy.
	stateCPComponentFrozen = "cp-component-frozen"
	// W8-CP4 latch: an on-disk PKI cert newer than what the live
	// socket presents — the daemon never reloaded the rotated cert.
	statePKIReloadStale = "cp-cert-reload-stale"
)

// On-disk bookkeeping file names under WatchdogStateDir — same names
// as the shell scripts so concurrent shell pieces share the budget.
const (
	fileRateRestart   = "last-sig13-restart" // shared restart budget
	fileRateTTLKill   = "last-ttl-restart"
	fileRatePoolKill  = "last-kinepool-kill"
	fileRateEtcdGuard = "last-etcd-guard" // evpurge+rescue budget
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
	// nil → evpurge.Run / etcdrescue.Run.
	evpurgeRunFn func(ctx context.Context, cfg evpurge.Config,
		cutoff time.Time, out io.Writer) error
	etcdRescueFn func(ctx context.Context, cfg etcdrescue.Config,
		out io.Writer) error
	// journalAnyFn is the unfiltered second probe used to classify an
	// empty unit-window read — `journalctl -n 1 --no-pager` with
	// stderr folded in. A quiet unit on a healthy journald must NOT
	// count as blindness; only when journald itself has nothing (or
	// only "No journal files") to say does the empty window count.
	// nil → journalctlAny.
	journalAnyFn func(ctx context.Context) (string, error)

	// --- injectable seams for W8 additions (defaults follow) ---
	// ssKillFn runs `ss -K sport = :6443` — kills hung HTTP/2 watch
	// streams before a wedge restart (W8-CP1).
	ssKillFn func(ctx context.Context) error
	// cpHealthFn is the KCM/scheduler healthz probe: true on a 2xx
	// response. nil → probeHTTP2xx.
	cpHealthFn func(ctx context.Context, url string) bool
	// kcmMetricsFn fetches the KCM /metrics body (leader-without-
	// workers evidence). nil → httpGET insecure.
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
// dbSize >= DBSizeLimit → evpurge + ONLINE-ONLY etcd rescue under the
// last-etcd-guard budget (the offline defrag stops k0scontroller and
// stays a manual action).
type EtcdGuardConfig struct {
	Endpoint    string // "" → https://127.0.0.1:2379
	DBSizeLimit int64  // dbSize trigger bytes; <=0 → 1.5 GiB
	// MinRun is the evpurge+rescue rate budget; <=0 → 1h.
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
	if c.journalFn == nil {
		c.journalFn = journalctl
	}
	if c.journalAnyFn == nil {
		c.journalAnyFn = journalctlAny
	}
	if c.pgWireFn == nil {
		c.pgWireFn = pgWireOK
	}
	if c.restartFn == nil {
		c.restartFn = func(ctx context.Context, unit string) error {
			// The remediate gate used `timeout 90` — the restart
			// keeps its own 90s budget, not the 10s query cap (a
			// 10s clamp SIGKILLed a slow restart mid-flight and
			// logged FAIL while systemd finished asynchronously).
			_, err := systemctl(ctx, 90*time.Second, "restart", unit)
			return err
		}
	}
	if c.propFn == nil {
		c.propFn = func(ctx context.Context, unit, prop string) (string, error) {
			return systemctl(ctx, defaultSystemctlBudget,
				"show", unit, "-p", prop, "--value")
		}
	}
	if c.isActive == nil {
		c.isActive = func(ctx context.Context, unit string) (string, error) {
			// is-active exits non-zero for inactive — the output is
			// the value, not an error (shell `|| true` parity).
			out, _ := systemctl(ctx, defaultSystemctlBudget, "is-active", unit)
			return out, nil
		}
	}
	if c.notifyFn == nil && c.Feeder.NotifySocket != "" {
		sock := c.Feeder.NotifySocket
		c.notifyFn = func(msg string) error { return sdNotify(sock, msg) }
	}
	if c.probeFn == nil {
		to := c.Feeder.ProbeTO
		c.probeFn = func(ctx context.Context, url string) bool {
			return probeAnyCode(ctx, url, to)
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
		c.evpurgeRunFn = evpurge.Run
	}
	if c.etcdRescueFn == nil {
		c.etcdRescueFn = etcdrescue.Run
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
			cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(cctx, "ss", "-K", "sport", "=", ":6443")
			cmd.Env = scrubSystemdEnv(os.Environ())
			out, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
			}
			return nil
		}
	}
	if c.cpHealthFn == nil {
		c.cpHealthFn = func(ctx context.Context, url string) bool {
			return probeHTTP2xx(ctx, url, 5*time.Second)
		}
	}
	if c.kcmMetricsFn == nil {
		c.kcmMetricsFn = func(ctx context.Context, url string) (string, error) {
			return httpGetInsecure(ctx, url, 8*time.Second)
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

// readState reads an arbitrary bookkeeping file under the state dir.
func (h *Hygiene) readState(name string) string {
	data, err := os.ReadFile(filepath.Join(h.cfg.WatchdogStateDir, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// removeStateFile deletes a bookkeeping file (ttl-last-wedged-pid etc.).
func removeStateFile(dir, name string) error {
	err := os.Remove(filepath.Join(dir, name))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// splitLines was removed: line iteration is done in place with
// strings.Cut at each call site — no intermediate []string on
// potentially multi-MiB journal/proc text.

// writeState writes a bookkeeping file under the state dir.
func (h *Hygiene) writeState(name, content string) {
	p := filepath.Join(h.cfg.WatchdogStateDir, name)
	if err := os.WriteFile(p, []byte(content+"\n"), 0o644); err != nil {
		logger().Warn("controllerhygiene: state file write failed",
			"path", p, "error", err)
	}
}

// --- /proc helpers ---
// The /proc reads live in platform/procfs (h.proc): pid-dir
// listing, cmdline/comm reads, stat parsing (pid age, PPID) and
// the pgrep -x | head -1 lowest-pid comm lookup.

// --- external interaction defaults (all behind Config seams) ---

// maxJournalBytes caps the journal text retained per read — a log
// storm between probe cycles must not push unbounded stdout into the
// agent's heap (the rest is drained and discarded so the child can
// still exit cleanly).
const maxJournalBytes = 16 << 20

// journalctl is the default journal reader: `timeout 15 journalctl -u
// <unit> --since <ts> --no-pager`. Output-only on error is NOT done
// here — callers map errors to empty text (grep -c == 0 parity).
func journalctl(ctx context.Context, unit string, since time.Time) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, defaultJournalTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "journalctl", "-u", unit,
		"--since", since.Format("2006-01-02 15:04:05"), "--no-pager")
	cmd.Env = scrubSystemdEnv(os.Environ())
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	// journald's own diagnostics ("No journal files were found.",
	// "File ... is corrupt") go to STDERR with exit 0 — a stdout-only
	// capture classifies a broken journald as a quiet unit and the
	// journal-unreadable latch never fires. Fold stderr in; the
	// bounded buffer is tiny because journald diagnostics are a few
	// lines (payload data is on stdout).
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return "", err
	}
	out, _ := io.ReadAll(io.LimitReader(stdout, maxJournalBytes))
	_, _ = io.Copy(io.Discard, stdout) // drain so Wait cannot deadlock
	if err := cmd.Wait(); err != nil {
		return "", err
	}
	return string(out) + stderr.String(), nil
}

// journalctlAny is the default unfiltered probe — `timeout 15
// journalctl -n 1 --no-pager` with stderr folded in: journald's own
// diagnostics ("No journal files were found.", "File ... is
// corrupt") are emitted on stderr, so a stdout-only capture cannot
// see them.
func journalctlAny(ctx context.Context) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, defaultJournalTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "journalctl", "-n", "1", "--no-pager")
	cmd.Env = scrubSystemdEnv(os.Environ())
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// journalText returns the unit journal since `since`, mapping errors
// to empty — `journalctl ... 2>/dev/null | grep -c` parity (a failed
// journal read counts as 0 hits, never as wedge evidence). Every
// read also feeds the journal-unreadable accounting: a journald that
// persistently answers nothing while journal storage exists blinds
// ALL journal-grep checks, and that blindness must latch+log, not
// stay a per-cycle warning line.
func (h *Hygiene) journalText(ctx context.Context, since time.Time) string {
	out, err := h.cfg.journalFn(ctx, h.cfg.JournalUnit, since)
	h.noteJournalRead(ctx, out, err)
	if err != nil {
		h.state.AppendLogWarn(fmt.Sprintf(
			"controllerhygiene: journal read failed (unit=%s): %v — journal checks see 0 hits",
			h.cfg.JournalUnit, err))
		return ""
	}
	return out
}

// classifyJournalRead reduces one journal-read result to the
// readable/unreadable verdict the tracker counts. A legitimately
// quiet unit window (err==nil, empty output) is ambiguous, so the
// unfiltered `journalctl -n 1` probe disambiguates — journald
// answering ANY line (even "-- No entries --") means the empty
// window was a quiet unit, while an error, a files-gone notice or
// literally zero bytes is journald-level blindness.
func (h *Hygiene) classifyJournalRead(ctx context.Context, out string, err error) (bool, string) {
	switch {
	case err != nil:
		return false, fmt.Sprintf("read failed: %v", err)
	case journalwatch.FilesGone(out):
		return false, "journalctl reports no journal files"
	case strings.TrimSpace(out) == "":
		uout, uerr := h.cfg.journalAnyFn(ctx)
		switch {
		case uerr != nil:
			return false, fmt.Sprintf("unfiltered probe failed: %v", uerr)
		case journalwatch.FilesGone(uout):
			return false, "journalctl reports no journal files"
		case strings.TrimSpace(uout) == "":
			return false, "journald-wide empty reply"
		}
	}
	return true, ""
}

// noteJournalRead feeds one classified journal read into the
// journal-unreadable tracker and drives the latch on transitions:
// enter → state-journal-unreadable + the suspect line (suspectLog
// then re-reminds at most once per SuspectLogCadence while the
// latch stays held); exit → STATE-EXIT. The journalDir gate lives
// inside the tracker — a host with no journal storage never fires.
func (h *Hygiene) noteJournalRead(ctx context.Context, out string, err error) {
	ok, detail := h.classifyJournalRead(ctx, out, err)
	enter, exit := h.journalReads.NoteRead(ok)
	// Re-establish after external removal: janitor's 24h reap or a
	// manual rm can delete the file while the tracker stays latched,
	// and `enter` won't fire twice per episode — without this the
	// latch/metric/condition go dark mid-episode.
	if enter || (h.journalReads.Latched() &&
		!h.state.Exists(stateJournalUnreadable)) {
		h.state.Enter(stateJournalUnreadable, detail)
		if enter {
			h.cycles.WithLabelValues(checkJournal, "journal_unreadable").Inc()
		}
	}
	if !ok && h.journalReads.Latched() {
		h.state.SuspectLog(stateJournalUnreadable, fmt.Sprintf(
			"suspect: journal-unreadable %s — %d consecutive journal "+
				"reads produced nothing while journal storage exists; "+
				"every journal-grep check is blind",
			detail, h.journalReads.Fails()), h.cfg.SuspectLogCadence)
	}
	if exit {
		h.stateExit(stateJournalUnreadable)
	}
}

// scrubSystemdEnv drops NOTIFY_SOCKET/WATCHDOG_* so child systemctl /
// journalctl processes cannot sd_notify back to our unit — the
// `env -u NOTIFY_SOCKET -u WATCHDOG_PID -u WATCHDOG_USEC` fix the
// feeder applies (systemd>=255 auto-sends EXIT_STATUS otherwise).
func scrubSystemdEnv(env []string) []string {
	out := env[:0]
	for _, e := range env {
		if strings.HasPrefix(e, "NOTIFY_SOCKET=") ||
			strings.HasPrefix(e, "WATCHDOG_PID=") ||
			strings.HasPrefix(e, "WATCHDOG_USEC=") {
			continue
		}
		out = append(out, e)
	}
	clear(env[len(out):]) // drop refs held by the filtered tail
	return out
}

// defaultSystemctlBudget caps the query-shaped systemctl calls —
// shell `timeout 10` parity.
const defaultSystemctlBudget = 10 * time.Second

// systemctl runs `timeout <budget> systemctl <args>` with the
// scrubbed env. The budget is a caller parameter, not a fixed 10s:
// the restart path needs its own 90s (an unconditional 10s wrap
// SIGKILLed a slow `systemctl restart` mid-flight — the unit still
// restarted asynchronously, but the gate logged FAIL).
func systemctl(ctx context.Context, budget time.Duration, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	cmd := exec.CommandContext(cctx, "systemctl", args...)
	cmd.Env = scrubSystemdEnv(os.Environ())
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// sdNotify sends msg as a datagram to the sd_notify unix socket —
// `systemd-notify WATCHDOG=1` parity without the binary. '@'-prefixed
// names are abstract sockets.
func sdNotify(sock, msg string) error {
	addr := sock
	if strings.HasPrefix(addr, "@") {
		addr = "\x00" + addr[1:]
	}
	conn, err := net.Dial("unixgram", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	// A wedged notify socket must not hang the feeder loop —
	// datagram writes are near-instant, so the deadline only covers
	// pathological socket states.
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte(msg))
	return err
}

// pgWireOK is the native-Go port of lib.sh pg_wire_ok: send a
// Postgres StartupMessage (user=postgres db=postgres, protocol 3.0)
// and check the first response byte — 'R' auth request / 'S' param
// status / 'N' notice / 'K' backend key = healthy; 'E' error, RST or
// timeout = broken (pgbouncer "server login has been failing").
func pgWireOK(ctx context.Context, hostport string) bool {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host, port = hostport, "5432"
	}
	d := net.Dialer{Timeout: 8 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	params := "user\x00postgres\x00database\x00postgres\x00\x00"
	msg := append([]byte{0, 3, 0, 0}, params...) // 196608 big-endian
	pkt := make([]byte, 4, 4+len(msg))
	binary.BigEndian.PutUint32(pkt, uint32(len(msg)+4)) // length incl. itself
	pkt = append(pkt, msg...)
	if _, err := conn.Write(pkt); err != nil {
		return false
	}
	b := make([]byte, 1)
	if _, err := io.ReadFull(conn, b); err != nil {
		return false
	}
	return strings.IndexByte(pgAuthOK, b[0]) >= 0
}

// probeClient is shared by every probeAnyCode call — a fresh
// Transport per probe would pin an idle connection (and its TLS
// buffers) on the apiserver between cycles. IdleConnTimeout bounds
// that pool (90s > the 60s cycle, so the conn is reused each probe).
var probeClient = func() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // mirrors curl -ks
	tr.IdleConnTimeout = 90 * time.Second
	return &http.Client{Transport: tr}
}()

// probeAnyCode is the default liveness probe: ANY HTTP response code
// means ALIVE — the shell targets a process-level wedge (event loop
// dead, no TLS accept), not readyz content. `curl -ks --max-time 5
// -o /dev/null -w '%{http_code}' != 000` parity.
func probeAnyCode(ctx context.Context, url string, timeout time.Duration) bool {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := probeClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return true
}

// --- apiserver credential loading + rv LIST probe ---

// ensureClient lazily builds the mTLS HTTP client the first time the
// credential source exists — the per-run `[ -f admin.crt ]` gate of
// the shell maps to "no client → hub checks skipped this cycle".
// The shell re-read the cert files EVERY probe; the client is rebuilt
// whenever the credential files' mtime/size fingerprint changes —
// caching a rotated cert forever would make post-rotation probes fail
// permanently and the dead-fallback could restart a healthy apiserver.
func (h *Hygiene) ensureClient() *http.Client {
	if h.cfg.HTTPClient != nil {
		return h.client // injected test seam — never rebuilt
	}
	fp := h.credFingerprint()
	if h.client != nil && fp == h.credFP {
		return h.client
	}
	c, err := h.buildClient()
	if err != nil {
		h.state.AppendLogWarn(fmt.Sprintf(
			"controllerhygiene: apiserver credential load failed: %v — wedge checks blind this cycle",
			err))
		return nil
	}
	if c == nil {
		return nil
	}
	if h.client != nil {
		h.client.CloseIdleConnections() // drop the rotated client's pool
	}
	h.client = c
	h.credFP = fp
	return c
}

// credFingerprint stamps mtime+size of every credential source file —
// a k0s admin.conf/cert rotation changes it and triggers a rebuild.
func (h *Hygiene) credFingerprint() string {
	var b strings.Builder
	for _, f := range []string{
		h.cfg.AdminKubeconfig, h.cfg.AdminCert, h.cfg.AdminKey, h.cfg.AdminCA,
	} {
		if fi, err := os.Stat(f); err == nil {
			fmt.Fprintf(&b, "%s:%x:%x;", f, fi.ModTime().UnixNano(), fi.Size())
		}
	}
	return b.String()
}

// buildClient loads client credentials from admin.conf (kubeconfig
// with embedded cert/key) or the admin.crt/admin.key + ca.crt triple,
// mirroring `curl -sk --cacert ca --cert crt --key key`.
func (h *Hygiene) buildClient() (*http.Client, error) {
	certPEM, keyPEM, caPEM, err := h.loadCreds()
	if err != nil || len(certPEM) == 0 || len(keyPEM) == 0 {
		return nil, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("admin client cert: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates:       []tls.Certificate{pair},
		InsecureSkipVerify: h.cfg.InsecureTLS, //nolint:gosec // mirrors curl -sk
	}
	if !h.cfg.InsecureTLS && len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("no certificates in CA data")
		}
		tlsCfg.RootCAs = pool
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	tr.IdleConnTimeout = 90 * time.Second
	return &http.Client{Transport: tr}, nil
}

// loadCreds resolves the admin client cert/key (+optional CA) PEM
// blocks: admin.conf kubeconfig first (embedded *-data fields, file
// refs resolved relative to the kubeconfig dir), then the flat
// cert/key/ca files.
func (h *Hygiene) loadCreds() (cert, key, ca []byte, err error) {
	if _, statErr := os.Stat(h.cfg.AdminKubeconfig); statErr == nil {
		kc, kerr := clientcmd.LoadFromFile(h.cfg.AdminKubeconfig)
		if kerr != nil {
			return nil, nil, nil, fmt.Errorf("load %s: %w", h.cfg.AdminKubeconfig, kerr)
		}
		for _, a := range kc.AuthInfos {
			if len(a.ClientCertificateData) > 0 {
				cert = a.ClientCertificateData
			} else if a.ClientCertificate != "" {
				// A kubeconfig that REFERENCES cert/key files and
				// cannot read them is not "no creds" — warn so the
				// blind-cycle no_creds result stays attributable.
				ref := resolveRel(h.cfg.AdminKubeconfig, a.ClientCertificate)
				if b, rerr := os.ReadFile(ref); rerr != nil {
					h.state.AppendLogWarn(fmt.Sprintf(
						"controllerhygiene: kubeconfig client-cert %s unreadable: %v",
						ref, rerr))
				} else {
					cert = b
				}
			}
			if len(a.ClientKeyData) > 0 {
				key = a.ClientKeyData
			} else if a.ClientKey != "" {
				ref := resolveRel(h.cfg.AdminKubeconfig, a.ClientKey)
				if b, rerr := os.ReadFile(ref); rerr != nil {
					h.state.AppendLogWarn(fmt.Sprintf(
						"controllerhygiene: kubeconfig client-key %s unreadable: %v",
						ref, rerr))
				} else {
					key = b
				}
			}
			if len(cert) > 0 && len(key) > 0 {
				break
			}
		}
		for _, cl := range kc.Clusters {
			if len(cl.CertificateAuthorityData) > 0 {
				ca = cl.CertificateAuthorityData
				break
			}
			if cl.CertificateAuthority != "" {
				if b, rerr := os.ReadFile(resolveRel(h.cfg.AdminKubeconfig, cl.CertificateAuthority)); rerr == nil {
					ca = b
					break
				}
			}
		}
		return cert, key, ca, nil
	}
	if _, statErr := os.Stat(h.cfg.AdminCert); statErr != nil {
		return nil, nil, nil, nil // not a controller / k0s not initialised
	}
	cert, err = os.ReadFile(h.cfg.AdminCert)
	if err != nil {
		return nil, nil, nil, err
	}
	key, err = os.ReadFile(h.cfg.AdminKey)
	if err != nil {
		return nil, nil, nil, err
	}
	if b, rerr := os.ReadFile(h.cfg.AdminCA); rerr == nil {
		ca = b
	}
	return cert, key, ca, nil
}

// resolveRel resolves a kubeconfig file reference relative to the
// kubeconfig's directory (clientcmd semantics for non-absolute paths).
func resolveRel(kubeconfig, ref string) string {
	if filepath.IsAbs(ref) {
		return ref
	}
	return filepath.Join(filepath.Dir(kubeconfig), ref)
}

// listRV returns the LIST-level resourceVersion of one apiserver
// endpoint — api_list_rv parity. cached=true → ?resourceVersion=0
// (watch-cache), cached=false → ?resourceVersion= (consistent read →
// storage backend). ok=false on any transport/HTTP/parse failure.
func (h *Hygiene) listRV(ctx context.Context, endpoint string, cached bool) (int64, bool) {
	if h.cfg.listRVFn != nil {
		return h.cfg.listRVFn(ctx, endpoint, cached)
	}
	client := h.ensureClient()
	if client == nil {
		return 0, false
	}
	q := "resourceVersion="
	if cached {
		q = "resourceVersion=0"
	}
	qctx, cancel := context.WithTimeout(ctx, h.cfg.QueryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(qctx, http.MethodGet,
		"https://"+endpoint+h.cfg.APIPath+"?"+q+"&limit=1", nil)
	if err != nil {
		return 0, false
	}
	resp, err := client.Do(req)
	if err != nil {
		logger().Warn("controllerhygiene: rv probe failed",
			"endpoint", endpoint, "cached", cached, "error", err,
		)
		return 0, false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, false
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		logger().Warn("controllerhygiene: rv probe non-200",
			"endpoint", endpoint, "cached", cached,
			"status", resp.StatusCode)
		return 0, false
	}
	var list struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return 0, false
	}
	rv, err := strconv.ParseInt(list.Metadata.ResourceVersion, 10, 64)
	if err != nil {
		return 0, false
	}
	return rv, true
}

// --- etcdguard: embedded-etcd quota self-defence ---
//
// The cicd cluster runs k0s embedded etcd; it once hit the backend
// quota (mvcc: database space exceeded — runbook
// k0s-etcd-rescue-runbook.md) while the remedy (evpurge + compact +
// defrag + alarm disarm) sat behind manual CLI commands. The guard
// automates that: every cycle on hosts whose K0sDir carries
// bin/etcdctl + pki/etcd/ca.crt (kine hosts have neither and no-op
// silently) it reads `endpoint status -w json` — plus `alarm list`
// while under the size trigger — and exports the db-size / nospace
// gauges. A NOSPACE alarm or dbSize >= EtcdDBSizeLimit spends the
// last-etcd-guard budget (EtcdGuardMinRun, 1h) on evpurge.Run +
// etcdrescue.Run with OnlineOnly, all inside a bounded ctx — the
// offline defrag stops k0scontroller and is NEVER a background
// action.

// checkEtcdQuota runs one etcdguard cycle.
func (h *Hygiene) checkEtcdQuota(ctx context.Context) {
	if _, err := os.Stat(filepath.Join(h.cfg.K0sDir, "bin", "etcdctl")); err != nil {
		h.cycles.WithLabelValues(checkEtcd, "no_etcdctl").Inc()
		return
	}
	if _, err := os.Stat(filepath.Join(h.cfg.K0sDir,
		"pki", "etcd", "ca.crt")); err != nil {
		h.cycles.WithLabelValues(checkEtcd, "no_etcd_pki").Inc()
		return
	}

	dbSize, dbUse, err := h.etcdStatus(ctx)
	if err != nil {
		// etcd unreachable — nothing measurable; the wedge/feeder
		// guards own the control-plane-down story.
		h.state.AppendLogWarn(fmt.Sprintf(
			"etcdguard: endpoint status failed (endpoint=%s): %v — quota check skipped",
			h.cfg.EtcdGuard.Endpoint, err))
		h.cycles.WithLabelValues(checkEtcd, "status_error").Inc()
		return
	}
	h.etcdDBSize.Set(float64(dbSize))
	h.etcdDBUse.Set(float64(dbUse))

	// The alarm-list probe only runs while dbSize is below the
	// trigger: over-limit the action decision is already made, so a
	// second etcdctl would only double the routine probe cost —
	// against a hung etcd each call can burn its whole command
	// timeout. A skipped probe leaves the nospace gauge at its last
	// value, the same "keep last, never force-clear a
	// possibly-armed alarm" semantics as a probe error.
	var nospace bool
	if dbSize < h.cfg.EtcdGuard.DBSizeLimit {
		ns, aerr := h.etcdNospaceArmed(ctx)
		if aerr != nil {
			// A failed alarm read must not hide a real alarm —
			// treat the size signal as authoritative this cycle,
			// surface the error once in the log, and LEAVE the
			// gauge at its last value.
			h.state.AppendLogWarn(fmt.Sprintf("etcdguard: alarm list failed: %v", aerr))
		} else if ns {
			nospace = true
			h.etcdNospace.Set(1)
		} else {
			h.etcdNospace.Set(0)
		}
	}

	var reason string
	switch {
	case nospace:
		reason = "nospace-alarm"
	case dbSize >= h.cfg.EtcdGuard.DBSizeLimit:
		reason = fmt.Sprintf("dbSize=%d>=%d", dbSize, h.cfg.EtcdGuard.DBSizeLimit)
	default:
		h.cycles.WithLabelValues(checkEtcd, "ok").Inc()
		return
	}

	if !h.state.RateOK(fileRateEtcdGuard,
		h.cfg.EtcdGuard.MinRun) {
		h.state.SuspectLog(checkEtcd, fmt.Sprintf(
			"etcdguard: %s but in guard cooldown (<%dm), skip",
			reason, int(h.cfg.EtcdGuard.MinRun.Minutes())),
			h.cfg.SuspectLogCadence)
		h.cycles.WithLabelValues(checkEtcd, "cooldown").Inc()
		return
	}
	h.state.AppendLog(fmt.Sprintf(
		"ACTION: etcdguard %s — evpurge stale events + ONLINE-ONLY "+
			"etcd rescue (offline defrag forbidden)", reason))
	// Budget spent before the action — a kill mid-rescue must not
	// allow a second run inside the window (feeder G6 parity).
	h.state.RateSpend(fileRateEtcdGuard)
	out := &guardLogWriter{h: h}

	// The whole remediation runs under a bounded ctx: evpurge is
	// unbounded pagination + delete work against a possibly
	// degraded apiserver and the rescue is ~12 sequential etcdctl
	// calls — on the process-lifetime ctx either could stall this
	// (synchronous) cycle for hours. Both steps are idempotent and
	// the rate budget was already spent, so exhausting the deadline
	// only defers the remainder to the next EtcdGuardMinRun window.
	gctx, gcancel := context.WithTimeout(ctx, defaultEtcdGuardBudget)
	defer gcancel()

	// Stale apiserver events are the classic quota-filler after a
	// control-plane outage — purge first so the rescue's compaction
	// has garbage to drop. Cutoff keeps the apiserver's own 1h event
	// TTL: only GC debt is deleted, fresh events survive.
	perr := h.cfg.evpurgeRunFn(gctx, evpurge.Config{
		API:      "https://" + h.cfg.Hub.SelfEndpoint,
		CAFile:   h.cfg.AdminCA,
		CertFile: h.cfg.AdminCert,
		KeyFile:  h.cfg.AdminKey,
	}, h.cfg.nowFn().Add(-eventStaleAge), out)
	out.flush()
	if perr != nil {
		// Logged on its own — a purge miss does NOT fail the cycle
		// when the quota-remediating step still lands below.
		h.state.AppendLogWarn(fmt.Sprintf("etcdguard: evpurge failed: %v", perr))
	}
	// remediated tracks the step that actually relieves the quota:
	// the online rescue (compact+defrag). evpurge only drops event
	// GC debt so the rescue has garbage to free — when the rescue
	// ran, its result IS the verdict, even if evpurge failed
	// upstream (the purge failure stays logged above either way).
	remediated := perr == nil
	// A dead gctx here means evpurge (or a cancelled parent) ate
	// the whole budget — spawn no further calls that can only fail;
	// the rescue is idempotent and retries in the next window.
	if gctx.Err() == nil {
		rerr := h.cfg.etcdRescueFn(gctx, etcdrescue.Config{
			K0sDir:   h.cfg.K0sDir,
			Endpoint: h.cfg.EtcdGuard.Endpoint,
			// OnlineOnly: this is background auto-maintenance — the
			// systemctl-stop + standalone-etcd defrag would take the
			// control plane down and stays a manual rescue-etcd
			// action.
			OnlineOnly: true,
			// The guard is a loop, not an operator: cap each spawned
			// command far below etcdrescue's interactive default
			// (defaultCallTimeout = 10m) so ~12 sequential calls
			// stay near the guard budget instead of ~2h.
			CallTimeout: defaultEtcdGuardCallTimeout,
		}, out)
		out.flush()
		if rerr != nil {
			h.state.AppendLogWarn(fmt.Sprintf("etcdguard: rescue incomplete: %v", rerr))
		}
		remediated = rerr == nil
	} else {
		// The budget died inside evpurge — the rescue never ran,
		// so the cycle is incomplete, not a clean ok.
		remediated = false
	}
	if errors.Is(gctx.Err(), context.DeadlineExceeded) {
		h.state.AppendLogWarn(fmt.Sprintf(
			"etcdguard: run budget (%s) exhausted — remaining steps "+
				"deferred to the next %s window",
			defaultEtcdGuardBudget, h.cfg.EtcdGuard.MinRun))
	}
	h.actions.WithLabelValues(checkEtcd, "evpurge_rescue").Inc()
	if remediated {
		h.cycles.WithLabelValues(checkEtcd, "ok").Inc()
	} else {
		h.cycles.WithLabelValues(checkEtcd, "remediate_error").Inc()
	}
}

// etcdStatus fetches `endpoint status -w json` and returns the db
// file size + in-use size of element[0] (same JSON shape
// etcdrescue.parseStatusJSON consumes).
func (h *Hygiene) etcdStatus(ctx context.Context) (dbSize, dbUse int64, err error) {
	b, err := h.cfg.etcdctlFn(ctx, "endpoint", "status", "-w", "json")
	if err != nil {
		return 0, 0, err
	}
	var arr []struct {
		Status struct {
			DBSize      int64 `json:"dbSize"`
			DBSizeInUse int64 `json:"dbSizeInUse"`
		} `json:"Status"`
	}
	if err := json.Unmarshal(b, &arr); err != nil {
		return 0, 0, fmt.Errorf("parse endpoint status: %w", err)
	}
	if len(arr) == 0 {
		return 0, 0, fmt.Errorf("parse endpoint status: empty endpoint list")
	}
	return arr[0].Status.DBSize, arr[0].Status.DBSizeInUse, nil
}

// etcdNospaceArmed reports whether `alarm list` carries a NOSPACE
// entry — the memberID:xxx alarm:NOSPACE grep the manual flow used.
func (h *Hygiene) etcdNospaceArmed(ctx context.Context) (bool, error) {
	b, err := h.cfg.etcdctlFn(ctx, "alarm", "list")
	if err != nil {
		return false, err
	}
	return strings.Contains(string(b), "NOSPACE"), nil
}

// guardLogWriter adapts the evpurge/etcdrescue io.Writer output to
// the watchdog log — each completed line lands as its own timestamped
// appendLog entry (the "<rfc3339> <msg>" filelog contract), prefixed
// so the sub-command output is attributable in the NPD tail.
type guardLogWriter struct {
	h   *Hygiene
	buf strings.Builder
}

func (w *guardLogWriter) Write(p []byte) (int, error) {
	w.buf.Write(p)
	for {
		s := w.buf.String()
		i := strings.IndexByte(s, '\n')
		if i < 0 {
			return len(p), nil
		}
		if line := strings.TrimSpace(s[:i]); line != "" {
			w.h.state.AppendLog("etcdguard: " + line)
		}
		w.buf.Reset()
		w.buf.WriteString(s[i+1:])
	}
}

// flush emits any trailing partial line — called after each sub-run
// so a stream ending without '\n' still reaches the log.
func (w *guardLogWriter) flush() {
	if line := strings.TrimSpace(w.buf.String()); line != "" {
		w.h.state.AppendLog("etcdguard: " + line)
	}
	w.buf.Reset()
}
