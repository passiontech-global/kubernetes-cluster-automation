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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/client-go/tools/clientcmd"
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
	defaultInterval     = 60 * time.Second // merged timer cadence
	minUptimeSeconds    = 1200             // WD_REQUIRES: uptime
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
)

// Check names — prometheus `check` label + log context.
const (
	checkHub      = "apiserver-hub"
	checkKineTTL  = "kine-ttl"
	checkKinePool = "kine-pool"
	checkOOMLoop  = "oomloop"
	checkFeeder   = "feeder"
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
	clkTck            = 100.0          // getconf CLK_TCK on x86_64 Linux
	tcpStateListen    = "0A"
	pgAuthOK          = "RSNK"
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

// Config carries the subsystem knobs — all test-injectable.
type Config struct {
	Enabled  bool          // false → Run idles until ctx done
	Interval time.Duration // guard cycle cadence (60s)
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
	// SelfEndpoint is the apiserver probed for rv_cache/rv_now —
	// always the local listener (SELF_EP=127.0.0.1:6443).
	SelfEndpoint string
	// SelfAPI is API_SELF: this hub's apiserver "ip:port" used only
	// for deterministic first-hub ordering vs PeerAPI.
	SelfAPI string
	// PeerAPI is API_PEER: the other hub's apiserver "ip:port"; empty
	// = single-hub cluster (self always first).
	PeerAPI         string
	AdminKubeconfig string // k0s admin.conf (embedded client creds)
	AdminCert       string // fallback client-cert triple
	AdminKey        string
	AdminCA         string
	// InsecureTLS mirrors `curl -sk` (k0s apiserver certs do not
	// carry 127.0.0.1 SANs reliably); CA pinning only applies when
	// false.
	InsecureTLS  bool
	APIPath      string        // LIST path returning .metadata.resourceVersion
	QueryTimeout time.Duration // per-query deadline
	// Sig13Mode is SIG13_AUTOFIX for k0scontroller restarts.
	Sig13Mode          string
	StaleMinErrs       int           // journal errs/6min → apiserver-cache-stale
	GapMin             int64         // rv_now - rv_cache wedge threshold
	GapCycles          int           // consecutive gap-over-threshold → wedge
	FrozenCycles       int           // consecutive identical rv_cache → wedge
	SoloCycles         int           // wedge cycles before first-hub may act alone
	MinRestartInterval time.Duration // restart budget
	// KineDBProbe is KINE_DB_PROBE "host:port" — pg-wire probe used
	// by the dead-fallback; empty disables it (veto preserved).
	KineDBProbe string

	// KineTTLMode is KINE_TTL_AUTOFIX for kine process kills.
	KineTTLMode          string
	KineTTLMinRestart    time.Duration // fast-kill budget
	KineTTLCtlRestart    time.Duration // rewedge-loop probe-kill cadence
	KineTTLRewedgeCycles int           // distinct wedged pids → kine-ttl-loop
	KineTTLMinProcAge    time.Duration // pid must outlive seed window

	// KinePoolMode is KINE_POOL_AUTOFIX for pool-spiral kills.
	KinePoolMode       string
	KinePoolMaxConns   int           // conns-to-DB spiral threshold
	KinePoolCycles     int           // consecutive over-threshold → kill
	KinePoolMinRestart time.Duration // kill budget
	KineDBPortFallback int           // DB port when --endpoint has none

	// OOMLoopMode is K0S_OOMLOOP_AUTOFIX for the oom_score_adj shield.
	OOMLoopMode        string
	OOMLoopMinKills    int           // kills in window → loop
	OOMLoopWindow      time.Duration // sliding window
	CGroupEventsFile   string        // cgroup v2 memory.events
	APIServerShieldAdj int           // kube-apiserver protection
	KineShieldAdj      int           // kine sacrifice ranking

	// Feeder: sd_notify WATCHDOG=1 loop gated on apiserver liveness.
	// Active only when FeederEnabled AND (NotifySocket non-empty or a
	// notifyFn seam is injected) — in a pod without NOTIFY_SOCKET the
	// feeder is inert.
	FeederEnabled  bool
	NotifySocket   string        // sd_notify datagram address (env NOTIFY_SOCKET)
	FeedInterval   time.Duration // probe/feed cadence
	FeedMaxFail    int           // consecutive fails → remediate
	FeedGraceFails int           // fail budget before first success
	FeedProbeURL   string        // readyz-ish endpoint; any HTTP code = alive
	FeedProbeTO    time.Duration
	// FeederStateDir holds the remediate rate-limit file (shell
	// STATE_DIR=/var/lib/k0s-systemd-watchdog).
	FeederStateDir      string
	RemediateMinRestart time.Duration // G5 budget
	RemediateFreshGrace time.Duration // G3 fresh-start grace
	RemediatePeerFile   string        // PEER_APISERVER= override file

	// HTTPClient, when set, is used for ALL apiserver queries (rv
	// probes) and overrides the credential files — test seam.
	HTTPClient *http.Client

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
}

func (c *Config) applyDefaults() {
	if c.Interval <= 0 {
		c.Interval = defaultInterval
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
	if c.SelfEndpoint == "" {
		c.SelfEndpoint = defaultSelfEndpoint
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
	if c.Sig13Mode == "" {
		c.Sig13Mode = ModeOff
	}
	if c.StaleMinErrs <= 0 {
		c.StaleMinErrs = defaultStaleMinErrs
	}
	if c.GapMin <= 0 {
		c.GapMin = defaultGapMin
	}
	if c.GapCycles <= 0 {
		c.GapCycles = defaultGapCycles
	}
	if c.FrozenCycles <= 0 {
		c.FrozenCycles = defaultFrozenCycles
	}
	if c.SoloCycles <= 0 {
		c.SoloCycles = defaultSoloCycles
	}
	if c.MinRestartInterval <= 0 {
		c.MinRestartInterval = defaultMinRestart
	}
	if c.KineTTLMode == "" {
		c.KineTTLMode = ModeOff
	}
	if c.KineTTLMinRestart <= 0 {
		c.KineTTLMinRestart = defaultTTLMinRestart
	}
	if c.KineTTLCtlRestart <= 0 {
		c.KineTTLCtlRestart = defaultTTLCtlRestart
	}
	if c.KineTTLRewedgeCycles <= 0 {
		c.KineTTLRewedgeCycles = defaultTTLRewedgeCycles
	}
	if c.KineTTLMinProcAge <= 0 {
		c.KineTTLMinProcAge = defaultTTLMinProcAge
	}
	if c.KinePoolMode == "" {
		c.KinePoolMode = ModeOff
	}
	if c.KinePoolMaxConns <= 0 {
		c.KinePoolMaxConns = defaultPoolMaxConns
	}
	if c.KinePoolCycles <= 0 {
		c.KinePoolCycles = defaultPoolCycles
	}
	if c.KinePoolMinRestart <= 0 {
		c.KinePoolMinRestart = defaultPoolMinRestart
	}
	if c.KineDBPortFallback <= 0 {
		c.KineDBPortFallback = defaultDBPortFallback
	}
	if c.OOMLoopMode == "" {
		c.OOMLoopMode = ModeOff
	}
	if c.OOMLoopMinKills <= 0 {
		c.OOMLoopMinKills = defaultOOMMinKills
	}
	if c.OOMLoopWindow <= 0 {
		c.OOMLoopWindow = defaultOOMWindow
	}
	if c.CGroupEventsFile == "" {
		c.CGroupEventsFile = defaultCGroupEvents
	}
	// Shield adjs are non-zero in both directions; an explicit 0
	// would mean "shield to neutral" which is never what the loop
	// wants — treat unset as unset.
	if c.APIServerShieldAdj == 0 {
		c.APIServerShieldAdj = defaultAPIServerAdj
	}
	if c.KineShieldAdj == 0 {
		c.KineShieldAdj = defaultKineAdj
	}
	if c.FeedInterval <= 0 {
		c.FeedInterval = defaultFeedInterval
	}
	if c.FeedMaxFail <= 0 {
		c.FeedMaxFail = defaultFeedMaxFail
	}
	if c.FeedGraceFails <= 0 {
		c.FeedGraceFails = defaultFeedGraceFails
	}
	if c.FeedProbeURL == "" {
		c.FeedProbeURL = defaultFeedProbeURL
	}
	if c.FeedProbeTO <= 0 {
		c.FeedProbeTO = defaultFeedProbeTO
	}
	if c.FeederStateDir == "" {
		c.FeederStateDir = defaultFeederStateDir
	}
	if c.RemediateMinRestart <= 0 {
		c.RemediateMinRestart = defaultRemediateMinRst
	}
	if c.RemediateFreshGrace <= 0 {
		c.RemediateFreshGrace = defaultRemediateGrace
	}
	if c.RemediatePeerFile == "" {
		c.RemediatePeerFile = defaultPeerFile
	}
	if c.NotifySocket == "" {
		c.NotifySocket = os.Getenv("NOTIFY_SOCKET")
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
	if c.pgWireFn == nil {
		c.pgWireFn = pgWireOK
	}
	if c.restartFn == nil {
		c.restartFn = func(ctx context.Context, unit string) error {
			// The remediate gate used `timeout 90` — keep a bounded
			// budget for the restart itself.
			rctx, cancel := context.WithTimeout(ctx, 90*time.Second)
			defer cancel()
			_, err := systemctl(rctx, "restart", unit)
			return err
		}
	}
	if c.propFn == nil {
		c.propFn = func(ctx context.Context, unit, prop string) (string, error) {
			return systemctl(ctx, "show", unit, "-p", prop, "--value")
		}
	}
	if c.isActive == nil {
		c.isActive = func(ctx context.Context, unit string) (string, error) {
			// is-active exits non-zero for inactive — the output is
			// the value, not an error (shell `|| true` parity).
			out, _ := systemctl(ctx, "is-active", unit)
			return out, nil
		}
	}
	if c.notifyFn == nil && c.NotifySocket != "" {
		sock := c.NotifySocket
		c.notifyFn = func(msg string) error { return sdNotify(sock, msg) }
	}
	if c.probeFn == nil {
		to := c.FeedProbeTO
		c.probeFn = func(ctx context.Context, url string) bool {
			return probeAnyCode(ctx, url, to)
		}
	}
}

// Hygiene runs the controller guards on one ticker plus the feeder
// loop.
type Hygiene struct {
	cfg    Config
	client *http.Client // mTLS client for rv probes; nil when creds absent
	credFP string       // credential-file fingerprint the client was built from

	cycles    *prometheus.CounterVec // check, result
	actions   *prometheus.CounterVec // check, action
	rvGap     prometheus.Gauge
	kineConns prometheus.Gauge
	oomWindow prometheus.Gauge
	feeding   prometheus.Gauge
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
	h := &Hygiene{cfg: cfg}
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

	if reg != nil {
		for _, c := range []prometheus.Collector{
			h.cycles, h.actions, h.rvGap, h.kineConns, h.oomWindow, h.feeding,
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
	return h.cfg.FeederEnabled && h.cfg.notifyFn != nil
}

// Run starts the feeder goroutine (when active), checks immediately,
// then cycles every Interval until ctx is cancelled.
func (h *Hygiene) Run(ctx context.Context) {
	if !h.cfg.Enabled {
		// Constructed but disabled — idle instead of returning: the
		// agent restarts a returned Run in a hot loop.
		<-ctx.Done()
		return
	}
	if h.feederActive() {
		go h.runFeeder(ctx)
	}
	h.Cycle(ctx)
	t := time.NewTicker(h.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.Cycle(ctx)
		}
	}
}

// Cycle runs one round of all four guards. The k0scontroller unit
// file gates everything (WD_REQUIRES: unit:k0scontroller). Each check
// must never panic and degrades to no-op on missing files.
func (h *Hygiene) Cycle(ctx context.Context) {
	if _, err := os.Stat(h.cfg.K0sControllerUnitFile); err != nil {
		h.cycles.WithLabelValues("all", "gated").Inc()
		return
	}
	_ = os.MkdirAll(h.cfg.WatchdogStateDir, 0o755)
	// The 60s-timer guards (kine pool, OOM loop) had no uptime gate in
	// shell — they run immediately. Only the module-22 checks carried
	// WD_REQUIRES: uptime.
	h.checkKinePool(ctx)
	h.checkOOMLoop(ctx)
	// uptime gate (WD_REQUIRES: uptime unit:k0scontroller — 20min
	// grace after boot before the destructive wedge/TTL checks).
	if up, err := h.uptimeSeconds(); err == nil && up < minUptimeSeconds {
		h.cycles.WithLabelValues(checkHub, "uptime_gate").Inc()
		return
	}
	h.checkApiserverHub(ctx)
	h.checkKineTTL(ctx)
}

// --- watchdog file helpers (lib.sh parity) ---
// state-<name>    : latch file, content = epoch of entry
// last-*          : rate-limit budget, content = epoch of last spend
// consecutive-*   : consecutive-fail counters (on-disk parity — the
//                   files are shared with still-deployed shell pieces)
// watchdog log    : "<rfc3339> <msg>" appended to WatchdogLogFile

// appendLog mirrors lib.sh log(): "<date -Is> <msg>" appended to the
// watchdog log, plus a slog mirror for `kubectl logs` debugging.
// Best-effort: an unwritable log file never fails a check.
func (h *Hygiene) appendLog(msg string) {
	slog.Info(msg, "subsystem", "controllerhygiene")
	h.writeLogFile(msg)
}

// appendLogWarn is appendLog for failure/degraded paths — the file
// line is identical (NPD contract), the slog mirror is Warn-level.
func (h *Hygiene) appendLogWarn(msg string) {
	slog.Warn(msg, "subsystem", "controllerhygiene")
	h.writeLogFile(msg)
}

func (h *Hygiene) writeLogFile(msg string) {
	f, err := os.OpenFile(h.cfg.WatchdogLogFile,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		slog.Warn("controllerhygiene: watchdog log file unwritable",
			"file", h.cfg.WatchdogLogFile, "error", err,
			"subsystem", "controllerhygiene")
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", h.cfg.nowFn().Format(time.RFC3339), msg)
}

func (h *Hygiene) statePath(name string) string {
	return filepath.Join(h.cfg.WatchdogStateDir, "state-"+name)
}

// stateExists reports whether the latch file is present.
func (h *Hygiene) stateExists(name string) bool {
	_, err := os.Stat(h.statePath(name))
	return err == nil
}

// writeEpochFile writes the current epoch via tmp+rename — the same
// atomic-copy contract the watchdog prom files rely on. The leading
// dot keeps the tmp name out of hostmetrics' state-* scan.
func (h *Hygiene) writeEpochFile(path string) {
	content := strconv.FormatInt(h.cfg.nowFn().Unix(), 10) + "\n"
	tmp := filepath.Join(filepath.Dir(path), ".tmp-"+filepath.Base(path))
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		slog.Warn("controllerhygiene: state file write failed",
			"path", path, "error", err, "subsystem", "controllerhygiene")
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		slog.Warn("controllerhygiene: state file install failed",
			"path", path, "error", err, "subsystem", "controllerhygiene")
	}
}

// stateEnter creates state-<name> only when absent and logs the
// transition once — lib.sh STATE-ENTER parity.
func (h *Hygiene) stateEnter(name, extra string) {
	p := h.statePath(name)
	if _, err := os.Stat(p); err == nil {
		return
	}
	h.writeEpochFile(p)
	if _, err := os.Stat(p); err != nil {
		return
	}
	if extra != "" {
		h.appendLog(fmt.Sprintf("STATE-ENTER: %s %s", name, extra))
	} else {
		h.appendLog(fmt.Sprintf("STATE-ENTER: %s", name))
	}
}

// stateExit removes state-<name> if present and logs the transition.
func (h *Hygiene) stateExit(name string) {
	p := h.statePath(name)
	if _, err := os.Stat(p); err != nil {
		return
	}
	if err := os.Remove(p); err != nil {
		slog.Warn("controllerhygiene: state latch remove failed",
			"state", name, "path", p, "error", err,
			"subsystem", "controllerhygiene")
		return
	}
	h.appendLog(fmt.Sprintf("STATE-EXIT: %s", name))
}

// readEpoch parses an epoch file — garbage/absent → 0 (rate_ok parity).
func (h *Hygiene) readEpoch(path string) int64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// rateOK reports whether the budget file is absent, unparseable, or
// older than interval — lib.sh rate_ok parity.
func (h *Hygiene) rateOK(dir, name string, interval time.Duration) bool {
	last := h.readEpoch(filepath.Join(dir, name))
	return h.cfg.nowFn().Unix()-last >= int64(interval.Seconds())
}

// rateSpend writes the current epoch to the budget file.
func (h *Hygiene) rateSpend(dir, name string) {
	h.writeEpochFile(filepath.Join(dir, name))
}

// ctrInc mirrors lib.sh ctr_inc: read + increment + write + return.
// Garbage → 1.
func (h *Hygiene) ctrInc(name string) int {
	p := filepath.Join(h.cfg.WatchdogStateDir, name)
	n := int(h.readEpoch(p))
	n++
	content := strconv.Itoa(n) + "\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		slog.Warn("controllerhygiene: counter file write failed",
			"path", p, "error", err, "subsystem", "controllerhygiene")
		return 0
	}
	return n
}

// ctrRead returns a consecutive-* file value (garbage/absent → 0).
func (h *Hygiene) ctrRead(name string) int {
	return int(h.readEpoch(filepath.Join(h.cfg.WatchdogStateDir, name)))
}

// ctrReset removes a consecutive-* file.
func (h *Hygiene) ctrReset(name string) {
	_ = os.Remove(filepath.Join(h.cfg.WatchdogStateDir, name))
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
		slog.Warn("controllerhygiene: state file write failed",
			"path", p, "error", err, "subsystem", "controllerhygiene")
	}
}

// --- /proc helpers ---

// procFile joins ProcRoot/<pid>/<elems...>.
func (h *Hygiene) procFile(pid int, elems ...string) string {
	parts := append([]string{h.cfg.ProcRoot, strconv.Itoa(pid)}, elems...)
	return filepath.Join(parts...)
}

// uptimeSeconds parses <ProcRoot>/uptime.
func (h *Hygiene) uptimeSeconds() (float64, error) {
	data, err := os.ReadFile(filepath.Join(h.cfg.ProcRoot, "uptime"))
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, fmt.Errorf("empty uptime")
	}
	return strconv.ParseFloat(fields[0], 64)
}

var pidDirRe = regexp.MustCompile(`^[0-9]+$`)

// procPIDs lists the numeric pid dirs under ProcRoot, ascending —
// `pgrep -x | head -1` parity (lowest pid wins).
func (h *Hygiene) procPIDs() []int {
	entries, err := os.ReadDir(h.cfg.ProcRoot)
	if err != nil {
		return nil
	}
	var pids []int
	for _, e := range entries {
		if !e.IsDir() || !pidDirRe.MatchString(e.Name()) {
			continue
		}
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids)
	return pids
}

// findProcByComm returns the lowest pid whose /proc/<pid>/comm equals
// name — `pgrep -x <name> | head -1` parity. 0 when absent.
func (h *Hygiene) findProcByComm(name string) int {
	for _, pid := range h.procPIDs() {
		data, err := os.ReadFile(h.procFile(pid, "comm"))
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(data)) == name {
			return pid
		}
	}
	return 0
}

// procCmdline returns the argv of pid (NUL-separated in /proc).
func (h *Hygiene) procCmdline(pid int) []string {
	data, err := os.ReadFile(h.procFile(pid, "cmdline"))
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
}

// pidAgeSeconds returns the process age in seconds — `ps -o etimes=`
// parity. Computed from /proc/<pid>/stat starttime (field 22, jiffies)
// against /proc/uptime; the post-comm parsing trick (fields after the
// LAST ')') is the same as lib.sh read_cpu_jiffies.
func (h *Hygiene) pidAgeSeconds(pid int) (float64, error) {
	data, err := os.ReadFile(h.procFile(pid, "stat"))
	if err != nil {
		return 0, err
	}
	s := string(data)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, fmt.Errorf("bad stat")
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 20 {
		return 0, fmt.Errorf("short stat")
	}
	start, err := strconv.ParseFloat(f[19], 64) // field 22 overall
	if err != nil {
		return 0, err
	}
	up, err := h.uptimeSeconds()
	if err != nil {
		return 0, err
	}
	age := up - start/clkTck
	if age < 0 {
		return 0, nil
	}
	return age, nil
}

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
	if err := cmd.Start(); err != nil {
		return "", err
	}
	out, _ := io.ReadAll(io.LimitReader(stdout, maxJournalBytes))
	_, _ = io.Copy(io.Discard, stdout) // drain so Wait cannot deadlock
	if err := cmd.Wait(); err != nil {
		return "", err
	}
	return string(out), nil
}

// journalText returns the unit journal since `since`, mapping errors
// to empty — `journalctl ... 2>/dev/null | grep -c` parity (a failed
// journal read counts as 0 hits, never as wedge evidence).
func (h *Hygiene) journalText(ctx context.Context, since time.Time) string {
	out, err := h.cfg.journalFn(ctx, h.cfg.JournalUnit, since)
	if err != nil {
		return ""
	}
	return out
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

// systemctl runs `timeout 10 systemctl <args>` with the scrubbed env.
func systemctl(ctx context.Context, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
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
	if err != nil || c == nil {
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
				cert, _ = os.ReadFile(resolveRel(h.cfg.AdminKubeconfig, a.ClientCertificate))
			}
			if len(a.ClientKeyData) > 0 {
				key = a.ClientKeyData
			} else if a.ClientKey != "" {
				key, _ = os.ReadFile(resolveRel(h.cfg.AdminKubeconfig, a.ClientKey))
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
		return 0, false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, false
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
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
