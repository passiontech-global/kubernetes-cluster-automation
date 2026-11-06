// config.go — the Config surface: the flat wiring knobs
// (paths/transport, the watchdogconf reloader, the unexported test
// seams) plus the per-domain sub-config groups ConfigFromEnv
// resolves (Hub/Sig13/KineTTL/KinePool/OOMLoop/Feeder/EtcdGuard/
// CPFreeze/PKIDrift), and applyDefaults — it fills every unset knob
// from the package defaults and wires the injectable seam defaults
// (journal/systemd/probe funcs).
package controllerhygiene

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/ops/etcdmaint"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/ops/eventpurge"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostexec"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/probee"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
)

// Config carries the subsystem knobs — all test-injectable. The
// domain groups nest the knobs by their env-prefix family
// (ConfigFromEnv fills them); shared paths/transport, the watchdog
// conf reloader and the private test seams stay flat.
type Config struct {
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
	// cert triple + --endpoints + --command-timeout and execs
	// container-side through hostexec.Run; stdout-only — stderr
	// captured separately so -w json parses).
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
			argv := append(append([]string{bin}, certArgs...), args...)
			cctx, cancel := context.WithTimeout(ctx, defaultEtcdctlBudget)
			defer cancel()
			// Deliberately container-side via hostexec.Run, NOT the
			// nsenter-wrapped Config seam: bin is a hostPath-prefixed
			// path (<hostRoot>/var/lib/k0s/bin/etcdctl) that only
			// exists in the pod's mount view — an nsenter -m wrap
			// would look for "/host/..." on the host fs where it
			// does not exist. The endpoint is loopback, reachable
			// because the DaemonSet is hostNetwork. etcdctl >=3.7
			// warns "unrecognized environment variable ETCDCTL_API"
			// on stderr — v3 is the default API anyway — so stderr
			// stays a separate stream: -w json output must parse;
			// a combined capture would poison the payload.
			out, serr, err := hostexec.Run(cctx, argv, "")
			if err != nil {
				return []byte(out), fmt.Errorf("%w: %s", err,
					strings.TrimSpace(serr))
			}
			return []byte(out), nil
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
