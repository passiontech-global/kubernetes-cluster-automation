// config.go — the Config surface: the flat wiring knobs
// (paths/transport, the watchdogconf reloader) plus the per-domain
// sub-config groups ConfigFromEnv resolves (Hub/Sig13/KineTTL/
// KinePool/OOMLoop/Feeder/EtcdGuard/CPFreeze/PKIDrift), and
// ApplyDefaults — it fills every unset knob from the package
// defaults and wires the injectable seam defaults
// (journal/systemd/probe funcs, seams.go).
//
// This is the cdeps half of the controllerhygiene per-domain split:
// Config lives here (not in the parent package) so every domain
// check package consumes the same knob surface without importing
// the orchestrator — the wdeps.Config precedent. The parent
// aliases it: controllerhygiene.Config IS cdeps.Config.
package cdeps

import (
	"net/http"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/subframe"
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
	// MinUptimeSeconds is the module-22 WD_REQUIRES:uptime gate —
	// the 20min post-boot grace before the destructive wedge/TTL
	// checks (exported: the parent's group gate reads it).
	MinUptimeSeconds = 1200 // WD_REQUIRES: uptime
	defaultStateDir  = "/host/var/lib/node-watchdog"
	defaultLogFile   = "/host/var/log/node-watchdog.log"
	defaultProcRoot  = "/proc" // hostPID:true makes pod /proc == host /proc
	defaultUnitFile  = "/host/etc/systemd/system/k0scontroller.service"
	// DefaultJournalUnit is `journalctl -u <unit>`'s default.
	DefaultJournalUnit = "k0scontroller"
	// DefaultRestartUnit is the unit the wedge guard restarts.
	DefaultRestartUnit  = "k0scontroller.service"
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
	// DefaultOOMMinKills is the kills-in-window trigger — exported
	// for the oom domain tests that seed exactly the boundary.
	DefaultOOMMinKills  = 3
	defaultOOMWindow    = time.Hour
	defaultCGroupEvents = "/host/sys/fs/cgroup/system.slice/" +
		"k0scontroller.service/memory.events"
	defaultAPIServerAdj   = -800
	defaultKineAdj        = 500
	defaultJournalTimeout = 15 * time.Second
	// DefaultJournalUnreadableNeeded is the consecutive-failed-read
	// budget for the journal-unreadable blindness latch (incident:
	// broken journald on a cicd controller left every journal check
	// silently seeing "0 hits").
	DefaultJournalUnreadableNeeded = 5

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
	// spofStreakMultiplier is the spof-streak rule: on a
	// single-controller topology every consecutive-failure streak
	// gating a k0scontroller restart is doubled — a transient flap
	// costs 30-45s of API downtime with no peer to serve the gap
	// (production, cicd).
	spofStreakMultiplier = 2

	// defaultK0sDir is the shared k0s data dir — etcdguard probes
	// under it and the PKI-drift default pairs derive from it.
	defaultK0sDir = "/host/var/lib/k0s" // DaemonSet host mount
	// defaultK0sRunDir is the k0s runtime dir — konnectivity-server
	// and its UDS live under it (DaemonSet host mount).
	defaultK0sRunDir = "/host/run/k0s"
	// defaultSuspectLogCadence is the re-reminder interval suspectLog
	// applies to suspect/hold lines whose latch stays held: STATE-
	// ENTER announces the transition and the raw line then repeats
	// at most this often — the field-verified failure mode was
	// kine-ttl-loop logging every 60s cycle for weeks on nonprod
	// (1600+ lines), drowning the watchdog tail.
	defaultSuspectLogCadence = time.Hour

	// cp-freeze-heal defaults: 3 consecutive healthz failures, or a KCM that
	// is leader yet carries zero queued work for >10m — while the
	// peer apiserver still answers — restarts k0scontroller under a
	// 2h budget.
	defaultCPFreezeCycles     = 3
	defaultCPFreezeQuietFor   = 10 * time.Minute
	defaultCPFreezeMinRestart = 2 * time.Hour
	// pki-cert-drift: an on-disk cert newer than the socket-presented cert
	// for 2 consecutive cycles → restart the owning unit (1h budget).
	defaultPKIDriftCycles     = 2
	defaultPKIRestartInterval = time.Hour
)

// Config carries the subsystem knobs — all test-injectable. The
// domain groups nest the knobs by their env-prefix family
// (ConfigFromEnv fills them); shared paths/transport, the watchdog
// conf reloader and the test seams stay flat (the seams embedded —
// every field reaches as c.Seams.<Group>.<Name> or promoted
// c.<Name>, wdeps.Seams parity).
type Config struct {
	// Base is the shared watchdog-subsystem block — cadence,
	// WatchdogStateDir (state-*/last-*/consecutive-*/oomloop-*
	// files), WatchdogLogFile (the NPD-filelog append target —
	// message text is a contract), ProcRoot, the systemd client
	// driving every host command the seam defaults spawn
	// (nsenter-wrapped to host PID 1's namespaces inside the
	// DaemonSet; nil → the seam defaults report "no systemd client
	// wired" and the dependent checks degrade), WatchdogSrc (the
	// BUG-H9 live conf reloader — RefreshWatchdogConf re-applies
	// conf-derived knobs each cycle while preserving env/
	// programmatic overrides) and the clock cell splice
	// (subframe.FromDeps).
	subframe.Base
	// CycleTimeout is the per-Cycle deadline Run applies around each
	// Cycle: every spawned command and HTTP probe is ctx-aware, so
	// a stalled check is aborted instead of starving the
	// restart-critical guards past this bound on any tick.
	// <=0 → defaultCycleTimeout (15m).
	CycleTimeout time.Duration
	// K0sControllerUnitFile gates ALL checks (WD_REQUIRES:
	// unit:k0scontroller) — workers/test envs are a silent no-op.
	K0sControllerUnitFile string
	JournalUnit           string // journalctl -u <unit>
	RestartUnit           string // unit restarted by the wedge guard
	// K0sDir is the k0s data dir — etcdguard probes under it and the
	// PKI-drift default pairs derive from it. "" → /host/var/lib/k0s.
	K0sDir string
	// K0sRunDir is the k0s runtime dir — the konnectivity-server
	// UDS probe reads <K0sRunDir>/konnectivity-server/*.sock.
	// "" → /host/run/k0s (DaemonSet host mount).
	K0sRunDir string
	// TextfileDir is the node-exporter drop dir (NODE_HOST_AGENT_
	// TEXTFILE_DIR via hostctx) — "" falls back to the K0sDir
	// sibling derivation textfilePromDir kept before the env
	// override existed.
	TextfileDir string
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
	// CPFreeze is the cp-freeze-heal KCM/scheduler freeze auto-heal — no env
	// wiring; package defaults unless set programmatically.
	CPFreeze CPFreezeConfig
	// PKIDrift is the pki-cert-drift on-disk-vs-served PKI cert drift check —
	// no env wiring; package defaults unless set programmatically.
	PKIDrift PKIDriftConfig
	// TotalControllers is the spof-streak topology override: >0 pins
	// the control-plane size explicitly; 0 (default) = auto — an
	// unset Hub.PeerAPI means a single-controller cluster.
	TotalControllers int
	// EtcdSnapshotDir overrides the etcd snapshot verifier's scan
	// dir ("" → K0sDir/etcd/snapshots then EtcdBackupDir).
	EtcdSnapshotDir string
	// EtcdBackupDir is the snapshot verifier's second default scan
	// dir — PathJoin-derived in ConfigFromEnv so the DaemonSet
	// reads the HOST /var/backups/etcd, identity standalone.
	// "" → /var/backups/etcd.
	EtcdBackupDir string

	// Seams are the injectable test seams — every check reads them
	// through d.Cfg.<name> (promoted) so tests re-stub a live
	// Hygiene after New. The fields are grouped by concern
	// (Probe/Host/Etcd) — see seams.go.
	Seams
}

// ApplyDefaults fills every unset knob — the per-group methods below
// own their own fields exactly like the old flat pass did. Exported:
// the parent's New drives it (wdeps.ApplyDefaults parity).
func (c *Config) ApplyDefaults() {
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
		c.JournalUnit = DefaultJournalUnit
	}
	if c.RestartUnit == "" {
		c.RestartUnit = DefaultRestartUnit
	}
	c.applyHubDefaults()
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
	c.applySig13Defaults()
	c.applyKineTTLDefaults()
	c.applyKinePoolDefaults()
	c.applyOOMLoopDefaults()
	c.applyFeederDefaults()
	if c.K0sDir == "" {
		c.K0sDir = defaultK0sDir
	}
	if c.K0sRunDir == "" {
		c.K0sRunDir = defaultK0sRunDir
	}
	c.applyEtcdGuardDefaults()
	if c.SuspectLogCadence <= 0 {
		c.SuspectLogCadence = defaultSuspectLogCadence
	}
	c.applyCPFreezeDefaults()
	c.applyPKIDriftDefaults()
	// The seam defaults are the tail of the old flat pass — same
	// nil → production impl rules, grouped in seams.go.
	c.Seams.applyDefaults(c)
}
