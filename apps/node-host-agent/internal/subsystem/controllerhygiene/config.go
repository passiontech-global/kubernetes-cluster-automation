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
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/etcdmaint"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/eventpurge"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostexec"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/probee"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
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
	nowFn     timex.Clock
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
	if c.nowFn == nil {
		c.nowFn = timex.SystemClock
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
	c.applyEtcdGuardDefaults()
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
	c.applyCPFreezeDefaults()
	c.applyPKIDriftDefaults()
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
