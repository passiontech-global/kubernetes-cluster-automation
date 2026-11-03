// Package workerhygiene ports the worker-only node-watchdog shell
// modules (WD_REQUIRES: uptime k0sworker) into one agent subsystem:
//
//   - 05-kubelet-stall.sh       — sig1/sig2/kubelet-10250: informer
//     zombie journal spam, phantom pods (>=5 pod dirs, zero live
//     tasks), or a dead :10250 healthz → consecutive-gated k0sworker
//     restart + state-kubelet-runtime-stall latch.
//   - 06-kubelet-watch-wedge.sh — sig16: pods assigned to this node in
//     the API for >15m without a kubelet pod dir → kubelet watch
//     stream wedge → state-kubelet-watch-wedge + k0sworker restart
//     (shared last-restart budget; gated when ALL apiserver backends
//     are stale — upstream wedge, restart useless).
//   - 36-pod-teardown.sh   — sig16: pods stuck Terminating with zero
//     live containerd tasks get force-deleted (verified object
//     cleanup, never while a task is alive); pods Terminating >30m
//     whose task dirs still exist = node-side wedge →
//     state-pod-teardown-wedged latch for the NPD→NHC→SNR reboot path.
//   - 30-konnectivity.sh   — sig6: konnectivity-agent's
//     agent-identifiers=host=<IP> is baked into env at POD creation —
//     after a node InternalIP change the pod keeps registering the old
//     IP and konnectivity-server can't route dials (kubectl logs/exec
//     timeout while the node looks fine, incident 2026-09-13). Remedy:
//     recreate the konnectivity-agent pod so a fresh sandbox gets the
//     new baked env.
//   - 33-dns-resolv-drift.sh — sig12: kubelet snapshots host
//     /etc/resolv.conf into dnsPolicy:Default pods at sandbox create;
//     a resolv.conf repoint never reaches running pods (incident
//     2026-09-15: node-local-dns kept nameserver 8.8.8.8 → "." forwarded
//     to public DNS → api.passiontech.internal NXDOMAIN ~29h). Remedy:
//     SIGKILL the pod's PAUSE pid — kubelet recreates the sandbox with
//     the fresh resolv.conf (killing the app container keeps the old
//     sandbox and changes nothing).
//   - 31-ctr-tasks.sh      — sig7: wedged containerd task dirs (init
//     dead/zombie >=5m, half-written dir without init.pid >=5m, or
//     missing log.json >=5m) get their shim killed + dir removed;
//     orphan containerd-shim-runc-v2 processes whose task dir vanished
//     get SIGKILLed.
//   - 32-cilium.sh         — sig9: cilium-agent :9879 healthz down →
//     state-cilium-agent-down + SIGKILL the agent container so
//     kubelet restarts it (shared last-cilium-restart budget).
//   - 35-cilium-init-stuck.sh — sig15: endpoints stuck in
//     reserved:init (informer wedge, healthz still OK) →
//     state-cilium-init-stuck + SIGKILL cilium-agent.
//   - 37-ctr-image-healer.sh — pods stuck Waiting
//     (CreateContainerError/ErrImagePull/ImagePullBackOff) whose
//     message is a corrupted containerd layer/content-store error
//     (missing content digest, failed layer extraction, missing
//     parent snapshot) get their image removed via `ctr images rm
//     --sync` so kubelet's next pull re-fetches the bad layer —
//     the pod recovers without a node reboot. Shared
//     last-ctr-image-rm 15m budget.
//   - 38-cilium-bpf-ipam.sh — cilium IPAM leak detector: reads
//     ipam.ipv4 used/available off the agent unix socket and
//     cross-checks the allocated count against non-hostNetwork
//     Running pods on this node (allocated − in-use = leaked IPs
//     held by dead pods). Gauges are exported every probe;
//     leaked >30 or available <=2 for ConsecNeeded consecutive
//     cycles → state-cilium-ipam-exhausted latch.
//   - T15 (k0s-kubelet-watchdog.sh + k0sworker-remediate.sh) — the
//     Option-D kubelet watchdog feeder, on its own 15s ticker
//     parallel to Cycle: probe :10248/healthz (body must be "ok"),
//     and after 4 consecutive fails (~60s) run the ordered gates
//     (uptime/settle/overload/apiserver/rate-limit) before spending
//     the shared last-restart budget on a k0sworker restart. An
//     exhausted budget latches state-kubelet-healthz-down instead —
//     the NHC→SNR reboot escalation path.
//
// Differences from the shell versions (documented, behaviour-equivalent):
//   - `k0s ctr tasks ls` / `tasks kill` is replaced by scanning the
//     containerd runtime-v2 task dirs + sandbox-controller shim dirs:
//     config.json carries io.kubernetes.pod.uid / .container.name and
//     init.pid the host pid — the node-side ground truth the modules
//     already used for teardown verification. No ctr socket needed.
//   - /proc reads go through ProcRoot (default /proc — the DaemonSet
//     runs hostPID so in-pod /proc IS host /proc).
//   - consecutive-* counters are in-memory (agent restarts are rare;
//     the hysteresis cost of losing one count is bounded by Interval).
//   - One pod LIST per cycle feeds all three checks — the shell
//     queried per module; sharing gives one consistent apiserver
//     verdict and halves API calls.
package workerhygiene

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/systemd"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/watchdogconf"
)

// Defaults mirror the shell modules + the DaemonSet host mounts.
const (
	defaultInterval = 2 * time.Minute
	// minUptimeSeconds mirrors the shell runner's WD_REQUIRES: uptime
	// gate (MIN_UPTIME_S=1200) — no destructive checks in the first
	// 20 minutes after boot.
	minUptimeSeconds         = 1200
	defaultWatchdogStateDir  = "/host/var/lib/node-watchdog"
	defaultWatchdogLogFile   = "/host/var/log/node-watchdog.log"
	defaultProcRoot          = "/proc" // hostPID:true makes pod /proc == host /proc
	defaultCtrTaskRoot       = "/host/run/k0s/containerd/io.containerd.runtime.v2.task/k8s.io"
	defaultSandboxCtlRoot    = "/host/run/k0s/containerd/io.containerd.sandbox.controller.v1.shim"
	defaultHostResolvConf    = "/host/etc/resolv.conf"
	defaultK0sWorkerUnitFile = "/host/etc/systemd/system/k0sworker.service"
	defaultKubeletPodsDir    = "/host/var/lib/k0s/kubelet/pods"
	defaultKubeletHealthzURL = "https://127.0.0.1:10250/healthz"
	defaultCiliumHealthzURL  = "http://127.0.0.1:9879/healthz"
	// The DaemonSet mounts host /run at /host/run — /host/var/run is
	// never mounted (host /var/run is a symlink to /run on modern
	// distros but the pod bind-mount does not follow it).
	defaultCiliumSocket       = "/host/run/cilium/cilium.sock"
	defaultStuckDeleteAge     = 15 * time.Minute // shell STUCK_DELETE_S=900
	defaultStuckWedgeAge      = 30 * time.Minute // shell STUCK_WEDGE_S=1800
	defaultKubeletWatchMinAge = 15 * time.Minute // shell KUBELET_WATCH_MIN_AGE_S=900
	defaultMaxForceDelete     = 5                // bounds per-cycle churn (shell used 3; 5 keeps parity headroom)
	defaultMaxCtrTaskClean    = 5                // shell cap 5 per cycle
	defaultMaxShimKill        = 10               // shell cap 5; 10 bounds orphan-shim storms with headroom
	defaultConsecNeeded       = 2                // shell CONSEC_NEEDED=2
	defaultMinRestartInterval = 30 * time.Minute // shell MIN_RESTART_INTERVAL_S=1800
	// ctrImageRmInterval is the 37-ctr-image-healer budget — image
	// removal is idempotent so it needs no consecutive gate; the 15m
	// cooldown alone bounds the churn.
	ctrImageRmInterval = 15 * time.Minute
	// k0sWorkerSettle mirrors the plan's k0sworker_settled >=180s gate:
	// a k0sworker restarted moments ago gets a settle window before
	// ANY new restart is spent on it — kubelet needs the window to
	// re-list pods / rebuild its watch stream.
	k0sWorkerSettle = 180 * time.Second
	// journalWindow mirrors the runner's `journalctl -u k0sworker
	// --since "-10 min"` shared snapshot.
	journalWindow     = "-10 min"
	journalHitsThresh = 60 // shell JOURNAL_HITS_THRESHOLD
	poddirThreshold   = 5  // shell PODDIR_THRESHOLD
	probeAttempts     = 3  // kubelet :10250 curl loop runs 3x
	probeGap          = 2 * time.Second
	probeTimeout      = 3 * time.Second // curl -ksm3
	ciliumProbeTime   = 5 * time.Second // task spec: 3x timeout 5s
	// T15 kubelet watchdog feeder (k0s-kubelet-watchdog.sh). The
	// shell unit probed every 20s inside a 200s WatchdogSec grace —
	// ~200s of continuous silence before the remediate oneshot ran.
	// The agent deliberately tightens this to a 15s cadence with
	// KWD_MAX_FAIL=4 consecutive fails (~60s) and NO additional grace:
	// detection is faster, and the shell's slack is replaced by the
	// remediate Gate-0 re-probe + the ordered gates (every one is a
	// chance to stop before the restart). curl --max-time 5 bounds
	// every probe.
	defaultKubeletWdInterval   = 15 * time.Second
	defaultKubeletWdMaxFail    = 4
	defaultKubeletWdProbeURL   = "http://127.0.0.1:10248/healthz"
	defaultKubeletWdReprobeGap = 3 * time.Second // remediate Gate-0: two probes ~3s apart
	// G4 fallback when no API backends are configured — the
	// worker-local api-local-lb listener (k0s haproxy).
	defaultAPIFallbackURL = "https://localhost:7443/livez"
	kubeletWdProbeTimeout = 5 * time.Second
	apiLivezProbeTimeout  = 5 * time.Second
	// A4 (PLEG/containerd probes), A3 (ingest GC), A2 (zombie
	// storm), A5 (journald integrity), B1 (cilium-envoy), B4 (MTU
	// drift) — defaults mirror the same /host mount convention.
	defaultKubeletSyncloopURL  = "https://127.0.0.1:10250/healthz/syncloop"
	defaultContainerdSocket    = "/host/run/k0s/containerd/containerd.sock"
	defaultCiliumEnvoyReadyURL = "http://127.0.0.1:9964/ready"
	defaultCtrIngestDir        = "/host/var/lib/k0s/containerd/io.containerd.content.v1.content/ingest"
	defaultK0sDataDir          = "/host/var/lib/k0s"
	defaultSysClassNet         = "/sys/class/net"
	defaultNebulaIface         = "neb1"
	defaultCiliumIface         = "cilium_net"
	defaultCiliumRuntimeConfig = "/host/run/cilium/state/agent-runtime-config.json"
	unixSockProbeTimeout       = 5 * time.Second
	zombieStormThreshold       = 500 // <defunct> children of one parent = storm
	ctrIngestMaxAge            = 3 * time.Hour
	ctrIngestScanInterval      = 6 * time.Hour
	k0sDiskHighWatermark       = 0.75
	// journaldVacuumInterval bounds how often the A5 remedy runs —
	// journalctl --rotate is cheap but --vacuum-time does real IO.
	journaldVacuumInterval = 30 * time.Minute
)

// Check names — prometheus `check` label + log context.
const (
	checkTeardown    = "pod-teardown"
	checkKonn        = "konnectivity"
	checkDNS         = "dns-resolv"
	checkStall       = "kubelet-stall"
	checkWatch       = "kubelet-watch-wedge"
	checkCtrTasks    = "ctr-tasks"
	checkCilium      = "cilium"
	checkCiliumInit  = "cilium-init-stuck"
	checkCtrImages   = "ctr-image-healer"   // 37
	checkCiliumIPAM  = "cilium-ipam"        // 38
	checkKubeletWd   = "kubelet-watchdog"   // T15 feeder + remediate
	checkSyncloop    = "kubelet-syncloop"   // A4 PLEG probe
	checkCtrSock     = "containerd-sock"    // A4 socket hang probe
	checkIngestGC    = "ctr-ingest-gc"      // 39 (A3)
	checkZombieStorm = "zombie-storm"       // A2
	checkJournald    = "journald-integrity" // A5
	checkCiliumEnvoy = "cilium-envoy"       // B1
	checkCiliumMTU   = "cilium-mtu"         // B4
)

// Config carries the hygiene knobs — all test-injectable.
type Config struct {
	NodeName          string        // this node (spec.nodeName)
	Interval          time.Duration // check cadence
	Enabled           bool          // false → Run idles until ctx done
	WatchdogStateDir  string        // state-*/last-*/consecutive-* files
	WatchdogLogFile   string        // appended watchdog log (NPD filelog)
	ProcRoot          string        // host /proc
	CtrTaskRoot       string        // containerd runtime-v2 task dirs
	SandboxCtlRoot    string        // sandbox-controller shim dirs
	HostResolvConf    string        // host resolv.conf (dns drift baseline)
	K0sWorkerUnitFile string        // presence gates all checks
	KubeletPodsDir    string        // host kubelet pod dirs (05/06)
	KubeletHealthzURL string        // kubelet :10250 probe (05)
	CiliumHealthzURL  string        // cilium-agent :9879 probe (32)
	CiliumSocket      string        // cilium agent unix socket (35)
	Client            kubernetes.Interface
	// Systemd drives host restarts/probes (nsenter-wrapped inside the
	// container). nil → all systemd-dependent checks degrade to the
	// "cannot determine → keep" branch (log-only).
	Systemd *systemd.Client
	// Watchdog is the parsed node-watchdog.conf — feeds the runner's
	// per-module kill switch (WD_SIG_<NAME>=off) and, through
	// APIBackendIPs, the upstream-stale gate of the watch-wedge
	// check. nil → every check runs (pre-conf behaviour).
	Watchdog *watchdogconf.Config
	// WatchdogSrc, when set, re-reads the conf every Cycle so
	// hostconfig rewrites (WD_SIG_*, API_BACKENDS) apply live —
	// APIBackends below is then refreshed from the file each cycle.
	WatchdogSrc *watchdogconf.Reloader
	// APIBackends are the "ip[:port]" apiserver endpoints module 06
	// gates on — wired from watchdogconf.APIBackendIPs() by main
	// (kept current by WatchdogSrc when set).
	APIBackends []string
	// KubeletWatchdogHosts is the cluster var systemd_watchdog_hosts —
	// the T15 opt-in host list the shell feeder unit gated on (wired
	// by main from the vars dir / env). The feeder activates when this
	// node is listed here OR by default on any worker node
	// (K0sWorkerUnitFile present) — in the agent port the T15 pilot
	// graduated fleet-wide, so an empty list never disables it.
	KubeletWatchdogHosts []string
	KubeletWdInterval    time.Duration // feeder probe cadence (15s)
	KubeletWdMaxFail     int           // consecutive fails → remediate gates (4 = ~60s)
	KubeletWdProbeURL    string        // kubelet :10248 healthz — body must be "ok"
	// KubeletWdReprobeGap is the sleep between the remediate Gate-0
	// re-probes — the shell's "probe twice 3s apart" self-correct
	// window before any gate runs.
	KubeletWdReprobeGap time.Duration
	// APIFallbackURL is the G4 last-resort /livez target when no
	// API backends are configured (worker-local api-local-lb :7443).
	APIFallbackURL     string
	StuckDeleteAge     time.Duration // Terminating age → force-delete candidate
	StuckWedgeAge      time.Duration // Terminating age + task dir → wedge latch
	KubeletWatchMinAge time.Duration // pod age without pod dir → watch wedge (06)
	MaxForceDelete     int           // force-delete cap per cycle
	MaxCtrTaskClean    int           // wedged ctr task dir cap per cycle (31)
	MaxShimKill        int           // orphan shim kill cap per cycle (31)
	ConsecNeeded       int           // consecutive suspect cycles before action
	MinRestartInterval time.Duration // rate-limit budget for recreating actions
	ProbeGap           time.Duration // sleep between probe retries (05/32)
	// Wave-2 checks: A4 syncloop/containerd probes, A3 ingest GC,
	// A2 zombie storm, A5 journald integrity, B1 cilium-envoy, B4
	// MTU drift — all default-injected like the other knobs.
	KubeletSyncloopURL    string        // kubelet :10250 /healthz/syncloop (PLEG)
	ContainerdSocket      string        // containerd grpc unix socket under /host/run
	CiliumEnvoyReadyURL   string        // cilium-envoy admin :9964/ready
	CtrIngestDir          string        // containerd content ingest dir (39)
	K0sDataDir            string        // /var/lib/k0s — disk-high ingest-GC trigger
	SysClassNet           string        // /sys/class/net — MTU reads (B4)
	NebulaIface           string        // overlay iface MTU baseline (neb1 = 1300)
	CiliumIface           string        // cilium host iface (cilium_net)
	CiliumRuntimeConfig   string        // agent-runtime-config.json MTU fallback
	ZombieStormThreshold  int           // defunct children of one parent → storm
	CtrIngestMaxAge       time.Duration // ingest dir mtime older than → stale (3h)
	CtrIngestScanInterval time.Duration // periodic rescan even under disk WM (6h)
	K0sDiskHighWatermark  float64       // /var/lib/k0s used ratio triggering GC

	// killFn delivers signals — seam for tests (SIGKILL on pause /
	// proxy-agent/shim/cilium pids, and signal-0 liveness probes).
	killFn func(pid int, sig syscall.Signal) error
	// nowFn supplies the current time — seam for tests.
	nowFn func() time.Time
	// probeHTTP does one GET and returns nil on ANY HTTP response
	// (curl -ks parity — a 401 means the listener is alive). Seam.
	probeHTTP func(ctx context.Context, url string, timeout time.Duration) error
	// unixGet GETs path over a unix socket and returns the body —
	// the cilium-dbg endpoint list replacement (35). Seam.
	unixGet func(ctx context.Context, socket, path string) ([]byte, error)
	// ctrRmImage removes one image from the k8s.io containerd
	// namespace — the corrupted-layer remedy (37), `k0s ctr
	// --namespace k8s.io images rm --sync <image>` via the systemd
	// exec wrapper. nil → Systemd.Exec default. Seam.
	ctrRmImage func(ctx context.Context, image string) error
	// journalFn returns the k0sworker journal window — the runner's
	// shared -10min snapshot (05/06). nil → Systemd.Journal.
	journalFn func(ctx context.Context) (string, error)
	// journalAnyFn is the A5 second probe — `journalctl -n 1
	// --no-pager` with NO unit filter. An empty k0sworker window is
	// only corruption evidence when journald ITSELF has nothing (or
	// only corrupt warnings) to say — a quiet unit on a healthy
	// journald must not trigger the rotate+vacuum remedy. nil →
	// Systemd.ExecCombined (stderr folded in — journald's own
	// diagnostics, e.g. "File ... is corrupt", never reach stdout).
	journalAnyFn func(ctx context.Context) (string, error)
	// probeBodyOK does one GET and reports whether the trimmed body is
	// exactly "ok" — the :10248 healthz contract (curl -s body compare
	// parity: a wedged kubelet can still answer HTTP with a non-ok
	// body, so any-HTTP-code-alive is not enough here). Seam.
	probeBodyOK func(ctx context.Context, url string, timeout time.Duration) bool
	// probeHTTPStatus does one GET and returns the status code — the
	// probeHTTP variant for endpoints where the CODE is the verdict
	// (syncloop 500 vs healthz 200, envoy /ready 503). Seam.
	probeHTTPStatus func(ctx context.Context, url string, timeout time.Duration) (int, error)
	// probeUnixSock connects to a unix socket under a deadline — the
	// containerd-socket hang probe (A4). Seam.
	probeUnixSock func(ctx context.Context, socket string, timeout time.Duration) error
	// statfsFn reads fs usage for the ingest-GC disk trigger (A3).
	// Seam for tests (default unix.Statfs).
	statfsFn func(string, *unix.Statfs_t) error
	// ctrRmIngest removes one stale ingest ref — `k0s ctr -n k8s.io
	// content ingest rm <ref>` via the systemd exec wrapper (A3).
	// nil → Systemd.Exec default. Seam.
	ctrRmIngest func(ctx context.Context, ref string) error
}

func (c *Config) applyDefaults() {
	if c.Interval <= 0 {
		c.Interval = defaultInterval
	}
	if c.WatchdogStateDir == "" {
		c.WatchdogStateDir = defaultWatchdogStateDir
	}
	if c.WatchdogLogFile == "" {
		c.WatchdogLogFile = defaultWatchdogLogFile
	}
	if c.ProcRoot == "" {
		c.ProcRoot = defaultProcRoot
	}
	if c.CtrTaskRoot == "" {
		c.CtrTaskRoot = defaultCtrTaskRoot
	}
	if c.SandboxCtlRoot == "" {
		c.SandboxCtlRoot = defaultSandboxCtlRoot
	}
	if c.HostResolvConf == "" {
		c.HostResolvConf = defaultHostResolvConf
	}
	if c.K0sWorkerUnitFile == "" {
		c.K0sWorkerUnitFile = defaultK0sWorkerUnitFile
	}
	if c.KubeletPodsDir == "" {
		c.KubeletPodsDir = defaultKubeletPodsDir
	}
	if c.KubeletHealthzURL == "" {
		c.KubeletHealthzURL = defaultKubeletHealthzURL
	}
	if c.CiliumHealthzURL == "" {
		c.CiliumHealthzURL = defaultCiliumHealthzURL
	}
	if c.CiliumSocket == "" {
		c.CiliumSocket = defaultCiliumSocket
	}
	if c.StuckDeleteAge <= 0 {
		c.StuckDeleteAge = defaultStuckDeleteAge
	}
	if c.StuckWedgeAge <= 0 {
		c.StuckWedgeAge = defaultStuckWedgeAge
	}
	if c.KubeletWatchMinAge <= 0 {
		c.KubeletWatchMinAge = defaultKubeletWatchMinAge
	}
	if c.MaxForceDelete <= 0 {
		c.MaxForceDelete = defaultMaxForceDelete
	}
	if c.MaxCtrTaskClean <= 0 {
		c.MaxCtrTaskClean = defaultMaxCtrTaskClean
	}
	if c.MaxShimKill <= 0 {
		c.MaxShimKill = defaultMaxShimKill
	}
	if c.ConsecNeeded <= 0 {
		c.ConsecNeeded = defaultConsecNeeded
	}
	if c.MinRestartInterval <= 0 {
		c.MinRestartInterval = defaultMinRestartInterval
	}
	if c.ProbeGap <= 0 {
		c.ProbeGap = probeGap
	}
	if c.KubeletWdInterval <= 0 {
		c.KubeletWdInterval = defaultKubeletWdInterval
	}
	if c.KubeletWdMaxFail <= 0 {
		c.KubeletWdMaxFail = defaultKubeletWdMaxFail
	}
	if c.KubeletWdProbeURL == "" {
		c.KubeletWdProbeURL = defaultKubeletWdProbeURL
	}
	if c.KubeletWdReprobeGap <= 0 {
		c.KubeletWdReprobeGap = defaultKubeletWdReprobeGap
	}
	if c.APIFallbackURL == "" {
		c.APIFallbackURL = defaultAPIFallbackURL
	}
	if c.KubeletSyncloopURL == "" {
		c.KubeletSyncloopURL = defaultKubeletSyncloopURL
	}
	if c.ContainerdSocket == "" {
		c.ContainerdSocket = defaultContainerdSocket
	}
	if c.CiliumEnvoyReadyURL == "" {
		c.CiliumEnvoyReadyURL = defaultCiliumEnvoyReadyURL
	}
	if c.CtrIngestDir == "" {
		c.CtrIngestDir = defaultCtrIngestDir
	}
	if c.K0sDataDir == "" {
		c.K0sDataDir = defaultK0sDataDir
	}
	if c.SysClassNet == "" {
		c.SysClassNet = defaultSysClassNet
	}
	if c.NebulaIface == "" {
		c.NebulaIface = defaultNebulaIface
	}
	if c.CiliumIface == "" {
		c.CiliumIface = defaultCiliumIface
	}
	if c.CiliumRuntimeConfig == "" {
		c.CiliumRuntimeConfig = defaultCiliumRuntimeConfig
	}
	if c.ZombieStormThreshold <= 0 {
		c.ZombieStormThreshold = zombieStormThreshold
	}
	if c.CtrIngestMaxAge <= 0 {
		c.CtrIngestMaxAge = ctrIngestMaxAge
	}
	if c.CtrIngestScanInterval <= 0 {
		c.CtrIngestScanInterval = ctrIngestScanInterval
	}
	if c.K0sDiskHighWatermark <= 0 {
		c.K0sDiskHighWatermark = k0sDiskHighWatermark
	}
	if c.killFn == nil {
		c.killFn = func(pid int, sig syscall.Signal) error {
			return syscall.Kill(pid, sig)
		}
	}
	if c.nowFn == nil {
		c.nowFn = time.Now
	}
	if c.probeHTTP == nil {
		// curl -ks parity: insecure TLS (kubelet cert SANs don't cover
		// 127.0.0.1), and ANY HTTP response — including 401 — means
		// the listener is alive.
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // mirrors curl -ks
		tr.IdleConnTimeout = 90 * time.Second
		client := &http.Client{Transport: tr}
		c.probeHTTP = func(ctx context.Context, url string, timeout time.Duration) error {
			pctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			req, err := http.NewRequestWithContext(pctx, http.MethodGet, url, nil)
			if err != nil {
				return err
			}
			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
			return nil
		}
	}
	if c.unixGet == nil {
		c.unixGet = func(ctx context.Context, socket, path string) ([]byte, error) {
			// DisableKeepAlives: the transport is built per call, so a
			// kept-alive unix conn would pin the readLoop/writeLoop
			// goroutines for the transport's whole IdleConnTimeout —
			// with keep-alives off the conn closes on Body.Close and
			// they finish immediately. Draining the body first lets
			// the close happen promptly.
			tr := &http.Transport{
				DisableKeepAlives: true,
				DialContext: func(dctx context.Context, _, _ string) (net.Conn, error) {
					d := net.Dialer{Timeout: 5 * time.Second}
					return d.DialContext(dctx, "unix", socket)
				},
			}
			cl := &http.Client{Transport: tr, Timeout: 10 * time.Second}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet,
				"http://localhost"+path, nil)
			if err != nil {
				return nil, err
			}
			resp, err := cl.Do(req)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
				return nil, fmt.Errorf("cilium api %s: status %d", path, resp.StatusCode)
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			return body, err
		}
	}
	if c.ctrRmImage == nil {
		sd := c.Systemd
		c.ctrRmImage = func(ctx context.Context, image string) error {
			if sd == nil {
				return fmt.Errorf("no systemd client wired")
			}
			_, err := sd.Exec(ctx,
				"k0s", "ctr", "--namespace", "k8s.io", "images", "rm", "--sync", image)
			return err
		}
	}
	if c.journalFn == nil {
		sd := c.Systemd
		c.journalFn = func(ctx context.Context) (string, error) {
			if sd == nil {
				return "", nil
			}
			return sd.Journal(ctx, "k0sworker.service", journalWindow)
		}
	}
	if c.journalAnyFn == nil {
		sd := c.Systemd
		c.journalAnyFn = func(ctx context.Context) (string, error) {
			if sd == nil {
				return "", nil
			}
			return sd.ExecCombined(ctx,
				"journalctl", "-n", "1", "--no-pager")
		}
	}
	if c.probeBodyOK == nil {
		// kubelet :10248 contract (curl -s parity): the healthz port is
		// unauthenticated plaintext and the body must be exactly "ok" —
		// a wedged kubelet can still answer HTTP with a non-ok body.
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.IdleConnTimeout = 90 * time.Second
		client := &http.Client{Transport: tr}
		c.probeBodyOK = func(ctx context.Context, url string, timeout time.Duration) bool {
			pctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			req, err := http.NewRequestWithContext(pctx, http.MethodGet, url, nil)
			if err != nil {
				return false
			}
			resp, err := client.Do(req)
			if err != nil {
				return false
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			return strings.TrimSpace(string(body)) == "ok"
		}
	}
	if c.probeHTTPStatus == nil {
		// Same insecure-TLS transport as probeHTTP — the status code
		// is the verdict (syncloop 500, envoy /ready 503).
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // mirrors curl -ks
		tr.IdleConnTimeout = 90 * time.Second
		client := &http.Client{Transport: tr}
		c.probeHTTPStatus = func(ctx context.Context, url string, timeout time.Duration) (int, error) {
			pctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			req, err := http.NewRequestWithContext(pctx, http.MethodGet, url, nil)
			if err != nil {
				return 0, err
			}
			resp, err := client.Do(req)
			if err != nil {
				return 0, err
			}
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
			return resp.StatusCode, nil
		}
	}
	if c.probeUnixSock == nil {
		c.probeUnixSock = func(ctx context.Context, socket string, timeout time.Duration) error {
			d := net.Dialer{Timeout: timeout}
			conn, err := d.DialContext(ctx, "unix", socket)
			if err != nil {
				return err
			}
			// A successful dial IS the verdict — a close error
			// (e.g. the peer reset first) must not downgrade it.
			_ = conn.Close()
			return nil
		}
	}
	if c.statfsFn == nil {
		c.statfsFn = unix.Statfs
	}
	if c.ctrRmIngest == nil {
		sd := c.Systemd
		c.ctrRmIngest = func(ctx context.Context, ref string) error {
			if sd == nil {
				return fmt.Errorf("no systemd client wired")
			}
			_, err := sd.Exec(ctx,
				"k0s", "ctr", "-n", "k8s.io", "content", "ingest", "rm", ref)
			return err
		}
	}
}

// Regexes — anchored where the shell learned to anchor (the konn pod
// name and the DNS pod names MUST be anchored: unanchored ~= filters
// previously matched konnectivity-agent-patcher-* and coredns-* job
// pods → wrong pause killed, incident 2026-09-26).
var (
	// config.json annotation extraction — same pattern shape as the
	// shell sed: key, junk up to the quote, 36-char uid value.
	podUIDRe        = regexp.MustCompile(`"io\.kubernetes\.pod\.uid"[^0-9a-f-]*"([0-9a-f-]{36})"`)
	containerNameRe = regexp.MustCompile(`"io\.kubernetes\.container\.name"[^"]*"([^"]+)"`)
	// --node-ip=<ip> inside the k0sworker unit's ExecStart.
	nodeIPRe = regexp.MustCompile(`--node-ip=([0-9.]+)`)
	// --agent-identifiers=host=<ip> inside proxy-agent cmdline —
	// fallback when environ is unreadable. NEVER grep bare 'host='
	// (matches --proxy-server-host first — the false positive that
	// caused the 163x pause-kill loop of 2026-09-19..23).
	agentHostRe = regexp.MustCompile(`--agent-identifiers=host=([0-9.]+)`)
	// DaemonSet pod names only (anchored — see comment block above).
	konnPodRe = regexp.MustCompile(`^konnectivity-agent-[a-z0-9]+$`)
	dnsPodRe  = regexp.MustCompile(`^(node-local-dns-[a-z0-9]+|coredns-[a-z0-9]+-[a-z0-9]+)$`)
	pidDirRe  = regexp.MustCompile(`^[0-9]+$`)
	// Journal signatures (05/06) — grep -cE parity: count MATCHING
	// LINES, not occurrences.
	stallJournalRe = regexp.MustCompile(`node "[^"]+" not found|not registered yet`)
	watchJournalRe = regexp.MustCompile(`not registered|no relationship found between node`)
	// `containerd-shim-runc-v2 ... -id <64hex>` — orphan-shim task id
	// extraction (shell sed pattern).
	shimIDRe = regexp.MustCompile(`-id ([0-9a-f]{64})`)
	// cri.container-type=sandbox inside task config.json — pause
	// tasks legitimately lack log.json (shell grep -q parity).
	sandboxTypeRe = regexp.MustCompile(`cri\.container-type[^,]*sandbox`)
	// Corrupted containerd layer/content-store signatures inside a
	// pod's Waiting message (37) — a missing blob/snapshot never
	// heals by retrying the pull; the image record must go.
	corruptImageRe = regexp.MustCompile(
		`content digest sha256:[0-9a-f]+: not found|` +
			`failed to extract layer|` +
			`parent snapshot .* does not exist`)
	// Pod UID inside a /proc/<pid>/cgroup path — kubepods slices
	// embed it with underscores
	// (kubepods-burstable-pod<8_4_4_4_12>.slice), some runtimes keep
	// dashes; both normalize to the dashed form.
	podUIDCgroupRe = regexp.MustCompile(`pod([0-9a-fA-F_-]{36})`)
)

// Hygiene runs the worker checks on one ticker.
type Hygiene struct {
	cfg Config

	// In-memory consecutive counters — the shell kept these as
	// consecutive-* files; in-agent state survives between cycles and
	// an agent restart just re-arms the count (bounded by Interval).
	wedgeFails      int
	konnFails       int
	dnsFails        int
	stallFails      int
	watchFails      int
	ciliumFails     int
	ciliumInitFails int
	ciliumIPAMFails int
	// kubeletWdFails is the T15 feeder's consecutive-fail counter —
	// in-memory like the others (the shell counted within one feeder
	// process anyway; an agent restart re-arms bounded by the 15s tick).
	kubeletWdFails int
	// kubeletFeederWasActive tracks the last tick's activation state
	// so a false→true flip (node re-added to systemd_watchdog_hosts,
	// unit file reinstalled, WD_SIG lifted) drops a stale partial
	// fail-streak instead of counting it toward a restart.
	kubeletFeederWasActive bool
	taskMapBuilds          int // buildTaskMap invocation count (tests)

	// Wave-2 counters/state: A4 syncloop + containerd-sock, A3
	// ingest GC, A2 zombie storm (per-parent streaks), A5 journald,
	// B1 cilium-envoy, B4 MTU drift.
	syncloopFails int
	ctrsockFails  int
	envoyFails    int
	journaldFails int
	// zombieStreaks counts consecutive cycles each parent has
	// produced > ZombieStormThreshold defunct children (A2). Keyed
	// by zombieParent (pid + stat starttime), NOT raw pid — a pid
	// recycled between cycles must not inherit a dead process's
	// streak and hold the latch open for a storm that is over.
	zombieStreaks map[zombieParent]int
	// ciliumAgentKilled is set by killCiliumAgent — B1 restarts
	// cilium-envoy the same cycle so its xDS listener can't hold a
	// stale socket across the agent restart.
	ciliumAgentKilled bool
	// lastIngestScan is the last time the ingest GC walked the
	// ingest dir — the 6h periodic trigger (A3).
	lastIngestScan time.Time

	// rateMu serialises rate-budget check+spend pairs: the feeder
	// goroutine (remediate G5/G6) and Cycle checks compete for the
	// shared "last-restart" budget — an unlocked check-then-spend
	// lets both pass inside the same window (TOCTOU double-restart).
	// Held only around the file check+write, never across
	// network/systemd calls.
	rateMu          sync.Mutex
	cycles          *prometheus.CounterVec // check, result
	actions         *prometheus.CounterVec // check, action
	ciliumAllocated prometheus.Gauge       // cilium IPAM allocated IPs (38)
	ciliumLeaked    prometheus.Gauge       // allocated − in-use (38)
	// ctrIngestsCleaned counts ingest dirs removed by the A3 GC.
	ctrIngestsCleaned prometheus.Counter
}

// New returns a Hygiene and registers its metrics on reg.
func New(cfg Config, reg prometheus.Registerer) (*Hygiene, error) {
	cfg.applyDefaults()
	h := &Hygiene{cfg: cfg, zombieStreaks: map[zombieParent]int{}}

	h.cycles = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_workerhygiene_cycles_total",
		Help: "Worker-hygiene check cycles by check and result (ok|abort|gated).",
	}, []string{"check", "result"})
	h.actions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_workerhygiene_actions_total",
		Help: "Worker-hygiene remediation actions by check and action " +
			"(force_delete|pod_delete|sigkill|pause_kill|restart|rm_dir|shim_kill|image_rm|remediate).",
	}, []string{"check", "action"})
	h.ciliumAllocated = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_workerhygiene_cilium_allocated_ips",
		Help: "IPv4 addresses cilium IPAM reports allocated on this node.",
	})
	h.ciliumLeaked = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_workerhygiene_cilium_leaked_ips",
		Help: "Allocated cilium IPs not held by a non-hostNetwork Running pod on this node (leaked).",
	})
	h.ctrIngestsCleaned = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "node_host_agent_workerhygiene_ctr_ingests_cleaned_total",
		Help: "Stale containerd content ingest dirs removed by the ingest GC (39).",
	})

	if reg != nil {
		for _, c := range []prometheus.Collector{
			h.cycles, h.actions, h.ciliumAllocated, h.ciliumLeaked,
			h.ctrIngestsCleaned,
		} {
			if err := reg.Register(c); err != nil {
				return nil, fmt.Errorf("register workerhygiene metrics: %w", err)
			}
		}
	}
	return h, nil
}

// Name identifies the subsystem for logging.
func (h *Hygiene) Name() string { return "workerhygiene" }

// Run checks immediately, then every Interval until ctx is cancelled.
// The T15 kubelet watchdog feeder runs on its own faster ticker in
// parallel — the controllerhygiene runFeeder pattern (shell had a
// dedicated systemd unit looping every ~15s).
func (h *Hygiene) Run(ctx context.Context) {
	if !h.cfg.Enabled {
		// Constructed but disabled — idle instead of returning: the
		// agent restarts a returned Run in a hot loop.
		<-ctx.Done()
		return
	}
	// The tick self-gates on kubeletFeederActive() each round, so a
	// node dropped from systemd_watchdog_hosts (unit file pruned) or
	// a WD_SIG_KUBELET_WATCHDOG=off conf rewrite idles without an
	// agent restart. The wait makes Run's return coincide with the
	// feeder's exit — a restarted Run must never stack a second
	// feeder, and callers may tear down cfg paths on return.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		h.runKubeletFeeder(ctx)
	}()
	h.Cycle(ctx)
	t := time.NewTicker(h.cfg.Interval)
	defer t.Stop()
	defer wg.Wait()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.Cycle(ctx)
		}
	}
}

// Cycle runs one round of all three checks. The k0sworker unit file
// gates everything (WD_REQUIRES: k0sworker) — controllers and test
// envs without the unit are a silent no-op. Each check must never
// panic and degrades to no-op on missing files.
func (h *Hygiene) Cycle(ctx context.Context) {
	if _, err := os.Stat(h.cfg.K0sWorkerUnitFile); err != nil {
		h.cycles.WithLabelValues("all", "gated").Inc()
		return
	}
	// uptime gate (WD_REQUIRES: uptime k0sworker — the shell also
	// required uptime >= 1200s): a freshly rebooted node gets grace
	// before any destructive check runs — Terminating ages surviving
	// a reboot must not trigger action inside the first minutes.
	if up, err := h.uptimeSeconds(); err == nil && up < minUptimeSeconds {
		h.cycles.WithLabelValues("all", "uptime_gate").Inc()
		return
	}
	// One LIST feeds teardown + konnectivity-pod-lookup + dns checks.
	// The field selector is still sent (production pre-filter) but the
	// node match is re-checked per pod — the fake clientset ignores
	// selectors, and a wrong match is a wrong kill.
	pods, apiOK := h.listNodePods(ctx)
	// The containerd task map reads EVERY task dir's config.json —
	// build it lazily, at most once per cycle, shared between the
	// teardown, stall and dns checks. Most cycles neither needs it (no
	// pod Terminating, no dns-pod running) so it stays unbuilt.
	var tasks map[string][]ctrTask
	tasksOnce := func() map[string][]ctrTask {
		if tasks == nil {
			tasks = h.buildTaskMap()
		}
		return tasks
	}
	// The k0sworker journal snapshot is shared between 05/06 — the
	// runner dumped it once per run for the same reason (journald is
	// slow on CPU-starved nodes; two windows could disagree). Lazy:
	// an idle cycle never touches journald.
	journal := ""
	journalSet := false
	journalOnce := func() string {
		if !journalSet {
			journalSet = true
			j, err := h.cfg.journalFn(ctx)
			if err != nil {
				h.appendLog(fmt.Sprintf("k0sworker journal snapshot failed: %v", err))
			}
			journal = j
		}
		return journal
	}
	// Refresh the conf every cycle when a source is wired — hostconfig
	// rewrites /etc/node-watchdog.conf mid-run (WD_SIG_* kill switches,
	// API_BACKENDS); the runner re-sourced it every run.
	if h.cfg.WatchdogSrc != nil {
		h.cfg.Watchdog = h.cfg.WatchdogSrc.Get()
	}
	if wd := h.cfg.Watchdog; wd != nil && h.cfg.WatchdogSrc != nil {
		h.cfg.APIBackends = wd.APIBackendIPs()
	}
	// workerActive is the WD_REQUIRES k0sworker gate for ALL worker
	// checks — a node where k0sworker is intentionally down/inactive
	// skips every check exactly like the runner did. A nil Systemd
	// client (tests, unwired agent) can't answer → treat as active
	// so the checks still run on their other evidence. A client that
	// answers with an ERROR (dbus down, systemctl missing) is
	// different from nil — the gate is wired but unverifiable, so
	// fail closed: gate the checks off this cycle rather than risk
	// hygiene actions on a possibly intentionally-downed worker.
	workerActive := true
	if h.cfg.Systemd != nil {
		if active, err := h.cfg.Systemd.Active(ctx, "k0sworker.service"); err != nil {
			slog.Warn("workerhygiene: k0sworker is-active probe "+
				"failed — worker checks gated off this cycle "+
				"(fail closed)",
				"subsystem", "workerhygiene",
				"unit", "k0sworker.service", "error", err)
			workerActive = false
		} else {
			workerActive = active
		}
	}
	// B1: an agent kill this cycle also restarts cilium-envoy — the
	// flag is reset before any check runs.
	h.ciliumAgentKilled = false
	sigOn := func(name string) bool {
		return h.cfg.Watchdog == nil || h.cfg.Watchdog.SignalEnabled(name)
	}
	run := func(name string, fn func()) {
		if sigOn(name) {
			fn()
		} else {
			h.cycles.WithLabelValues(name, "disabled").Inc()
		}
	}
	run(checkStall, func() {
		h.checkKubeletStall(ctx, apiOK, journalOnce, workerActive)
	})
	run(checkWatch, func() {
		h.checkKubeletWatchWedge(ctx, pods, apiOK, journalOnce, workerActive)
	})
	run(checkTeardown, func() {
		h.checkPodTeardown(ctx, pods, apiOK, tasksOnce, workerActive)
	})
	run(checkKonn, func() {
		h.checkKonnectivity(ctx, pods, workerActive)
	})
	run(checkDNS, func() {
		h.checkDNSResolvDrift(pods, apiOK, tasksOnce, workerActive)
	})
	run(checkSyncloop, func() {
		h.checkKubeletSyncloop(ctx, workerActive)
	})
	run(checkCtrSock, func() {
		h.checkContainerdSock(ctx, workerActive)
	})
	run(checkCtrTasks, func() {
		h.checkCtrTasks(ctx, workerActive)
	})
	run(checkIngestGC, func() {
		h.checkCtrIngestGC(ctx, workerActive)
	})
	run(checkCilium, func() {
		h.checkCilium(ctx, apiOK, workerActive)
	})
	run(checkCiliumInit, func() {
		h.checkCiliumInitStuck(ctx, apiOK, workerActive)
	})
	run(checkCtrImages, func() {
		h.checkCtrImages(ctx, pods, apiOK, workerActive)
	})
	run(checkCiliumIPAM, func() {
		h.checkCiliumIPAM(ctx, pods, apiOK, workerActive)
	})
	run(checkCiliumEnvoy, func() {
		h.checkCiliumEnvoy(ctx, workerActive)
	})
	run(checkCiliumMTU, func() {
		h.checkCiliumMTU(workerActive)
	})
	run(checkZombieStorm, func() {
		h.checkZombieStorm(workerActive)
	})
	run(checkJournald, func() {
		h.checkJournaldIntegrity(ctx, workerActive)
	})
}

// listNodePods lists pods scheduled to this node; apiOK=false means
// the LIST failed — checks treat it as "apiserver unreachable"
// (inconclusive: keep counters/latches, never act).
func (h *Hygiene) listNodePods(ctx context.Context) ([]corev1.Pod, bool) {
	list, err := h.cfg.Client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + h.cfg.NodeName,
	})
	if err != nil {
		h.appendLog(fmt.Sprintf(
			"suspect: pod list failed node=%s: %v — pod checks inconclusive this cycle",
			h.cfg.NodeName, err))
		return nil, false
	}
	pods := make([]corev1.Pod, 0, len(list.Items))
	for i := range list.Items {
		if list.Items[i].Spec.NodeName == h.cfg.NodeName {
			pods = append(pods, list.Items[i])
		}
	}
	return pods, true
}

// --- watchdog file helpers (lib.sh parity) ---
// state-<name>   : latch file, content = epoch of entry
// last-*         : rate-limit budget, content = epoch of last spend
// watchdog log   : "<rfc3339> <msg>" appended to WatchdogLogFile,
//                  mirrored to slog.

// appendLog mirrors lib.sh log(): "<date -Is> <msg>" appended to the
// watchdog log (NPD filelog tails it — message text is a contract),
// plus a slog mirror for `kubectl logs` debugging. Best-effort: an
// unwritable log file never fails a check.
func (h *Hygiene) appendLog(msg string) {
	slog.Info(msg, "subsystem", "workerhygiene")
	f, err := os.OpenFile(h.cfg.WatchdogLogFile,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", h.cfg.nowFn().Format(time.RFC3339), msg)
}

func (h *Hygiene) statePath(name string) string {
	return filepath.Join(h.cfg.WatchdogStateDir, "state-"+name)
}

// stateExists reports whether the latch file is present (e.g. the
// node-overloaded latch written by the shell runner).
func (h *Hygiene) stateExists(name string) bool {
	_, err := os.Stat(h.statePath(name))
	return err == nil
}

// stateEnter creates state-<name> with the current epoch — only when
// absent (the file's mtime/content is when the condition STARTED) and
// logs the transition once, lib.sh STATE-ENTER parity.
func (h *Hygiene) stateEnter(name, extra string) {
	p := h.statePath(name)
	if _, err := os.Stat(p); err == nil {
		return
	}
	content := strconv.FormatInt(h.cfg.nowFn().Unix(), 10) + "\n"
	// Tmp name mirrors apiprober's writeFileAtomic: a leading dot
	// keeps it out of hostmetrics' state-* scan — a "state-<n>.tmp"
	// file would register a phantom "<n>.tmp" watchdog_state series
	// that then sits at 0 forever (seenStates never drops keys).
	tmp := filepath.Join(filepath.Dir(p), ".tmp-"+filepath.Base(p))
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		slog.Warn("workerhygiene: state latch write failed",
			"subsystem", "workerhygiene", "state", name, "path", p, "error", err)
		return
	}
	if err := os.Rename(tmp, p); err != nil {
		slog.Warn("workerhygiene: state latch write failed",
			"subsystem", "workerhygiene", "state", name, "path", p, "error", err)
		return
	}
	if extra != "" {
		h.appendLog(fmt.Sprintf("STATE-ENTER: %s %s", name, extra))
	} else {
		h.appendLog(fmt.Sprintf("STATE-ENTER: %s", name))
	}
}

// stateExit removes state-<name> if present and logs the transition —
// clears the NPD permanent condition.
func (h *Hygiene) stateExit(name string) {
	p := h.statePath(name)
	if _, err := os.Stat(p); err != nil {
		return
	}
	if err := os.Remove(p); err != nil {
		slog.Warn("workerhygiene: state latch remove failed",
			"subsystem", "workerhygiene", "state", name, "path", p, "error", err)
		return
	}
	h.appendLog(fmt.Sprintf("STATE-EXIT: %s", name))
}

// rateOK reports whether the rate budget file is absent, unparseable,
// or older than interval — lib.sh rate_ok parity (garbage → 0 → ok).
func (h *Hygiene) rateOK(name string, interval time.Duration) bool {
	data, err := os.ReadFile(filepath.Join(h.cfg.WatchdogStateDir, name))
	if err != nil {
		return true
	}
	last, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return true
	}
	return h.cfg.nowFn().Unix()-last >= int64(interval.Seconds())
}

// rateSpend writes the current epoch to the budget file. A failed
// write loses the spend — the next check sees the budget as
// unspent — so the operator gets a Warn, not silence.
func (h *Hygiene) rateSpend(name string) {
	p := filepath.Join(h.cfg.WatchdogStateDir, name)
	content := strconv.FormatInt(h.cfg.nowFn().Unix(), 10) + "\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		slog.Warn("workerhygiene: rate budget write failed",
			"subsystem", "workerhygiene", "budget", name, "path", p, "error", err)
	}
}

// rateTrySpend is the atomic check+spend used for the budgets two
// goroutines compete on (feeder remediate G5/G6 vs Cycle checks —
// "last-restart" above all): without the mutex a feeder G5 "ok" and a
// Cycle check "ok" could both pass in the same window and double-spend
// a restart. The spend lands BEFORE the caller acts — a failed action
// still consumed the budget (lib.sh rate_spend parity).
func (h *Hygiene) rateTrySpend(name string, interval time.Duration) bool {
	h.rateMu.Lock()
	defer h.rateMu.Unlock()
	if !h.rateOK(name, interval) {
		return false
	}
	h.rateSpend(name)
	return true
}

// --- /proc + containerd task helpers ---

// procFile joins ProcRoot/<pid>/<elems...>.
func (h *Hygiene) procFile(pid int, elems ...string) string {
	parts := append([]string{h.cfg.ProcRoot, strconv.Itoa(pid)}, elems...)
	return filepath.Join(parts...)
}

// pidLive mirrors the shell liveness check: kill -0 succeeds AND the
// /proc/<pid>/stat state field is not "Z" (zombie). An unreadable or
// unparseable stat after a successful kill -0 counts as LIVE — fail
// toward not-killing / not-force-deleting on uncertainty. The stat
// state field is parsed after the LAST ')' because comm (field 2) can
// contain spaces and parens (same trick as read_cpu_jiffies).
func (h *Hygiene) pidLive(pid int) bool {
	if pid <= 0 {
		return false
	}
	if h.cfg.killFn(pid, 0) != nil {
		return false
	}
	data, err := os.ReadFile(h.procFile(pid, "stat"))
	if err != nil {
		return true
	}
	s := string(data)
	if i := strings.LastIndexByte(s, ')'); i >= 0 {
		if f := strings.Fields(s[i+1:]); len(f) > 0 {
			return f[0] != "Z"
		}
	}
	return true
}

// procPIDs lists the numeric pid dirs under ProcRoot.
// uptimeSeconds parses <ProcRoot>/uptime — a read failure returns an
// error and Cycle proceeds (fail-open like the shell's missing-uptime
// edge: gating on a parse failure would silently disable the checks).
func (h *Hygiene) uptimeSeconds() (float64, error) {
	data, err := os.ReadFile(filepath.Join(h.cfg.ProcRoot, "uptime"))
	if err != nil {
		return 0, err
	}
	up, err := strconv.ParseFloat(strings.Fields(string(data))[0], 64)
	if err != nil {
		return 0, err
	}
	return up, nil
}

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
	return pids
}

// procCmdline returns the argv of pid (NUL-separated in /proc).
func (h *Hygiene) procCmdline(pid int) []string {
	data, err := os.ReadFile(h.procFile(pid, "cmdline"))
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
}

// procEnvValue reads KEY=<value> from /proc/<pid>/environ.
func (h *Hygiene) procEnvValue(pid int, key string) string {
	data, err := os.ReadFile(h.procFile(pid, "environ"))
	if err != nil {
		return ""
	}
	prefix := key + "="
	for _, e := range strings.Split(string(data), "\x00") {
		if v, ok := strings.CutPrefix(e, prefix); ok {
			return v
		}
	}
	return ""
}

// ctrTask is one containerd task dir (runtime-v2 task or sandbox
// controller shim) — the node-side ground truth for "are tasks of
// this pod still around", replacing `ctr tasks ls` so no ctr socket
// is needed inside the agent pod.
type ctrTask struct {
	uid  string // io.kubernetes.pod.uid annotation
	name string // io.kubernetes.container.name annotation ("pause"/"POD" = sandbox infra)
	pid  int    // init.pid contents
	live bool   // kill -0 ok and not zombie
}

// buildTaskMap scans CtrTaskRoot/*/ and SandboxCtlRoot/*/ once per
// cycle and groups task dirs by pod UID — shared by the teardown and
// dns checks. Missing roots/files are skipped, never fatal.
// taskMapBuilds counts invocations so tests can assert the lazy
// once-per-cycle behaviour directly.
func (h *Hygiene) buildTaskMap() map[string][]ctrTask {
	h.taskMapBuilds++
	m := map[string][]ctrTask{}
	for _, root := range []string{h.cfg.CtrTaskRoot, h.cfg.SandboxCtlRoot} {
		entries, err := os.ReadDir(root)
		if err != nil {
			// A genuinely-absent root is normal (no sandbox-shim
			// dir on this containerd layout); a permission/IO
			// error silently degrades the task map — force-delete
			// decisions then run on incomplete data.
			if !os.IsNotExist(err) {
				h.appendLog(fmt.Sprintf(
					"suspect: ctr task root %s unreadable: %v — task map incomplete",
					root, err))
			}
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			d := filepath.Join(root, e.Name())
			cfgData, err := os.ReadFile(filepath.Join(d, "config.json"))
			if err != nil {
				continue
			}
			um := podUIDRe.FindSubmatch(cfgData)
			if um == nil {
				continue
			}
			t := ctrTask{uid: string(um[1])}
			if nm := containerNameRe.FindSubmatch(cfgData); nm != nil {
				t.name = string(nm[1])
			}
			if pidData, err := os.ReadFile(filepath.Join(d, "init.pid")); err == nil {
				if pid, err := strconv.Atoi(strings.TrimSpace(string(pidData))); err == nil {
					t.pid = pid
					t.live = h.pidLive(pid)
				}
			}
			m[t.uid] = append(m[t.uid], t)
		}
	}
	return m
}

// countLive returns how many tasks of a UID still have a live init
// pid — the force-delete precondition (zero live tasks = verified
// container death, status.containerStatuses is only last-known).
func countLive(tasks []ctrTask) int {
	n := 0
	for _, t := range tasks {
		if t.live {
			n++
		}
	}
	return n
}

// --- Check 1: pod-teardown (36-pod-teardown.sh) ---

// podHasPVC reports whether the pod mounts a persistentVolumeClaim —
// force-deleting a PVC consumer on a wrong "dead" verdict risks a
// dual-mount of an RWO volume.
func podHasPVC(p *corev1.Pod) bool {
	for _, v := range p.Spec.Volumes {
		// PVC + generic ephemeral volumes share the same dual-mount
		// risk class on a wrong "dead" verdict.
		if v.PersistentVolumeClaim != nil || v.Ephemeral != nil {
			return true
		}
	}
	return false
}

// isMirrorPod reports kubelet-static mirror pods — deleting the
// mirror object changes nothing on disk.
func isMirrorPod(p *corev1.Pod) bool {
	_, ok := p.Annotations["kubernetes.io/config.mirror"]
	return ok
}

// forceDeletePod removes the pod object with grace 0 + Background
// propagation — reached only after zero-live-task verification, so it
// is pure object cleanup (no split-brain/dual-mount risk).
func (h *Hygiene) forceDeletePod(ctx context.Context, p *corev1.Pod) error {
	// Log line is an NPD contract: ends in "force-delete pod ..." so
	// the StuckPodForceDeleted filelog pattern still fires.
	h.appendLog(fmt.Sprintf(
		"POD-TEARDOWN-FORCE-DELETE: force-delete pod %s/%s (uid %.8s) - Terminating %ds, zero live tasks",
		p.Namespace, p.Name, string(p.UID),
		int64(h.cfg.nowFn().Sub(p.DeletionTimestamp.Time).Seconds())))
	return h.cfg.Client.CoreV1().Pods(p.Namespace).Delete(ctx, p.Name,
		metav1.DeleteOptions{
			GracePeriodSeconds: ptr.To[int64](0),
			PropagationPolicy:  ptr.To(metav1.DeletePropagationBackground),
		})
}

func (h *Hygiene) checkPodTeardown(ctx context.Context, pods []corev1.Pod,
	apiOK bool, tasksOnce func() map[string][]ctrTask, workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkTeardown, "gated").Inc()
		return
	}
	if !apiOK {
		// Inconclusive — shell "exit 0" semantics: abort silently,
		// keep counters and latches (no state_exit flap on API blip).
		h.cycles.WithLabelValues(checkTeardown, "abort").Inc()
		return
	}
	// The task map is only worth building once a Terminating pod
	// exists — with none, the whole loop below is a no-op.
	var tasks map[string][]ctrTask
	now := h.cfg.nowFn()
	wedged := 0
	ndel := 0
	for i := range pods {
		p := &pods[i]
		if p.DeletionTimestamp == nil {
			continue
		}
		if tasks == nil {
			tasks = tasksOnce()
		}
		uid := string(p.UID)
		age := now.Sub(p.DeletionTimestamp.Time)
		// Wedge evidence is measured on pod level: Terminating long
		// past StuckWedgeAge AND containerd still holds a task dir
		// (live or not) — sig7/force-delete had their chance; only a
		// reboot clears a shim/kernel-level wedge.
		if age >= h.cfg.StuckWedgeAge && len(tasks[uid]) >= 1 {
			wedged++
		}
		if age < h.cfg.StuckDeleteAge {
			continue
		}
		// Rule C: external resources or kubelet mirrors → never
		// force-delete (finalizer = another controller owns cleanup;
		// PVC = dual-mount risk; mirror = pointless).
		if len(p.Finalizers) > 0 || podHasPVC(p) || isMirrorPod(p) {
			continue
		}
		if countLive(tasks[uid]) > 0 {
			continue // a live task exists — kubelet may still be tearing down
		}
		if ndel >= h.cfg.MaxForceDelete {
			continue // per-cycle cap bounds the blast radius
		}
		if err := h.forceDeletePod(ctx, p); err != nil {
			h.appendLog(fmt.Sprintf("suspect: force-delete %s/%s failed: %v",
				p.Namespace, p.Name, err))
			continue
		}
		ndel++
		h.actions.WithLabelValues(checkTeardown, "force_delete").Inc()
	}

	switch {
	case wedged >= 1:
		h.wedgeFails++
		if h.wedgeFails >= h.cfg.ConsecNeeded {
			if h.stateExists("node-overloaded") {
				// Suppression parity: a wedge under overload is a
				// symptom — rebooting would dump 100% of its load
				// onto the remaining nodes (amplifier). Log-only,
				// once per suppression episode.
				if !h.stateExists("pod-teardown-wedged") {
					h.appendLog(fmt.Sprintf(
						"pod-teardown-wedged suppressed-overloaded stuck=%d", wedged))
				}
			} else {
				h.stateEnter("pod-teardown-wedged", fmt.Sprintf("stuck=%d", wedged))
			}
		} else {
			h.appendLog(fmt.Sprintf("suspect: pod-teardown-wedged stuck=%d (check %d/%d)",
				wedged, h.wedgeFails, h.cfg.ConsecNeeded))
		}
	default:
		h.wedgeFails = 0
		h.stateExit("pod-teardown-wedged")
	}
	h.cycles.WithLabelValues(checkTeardown, "ok").Inc()
}

// --- Check 2: konnectivity IP drift (30-konnectivity.sh) ---

// k0sWorkerNodeIP reads --node-ip=<ip> out of the k0sworker unit —
// the node's InternalIP konnectivity-agent should have baked in.
func (h *Hygiene) k0sWorkerNodeIP() string {
	data, err := os.ReadFile(h.cfg.K0sWorkerUnitFile)
	if err != nil {
		return ""
	}
	if m := nodeIPRe.FindSubmatch(data); m != nil {
		return string(m[1])
	}
	return ""
}

// isProxyAgent matches `pgrep -f 'proxy-agent --'` on the joined
// cmdline (the bare "/proxy-agent" prefix covers argv[0]-only forms).
func isProxyAgent(argv []string) bool {
	// Shell parity: `pgrep -f 'proxy-agent --'` — the trailing
	// space/dash keeps /proxy-agent-foo lookalikes out.
	joined := strings.Join(argv, " ")
	return strings.HasPrefix(joined, "/proxy-agent ") ||
		strings.Contains(joined, "proxy-agent --")
}

// proxyAgentHost returns the host identifier baked into the agent:
// NODE_IP from environ (downward status.hostIP, set at pod create),
// falling back to --agent-identifiers=host=<ip> on the cmdline.
func (h *Hygiene) proxyAgentHost(pid int, argv []string) string {
	if v := h.procEnvValue(pid, "NODE_IP"); v != "" {
		return v
	}
	if m := agentHostRe.FindStringSubmatch(strings.Join(argv, " ")); m != nil {
		return m[1]
	}
	return ""
}

// deleteKonnectivityPod deletes this node's konnectivity-agent pod in
// kube-system (grace 0) — the Go equivalent of SIGKILL on its pause
// task: the DaemonSet recreates the pod with freshly baked env.
// Anchored name match + namespace pin (see konnPodRe comment).
func (h *Hygiene) deleteKonnectivityPod(ctx context.Context, pods []corev1.Pod) bool {
	for i := range pods {
		p := &pods[i]
		if p.Namespace != "kube-system" || !konnPodRe.MatchString(p.Name) ||
			p.DeletionTimestamp != nil {
			continue
		}
		if err := h.cfg.Client.CoreV1().Pods(p.Namespace).Delete(ctx, p.Name,
			metav1.DeleteOptions{GracePeriodSeconds: ptr.To[int64](0)}); err != nil {
			h.appendLog(fmt.Sprintf(
				"suspect: konnectivity pod delete %s/%s failed: %v",
				p.Namespace, p.Name, err))
			continue // a stale entry must not block the next candidate
		}
		return true
	}
	return false
}

func (h *Hygiene) checkKonnectivity(ctx context.Context, pods []corev1.Pod, workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkKonn, "gated").Inc()
		return
	}
	nodeIP := h.k0sWorkerNodeIP()
	// Healthy = ANY proxy-agent process baked with the current node
	// IP. Scan ALL processes, never take the first match: an orphaned
	// agent (task dir gone, process alive under a dead shim) keeps its
	// old NODE_IP and usually has the lower pid — first-match would
	// read the orphan's environ and report "stale" forever
	// (incident 2026-09-19..23: 163 pause kills). Only when NO
	// process matches do we suspect.
	healthy := false
	agentHost := ""
	stalePID := 0
	for _, pid := range h.procPIDs() {
		argv := h.procCmdline(pid)
		if !isProxyAgent(argv) {
			continue
		}
		phost := h.proxyAgentHost(pid, argv)
		if nodeIP != "" && phost == nodeIP {
			healthy = true
			break
		}
		if phost != "" && agentHost == "" {
			agentHost = phost
			stalePID = pid
		}
	}

	if healthy || nodeIP == "" || agentHost == "" {
		// Healthy or inconclusive (no node-ip parsed / no proxy-agent
		// found — e.g. konnectivity not deployed): reset, drop latch.
		h.konnFails = 0
		h.stateExit("konnectivity-ip-mismatch")
		h.cycles.WithLabelValues(checkKonn, "ok").Inc()
		return
	}

	h.konnFails++
	h.stateEnter("konnectivity-ip-mismatch",
		fmt.Sprintf("host=%s node-ip=%s", agentHost, nodeIP))
	if h.konnFails >= h.cfg.ConsecNeeded &&
		h.rateTrySpend("last-konn-restart", h.cfg.MinRestartInterval) {
		// Budget spent atomically BEFORE acting — a failed action
		// still consumed it (conservative, rate_spend parity).
		h.konnFails = 0
		// NPD contract: "recreating konnectivity-agent ..." fires the
		// KonnectivityStaleId filelog pattern.
		h.appendLog(fmt.Sprintf(
			"KONNECTIVITY-IP-RESTART: recreating konnectivity-agent sandbox - stale identifier host=%s != node-ip=%s",
			agentHost, nodeIP))
		if h.deleteKonnectivityPod(ctx, pods) {
			h.actions.WithLabelValues(checkKonn, "pod_delete").Inc()
		} else if stalePID > 0 {
			// No API pod found (list failed or pod renamed) — kill
			// the stale proxy-agent directly. Least-bad: a container
			// restart alone can't fix env baked at pod create, but
			// it still clears a hung agent while humans look.
			if err := h.cfg.killFn(stalePID, syscall.SIGKILL); err != nil {
				h.appendLog(fmt.Sprintf(
					"suspect: kill stale proxy-agent pid=%d failed: %v", stalePID, err))
			} else {
				h.appendLog(fmt.Sprintf(
					"ACTION: killed stale proxy-agent pid=%d — no API pod found",
					stalePID))
			}
			h.actions.WithLabelValues(checkKonn, "sigkill").Inc()
		}
	} else {
		// NPD contract: "konnectivity stale identifier ..." fires the
		// same KonnectivityStaleId pattern while accumulating.
		h.appendLog(fmt.Sprintf(
			"suspect: konnectivity stale identifier host=%s != node-ip=%s (check %d/%d)",
			agentHost, nodeIP, h.konnFails, h.cfg.ConsecNeeded))
	}
	h.cycles.WithLabelValues(checkKonn, "ok").Inc()
}

// --- Check 3: DNS resolv.conf drift (33-dns-resolv-drift.sh) ---

// nameserverSet returns the sorted-unique nameserver IPs of a
// resolv.conf file. ok=false when the file contains
// "svc.cluster.local" — a ClusterFirst resolv.conf is NOT a host
// snapshot and must be skipped (killing those pauses killed innocent
// job pods — incident 2026-09-26).
func nameserverSet(path string) (ns []string, clusterLocal bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	if strings.Contains(string(data), "svc.cluster.local") {
		return nil, true
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" && !seen[f[1]] {
			seen[f[1]] = true
			ns = append(ns, f[1])
		}
	}
	sort.Strings(ns)
	return ns, false
}

func equalNS(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// dnsStale is one drifted DNS pod: the pause pid to SIGKILL and the
// pod name for logging.
type dnsStale struct {
	pod string
	pid int
}

// pausePIDOf finds the live pause (sandbox infra) task pid for a pod
// UID — container name "pause" (CRI) or "POD" (containerd internal
// name) in the task config.json annotations.
func pausePIDOf(tasks []ctrTask) int {
	for _, t := range tasks {
		if t.live && (t.name == "pause" || t.name == "POD") {
			return t.pid
		}
	}
	return 0
}

func (h *Hygiene) checkDNSResolvDrift(pods []corev1.Pod, apiOK bool,
	tasksOnce func() map[string][]ctrTask, workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkDNS, "gated").Inc()
		return
	}
	if !apiOK {
		// Same inconclusive rule as teardown: a failed LIST keeps
		// counters and the latch (no flap on API blip).
		h.cycles.WithLabelValues(checkDNS, "abort").Inc()
		return
	}
	hostNS, _ := nameserverSet(h.cfg.HostResolvConf)

	var stale []dnsStale
	if len(hostNS) > 0 { // empty host set → nothing to compare (shell parity)
		// Task map is built only when a Running dns-pod actually
		// needs its pause pid looked up.
		var tasks map[string][]ctrTask
		for i := range pods {
			p := &pods[i]
			if p.Status.Phase != corev1.PodRunning ||
				!dnsPodRe.MatchString(p.Name) {
				continue
			}
			if tasks == nil {
				tasks = tasksOnce()
			}
			pid := pausePIDOf(tasks[string(p.UID)])
			if pid == 0 {
				continue // no live pause task — can't see the pod's resolv.conf
			}
			// Read the POD's resolv.conf through the pause mount ns —
			// ProcRoot/<pid>/root is the task's filesystem view.
			podNS, clusterLocal := nameserverSet(
				h.procFile(pid, "root/etc/resolv.conf"))
			if clusterLocal || len(podNS) == 0 {
				continue
			}
			if !equalNS(podNS, hostNS) {
				stale = append(stale, dnsStale{pod: p.Name, pid: pid})
			}
		}
	}

	if len(stale) == 0 {
		h.dnsFails = 0
		h.stateExit("dns-resolv-stale")
		h.cycles.WithLabelValues(checkDNS, "ok").Inc()
		return
	}

	specs := make([]string, 0, len(stale))
	for _, s := range stale {
		specs = append(specs, fmt.Sprintf("%s:pid=%d", s.pod, s.pid))
	}
	staleStr := strings.Join(specs, " ")
	// Latch first — the state file is what NPD's permanent
	// DnsResolvStale condition checks; the counter gates the action.
	h.stateEnter("dns-resolv-stale", staleStr)
	h.dnsFails++
	switch {
	case h.dnsFails >= h.cfg.ConsecNeeded &&
		h.rateTrySpend("last-dnsresolv-restart", h.cfg.MinRestartInterval):
		// budget already spent atomically — spend BEFORE action (lib.sh)
		for _, s := range stale {
			// SIGKILL on the PAUSE pid — NOT the app container
			// (restarting the app keeps the old sandbox +
			// resolv.conf; the pod object itself is fine).
			h.appendLog(fmt.Sprintf(
				"DNS-RESOLV-RESTART: killing pause %d (%s) - dns-resolv-stale, resolv.conf pod stale vs host",
				s.pid, s.pod))
			if err := h.cfg.killFn(s.pid, syscall.SIGKILL); err != nil {
				h.appendLog(fmt.Sprintf(
					"suspect: kill pause %d (%s) failed: %v", s.pid, s.pod, err))
			}
			h.actions.WithLabelValues(checkDNS, "pause_kill").Inc()
		}
		h.dnsFails = 0
	default:
		h.appendLog(fmt.Sprintf("suspect: dns-resolv-stale %s (check %d/%d)",
			staleStr, h.dnsFails, h.cfg.ConsecNeeded))
	}
	h.cycles.WithLabelValues(checkDNS, "ok").Inc()
}

// --- shared helpers for the ported kubelet/cilium/ctr checks ---

// countMatchingLines is grep -cE parity: lines matching re.
// strings.Cut iterates in place — no giant []string allocation on
// a multi-MiB journal snapshot.
func countMatchingLines(re *regexp.Regexp, s string) int {
	n := 0
	for rest := s; rest != ""; {
		line, after, _ := strings.Cut(rest, "\n")
		rest = after
		if re.MatchString(line) {
			n++
		}
	}
	return n
}

// dashedHost maps "ip[:port]" to the watchdog file suffix ip-dashed —
// same transform as apiprober's dashedIP (state-apiserver-backend-
// stale-<dashed> keying).
func dashedHost(addr string) string {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	} else if i := strings.LastIndexByte(addr, ':'); i >= 0 {
		host = addr[:i]
	}
	return strings.ReplaceAll(host, ".", "-")
}

// probeHTTPSeries runs up to `attempts` GET probes `gap` apart —
// the shell's curl retry loops (a single blip must not trigger a
// restart). Returns nil on the first success.
func (h *Hygiene) probeHTTPSeries(ctx context.Context, url string,
	attempts int, timeout, gap time.Duration) error {
	var last error
	for i := 0; i < attempts; i++ {
		last = h.cfg.probeHTTP(ctx, url, timeout)
		if last == nil {
			return nil
		}
		if i+1 < attempts {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(gap):
			}
		}
	}
	return last
}

// podDirCount counts kubelet pod dirs — the shell's
// `find $KUBELET_PODS_DIR -mindepth 1 -maxdepth 1 -type d | wc -l`.
// ok=false means the dir is unreadable (treated like missing).
func (h *Hygiene) podDirCount() (n int, ok bool) {
	entries, err := os.ReadDir(h.cfg.KubeletPodsDir)
	if err != nil {
		return 0, false
	}
	for _, e := range entries {
		if e.IsDir() {
			n++
		}
	}
	return n, true
}

// taskRecordCount counts containerd task records — `ctr tasks ls |
// wc -l` parity for the phantom-pods signal: every task dir under the
// runtime + sandbox roots is a record, RUNNING or STOPPED alike (the
// shell counted output lines, never filtered on task state). A
// drained/evicted node holding stopped task dirs is NOT phantom —
// counting only live init pids would false-positive a k0sworker
// restart every MinRestartInterval.
func (h *Hygiene) taskRecordCount() int {
	n := 0
	for _, root := range []string{h.cfg.CtrTaskRoot, h.cfg.SandboxCtlRoot} {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				n++
			}
		}
	}
	return n
}

// k0sWorkerSettled gates k0sworker restarts: the unit must have been
// continuously active for >=180s — restarting a kubelet that is still
// re-listing its pods turns a settle blip into a restart loop.
// nil Systemd (unwired/tests) can't answer → settled.
func (h *Hygiene) k0sWorkerSettled(ctx context.Context) bool {
	if h.cfg.Systemd == nil {
		return true
	}
	age, err := h.cfg.Systemd.ActiveAge(ctx, "k0sworker.service")
	return err == nil && age >= k0sWorkerSettle
}

// restartK0sWorker wraps Systemd.Restart — a nil client can't act
// (unwired agent) and reports so the action is logged not counted.
func (h *Hygiene) restartK0sWorker(ctx context.Context) error {
	if h.cfg.Systemd == nil {
		return fmt.Errorf("no systemd client wired")
	}
	return h.cfg.Systemd.Restart(ctx, "k0sworker.service")
}

// --- Check: kubelet-stall (05-kubelet-stall.sh) ---

// checkKubeletStall detects a zombie kubelet: informer-zombie journal
// spam, phantom pods (pod dirs but zero task records), or a dead
// :10250 listener. 2 consecutive cycles → latch kubelet-runtime-stall
// + restart k0sworker through the shared last-restart budget, gated
// on overload / API reachability / settle.
func (h *Hygiene) checkKubeletStall(ctx context.Context, apiOK bool,
	journalOnce func() string, workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkStall, "gated").Inc()
		return
	}
	reason := ""
	if hits := countMatchingLines(stallJournalRe, journalOnce()); hits > journalHitsThresh {
		reason = fmt.Sprintf("informer-zombie hits=%d/10min", hits)
	}
	if reason == "" {
		if poddirs, ok := h.podDirCount(); ok && poddirs >= poddirThreshold {
			if _, err := os.ReadDir(h.cfg.CtrTaskRoot); err != nil {
				reason = fmt.Sprintf("phantom-pods poddirs=%d ctr=unreachable", poddirs)
			} else if h.taskRecordCount() == 0 {
				reason = fmt.Sprintf("phantom-pods poddirs=%d tasks=0", poddirs)
			}
		}
	}
	if reason == "" {
		// kubelet-10250-down: the listener may take 30-60s after a
		// k0sworker restart — all 3 probes must fail (curl -ks parity:
		// any HTTP response, even 401, means the listener is alive).
		if err := h.probeHTTPSeries(ctx, h.cfg.KubeletHealthzURL,
			probeAttempts, probeTimeout, h.cfg.ProbeGap); err != nil {
			reason = "kubelet-10250-down"
		}
	}
	if reason == "" {
		h.stallFails = 0
		h.stateExit("kubelet-runtime-stall")
		h.cycles.WithLabelValues(checkStall, "ok").Inc()
		return
	}
	h.stallFails++
	if h.stallFails < h.cfg.ConsecNeeded {
		h.appendLog(fmt.Sprintf("suspect: %s (check %d/%d)",
			reason, h.stallFails, h.cfg.ConsecNeeded))
		h.cycles.WithLabelValues(checkStall, "ok").Inc()
		return
	}
	overloaded := h.stateExists("node-overloaded")
	if strings.HasPrefix(reason, "phantom-pods") || strings.HasPrefix(reason, "kubelet-10250-down") {
		if !overloaded {
			h.stateEnter("kubelet-runtime-stall", reason)
		} else if !h.stateExists("kubelet-runtime-stall") {
			// Wedge under CPU starvation is a symptom, not a dead
			// node — latching would kick NHC→SNR and dump 100% of
			// load onto the survivors (amplifier). Log-only.
			h.appendLog(fmt.Sprintf("runtime-stall-suppressed-overloaded - %s", reason))
		}
	} else {
		h.stateExit("kubelet-runtime-stall")
	}
	switch {
	case overloaded:
		h.appendLog(fmt.Sprintf("suspect: %s - node overloaded, skip restart k0sworker", reason))
	case !apiOK:
		h.appendLog(fmt.Sprintf("suspect: %s - API unreachable (isolated?), skip restart k0sworker", reason))
	case !h.k0sWorkerSettled(ctx):
		h.appendLog(fmt.Sprintf("suspect: %s - k0sworker not settled (<180s), skip restart", reason))
	case !h.rateTrySpend("last-restart", h.cfg.MinRestartInterval):
		h.appendLog(fmt.Sprintf("suspect: %s - in restart cooldown (<30m), skip", reason))
	default:
		// Budget already spent atomically by the rateTrySpend case —
		// the feeder goroutine competes for the same file.
		h.appendLog(fmt.Sprintf("ACTION: restarting k0sworker - %s (persisted %dx)",
			reason, h.stallFails))
		h.stallFails = 0
		if err := h.restartK0sWorker(ctx); err != nil {
			h.appendLog(fmt.Sprintf("k0sworker restart failed: %v", err))
		} else {
			h.actions.WithLabelValues(checkStall, "restart").Inc()
		}
	}
	h.cycles.WithLabelValues(checkStall, "ok").Inc()
}

// --- Check: kubelet-watch-wedge (06-kubelet-watch-wedge.sh) ---

// checkKubeletWatchWedge detects a wedged kubelet pod-watch stream:
// pods assigned to this node (not Terminating, not terminal, older
// than KubeletWatchMinAge) whose kubelet pod dir was never created.
// Journal spam is early-warning only. 2 consecutive cycles → latch
// kubelet-watch-wedge + restart k0sworker — unless EVERY apiserver
// backend is stale (upstream wedge: the missing pods are a phantom of
// stale LIST data, restarting kubelet is useless churn).
func (h *Hygiene) checkKubeletWatchWedge(ctx context.Context, pods []corev1.Pod,
	apiOK bool, journalOnce func() string, workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkWatch, "gated").Inc()
		return
	}
	if spam := countMatchingLines(watchJournalRe, journalOnce()); spam > journalHitsThresh {
		h.appendLog(fmt.Sprintf(
			"suspect: kubelet-watch-wedge early-warn spam=%d/10min (not-registered/no-relationship)", spam))
	}
	if !apiOK {
		// Inconclusive — keep counters/latch exactly like the shell
		// (a flapping API must not clear wedge evidence). Only log
		// when there is something worth keeping.
		if h.stateExists("kubelet-watch-wedge") || h.watchFails > 0 {
			h.appendLog("suspect: kubelet-watch-wedge pods query fail — inconclusive, keeping state")
		}
		h.cycles.WithLabelValues(checkWatch, "abort").Inc()
		return
	}
	now := h.cfg.nowFn()
	missing := 0
	for i := range pods {
		p := &pods[i]
		if p.DeletionTimestamp != nil ||
			p.Status.Phase == corev1.PodSucceeded ||
			p.Status.Phase == corev1.PodFailed {
			continue
		}
		ct := p.CreationTimestamp.Time
		if ct.IsZero() || now.Sub(ct) < h.cfg.KubeletWatchMinAge {
			continue
		}
		if st, err := os.Stat(filepath.Join(h.cfg.KubeletPodsDir,
			string(p.UID))); err != nil || !st.IsDir() {
			missing++
		}
	}
	if missing == 0 {
		h.watchFails = 0
		h.stateExit("kubelet-watch-wedge")
		h.cycles.WithLabelValues(checkWatch, "ok").Inc()
		return
	}
	h.watchFails++
	if h.watchFails < h.cfg.ConsecNeeded {
		h.appendLog(fmt.Sprintf(
			"suspect: kubelet-watch-wedge %d pod(s) assigned but no pod dir on node (check %d/%d)",
			missing, h.watchFails, h.cfg.ConsecNeeded))
		h.cycles.WithLabelValues(checkWatch, "ok").Inc()
		return
	}
	h.stateEnter("kubelet-watch-wedge", fmt.Sprintf("unseen-pods=%d", missing))
	// Upstream gate: EVERY apiserver backend stale → the unseen pods
	// are stale-LIST fallout, not a kubelet wedge (sig14 latches the
	// state-apiserver-backend-stale-<ip> files).
	if len(h.cfg.APIBackends) > 0 {
		nstale := 0
		for _, be := range h.cfg.APIBackends {
			if h.stateExists("apiserver-backend-stale-" + dashedHost(be)) {
				nstale++
			}
		}
		if nstale == len(h.cfg.APIBackends) {
			h.appendLog(fmt.Sprintf(
				"suspect: kubelet-watch-wedge unseen=%d but %d/%d api backend stale — upstream wedge, skip restart k0sworker",
				missing, nstale, len(h.cfg.APIBackends)))
			h.cycles.WithLabelValues(checkWatch, "ok").Inc()
			return
		}
	}
	switch {
	case h.stateExists("node-overloaded"):
		h.appendLog(fmt.Sprintf(
			"suspect: kubelet-watch-wedge unseen=%d - node overloaded, skip restart k0sworker", missing))
	case !h.k0sWorkerSettled(ctx):
		h.appendLog(fmt.Sprintf(
			"suspect: kubelet-watch-wedge unseen=%d - k0sworker not settled (<180s), skip restart", missing))
	case !h.rateTrySpend("last-restart", h.cfg.MinRestartInterval):
		h.appendLog(fmt.Sprintf(
			"suspect: kubelet-watch-wedge unseen=%d - in restart cooldown (<30m), skip", missing))
	default:
		// Budget already spent atomically by the rateTrySpend case —
		// the feeder goroutine competes for the same file.
		h.appendLog(fmt.Sprintf(
			"ACTION: restarting k0sworker - kubelet-watch-wedge unseen-pods=%d (persisted %dx)",
			missing, h.watchFails))
		h.watchFails = 0
		if err := h.restartK0sWorker(ctx); err != nil {
			h.appendLog(fmt.Sprintf("k0sworker restart failed: %v", err))
		} else {
			h.actions.WithLabelValues(checkWatch, "restart").Inc()
		}
	}
	h.cycles.WithLabelValues(checkWatch, "ok").Inc()
}

// --- Check: ctr-tasks (31-ctr-tasks.sh) ---

// procAge returns the age of a /proc/<pid> dir (shell
// `now - stat -c %Y` — a shim that just spawned still has a fresh
// mtime, so the 5m window can't kill a starting task).
func (h *Hygiene) procAge(pid int) time.Duration {
	fi, err := os.Stat(h.procFile(pid))
	if err != nil {
		return 0
	}
	return h.cfg.nowFn().Sub(fi.ModTime())
}

// pidsWithCmdline returns pids whose joined cmdline contains sub —
// the pkill -f replacement (the agent can't rely on pkill being in
// the container image).
func (h *Hygiene) pidsWithCmdline(sub string) []int {
	var out []int
	for _, pid := range h.procPIDs() {
		if strings.Contains(strings.Join(h.procCmdline(pid), " "), sub) {
			out = append(out, pid)
		}
	}
	return out
}

// checkCtrTasks cleans wedged containerd task dirs and orphan shims —
// the filesystem port of the shell's ctr-based checks (no ctr socket
// needed in the agent pod):
//
//   - Orphan shim: live containerd-shim-runc-v2 process whose -id task
//     dir is gone from BOTH roots, proc age >=5m → SIGKILL (cap
//     MaxShimKill/cycle).
//   - Wedged task dir: init.pid unreadable/dead/zombie, OR init alive
//     but log.json missing on a non-sandbox task — confirmed via a
//     wedged-seen-<id> marker persisting >=5m (the marker replaces
//     "dead >=5m": dir age can't distinguish a just-exited init from
//     a real wedge). Confirmed → SIGKILL live init + any process
//     holding the id, then remove the dir (cap MaxCtrTaskClean/cycle).
func (h *Hygiene) checkCtrTasks(ctx context.Context, workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkCtrTasks, "gated").Inc()
		return
	}
	entries, err := os.ReadDir(h.cfg.CtrTaskRoot)
	if err != nil {
		h.appendLog(fmt.Sprintf(
			"suspect: ctr task root %s unreadable: %v — ctr-tasks check skipped",
			h.cfg.CtrTaskRoot, err))
		h.cycles.WithLabelValues(checkCtrTasks, "abort").Inc()
		return
	}
	liveDirs := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			liveDirs[e.Name()] = true
		}
	}
	sbDirs := map[string]bool{}
	if es, err := os.ReadDir(h.cfg.SandboxCtlRoot); err == nil {
		for _, e := range es {
			if e.IsDir() {
				sbDirs[e.Name()] = true
			}
		}
	}
	// Phase B — orphan shims (shell ran this FIRST: a shim whose task
	// dir vanished makes every shim-mediated kill fail forever).
	nShim := 0
	for _, pid := range h.procPIDs() {
		if nShim >= h.cfg.MaxShimKill {
			break
		}
		joined := strings.Join(h.procCmdline(pid), " ")
		if !strings.Contains(joined, "containerd-shim-runc-v2") {
			continue
		}
		m := shimIDRe.FindStringSubmatch(joined)
		if m == nil {
			continue
		}
		sid := m[1]
		if liveDirs[sid] || sbDirs[sid] {
			continue
		}
		if h.procAge(pid) < 5*time.Minute {
			continue
		}
		h.appendLog(fmt.Sprintf(
			"ACTION: kill orphan shim pid=%d id=%.12s - task dir missing", pid, sid))
		if err := h.cfg.killFn(pid, syscall.SIGKILL); err != nil {
			h.appendLog(fmt.Sprintf(
				"suspect: kill orphan shim pid=%d failed: %v", pid, err))
		}
		nShim++
		h.actions.WithLabelValues(checkCtrTasks, "shim_kill").Inc()
	}
	// Prune wedged-seen markers for dirs that disappeared between
	// runs (teardown finished or a previous cleanup won the race).
	if ms, err := filepath.Glob(
		filepath.Join(h.cfg.WatchdogStateDir, "wedged-seen-*")); err == nil {
		for _, m := range ms {
			if !liveDirs[strings.TrimPrefix(filepath.Base(m), "wedged-seen-")] {
				_ = os.Remove(m)
			}
		}
	}
	// Scan task dirs → wedge candidates confirmed by a >=5m marker.
	var wedged []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id := e.Name()
		d := filepath.Join(h.cfg.CtrTaskRoot, id)
		marker := "wedged-seen-" + id
		dead := false
		pidData, err := os.ReadFile(filepath.Join(d, "init.pid"))
		ipid, _ := strconv.Atoi(strings.TrimSpace(string(pidData)))
		if err != nil || ipid <= 0 || !h.pidLive(ipid) {
			// Unreadable init.pid = half-written dir (containerd
			// restart mid-create) or an exited init — both are
			// wedge-shaped, but a task STARTING writes init.pid a
			// few seconds after the dir: the 5m marker window absorbs
			// that race.
			dead = true
		} else if _, err := os.Stat(filepath.Join(d, "log.json")); err != nil {
			// init alive but log.json gone: runc kill fails with
			// ENOENT forever on non-sandbox tasks (pause tasks have
			// no log.json legitimately); unreadable config.json =
			// wreckage → dead too (grep miss parity).
			if cfg, err := os.ReadFile(filepath.Join(d, "config.json")); err != nil ||
				!sandboxTypeRe.Match(cfg) {
				dead = true
			}
		}
		if !dead {
			// Recovered between runs → cancel the pending confirm.
			_ = os.Remove(filepath.Join(h.cfg.WatchdogStateDir, marker))
			continue
		}
		if !h.stateFileExists(marker) {
			h.rateSpend(marker)
			h.appendLog(fmt.Sprintf("ctr-task-dead candidate %.12s - confirm next run", id))
			continue
		}
		if !h.rateOK(marker, 5*time.Minute) {
			continue
		}
		wedged = append(wedged, d)
	}
	nClean := 0
	for _, d := range wedged {
		id := filepath.Base(d)
		_ = os.Remove(filepath.Join(h.cfg.WatchdogStateDir, "wedged-seen-"+id))
		if nClean >= h.cfg.MaxCtrTaskClean {
			h.appendLog(fmt.Sprintf("suspect: ctr-task-wedged still pending cap=%d",
				h.cfg.MaxCtrTaskClean))
			break
		}
		// Live init with missing log.json → SIGKILL it first so the
		// shim can drain and exit (shell's kill -9 init).
		if pidData, err := os.ReadFile(filepath.Join(d, "init.pid")); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(pidData))); err == nil &&
				pid > 0 && h.pidLive(pid) {
				h.appendLog(fmt.Sprintf(
					"ACTION: kill -9 init %d of %.12s - log.json missing", pid, id))
				if err := h.cfg.killFn(pid, syscall.SIGKILL); err != nil {
					h.appendLog(fmt.Sprintf(
						"suspect: kill init %d of %.12s failed: %v", pid, id, err))
				}
			}
		}
		// pkill -9 -f "$id" parity: kill shim/runc leftovers holding
		// the task id, then remove the dir — containerd GCs the task
		// record once the shim is gone.
		for _, pid := range h.pidsWithCmdline(id) {
			if err := h.cfg.killFn(pid, syscall.SIGKILL); err != nil {
				h.appendLog(fmt.Sprintf(
					"suspect: kill leftover pid=%d holding task %.12s failed: %v",
					pid, id, err))
			}
		}
		h.appendLog(fmt.Sprintf("ACTION: rm wedged task dir %.12s - dead >=5m", id))
		if err := os.RemoveAll(d); err != nil {
			h.appendLog(fmt.Sprintf("suspect: rm task dir %.12s failed: %v", id, err))
		}
		nClean++
		h.actions.WithLabelValues(checkCtrTasks, "rm_dir").Inc()
	}
	h.cycles.WithLabelValues(checkCtrTasks, "ok").Inc()
}

// stateFileExists reports whether a state-dir file exists — unlike
// stateExists it checks RAW filenames (markers like wedged-seen-<id>
// are not state-* latches).
func (h *Hygiene) stateFileExists(name string) bool {
	_, err := os.Stat(filepath.Join(h.cfg.WatchdogStateDir, name))
	return err == nil
}

// --- Check: cilium (32-cilium.sh + 35-cilium-init-stuck.sh) ---

// ciliumNamedTasks finds containerd tasks of one cilium container
// (cilium-agent / cilium-envoy) by container-name annotation — the
// Go port of `ctr containers ls 'labels."io.kubernetes.container.name"=="<name>"'`.
// reachable=false means the task root itself is unreadable (ctr
// unreachable parity: inconclusive, keep counters/latches).
func (h *Hygiene) ciliumNamedTasks(name string) (tasks []ctrTask, reachable bool) {
	if _, err := os.ReadDir(h.cfg.CtrTaskRoot); err != nil {
		h.appendLog(fmt.Sprintf(
			"suspect: ctr task root %s unreadable: %v — cilium checks inconclusive",
			h.cfg.CtrTaskRoot, err))
		return nil, false
	}
	for _, root := range []string{h.cfg.CtrTaskRoot, h.cfg.SandboxCtlRoot} {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			d := filepath.Join(root, e.Name())
			cfgData, err := os.ReadFile(filepath.Join(d, "config.json"))
			if err != nil {
				continue
			}
			nm := containerNameRe.FindSubmatch(cfgData)
			if nm == nil || string(nm[1]) != name {
				continue
			}
			t := ctrTask{}
			if pidData, err := os.ReadFile(filepath.Join(d, "init.pid")); err == nil {
				if pid, err := strconv.Atoi(strings.TrimSpace(string(pidData))); err == nil {
					t.pid = pid
					t.live = h.pidLive(pid)
				}
			}
			tasks = append(tasks, t)
		}
	}
	return tasks, true
}

// ciliumAgentTasks is the cilium-agent specialization kept for the
// 32/35 call sites.
func (h *Hygiene) ciliumAgentTasks() (tasks []ctrTask, reachable bool) {
	return h.ciliumNamedTasks("cilium-agent")
}

// killNamedTasks SIGKILLs every live init pid of the named
// container — `ctr tasks kill -s SIGKILL` parity. true = at least
// one task killed (a dead task can't be signalled; kubelet retries
// on its own).
func (h *Hygiene) killNamedTasks(tasks []ctrTask, name string) bool {
	killed := false
	for _, t := range tasks {
		if t.live && t.pid > 0 {
			if err := h.cfg.killFn(t.pid, syscall.SIGKILL); err != nil {
				h.appendLog(fmt.Sprintf(
					"suspect: kill %s pid=%d failed: %v", name, t.pid, err))
			} else {
				killed = true
			}
		}
	}
	return killed
}

// killCiliumAgent SIGKILLs the cilium-agent tasks and flags the
// kill so the B1 check restarts cilium-envoy the same cycle.
func (h *Hygiene) killCiliumAgent(tasks []ctrTask) bool {
	if h.killNamedTasks(tasks, "cilium-agent") {
		h.ciliumAgentKilled = true
		return true
	}
	return false
}

// checkCilium — sig9: cilium-agent :9879 healthz down → latch
// cilium-agent-down + SIGKILL the agent container (kubelet restarts
// it immediately, bypassing CrashLoopBackOff). Gates: apiOK (restart
// while the API is dead can't resync), node-overloaded, shared
// last-cilium-restart 30m budget.
func (h *Hygiene) checkCilium(ctx context.Context, apiOK, workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkCilium, "gated").Inc()
		return
	}
	tasks, reachable := h.ciliumAgentTasks()
	if !reachable {
		// ctr unreachable → inconclusive, keep everything.
		h.cycles.WithLabelValues(checkCilium, "abort").Inc()
		return
	}
	if len(tasks) == 0 {
		// No cilium-agent container → this node runs no cilium
		// (calico cluster, hub): clear any false-positive state.
		h.ciliumFails = 0
		h.stateExit("cilium-agent-down")
		h.cycles.WithLabelValues(checkCilium, "ok").Inc()
		return
	}
	err := h.probeHTTPSeries(ctx, h.cfg.CiliumHealthzURL,
		probeAttempts, ciliumProbeTime, h.cfg.ProbeGap)
	if err == nil {
		h.ciliumFails = 0
		h.stateExit("cilium-agent-down")
		h.cycles.WithLabelValues(checkCilium, "ok").Inc()
		return
	}
	h.stateEnter("cilium-agent-down", "")
	h.ciliumFails++
	switch {
	case !apiOK:
		h.appendLog(fmt.Sprintf(
			"suspect: cilium-agent-down healthz fail %dx but API unreachable — skip kill (agent still cannot sync even after restart)",
			h.ciliumFails))
	case h.ciliumFails >= h.cfg.ConsecNeeded &&
		h.rateOK("last-cilium-restart", h.cfg.MinRestartInterval) &&
		!h.stateExists("node-overloaded"):
		if h.killCiliumAgent(tasks) {
			h.appendLog(fmt.Sprintf(
				"ACTION: killed cilium-agent container - healthz down %dx (kubelet will restart)",
				h.ciliumFails))
			h.rateSpend("last-cilium-restart")
			h.ciliumFails = 0
			h.actions.WithLabelValues(checkCilium, "sigkill").Inc()
		} else {
			h.appendLog(fmt.Sprintf(
				"suspect: cilium-agent-down healthz fail %dx, no running task to kill (kubelet retries itself)",
				h.ciliumFails))
		}
	default:
		h.appendLog(fmt.Sprintf(
			"suspect: cilium-agent-down healthz 127.0.0.1:9879 fail (check %d/%d)",
			h.ciliumFails, h.cfg.ConsecNeeded))
	}
	h.cycles.WithLabelValues(checkCilium, "ok").Inc()
}

// checkCiliumInitStuck — sig15: endpoints stuck in reserved:init
// while healthz stays green (informer wedge — every new pod gets a
// black-holed datapath). The shell ran `cilium-dbg endpoint list` via
// ctr exec; the agent reads the same data from the cilium agent unix
// socket (/v1/endpoint) — reserved:init counting is identical.
// Inconclusive (socket/exec fail) → keep counters, never reset.
func (h *Hygiene) checkCiliumInitStuck(ctx context.Context, apiOK, workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkCiliumInit, "gated").Inc()
		return
	}
	tasks, reachable := h.ciliumAgentTasks()
	if !reachable {
		h.cycles.WithLabelValues(checkCiliumInit, "abort").Inc()
		return
	}
	if len(tasks) == 0 {
		h.cycles.WithLabelValues(checkCiliumInit, "ok").Inc()
		return
	}
	body, err := h.cfg.unixGet(ctx, h.cfg.CiliumSocket, "/v1/endpoint")
	if err != nil {
		// Endpoint list unreadable — inconclusive: don't count, don't
		// reset (shell: tasks exec fail → exit 0).
		h.appendLog(fmt.Sprintf(
			"suspect: cilium-init-stuck endpoint query on %s failed: %v — inconclusive, keeping state",
			h.cfg.CiliumSocket, err))
		h.cycles.WithLabelValues(checkCiliumInit, "abort").Inc()
		return
	}
	initEps := strings.Count(string(body), "reserved:init")
	if initEps == 0 {
		h.ciliumInitFails = 0
		h.stateExit("cilium-init-stuck")
		h.cycles.WithLabelValues(checkCiliumInit, "ok").Inc()
		return
	}
	h.ciliumInitFails++
	if h.ciliumInitFails < h.cfg.ConsecNeeded {
		h.appendLog(fmt.Sprintf("suspect: cilium-init-stuck init_eps=%d (check %d/%d)",
			initEps, h.ciliumInitFails, h.cfg.ConsecNeeded))
		h.cycles.WithLabelValues(checkCiliumInit, "ok").Inc()
		return
	}
	// Wedge confirmed — latch before any gate like the shell.
	h.stateEnter("cilium-init-stuck", fmt.Sprintf("init_eps=%d", initEps))
	switch {
	case !apiOK:
		h.appendLog(fmt.Sprintf(
			"suspect: cilium-init-stuck init_eps=%d %dx but API unreachable — skip kill (agent still cannot resync even after restart)",
			initEps, h.ciliumInitFails))
	case h.stateExists("node-overloaded"):
		h.appendLog(fmt.Sprintf(
			"suspect: cilium-init-stuck init_eps=%d %dx but node overloaded — skip kill",
			initEps, h.ciliumInitFails))
	case !h.rateOK("last-cilium-restart", h.cfg.MinRestartInterval):
		h.appendLog(fmt.Sprintf(
			"suspect: cilium-init-stuck init_eps=%d %dx but restart cooldown — skip kill",
			initEps, h.ciliumInitFails))
	default:
		if h.killCiliumAgent(tasks) {
			h.appendLog(fmt.Sprintf(
				"ACTION: killed cilium-agent container - init_eps=%d %dx (kubelet will restart -> informer resync)",
				initEps, h.ciliumInitFails))
			h.rateSpend("last-cilium-restart")
			h.ciliumInitFails = 0
			h.actions.WithLabelValues(checkCiliumInit, "sigkill").Inc()
		} else {
			h.appendLog(fmt.Sprintf(
				"suspect: cilium-init-stuck init_eps=%d %dx, no running task to kill (kubelet retries itself)",
				initEps, h.ciliumInitFails))
		}
	}
	h.cycles.WithLabelValues(checkCiliumInit, "ok").Inc()
}

// --- Check: ctr-image-healer (37-ctr-image-healer.sh) ---

// corruptImageWaitingReason mirrors the shell reason list — pull
// failures (ErrImagePull/ImagePullBackOff) and create failures
// (CreateContainerError) both surface corrupted-layer messages.
func corruptImageWaitingReason(r string) bool {
	switch r {
	case "CreateContainerError", "ErrImagePull", "ImagePullBackOff":
		return true
	}
	return false
}

// normalizeCRIImageName rewrites a kubelet-reported image spec into
// the canonical ref containerd's CRI plugin stored it under. `ctr
// images rm` does zero normalization — it matches the image store's
// name verbatim — while the CRI plugin canonicalizes at pull time
// (distribution/reference splitDockerDomain):
//   - first path segment without '.'/':' that isn't "localhost" is a
//     repo path component, not a registry → prepend "docker.io/";
//   - a single-segment repo path under docker.io gets "library/"
//     inserted (nginx → docker.io/library/nginx) — private-registry
//     single-segment paths are left alone;
//   - a name:tag@sha256:… ref canonicalizes to name@sha256:… (the
//     digest wins, the tag is dropped — only a ':' after the last '/'
//     is a tag; a registry port like host:5000/… is not).
//
// Already-canonical refs pass through unchanged (idempotent).
func normalizeCRIImageName(spec string) string {
	name, digest := spec, ""
	if i := strings.IndexByte(spec, '@'); i >= 0 {
		name, digest = spec[:i], spec[i:]
		if j := strings.LastIndexByte(name, ':'); j > strings.LastIndexByte(name, '/') {
			name = name[:j]
		}
	}
	domain, rest := "", name
	if i := strings.IndexByte(name, '/'); i >= 0 {
		if head := name[:i]; strings.ContainsAny(head, ".:") || head == "localhost" {
			domain, rest = head, name[i+1:]
		}
	}
	if domain == "" {
		domain, rest = "docker.io", name
	}
	if domain == "docker.io" && !strings.ContainsRune(rest, '/') {
		rest = "library/" + rest
	}
	return domain + "/" + rest + digest
}

// checkCtrImages scans this node's pods for containers stuck Waiting
// on a corrupted containerd layer/content-store error and removes the
// broken image (`k0s ctr images rm --sync`) so kubelet's next pull
// re-fetches the missing layer — the pod recovers without a reboot.
// Removal is idempotent (ctr tolerates re-pulls of a pruned ref), so
// unlike the restart checks there is no consecutive gate: the 15m
// last-ctr-image-rm budget alone bounds the churn, and one spend
// covers the whole batch of matching images found in a cycle.
//
// Two containerd quirks shape the rm set:
//   - cs.Image is the SPEC name the pod asked for, but the CRI plugin
//     normalized it at pull (docker.io/ + library/ insertion, digest
//     canonicalization). `ctr images rm` matches store names verbatim
//     and exits 0 with only a warning on a miss — an unnormalized
//     "nginx:1.25" rm silently no-ops while the corrupt record stays.
//     Every spec is run through normalizeCRIImageName first.
//   - The image store keeps one record per ref: the tag record and the
//     repoDigest record (cs.ImageID, e.g. docker.io/library/nginx@…)
//     are separate entries. Removing only the tag leaves the digest
//     record resolvable, so both are removed per corrupted container.
//
// Normalization is preferred over `ctr images ls` reconciliation —
// one exec per ref keeps the seam shape; a normalized name that still
// isn't in the store just makes ctr warn and exit 0 (accepted).
func (h *Hygiene) checkCtrImages(ctx context.Context, pods []corev1.Pod,
	apiOK, workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkCtrImages, "gated").Inc()
		return
	}
	if !apiOK {
		// Inconclusive — same "keep state, never act" rule as the
		// other pod-list checks.
		h.cycles.WithLabelValues(checkCtrImages, "abort").Inc()
		return
	}
	// Dedupe refs across pods and statuses — several containers
	// pinned to one corrupted image need a single rm, not one each.
	seen := map[string]bool{}
	for i := range pods {
		p := &pods[i]
		statuses := slices.Concat(p.Status.InitContainerStatuses,
			p.Status.ContainerStatuses, p.Status.EphemeralContainerStatuses)
		for _, cs := range statuses {
			w := cs.State.Waiting
			if w == nil || !corruptImageWaitingReason(w.Reason) ||
				!corruptImageRe.MatchString(w.Message) {
				continue
			}
			if cs.Image != "" {
				seen[normalizeCRIImageName(cs.Image)] = true
			}
			if cs.ImageID != "" {
				seen[normalizeCRIImageName(cs.ImageID)] = true
			}
		}
	}
	if len(seen) == 0 {
		h.cycles.WithLabelValues(checkCtrImages, "ok").Inc()
		return
	}
	images := make([]string, 0, len(seen))
	for img := range seen {
		images = append(images, img)
	}
	sort.Strings(images) // deterministic order — same convention as dnsStale
	if !h.rateTrySpend("last-ctr-image-rm", ctrImageRmInterval) {
		h.appendLog(fmt.Sprintf(
			"suspect: ctr-image-healer corrupted image(s) %s - in rm cooldown (<15m), skip",
			strings.Join(images, " ")))
		h.cycles.WithLabelValues(checkCtrImages, "ok").Inc()
		return
	}
	// Budget spent atomically BEFORE acting (lib.sh rate_spend
	// parity): a failed rm still consumed the budget.
	for _, img := range images {
		if err := h.cfg.ctrRmImage(ctx, img); err != nil {
			h.appendLog(fmt.Sprintf(
				"suspect: ctr image rm %s failed: %v", img, err))
			continue
		}
		// NPD contract: "removed corrupted image" feeds the
		// CorruptedImageRemoved filelog pattern.
		h.appendLog(fmt.Sprintf("ACTION: removed corrupted image %s", img))
		h.actions.WithLabelValues(checkCtrImages, "image_rm").Inc()
	}
	h.cycles.WithLabelValues(checkCtrImages, "ok").Inc()
}

// --- Check: cilium-bpf-ipam (38-cilium-bpf-ipam.sh) ---

// ipamCount reads one ipam value as a count — accepts a bare number,
// an array (counted by length) or an object/map (counted by keys),
// because the plan's used/available fields may be reported either as
// counters or as the IP collections themselves.
func ipamCount(v json.RawMessage) (int, bool) {
	s := bytes.TrimSpace(v)
	if len(s) == 0 || bytes.Equal(s, []byte("null")) {
		return 0, false
	}
	switch s[0] {
	case '[':
		var arr []json.RawMessage
		if err := json.Unmarshal(s, &arr); err != nil {
			return 0, false
		}
		return len(arr), true
	case '{':
		var m map[string]json.RawMessage
		if err := json.Unmarshal(s, &m); err != nil {
			return 0, false
		}
		return len(m), true
	default:
		var n float64
		if err := json.Unmarshal(s, &n); err != nil {
			return 0, false
		}
		return int(n), true
	}
}

// freeIPAMPool counts ipam.allocations entries marked free — in
// cluster-pool/multi-pool mode that map is the node's WHOLE pool
// (allocated AND free IPs; a free entry carries an empty owner).
// Values on the real wire are owner-name strings ("10.0.0.5":
// "pod-a"), so an EMPTY string is the free marker; the
// {"owner": "…"} object shape is accepted too for older agents.
// ok=false when the map is absent or fully owned: an all-owned map
// can't be told apart from an allocated-only dump (the non-pool
// modes), and reporting "0 free" there would false-latch exhaustion.
func freeIPAMPool(m map[string]json.RawMessage) (int, bool) {
	if len(m) == 0 {
		return 0, false
	}
	free := 0
	for _, v := range m {
		var owner string
		if err := json.Unmarshal(v, &owner); err == nil {
			if owner == "" {
				free++
			}
			continue
		}
		var e struct {
			Owner string `json:"owner"`
		}
		if err := json.Unmarshal(v, &e); err == nil && e.Owner == "" {
			free++
		}
	}
	return free, free > 0
}

// parseCiliumIPAM extracts used/available IPv4 counts from a
// /v1/healthz body. Two wire shapes are accepted:
//   - ipam.ipv4 as an object {"used":…, "available":…} — the shape
//     module 38 consumes; each value may be a number or a collection
//     (counted by length via ipamCount).
//   - ipam.ipv4 as an array — upstream cilium: the array IS the
//     allocated-IP list, so used = len. The healthz payload carries
//     no pool total in that shape; available is only recovered when
//     ipam.allocations exposes free (unowned) pool entries, else -1
//     (unknown — never invent a pool size).
//
// available == -1 means "unknown" — the `available <= 2` trigger is
// then skipped while `leaked > 30` still applies. ok=false means no
// usable ipam section: inconclusive.
func parseCiliumIPAM(body []byte) (used, available int, ok bool) {
	var resp struct {
		IPAM *struct {
			IPV4        json.RawMessage            `json:"ipv4"`
			Allocations map[string]json.RawMessage `json:"allocations"`
		} `json:"ipam"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.IPAM == nil {
		return 0, -1, false
	}
	available = -1
	raw := bytes.TrimSpace(resp.IPAM.IPV4)
	if len(raw) == 0 {
		return 0, -1, false
	}
	switch raw[0] {
	case '{':
		var obj struct {
			Used      json.RawMessage `json:"used"`
			Available json.RawMessage `json:"available"`
		}
		if err := json.Unmarshal(raw, &obj); err != nil {
			return 0, -1, false
		}
		if n, found := ipamCount(obj.Used); found {
			used = n
		}
		if n, found := ipamCount(obj.Available); found {
			available = n
		}
		return used, available, true
	case '[':
		var arr []json.RawMessage
		if err := json.Unmarshal(raw, &arr); err != nil {
			return 0, -1, false
		}
		used = len(arr)
		if free, found := freeIPAMPool(resp.IPAM.Allocations); found {
			available = free
		}
		return used, available, true
	default:
		// Bare number — the allocated count itself.
		if n, found := ipamCount(raw); found {
			return n, -1, true
		}
		return 0, -1, false
	}
}

// checkCiliumIPAM reads the agent's IPAM usage off the unix socket
// and cross-checks it against the non-hostNetwork Running pods on
// this node: allocated − in-use = leaked IPs still held for dead
// pods (a real pod eventually can't get an address — the black-hole
// datapath this module exists to catch early). A small constant leak
// (~2: router + health reserved IPs) is normal, so the latch needs
// leaked >30 or available <=2 for ConsecNeeded consecutive cycles.
// The gauges update on every successful probe regardless.
func (h *Hygiene) checkCiliumIPAM(ctx context.Context, pods []corev1.Pod,
	apiOK, workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkCiliumIPAM, "gated").Inc()
		return
	}
	if !apiOK {
		// The in-use count comes from the API — a failed LIST would
		// make EVERY allocated IP look leaked.
		h.cycles.WithLabelValues(checkCiliumIPAM, "abort").Inc()
		return
	}
	body, err := h.cfg.unixGet(ctx, h.cfg.CiliumSocket, "/v1/healthz")
	if err != nil {
		// Socket unreadable — inconclusive: keep counters/latch
		// (same rule as checkCiliumInitStuck).
		h.cycles.WithLabelValues(checkCiliumIPAM, "abort").Inc()
		return
	}
	used, available, ok := parseCiliumIPAM(body)
	if !ok {
		h.appendLog("suspect: cilium-ipam healthz has no parseable ipam.ipv4 data — inconclusive")
		h.cycles.WithLabelValues(checkCiliumIPAM, "abort").Inc()
		return
	}
	inUse := 0
	for i := range pods {
		p := &pods[i]
		// The denominator is "pods holding an address", not
		// "Running pods": the CNI call happens at sandbox create,
		// so a Pending/ContainerCreating pod already owns its IP —
		// counting only Running would report those allocations as
		// leaks. Terminal pods keep a stale .status.podIP; cilium
		// frees that allocation at teardown, and if it hasn't, that
		// IS the leak this check exists to find.
		if p.Spec.HostNetwork || p.Status.PodIP == "" ||
			p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		inUse++
	}
	leaked := used - inUse
	if leaked < 0 {
		leaked = 0
	}
	h.ciliumAllocated.Set(float64(used))
	h.ciliumLeaked.Set(float64(leaked))
	exhausted := leaked > 30 || (available >= 0 && available <= 2)
	if !exhausted {
		h.ciliumIPAMFails = 0
		h.stateExit("cilium-ipam-exhausted")
		h.cycles.WithLabelValues(checkCiliumIPAM, "ok").Inc()
		return
	}
	h.ciliumIPAMFails++
	if h.ciliumIPAMFails >= h.cfg.ConsecNeeded {
		h.stateEnter("cilium-ipam-exhausted", fmt.Sprintf(
			"used=%d in-use=%d leaked=%d available=%d", used, inUse, leaked, available))
	} else {
		h.appendLog(fmt.Sprintf(
			"suspect: cilium-ipam-exhausted used=%d in-use=%d leaked=%d available=%d (check %d/%d)",
			used, inUse, leaked, available, h.ciliumIPAMFails, h.cfg.ConsecNeeded))
	}
	h.cycles.WithLabelValues(checkCiliumIPAM, "ok").Inc()
}

// --- kubelet watchdog feeder + remediate (T15) ---
// Port of scripts/k0s-kubelet-watchdog.sh + k0sworker-remediate.sh.
// The shell feeder was a dedicated systemd unit (k0sworker-watchdog)
// feeding WATCHDOG=1 into its own WatchdogSec and dying `exit 1`
// after KWD_MAX_FAIL consecutive :10248 failures — OnFailure then ran
// the remediate oneshot. In-agent there is no watchdog unit to feed:
// the agent IS the loop — probe every KubeletWdInterval, and on
// KubeletWdMaxFail consecutive fails (~60s) run the same ordered
// gates inline, then re-arm like the unit's Restart=always.
//
// Remediate gates (k0sworker-remediate.sh order — every SKIP exits
// without action; restart only when ALL agree):
//   G0 re-probe :10248 twice ~3s apart → one "ok" = steal blip,
//                                      self-correct (the shell's
//                                      Gate-1, numbered G0 here so the
//                                      existing G1–G6 strings stay)
//   G1 uptime <1200s                 → fresh boot, kubelet still up-coming
//   G2 k0sworker active <180s        → settle window (kubelet init)
//   G3 state-node-overloaded latched → wedge is a load symptom
//   G4 no API backend answers /livez → node isolated, restart = churn
//   G5 last-restart <30m             → shared budget spent → latch
//                                      state-kubelet-healthz-down so
//                                      NHC→SNR escalates to reboot
//   G6 spend budget + reset-failed + systemctl restart k0sworker

// runKubeletFeeder is the T15 feeder's forever loop — returns only
// when ctx is cancelled. The tick self-gates per round; the "start"
// line is logged on each activation transition inside the tick, not
// here — the goroutine also runs on nodes where the feeder never
// activates.
func (h *Hygiene) runKubeletFeeder(ctx context.Context) {
	t := time.NewTicker(h.cfg.KubeletWdInterval)
	defer t.Stop()
	for {
		h.kubeletFeedTick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// kubeletFeederActive reports whether the feeder should probe this
// node — the shell install gate: the unit ran only on hosts listed in
// systemd_watchdog_hosts (KubeletWatchdogHosts); in-agent the check
// ALSO passes by default on any worker node (k0sworker.service
// present — the pilot graduated fleet-wide). WD_SIG_KUBELET_WATCHDOG
// =off is the per-module kill switch, honoured live via WatchdogSrc.
func (h *Hygiene) kubeletFeederActive() bool {
	if wd := h.feederWatchdogConf(); wd != nil && !wd.SignalEnabled(checkKubeletWd) {
		return false
	}
	for _, name := range h.cfg.KubeletWatchdogHosts {
		if name == h.cfg.NodeName {
			return true
		}
	}
	_, err := os.Stat(h.cfg.K0sWorkerUnitFile)
	return err == nil
}

// feederWatchdogConf returns the freshest parsed node-watchdog.conf
// WITHOUT mutating cfg — Cycle refreshes cfg.Watchdog itself; the
// feeder goroutine must never write cfg fields (data race).
func (h *Hygiene) feederWatchdogConf() *watchdogconf.Config {
	if h.cfg.WatchdogSrc != nil {
		return h.cfg.WatchdogSrc.Get()
	}
	// Without a reloader cfg.Watchdog is immutable — Cycle's refresh
	// block is guarded by WatchdogSrc != nil too.
	return h.cfg.Watchdog
}

// kubeletFeedTick is one feeder round: probe :10248, count fails, run
// the remediate gates at MaxFail — k0s-kubelet-watchdog.sh's loop
// body minus the sd_notify feed (no watchdog unit exists in-agent).
func (h *Hygiene) kubeletFeedTick(ctx context.Context) {
	active := h.kubeletFeederActive()
	if active && !h.kubeletFeederWasActive {
		// false→true activation (first active tick, node re-added to
		// systemd_watchdog_hosts, unit file reinstalled, WD_SIG
		// lifted) — a partial fail-streak from before the gap is
		// stale evidence and must not count toward a restart.
		h.appendLog(fmt.Sprintf(
			"kubelet-feeder: start interval=%ds maxfail=%d url=%s",
			int(h.cfg.KubeletWdInterval.Seconds()), h.cfg.KubeletWdMaxFail,
			h.cfg.KubeletWdProbeURL))
		if h.kubeletWdFails > 0 {
			h.appendLog(fmt.Sprintf(
				"kubelet-feeder: re-activated — dropping %d stale fails", h.kubeletWdFails))
		}
		h.kubeletWdFails = 0
	}
	h.kubeletFeederWasActive = active
	if !active {
		return
	}
	if h.cfg.probeBodyOK(ctx, h.cfg.KubeletWdProbeURL, kubeletWdProbeTimeout) {
		if h.kubeletWdFails > 0 {
			h.appendLog(fmt.Sprintf(
				"kubelet-feeder: probe OK again after %d fail", h.kubeletWdFails))
		}
		h.kubeletWdFails = 0
		h.stateExit("kubelet-healthz-down")
		return
	}
	// PartOf=k0sworker.service parity: the shell feeder unit stood
	// down with k0sworker — an intentionally inactive worker must not
	// accumulate fails toward a restart it doesn't want, and must not
	// keep a healthz-down latch that escalates a deliberate stop into
	// an NHC→SNR reboot.
	if h.cfg.Systemd != nil {
		active, err := h.cfg.Systemd.Active(ctx, "k0sworker.service")
		if err != nil {
			// Fail closed: the gate can't be evaluated — freeze
			// this tick entirely. Accumulating fails could escalate
			// to remediation on an unverifiable worker state, while
			// resetting them would discard real evidence.
			slog.Warn("kubelet-feeder: k0sworker is-active probe "+
				"failed — skipping this tick (fail closed)",
				"subsystem", "workerhygiene",
				"unit", "k0sworker.service", "error", err)
			return
		}
		if !active {
			if h.kubeletWdFails > 0 {
				h.appendLog("kubelet-feeder: k0sworker not active — fails reset (PartOf parity)")
			}
			h.kubeletWdFails = 0
			h.stateExit("kubelet-healthz-down")
			return
		}
	}
	h.kubeletWdFails++
	h.appendLog(fmt.Sprintf("kubelet-feeder: probe fail %d/%d",
		h.kubeletWdFails, h.cfg.KubeletWdMaxFail))
	if h.kubeletWdFails < h.cfg.KubeletWdMaxFail {
		return
	}
	h.appendLog(fmt.Sprintf(
		"kubelet-feeder: %d consecutive fails (~%ds) — running remediation gates",
		h.kubeletWdFails,
		int(h.cfg.KubeletWdInterval.Seconds())*h.cfg.KubeletWdMaxFail))
	h.runKubeletRemediate(ctx)
	// Re-arm like the shell's exit-1 → unit fail → OnFailure →
	// Restart=always round: the remediate pass ENDS this fails run
	// whatever the gates decided.
	h.kubeletWdFails = 0
}

// runKubeletRemediate is the ordered-gate port of
// k0sworker-remediate.sh — a probe failure does NOT prove the kubelet
// is dead (the probe may just be timing out under steal); every gate
// is a chance to stop before the shared last-restart budget is spent.
func (h *Hygiene) runKubeletRemediate(ctx context.Context) {
	h.actions.WithLabelValues(checkKubeletWd, "remediate").Inc()
	h.appendLog("kubelet-remediate: healthz :10248 down ~60s — running ordered gates before k0sworker restart")

	// G0 re-probe — the shell's Gate 1: probe :10248 twice ~3s apart
	// before ANYTHING else. Four failed ticks do not prove a dead
	// kubelet — under CPU steal the probes themselves time out, and
	// the ~60s streak may already be over. One "ok" → self-correct
	// (drop the fail streak and any escalation latch), never spend a
	// restart on a healthy kubelet.
	for i := 1; i <= 2; i++ {
		if h.cfg.probeBodyOK(ctx, h.cfg.KubeletWdProbeURL, kubeletWdProbeTimeout) {
			h.appendLog(fmt.Sprintf(
				"kubelet-remediate: SKIP(G0-reprobe) :10248 answered 'ok' on re-probe %d — false alarm (steal blip), self-correcting", i))
			h.kubeletWdFails = 0
			h.stateExit("kubelet-healthz-down")
			return
		}
		if i < 2 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(h.cfg.KubeletWdReprobeGap):
			}
		}
	}
	h.appendLog("kubelet-remediate: G0 :10248 still dead after 2 re-probes — continuing ordered gates")

	// G1 uptime (WD_REQUIRES: uptime) — a node <20m up is still
	// bringing kubelet online; a restart inside the window only churns.
	if up, err := h.uptimeSeconds(); err == nil && up < minUptimeSeconds {
		h.appendLog(fmt.Sprintf(
			"kubelet-remediate: SKIP(G1-uptime) uptime %.0fs < %ds", up, minUptimeSeconds))
		return
	}

	// G2 settle — k0sworker ActiveEnterTimestampMonotonic younger than
	// the 180s settle window: the kubelet from the previous restart may
	// still be initialising; spending the budget now just resets that
	// init cycle. An unreadable timestamp also skips (never restart
	// blind).
	if !h.k0sWorkerSettled(ctx) {
		h.appendLog("kubelet-remediate: SKIP(G2-settle) k0sworker active <180s or timestamp unreadable")
		return
	}

	// G3 overload — a kubelet wedge under CPU starvation is a
	// symptom, not a dead kubelet; restarting dumps its load onto the
	// surviving nodes (amplifier).
	if h.stateExists("node-overloaded") {
		h.appendLog("kubelet-remediate: SKIP(G3-overload) state-node-overloaded latched")
		return
	}

	// G4 apiserver — a node that reaches NO API backend is isolated;
	// restarting kubelet only adds a NotReady blip + resync churn.
	if !h.anyAPIBackendLive(ctx) {
		h.appendLog("kubelet-remediate: SKIP(G4-apiserver) no API backend answers /livez — node isolated")
		return
	}

	// G5 rate-limit — the last-restart budget is SHARED with every
	// other k0sworker restart source (30m), including the Cycle checks
	// running on their own goroutine — the check+spend is atomic
	// (rateTrySpend) or a stall/watch restart could pass the same
	// window and double-restart. Exhausted → escalate to the NHC→SNR
	// reboot path via the latch instead of piling on.
	if !h.rateTrySpend("last-restart", h.cfg.MinRestartInterval) {
		h.stateEnter("kubelet-healthz-down", "restart-budget-exhausted")
		h.appendLog("kubelet-remediate: SKIP(G5-ratelimit) k0sworker restart <30m ago — " +
			"state-kubelet-healthz-down latched (NHC→SNR escalation)")
		return
	}

	// G6 act — the budget was already spent atomically above (shell
	// parity: a hung/failed restart still consumed it). reset-failed
	// first so a stale failed state can't wedge the unit's next start.
	h.appendLog(fmt.Sprintf(
		"ACTION: restarting k0sworker (reason=systemd-watchdog-kubelet-healthz-60s fails=%d)",
		h.cfg.KubeletWdMaxFail))
	h.resetFailedK0sWorker(ctx)
	if err := h.restartK0sWorker(ctx); err != nil {
		h.appendLog(fmt.Sprintf(
			"kubelet-remediate: G6 restart k0sworker FAIL: %v (budget spent)", err))
		return
	}
	h.appendLog("kubelet-remediate: G6 k0sworker restarted")
	h.actions.WithLabelValues(checkKubeletWd, "restart").Inc()
}

// anyAPIBackendLive is the G4 probe — the shell TCP-checked the
// apiserver endpoint (API_PROBE_HOSTPORT/kubelet.conf) before
// declaring the node isolated; the agent GETs /livez on every
// configured API backend (API_BACKENDS, ports preserved) and counts
// ANY HTTP response as reachable (curl -sk parity — even a 500 means
// the listener is alive). With no backends configured it falls back
// to the worker-local api-local-lb listener (APIFallbackURL).
func (h *Hygiene) anyAPIBackendLive(ctx context.Context) bool {
	var urls []string
	if wd := h.feederWatchdogConf(); wd != nil {
		for _, b := range wd.APIBackends {
			if b.Addr != "" {
				urls = append(urls,
					"https://"+withDefaultAPIPort(b.Addr)+"/livez")
			}
		}
	}
	if len(urls) == 0 && h.cfg.WatchdogSrc == nil {
		// No reloader → cfg.APIBackends is immutable (Cycle refreshes
		// it from the conf only when a reloader exists).
		for _, a := range h.cfg.APIBackends {
			urls = append(urls, "https://"+withDefaultAPIPort(a)+"/livez")
		}
	}
	if len(urls) == 0 {
		urls = []string{h.cfg.APIFallbackURL}
	}
	for _, url := range urls {
		if h.cfg.probeHTTP(ctx, url, apiLivezProbeTimeout) == nil {
			return true
		}
	}
	return false
}

// withDefaultAPIPort appends the apiserver default port to a bare-IP
// backend entry — API_BACKENDS is "ip:port" but bare-IP entries occur
// (APIBackendIPs strips ports for the stale-latch key).
func withDefaultAPIPort(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	if strings.LastIndexByte(addr, ':') < 0 {
		return addr + ":6443"
	}
	return addr
}

// resetFailedK0sWorker mirrors `systemctl reset-failed k0sworker` —
// clears a lingering failed state so the following restart is a clean
// start, not a retry of a queued failed job. Best-effort: an error is
// logged, never fatal; a nil Systemd client (unwired agent/tests) is
// a no-op.
func (h *Hygiene) resetFailedK0sWorker(ctx context.Context) {
	if h.cfg.Systemd == nil {
		return
	}
	if out, err := h.cfg.Systemd.Exec(ctx,
		"systemctl", "reset-failed", "k0sworker.service"); err != nil {
		h.appendLog(fmt.Sprintf(
			"kubelet-remediate: reset-failed k0sworker failed: %v (%s)",
			err, strings.TrimSpace(out)))
	}
}

// --- Check: kubelet syncloop / containerd socket (A4) ---
// 05's :10250 /healthz probe can stay green through a PLEG freeze —
// kubelet exposes /healthz/syncloop specifically for the sync loop
// (returns 500 the moment PLEG dies). The containerd unix socket is
// the other half: a hung containerd wedges PLEG while every HTTP
// endpoint still answers. Both are latch-only signals — the shared
// restart machinery (05/T15) does the remediation.

func (h *Hygiene) checkKubeletSyncloop(ctx context.Context, workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkSyncloop, "gated").Inc()
		return
	}
	var lastErr error
	alive := false
	for i := 0; i < probeAttempts; i++ {
		code, err := h.cfg.probeHTTPStatus(ctx,
			h.cfg.KubeletSyncloopURL, probeTimeout)
		if err == nil && code == http.StatusOK {
			alive = true
			break
		}
		lastErr = err
		if lastErr == nil {
			// A non-200 answer carries no Go error — record the
			// code or the latch extra reads "last_err=<nil>".
			lastErr = fmt.Errorf("syncloop status %d", code)
		}
		if i+1 < probeAttempts {
			select {
			case <-ctx.Done():
				h.cycles.WithLabelValues(checkSyncloop, "abort").Inc()
				return
			case <-time.After(h.cfg.ProbeGap):
			}
		}
	}
	if alive {
		h.syncloopFails = 0
		h.stateExit("kubelet-syncloop-down")
		h.cycles.WithLabelValues(checkSyncloop, "ok").Inc()
		return
	}
	h.syncloopFails++
	if h.syncloopFails >= h.cfg.ConsecNeeded {
		h.stateEnter("kubelet-syncloop-down",
			fmt.Sprintf("pleg-frozen last_err=%v", lastErr))
	} else {
		h.appendLog(fmt.Sprintf(
			"suspect: kubelet-syncloop-down /healthz/syncloop fail (PLEG?) err=%v (check %d/%d)",
			lastErr, h.syncloopFails, h.cfg.ConsecNeeded))
	}
	h.cycles.WithLabelValues(checkSyncloop, "ok").Inc()
}

func (h *Hygiene) checkContainerdSock(ctx context.Context, workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkCtrSock, "gated").Inc()
		return
	}
	err := h.cfg.probeUnixSock(ctx, h.cfg.ContainerdSocket, unixSockProbeTimeout)
	if err == nil {
		h.ctrsockFails = 0
		h.stateExit("containerd-sock-down")
		h.cycles.WithLabelValues(checkCtrSock, "ok").Inc()
		return
	}
	h.ctrsockFails++
	if h.ctrsockFails >= h.cfg.ConsecNeeded {
		h.stateEnter("containerd-sock-down",
			fmt.Sprintf("probe_err=%v", err))
	} else {
		h.appendLog(fmt.Sprintf(
			"suspect: containerd-sock-down %s probe fail: %v (check %d/%d)",
			h.cfg.ContainerdSocket, err, h.ctrsockFails, h.cfg.ConsecNeeded))
	}
	h.cycles.WithLabelValues(checkCtrSock, "ok").Inc()
}

// --- Check: containerd stale ingest GC (A3 — 39-ctr-ingest-gc) ---
// A hard-reboot or OOM mid-pull leaves ingest dirs containerd never
// reaps; kubelet's ImageGC can't see them because the lease is
// orphaned. Runs when /var/lib/k0s is >75% full OR every 6h; ingest
// dirs with mtime >3h (no legitimate pull survives that) are removed
// via `ctr content ingest rm`, with a direct dir rm as fallback.

func (h *Hygiene) checkCtrIngestGC(ctx context.Context, workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkIngestGC, "gated").Inc()
		return
	}
	var st unix.Statfs_t
	diskHigh := false
	if err := h.cfg.statfsFn(h.cfg.K0sDataDir, &st); err == nil && st.Blocks > 0 {
		used := float64(st.Blocks-st.Bavail) / float64(st.Blocks)
		diskHigh = used > h.cfg.K0sDiskHighWatermark
	}
	due := h.cfg.nowFn().Sub(h.lastIngestScan) >= h.cfg.CtrIngestScanInterval
	if !diskHigh && !due {
		h.cycles.WithLabelValues(checkIngestGC, "ok").Inc()
		return
	}
	entries, err := os.ReadDir(h.cfg.CtrIngestDir)
	if err != nil {
		if os.IsNotExist(err) {
			// Absent dir = nothing to scan — stamp like a clean
			// walk so the 6h cadence still applies.
			h.lastIngestScan = h.cfg.nowFn()
			h.cycles.WithLabelValues(checkIngestGC, "ok").Inc()
			return
		}
		// A transient read failure must NOT stamp lastIngestScan —
		// stamping here would defer the retry by a full
		// CtrIngestScanInterval (6h).
		h.appendLog(fmt.Sprintf(
			"suspect: ctr ingest dir %s unreadable: %v — ingest GC skipped",
			h.cfg.CtrIngestDir, err))
		h.cycles.WithLabelValues(checkIngestGC, "abort").Inc()
		return
	}
	h.lastIngestScan = h.cfg.nowFn()
	now := h.cfg.nowFn()
	n := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if n >= h.cfg.MaxCtrTaskClean {
			h.appendLog(fmt.Sprintf(
				"suspect: ctr-ingest-gc still pending cap=%d", h.cfg.MaxCtrTaskClean))
			break
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		age := now.Sub(fi.ModTime())
		if age < h.cfg.CtrIngestMaxAge {
			continue
		}
		ref := e.Name()
		d := filepath.Join(h.cfg.CtrIngestDir, ref)
		if rerr := h.cfg.ctrRmIngest(ctx, ref); rerr != nil {
			h.appendLog(fmt.Sprintf(
				"suspect: ctr content ingest rm %s failed: %v — removing dir directly", ref, rerr))
		}
		if _, serr := os.Stat(d); serr == nil {
			if rerr := os.RemoveAll(d); rerr != nil {
				h.appendLog(fmt.Sprintf(
					"suspect: rm orphan ingest dir %s failed: %v", d, rerr))
				continue
			}
		}
		h.appendLog(fmt.Sprintf(
			"ACTION: ctr-ingest-gc removed stale ingest %s (age=%.1fh disk_high=%v)",
			ref, age.Hours(), diskHigh))
		n++
		h.ctrIngestsCleaned.Inc()
		h.actions.WithLabelValues(checkIngestGC, "ingest_rm").Inc()
	}
	h.cycles.WithLabelValues(checkIngestGC, "ok").Inc()
}

// --- Check: zombie storm (A2) ---
// A container without an init reaper (or a wedged shim) leaves
// hundreds of <defunct> processes under one parent. One parent with
// >ZombieStormThreshold zombies for ConsecNeeded cycles = a storm:
// the pod UID is recovered from the parent's cgroup and reported to
// node-watchdog.log for the nodereporter ZombieProcessStorm Event.

// procStatStatePPID parses /proc/<pid>/stat for state + ppid — the
// fields right after the LAST ')' (comm can hold spaces/parens).
func (h *Hygiene) procStatStatePPID(pid int) (state string, ppid int, ok bool) {
	data, err := os.ReadFile(h.procFile(pid, "stat"))
	if err != nil {
		return "", 0, false
	}
	s := string(data)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return "", 0, false
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 2 { // f[0]=state, f[1]=ppid
		return "", 0, false
	}
	p, err := strconv.Atoi(f[1])
	if err != nil || p < 0 {
		return "", 0, false
	}
	return f[0], p, true
}

// podUIDForPID extracts the pod UID owning a pid via
// /proc/<pid>/cgroup — kubepods slices embed the uid with
// underscores; normalized to the dashed form. The parse assumes
// the cgroup-v2 unified hierarchy (the `0::/kubepods...` line and
// kubepods*.slice naming — k0s hosts are v2; on v1 the per-
// hierarchy lines differ and pod_uid resolves "unknown").
func (h *Hygiene) podUIDForPID(pid int) string {
	data, err := os.ReadFile(h.procFile(pid, "cgroup"))
	if err != nil {
		return "unknown"
	}
	if m := podUIDCgroupRe.FindSubmatch(data); m != nil {
		return strings.ReplaceAll(string(m[1]), "_", "-")
	}
	return "unknown"
}

// zombieParent keys one storm streak: pid alone lies after PID
// reuse — the /proc/<pid>/stat starttime (field 22, jiffies since
// boot) tags the process generation so a recycled ppid restarts at
// streak 0 instead of inheriting a dead parent's count and holding
// the latch open for a storm that ended with it. An unreadable
// starttime leaves the zero value — streaks then merge on pid
// alone (same as the pre-key behaviour: the pid still has to stay
// over threshold to accumulate).
type zombieParent struct {
	pid   int
	start string // /proc/<pid>/stat field 22
}

// procStartTime reads /proc/<pid>/stat field 22 (starttime) — the
// generation tag inside zombieParent. "" when the stat is
// unreadable or truncated (the parent exited mid-sweep).
func (h *Hygiene) procStartTime(pid int) string {
	data, err := os.ReadFile(h.procFile(pid, "stat"))
	if err != nil {
		return ""
	}
	s := string(data)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return ""
	}
	// Fields after ')' start at field 3: f[0]=state, f[1]=ppid,
	// … f[19]=starttime (field 22).
	f := strings.Fields(s[i+1:])
	if len(f) <= 19 {
		return ""
	}
	return f[19]
}

func (h *Hygiene) checkZombieStorm(workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkZombieStorm, "gated").Inc()
		return
	}
	byPPID := map[int]int{}
	for _, pid := range h.procPIDs() {
		state, ppid, ok := h.procStatStatePPID(pid)
		if !ok || state != "Z" {
			continue
		}
		byPPID[ppid]++
	}
	// Resolve each parent once — one extra stat read per parent,
	// not per zombie.
	parents := map[int]zombieParent{}
	keyOf := func(ppid int) zombieParent {
		k, ok := parents[ppid]
		if !ok {
			k = zombieParent{pid: ppid, start: h.procStartTime(ppid)}
			parents[ppid] = k
		}
		return k
	}
	storm := false
	for parent, streak := range h.zombieStreaks {
		if _, ok := byPPID[parent.pid]; !ok || keyOf(parent.pid) != parent {
			delete(h.zombieStreaks, parent) // parent gone or pid recycled — streak dead
		} else if streak >= h.cfg.ConsecNeeded {
			storm = true
		}
	}
	for ppid, n := range byPPID {
		key := keyOf(ppid)
		if n <= h.cfg.ZombieStormThreshold {
			delete(h.zombieStreaks, key)
			continue
		}
		h.zombieStreaks[key]++
		switch streak := h.zombieStreaks[key]; {
		case streak == h.cfg.ConsecNeeded:
			storm = true
			uid := h.podUIDForPID(ppid)
			// NPD contract: nodereporter maps this line to the
			// ZombieProcessStorm Event + problem_counter. Logged
			// on streak ENTRY only — repeating it every cycle while
			// the storm persists would spawn a fresh K8s Event per
			// interval (the !stateExists gating checkCiliumMTU
			// uses).
			h.appendLog(fmt.Sprintf(
				"ACTION zombie-storm: pod_uid=%s zombies=%d ppid=%d", uid, n, ppid))
		case streak > h.cfg.ConsecNeeded:
			storm = true // latched storm continues — no repeated ACTION line
		default:
			h.appendLog(fmt.Sprintf(
				"suspect: zombie-storm ppid=%d zombies=%d (check %d/%d)",
				ppid, n, streak, h.cfg.ConsecNeeded))
		}
	}
	if storm {
		h.stateEnter("zombie-storm", "")
	} else {
		h.stateExit("zombie-storm")
	}
	h.cycles.WithLabelValues(checkZombieStorm, "ok").Inc()
}

// --- Check: journald integrity (A5) ---
// After a hard-reboot (SNR) journald's binary files corrupt at the
// tail: `journalctl -u k0sworker` errors, prints "corrupt", or
// returns abnormally empty while the unit is active — which also
// blinds the 05/06 journal-signature checks. The remedy is the
// operator's rotate+vacuum, bounded by a rate budget.

func (h *Hygiene) checkJournaldIntegrity(ctx context.Context, workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkJournald, "gated").Inc()
		return
	}
	out, err := h.cfg.journalFn(ctx)
	corrupt := err != nil ||
		strings.Contains(strings.ToLower(out), "corrupt")
	empty := err == nil && strings.TrimSpace(out) == ""
	if empty {
		// "No k0sworker lines in 10m" is ambiguous — a
		// healthy-but-quiet unit hits the same branch as real
		// corruption, and remediating it would rotate+vacuum every
		// cooldown forever. Second probe: the UNFILTERED journal.
		// Any line means journald is fine and the unit is just
		// silent; an error, an empty reply, or a "corrupt" warning
		// is journald-level anomaly — only then remediate.
		unfiltered, uerr := h.cfg.journalAnyFn(ctx)
		if uerr == nil && strings.TrimSpace(unfiltered) != "" &&
			!strings.Contains(strings.ToLower(unfiltered), "corrupt") {
			empty = false
		}
	}
	switch {
	case corrupt, empty:
		h.journaldFails++
		if h.journaldFails < h.cfg.ConsecNeeded {
			h.appendLog(fmt.Sprintf(
				"suspect: journald-integrity journal corrupt=%v empty=%v err=%v while k0sworker active (check %d/%d)",
				corrupt, empty, err, h.journaldFails, h.cfg.ConsecNeeded))
			h.cycles.WithLabelValues(checkJournald, "ok").Inc()
			return
		}
	default:
		h.journaldFails = 0
		h.cycles.WithLabelValues(checkJournald, "ok").Inc()
		return
	}
	if h.cfg.Systemd == nil {
		h.cycles.WithLabelValues(checkJournald, "gated").Inc()
		return
	}
	if !h.rateTrySpend("last-journald-vacuum", journaldVacuumInterval) {
		h.appendLog("suspect: journald-integrity confirmed but vacuum " +
			"cooldown active — skip")
		h.cycles.WithLabelValues(checkJournald, "ok").Inc()
		return
	}
	h.appendLog(fmt.Sprintf(
		"ACTION: journalctl --rotate --vacuum-time=3d - journal corrupt=%v empty=%v err=%v for active k0sworker",
		corrupt, empty, err))
	if jout, jerr := h.cfg.Systemd.Exec(ctx,
		"journalctl", "--rotate", "--vacuum-time=3d"); jerr != nil {
		h.appendLog(fmt.Sprintf(
			"suspect: journalctl --rotate --vacuum-time=3d failed: %v (%s)",
			jerr, strings.TrimSpace(jout)))
	} else {
		h.actions.WithLabelValues(checkJournald, "rotate_vacuum").Inc()
	}
	h.journaldFails = 0
	h.cycles.WithLabelValues(checkJournald, "ok").Inc()
}

// --- Check: cilium-envoy readiness + agent healthz (2.5 & B1) ---
// From cilium 1.16 the L7/xDS listener lives in a separate
// cilium-envoy container: an agent restart (sig9/15) can strand it
// holding a stale unix socket — L3/L4 still flows while Gateway API
// traffic 503s. The check probes the envoy admin port and reads the
// agent's /v1/healthz subsystem states for evidence; the kill fires
// when the agent was SIGKILLed this cycle or envoy stays unready
// for ConsecNeeded cycles.

// ciliumUnhealthySubsystems lists healthz subsystem paths whose
// state is neither Ok nor Disabled — nested maps are walked so
// {"cluster":{"cilium":{"state":"Failure"}}} resolves too.
func ciliumUnhealthySubsystems(body []byte) []string {
	var v any
	if json.Unmarshal(body, &v) != nil {
		return nil
	}
	var bad []string
	var walk func(path string, n any)
	walk = func(path string, n any) {
		m, ok := n.(map[string]any)
		if !ok {
			return
		}
		if s, ok := m["state"].(string); ok && s != "Ok" && s != "Disabled" {
			bad = append(bad, path+"="+s)
		}
		for k, c := range m {
			child := k
			if path != "" {
				child = path + "." + k
			}
			walk(child, c)
		}
	}
	walk("", v)
	sort.Strings(bad)
	return bad
}

func (h *Hygiene) checkCiliumEnvoy(ctx context.Context, workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkCiliumEnvoy, "gated").Inc()
		return
	}
	tasks, reachable := h.ciliumNamedTasks("cilium-envoy")
	if !reachable {
		h.cycles.WithLabelValues(checkCiliumEnvoy, "abort").Inc()
		return
	}
	if len(tasks) == 0 {
		// No cilium-envoy container — older cilium or no L7 proxy:
		// clear any stale latch like checkCilium does.
		h.envoyFails = 0
		h.stateExit("cilium-envoy-down")
		h.cycles.WithLabelValues(checkCiliumEnvoy, "ok").Inc()
		return
	}
	// 2.5: subsystem/datapath health off the agent socket is
	// evidence only — an unreadable socket must not block the envoy
	// verdict (the admin port is the primary signal).
	if body, err := h.cfg.unixGet(ctx, h.cfg.CiliumSocket, "/v1/healthz"); err == nil {
		if bad := ciliumUnhealthySubsystems(body); len(bad) > 0 {
			h.appendLog(fmt.Sprintf(
				"suspect: cilium subsystem health degraded: %s",
				strings.Join(bad, ",")))
		}
	}
	// Trigger 1: the agent was SIGKILLed this cycle — envoy may hold
	// the stale socket, restart it alongside (B1).
	if h.ciliumAgentKilled {
		h.killCiliumEnvoy(tasks, "cilium-agent restarted this cycle")
		h.cycles.WithLabelValues(checkCiliumEnvoy, "ok").Inc()
		return
	}
	code, err := h.cfg.probeHTTPStatus(ctx,
		h.cfg.CiliumEnvoyReadyURL, ciliumProbeTime)
	if err == nil && code == http.StatusOK {
		h.envoyFails = 0
		h.stateExit("cilium-envoy-down")
		h.cycles.WithLabelValues(checkCiliumEnvoy, "ok").Inc()
		return
	}
	h.envoyFails++
	if h.envoyFails < h.cfg.ConsecNeeded {
		h.appendLog(fmt.Sprintf(
			"suspect: cilium-envoy-down ready probe code=%d err=%v (check %d/%d)",
			code, err, h.envoyFails, h.cfg.ConsecNeeded))
		h.cycles.WithLabelValues(checkCiliumEnvoy, "ok").Inc()
		return
	}
	h.stateEnter("cilium-envoy-down",
		fmt.Sprintf("ready_probe_fails=%d", h.envoyFails))
	h.killCiliumEnvoy(tasks,
		fmt.Sprintf("unready %d consecutive cycles", h.envoyFails))
	h.cycles.WithLabelValues(checkCiliumEnvoy, "ok").Inc()
}

// killCiliumEnvoy restarts the envoy container through its init
// pids — kubelet rebuilds it like the agent path. The dedicated
// budget keeps envoy kills from eating the agent's restart rate.
func (h *Hygiene) killCiliumEnvoy(tasks []ctrTask, why string) {
	if !h.rateTrySpend("last-cilium-envoy-restart", h.cfg.MinRestartInterval) {
		h.appendLog(fmt.Sprintf(
			"suspect: cilium-envoy kill skipped (%s) — restart cooldown (<30m)", why))
		return
	}
	if h.killNamedTasks(tasks, "cilium-envoy") {
		h.appendLog(fmt.Sprintf(
			"ACTION: killed cilium-envoy container - %s (kubelet will restart -> xDS resync)", why))
		h.envoyFails = 0
		h.actions.WithLabelValues(checkCiliumEnvoy, "sigkill").Inc()
	} else {
		h.appendLog(fmt.Sprintf(
			"suspect: cilium-envoy kill skipped (%s) — no running task to kill", why))
	}
}

// --- Check: MTU drift, cilium datapath vs overlay (B4) ---
// A pod created before the MTU change keeps MTU 1500 while the
// overlay neb1 is 1300 — the bpf policy-route then returns
// FRAG_NEEDED and the flow dies after SYN-ACK. Latch +
// ACTION cilium-mtu-drift: so nodereporter raises
// CiliumMTUExceedsOverlay.

func mtuOfIface(sysnet, iface string) (int64, bool) {
	data, err := os.ReadFile(filepath.Join(sysnet, iface, "mtu"))
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// runtimeConfigMTU reads the cilium MTU out of
// agent-runtime-config.json — the fallback when cilium_net has no
// sysfs entry. The key is searched recursively through maps AND
// arrays (versions nest it differently); with several `mtu` keys
// the MAX wins — deterministic (Go map order makes a "first
// match" walk unstable), and the drift check wants the worst-case
// datapath MTU anyway.
func runtimeConfigMTU(path string) (int64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	var v any
	if json.Unmarshal(data, &v) != nil {
		return 0, false
	}
	var vals []int64
	var walk func(n any)
	walk = func(n any) {
		switch t := n.(type) {
		case map[string]any:
			for k, val := range t {
				if strings.EqualFold(k, "mtu") {
					if f, isNum := val.(float64); isNum {
						vals = append(vals, int64(f))
					}
				}
				walk(val)
			}
		case []any:
			for _, val := range t {
				walk(val)
			}
		}
	}
	walk(v)
	if len(vals) == 0 {
		return 0, false
	}
	return slices.Max(vals), true
}

func (h *Hygiene) checkCiliumMTU(workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkCiliumMTU, "gated").Inc()
		return
	}
	neb, nebOK := mtuOfIface(h.cfg.SysClassNet, h.cfg.NebulaIface)
	cil, cilOK := mtuOfIface(h.cfg.SysClassNet, h.cfg.CiliumIface)
	if !cilOK {
		cil, cilOK = runtimeConfigMTU(h.cfg.CiliumRuntimeConfig)
	}
	if !nebOK || !cilOK {
		// No overlay or no cilium datapath to compare — a drift
		// latch from before must not linger.
		h.stateExit("cilium-mtu-drift")
		h.cycles.WithLabelValues(checkCiliumMTU, "ok").Inc()
		return
	}
	if cil > neb {
		if !h.stateExists("cilium-mtu-drift") {
			h.stateEnter("cilium-mtu-drift",
				fmt.Sprintf("cilium=%d nebula=%d", cil, neb))
			// NPD contract: nodereporter maps this line to the
			// CiliumMTUExceedsOverlay Event + problem_counter.
			h.appendLog(fmt.Sprintf(
				"ACTION cilium-mtu-drift: cilium=%d nebula=%d", cil, neb))
		}
	} else {
		h.stateExit("cilium-mtu-drift")
	}
	h.cycles.WithLabelValues(checkCiliumMTU, "ok").Inc()
}
