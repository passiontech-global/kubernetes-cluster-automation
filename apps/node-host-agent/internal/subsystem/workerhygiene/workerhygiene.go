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
//   - W7 additions — d-state-storm (H1: >=5 total or >=2
//     runtime-critical procs in uninterruptible sleep for
//     ConsecNeeded cycles → state-d-state-storm → KernelHungTasks),
//     systemd-scopes (H2: 30m reset-failed sweep of abandoned
//     cri-containerd-*.scope units), the cilium-envoy xDS NACK guard
//   - cilium-lrp-dns :53 datapath probe (H3), spegel-mirror (H4:
//     Ready=False DaemonSet pod → delete + state latch), and
//     calico-hygiene (H7: orphan cali* veth leak + felix :9099
//     readiness — active only on calico nodes like cicd).
//   - W8 additions — the agent-owned watchdog heartbeat (BUG-H1:
//     Cycle() refreshes last-run + seeds installed, the reporter's
//     self-heartbeat made WatchdogStale permanently blind),
//     k0sworker restarts on the A4 syncloop/containerd-sock latches
//     (BUG-H4, shared overload/settle/last-restart gates), mtime
//     refresh on maintained latches (BUG-H6), 2xx-only probeHTTP
//     verdicts (BUG-H7), pod-log + snapshot attribution in
//     disk-bloat (BUG-H8), felix restart + cali* orphan-veth GC
//     (W8-NM3), cilium BPF map pressure (W8-NM3), and the PSI
//     memory-thrash evictor (W2).
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
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
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

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/cycle"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/journalwatch"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/watchdogconf"
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
	defaultKubeletTokenPath    = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultContainerdSocket    = "/host/run/k0s/containerd.sock"
	defaultCiliumEnvoyReadyURL = "http://127.0.0.1:9964/ready"
	defaultCtrIngestDir        = "/host/var/lib/k0s/containerd/io.containerd.content.v1.content/ingest"
	defaultK0sDataDir          = "/host/var/lib/k0s"
	defaultSysClassNet         = "/sys/class/net"
	defaultNebulaIface         = "neb1"
	defaultCiliumIface         = "cilium_net"
	defaultCiliumWG0Iface      = "cilium_wg0"
	defaultCiliumRuntimeConfig = "/host/run/cilium/state/agent-runtime-config.json"
	// defaultNetnsDir is the host /run/netns mount — the CNI
	// netns-file leak reaper scans cni-* entries here.
	defaultNetnsDir       = "/host/run/netns"
	unixSockProbeTimeout  = 5 * time.Second
	zombieStormThreshold  = 500 // <defunct> children of one parent = storm
	ctrIngestMaxAge       = 3 * time.Hour
	ctrIngestScanInterval = 6 * time.Hour
	k0sDiskHighWatermark  = 0.75
	// W6.3 disk-bloat thresholds: above the warn watermark the
	// bounded walk runs (at most once per DiskBloatScanInterval —
	// the walk itself costs IO on the disk that is already full);
	// above the critical watermark a non-system offender may be
	// evicted outright. Any single dir past the pod threshold is a
	// runaway target.
	k0sDiskBloatWatermark         = 0.85
	k0sDiskBloatCriticalWatermark = 0.92
	diskBloatPodThresholdBytes    = int64(15) << 30 // 15 GiB
	diskBloatScanInterval         = 15 * time.Minute
	diskBloatEvictInterval        = 15 * time.Minute // last-disk-bloat-evict budget
	maxBloatWalkEntries           = 10000            // walk cap per scanned dir
	// journaldVacuumInterval bounds how often the A5 remedy runs —
	// journalctl --rotate is cheap but --vacuum-time does real IO.
	journaldVacuumInterval = 30 * time.Minute
	// defaultJournalUnreadableNeeded is the consecutive-failed-read
	// budget for the journal-unreadable blindness latch (cicd
	// controller incident: broken journald left every journal-based
	// check silently seeing "0 hits").
	defaultJournalUnreadableNeeded = 5
	// Wave-7 defaults (W7-H1..H7): the D-state storm thresholds
	// (total procs OR runtime-critical procs), the 30m
	// systemd-scope reaper cadence, the envoy admin stats +
	// node-local-dns :53 probe targets, the spegel pod maturity
	// floor, and the calico guard knobs.
	defaultDStateStormThreshold = 5
	dStateRuntimeMin            = 2 // runtime-critical D-state procs → storm
	systemdScopeScanInterval    = 30 * time.Minute
	defaultCiliumEnvoyAdminURL  = "http://127.0.0.1:9901/stats?filter=update_rejected"
	// The LRP datapath probe targets the kube-dns ClusterIP — the
	// CiliumLocalRedirectPolicy's serviceMatcher redirects
	// 10.96.0.10:53 to the local cache pod, so this exercises the
	// real frontend→backend path from the host netns (socket-LB).
	// 169.254.20.10 only exists in the legacy hostNetwork/iptables
	// mode (calico cluster, where this check is dormant) — probing
	// it on a cilium node always fails → false-positive pod kills.
	defaultLocalDNSProbeAddr      = "10.96.0.10:53"
	defaultLocalDNSProbeName      = "kubernetes.default.svc.cluster.local"
	spegelMinPodAge               = 3 * time.Minute
	defaultCalicoFelixReadyURL    = "http://127.0.0.1:9099/readiness"
	defaultCalicoOrphanVethThresh = 50 // cali* ifaces above the pod count → leak
	// Wave-8 knobs: felix restart after the latch persisted this
	// many consecutive failed cycles, orphan-veth down-age for the
	// cali* GC, the critical BPF map fill ratio (W8-NM3), the PSI
	// memory-thrash guard thresholds (W2), the /var/log/pods walk
	// (BUG-H8) and the evict cooldown shared with disk-bloat.
	calicoFelixRestartFails = 3
	calicoVethGCMinAge      = 15 * time.Minute
	defaultBPFMapHighRatio  = 0.90
	defaultPodLogsDir       = "/host/var/log/pods"
	defaultPSIFullAvg60     = 25.0             // /proc/pressure/memory full avg60 in percent
	defaultMemFreeMinRatio  = 0.08             // MemAvailable/MemTotal floor
	psiEvictInterval        = 15 * time.Minute // last-psi-evict budget
	// Wave-9 knobs: the kernel slab-leak guard thresholds
	// (SUnreclaim/MemTotal enter/clear hysteresis + the
	// drop_caches budget), the orphan CNI netns confirmation age,
	// the WireGuard encapsulation overhead subtracted from the
	// overlay MTU for the cilium_wg0 drift check, and the
	// content-store prune budget.
	slabLeakEnterRatio     = 0.35
	slabLeakClearRatio     = 0.25
	slabDropCachesInterval = time.Hour
	cniNetnsMinAge         = 30 * time.Minute
	wgEncapOverheadBytes   = 60
	contentPruneInterval   = 6 * time.Hour
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
	checkCiliumWG    = "cilium-wg-peers"    // W5.6
	checkDiskBloat   = "disk-bloat"         // W6.3
	checkDState      = "d-state-storm"      // W7-H1
	checkSysScopes   = "systemd-scopes"     // W7-H2
	checkCiliumLRP   = "cilium-lrp-dns"     // W7-H3
	checkSpegel      = "spegel-mirror"      // W7-H4
	checkCalico      = "calico-hygiene"     // W7-H7
	checkCiliumBPF   = "cilium-bpf-maps"    // W8-NM3 (inside checkCilium)
	checkPSIThrash   = "psi-memory-thrash"  // W2
	checkCNINetns    = "cni-netns-gc"       // W9 orphan /run/netns/cni-* reaper
	checkCtrMeta     = "containerd-meta"    // W10-KR3 meta.db corruption + orphan shims
	checkHostOOM     = "host-oom"           // W10-KR1 SystemOOMVictim event + metric
	checkOrphanHP    = "orphan-hostpath"    // W10-ST2 orphaned pvc-* hostPath dirs
)

// stateJournalUnreadable is the blindness latch the journal-read
// accounting sets: journald installed (journal storage exists) but
// every read produces nothing — the 05/06 signature greps and the
// nodereporter journal monitors are blind until it clears.
const stateJournalUnreadable = "journal-unreadable"

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
	KubeletSyncloopURL string // kubelet :10250 /healthz/syncloop (PLEG)
	// KubeletTokenPath is the bearer-token file attached to kubelet's
	// secure-port probes — kubelet denies anonymous /healthz access,
	// so the syncloop probe authenticates with the pod SA token
	// (requires get on nonResourceURL /healthz/syncloop). Empty or
	// unreadable → the probe runs unauthenticated and 401/403
	// answers mark the check inconclusive, not down.
	KubeletTokenPath      string
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
	// W6.3 disk-bloat runaway detector: above K0sDiskBloatWatermark
	// the bounded emptyDir/snapshot walk runs (gated by
	// DiskBloatScanInterval — the walk costs IO on the disk that is
	// already full); above K0sDiskBloatCriticalWatermark a
	// non-system pod holding more than DiskBloatPodThresholdBytes
	// may be evicted through the API (last-disk-bloat-evict budget).
	K0sDiskBloatWatermark         float64
	K0sDiskBloatCriticalWatermark float64
	DiskBloatPodThresholdBytes    int64
	DiskBloatScanInterval         time.Duration
	// Wave-7 knobs: H1 D-state storm threshold, H3 envoy admin
	// stats URL + the node-local-dns :53 datapath probe target,
	// H7 calico orphan-veth headroom + felix readiness probe.
	DStateStormThreshold      int    // total D-state procs → storm latch (5)
	CiliumEnvoyAdminURL       string // envoy :9901 /stats?filter=update_rejected
	LocalDNSProbeAddr         string // node-local-dns :53 probe target (169.254.20.10:53)
	LocalDNSProbeName         string // query name the DNS probe resolves
	CalicoFelixReadyURL       string // calico-node felix :9099/readiness probe
	CalicoOrphanVethThreshold int    // cali* ifaces above the pod count → leak (50)
	// Wave-8 knobs: the /var/log/pods walk added to disk-bloat
	// (BUG-H8), the critical BPF map fill ratio for the cilium-bpf
	// latch (W8-NM3), and the PSI memory-thrash guard (W2): latch
	// when /proc/pressure/memory `full avg60` exceeds PSIFullAvg60
	// (percent) AND MemAvailable/MemTotal drops under
	// MemFreeMinRatio for ConsecNeeded cycles.
	PodLogsDir      string  // /var/log/pods walk root (BUG-H8)
	BPFMapHighRatio float64 // critical-map fill ratio → latch (0.90)
	PSIFullAvg60    float64 // PSI memory full avg60 percent (25)
	MemFreeMinRatio float64 // free-mem ratio floor (0.08)
	// Wave-9 knobs: the cilium WireGuard datapath iface for the
	// double-encap MTU check (B4 extension), and the host
	// /run/netns mount the orphan cni-* reaper scans.
	CiliumWG0Iface string // cilium WG tunnel iface (cilium_wg0)
	NetnsDir       string // host /run/netns — orphan cni-* netns files
	// Wave-10 knobs (KR1/KR3/ST2):
	// ContainerdMetaJournalFn is the KR3 journal probe — `journalctl
	// -u k0sworker -u containerd --since "3 minutes ago"`. nil →
	// Systemd.ExecCombined default; a nil Systemd leaves the journal
	// half of the check inconclusive (the orphan-shim half still runs).
	ContainerdMetaJournalFn func(ctx context.Context) (string, error)
	// OrphanHostPathDirs are the host-side local-provisioner roots
	// ST2 scans for pvc-* dirs whose PV is gone.
	OrphanHostPathDirs []string
	// HostOOM* are the hostmetrics kmsg scanner's markers this check
	// consumes (KR1) — defaults derive from WatchdogStateDir so both
	// subsystems agree on the file contract without wiring.
	HostOOMVictimFile  string // "<epoch> <comm>" latest host-level victim
	HostOOMCountFile   string // cumulative host-level OOM kills
	ConntrackDropsFile string // cumulative nf_conntrack table-full records
	// EventNamespace receives the SystemOOMVictim node event.
	EventNamespace string

	// killFn delivers signals — seam for tests (SIGKILL on pause /
	// proxy-agent/shim/cilium pids, and signal-0 liveness probes).
	killFn func(pid int, sig syscall.Signal) error
	// nowFn supplies the current time — seam for tests.
	nowFn func() time.Time
	// probeHTTP does one GET and returns nil only on a 2xx response
	// (BUG-H7 — a 500/503 means the probed service is wedged, not
	// "the listener is alive"). Seam.
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
	// (syncloop 500 vs healthz 200, envoy /ready 503) or where ANY
	// answer proves liveness (kubelet :10250 /healthz, api /livez —
	// a 401/403 is an auth denial, not a dead listener). bearer != ""
	// attaches an Authorization header (kubelet :10250 requires
	// auth). Seam.
	probeHTTPStatus func(ctx context.Context, url, bearer string, timeout time.Duration) (int, error)
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
	// ctrPruneContent runs the store-wide content GC — `k0s ctr -n
	// k8s.io content prune` via the systemd exec wrapper (W9). It
	// only fires while /var/lib/k0s sits above the high watermark,
	// on the last-content-gc 6h budget. nil → Systemd.Exec
	// default. Seam.
	ctrPruneContent func(ctx context.Context) error
	// wgAllowedIPsFn returns how many cilium_wg0 peers carry a real
	// allowed-ips set — `wg show cilium_wg0 allowed-ips` parsed
	// (peers at "(none)" are wiped). nil → Systemd.Exec default.
	// Seam for the W5.6 check.
	wgAllowedIPsFn func(ctx context.Context) (int, error)
	// ciliumEncryptPeersFn returns the expected WG peer count —
	// `cilium-dbg encrypt status` parsed. An error or a count <=0
	// makes the caller fall back to ReadyNodes-1. nil →
	// Systemd.Exec default. Seam.
	ciliumEncryptPeersFn func(ctx context.Context) (int, error)
	// httpGetBody GETs a plain-HTTP endpoint and returns the body —
	// the envoy admin stats page (W7-H3 xDS NACK guard). Seam.
	httpGetBody func(ctx context.Context, url string, timeout time.Duration) ([]byte, error)
	// dnsProbe sends one UDP DNS query for a fixed cluster name to
	// addr and reports whether a well-formed answer returns before
	// the deadline — the node-local-dns :53 datapath probe
	// (W7-H3). Seam.
	dnsProbe func(addr, name string, timeout time.Duration) bool

	// JournalDirs are the host journal storage roots — the
	// journal-unreadable latch may only fire while at least one
	// exists (a host with no journald at all fails every read by
	// configuration, not by fault).
	JournalDirs []string
	// JournalUnreadableNeeded is the consecutive-failed-read budget
	// before state-journal-unreadable latches; <=0 → 5.
	JournalUnreadableNeeded int
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
	if c.KubeletTokenPath == "" {
		c.KubeletTokenPath = defaultKubeletTokenPath
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
	if c.CiliumWG0Iface == "" {
		c.CiliumWG0Iface = defaultCiliumWG0Iface
	}
	if c.NetnsDir == "" {
		c.NetnsDir = defaultNetnsDir
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
	if c.K0sDiskBloatWatermark <= 0 {
		c.K0sDiskBloatWatermark = k0sDiskBloatWatermark
	}
	if c.K0sDiskBloatCriticalWatermark <= 0 {
		c.K0sDiskBloatCriticalWatermark = k0sDiskBloatCriticalWatermark
	}
	if c.DiskBloatPodThresholdBytes <= 0 {
		c.DiskBloatPodThresholdBytes = diskBloatPodThresholdBytes
	}
	if c.DiskBloatScanInterval <= 0 {
		c.DiskBloatScanInterval = diskBloatScanInterval
	}
	if c.DStateStormThreshold <= 0 {
		c.DStateStormThreshold = defaultDStateStormThreshold
	}
	if c.CiliumEnvoyAdminURL == "" {
		c.CiliumEnvoyAdminURL = defaultCiliumEnvoyAdminURL
	}
	if c.LocalDNSProbeAddr == "" {
		c.LocalDNSProbeAddr = defaultLocalDNSProbeAddr
	}
	if c.LocalDNSProbeName == "" {
		c.LocalDNSProbeName = defaultLocalDNSProbeName
	}
	if c.CalicoFelixReadyURL == "" {
		c.CalicoFelixReadyURL = defaultCalicoFelixReadyURL
	}
	if c.CalicoOrphanVethThreshold <= 0 {
		c.CalicoOrphanVethThreshold = defaultCalicoOrphanVethThresh
	}
	if c.PodLogsDir == "" {
		c.PodLogsDir = defaultPodLogsDir
	}
	if c.BPFMapHighRatio <= 0 {
		c.BPFMapHighRatio = defaultBPFMapHighRatio
	}
	if c.PSIFullAvg60 <= 0 {
		c.PSIFullAvg60 = defaultPSIFullAvg60
	}
	if c.MemFreeMinRatio <= 0 {
		c.MemFreeMinRatio = defaultMemFreeMinRatio
	}
	// Wave-10 (KR1/KR3/ST2) defaults — WatchdogStateDir is already
	// resolved above, so the marker-file paths derive from the same
	// dir hostmetrics writes into.
	if len(c.OrphanHostPathDirs) == 0 {
		// Paths are used RAW (no HostRoot prefix): the DaemonSet
		// mounts host /var/openebs/local at the SAME container path
		// (sweeper contract). /opt/local-path-provisioner has no
		// container mount — ReadDir just misses there — but is the
		// real host path in standalone mode. Extra provisioner
		// roots need a matching DS hostPath mount to be scanned.
		c.OrphanHostPathDirs = []string{
			"/var/openebs/local",
			"/opt/local-path-provisioner",
		}
	}
	if c.HostOOMVictimFile == "" {
		c.HostOOMVictimFile = filepath.Join(c.WatchdogStateDir,
			"kmsg-host-oom-victim")
	}
	if c.HostOOMCountFile == "" {
		c.HostOOMCountFile = filepath.Join(c.WatchdogStateDir,
			"kmsg-host-oom-count")
	}
	if c.ConntrackDropsFile == "" {
		c.ConntrackDropsFile = filepath.Join(c.WatchdogStateDir,
			"kmsg-conntrack-drops")
	}
	if c.EventNamespace == "" {
		c.EventNamespace = "default"
	}
	if c.httpGetBody == nil {
		// Plain HTTP (no TLS) — the envoy admin stats page lives on
		// loopback :9901. A non-200 is an error: the reject-delta
		// verdict is unreadable, not "zero".
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.IdleConnTimeout = 90 * time.Second
		client := &http.Client{Transport: tr}
		c.httpGetBody = func(ctx context.Context, url string, timeout time.Duration) ([]byte, error) {
			pctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			req, err := http.NewRequestWithContext(pctx, http.MethodGet, url, nil)
			if err != nil {
				return nil, err
			}
			resp, err := client.Do(req)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
				return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
			}
			return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		}
	}
	if c.dnsProbe == nil {
		c.dnsProbe = probeDNSUDP
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
		// BUG-H7: an HTTP response no longer counts as alive on its
		// own — a wedged cilium-agent :9879/healthz answering 500/503
		// must read as DOWN. Only a 2xx is a pass; insecure TLS stays
		// (kubelet cert SANs don't cover 127.0.0.1, curl -ks parity).
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
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				return fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
			}
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
				// Fail, not empty: a nil client fed the unreadable
				// tracker a fake "journald-wide empty reply" verdict.
				return "", fmt.Errorf("no systemd client wired")
			}
			return sd.Journal(ctx, "k0sworker.service", journalWindow)
		}
	}
	if c.journalAnyFn == nil {
		sd := c.Systemd
		c.journalAnyFn = func(ctx context.Context) (string, error) {
			if sd == nil {
				return "", fmt.Errorf("no systemd client wired")
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
		c.probeHTTPStatus = func(ctx context.Context, url, bearer string, timeout time.Duration) (int, error) {
			pctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			req, err := http.NewRequestWithContext(pctx, http.MethodGet, url, nil)
			if err != nil {
				return 0, err
			}
			if bearer != "" {
				req.Header.Set("Authorization", "Bearer "+bearer)
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
	if c.ctrPruneContent == nil {
		sd := c.Systemd
		c.ctrPruneContent = func(ctx context.Context) error {
			if sd == nil {
				return fmt.Errorf("no systemd client wired")
			}
			_, err := sd.Exec(ctx,
				"k0s", "ctr", "-n", "k8s.io", "content", "prune")
			return err
		}
	}
	if c.wgAllowedIPsFn == nil {
		sd := c.Systemd
		c.wgAllowedIPsFn = func(ctx context.Context) (int, error) {
			if sd == nil {
				return 0, fmt.Errorf("no systemd client wired")
			}
			out, err := sd.Exec(ctx, "wg", "show", "cilium_wg0", "allowed-ips")
			if err != nil {
				return 0, err
			}
			return parseWGAllowedIPs(out), nil
		}
	}
	if c.ciliumEncryptPeersFn == nil {
		c.ciliumEncryptPeersFn = func(ctx context.Context) (int, error) {
			// The agent's own API beats `cilium-dbg`: the binary only
			// lives INSIDE the cilium-agent container — an sd.Exec on
			// the host always fails and silently degrades every cycle
			// to the ReadyNodes-1 fallback. /v1/healthz's
			// cluster.nodes[] lists exactly the remote cilium members
			// this node should peer with (virtual/liqo nodes run no
			// agent, so they never appear).
			body, err := c.unixGet(ctx, c.CiliumSocket, "/v1/healthz")
			if err != nil {
				return 0, err
			}
			n, ok := parseCiliumHealthNodes(body)
			if !ok {
				return 0, fmt.Errorf("no cluster.nodes in cilium healthz")
			}
			return n, nil
		}
	}
	if len(c.JournalDirs) == 0 {
		// /host mount convention like the other defaults; standalone
		// wiring passes the unprefixed host paths.
		c.JournalDirs = []string{
			"/host/var/log/journal", "/host/run/log/journal"}
	}
	if c.JournalUnreadableNeeded <= 0 {
		c.JournalUnreadableNeeded = defaultJournalUnreadableNeeded
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
	// W7 pod matchers — anchored like konnPodRe/dnsPodRe.
	nldPodRe        = regexp.MustCompile(`^node-local-dns-[a-z0-9]+$`) // H3 LRP DNS guard
	spegelPodRe     = regexp.MustCompile(`^spegel-[a-z0-9]+$`)         // H4 P2P mirror
	calicoNodePodRe = regexp.MustCompile(`^calico-node-[a-z0-9]+$`)    // H7 felix
)

// Hygiene runs the worker checks on one ticker.
type Hygiene struct {
	cfg Config
	// proc is the /proc view bound to cfg.ProcRoot — the shared
	// platform/procfs helpers (pid listing, cmdline/environ/stat
	// reads, liveness) the checks below all go through.
	proc procfs.FS

	// state is the shared hoststate.Store for the watchdog state-dir
	// contract (state-* latches, last-* rate budgets, installed/
	// last-run heartbeat, watchdog log appends). Its clock is a
	// closure over the LIVE cfg.nowFn so post-construction test
	// stubs still apply; its RateTrySpend mutex serialises the
	// feeder-vs-Cycle check+spend pairs the old rateMu guarded
	// (TOCTOU double-restart on the shared last-* budgets).
	state *hoststate.Store

	// In-memory consecutive counters — the shell kept these as
	// consecutive-* files; in-agent state survives between cycles and
	// an agent restart just re-arms the count (bounded by Interval).
	// Most streaks live on their Check structs now; the four below
	// stay on Hygiene because pre-Check tests poke them by name
	// (e.h.stallFails et al. — more than five call sites each, so
	// keeping the field beats churning the test contract).
	stallFails      int // kubelet-stall streak (stallCheck)
	ciliumInitFails int // cilium-init-stuck streak (ciliumInitCheck)
	ciliumIPAMFails int // cilium-ipam streak (ciliumIPAMCheck)
	ciliumWGFails   int // cilium_wg0 peer-deficit streak (ciliumWGCheck)
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

	// journalReads is the journal-unreadable accounting — every
	// journal read (k0sworker snapshot + A5 probes) is classified
	// into it; the tracker fires the state-journal-unreadable latch
	// on persistent blindness while journal storage exists.
	journalReads journalwatch.Tracker
	// ciliumAgentKilled is shared between the cilium check family
	// and the envoy check: killCiliumAgent sets it (the agent kill
	// can come from the cilium, cilium-init or wg-peers check —
	// whichever wins the shared last-cilium-restart budget first),
	// and the envoy check restarts cilium-envoy the same cycle so
	// its xDS listener can't hold a stale socket across the agent
	// restart. Cycle resets it before the checks run.
	ciliumAgentKilled bool

	// Wave-10 ST2 gauge values — shared between orphanHPCheck
	// (writes them each cycle) and writeNodeAgentPromTextfile
	// (reads them at end of Cycle); tests poke them too.
	orphanHostPathBytes int64
	orphanHostPathDirs  int

	cycles          *prometheus.CounterVec // check, result
	actions         *prometheus.CounterVec // check, action
	ciliumAllocated prometheus.Gauge       // cilium IPAM allocated IPs (38)
	ciliumLeaked    prometheus.Gauge       // allocated − in-use (38)
	// ctrIngestsCleaned counts ingest dirs removed by the A3 GC.
	ctrIngestsCleaned prometheus.Counter

	// checks is the ordered per-Cycle dispatch list — initChecks
	// fills it; the order preserves the sequence the checks ran
	// before the table existed. The checks are also named fields
	// so tests can reach per-check state and the old
	// Hygiene-method forwarders resolve without a list walk.
	checks      []Check
	stall       *stallCheck
	watch       *watchWedgeCheck
	teardown    *podTeardownCheck
	konn        *konnCheck
	dns         *dnsResolvCheck
	syncloop    *syncloopCheck
	ctrsock     *ctrsockCheck
	ctrTasks    *ctrTasksCheck
	ingestGC    *ingestGCCheck
	cilium      *ciliumCheck
	ciliumInit  *ciliumInitCheck
	ctrImages   *ctrImagesCheck
	ciliumIPAM  *ciliumIPAMCheck
	ciliumEnvoy *ciliumEnvoyCheck
	ciliumMTU   *ciliumMTUCheck
	ciliumWG    *ciliumWGCheck
	diskBloat   *diskBloatCheck
	journald    *journaldCheck
	zombies     *zombieStormCheck
	dstate      *dstateCheck
	scopes      *scopesCheck
	ciliumLRP   *ciliumLRPCheck
	spegel      *spegelCheck
	calico      *calicoCheck
	cniNetns    *cniNetnsCheck
	psiThrash   *psiThrashCheck
	ctrMeta     *ctrMetaCheck
	hostOOM     *hostOOMCheck
	orphanHP    *orphanHPCheck
}

// New returns a Hygiene and registers its metrics on reg.
func New(cfg Config, reg prometheus.Registerer) (*Hygiene, error) {
	if cfg.Client == nil {
		// The first Cycle LIST would nil-pointer panic — the check
		// contract is "never panic", so reject at construction.
		return nil, fmt.Errorf("workerhygiene: Config.Client is required")
	}
	cfg.applyDefaults()
	h := &Hygiene{cfg: cfg, proc: procfs.New(cfg.ProcRoot)}
	// Now MUST close over the live config field, not the cfg
	// parameter: tests re-stub h.cfg.nowFn after New returns and
	// the store has to observe the new clock (hoststate.New doc).
	h.state = hoststate.New(cfg.WatchdogStateDir, cfg.WatchdogLogFile,
		func() time.Time { return h.cfg.nowFn() }, logger)
	h.journalReads = journalwatch.Tracker{
		Needed: cfg.JournalUnreadableNeeded,
		Dirs:   cfg.JournalDirs,
	}

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
	h.initChecks()
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
		cycle.Idle(ctx)
		return
	}
	// The tick self-gates on kubeletFeederActive() each round, so a
	// node dropped from systemd_watchdog_hosts (unit file pruned) or
	// a WD_SIG_KUBELET_WATCHDOG=off conf rewrite idles without an
	// agent restart. The wait makes Run's return coincide with the
	// feeder's exit — a restarted Run must never stack a second
	// feeder, and callers may tear down cfg paths on return.
	// The feeder gets its OWN cancel: a bare `defer wg.Wait()` also
	// runs during panic unwinding, but the feeder only exits on
	// ctx.Done() — nothing cancels ctx on a Cycle panic, so Run
	// parked forever and the agent's recover never fired (the
	// subsystem died silently). Cancelling first bounds the wait on
	// EVERY exit path — panic included — so the panic reaches the
	// agent recover and a restarted Run finds the old feeder gone.
	fctx, stop := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			// A feeder panic must not take the daemon down — the
			// agent's recover only wraps Run itself, not
			// goroutines Run spawned.
			if r := recover(); r != nil {
				logger().Error("workerhygiene: kubelet watchdog feeder "+
					"panicked — feeder dead until Run restart",
					"panic", r)
			}
		}()
		h.runKubeletFeeder(fctx)
	}()
	// Feeder setup precedes the FIRST Cycle too — a first-Cycle
	// panic must tear down a running feeder, not stack a second
	// one behind it on the agent's restart.
	defer func() {
		stop()
		wg.Wait()
	}()
	cycle.Every("workerhygiene", h.cfg.Interval, h.Cycle).Run(ctx)
}

// Cycle runs one round of every check in the ordered dispatch
// list. The k0sworker unit file gates everything (WD_REQUIRES:
// k0sworker) — controllers and test envs without the unit are a
// silent no-op. Each check must never panic and degrades to no-op
// on missing files.
func (h *Hygiene) Cycle(ctx context.Context) {
	if _, err := os.Stat(h.cfg.K0sWorkerUnitFile); err != nil {
		h.cycles.WithLabelValues("all", "gated").Inc()
		return
	}
	// uptime gate (WD_REQUIRES: uptime k0sworker — the shell also
	// required uptime >= 1200s): a freshly rebooted node gets grace
	// before any destructive check runs — Terminating ages surviving
	// a reboot must not trigger action inside the first minutes.
	if up, err := h.proc.UptimeSeconds(); err == nil && up < minUptimeSeconds {
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
	// pod Terminating, no dns-pod running) so it stays unbuilt. The
	// second return is the root-reachability flag: false = a task
	// root could not be listed, so "zero live tasks" verdicts are
	// unverifiable (teardown fails closed).
	var tasks map[string][]ctrTask
	tasksComplete := true
	tasksOnce := func() (map[string][]ctrTask, bool) {
		if tasks == nil {
			tasks, tasksComplete = h.buildTaskMap()
		}
		return tasks, tasksComplete
	}
	// One /proc pid-dir listing feeds every per-cycle process scan
	// (konnectivity proxy-agent sweep, ctr-tasks orphan shims +
	// per-dir leftover kills, zombie-storm count) — independent
	// ReadDir sweeps were 3-5 full walks of a several-thousand-entry
	// dir. Lazy like the task map: most cycles never need it.
	var pids []int
	pidsOnce := func() []int {
		if pids == nil {
			// ReadDir-order pids, error swallowed like the old
			// procPIDs — a nil result retries the scan on the
			// next pidsOnce call (same as before).
			pids, _ = h.proc.PIDs()
		}
		return pids
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
			switch {
			case err != nil:
				h.state.AppendLog(fmt.Sprintf("k0sworker journal snapshot failed: %v", err))
				h.noteJournalRead(false,
					fmt.Sprintf("snapshot failed: %v", err))
			case journalwatch.FilesGone(j):
				h.noteJournalRead(false,
					"journalctl reports no journal files")
			case strings.TrimSpace(j) != "":
				h.noteJournalRead(true, "")
				// err==nil && empty: a quiet 10m window is
				// ambiguous (A5's unfiltered probe owns the
				// disambiguation) — it neither counts the
				// streak nor clears it.
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
			logger().Warn("workerhygiene: k0sworker is-active probe "+
				"failed — worker checks gated off this cycle "+
				"(fail closed)",
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
	// The checks dispatch through the ordered list initChecks
	// built — the order preserves the sequence the checks ran
	// before the table existed. Disabled checks (WD_SIG_<NAME>=off)
	// count cycles{check,disabled} exactly like the old run gate.
	env := &cycleEnv{
		pods:         pods,
		apiOK:        apiOK,
		workerActive: workerActive,
		tasksOnce:    tasksOnce,
		pidsOnce:     pidsOnce,
		journalOnce:  journalOnce,
	}
	for _, c := range h.checks {
		if sigOn(c.Name()) {
			c.Run(ctx, env)
		} else {
			h.cycles.WithLabelValues(c.Name(), "disabled").Inc()
		}
	}
	// W10 node_agent_* gauges — one textfile per cycle carrying the
	// OOM/conntrack counters and the orphan-hostpath measurements
	// the checks above just refreshed.
	h.writeNodeAgentPromTextfile()
	// BUG-H1: the periodic watchdog heartbeat lives HERE now —
	// nodereporter used to refresh last-run every Cycle, which made
	// its own WatchdogStale probe permanently blind. The hygiene
	// Cycle owns the refresh (controllerhygiene/nethealth do the
	// same on non-worker nodes); gated early-returns above skip it
	// so a node where the checks never ran does not claim a run.
	h.state.Heartbeat()
}

// listNodePods lists pods scheduled to this node; apiOK=false means
// the LIST failed — checks treat it as "apiserver unreachable"
// (inconclusive: keep counters/latches, never act).
func (h *Hygiene) listNodePods(ctx context.Context) ([]corev1.Pod, bool) {
	list, err := h.cfg.Client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + h.cfg.NodeName,
	})
	if err != nil {
		h.state.AppendLog(fmt.Sprintf(
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
// state-<name> latches, last-* rate budgets, the installed/last-run
// heartbeat and watchdog-log appends are the shared hoststate.Store
// contract — h.state (built in New) implements them; see
// internal/platform/hoststate for the file-format docs.

// --- /proc + containerd task helpers ---
// The /proc reads themselves live in platform/procfs (h.proc) —
// pid listing, cmdline/environ/stat parsing, liveness, uptime. What
// remains below is only the part that must read the live config
// seams (killFn/nowFn are re-stubbed by tests after New).

// pidLive is procfs.FS.Live bound to this subsystem's killFn seam —
// h.cfg.killFn is read at call time because tests re-stub it after
// New returns.
func (h *Hygiene) pidLive(pid int) bool {
	return h.proc.Live(pid, h.cfg.killFn)
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
// dns checks. Missing files are skipped, never fatal.
//
// complete=false when a task ROOT itself could not be listed — the
// map then only claims "no live tasks" for pods whose tasks it
// never saw, so force-delete callers must fail closed (checkCtrTasks
// abort parity): the runtime root must exist on a live worker (ANY
// error incl. ENOENT is suspect), while a genuinely-absent sandbox
// root is normal on layouts without a shim dir and stays complete.
// taskMapBuilds counts invocations so tests can assert the lazy
// once-per-cycle behaviour directly.
func (h *Hygiene) buildTaskMap() (map[string][]ctrTask, bool) {
	h.taskMapBuilds++
	m := map[string][]ctrTask{}
	complete := true
	for i, root := range []string{h.cfg.CtrTaskRoot, h.cfg.SandboxCtlRoot} {
		entries, err := os.ReadDir(root)
		if err != nil {
			if i == 0 || !os.IsNotExist(err) {
				complete = false
			}
			// A permission/IO error silently degrades the task
			// map — surface it so force-delete decisions aren't
			// the only trace of running on incomplete data.
			if !os.IsNotExist(err) {
				h.state.AppendLog(fmt.Sprintf(
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
	return m, complete
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
	h.state.AppendLog(fmt.Sprintf(
		"POD-TEARDOWN-FORCE-DELETE: force-delete pod %s/%s (uid %.8s) - Terminating %ds, zero live tasks",
		p.Namespace, p.Name, string(p.UID),
		int64(h.cfg.nowFn().Sub(p.DeletionTimestamp.Time).Seconds())))
	return h.cfg.Client.CoreV1().Pods(p.Namespace).Delete(ctx, p.Name,
		metav1.DeleteOptions{
			GracePeriodSeconds: ptr.To[int64](0),
			PropagationPolicy:  ptr.To(metav1.DeletePropagationBackground),
		})
}

// procAge is procfs.FS.Age bound to the nowFn seam (tests re-stub
// h.cfg.nowFn after New).
func (h *Hygiene) procAge(pid int) time.Duration {
	return h.proc.Age(pid, h.cfg.nowFn())
}

// pidsWithCmdline returns pids whose joined cmdline contains sub —
// the pkill -f replacement (the agent can't rely on pkill being in
// the container image). The pid list is the caller's per-cycle
// snapshot.
func (h *Hygiene) pidsWithCmdline(sub string, pids []int) []int {
	var out []int
	for _, pid := range pids {
		if strings.Contains(strings.Join(h.proc.Cmdline(pid), " "), sub) {
			out = append(out, pid)
		}
	}
	return out
}

// --- orphan-shim scope helpers ---
//
// The Phase-B shim reaper must only ever reap shims of THE containerd
// instance CtrTaskRoot belongs to. A node can run a second containerd
// (host dockerd serves namespace moby on /run/containerd/containerd.sock,
// concourse workers spawn their own) whose shims read as "orphan" the
// moment their -id doesn't exist under the k0s k8s.io task root —
// SIGKILLing them cold-restarted every docker container per sweep
// (NodeOverloaded incident 2026-11: 10 containers x every ~6min).
// The shim's own cmdline carries the proof: -namespace + -address.

// stateFileExists reports whether a state-dir file exists — unlike
// stateExists it checks RAW filenames (markers like wedged-seen-<id>
// are not state-* latches).
func (h *Hygiene) stateFileExists(name string) bool {
	_, err := os.Stat(filepath.Join(h.cfg.WatchdogStateDir, name))
	return err == nil
}

// --- Check: cilium (32-cilium.sh + 35-cilium-init-stuck.sh) ---

// podReady reports whether the pod's Ready condition is True — the
// API-side verdict the datapath guards contrast against (a pod
// Ready=True whose service listener is dead is exactly the wedge
// these checks heal).
func podReady(p *corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}
