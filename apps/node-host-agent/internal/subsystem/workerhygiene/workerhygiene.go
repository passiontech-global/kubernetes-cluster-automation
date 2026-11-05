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
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
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
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/journalwatch"
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
	// W7 pod matchers — anchored like konnPodRe/dnsPodRe.
	nldPodRe        = regexp.MustCompile(`^node-local-dns-[a-z0-9]+$`) // H3 LRP DNS guard
	spegelPodRe     = regexp.MustCompile(`^spegel-[a-z0-9]+$`)         // H4 P2P mirror
	calicoNodePodRe = regexp.MustCompile(`^calico-node-[a-z0-9]+$`)    // H7 felix
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
	syncloopFails  int
	syncloopUnauth bool // last probe was 401/403 — log the streak once
	ctrsockFails   int
	envoyFails     int
	journaldFails  int
	// ciliumWGFails counts consecutive cycles the WireGuard peer
	// table reads below expectation (W5.6).
	ciliumWGFails int
	// lastBloatScan stamps the last bounded disk-bloat walk — the
	// tree scan costs IO on the very disk that is full, so above
	// the warn watermark it runs at most once per
	// DiskBloatScanInterval (W6.3).
	lastBloatScan time.Time
	// journalReads is the journal-unreadable accounting — every
	// journal read (k0sworker snapshot + A5 probes) is classified
	// into it; the tracker fires the state-journal-unreadable latch
	// on persistent blindness while journal storage exists.
	journalReads journalwatch.Tracker
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

	// Wave-7 counters/state: H1 d-state storm streak, H2 last
	// systemd scope sweep, H3 envoy xDS NACK streak (+ the
	// baseline/last-seen reject sums) and the node-local-dns probe
	// streak, H4 spegel ready-fail streak, H7 calico veth-leak and
	// felix readiness streaks.
	dstateFails      int
	lastScopeScan    time.Time
	envoyXDSInit     bool
	envoyXDSLast     uint64
	envoyXDSFails    int
	nldFails         int
	spegelFails      int
	calicoVethFails  int
	calicoFelixFails int

	// Wave-8 counters: the W2 PSI memory-thrash streak.
	psiThrashFails int

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
	if cfg.Client == nil {
		// The first Cycle LIST would nil-pointer panic — the check
		// contract is "never panic", so reject at construction.
		return nil, fmt.Errorf("workerhygiene: Config.Client is required")
	}
	cfg.applyDefaults()
	h := &Hygiene{cfg: cfg, zombieStreaks: map[zombieParent]int{}}
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
			pids = h.procPIDs()
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
				h.appendLog(fmt.Sprintf("k0sworker journal snapshot failed: %v", err))
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
		h.checkKonnectivity(ctx, pods, pidsOnce, workerActive)
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
		h.checkCtrTasks(ctx, pidsOnce, workerActive)
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
	run(checkCiliumWG, func() {
		h.checkCiliumWGPeers(ctx, apiOK, workerActive)
	})
	run(checkDiskBloat, func() {
		h.checkDiskBloat(ctx, pods, apiOK, workerActive)
	})
	run(checkZombieStorm, func() {
		h.checkZombieStorm(pidsOnce, workerActive)
	})
	run(checkJournald, func() {
		h.checkJournaldIntegrity(ctx, workerActive)
	})
	run(checkDState, func() {
		h.checkDStateTasks(pidsOnce, workerActive)
	})
	run(checkSysScopes, func() {
		h.checkSystemdScopes(ctx, workerActive)
	})
	run(checkCiliumLRP, func() {
		h.checkCiliumLRPDNS(ctx, pods, apiOK, workerActive)
	})
	run(checkSpegel, func() {
		h.checkSpegelMirror(ctx, pods, apiOK, workerActive)
	})
	run(checkCalico, func() {
		h.checkCalicoHygiene(ctx, pods, apiOK, workerActive)
	})
	run(checkCNINetns, func() {
		h.checkOrphanCNINetns(ctx, pidsOnce, workerActive)
	})
	run(checkPSIThrash, func() {
		h.checkPSIThrash(ctx, pods, apiOK, pidsOnce, workerActive)
	})
	// BUG-H1: the periodic watchdog heartbeat lives HERE now —
	// nodereporter used to refresh last-run every Cycle, which made
	// its own WatchdogStale probe permanently blind. The hygiene
	// Cycle owns the refresh (controllerhygiene/nethealth do the
	// same on non-worker nodes); gated early-returns above skip it
	// so a node where the checks never ran does not claim a run.
	h.writeHeartbeat()
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
	logger().Info(msg)
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
// logs the transition once, lib.sh STATE-ENTER parity. An existing
// latch gets its mtime refreshed (BUG-H6): the janitor reaps state-*
// files older than 24h, so a latch maintained for days by an owner
// still evaluating the condition would otherwise be reaped
// mid-episode.
func (h *Hygiene) stateEnter(name, extra string) {
	p := h.statePath(name)
	if _, err := os.Stat(p); err == nil {
		now := h.cfg.nowFn()
		_ = os.Chtimes(p, now, now)
		return
	}
	content := strconv.FormatInt(h.cfg.nowFn().Unix(), 10) + "\n"
	// Tmp name mirrors apiprober's writeFileAtomic: a leading dot
	// keeps it out of hostmetrics' state-* scan — a "state-<n>.tmp"
	// file would register a phantom "<n>.tmp" watchdog_state series
	// that then sits at 0 forever (seenStates never drops keys).
	tmp := filepath.Join(filepath.Dir(p), ".tmp-"+filepath.Base(p))
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		logger().Warn("workerhygiene: state latch write failed",
			"state", name, "path", p, "error", err)
		return
	}
	if err := os.Rename(tmp, p); err != nil {
		logger().Warn("workerhygiene: state latch write failed",
			"state", name, "path", p, "error", err)
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
		logger().Warn("workerhygiene: state latch remove failed",
			"state", name, "path", p, "error", err)
		return
	}
	h.appendLog(fmt.Sprintf("STATE-EXIT: %s", name))
}

// writeHeartbeat is the agent-owned replacement for the shell
// watchdog's prom_emit heartbeat (BUG-H1): `installed` is created
// only when absent (baseline epoch, ansible force:false parity) and
// `last-run` is rewritten every cycle — nodereporter's
// watchdogStale() reads exactly this pair. Writes are atomic via
// the ".tmp-<name>" convention so a reader never sees a truncated
// epoch; a failed write is logged, never fatal.
func (h *Hygiene) writeHeartbeat() {
	if err := os.MkdirAll(h.cfg.WatchdogStateDir, 0o755); err != nil {
		logger().Warn("workerhygiene: watchdog heartbeat failed",
			"dir", h.cfg.WatchdogStateDir, "error", err)
		return
	}
	now := h.cfg.nowFn().Unix()
	installed := filepath.Join(h.cfg.WatchdogStateDir, "installed")
	if _, err := os.Stat(installed); os.IsNotExist(err) {
		h.writeEpochFile(installed, now)
	}
	h.writeEpochFile(filepath.Join(h.cfg.WatchdogStateDir, "last-run"), now)
}

// writeEpochFile writes "<epoch>\n" via the stateEnter ".tmp-<name>"
// tmp+rename convention — atomic on POSIX.
func (h *Hygiene) writeEpochFile(path string, epoch int64) {
	tmp := filepath.Join(filepath.Dir(path), ".tmp-"+filepath.Base(path))
	content := strconv.FormatInt(epoch, 10) + "\n"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		logger().Warn("workerhygiene: heartbeat write failed",
			"path", path, "error", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		logger().Warn("workerhygiene: heartbeat write failed",
			"path", path, "error", err)
	}
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
		logger().Warn("workerhygiene: rate budget write failed",
			"budget", name, "path", p, "error", err)
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
	f := strings.Fields(string(data))
	if len(f) == 0 {
		return 0, fmt.Errorf("empty uptime")
	}
	return strconv.ParseFloat(f[0], 64)
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
	apiOK bool, tasksOnce func() (map[string][]ctrTask, bool), workerActive bool) {
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
			var complete bool
			tasks, complete = tasksOnce()
			if !complete {
				// A task root was unreadable — "zero live tasks"
				// is unverifiable, so a force-delete could reap a
				// pod whose tasks the map never saw. Inconclusive
				// cycle: keep counters/latch, act on nothing
				// (checkCtrTasks unreadable-root parity).
				h.appendLog(
					"suspect: pod-teardown aborted — ctr task map incomplete, force-deletes unverifiable")
				h.cycles.WithLabelValues(checkTeardown, "abort").Inc()
				return
			}
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

func (h *Hygiene) checkKonnectivity(ctx context.Context, pods []corev1.Pod,
	pidsOnce func() []int, workerActive bool) {
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
	for _, pid := range pidsOnce() {
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
	tasksOnce func() (map[string][]ctrTask, bool), workerActive bool) {
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
			// Namespace pin like deleteKonnectivityPod: the name
			// regex alone would match a user pod named coredns-*/
			// node-local-dns-* in ANY namespace — the pause SIGKILL
			// is only for the kube-system DaemonSets.
			if p.Status.Phase != corev1.PodRunning ||
				p.Namespace != "kube-system" ||
				!dnsPodRe.MatchString(p.Name) {
				continue
			}
			if tasks == nil {
				tasks, _ = tasksOnce()
				// An incomplete map is fail-closed here already:
				// an unseen pause pid reads as pid==0 → the pod
				// is skipped, never killed.
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

// kubelet10250Alive runs the kubelet :10250 /healthz liveness series
// — the shell's `curl -ks` retry loop. ANY HTTP response proves the
// listener is alive; only a transport error/timeout counts as down.
// A 401/403 is kubelet answering an auth denial, NOT a dead listener
// — probing anonymously read that as "down" → kubelet-10250-down →
// k0sworker restarts spent on a healthy kubelet (same bug class the
// syncloop probe fixed by authenticating + treating unauth answers
// as non-verdicts). The SA bearer from KubeletTokenPath rides along
// so clusters requiring auth return the real healthz verdict; a
// missing token just falls back to anonymous, whose 401 still counts
// as alive.
func (h *Hygiene) kubelet10250Alive(ctx context.Context) bool {
	bearer := h.kubeletBearer()
	for i := 0; i < probeAttempts; i++ {
		if _, err := h.cfg.probeHTTPStatus(ctx,
			h.cfg.KubeletHealthzURL, bearer, probeTimeout); err == nil {
			return true
		}
		if i+1 < probeAttempts {
			select {
			case <-ctx.Done():
				return false
			case <-time.After(h.cfg.ProbeGap):
			}
		}
	}
	return false
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
		// ANY HTTP response, even 401/403, means the listener is
		// alive).
		if !h.kubelet10250Alive(ctx) {
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
	// Stat the pods ROOT once before the per-pod sweep: with the dir
	// itself unreadable/vanished every per-pod stat fails and ALL
	// assigned pods count "missing" → false wedge latch + a k0sworker
	// restart spent on a filesystem blip. The IsDir half matters just
	// as much as the error half: a regular FILE at the path stats
	// cleanly but every per-pod join then fails ENOTDIR — the same
	// false wedge via a different syscall. Inconclusive — keep
	// counters/latch exactly like the !apiOK path.
	st, err := os.Stat(h.cfg.KubeletPodsDir)
	if err != nil || !st.IsDir() {
		h.appendLog(fmt.Sprintf(
			"suspect: kubelet pods dir %s unstatable or not a directory (isdir=%v, err=%v) — watch-wedge inconclusive, keeping state",
			h.cfg.KubeletPodsDir, err == nil && st.IsDir(), err))
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
// the container image). The pid list is the caller's per-cycle
// snapshot.
func (h *Hygiene) pidsWithCmdline(sub string, pids []int) []int {
	var out []int
	for _, pid := range pids {
		if strings.Contains(strings.Join(h.procCmdline(pid), " "), sub) {
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

// shimFlagValue extracts `-name value` / `-name=value` (double-dash
// forms tolerated) from a shim argv. ok=false when the flag is absent
// or value-less.
func shimFlagValue(argv []string, name string) (string, bool) {
	for i, a := range argv {
		if a == "-"+name || a == "--"+name {
			if i+1 < len(argv) {
				return argv[i+1], true
			}
			return "", false
		}
		if v, ok := strings.CutPrefix(a, "-"+name+"="); ok {
			return v, true
		}
		if v, ok := strings.CutPrefix(a, "--"+name+"="); ok {
			return v, true
		}
	}
	return "", false
}

// hostSidePath maps an in-pod /host-mounted path back to the path a
// host process reports — the shim's -address carries the HOST socket
// path (/run/k0s/containerd.sock) while config paths live under the
// host-root mount (/host/run/k0s/containerd.sock).
func hostSidePath(p string) string {
	if rest, ok := strings.CutPrefix(p, "/host/"); ok {
		return "/" + rest
	}
	if p == "/host" {
		return "/"
	}
	return p
}

// normalizeCtrAddr canonicalizes a containerd grpc socket address so
// a cosmetic difference can't mark our own shim foreign: the unix://
// scheme and the /var/run symlink collapse to the canonical /run path.
func normalizeCtrAddr(a string) string {
	a = strings.TrimPrefix(a, "unix://")
	if a == "" {
		return ""
	}
	a = filepath.Clean("/" + strings.TrimPrefix(a, "/"))
	if rest, ok := strings.CutPrefix(a, "/var/run/"); ok {
		a = "/run/" + rest
	}
	return a
}

// ctrShimSockets returns the host-side socket paths the k0s
// containerd is expected to listen on: the configured
// ContainerdSocket plus the path derived from CtrTaskRoot
// (…/containerd/io.containerd.runtime.v2.task/k8s.io → the sibling
// …/k0s/containerd.sock — k0s keeps the socket next to the containerd
// root dir, not inside it).
func (h *Hygiene) ctrShimSockets() map[string]bool {
	out := map[string]bool{}
	if s := normalizeCtrAddr(hostSidePath(h.cfg.ContainerdSocket)); s != "" {
		out[s] = true
	}
	derived := filepath.Join(
		filepath.Dir(filepath.Dir(filepath.Dir(h.cfg.CtrTaskRoot))),
		"containerd.sock")
	if s := normalizeCtrAddr(hostSidePath(derived)); s != "" {
		out[s] = true
	}
	return out
}

// validShimNamespace guards the per-namespace task-dir join against
// path traversal — a shim cmdline is host-controlled input.
func validShimNamespace(ns string) bool {
	return ns != "" && ns != "." && ns != ".." &&
		!strings.ContainsAny(ns, "/\\")
}

// shimTaskDir resolves the task dir a shim of namespace ns + id would
// own under THIS containerd: k8s.io is CtrTaskRoot itself, a foreign
// namespace on the same daemon lives at the sibling
// io.containerd.runtime.v2.task/<ns>/<id> dir.
func (h *Hygiene) shimTaskDir(ns, id string) string {
	return filepath.Join(filepath.Dir(h.cfg.CtrTaskRoot), ns, id)
}

// ctrShimScope parses a containerd-shim-runc-v2 argv and reports the
// task id + whether the shim belongs to the containerd instance this
// agent watches. A shim is in-scope only when BOTH flags are present
// AND -address names our containerd socket — a missing/unparseable
// flag means the instance can't be verified, so the shim is treated
// as foreign (fail closed: never reap an unidentified shim).
func (h *Hygiene) ctrShimScope(argv []string) (ns, sid string, inScope bool) {
	m := shimIDRe.FindStringSubmatch(strings.Join(argv, " "))
	if m == nil {
		return "", "", false
	}
	ns, nsOK := shimFlagValue(argv, "namespace")
	addr, addrOK := shimFlagValue(argv, "address")
	if !nsOK || !addrOK || !validShimNamespace(ns) {
		return "", "", false
	}
	if !h.ctrShimSockets()[normalizeCtrAddr(addr)] {
		return "", "", false
	}
	return ns, m[1], true
}

// checkCtrTasks cleans wedged containerd task dirs and orphan shims —
// the filesystem port of the shell's ctr-based checks (no ctr socket
// needed in the agent pod):
//
//   - Orphan shim: live containerd-shim-runc-v2 process scoped to THIS
//     containerd (-address names the k0s socket; -address/-namespace
//     absent or foreign → not ours, never touched) whose -id task dir
//     is gone from its namespace's task root AND the sandbox root,
//     proc age >=5m → SIGKILL (cap MaxShimKill/cycle).
//   - Wedged task dir: init.pid unreadable/dead/zombie, OR init alive
//     but log.json missing on a non-sandbox task — confirmed via a
//     wedged-seen-<id> marker persisting >=5m (the marker replaces
//     "dead >=5m": dir age can't distinguish a just-exited init from
//     a real wedge). Confirmed → SIGKILL live init + any process
//     holding the id, then remove the dir (cap MaxCtrTaskClean/cycle).
func (h *Hygiene) checkCtrTasks(ctx context.Context,
	pidsOnce func() []int, workerActive bool) {
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
	// dir vanished makes every shim-mediated kill fail forever). The
	// reaper is scoped by -address to the containerd that owns
	// CtrTaskRoot: a second containerd on the same host (host dockerd's
	// moby shims, a concourse worker's own daemon) has task dirs under
	// a DIFFERENT root, so its shims used to all read "orphan" and get
	// SIGKILLed every sweep — cold-restarting every foreign container
	// and saturating the node (NodeOverloaded incident 2026-11).
	nShim := 0
	pids := pidsOnce()
	for _, pid := range pids {
		if nShim >= h.cfg.MaxShimKill {
			break
		}
		argv := h.procCmdline(pid)
		joined := strings.Join(argv, " ")
		if !strings.Contains(joined, "containerd-shim-runc-v2") {
			continue
		}
		ns, sid, inScope := h.ctrShimScope(argv)
		if !inScope {
			continue
		}
		if ns == "k8s.io" {
			if liveDirs[sid] || sbDirs[sid] {
				continue
			}
		} else {
			// Foreign namespace on OUR containerd (e.g. a `ctr -n`
			// task): resolve the dir under the sibling namespace
			// root — only a genuinely missing dir is an orphan.
			if _, err := os.Stat(h.shimTaskDir(ns, sid)); err == nil ||
				sbDirs[sid] {
				continue
			}
		}
		if h.procAge(pid) < 5*time.Minute {
			continue
		}
		h.appendLog(fmt.Sprintf(
			"ACTION: kill orphan shim pid=%d id=%.12s ns=%s - task dir missing",
			pid, sid, ns))
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
		if nClean >= h.cfg.MaxCtrTaskClean {
			h.appendLog(fmt.Sprintf("suspect: ctr-task-wedged still pending cap=%d",
				h.cfg.MaxCtrTaskClean))
			break
		}
		// Marker removal only once the dir is actually being
		// cleaned: a dir dropped by the cap must KEEP its
		// confirmed marker — removing it first made over-cap
		// dirs re-confirm for another 5m forever.
		_ = os.Remove(filepath.Join(h.cfg.WatchdogStateDir, "wedged-seen-"+id))
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
		for _, pid := range h.pidsWithCmdline(id, pids) {
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
		// W8-NM3: a healthy healthz doesn't prove the datapath —
		// conntrack/SNAT/LB BPF maps can sit at capacity while the
		// agent still answers 200. Evaluate the map fill ratios on
		// the same agent socket.
		h.checkCiliumBPFMaps(ctx)
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
		!h.stateExists("node-overloaded") &&
		h.rateTrySpend("last-cilium-restart", h.cfg.MinRestartInterval):
		// Budget spent atomically BEFORE acting (rate_spend
		// parity): a missed kill still consumed it — the feeder
		// goroutine competes for the same file.
		if h.killCiliumAgent(tasks) {
			h.appendLog(fmt.Sprintf(
				"ACTION: killed cilium-agent container - healthz down %dx (kubelet will restart)",
				h.ciliumFails))
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
	case !h.rateTrySpend("last-cilium-restart", h.cfg.MinRestartInterval):
		h.appendLog(fmt.Sprintf(
			"suspect: cilium-init-stuck init_eps=%d %dx but restart cooldown — skip kill",
			initEps, h.ciliumInitFails))
	default:
		// Budget already spent atomically by the rateTrySpend case —
		// the feeder goroutine competes for the same file.
		if h.killCiliumAgent(tasks) {
			h.appendLog(fmt.Sprintf(
				"ACTION: killed cilium-agent container - init_eps=%d %dx (kubelet will restart -> informer resync)",
				initEps, h.ciliumInitFails))
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

// --- W8-NM3: cilium BPF map pressure ---
// The datapath dies silently long before the agent does: once the
// conntrack, SNAT or LB-service maps hit maxEntries, new flows are
// dropped/blackholed while :9879/healthz keeps returning 200. The
// check reads `GET /v1/map` off the agent socket and latches
// state-cilium-bpf-map-pressure when any critical map exceeds
// BPFMapHighRatio of its capacity — the latch is what NPD/NHC sees;
// no remedy is attempted (map growth needs a datapath
// restart/resize decision a node agent must not take alone).

// ciliumBPFMapCritical is the map set whose fill ratio gates the
// latch — the v4 conntrack pair, the SNAT pool and the v2 LB
// services map hit hard maxEntries first and each blackholes a
// different traffic class when full.
var ciliumBPFMapCritical = map[string]bool{
	"cilium_ct4_global":       true,
	"cilium_ct_any4_global":   true,
	"cilium_snat_v4_external": true,
	"cilium_lb4_services_v2":  true,
}

// parseCiliumBPFMaps extracts name → [used, max] from a /v1/map
// body. Wire shapes differ across agent versions: entries are
// objects carrying either "name" or "path" (the map name is the
// path basename), the used count arrives as a "used"/"entries"/
// "count" number or a "cache" array whose length is the live
// entries, and capacity as "size"/"max"/"maxSize"/"capacity". A map
// with no readable used+max pair is skipped — pressure can only be
// claimed on both numbers.
func parseCiliumBPFMaps(body []byte) map[string][2]int64 {
	var top any
	if json.Unmarshal(body, &top) != nil {
		return nil
	}
	numOf := func(m map[string]any, keys ...string) (int64, bool) {
		for _, k := range keys {
			if f, ok := m[k].(float64); ok {
				return int64(f), true
			}
		}
		return 0, false
	}
	out := map[string][2]int64{}
	var walk func(n any)
	walk = func(n any) {
		switch t := n.(type) {
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			name, _ := t["name"].(string)
			if name == "" {
				if p, _ := t["path"].(string); p != "" {
					name = filepath.Base(p)
				}
			}
			if name != "" && ciliumBPFMapCritical[name] {
				used, uok := numOf(t, "used", "entries", "count")
				if !uok {
					// Entry arrays carry the live count as their
					// length ("cache" on the /v1/map wire;
					// "entries" on some dumps).
					for _, k := range []string{"cache", "entries"} {
						if arr, ok := t[k].([]any); ok {
							used, uok = int64(len(arr)), true
							break
						}
					}
				}
				max, mok := numOf(t, "max", "maxSize", "max-size", "capacity", "size")
				if uok && mok && max > 0 {
					out[name] = [2]int64{used, max}
				}
			}
			// Map collections may be nested under "maps"/
			// "dynamicMaps"/"staticMaps" keys.
			for _, v := range t {
				walk(v)
			}
		}
	}
	walk(top)
	return out
}

// checkCiliumBPFMaps reads the map fill ratios off the agent socket
// and latches state-cilium-bpf-map-pressure when a critical map
// exceeds BPFMapHighRatio. An unreadable socket or unparseable body
// is inconclusive (the cilium checks' keep-state rule) — the latch
// is neither entered nor cleared on missing evidence.
func (h *Hygiene) checkCiliumBPFMaps(ctx context.Context) {
	body, err := h.cfg.unixGet(ctx, h.cfg.CiliumSocket, "/v1/map")
	if err != nil {
		h.appendLog(fmt.Sprintf(
			"suspect: cilium-bpf-maps map query on %s failed: %v — inconclusive, keeping state",
			h.cfg.CiliumSocket, err))
		h.cycles.WithLabelValues(checkCiliumBPF, "abort").Inc()
		return
	}
	maps := parseCiliumBPFMaps(body)
	var over []string
	for name, um := range maps {
		if float64(um[0]) >= h.cfg.BPFMapHighRatio*float64(um[1]) {
			over = append(over, fmt.Sprintf("%s=%d/%d", name, um[0], um[1]))
		}
	}
	if len(over) == 0 {
		h.stateExit("cilium-bpf-map-pressure")
		h.cycles.WithLabelValues(checkCiliumBPF, "ok").Inc()
		return
	}
	sort.Strings(over)
	h.stateEnter("cilium-bpf-map-pressure", strings.Join(over, " "))
	h.cycles.WithLabelValues(checkCiliumBPF, "ok").Inc()
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
			logger().Warn("kubelet-feeder: k0sworker is-active probe "+
				"failed — skipping this tick (fail closed)",
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
		// probeHTTPStatus, not probeHTTP: the verdict is liveness,
		// so ANY HTTP code — even 401/403/500 — proves the listener
		// answered (curl -sk parity; a 2xx-only read made an
		// auth-refusing or LB-degraded endpoint look "unreachable"
		// and falsely gated remediation as isolated).
		if _, err := h.cfg.probeHTTPStatus(ctx, url, "",
			apiLivezProbeTimeout); err == nil {
			return true
		}
	}
	return false
}

// withDefaultAPIPort appends the apiserver default port to a bare-IP
// backend entry — API_BACKENDS is "ip:port" but bare-IP entries occur
// (APIBackendIPs strips ports for the stale-latch key).
func withDefaultAPIPort(addr string) string {
	// An EMPTY port parses cleanly ("1.2.3.4:" → host ok, port "")
	// but builds a malformed probe URL ("https://1.2.3.4:/livez")
	// that fails every GET silently → node reads isolated forever.
	// Treat it as "port missing" like a bare IP.
	if _, port, err := net.SplitHostPort(addr); err == nil && port != "" {
		return addr
	}
	addr = strings.TrimSuffix(addr, ":")
	if strings.LastIndexByte(addr, ':') < 0 ||
		(strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]")) {
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
// endpoint still answers. Both latches now self-heal (BUG-H4): at
// ConsecNeeded fails they run the shared k0sworker restart gates
// (overload / settle / last-restart budget) instead of waiting for
// 05/T15 to notice.

func (h *Hygiene) checkKubeletSyncloop(ctx context.Context, workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkSyncloop, "gated").Inc()
		return
	}
	var lastErr error
	alive := false
	unauth := false
	// The bearer token is re-read every cycle — the file is small
	// and bound SA tokens rotate.
	bearer := h.kubeletBearer()
	for i := 0; i < probeAttempts; i++ {
		code, err := h.cfg.probeHTTPStatus(ctx,
			h.cfg.KubeletSyncloopURL, bearer, probeTimeout)
		if err == nil {
			switch {
			case code == http.StatusOK:
				alive = true
			case code == http.StatusUnauthorized || code == http.StatusForbidden:
				// Kubelet answered but won't divulge the verdict —
				// retrying the same credentials won't help.
				unauth = true
			default:
				lastErr = fmt.Errorf("syncloop status %d", code)
			}
		} else {
			lastErr = err
		}
		if alive || unauth {
			break
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
	if unauth {
		// The verdict is unknowable without working credentials —
		// inconclusive like the other keep-state paths, NOT a down
		// signal. Logged once per unauth streak so a permanently
		// unauthenticated deployment doesn't spam every cycle.
		if !h.syncloopUnauth {
			h.appendLog("suspect: kubelet-syncloop-down probe unauthorized " +
				"(401/403 — token missing or RBAC nonResourceURL /healthz/* not " +
				"granted) — inconclusive, keeping state")
			h.syncloopUnauth = true
		}
		h.cycles.WithLabelValues(checkSyncloop, "inconclusive").Inc()
		return
	}
	h.syncloopUnauth = false
	if alive {
		h.syncloopFails = 0
		h.stateExit("kubelet-syncloop-down")
		h.cycles.WithLabelValues(checkSyncloop, "ok").Inc()
		return
	}
	h.syncloopFails++
	if h.syncloopFails < h.cfg.ConsecNeeded {
		h.appendLog(fmt.Sprintf(
			"suspect: kubelet-syncloop-down /healthz/syncloop fail (PLEG?) err=%v (check %d/%d)",
			lastErr, h.syncloopFails, h.cfg.ConsecNeeded))
		h.cycles.WithLabelValues(checkSyncloop, "ok").Inc()
		return
	}
	// BUG-H4: a frozen PLEG is a kubelet stall the 05 probe can't
	// see — confirmed consecutive fails now self-heal through the
	// shared k0sworker restart gates (overload / settle /
	// last-restart budget), checkKubeletStall parity.
	overloaded := h.stateExists("node-overloaded")
	if !overloaded {
		h.stateEnter("kubelet-syncloop-down",
			fmt.Sprintf("pleg-frozen last_err=%v", lastErr))
	} else if !h.stateExists("kubelet-syncloop-down") {
		// A stall under CPU starvation is a symptom — latching
		// would escalate to NHC→SNR and dump 100% of the load
		// onto the survivors (amplifier). Log-only.
		h.appendLog(fmt.Sprintf(
			"kubelet-syncloop-down suppressed-overloaded - pleg-frozen last_err=%v", lastErr))
	}
	switch {
	case overloaded:
		h.appendLog(fmt.Sprintf(
			"suspect: kubelet-syncloop-down - node overloaded, skip restart k0sworker (err=%v)", lastErr))
	case !h.k0sWorkerSettled(ctx):
		h.appendLog("suspect: kubelet-syncloop-down - k0sworker not settled (<180s), skip restart")
	case !h.rateTrySpend("last-restart", h.cfg.MinRestartInterval):
		h.appendLog("suspect: kubelet-syncloop-down - in restart cooldown (<30m), skip")
	default:
		// Budget already spent atomically by the rateTrySpend
		// case — the feeder goroutine competes for the same file.
		h.appendLog(fmt.Sprintf(
			"ACTION: restarting k0sworker - kubelet-syncloop-down pleg-frozen (persisted %dx)",
			h.syncloopFails))
		h.syncloopFails = 0
		if err := h.restartK0sWorker(ctx); err != nil {
			h.appendLog(fmt.Sprintf("k0sworker restart failed: %v", err))
		} else {
			h.actions.WithLabelValues(checkSyncloop, "restart").Inc()
		}
	}
	h.cycles.WithLabelValues(checkSyncloop, "ok").Inc()
}

// kubeletBearer reads the service-account token kubelet's :10250
// webhook auth accepts — re-read every call so bound-token rotation
// needs no caching logic. Missing/unreadable file → "" (the probe
// runs unauthenticated and 401/403 marks the check inconclusive).
func (h *Hygiene) kubeletBearer() string {
	b, err := os.ReadFile(h.cfg.KubeletTokenPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
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
	if h.ctrsockFails < h.cfg.ConsecNeeded {
		h.appendLog(fmt.Sprintf(
			"suspect: containerd-sock-down %s probe fail: %v (check %d/%d)",
			h.cfg.ContainerdSocket, err, h.ctrsockFails, h.cfg.ConsecNeeded))
		h.cycles.WithLabelValues(checkCtrSock, "ok").Inc()
		return
	}
	// BUG-H4: a hung containerd socket wedges PLEG and every pod
	// lifecycle op — confirmed consecutive fails self-heal through
	// the shared k0sworker restart gates, checkKubeletSyncloop
	// parity.
	overloaded := h.stateExists("node-overloaded")
	if !overloaded {
		h.stateEnter("containerd-sock-down",
			fmt.Sprintf("probe_err=%v", err))
	} else if !h.stateExists("containerd-sock-down") {
		h.appendLog(fmt.Sprintf(
			"containerd-sock-down suppressed-overloaded - probe_err=%v", err))
	}
	switch {
	case overloaded:
		h.appendLog(fmt.Sprintf(
			"suspect: containerd-sock-down - node overloaded, skip restart k0sworker (err=%v)", err))
	case !h.k0sWorkerSettled(ctx):
		h.appendLog("suspect: containerd-sock-down - k0sworker not settled (<180s), skip restart")
	case !h.rateTrySpend("last-restart", h.cfg.MinRestartInterval):
		h.appendLog("suspect: containerd-sock-down - in restart cooldown (<30m), skip")
	default:
		// Budget already spent atomically by the rateTrySpend
		// case — the feeder goroutine competes for the same file.
		h.appendLog(fmt.Sprintf(
			"ACTION: restarting k0sworker - containerd-sock-down %s (persisted %dx)",
			h.cfg.ContainerdSocket, h.ctrsockFails))
		h.ctrsockFails = 0
		if err := h.restartK0sWorker(ctx); err != nil {
			h.appendLog(fmt.Sprintf("k0sworker restart failed: %v", err))
		} else {
			h.actions.WithLabelValues(checkCtrSock, "restart").Inc()
		}
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
	// Free > total wraps uint64 to ~2^64 → used ~= 1.0 → diskHigh
	// permanently true → the GC sweeps EVERY cycle (btrfs/XFS can
	// report Bavail > Blocks). Saturate instead of subtracting
	// blind — same guard as concourse_cache's fsPressure. The
	// free-side field is Bavail, not Bfree: kubelet/containerd run
	// unprivileged against the root-reserved block margin, so
	// unprivileged-free is the signal that trips ENOSPC first.
	if err := h.cfg.statfsFn(h.cfg.K0sDataDir, &st); err == nil &&
		st.Blocks > 0 && st.Bavail <= st.Blocks {
		used := float64(st.Blocks-st.Bavail) / float64(st.Blocks)
		diskHigh = used > h.cfg.K0sDiskHighWatermark
	}
	due := h.cfg.nowFn().Sub(h.lastIngestScan) >= h.cfg.CtrIngestScanInterval
	if !diskHigh && !due {
		h.cycles.WithLabelValues(checkIngestGC, "ok").Inc()
		return
	}
	// W9: above the high watermark the content store itself may be
	// the hog — run the store-wide prune on its own 6h budget IN
	// ADDITION to the stale-ingest sweep below. Below the
	// watermark (periodic rescan only) it never fires.
	if diskHigh {
		h.maybePruneContentStore(ctx)
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

// maybePruneContentStore runs `k0s ctr -n k8s.io content prune` —
// the store-wide GC that drops content blobs no lease references
// (the stale-ingest sweep only touches ingest/ leftovers; leaked
// leased content is what actually fills /var/lib/k0s). Budgeted by
// the last-content-gc marker at contentPruneInterval — the prune
// walks every blob + lease so it must not run every cycle even
// while the disk stays above the watermark. The budget is spent
// BEFORE the command (rate_spend parity); a failed prune logs
// suspect and does NOT count as an action.
func (h *Hygiene) maybePruneContentStore(ctx context.Context) {
	if !h.rateTrySpend("last-content-gc", contentPruneInterval) {
		return
	}
	if err := h.cfg.ctrPruneContent(ctx); err != nil {
		h.appendLog(fmt.Sprintf(
			"suspect: ctr-ingest-gc content prune failed: %v", err))
		return
	}
	h.appendLog("ACTION: ctr-ingest-gc content prune ran (disk above watermark)")
	h.actions.WithLabelValues(checkIngestGC, "content_gc").Inc()
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

func (h *Hygiene) checkZombieStorm(pidsOnce func() []int, workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkZombieStorm, "gated").Inc()
		return
	}
	byPPID := map[int]int{}
	for _, pid := range pidsOnce() {
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
	// Loop 1 only PRUNES dead streaks — a stored streak must not set
	// storm here: this cycle's zombie count isn't re-validated yet,
	// so a parent that dropped below threshold would hold the latch
	// one extra cycle. Loop 2 re-validates against the current count
	// before any streak contributes to storm.
	storm := false
	for parent := range h.zombieStreaks {
		if _, ok := byPPID[parent.pid]; !ok || keyOf(parent.pid) != parent {
			delete(h.zombieStreaks, parent) // parent gone or pid recycled — streak dead
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

// noteJournalRead feeds one classified journal read into the
// journal-unreadable tracker and drives the latch on transitions:
// enter → state-journal-unreadable + the suspect line, logged once
// per latch entry (the stateExists gate — the latch dedupes the
// alert AND its first line, like checkCiliumMTU); exit → STATE-EXIT
// when a read finally returns journal data (or the journal storage
// vanished — config change, not blindness). The journalDir gate
// lives inside the tracker: a host with no journald storage never
// fires — every read failing is then configuration, not a fault.
func (h *Hygiene) noteJournalRead(ok bool, detail string) {
	enter, exit := h.journalReads.NoteRead(ok)
	if enter && !h.stateExists(stateJournalUnreadable) {
		h.stateEnter(stateJournalUnreadable, detail)
		h.appendLog(fmt.Sprintf(
			"suspect: journal-unreadable %s — %d consecutive journal "+
				"reads produced nothing while journal storage exists; "+
				"every journal-grep check is blind",
			detail, h.journalReads.Fails()))
		h.cycles.WithLabelValues(checkJournald, "journal_unreadable").Inc()
	} else if h.journalReads.Latched() &&
		!h.stateExists(stateJournalUnreadable) {
		// Re-establish after external removal: the latch file can
		// vanish while the tracker stays latched (janitor 24h reap,
		// manual rm) and `enter` is a once-per-episode edge that
		// won't fire again — without this the metric/condition go
		// dark mid-episode.
		h.stateEnter(stateJournalUnreadable, detail)
	}
	if exit {
		h.stateExit(stateJournalUnreadable)
	}
}

// --- Check: journald integrity (A5) ---
// After a hard-reboot (SNR) journald's binary files corrupt at the
// tail: `journalctl -u k0sworker` prints "corrupt" or returns
// abnormally empty while the unit is active — which also blinds the
// 05/06 journal-signature checks. An exec-level read ERROR is not
// corruption evidence (journald never answered — the
// journal-unreadable tracker owns that signal). The remedy is the
// operator's rotate+vacuum, bounded by a rate budget.
//
// The same probes feed the journal-unreadable accounting: when
// journald cannot answer at all (read error, "No journal files", or
// a journald-wide empty unfiltered reply) for JournalUnreadableNeeded
// consecutive reads AND journal storage exists, the
// state-journal-unreadable latch marks the blindness — the
// rotate+vacuum remedy only covers the CORRUPT subset, a dead or
// mute journald needs surfacing, not vacuuming.

func (h *Hygiene) checkJournaldIntegrity(ctx context.Context, workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkJournald, "gated").Inc()
		return
	}
	out, err := h.cfg.journalFn(ctx)
	// Only OUTPUT evidence counts as corruption: an exec-level error
	// (nsenter/journalctl timeout, transient host exec failure) means
	// journald never answered — that is journal-UNREADABLE, not
	// corrupt. Lumping err into "corrupt" ran the rotate+vacuum
	// remedy on every cooldown for a purely transient failure.
	// Journal() folds stderr in, so a corrupt-file notice survives
	// even a non-zero exit and still counts here.
	corrupt := strings.Contains(strings.ToLower(out), "corrupt")
	empty := err == nil && strings.TrimSpace(out) == ""
	var unfiltered string
	var uerr error
	if empty {
		// "No k0sworker lines in 10m" is ambiguous — a
		// healthy-but-quiet unit hits the same branch as real
		// corruption, and remediating it would rotate+vacuum every
		// cooldown forever. Second probe: the UNFILTERED journal.
		// Any line means journald is fine and the unit is just
		// silent; an error, an empty reply, or a "corrupt" warning
		// is journald-level anomaly — only then remediate.
		unfiltered, uerr = h.cfg.journalAnyFn(ctx)
		if uerr == nil && strings.TrimSpace(unfiltered) != "" &&
			!strings.Contains(strings.ToLower(unfiltered), "corrupt") {
			empty = false
		}
	}
	// journal-unreadable accounting: a "corrupt" notice means
	// journald ANSWERED (A5's remedy owns that path) — only a read
	// that produced literally nothing while journald should be
	// talking counts as blindness.
	unreadable := false
	udetail := ""
	switch {
	case err != nil:
		unreadable, udetail = true, fmt.Sprintf("read failed: %v", err)
	case journalwatch.FilesGone(out):
		unreadable, udetail = true, "journalctl reports no journal files"
	case empty:
		switch {
		case uerr != nil:
			unreadable, udetail = true,
				fmt.Sprintf("unfiltered probe failed: %v", uerr)
		case journalwatch.FilesGone(unfiltered):
			unreadable, udetail = true,
				"journalctl reports no journal files"
		case strings.TrimSpace(unfiltered) == "":
			unreadable, udetail = true, "journald-wide empty reply"
		}
	}
	h.noteJournalRead(!unreadable, udetail)
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
	case err != nil:
		// Exec failure without corruption evidence — inconclusive
		// (the unreadable tracker owns this signal): keep the fail
		// streak intact but never grow it, and never vacuum.
		h.cycles.WithLabelValues(checkJournald, "abort").Inc()
		return
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
	// W7-H3: xDS NACK guard — envoy can answer /ready=200 while
	// rejecting every config push (cds/lds/rds update_rejected
	// climbing → Gateway/Gateway API routes 404/503 while their API
	// objects report Accepted:True). Positive deltas for
	// ConsecNeeded consecutive cycles latch
	// state-cilium-envoy-xds-reject and restart envoy through the
	// same last-cilium-envoy-restart budget. Runs BEFORE the ready
	// probe's early-return so a green /ready can't hide the wedge.
	if reject, inconclusive := h.evalEnvoyXDS(ctx); inconclusive {
		// Stats page unreadable — inconclusive, keep the streak
		// (a dead envoy fails its own ready probe next).
	} else if reject {
		h.envoyXDSFails++
	} else {
		h.envoyXDSFails = 0
		h.stateExit("cilium-envoy-xds-reject")
	}
	if h.envoyXDSFails >= h.cfg.ConsecNeeded {
		h.stateEnter("cilium-envoy-xds-reject",
			fmt.Sprintf("update_rejected=%d fails=%d",
				h.envoyXDSLast, h.envoyXDSFails))
		h.killCiliumEnvoy(tasks,
			fmt.Sprintf("xDS update_rejected deltas %d consecutive cycles",
				h.envoyXDSFails))
	}
	code, err := h.cfg.probeHTTPStatus(ctx,
		h.cfg.CiliumEnvoyReadyURL, "", ciliumProbeTime)
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
	// W9 double-encap guard: on the WireGuard datapath cilium_wg0
	// carries pod traffic INSIDE the nebula overlay — its MTU must
	// leave room for the WG header (~60B) under the overlay MTU.
	// A wg0 MTU above neb−60 means pod packets exceed what the
	// double-encapsulated path can carry → silent blackhole.
	wg, wgOK := mtuOfIface(h.cfg.SysClassNet, h.cfg.CiliumWG0Iface)
	if !nebOK {
		// No overlay to compare against — a drift latch from
		// before must not linger.
		h.stateExit("cilium-mtu-drift")
		h.cycles.WithLabelValues(checkCiliumMTU, "ok").Inc()
		return
	}
	var driftWhy string
	switch {
	case cilOK && cil > neb:
		driftWhy = fmt.Sprintf("cilium_net=%d nebula=%d", cil, neb)
	case wgOK && wg > neb-wgEncapOverheadBytes:
		driftWhy = fmt.Sprintf("cilium_wg0=%d nebula=%d (wg overhead %d)",
			wg, neb, wgEncapOverheadBytes)
	}
	if driftWhy != "" {
		if !h.stateExists("cilium-mtu-drift") {
			h.stateEnter("cilium-mtu-drift", driftWhy)
			// NPD contract: nodereporter maps this line to the
			// CiliumMTUExceedsOverlay Event + problem_counter.
			h.appendLog(fmt.Sprintf(
				"ACTION cilium-mtu-drift: %s", driftWhy))
		}
	} else {
		h.stateExit("cilium-mtu-drift")
	}
	h.cycles.WithLabelValues(checkCiliumMTU, "ok").Inc()
}

// --- Check: cilium WireGuard peer-gc drift healer (W5.6) ---
// A cilium WireGuard node can lose its wg0 peer table (kernel-side
// peer GC racing agent bookkeeping): cilium_wg0 exists, the agent's
// healthz stays green, but every peer's allowed-ips reads "(none)"
// — the node encrypts nothing while cross-node pod traffic
// blackholes. The healer compares live allowed-ips peers against the
// expected count (cilium-dbg encrypt status, falling back to
// ReadyNodes-1) and restarts the agent through the shared cilium
// budget.

// parseWGAllowedIPs counts peers carrying a real allowed-ips set —
// `wg show <iface> allowed-ips` prints "<pubkey>\t<ip,ip,...>" per
// line, "(none)" for a peer whose routes were wiped.
func parseWGAllowedIPs(out string) int {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[1] == "(none)" {
			continue
		}
		n++
	}
	return n
}

// encryptPeersRe matches a textual "num-peers"-style field inside
// `cilium-dbg encrypt status` — versions that print a table instead
// of JSON (e.g. "NumPeers: 5", "num_peers=5").
var encryptPeersRe = regexp.MustCompile(`(?i)num.?peers[^0-9]*([0-9]+)`)

// jsonFindKeys collects every numeric value under keys matching
// (case-insensitive) any wanted name — the same recursive walk
// runtimeConfigMTU uses for `mtu` (cilium versions nest the count
// differently).
func jsonFindKeys(v any, out *[]int64, keys ...string) {
	switch n := v.(type) {
	case map[string]any:
		for k, val := range n {
			for _, want := range keys {
				if strings.EqualFold(k, want) {
					if f, ok := val.(float64); ok {
						*out = append(*out, int64(f))
					}
				}
			}
			jsonFindKeys(val, out, keys...)
		}
	case []any:
		for _, val := range n {
			jsonFindKeys(val, out, keys...)
		}
	}
}

// parseCiliumEncryptPeers extracts the expected WireGuard peer count
// from `cilium-dbg encrypt status`. JSON bodies are searched for a
// num-peers-ish key (the largest match wins — interfaces may repeat
// the field); a non-JSON body falls back to a text regex. ok=false
// means no usable number (non-wireguard mode, older agent).
func parseCiliumEncryptPeers(out string) (int, bool) {
	var v any
	if json.Unmarshal([]byte(out), &v) == nil {
		var vals []int64
		jsonFindKeys(v, &vals, "num-peers", "numpeers", "num_peers")
		if len(vals) > 0 {
			return int(slices.Max(vals)), true
		}
		return 0, false
	}
	if m := encryptPeersRe.FindStringSubmatch(out); m != nil {
		n, err := strconv.Atoi(m[1])
		return n, err == nil
	}
	return 0, false
}

// parseCiliumHealthNodes counts remote cluster members in the
// agent's /v1/healthz payload ({"cluster":{"nodes":[...]}} — the
// same source `cilium status` reports "Cluster health: N/M"). Every
// entry is a remote node running cilium-agent, i.e. one WireGuard
// peer this node should hold; virtual/liqo nodes run no agent and
// never appear. ok=false when the section is absent or empty — the
// caller then falls back to the node-list heuristic.
func parseCiliumHealthNodes(body []byte) (int, bool) {
	var resp struct {
		Cluster *struct {
			Nodes []json.RawMessage `json:"nodes"`
		} `json:"cluster"`
	}
	if err := json.Unmarshal(body, &resp); err != nil ||
		resp.Cluster == nil || len(resp.Cluster.Nodes) == 0 {
		return 0, false
	}
	return len(resp.Cluster.Nodes), true
}

// readyNodeCount lists Ready, REAL nodes — the expected-peers
// fallback (every other real Ready node should be a WireGuard
// peer). Virtual nodes (Liqo/virtual-kubelet) are excluded — they
// run no cilium-agent so they never become peers; control-plane
// members are excluded too: undercounting expected is the
// fail-safe direction (it can only blunt a partial-drift signal,
// never produce the repeated false kill an overcount causes).
func (h *Hygiene) readyNodeCount(ctx context.Context) int {
	list, err := h.cfg.Client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0
	}
	n := 0
	for i := range list.Items {
		node := &list.Items[i]
		// Virtual nodes run no cilium-agent — never peers.
		if _, ok := node.Labels["liqo.io/type"]; ok {
			continue
		}
		if _, ok := node.Labels["virtual-kubelet.io/provider"]; ok {
			continue
		}
		if node.Labels["type"] == "virtual-kubelet" {
			continue
		}
		// Control-plane members may or may not run the agent —
		// excluding them can only undercount (fail safe).
		if _, ok := node.Labels["node-role.kubernetes.io/control-plane"]; ok {
			continue
		}
		if _, ok := node.Labels["node-role.kubernetes.io/master"]; ok {
			continue
		}
		for _, cond := range node.Status.Conditions {
			if cond.Type == corev1.NodeReady && cond.Status == corev1.ConditionTrue {
				n++
				break
			}
		}
	}
	return n
}

// checkCiliumWGPeers detects the wiped peer table: it runs only on
// nodes where cilium_wg0 exists, the API answered, and a
// cilium-agent task is running — every other shape is another
// check's signal. actual < expected for ConsecNeeded consecutive
// cycles latches state-cilium-wg-peer-wipe and SIGKILLs the agent
// (kubelet restarts it; the shared last-cilium-restart 30m budget
// and the node-overloaded gate apply like sig9).
func (h *Hygiene) checkCiliumWGPeers(ctx context.Context, apiOK, workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkCiliumWG, "gated").Inc()
		return
	}
	if !apiOK {
		// Inconclusive — keep counters/latch exactly like the other
		// API-dependent checks.
		h.cycles.WithLabelValues(checkCiliumWG, "abort").Inc()
		return
	}
	if _, err := os.Stat(filepath.Join(h.cfg.SysClassNet, "cilium_wg0")); err != nil {
		// No WireGuard datapath on this node (calico, tunnel mode,
		// hub) — nothing to heal; drop stale evidence.
		h.ciliumWGFails = 0
		h.stateExit("cilium-wg-peer-wipe")
		h.cycles.WithLabelValues(checkCiliumWG, "ok").Inc()
		return
	}
	tasks, reachable := h.ciliumAgentTasks()
	if !reachable {
		h.cycles.WithLabelValues(checkCiliumWG, "abort").Inc()
		return
	}
	running := false
	for _, t := range tasks {
		if t.live && t.pid > 0 {
			running = true
			break
		}
	}
	if !running {
		// No live cilium-agent — sig9 owns agent-down; killing
		// nothing here is correct, not a miss.
		h.ciliumWGFails = 0
		h.cycles.WithLabelValues(checkCiliumWG, "ok").Inc()
		return
	}
	actual, err := h.cfg.wgAllowedIPsFn(ctx)
	if err != nil {
		h.appendLog(fmt.Sprintf(
			"suspect: cilium-wg-peers wg allowed-ips probe failed: %v — inconclusive, keeping state", err))
		h.cycles.WithLabelValues(checkCiliumWG, "abort").Inc()
		return
	}
	expected, err := h.cfg.ciliumEncryptPeersFn(ctx)
	if err != nil || expected <= 0 {
		// encrypt status unreadable or carries no count — fall back
		// to ReadyNodes-1 (every OTHER Ready node is a peer).
		if n := h.readyNodeCount(ctx); n > 1 {
			expected = n - 1
		} else {
			expected = 0
		}
	}
	if expected <= 0 {
		// No expectation available — inconclusive but not harmful:
		// neither count nor clear a streak we cannot verify.
		h.cycles.WithLabelValues(checkCiliumWG, "ok").Inc()
		return
	}
	if actual >= expected {
		h.ciliumWGFails = 0
		h.stateExit("cilium-wg-peer-wipe")
		h.cycles.WithLabelValues(checkCiliumWG, "ok").Inc()
		return
	}
	h.ciliumWGFails++
	if h.ciliumWGFails < h.cfg.ConsecNeeded {
		h.appendLog(fmt.Sprintf(
			"suspect: cilium-wg-peers allowed_ips=%d expected=%d (check %d/%d)",
			actual, expected, h.ciliumWGFails, h.cfg.ConsecNeeded))
		h.cycles.WithLabelValues(checkCiliumWG, "ok").Inc()
		return
	}
	h.stateEnter("cilium-wg-peer-wipe",
		fmt.Sprintf("allowed_ips=%d expected=%d", actual, expected))
	switch {
	case h.stateExists("node-overloaded"):
		h.appendLog(fmt.Sprintf(
			"suspect: cilium-wg-peers allowed_ips=%d expected=%d %dx but node overloaded — skip kill",
			actual, expected, h.ciliumWGFails))
	case !h.rateTrySpend("last-cilium-restart", h.cfg.MinRestartInterval):
		h.appendLog(fmt.Sprintf(
			"suspect: cilium-wg-peers allowed_ips=%d expected=%d %dx but restart cooldown — skip kill",
			actual, expected, h.ciliumWGFails))
	default:
		// Budget already spent atomically by the rateTrySpend case.
		if h.killCiliumAgent(tasks) {
			// NPD contract: the cilium_wg0 line feeds
			// CiliumWireGuardPeerDrift (events.go).
			h.appendLog(fmt.Sprintf(
				"ACTION: killed cilium-agent container - cilium_wg0 has %d allowed-ip peers while expected %d (kubelet will restart -> wireguard peer resync)",
				actual, expected))
			h.ciliumWGFails = 0
			h.actions.WithLabelValues(checkCiliumWG, "sigkill").Inc()
		} else {
			h.appendLog(fmt.Sprintf(
				"suspect: cilium-wg-peers allowed_ips=%d expected=%d, no running task to kill",
				actual, expected))
		}
	}
	h.cycles.WithLabelValues(checkCiliumWG, "ok").Inc()
}

// --- Check: disk-bloat runaway detector + emergency evictor (W6.3) ---
// A runaway emptyDir (or a leaked containerd snapshot) can fill
// /var/lib/k0s faster than kubelet's eviction thresholds notice —
// the fs going full first kills kubelet/containerd writes and the
// node wedges. Above the warn watermark a bounded walk attributes
// space to pods and snapshots (any single dir past the threshold →
// state-disk-bloat + DiskBloatRunaway event); above the critical
// watermark the largest non-system pod offender is deleted via the
// API under the last-disk-bloat-evict budget.

// bloatHit is one over-threshold directory found by the walk.
type bloatHit struct {
	label string
	bytes int64
}

// readDirNames lists the immediate subdirectories of dir (an
// unreadable/absent root yields nil — the scan just sees no dirs).
func readDirNames(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
}

// walkBytes sums regular-file sizes under root. The walk is bounded:
// after maxBloatWalkEntries entries it stops and reports
// truncated=true — the total is then a lower bound (a tree that
// huge is bloat by definition, but the walk must never become its
// own IO problem on the disk that is already full).
func (h *Hygiene) walkBytes(root string) (total int64, truncated bool) {
	entries := 0
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entries are skipped, never fatal
		}
		entries++
		if entries > maxBloatWalkEntries {
			truncated = true
			return fs.SkipAll
		}
		if d.Type().IsRegular() {
			if fi, ierr := d.Info(); ierr == nil {
				total += fi.Size()
			}
		}
		return nil
	})
	return total, truncated
}

// podLogDirUID extracts the pod uid from a /var/log/pods dir name
// (<ns>_<pod>_<uid>): neither namespaces nor pod names can contain
// '_', so the LAST '_' delimits the uid. "" when there is no
// trailing segment.
func podLogDirUID(base string) string {
	if i := strings.LastIndexByte(base, '_'); i >= 0 && i+1 < len(base) {
		return base[i+1:]
	}
	return ""
}

// scanBloat runs the bounded walks the check is defined over:
// kubelet emptyDir volumes (tmpfs-backed ones can't fill the disk —
// skipped via statfs type), containerd overlayfs snapshots, and the
// /var/log/pods stdout log dirs (BUG-H8 — a runaway log writer
// fills the disk while its emptyDir stays small, and a leaked
// snapshot pins space no volume path accounts for). Over-threshold
// dirs return as hits; podTotals/podByUID feed the
// critical-watermark eviction decision.
func (h *Hygiene) scanBloat(pods []corev1.Pod) (hits []bloatHit,
	podTotals map[string]int64, podByUID map[string]*corev1.Pod) {
	podByUID = map[string]*corev1.Pod{}
	podTotals = map[string]int64{}
	for i := range pods {
		podByUID[string(pods[i].UID)] = &pods[i]
	}
	threshold := h.cfg.DiskBloatPodThresholdBytes
	// (1) emptyDir volumes: pods/<uid>/volumes/kubernetes.io~empty-dir/<vol>.
	for _, uidDir := range readDirNames(h.cfg.KubeletPodsDir) {
		uid := filepath.Base(uidDir)
		for _, vol := range readDirNames(filepath.Join(
			uidDir, "volumes", "kubernetes.io~empty-dir")) {
			var vst unix.Statfs_t
			if err := h.cfg.statfsFn(vol, &vst); err == nil &&
				int64(vst.Type) == int64(unix.TMPFS_MAGIC) {
				continue // medium=Memory emptyDir — can't fill the disk
			}
			size, _ := h.walkBytes(vol)
			podTotals[uid] += size
			if size > threshold {
				label := "pod-uid " + uid
				if p, ok := podByUID[uid]; ok && p != nil {
					label = "pod " + p.Namespace + "/" + p.Name
				}
				hits = append(hits, bloatHit{
					label: label + " volume " + filepath.Base(vol),
					bytes: size})
			}
		}
	}
	// (2) containerd overlayfs snapshots — <id>/fs is the unpacked
	// layer content; a leaked snapshot pins real disk. The CRI
	// plugin uses the container ID (== the task dir name) as the
	// snapshot key, so a live task dir maps the snapshot back to
	// its pod's uid for the eviction decision; unresolvable
	// snapshots stay hits-only.
	snapRoot := filepath.Join(h.cfg.K0sDataDir, "containerd",
		"io.containerd.snapshotter.v1.overlayfs", "snapshots")
	for _, snap := range readDirNames(snapRoot) {
		id := filepath.Base(snap)
		size, _ := h.walkBytes(filepath.Join(snap, "fs"))
		if size <= 0 {
			continue
		}
		if uid := h.snapshotPodUID(id); uid != "" {
			podTotals[uid] += size
		}
		if size > threshold {
			hits = append(hits, bloatHit{
				label: "snapshot " + id, bytes: size})
		}
	}
	// (3) pod stdout log dirs — <PodLogsDir>/<ns>_<pod>_<uid>/: the
	// containerd CRI writes container logs here (rotated at 10MiB ×
	// 5 by kubelet, but a chatty container under a stuck rotation —
	// or a pod with hundreds of short-lived restarts — outruns it).
	for _, logDir := range readDirNames(h.cfg.PodLogsDir) {
		base := filepath.Base(logDir)
		uid := podLogDirUID(base)
		size, _ := h.walkBytes(logDir)
		if uid != "" {
			podTotals[uid] += size
		}
		if size > threshold {
			label := "pod-logs " + base
			if p, ok := podByUID[uid]; ok && p != nil {
				label = "pod " + p.Namespace + "/" + p.Name + " logs"
			}
			hits = append(hits, bloatHit{label: label, bytes: size})
		}
	}
	return hits, podTotals, podByUID
}

// snapshotPodUID resolves a containerd snapshot id back to the pod
// uid owning it — the CRI plugin uses the container ID as the
// snapshot key, and the runtime-v2 task dir of that ID carries the
// io.kubernetes.pod.uid annotation in config.json (either task root
// may hold it). "" when no task dir resolves (leaked/orphan
// snapshot — no pod to bill it to).
func (h *Hygiene) snapshotPodUID(id string) string {
	for _, root := range []string{h.cfg.CtrTaskRoot, h.cfg.SandboxCtlRoot} {
		cfgData, err := os.ReadFile(filepath.Join(root, id, "config.json"))
		if err != nil {
			continue
		}
		if m := podUIDRe.FindSubmatch(cfgData); m != nil {
			return string(m[1])
		}
	}
	return ""
}

func (h *Hygiene) checkDiskBloat(ctx context.Context, pods []corev1.Pod,
	apiOK, workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkDiskBloat, "gated").Inc()
		return
	}
	var st unix.Statfs_t
	used := -1.0
	if err := h.cfg.statfsFn(h.cfg.K0sDataDir, &st); err == nil &&
		st.Blocks > 0 && st.Bavail <= st.Blocks {
		used = float64(st.Blocks-st.Bavail) / float64(st.Blocks)
	}
	if used < 0 {
		// statfs failed or returned garbage — inconclusive; keep
		// the latch like a failed probe.
		h.cycles.WithLabelValues(checkDiskBloat, "abort").Inc()
		return
	}
	if used <= h.cfg.K0sDiskBloatWatermark {
		h.stateExit("disk-bloat")
		h.cycles.WithLabelValues(checkDiskBloat, "ok").Inc()
		return
	}
	// The walk is IO on the disk that is full — at most once per
	// DiskBloatScanInterval; an existing latch persists meanwhile.
	if h.cfg.nowFn().Sub(h.lastBloatScan) < h.cfg.DiskBloatScanInterval {
		h.cycles.WithLabelValues(checkDiskBloat, "ok").Inc()
		return
	}
	h.lastBloatScan = h.cfg.nowFn()
	hits, podTotals, podByUID := h.scanBloat(pods)
	if len(hits) == 0 {
		h.stateExit("disk-bloat")
		h.cycles.WithLabelValues(checkDiskBloat, "ok").Inc()
		return
	}
	h.stateEnter("disk-bloat", fmt.Sprintf("targets=%d", len(hits)))
	for _, hit := range hits {
		// NPD contract: "ACTION disk-bloat: target=... bytes=...
		// used_pct=..." feeds DiskBloatRunaway (events.go).
		h.appendLog(fmt.Sprintf(
			"ACTION disk-bloat: target=%s bytes=%d used_pct=%.1f",
			hit.label, hit.bytes, used*100))
	}
	h.actions.WithLabelValues(checkDiskBloat, "detect").Inc()
	// Critical band: emergency-evict the largest non-system pod
	// holding more than the threshold — kube-system/node-ops are
	// never deleted by this check.
	if used <= h.cfg.K0sDiskBloatCriticalWatermark || !apiOK {
		h.cycles.WithLabelValues(checkDiskBloat, "ok").Inc()
		return
	}
	var victim *corev1.Pod
	var victimBytes int64
	for uid, total := range podTotals {
		p := podByUID[uid]
		if total <= h.cfg.DiskBloatPodThresholdBytes || p == nil ||
			p.DeletionTimestamp != nil ||
			p.Namespace == "kube-system" || p.Namespace == "node-ops" {
			continue
		}
		if victim == nil || total > victimBytes {
			victim, victimBytes = p, total
		}
	}
	if victim == nil {
		h.cycles.WithLabelValues(checkDiskBloat, "ok").Inc()
		return
	}
	if !h.rateTrySpend("last-disk-bloat-evict", diskBloatEvictInterval) {
		h.appendLog(fmt.Sprintf(
			"suspect: disk-bloat victim %s/%s bytes=%d - in evict cooldown (<15m), skip",
			victim.Namespace, victim.Name, victimBytes))
		h.cycles.WithLabelValues(checkDiskBloat, "ok").Inc()
		return
	}
	// Budget spent atomically BEFORE the delete (rate_spend parity —
	// a failed delete still consumed it).
	if err := h.cfg.Client.CoreV1().Pods(victim.Namespace).Delete(
		ctx, victim.Name, metav1.DeleteOptions{}); err != nil {
		h.appendLog(fmt.Sprintf(
			"suspect: disk-bloat evict %s/%s failed: %v",
			victim.Namespace, victim.Name, err))
	} else {
		h.appendLog(fmt.Sprintf(
			"ACTION: disk-bloat evicted pod %s/%s - emptyDir holds %d bytes, /var/lib/k0s at %.1f%%",
			victim.Namespace, victim.Name, victimBytes, used*100))
		h.actions.WithLabelValues(checkDiskBloat, "pod_evict").Inc()
	}
	h.cycles.WithLabelValues(checkDiskBloat, "ok").Inc()
}

// --- Check: d-state-storm (W7-H1) ---
// A wedged block device (btrfs/jbd2 journal), loop device
// (baggageclaim/LocalPV) or kernel mutex drops the calling process
// into D (uninterruptible sleep) — un-killable, invisible to the
// zombie storm (state Z) and the statfs stall probes (the mount
// still answers while a runc/shim sits frozen in fsync/umount).
// The check reuses the per-cycle pid sweep: every state-D process
// is counted, and the runtime-critical subset (runc, containerd*,
// k0s*, kubelet, btrfs-*, jbd2/* kernel threads) is tallied
// separately — a storm in THOSE wedges the pod lifecycle, not just
// one workload. /proc/<pid>/wchan names the kernel function holding
// the task, reported in the latch-entry ACTION line. No remedy is
// attempted (a D-state process survives SIGKILL and every service
// restart): the latch drives nodereporter's KernelHungTasks
// condition for the NHC→SNR reboot escalation path.

// procStatCommState parses /proc/<pid>/stat for comm + state — comm
// sits between the FIRST '(' and the LAST ')' (it can hold spaces
// and parens), state is the first field after that ')' (same trick
// as procStatStatePPID).
func (h *Hygiene) procStatCommState(pid int) (comm, state string, ok bool) {
	data, err := os.ReadFile(h.procFile(pid, "stat"))
	if err != nil {
		return "", "", false
	}
	s := string(data)
	i := strings.LastIndexByte(s, ')')
	open := strings.IndexByte(s, '(')
	if i < 0 || open < 0 || open > i {
		return "", "", false
	}
	f := strings.Fields(s[i+1:])
	if len(f) == 0 {
		return "", "", false
	}
	return s[open+1 : i], f[0], true
}

// procWchan returns the kernel function a task is sleeping inside —
// /proc/<pid>/wchan names it; "0" (running/not-sleeping) and
// unreadable files report "".
func (h *Hygiene) procWchan(pid int) string {
	data, err := os.ReadFile(h.procFile(pid, "wchan"))
	if err != nil {
		return ""
	}
	w := strings.TrimSpace(string(data))
	if w == "0" {
		return ""
	}
	return w
}

// dstateRuntimeComm reports whether a /proc/<pid>/stat comm belongs
// to the runtime-critical set — D-state here wedges the pod
// lifecycle (runc, containerd + containerd-shim, k0s workers,
// kubelet) or signals a hung fs journal (btrfs-*/jbd2/* kernel
// threads). Prefixes, not exact names: comm is truncated at 15
// bytes ("containerd-shim" is the shim's real comm) and jbd2
// threads embed the device (jbd2/vda1-8).
func dstateRuntimeComm(comm string) bool {
	for _, p := range []string{
		"runc", "containerd", "k0s", "kubelet", "btrfs-", "jbd2/",
	} {
		if strings.HasPrefix(comm, p) {
			return true
		}
	}
	return false
}

func (h *Hygiene) checkDStateTasks(pidsOnce func() []int, workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkDState, "gated").Inc()
		return
	}
	total, runtime := 0, 0
	// A small comm=wchan sample for the ACTION line — the kernel
	// function holding the tasks is the triage hint (umount_tree /
	// wait_transaction_locked / blk_mq_get_tag).
	wchans := make([]string, 0, 4)
	for _, pid := range pidsOnce() {
		comm, state, ok := h.procStatCommState(pid)
		if !ok || state != "D" {
			continue
		}
		total++
		if dstateRuntimeComm(comm) {
			runtime++
		}
		if len(wchans) < 4 {
			if w := h.procWchan(pid); w != "" {
				wchans = append(wchans, comm+"="+w)
			}
		}
	}
	if total < h.cfg.DStateStormThreshold && runtime < dStateRuntimeMin {
		h.dstateFails = 0
		h.stateExit("d-state-storm")
		h.cycles.WithLabelValues(checkDState, "ok").Inc()
		return
	}
	h.dstateFails++
	if h.dstateFails < h.cfg.ConsecNeeded {
		h.appendLog(fmt.Sprintf(
			"suspect: d-state-storm count=%d runtime=%d (check %d/%d)",
			total, runtime, h.dstateFails, h.cfg.ConsecNeeded))
		h.cycles.WithLabelValues(checkDState, "ok").Inc()
		return
	}
	if !h.stateExists("d-state-storm") {
		// NPD contract: nodereporter maps this line to the
		// KernelHungTasks Event + problem_counter — logged once per
		// latch entry (the !stateExists gate, checkCiliumMTU parity).
		h.appendLog(fmt.Sprintf(
			"ACTION d-state-storm: count=%d runtime=%d wchan=%s",
			total, runtime, strings.Join(wchans, ",")))
	}
	h.stateEnter("d-state-storm",
		fmt.Sprintf("count=%d runtime=%d", total, runtime))
	h.cycles.WithLabelValues(checkDState, "ok").Inc()
}

// --- Check: systemd-scopes (W7-H2) ---
// On high-churn nodes (cicd's Concourse/Tekton/Shipwright build
// pods, crashloop storms) PID 1 leaks transient
// cri-containerd-*.scope units in the failed state — they pile into
// systemd's unit hash table and every D-Bus call kubelet/containerd
// makes (sandbox create) slows from ms to seconds (kubernetes
// #104029). A 30m sweep lists the failed scopes and resets them —
// reset-failed is safe on live scopes (it only clears the failed
// bookkeeping of already-dead units).

func (h *Hygiene) checkSystemdScopes(ctx context.Context, workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkSysScopes, "gated").Inc()
		return
	}
	if h.cfg.Systemd == nil {
		h.cycles.WithLabelValues(checkSysScopes, "gated").Inc()
		return
	}
	if h.cfg.nowFn().Sub(h.lastScopeScan) < systemdScopeScanInterval {
		h.cycles.WithLabelValues(checkSysScopes, "ok").Inc()
		return
	}
	out, err := h.cfg.Systemd.Exec(ctx, "systemctl", "list-units",
		"--type=scope", "--state=failed", "--no-legend", "--plain",
		"cri-containerd-*.scope")
	if err != nil {
		// A transient systemctl/D-Bus failure is inconclusive — the
		// scan must NOT stamp (a stamped failure defers the retry a
		// full interval) and zero evidence was gathered.
		h.appendLog(fmt.Sprintf(
			"suspect: systemd-scopes list-units failed: %v (%s) — scan skipped",
			err, strings.TrimSpace(out)))
		h.cycles.WithLabelValues(checkSysScopes, "abort").Inc()
		return
	}
	h.lastScopeScan = h.cfg.nowFn()
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) > 0 &&
			strings.HasSuffix(f[0], ".scope") {
			n++
		}
	}
	if n == 0 {
		h.cycles.WithLabelValues(checkSysScopes, "ok").Inc()
		return
	}
	// NPD contract line (reset-failed evidence in the watchdog log).
	h.appendLog(fmt.Sprintf("ACTION: systemd-scopes reset-failed count=%d", n))
	if rout, rerr := h.cfg.Systemd.Exec(ctx,
		"systemctl", "reset-failed", "cri-containerd-*.scope"); rerr != nil {
		h.appendLog(fmt.Sprintf(
			"suspect: systemd-scopes reset-failed failed: %v (%s)",
			rerr, strings.TrimSpace(rout)))
	} else {
		h.actions.WithLabelValues(checkSysScopes, "reset_failed").Inc()
	}
	h.cycles.WithLabelValues(checkSysScopes, "ok").Inc()
}

// --- Check: cilium-envoy xDS NACK + node-local-dns LRP (W7-H3) ---
// Two datapath wedges that leave every healthz green:
//   - envoy rejects xDS pushes (cds/lds/rds update_rejected
//     counters climbing) — the listener accepts connections but
//     never programs new routes; Gateway API objects report
//     Accepted:True while replies 404/503.
//   - the LocalRedirectPolicy sends cluster :53 to the local
//     node-local-dns pod whose UDP/TCP :53 listener is hung while
//     its :8080 healthz still answers — every pod on the node loses
//     DNS (the 8-day LRP outage shape). The API still reports the
//     pod Ready=True, so the pod itself is the remedy target.

// parseEnvoyXDSRejected sums the cds/lds/rds update_rejected
// counters out of `envoy admin /stats?filter=update_rejected` —
// lines look like "cluster_manager.cds.update_rejected: 3". A stat
// counts toward the xDS NACK total when one dotted segment is
// cds/lds/rds AND the name ends in update_rejected.
func parseEnvoyXDSRejected(body []byte) uint64 {
	var total uint64
	for _, line := range strings.Split(string(body), "\n") {
		name, val, ok := strings.Cut(line, ":")
		if !ok || !strings.HasSuffix(strings.TrimSpace(name), "update_rejected") {
			continue
		}
		match := false
		for _, seg := range strings.Split(name, ".") {
			if seg == "cds" || seg == "lds" || seg == "rds" {
				match = true
				break
			}
		}
		if !match {
			continue
		}
		if v, err := strconv.ParseUint(strings.TrimSpace(val), 10, 64); err == nil {
			total += v
		}
	}
	return total
}

// evalEnvoyXDS fetches the envoy admin update_rejected page and
// reports whether the summed reject counters GREW since the last
// successful read — the delta is the wedge signal (a node can carry
// old rejects forever; only new NACKs mean pushes are failing now).
// The first successful read only establishes the baseline.
// inconclusive=true means the page could not be evaluated — the
// caller keeps the streak untouched (a dead envoy also fails its
// /ready probe and the B1 path owns that verdict).
func (h *Hygiene) evalEnvoyXDS(ctx context.Context) (reject, inconclusive bool) {
	if h.cfg.CiliumEnvoyAdminURL == "" {
		return false, true
	}
	body, err := h.cfg.httpGetBody(ctx, h.cfg.CiliumEnvoyAdminURL, ciliumProbeTime)
	if err != nil {
		return false, true
	}
	total := parseEnvoyXDSRejected(body)
	if !h.envoyXDSInit {
		h.envoyXDSInit = true
		h.envoyXDSLast = total
		return false, false
	}
	reject = total > h.envoyXDSLast
	h.envoyXDSLast = total
	return reject, false
}

// probeDNSUDP sends one minimal A-record query to addr over UDP and
// reports whether a well-formed reply returns before the deadline —
// the node-local-dns datapath probe (W7-H3). Any reply matching the
// query id proves :53 answers: NXDOMAIN/SERVFAIL still mean the
// listener is alive; silence means the LRP datapath is wedged.
func probeDNSUDP(addr, name string, timeout time.Duration) bool {
	id := uint16(time.Now().UnixNano())
	// Header: ID, flags 0x0100 (RD), QDCOUNT=1, AN/NS/AR=0.
	q := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" {
			continue
		}
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0, 0, 1, 0, 1) // root label + QTYPE A + QCLASS IN
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(q); err != nil {
		return false
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	// ID echo + QR bit set (a response, not another query or a stray
	// datagram sharing the id).
	return err == nil && n >= 4 && buf[0] == q[0] && buf[1] == q[1] &&
		buf[2]&0x80 != 0
}

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

// checkCiliumLRPDNS probes the node-local resolver's :53 listener
// while its pod claims Ready — a hung listener inside an LRP path
// blackholes cluster DNS node-wide. Confirmed for ConsecNeeded
// consecutive cycles → delete the node-local-dns pod on this node
// (the DaemonSet respawns it with a fresh socket; last-nld-restart
// 30m budget). Only evaluated on cilium nodes (cilium_host present)
// — calico nodes serve local DNS without the LRP datapath.
func (h *Hygiene) checkCiliumLRPDNS(ctx context.Context, pods []corev1.Pod,
	apiOK, workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkCiliumLRP, "gated").Inc()
		return
	}
	if _, err := os.Stat(filepath.Join(h.cfg.SysClassNet, "cilium_host")); err != nil {
		// No cilium datapath — the LRP wedge can't exist here.
		h.nldFails = 0
		h.cycles.WithLabelValues(checkCiliumLRP, "ok").Inc()
		return
	}
	// The plan gates on cilium-agent actually running: cilium_host
	// persists while the agent is down, and a dead/wedged agent can
	// break the :53 datapath itself — killing the nld pod then would
	// mask the real failure (checkCilium owns the agent-down verdict).
	agentTasks, ctrOK := h.ciliumAgentTasks()
	if !ctrOK {
		h.cycles.WithLabelValues(checkCiliumLRP, "abort").Inc()
		return
	}
	if len(agentTasks) == 0 {
		// Agent absent/dead — datapath verdict inconclusive; the LRP
		// check stands down rather than punish a healthy pod.
		h.nldFails = 0
		h.cycles.WithLabelValues(checkCiliumLRP, "gated").Inc()
		return
	}
	if !apiOK {
		// Inconclusive — keep the streak like the other API-gated
		// checks (a LIST flake must not count or clear evidence).
		h.cycles.WithLabelValues(checkCiliumLRP, "abort").Inc()
		return
	}
	var nld *corev1.Pod
	for i := range pods {
		p := &pods[i]
		if p.Namespace == "kube-system" && nldPodRe.MatchString(p.Name) &&
			p.DeletionTimestamp == nil && p.Status.Phase == corev1.PodRunning &&
			podReady(p) {
			nld = p
			break
		}
	}
	if nld == nil {
		// No Ready node-local-dns pod → nothing owes a datapath
		// answer (not-Running/NotReady pods are kubelet's problem).
		h.nldFails = 0
		h.cycles.WithLabelValues(checkCiliumLRP, "ok").Inc()
		return
	}
	if h.cfg.dnsProbe(h.cfg.LocalDNSProbeAddr, h.cfg.LocalDNSProbeName,
		ciliumProbeTime) {
		h.nldFails = 0
		h.cycles.WithLabelValues(checkCiliumLRP, "ok").Inc()
		return
	}
	h.nldFails++
	if h.nldFails < h.cfg.ConsecNeeded {
		h.appendLog(fmt.Sprintf(
			"suspect: cilium-lrp-dns :53 probe of %s failed while %s/%s Ready=True (check %d/%d)",
			h.cfg.LocalDNSProbeAddr, nld.Namespace, nld.Name,
			h.nldFails, h.cfg.ConsecNeeded))
		h.cycles.WithLabelValues(checkCiliumLRP, "ok").Inc()
		return
	}
	if !h.rateTrySpend("last-nld-restart", h.cfg.MinRestartInterval) {
		h.appendLog(fmt.Sprintf(
			"suspect: cilium-lrp-dns :53 probe fails %dx but pod restart in cooldown (<30m), skip",
			h.nldFails))
		h.cycles.WithLabelValues(checkCiliumLRP, "ok").Inc()
		return
	}
	// Budget spent atomically BEFORE the delete (rate_spend parity).
	h.appendLog(fmt.Sprintf(
		"ACTION: cilium-lrp-dns deleted pod %s/%s - :53 probe failed %dx while Ready=True (LRP datapath wedge)",
		nld.Namespace, nld.Name, h.nldFails))
	if err := h.cfg.Client.CoreV1().Pods(nld.Namespace).Delete(ctx, nld.Name,
		metav1.DeleteOptions{GracePeriodSeconds: ptr.To[int64](0)}); err != nil {
		h.appendLog(fmt.Sprintf(
			"suspect: cilium-lrp-dns delete %s/%s failed: %v",
			nld.Namespace, nld.Name, err))
	} else {
		h.actions.WithLabelValues(checkCiliumLRP, "pod_delete").Inc()
	}
	h.nldFails = 0
	h.cycles.WithLabelValues(checkCiliumLRP, "ok").Inc()
}

// --- Check: spegel-mirror (W7-H4) ---
// Containerd's mirror config on every node points image pulls at
// the LOCAL spegel peer first. A wedged spegel pod (accepts TCP but
// stalls TLS/HTTP headers) makes PullImage eat the full per-mirror
// timeout before falling back — mass ErrImagePull exactly during a
// rollout/drain. A Ready=False spegel DaemonSet pod for
// ConsecNeeded cycles latches state-spegel-mirror-degraded and
// deletes the pod (fresh socket + fresh state; last-spegel-restart
// 30m budget). The 3m age floor keeps a just-scheduled pod from
// being deleted mid-startup.

func (h *Hygiene) checkSpegelMirror(ctx context.Context, pods []corev1.Pod,
	apiOK, workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkSpegel, "gated").Inc()
		return
	}
	if !apiOK {
		// Inconclusive — keep streak/latch exactly like teardown.
		h.cycles.WithLabelValues(checkSpegel, "abort").Inc()
		return
	}
	var sp *corev1.Pod
	for i := range pods {
		p := &pods[i]
		if (p.Namespace != "spegel" && p.Namespace != "kube-system") ||
			!spegelPodRe.MatchString(p.Name) ||
			p.DeletionTimestamp != nil ||
			p.Status.Phase != corev1.PodRunning ||
			h.cfg.nowFn().Sub(p.CreationTimestamp.Time) < spegelMinPodAge {
			continue
		}
		sp = p
		break
	}
	if sp == nil || podReady(sp) {
		// No spegel DS on this node, or the pod is healthy — either
		// way the mirror datapath isn't our problem; clear stale
		// evidence like checkCilium's no-agent path.
		h.spegelFails = 0
		h.stateExit("spegel-mirror-degraded")
		h.cycles.WithLabelValues(checkSpegel, "ok").Inc()
		return
	}
	h.spegelFails++
	if h.spegelFails < h.cfg.ConsecNeeded {
		h.appendLog(fmt.Sprintf(
			"suspect: spegel-mirror pod %s/%s Ready=False (check %d/%d)",
			sp.Namespace, sp.Name, h.spegelFails, h.cfg.ConsecNeeded))
		h.cycles.WithLabelValues(checkSpegel, "ok").Inc()
		return
	}
	h.stateEnter("spegel-mirror-degraded",
		fmt.Sprintf("pod=%s/%s ready_fails=%d", sp.Namespace, sp.Name, h.spegelFails))
	if !h.rateTrySpend("last-spegel-restart", h.cfg.MinRestartInterval) {
		h.appendLog(fmt.Sprintf(
			"suspect: spegel-mirror %s/%s Ready=False %dx but restart in cooldown (<30m), skip",
			sp.Namespace, sp.Name, h.spegelFails))
		h.cycles.WithLabelValues(checkSpegel, "ok").Inc()
		return
	}
	// Budget spent atomically BEFORE the delete (rate_spend parity).
	h.appendLog(fmt.Sprintf(
		"ACTION: spegel-mirror deleted pod %s/%s - Ready=False %dx (containerd mirror points at a wedged peer)",
		sp.Namespace, sp.Name, h.spegelFails))
	if err := h.cfg.Client.CoreV1().Pods(sp.Namespace).Delete(ctx, sp.Name,
		metav1.DeleteOptions{GracePeriodSeconds: ptr.To[int64](0)}); err != nil {
		h.appendLog(fmt.Sprintf(
			"suspect: spegel-mirror delete %s/%s failed: %v",
			sp.Namespace, sp.Name, err))
	} else {
		h.spegelFails = 0
		h.actions.WithLabelValues(checkSpegel, "pod_delete").Inc()
	}
	h.cycles.WithLabelValues(checkSpegel, "ok").Inc()
}

// --- Check: calico-hygiene (W7-H7) ---
// The cicd cluster runs Calico, not Cilium — the cilium guard
// family above is all dormant there, while calico has its own leak
// modes: orphan cali* veth pairs left by failed CNI DELs (classic
// on high-churn CI nodes) and a wedged felix datapath whose
// :9099/readiness goes dark while the pod looks Running.
//   - Check 1 (veth leak): cali* iface count > node pod count +
//     CalicoOrphanVethThreshold for ConsecNeeded cycles →
//     state-calico-veth-leak (log-only — mass veth deletion is not
//     an unattended remedy).
//   - Check 2 (felix readiness): a Running calico-node pod whose
//     :9099/readiness fails ConsecNeeded cycles →
//     state-calico-felix-down for the NHC escalation path.
// The check is dormant everywhere cilium_host exists (cilium nodes)
// and on hosts with no cali* ifaces at all (non-calico, hub nodes).

// calicoIfaceCount counts cali* interfaces under SysClassNet; -1
// when the sysfs root is unreadable (inconclusive).
func (h *Hygiene) calicoIfaceCount() int {
	entries, err := os.ReadDir(h.cfg.SysClassNet)
	if err != nil {
		return -1
	}
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "cali") {
			n++
		}
	}
	return n
}

func (h *Hygiene) checkCalicoHygiene(ctx context.Context, pods []corev1.Pod,
	apiOK, workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkCalico, "gated").Inc()
		return
	}
	if _, err := os.Stat(filepath.Join(h.cfg.SysClassNet, "cilium_host")); err == nil {
		// Cilium node — every calico verdict belongs to the cilium
		// guard family; drop stale evidence like checkCiliumWGPeers.
		h.calicoVethFails = 0
		h.calicoFelixFails = 0
		h.stateExit("calico-veth-leak")
		h.stateExit("calico-felix-down")
		h.cycles.WithLabelValues(checkCalico, "ok").Inc()
		return
	}
	cali := h.calicoIfaceCount()
	if cali <= 0 {
		// No cali* veth at all — not a calico node (unreadable
		// sysfs reports -1 the same way: nothing to verify).
		h.calicoVethFails = 0
		h.calicoFelixFails = 0
		h.stateExit("calico-veth-leak")
		h.stateExit("calico-felix-down")
		h.cycles.WithLabelValues(checkCalico, "ok").Inc()
		return
	}
	if !apiOK {
		// Pod count is the leak baseline — an API flake makes the
		// comparison invalid. Keep streaks/latches (inconclusive).
		h.cycles.WithLabelValues(checkCalico, "abort").Inc()
		return
	}
	// Check 1 — orphan veth leak.
	if cali > len(pods)+h.cfg.CalicoOrphanVethThreshold {
		h.calicoVethFails++
		if h.calicoVethFails >= h.cfg.ConsecNeeded {
			if !h.stateExists("calico-veth-leak") {
				h.appendLog(fmt.Sprintf(
					"suspect: calico-hygiene orphan veth leak cali=%d pods=%d threshold=%d — CNI DEL cleanup is leaking veth pairs",
					cali, len(pods), h.cfg.CalicoOrphanVethThreshold))
			}
			h.stateEnter("calico-veth-leak",
				fmt.Sprintf("cali=%d pods=%d", cali, len(pods)))
		} else {
			h.appendLog(fmt.Sprintf(
				"suspect: calico-hygiene veth leak candidate cali=%d pods=%d (check %d/%d)",
				cali, len(pods), h.calicoVethFails, h.cfg.ConsecNeeded))
		}
	} else {
		h.calicoVethFails = 0
		h.stateExit("calico-veth-leak")
	}
	// Check 1b — orphan-veth GC (W8-NM3): while the leak latch is
	// set, reap cali* host veths that stayed DOWN (carrier 0) for
	// calicoVethGCMinAge. Live veths always answer carrier=1; a
	// leaked one from a failed CNI DEL is DOWN forever. The
	// veth-seen-<name> marker provides the 15m age — same
	// confirm-marker shape as wedged-seen-* (a veth must not be
	// deleted on a single read: an interface mid-creation can read
	// carrier 0 for a moment).
	if h.stateExists("calico-veth-leak") {
		h.gcCalicoOrphanVeths(ctx)
	}
	// Check 2 — felix readiness, gated on a Running calico-node pod
	// on this node (no pod → nothing to probe).
	var felix *corev1.Pod
	for i := range pods {
		p := &pods[i]
		if (p.Namespace == "kube-system" || p.Namespace == "calico-system") &&
			calicoNodePodRe.MatchString(p.Name) &&
			p.DeletionTimestamp == nil && p.Status.Phase == corev1.PodRunning {
			felix = p
			break
		}
	}
	switch {
	case felix == nil || h.cfg.CalicoFelixReadyURL == "":
		h.calicoFelixFails = 0
		h.stateExit("calico-felix-down")
	default:
		code, err := h.cfg.probeHTTPStatus(ctx,
			h.cfg.CalicoFelixReadyURL, "", ciliumProbeTime)
		if err == nil && code == http.StatusOK {
			h.calicoFelixFails = 0
			h.stateExit("calico-felix-down")
			break
		}
		h.calicoFelixFails++
		if h.calicoFelixFails < h.cfg.ConsecNeeded {
			h.appendLog(fmt.Sprintf(
				"suspect: calico-felix-down readiness probe code=%d err=%v (check %d/%d)",
				code, err, h.calicoFelixFails, h.cfg.ConsecNeeded))
			break
		}
		h.stateEnter("calico-felix-down",
			fmt.Sprintf("readiness_probe_fails=%d", h.calicoFelixFails))
		// W8-NM3: a felix datapath whose readiness stayed dark
		// across calicoFelixRestartFails consecutive cycles is a
		// real wedge, not a flap — delete the calico-node pod so
		// the DaemonSet rebuilds it (last-calico-restart budget).
		if h.calicoFelixFails >= calicoFelixRestartFails {
			switch {
			case h.stateExists("node-overloaded"):
				h.appendLog(fmt.Sprintf(
					"suspect: calico-felix-down %dx but node overloaded — skip pod restart", h.calicoFelixFails))
			case !h.rateTrySpend("last-calico-restart", h.cfg.MinRestartInterval):
				h.appendLog(fmt.Sprintf(
					"suspect: calico-felix-down %dx but pod restart in cooldown (<30m), skip", h.calicoFelixFails))
			default:
				// Budget spent atomically BEFORE the delete.
				h.appendLog(fmt.Sprintf(
					"ACTION: calico-hygiene deleted pod %s/%s - felix readiness down %dx",
					felix.Namespace, felix.Name, h.calicoFelixFails))
				if derr := h.cfg.Client.CoreV1().Pods(felix.Namespace).Delete(
					ctx, felix.Name, metav1.DeleteOptions{
						GracePeriodSeconds: ptr.To[int64](0)}); derr != nil {
					h.appendLog(fmt.Sprintf(
						"suspect: calico-hygiene delete %s/%s failed: %v",
						felix.Namespace, felix.Name, derr))
				} else {
					h.actions.WithLabelValues(checkCalico, "pod_delete").Inc()
				}
			}
		}
	}
	h.cycles.WithLabelValues(checkCalico, "ok").Inc()
}

// gcCalicoOrphanVeths reaps cali* host veths that have been DOWN
// (carrier 0) for calicoVethGCMinAge — the orphans a failed CNI
// DEL leaks: they still carry iptables routes and keep the leak
// count climbing even after the latch fired. Confirmation goes
// through a veth-seen-<name> marker in the state dir (the
// wedged-seen-* pattern — a single down read is not enough: an
// iface mid-creation reads carrier 0 briefly). Markers for ifaces
// that vanished or came back up are pruned.
func (h *Hygiene) gcCalicoOrphanVeths(ctx context.Context) {
	entries, err := os.ReadDir(h.cfg.SysClassNet)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "cali") {
			continue
		}
		marker := filepath.Join(h.cfg.WatchdogStateDir, "veth-seen-"+name)
		carrier, err := os.ReadFile(filepath.Join(h.cfg.SysClassNet, name, "carrier"))
		if err != nil {
			continue // racing an iface add/remove — neither up nor down
		}
		if strings.TrimSpace(string(carrier)) != "0" {
			// Live veth — a stale marker from an earlier leak
			// episode must not carry into this one.
			_ = os.Remove(marker)
			continue
		}
		if !h.stateFileExists("veth-seen-" + name) {
			h.rateSpend("veth-seen-" + name)
			h.appendLog(fmt.Sprintf(
				"calico-hygiene: orphan veth candidate %s - carrier down, confirm in %dm",
				name, int(calicoVethGCMinAge.Minutes())))
			continue
		}
		if !h.rateOK("veth-seen-"+name, calicoVethGCMinAge) {
			continue
		}
		if h.cfg.Systemd == nil {
			h.appendLog(fmt.Sprintf(
				"suspect: calico-hygiene orphan veth %s down >%dm but no systemd client — skip delete",
				name, int(calicoVethGCMinAge.Minutes())))
			continue
		}
		out, derr := h.cfg.Systemd.Exec(ctx, "ip", "link", "delete", name)
		if derr != nil {
			h.appendLog(fmt.Sprintf(
				"suspect: calico-hygiene ip link delete %s failed: %v (%s)",
				name, derr, strings.TrimSpace(out)))
			continue
		}
		_ = os.Remove(marker)
		h.appendLog(fmt.Sprintf(
			"ACTION: calico-hygiene deleted orphan veth %s - carrier down >%dm (CNI DEL leak)",
			name, int(calicoVethGCMinAge.Minutes())))
		h.actions.WithLabelValues(checkCalico, "veth_delete").Inc()
	}
	// Prune markers for ifaces that no longer exist.
	if ms, err := filepath.Glob(
		filepath.Join(h.cfg.WatchdogStateDir, "veth-seen-*")); err == nil {
		for _, m := range ms {
			name := strings.TrimPrefix(filepath.Base(m), "veth-seen-")
			if _, err := os.Stat(filepath.Join(h.cfg.SysClassNet, name)); err != nil {
				_ = os.Remove(m)
			}
		}
	}
}

// --- Check: orphan CNI netns reaper (W9) ---
// CNI plugins pin each pod sandbox's network namespace by
// bind-mounting its nsfs file at /run/netns/cni-<id>. A pod teardown
// that dies mid-DEL (crash, OOM kill, kubelet restart) leaks the
// mount: the file outlives the namespace, and `ip netns` listings
// accumulate dead entries that confuse operators and slow CNI
// scans. The reaper stats every cni-* file — the nsfs inode is the
// namespace's identity, shared with /proc/<pid>/ns/net for every
// process still inside it — and only a file whose inode NO live
// process references is an orphan. Confirmation is the
// cni-netns-seen-<name> two-pass marker (veth-seen-* parity): first
// sighting records the epoch, and only a file still unreferenced
// >= cniNetnsMinAge later is lazily unmounted + removed. The umount
// runs through the systemd nsenter wrapper so the HOST mount
// namespace is the one modified; the file removal uses the /host
// view (NetnsDir).

// netnsInode stats a netns file and returns the nsfs inode — the
// identity /proc/<pid>/ns/net entries share for the same network
// namespace (bind-mounted copies keep the inode).
func netnsInode(path string) (uint64, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Ino, true
}

// liveNetnsInodes collects the nsfs inode of every live process's
// network namespace. Unreadable entries are skipped — a pid that
// vanished mid-scan is not a reference.
func (h *Hygiene) liveNetnsInodes(pids []int) map[uint64]bool {
	out := map[uint64]bool{}
	for _, pid := range pids {
		if ino, ok := netnsInode(h.procFile(pid, "ns", "net")); ok {
			out[ino] = true
		}
	}
	return out
}

func (h *Hygiene) checkOrphanCNINetns(ctx context.Context, pidsOnce func() []int, workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkCNINetns, "gated").Inc()
		return
	}
	entries, err := os.ReadDir(h.cfg.NetnsDir)
	if err != nil {
		if os.IsNotExist(err) {
			// No netns dir at all (non-CNI node, unmounted /run) —
			// prune stale markers and go quiet.
			h.pruneCNINetnsMarkers(nil)
			h.cycles.WithLabelValues(checkCNINetns, "ok").Inc()
			return
		}
		h.appendLog(fmt.Sprintf(
			"suspect: cni-netns-gc read %s failed: %v — scan skipped",
			h.cfg.NetnsDir, err))
		h.cycles.WithLabelValues(checkCNINetns, "abort").Inc()
		return
	}
	// Collect cni-* candidates first — the /proc ns/net stat sweep
	// only runs when there is something to check.
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "cni-") {
			continue
		}
		names = append(names, e.Name())
	}
	if len(names) == 0 {
		h.pruneCNINetnsMarkers(nil)
		h.cycles.WithLabelValues(checkCNINetns, "ok").Inc()
		return
	}
	live := h.liveNetnsInodes(pidsOnce())
	seen := map[string]bool{}
	for _, name := range names {
		seen[name] = true
		path := filepath.Join(h.cfg.NetnsDir, name)
		ino, ok := netnsInode(path)
		if !ok {
			continue // vanished or unreadable — next cycle re-reads
		}
		if live[ino] {
			// A live process still sits in this netns — the mount
			// is real. Drop any stale marker so a later orphan
			// episode re-arms the full confirmation window.
			_ = os.Remove(filepath.Join(
				h.cfg.WatchdogStateDir, "cni-netns-seen-"+name))
			continue
		}
		marker := "cni-netns-seen-" + name
		if !h.stateFileExists(marker) {
			h.rateSpend(marker)
			h.appendLog(fmt.Sprintf(
				"cni-netns-gc: orphan netns candidate %s - no live process, confirm in %dm",
				name, int(cniNetnsMinAge.Minutes())))
			continue
		}
		if !h.rateOK(marker, cniNetnsMinAge) {
			continue
		}
		// Re-stat before acting: the inode must STILL be
		// unreferenced (a process may have joined the netns since
		// the snapshot; `live` is a per-cycle map).
		ino2, ok2 := netnsInode(path)
		if !ok2 || live[ino2] {
			continue
		}
		h.reapCNINetns(ctx, name)
	}
	h.pruneCNINetnsMarkers(seen)
	h.cycles.WithLabelValues(checkCNINetns, "ok").Inc()
}

// reapCNINetns lazily unmounts the orphan netns bind-mount inside
// the HOST mount namespace, then removes the file under the /host
// view. The marker is dropped only after the umount succeeds — a
// failed umount keeps the confirmation so the next cycle retries.
func (h *Hygiene) reapCNINetns(ctx context.Context, name string) {
	if h.cfg.Systemd == nil {
		h.appendLog(fmt.Sprintf(
			"suspect: cni-netns-gc orphan netns %s confirmed but no systemd client — skip umount",
			name))
		return
	}
	// The umount path is the HOST's /run/netns — NOT NetnsDir,
	// which is the /host-prefixed filesystem view used for scans.
	out, err := h.cfg.Systemd.Exec(ctx, "umount", "-l",
		"/run/netns/"+name)
	if err != nil {
		h.appendLog(fmt.Sprintf(
			"suspect: cni-netns-gc umount /run/netns/%s failed: %v (%s) — keeping marker",
			name, err, strings.TrimSpace(out)))
		return
	}
	if rerr := os.Remove(filepath.Join(h.cfg.NetnsDir, name)); rerr != nil &&
		!os.IsNotExist(rerr) {
		// The mount IS detached — the dangerous half is done; a
		// leftover plain file re-arms as a fresh candidate next
		// cycle rather than looping a doomed umount.
		h.appendLog(fmt.Sprintf(
			"suspect: cni-netns-gc rm %s failed: %v — mount detached, file remains",
			filepath.Join(h.cfg.NetnsDir, name), rerr))
	}
	_ = os.Remove(filepath.Join(
		h.cfg.WatchdogStateDir, "cni-netns-seen-"+name))
	h.appendLog(fmt.Sprintf(
		"ACTION: cni-netns-gc reaped orphan netns %s - unmounted + removed (no live process >%dm)",
		name, int(cniNetnsMinAge.Minutes())))
	h.actions.WithLabelValues(checkCNINetns, "umount_rm").Inc()
}

// pruneCNINetnsMarkers drops cni-netns-seen-* markers whose netns
// file vanished — a file that reappeared referenced or was cleaned
// up by other means must not keep a stale confirmation armed.
func (h *Hygiene) pruneCNINetnsMarkers(seen map[string]bool) {
	ms, err := filepath.Glob(filepath.Join(
		h.cfg.WatchdogStateDir, "cni-netns-seen-*"))
	if err != nil {
		return
	}
	for _, m := range ms {
		name := strings.TrimPrefix(filepath.Base(m), "cni-netns-seen-")
		if seen != nil && seen[name] {
			continue
		}
		if _, err := os.Stat(filepath.Join(h.cfg.NetnsDir, name)); err != nil {
			_ = os.Remove(m)
		}
	}
}

// --- Check: PSI memory thrash guard (W2) ---
// When the kernel is genuinely out of memory the LAST thing that
// should die is a system daemon — but the OOM killer scores by
// oom_score, not by "this box still needs a kubelet". A sustained
// memory-full stall (PSI `full avg60` > PSIFullAvg60) together with
// real free memory under MemFreeMinRatio means the node IS
// thrashing; for ConsecNeeded consecutive cycles the
// state-psi-memory-thrash latch fires and the highest-RSS eligible
// pod is evicted through the policy/v1 Eviction API (PDB-enforced,
// last-psi-evict 15m budget) — buying back headroom before the
// kernel picks a victim of its own (k0sworker, containerd, the
// agent itself). W9 hardening: a kernel-slab-leak latch suppresses
// the eviction entirely (a kernel leak is not a pod-size problem),
// and victim selection excludes system namespaces, critical
// priority classes, terminating pods, StatefulSet database/quorum
// members, and anything under the 512 MiB RSS floor.

// psiMemoryFullAvg60 parses <ProcRoot>/pressure/memory — the
// `full avg60=` value of the memory pressure stall (percent). PSI
// files look like:
//
//	some avg10=1.23 avg60=4.56 avg300=0.78 total=12345
//	full avg10=0.89 avg60=26.10 avg300=0.54 total=6789
//
// ok=false when the file is unreadable or carries no full avg60
// (PSI disabled on this kernel — the whole check is then dormant).
func (h *Hygiene) psiMemoryFullAvg60() (float64, bool) {
	data, err := os.ReadFile(filepath.Join(h.cfg.ProcRoot, "pressure", "memory"))
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] != "full" {
			continue
		}
		for _, kv := range f[1:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok || k != "avg60" {
				continue
			}
			if x, err := strconv.ParseFloat(v, 64); err == nil {
				return x, true
			}
		}
	}
	return 0, false
}

// memInfo holds the <ProcRoot>/meminfo fields the memory checks
// consume — all values in kB as reported by the kernel.
type memInfo struct {
	totalKB     int64
	availKB     int64
	slabUnrecKB int64 // SUnreclaim — slab the kernel cannot reclaim
	parsed      bool  // at least MemTotal + MemAvailable seen
}

// readMeminfo parses <ProcRoot>/meminfo once for every consumer —
// MemTotal/MemAvailable drive the free-ratio floor, SUnreclaim the
// W9-KR3 slab-leak guard. ok=false semantics live on the callers:
// a missing MemTotal or MemAvailable means "unreadable".
func (h *Hygiene) readMeminfo() memInfo {
	var m memInfo
	data, err := os.ReadFile(filepath.Join(h.cfg.ProcRoot, "meminfo"))
	if err != nil {
		return m
	}
	var total, avail, slab int64
	var sawTotal, sawAvail bool
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			total, sawTotal = v, true
		case "MemAvailable:":
			avail, sawAvail = v, true
		case "SUnreclaim:":
			slab = v
		}
	}
	if !sawTotal || !sawAvail || total <= 0 {
		return m
	}
	m.totalKB, m.availKB, m.slabUnrecKB, m.parsed = total, avail, slab, true
	return m
}

// guardKernelSlabLeak is the W9-KR3 kernel slab-leak guard: while
// SUnreclaim/MemTotal sits above slabLeakEnterRatio the
// state-kernel-slab-leak latch is held and a 1h-budgeted
// drop_caches write ("2" — dentries+inodes) tries to hand the
// reclaimable share back. The latch is the PSI evictor's circuit
// breaker — a kernel leaking unreclaimable slab is a kernel bug,
// not a pod-size problem, and evicting workloads cannot fix it.
// Hysteresis: enter >0.35, clear <=0.25; between the two the latch
// (and its drop-caches cadence) simply persists. Returns true while
// the latch is held.
func (h *Hygiene) guardKernelSlabLeak(m memInfo) bool {
	ratio := float64(m.slabUnrecKB) / float64(m.totalKB)
	latched := h.stateExists("kernel-slab-leak")
	switch {
	case ratio > slabLeakEnterRatio:
		if !latched {
			// NPD contract parity: the ACTION line announces the
			// latch entry (nodereporter maps STATE-ENTER too).
			h.appendLog(fmt.Sprintf(
				"ACTION kernel-slab-leak: sunreclaim_ratio=%.3f sunreclaim_kb=%d memtotal_kb=%d",
				ratio, m.slabUnrecKB, m.totalKB))
		}
		latched = true
	case ratio <= slabLeakClearRatio:
		if latched {
			h.stateExit("kernel-slab-leak")
		}
		latched = false
	}
	if !latched {
		return false
	}
	// stateEnter refreshes the latch mtime every cycle it is held —
	// the janitor's 24h reap must not retire a live condition.
	h.stateEnter("kernel-slab-leak",
		fmt.Sprintf("sunreclaim_ratio=%.3f", ratio))
	if h.rateTrySpend("last-slab-drop-caches", slabDropCachesInterval) {
		h.dropKernelCaches()
	}
	return true
}

// dropKernelCaches writes "2" to <ProcRoot>/sys/vm/drop_caches —
// frees dentries/inodes/slab caches. Best-effort: a write failure
// is logged suspect and never counted as an action — the budget
// marker is already spent either way (rate_spend parity).
func (h *Hygiene) dropKernelCaches() {
	p := filepath.Join(h.cfg.ProcRoot, "sys", "vm", "drop_caches")
	if err := os.WriteFile(p, []byte("2\n"), 0o644); err != nil {
		h.appendLog(fmt.Sprintf(
			"suspect: kernel-slab-leak drop_caches write %s failed: %v",
			p, err))
		return
	}
	h.appendLog("ACTION: kernel-slab-leak wrote 2 to sys/vm/drop_caches")
	h.actions.WithLabelValues(checkPSIThrash, "drop_caches").Inc()
}

// procRSS reads /proc/<pid>/status VmRSS in bytes — the resident
// footprint used to rank eviction victims.
func (h *Hygiene) procRSS(pid int) int64 {
	data, err := os.ReadFile(h.procFile(pid, "status"))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		f := strings.Fields(line)
		if len(f) >= 2 {
			if kb, err := strconv.ParseInt(f[1], 10, 64); err == nil {
				return kb << 10 // VmRSS is reported in kB
			}
		}
	}
	return 0
}

// psiEvictExcludedNamespaces are namespaces the PSI evictor never
// touches — system daemons, CNI/mesh control planes, storage
// operators, cert/secrets plumbing, the flux delivery layer and the
// database quorum namespaces. Evicting from these under memory
// pressure removes the very components needed to recover.
var psiEvictExcludedNamespaces = map[string]bool{
	"kube-system":      true,
	"node-ops":         true,
	"medik8s":          true,
	"cilium":           true,
	"linkerd":          true,
	"linkerd-cni":      true,
	"openebs":          true,
	"cert-manager":     true,
	"external-secrets": true,
	"operators":        true,
	"everest-system":   true,
	"scylla":           true,
	"scylla-manager":   true,
	"flux-system":      true,
}

// psiEvictCriticalPriorityClasses — pods the scheduler marked
// untouchable; evicting them fights the cluster's own guarantees.
var psiEvictCriticalPriorityClasses = map[string]bool{
	"system-node-critical":    true,
	"system-cluster-critical": true,
}

// dbQuorumTokens mark StatefulSet-owned pods carrying database /
// quorum state — losing one replica under memory pressure can cost
// quorum, far worse than the memory it frees. Matched
// case-insensitively against label keys AND values.
var dbQuorumTokens = []string{
	"scylla", "dragonfly", "rabbitmq", "pxc", "psmdb", "postgresql",
}

// minEvictRSSBytes is the victim floor — below 512 MiB RSS a pod is
// not worth an eviction: the API churn + PDB slot buys back almost
// nothing while the thrash persists.
const minEvictRSSBytes = 512 * 1024 * 1024

// ownedByStatefulSet reports whether any ownerReference is a
// StatefulSet — the tiering hint for victim preference.
func ownedByStatefulSet(p *corev1.Pod) bool {
	for _, ref := range p.OwnerReferences {
		if ref.Kind == "StatefulSet" {
			return true
		}
	}
	return false
}

// carriesDBQuorumLabel reports whether the pod's labels name a
// database/quorum workload (dbQuorumTokens, case-insensitive over
// keys and values).
func carriesDBQuorumLabel(p *corev1.Pod) bool {
	for k, v := range p.Labels {
		lk, lv := strings.ToLower(k), strings.ToLower(v)
		for _, tok := range dbQuorumTokens {
			if strings.Contains(lk, tok) || strings.Contains(lv, tok) {
				return true
			}
		}
	}
	return false
}

// highestRSSPod returns the eviction victim for the
// psi-memory-thrash guard: the eligible non-system pod on this node
// whose summed /proc VmRSS is largest, subject to the W8-W1 safety
// rails —
//
//   - minEvictRSSBytes floor: no candidate >= 512 MiB RSS → no
//     eviction at all (victim=nil).
//   - psiEvictExcludedNamespaces + critical priority classes are
//     never candidates.
//   - StatefulSet pods carrying database/quorum labels are never
//     candidates (quorum loss >> memory freed).
//   - Tiered pick: BestEffort/Burstable pods NOT owned by a
//     StatefulSet are preferred; Guaranteed pods and other
//     StatefulSet pods are the fallback tier — evicting them is
//     still better than letting the kernel OOM killer choose.
//
// Pids are attributed to pods via the same /proc/<pid>/cgroup uid
// extraction the zombie check uses.
func (h *Hygiene) highestRSSPod(pods []corev1.Pod, pids []int) (victim *corev1.Pod, rss int64) {
	type candidate struct {
		pod       *corev1.Pod
		rss       int64
		preferred bool // Burstable/BestEffort && !StatefulSet-owned
	}
	byUID := map[string]*candidate{}
	for i := range pods {
		p := &pods[i]
		if p.DeletionTimestamp != nil || psiEvictExcludedNamespaces[p.Namespace] ||
			psiEvictCriticalPriorityClasses[p.Spec.PriorityClassName] ||
			(ownedByStatefulSet(p) && carriesDBQuorumLabel(p)) {
			continue
		}
		byUID[string(p.UID)] = &candidate{
			pod: p,
			// Guaranteed QoS (or empty — the API always sets the
			// class on real pods; empty only shows in tests) is
			// never "preferred" — empty stays preferred because a
			// fake/legacy pod without the class is not provably
			// Guaranteed.
			preferred: p.Status.QOSClass != corev1.PodQOSGuaranteed &&
				!ownedByStatefulSet(p),
		}
	}
	if len(byUID) == 0 || len(pids) == 0 {
		return nil, 0
	}
	for _, pid := range pids {
		uid := h.podUIDForPID(pid)
		if uid == "unknown" {
			continue
		}
		if c, ok := byUID[uid]; ok {
			c.rss += h.procRSS(pid)
		}
	}
	// Tiered selection: preferred candidates first; only when none
	// clears the RSS floor does the fallback tier compete.
	for _, wantPreferred := range []bool{true, false} {
		var best *candidate
		for _, c := range byUID {
			if c.preferred != wantPreferred || c.rss < minEvictRSSBytes {
				continue
			}
			if best == nil || c.rss > best.rss {
				best = c
			}
		}
		if best != nil {
			return best.pod, best.rss
		}
	}
	return nil, 0
}

func (h *Hygiene) checkPSIThrash(ctx context.Context, pods []corev1.Pod,
	apiOK bool, pidsOnce func() []int, workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkPSIThrash, "gated").Inc()
		return
	}
	avg60, psiOK := h.psiMemoryFullAvg60()
	m := h.readMeminfo()
	if !m.parsed {
		// meminfo unreadable — inconclusive, keep streak/latch
		// exactly like a failed probe (a transient read error must
		// not clear a live latch).
		h.cycles.WithLabelValues(checkPSIThrash, "abort").Inc()
		return
	}
	// W9-KR3: the slab-leak guard runs on EVERY readable-meminfo
	// cycle — its latch is this check's eviction circuit breaker,
	// and it must arm even on kernels without PSI or while PSI is
	// quiet (a kernel slab leak is a kernel problem, not a PSI one).
	slabLeaking := h.guardKernelSlabLeak(m)
	if !psiOK {
		// PSI disabled on this kernel — the whole thrash check is
		// dormant, but the slab guard above still evaluated.
		h.cycles.WithLabelValues(checkPSIThrash, "abort").Inc()
		return
	}
	free := float64(m.availKB) / float64(m.totalKB)
	thrash := avg60 > h.cfg.PSIFullAvg60 && free < h.cfg.MemFreeMinRatio
	if !thrash {
		h.psiThrashFails = 0
		h.stateExit("psi-memory-thrash")
		h.cycles.WithLabelValues(checkPSIThrash, "ok").Inc()
		return
	}
	h.psiThrashFails++
	if h.psiThrashFails < h.cfg.ConsecNeeded {
		h.appendLog(fmt.Sprintf(
			"suspect: psi-memory-thrash psi_full_avg60=%.1f mem_free=%.3f (check %d/%d)",
			avg60, free, h.psiThrashFails, h.cfg.ConsecNeeded))
		h.cycles.WithLabelValues(checkPSIThrash, "ok").Inc()
		return
	}
	if !h.stateExists("psi-memory-thrash") {
		// NPD contract: nodereporter maps this line to the
		// NodeMemoryPSIThrashing Event + problem_counter — logged
		// once per latch entry (checkCiliumMTU parity).
		h.appendLog(fmt.Sprintf(
			"ACTION psi-memory-thrash: psi_full_avg60=%.1f mem_free=%.3f fails=%d",
			avg60, free, h.psiThrashFails))
	}
	h.stateEnter("psi-memory-thrash",
		fmt.Sprintf("psi_full_avg60=%.1f mem_free=%.3f", avg60, free))
	if !apiOK {
		h.appendLog("suspect: psi-memory-thrash but API unreachable — skip pod evict")
		h.cycles.WithLabelValues(checkPSIThrash, "ok").Inc()
		return
	}
	if slabLeaking {
		// The kernel is leaking unreclaimable slab — evicting a
		// pod cannot fix that and would only remove capacity the
		// node needs to recover. drop_caches owns the reclaim;
		// the latch stays so the condition remains visible.
		h.appendLog("suspect: psi-memory-thrash pod evict suppressed - kernel-slab-leak latched")
		h.cycles.WithLabelValues(checkPSIThrash, "ok").Inc()
		return
	}
	victim, rss := h.highestRSSPod(pods, pidsOnce())
	if victim == nil {
		// No eligible victim above the RSS floor — latch only;
		// the kernel OOM verdict then stands (nothing ours worth
		// giving it).
		h.cycles.WithLabelValues(checkPSIThrash, "ok").Inc()
		return
	}
	if !h.rateTrySpend("last-psi-evict", psiEvictInterval) {
		h.appendLog(fmt.Sprintf(
			"suspect: psi-memory-thrash victim %s/%s rss=%d - in evict cooldown (<15m), skip",
			victim.Namespace, victim.Name, rss))
		h.cycles.WithLabelValues(checkPSIThrash, "ok").Inc()
		return
	}
	// Budget spent atomically BEFORE the eviction (rate_spend
	// parity). policy/v1 Eviction — NOT a raw pod delete: the
	// apiserver enforces the victim's PodDisruptionBudget
	// atomically, so a PDB-protected pod is refused instead of
	// silently disrupted.
	ev := &policyv1.Eviction{
		ObjectMeta: metav1.ObjectMeta{
			Name:      victim.Name,
			Namespace: victim.Namespace,
		},
	}
	h.appendLog(fmt.Sprintf(
		"ACTION: psi-memory-thrash evicted pod %s/%s - rss=%d bytes, psi_full_avg60=%.1f mem_free=%.3f",
		victim.Namespace, victim.Name, rss, avg60, free))
	if err := h.cfg.Client.PolicyV1().Evictions(victim.Namespace).
		Evict(ctx, ev); err != nil {
		h.appendLog(fmt.Sprintf(
			"suspect: psi-memory-thrash evict %s/%s failed: %v",
			victim.Namespace, victim.Name, err))
	} else {
		h.actions.WithLabelValues(checkPSIThrash, "pod_evict").Inc()
	}
	h.cycles.WithLabelValues(checkPSIThrash, "ok").Inc()
}
