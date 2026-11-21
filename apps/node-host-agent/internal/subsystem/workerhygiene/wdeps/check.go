// check.go — the Check contract the parent orchestrator dispatches
// and every domain check implements, plus the check-name table: the
// prometheus `check` label values AND the WD_SIG_<NAME> kill-switch
// keys. The names are byte-identical to the pre-split constants —
// they are the one canonical definition; parent aliases exist only
// for the test surface.
package wdeps

import (
	"context"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
)

// Check names — prometheus `check` label + log context + WD_SIG key.
const (
	CheckTeardown    = "pod-teardown"
	CheckKonn        = "konnectivity"
	CheckDNS         = "dns-resolv"
	CheckStall       = "kubelet-stall"
	CheckWatch       = "kubelet-watch-wedge"
	CheckCtrTasks    = "ctr-tasks"
	CheckCilium      = "cilium"
	CheckCiliumInit  = "cilium-init-stuck"
	CheckCtrImages   = "ctr-image-healer"   // 37
	CheckCiliumIPAM  = "cilium-ipam"        // 38
	CheckKubeletWd   = "kubelet-watchdog"   // T15 feeder + remediate
	CheckSyncloop    = "kubelet-syncloop"   // A4 PLEG probe
	CheckCtrSock     = "containerd-sock"    // A4 socket hang probe
	CheckIngestGC    = "ctr-ingest-gc"      // 39 (A3)
	CheckZombieStorm = "zombie-storm"       // A2
	CheckJournald    = "journald-integrity" // A5
	CheckCiliumEnvoy = "cilium-envoy"       // B1
	CheckCiliumMTU   = "cilium-mtu"         // B4
	CheckCiliumWG    = "cilium-wg-peers"    // cilium-wg-peer-gc
	CheckDiskBloat   = "disk-bloat"
	// Disk side-guards — each its own check so WD_SIG_<NAME> and
	// cycles{check,result} can gate/report them independently.
	CheckRunTmpfs      = "run-tmpfs-guard"
	CheckDevShm        = "dev-shm"
	CheckLocalPVQuota  = "localpv-quota"
	CheckCoredumpGC    = "coredump-gc"
	CheckWritableLayer = "writable-layer-scan"
	CheckDState        = "d-state-storm"
	CheckPipeWrite     = "pipe-write-freeze" // container stdout 64KB pipe deadlock detector (A1)
	CheckSysScopes     = "systemd-scopes"
	CheckCiliumLRP     = "cilium-lrp-dns" // envoy-xds-lrp
	CheckSpegel        = "spegel-mirror"
	CheckCalico        = "calico-hygiene"
	CheckCiliumBPF     = "cilium-bpf-maps" // mesh-net-guards (inside CheckCilium)
	CheckPSIThrash     = "psi-memory-thrash"
	CheckCNINetns      = "cni-netns-gc"    // orphan /run/netns/cni-* reaper
	CheckCtrMeta       = "containerd-meta" // meta-db-corruption meta.db corruption + orphan shims
	CheckHostOOM       = "host-oom"        // kernel-dmesg SystemOOMVictim event + metric
	CheckOrphanHP      = "orphan-hostpath" // orphan-hostpath orphaned pvc-* hostPath dirs
	// Runtime-resource guards (runtime package).
	CheckCgroupDying       = "cgroup-dying-reclaim"        // nr_dying_descendants reclaim
	CheckSystemdSessions   = "systemd-session-hygiene"     // logind session janitor
	CheckOverlayFSStale    = "overlayfs-stale-mount"       // ESTALE/lowerdir image healer
	CheckIOPressure        = "io-pressure-throttler"       // diskstats + PSI io throttler
	CheckConntrackLiberal  = "conntrack-tcp-liberal-guard" // neb1 be_liberal fixer
	CheckClockJump         = "clock-jump-session-healer"   // konn pod recreate after step
	CheckUnlinkedOpenFiles = "unlinked-open-files"         // deleted-but-open fd space guard
	CheckCgroupSwap        = "cgroup-swap-leak"            // kubepods memory.swap leak cap
	CheckCgroupThrottle    = "cgroup-pod-throttle"         // cgroup-pod-throttle pod memory.high + pids.max
	CheckSubprocOOM        = "container-subproc-oom"       // subproc-oom living-dead OOM detector
	CheckSATokenTTL        = "sa-token-ttl"                // sa-token-ttl projected SA token expiry guard
	CheckKernelNetShim     = "kernel-net-shim-hygiene"     // kernel drops + containerd shim RSS guard
	CheckMountinfo         = "mountinfo-hygiene"           // mountinfo bloat + orphan mount reaper
	// Self-healing wave (appended after the pre-existing checks —
	// order is load-bearing).
	CheckInotifyHygiene = "inotify-pressure-hygiene" // inotify instance/watch pressure + runaway-pod evictor
	CheckOrphanPodVols  = "orphan-pod-volumes"       // orphaned kubelet pod volume dirs

	// Wave-2 self-healing guards — appended at the tail so the 50
	// existing check labels (metric `check` values + WD_SIG keys)
	// keep their dispatch order.
	CheckEphemeralPorts = "ephemeral-port-pressure" // P0.3 netlink sock-diag port/ CLOSE_WAIT guard
	CheckHungRunc       = "hung-runc-reaper"        // P1.5 hung OCI runtime reaper
	CheckCSIGuard       = "csi-registration-guard"  // P1.6 CSI plugins_registry healer
	CheckGPUGuard       = "gpu-pcie-guard"          // P2.12 GPU PCIe/device-plugin desync guard
	CheckNetfilterGuard = "netfilter-guard"         // P2.11 xtables lock + hung cmd guard

	// Wave-3 self-healing guards — appended at the tail so the existing
	// check labels keep their dispatch order.
	CheckUDPStale = "udp-stale-socket" // #3 connected-UDP dead-backend socket destroyer

	// Wave-4 self-healing guards — appended at the tail so the existing
	// check labels keep their dispatch order.
	CheckKubeletCert      = "kubelet-cert"       // #4 worker kubelet serving cert expiry & :10250 reload drift
	CheckCiliumFQDN       = "cilium-fqdn"        // #5A Cilium toFQDNs DNS-proxy & endpoint regen guard (detect-only)
	CheckSystemdOOMD      = "systemd-oomd"       // #9 systemd-oomd pod/k0s slice kill guard (detect-only)
	CheckNetworkMountHung = "network-mount-hung" // #10 hung NFS/CIFS/FUSE/CephFS mount statfs subprocess guard
)

// CycleEnv is the per-cycle shared context Cycle hands to every
// Check: the node-pod LIST + apiserver reachability verdict, the
// k0sworker active gate (WD_REQUIRES: k0sworker — a worker that is
// intentionally down skips every check), and the lazy
// once-per-cycle snapshots the checks share — the containerd task
// map, the /proc pid sweep and the k0sworker journal window — so
// each stays built at most once per cycle, only when a check
// actually pulls it. All fields are read-only to the checks; the
// once-funcs are idempotent.
type CycleEnv struct {
	Pods            []corev1.Pod
	APIOK           bool
	WorkerActive    bool
	SystemdProbeErr bool
	TasksOnce       func() (map[string][]CtrTask, bool)
	PidsOnce        func() []int
	// PidsOK reports whether the preceding PidsOnce call's underlying
	// Proc.PIDs() succeeded (false = Proc.PIDs() returned an error,
	// distinct from a genuinely empty /proc returning nil, nil). Callers
	// must invoke PidsOnce() before reading PidsOK(). Nil in hand-built
	// envs → callers treat PidsOnce as error-free.
	PidsOK      func() bool
	JournalOnce func() string
	// JournalOK reports whether the preceding JournalOnce call's
	// underlying JournalFn succeeded (false on ClassFailed or
	// ClassFilesGone; true on ClassOK or ClassEmpty). Nil in
	// hand-built envs → callers treat JournalOnce as error-free.
	JournalOK func() bool
	// StatsOnce memoizes the per-pid /proc/<pid>/stat parse for the
	// whole cycle — ZombieStormCheck and DstateCheck each used to
	// read+parse every pid's stat back-to-back. The map holds only
	// successfully parsed stats; a missing pid reads as the same
	// ok=false the direct Stat call gave. Nil in hand-built envs →
	// checks fall back to per-pid d.Proc.Stat.
	StatsOnce func() map[int]procfs.Stat
	// MountinfoOnce memoizes reading Cfg.MountinfoFile per cycle so
	// mountinfo-hygiene, writable-layer-scan, disk-bloat, and
	// orphan-pod-volumes share one read. Nil in hand-built envs →
	// Deps.ReadMountinfo falls back to an uncached os.ReadFile.
	MountinfoOnce func() ([]byte, error)
	// CiliumHealthzOnce memoizes GET /v1/healthz over the cilium
	// socket per cycle so cilium-ipam, cilium-envoy, and
	// cilium-wg-peers share one socket probe. Nil in hand-built envs →
	// Deps.CiliumHealthz falls back to an uncached UnixGet.
	CiliumHealthzOnce func(context.Context) ([]byte, error)
	// WalkOnce memoizes WalkBytes per cycle — the disk-bloat scan
	// and the writable-layer scan walk the same snapshot/pod-volume
	// dirs in one cycle; the cache makes the IO-bounded walk run at
	// most once per path per cycle. Nil in tests → direct walks.
	// PRODUCTION leaves this nil: Cycle refreshes no closure here,
	// and the memoization + per-cycle entry budget live in
	// Deps.WalkBudgeted (walkCache/walkSpent below) next to
	// WalkBytes. A non-nil WalkOnce is the unit-test stub path —
	// WalkBudgeted delegates to it verbatim, bypassing the budget.
	WalkOnce func(root string) (total int64, truncated bool)

	// walkCache and walkSpent back Deps.WalkBudgeted: per-root
	// memoized sizings and the cumulative entries walked this
	// cycle against wdeps.MaxBloatScanEntries. Unexported — every
	// consumer goes through WalkBudgeted; hand-built envs start
	// zeroed and the cache map is created lazily on first use.
	walkCache map[string]walkResult
	walkSpent int

	podByUID map[string]*corev1.Pod
}

// PodByUID returns a lazy-cached map from pod UID string to *corev1.Pod
// over e.Pods.
func (e *CycleEnv) PodByUID() map[string]*corev1.Pod {
	if e.podByUID == nil {
		e.podByUID = make(map[string]*corev1.Pod, len(e.Pods))
		for i := range e.Pods {
			e.podByUID[string(e.Pods[i].UID)] = &e.Pods[i]
		}
	}
	return e.podByUID
}

// Check is one hygiene probe+remedy pair. Name() is the prometheus
// `check` label AND the WD_SIG_<NAME> kill-switch key — it must
// equal the Check* constant the counters/logs already use so latch
// names, metric label values and log lines stay identical. Run
// executes one round: implementations reach the shared seams
// (kube client, procfs view, state store, metrics, cfg knobs)
// through their *Deps (deps.go — the check-facing dependency
// surface) and own their own streak/latch bookkeeping.
type Check interface {
	Name() string
	Run(ctx context.Context, e *CycleEnv)
}
