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
	CheckCiliumWG    = "cilium-wg-peers"    // W5.6
	CheckDiskBloat   = "disk-bloat"         // W6.3
	CheckDState      = "d-state-storm"      // W7-H1
	CheckSysScopes   = "systemd-scopes"     // W7-H2
	CheckCiliumLRP   = "cilium-lrp-dns"     // W7-H3
	CheckSpegel      = "spegel-mirror"      // W7-H4
	CheckCalico      = "calico-hygiene"     // W7-H7
	CheckCiliumBPF   = "cilium-bpf-maps"    // W8-NM3 (inside CheckCilium)
	CheckPSIThrash   = "psi-memory-thrash"  // W2
	CheckCNINetns    = "cni-netns-gc"       // W9 orphan /run/netns/cni-* reaper
	CheckCtrMeta     = "containerd-meta"    // W10-KR3 meta.db corruption + orphan shims
	CheckHostOOM     = "host-oom"           // W10-KR1 SystemOOMVictim event + metric
	CheckOrphanHP    = "orphan-hostpath"    // W10-ST2 orphaned pvc-* hostPath dirs
	// Runtime-resource guards (runtime package).
	CheckCgroupDying       = "cgroup-dying-reclaim"        // nr_dying_descendants reclaim
	CheckSystemdSessions   = "systemd-session-hygiene"     // logind session janitor
	CheckOverlayFSStale    = "overlayfs-stale-mount"       // ESTALE/lowerdir image healer
	CheckIOPressure        = "io-pressure-throttler"       // diskstats + PSI io throttler
	CheckConntrackLiberal  = "conntrack-tcp-liberal-guard" // neb1 be_liberal fixer
	CheckClockJump         = "clock-jump-session-healer"   // konn pod recreate after step
	CheckUnlinkedOpenFiles = "unlinked-open-files"         // deleted-but-open fd space guard
	CheckCgroupSwap        = "cgroup-swap-leak"            // kubepods memory.swap leak cap
	CheckCgroupThrottle    = "cgroup-pod-throttle"         // W12-KR1 pod memory.high + pids.max
	CheckSubprocOOM        = "container-subproc-oom"       // subproc-oom living-dead OOM detector
	CheckSATokenTTL        = "sa-token-ttl"                // sa-token-ttl projected SA token expiry guard
	CheckKernelNetShim     = "kernel-net-shim-hygiene"     // kernel drops + containerd shim RSS guard
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
	Pods         []corev1.Pod
	APIOK        bool
	WorkerActive bool
	TasksOnce    func() (map[string][]CtrTask, bool)
	PidsOnce     func() []int
	JournalOnce  func() string
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
