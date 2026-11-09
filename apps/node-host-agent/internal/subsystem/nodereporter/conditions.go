// Condition evaluation + node status patching.
//
// The mapping table is a 1:1 port of the removed NPD
// watchdog-state-monitor.json (custom plugin): Type, default
// Reason/Message, permanent-rule problem Reason and the state-<key>
// latch file the check script probed. WatchdogStale is the special
// one — check-watchdog-fresh.sh gated on the `installed` marker and
// compared `last-run` age to 1200s.
package nodereporter

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

// conditionDef is one permanent NodeCondition — 1:1 with a
// conditions[] + permanent rules[] pair of the removed
// watchdog-state-monitor.json.
type conditionDef struct {
	typ            corev1.NodeConditionType
	defaultReason  string
	defaultMessage string
	problemReason  string
	stateKey       string // latch file state-<stateKey>; "" = special probe
	// altStateKeys are optional extra latches that trip the same
	// condition — the T15 kubelet watchdog's state-kubelet-healthz-down
	// (restart budget exhausted) and the A4 probes'
	// state-kubelet-syncloop-down / state-containerd-sock-down must
	// all fire KubeletRuntimeStall so the existing NHC
	// k0sworker-remediate-exhausted rule keeps working (BUG-H4).
	altStateKeys []string
}

// conditionDefs is the watchdog-condition table ported from the NPD
// JSON — order preserved so rendered status.conditions stays stable —
// plus agent-added entries at the tail (JournaldUnreadable, the infra and leak-pressure
// latch→condition surfaces and the workerhygiene cilium MTU/WG
// latches). Every typ is a nodecond constant — single source of
// truth for the condition names.
var conditionDefs = []conditionDef{
	{
		typ:            nodecond.NodeOverloaded,
		defaultReason:  "NodeLoadNormal",
		defaultMessage: "node not overloaded (load15 <= 4xCPU)",
		problemReason:  "NodeOverloadedDetected",
		stateKey:       latchdefs.LatchNodeOverloaded,
	},
	{
		typ:            nodecond.WatchdogStale,
		defaultReason:  "WatchdogFresh",
		defaultMessage: "node-watchdog ran recently (last-run < 20 min)",
		problemReason:  "WatchdogStaleDetected",
		// no stateKey — evaluated by watchdogStale() from installed/last-run
	},
	{
		typ:            nodecond.CiliumAgentDown,
		defaultReason:  "CiliumAgentUp",
		defaultMessage: "cilium-agent healthz OK",
		problemReason:  "CiliumAgentDownDetected",
		stateKey:       latchdefs.LatchCiliumAgentDown,
	},
	{
		typ:            nodecond.CiliumInitStuck,
		defaultReason:  "CiliumEndpointsReady",
		defaultMessage: "no cilium endpoint stuck in init (informer healthy)",
		problemReason:  "CiliumInitStuckDetected",
		stateKey:       latchdefs.LatchCiliumInitStuck,
	},
	{
		typ:            nodecond.KubeletRuntimeStall,
		defaultReason:  "KubeletRuntimeOk",
		defaultMessage: "no phantom-pods wedge (ctr alive, tasks > 0)",
		problemReason:  "KubeletRuntimeStallDetected",
		stateKey:       latchdefs.LatchKubeletRuntimeStall,
		// BUG-H4: the PLEG/syncloop freeze and the hung containerd
		// socket are runtime stalls too — every latch must light
		// the condition. kubelet-watch-wedge adds the kubelet watch-stream wedge
		// and the containerd meta.db corruption latch (restart can't
		// recover a corrupt store — same remediation class).
		altStateKeys: []string{
			latchdefs.LatchKubeletHealthzDown,
			latchdefs.LatchKubeletSyncloopDown,
			latchdefs.LatchContainerdSockDown,
			latchdefs.LatchKubeletWatchWedge,
			latchdefs.LatchContainerdCorrupt,
		},
	},
	{
		typ:            nodecond.DNSFallbackActive,
		defaultReason:  "DnsDirectOk",
		defaultMessage: "DNS via resolv.conf healthy, no /etc/hosts pin",
		problemReason:  "DnsFallbackEngaged",
		stateKey:       latchdefs.LatchDNSFallback,
	},
	{
		typ:            nodecond.DNSResolvStale,
		defaultReason:  "DnsResolvFresh",
		defaultMessage: "DNS pods (nld/coredns) resolv.conf matches host",
		problemReason:  "DnsResolvStaleDetected",
		stateKey:       latchdefs.LatchDNSResolvStale,
	},
	{
		typ:            nodecond.PodTeardownWedged,
		defaultReason:  "PodTeardownOk",
		defaultMessage: "no long-Terminating pod with leftover task",
		problemReason:  "PodTeardownWedgedDetected",
		stateKey:       latchdefs.LatchPodTeardownWedged,
	},
	{
		typ:            nodecond.KubeletWatchWedge,
		defaultReason:  "KubeletWatchOk",
		defaultMessage: "kubelet receives pod assignment normally (no unseen pod)",
		problemReason:  "KubeletWatchWedgeDetected",
		stateKey:       latchdefs.LatchKubeletWatchWedge,
	},
	{
		// Agent-added (not in the NPD JSON): the journalwatch
		// tracker's blindness latch — journald installed but every
		// journal read produces nothing, so all journal-grep checks
		// and this reporter's own journal monitors are blind.
		typ:            nodecond.JournaldUnreadable,
		defaultReason:  "JournaldReadable",
		defaultMessage: "journald journal reads return entries",
		problemReason:  "JournaldUnreadableDetected",
		stateKey:       latchdefs.LatchJournalUnreadable,
	},
	{
		// Agent-added (filesystem-readonly): hostmetrics' statfs probes found a
		// mount reporting ST_RDONLY — the fs remounted read-only
		// (kernel error path) and every write on it silently fails.
		// updateFSReadonlyEvidence/checkKernelDmesg: the same condition also trips on the
		// state-fs-readonly evidence latch — a PVC backing mount
		// found ro in /proc/1/mounts or a fresh kernel fs-error
		// record, before statfs ever sees ST_RDONLY.
		typ:            nodecond.FilesystemReadOnly,
		defaultReason:  "FilesystemReadWrite",
		defaultMessage: "all probed filesystems are read-write",
		problemReason:  "FilesystemReadOnlyDetected",
		stateKey:       latchdefs.LatchFilesystemReadonly,
		altStateKeys:   []string{latchdefs.LatchFSReadonly},
	},
	{
		// Agent-added (d-state-storm): workerhygiene's D-state storm
		// detector — >=5 tasks (or >=2 runtime-critical) stuck in
		// uninterruptible sleep means a hung kernel IO path no
		// service restart can clear; NHC→SNR owns the remedy.
		typ:            nodecond.KernelHungTasks,
		defaultReason:  "KernelTasksRunOk",
		defaultMessage: "no D-state task storm (uninterruptible sleep below threshold)",
		problemReason:  "KernelHungTasksDetected",
		stateKey:       latchdefs.LatchDStateStorm,
		// kernel-softlockup-monitor (npd subpackage): a kmsg
		// soft-lockup/RCU-stall signature is the same hang class —
		// the kernel monitor Enters one evidence latch per
		// signature so a CPU wedged inside the kernel raises
		// KernelHungTasks even when no D-state storm is counted.
		altStateKeys: []string{
			latchdefs.LatchKernelSoftLockup, latchdefs.LatchKernelRCUStall,
		},
	},
	// --- infra latch→condition surface ---
	// Agent-added conditions for the latches the hygiene subsystems
	// already wrote (or the infra guards add): every state-<key> below maps
	// 1:1 to a permanent NodeCondition so the NHC→SNR chain and the
	// problem_gauge series cover the full latch set.
	{
		typ:            nodecond.NebulaIsolated,
		defaultReason:  "NebulaMeshHealthy",
		defaultMessage: "all nebula peers handshake normally",
		problemReason:  "NebulaIsolatedDetected",
		stateKey:       latchdefs.LatchNebulaIsolated,
	},
	{
		typ:            nodecond.NebulaDegraded,
		defaultReason:  "NebulaDataplaneOk",
		defaultMessage: "nebula dataplane healthy (no relay/latency degradation)",
		problemReason:  "NebulaDegradedDetected",
		stateKey:       latchdefs.LatchNebulaDegraded,
	},
	{
		typ:            nodecond.CiliumEnvoyDown,
		defaultReason:  "CiliumEnvoyReady",
		defaultMessage: "cilium-envoy admin /ready OK",
		problemReason:  "CiliumEnvoyDownDetected",
		stateKey:       latchdefs.LatchCiliumEnvoyDown,
	},
	{
		typ:            nodecond.CiliumIPAMExhausted,
		defaultReason:  "CiliumIPAMOk",
		defaultMessage: "cilium IPAM pool has headroom (no address leak)",
		problemReason:  "CiliumIPAMExhaustedDetected",
		stateKey:       latchdefs.LatchCiliumIPAMExhausted,
	},
	{
		typ:            nodecond.CiliumBPFMapPressure,
		defaultReason:  "CiliumBPFMapsOk",
		defaultMessage: "critical cilium BPF maps below 90% capacity",
		problemReason:  "CiliumBPFMapPressureDetected",
		stateKey:       latchdefs.LatchCiliumBPFMapPressure,
	},
	{
		typ:            nodecond.SpegelMirrorDegraded,
		defaultReason:  "SpegelMirrorReady",
		defaultMessage: "spegel P2P mirror pod Ready",
		problemReason:  "SpegelMirrorDegradedDetected",
		stateKey:       latchdefs.LatchSpegelMirrorDegraded,
	},
	{
		typ:            nodecond.CalicoVethLeak,
		defaultReason:  "CalicoVethCountOk",
		defaultMessage: "cali* veth count matches pod count (no CNI DEL leak)",
		problemReason:  "CalicoVethLeakDetected",
		stateKey:       latchdefs.LatchCalicoVethLeak,
	},
	{
		typ:            nodecond.CalicoFelixDown,
		defaultReason:  "CalicoFelixReady",
		defaultMessage: "calico felix :9099 readiness OK",
		problemReason:  "CalicoFelixDownDetected",
		stateKey:       latchdefs.LatchCalicoFelixDown,
	},
	{
		typ:            nodecond.Fail2banDown,
		defaultReason:  "Fail2banActive",
		defaultMessage: "fail2ban service installed and active",
		problemReason:  "Fail2banDownDetected",
		stateKey:       latchdefs.LatchFail2banDown,
	},
	{
		typ:            nodecond.ConntrackPressure,
		defaultReason:  "ConntrackNormal",
		defaultMessage: "nf_conntrack table below pressure threshold",
		problemReason:  "ConntrackPressureDetected",
		stateKey:       latchdefs.LatchConntrackPressure,
	},
	{
		typ:            nodecond.KernelKeysPressure,
		defaultReason:  "KernelKeysNormal",
		defaultMessage: "kernel keyring quota below pressure threshold",
		problemReason:  "KernelKeysPressureDetected",
		stateKey:       latchdefs.LatchKernelKeysPressure,
	},
	{
		typ:            nodecond.ControlPlaneCertReloadStale,
		defaultReason:  "ControlPlaneCertReloadFresh",
		defaultMessage: "control-plane cert reload markers fresh",
		problemReason:  "ControlPlaneCertReloadStaleDetected",
		stateKey:       latchdefs.LatchCPCertReloadStale,
	},
	{
		typ:            nodecond.MemoryPSIThrashing,
		defaultReason:  "MemoryPSINormal",
		defaultMessage: "memory PSI full avg60 <= 25% or free memory >= 8%",
		problemReason:  "MemoryPSIThrashingDetected",
		stateKey:       latchdefs.LatchPSIMemoryThrash,
	},
	// --- leak-pressure latch→condition surface ---
	// Agent-added conditions for the latches the leak-pressure guards add (or the
	// H1 clock check already wrote): every state-<key> below maps
	// 1:1 to a permanent NodeCondition.
	{
		// nethealth's H1 clock-discipline latch — adjtimex reports
		// STA_UNSYNC or esterror > 500ms for ConsecNeeded cycles.
		typ:            nodecond.ClockUnsynchronized,
		defaultReason:  "ClockSynchronized",
		defaultMessage: "kernel clock disciplined (adjtimex synced, esterror <= 500ms)",
		problemReason:  "ClockUnsynchronizedDetected",
		stateKey:       latchdefs.LatchClockUnsync,
	},
	{
		// workerhygiene's kernel-slab-leak slab-leak guard — SUnreclaim above
		// 35% of MemTotal means kernel memory is leaking into
		// unreclaimable slab (dentries/inodes/slab caches that
		// drop_caches cannot fully reclaim).
		typ:            nodecond.KernelSlabLeak,
		defaultReason:  "KernelSlabNormal",
		defaultMessage: "unreclaimable kernel slab below pressure threshold",
		problemReason:  "KernelSlabLeakDetected",
		stateKey:       latchdefs.LatchKernelSlabLeak,
	},
	{
		// nethealth's overlay-mtu-guard DF PMTU probe — small-packet overlay
		// pings pass but a 1200-byte DF probe blackholes: the
		// double-encap path MTU sits below the overlay MTU.
		typ:            nodecond.NebulaPMTUBlackhole,
		defaultReason:  "NebulaPMTUOk",
		defaultMessage: "nebula overlay passes DF probes at probe size",
		problemReason:  "NebulaPMTUBlackholeDetected",
		stateKey:       latchdefs.LatchNebulaPMTUBlackhole,
	},
	// --- deep-failure latch→condition surface ---
	{
		// hostmetrics' pid-fd-pressure kernel resource exhaustion guard —
		// threads/pid or fd utilization above 0.90 for 3 consecutive
		// scrapes. PID/FD exhaustion precedes fork() failures and the
		// classic "can't start new process" node outage.
		typ:            nodecond.KernelResourceExhaustion,
		defaultReason:  "KernelResourcesNormal",
		defaultMessage: "kernel threads/pids and fd table below exhaustion threshold",
		problemReason:  "KernelResourceExhaustionDetected",
		stateKey:       latchdefs.LatchPIDFDPressure,
	},
	{
		// nethealth's clock-skew clock-skew guard — chronyc/adjtimex
		// offset above 2.0s for 5 consecutive cycles. Distinct from
		// ClockUnsynchronized: the clock HAS a sync source but sits
		// far enough off to break cert validity/raft leases.
		typ:            nodecond.ClockSkewDetected,
		defaultReason:  "ClockSkewOk",
		defaultMessage: "clock offset within 2.0s of NTP source",
		problemReason:  "ClockSkewDetected",
		stateKey:       latchdefs.LatchClockSkew,
	},
	// --- latch→condition surface: kernel/host deep-failure + hygiene ---
	// The remaining registered latches each map 1:1 to a permanent
	// NodeCondition — kubeconfig-cert-expiring from
	// controllerhygiene's cert-expiry probe, cpu-steal-pressure from
	// hostmetrics' hypervisor steal guard, cgroup-dying-leak and
	// systemd-session-bloat from workerhygiene's reclaim/session
	// hygiene checks.
	{
		// controllerhygiene's kubeconfig cert-expiry guard — an
		// embedded client cert in one of the node-daemons'
		// kubeconfigs approaching notAfter. Renewal belongs to the
		// certs pipeline, not the agent — the condition is the
		// signal channel.
		typ:            nodecond.KubeconfigCertExpiring,
		defaultReason:  "KubeconfigCertValid",
		defaultMessage: "kubeconfig client certificates valid beyond the expiry horizon",
		problemReason:  "KubeconfigCertExpiringDetected",
		stateKey:       latchdefs.LatchKubeconfigCertExpiring,
	},
	{
		// hostmetrics' cpu-steal guard — hypervisor steal time above
		// the pressure threshold for consecutive scrapes: a noisy
		// neighbour or overcommitted host starves every pod on the
		// node (token caches and leases start timing out first).
		typ:            nodecond.CPUStealPressure,
		defaultReason:  "CPUStealNormal",
		defaultMessage: "hypervisor CPU steal below pressure threshold",
		problemReason:  "CPUStealPressureDetected",
		stateKey:       latchdefs.LatchCPUStealPressure,
	},
	{
		// workerhygiene's cgroup-dying-reclaim — cgroup v2
		// nr_dying_descendants above threshold: deleted containers
		// pin page cache and slow every cgroup-tree walk (the
		// PLEG-not-healthy class).
		typ:            nodecond.CgroupDyingLeak,
		defaultReason:  "CgroupDyingNormal",
		defaultMessage: "cgroup dying descendants below pressure threshold",
		problemReason:  "CgroupDyingLeakDetected",
		stateKey:       latchdefs.LatchCgroupDyingLeak,
	},
	{
		// workerhygiene's systemd-session-hygiene — abandoned logind
		// session scopes accumulating (or D-Bus latency climbing)
		// degrades every systemctl call on the node.
		typ:            nodecond.SystemdSessionBloat,
		defaultReason:  "SystemdSessionsNormal",
		defaultMessage: "logind session count and D-Bus latency healthy",
		problemReason:  "SystemdSessionBloatDetected",
		stateKey:       latchdefs.LatchSystemdSessionBloat,
	},
	{
		// workerhygiene's kubelet-syncloop PLEG metrics guard —
		// relist latency (avg/quantile >5s) or last-seen lag >30s
		// for ConsecNeeded cycles. Early warning: PLEG is starving
		// before /healthz/syncloop ever answers 500, so NHC/SNR and
		// the runbooks see the degrade while the sync loop still
		// replies.
		typ:            nodecond.KubeletPLEGUnhealthy,
		defaultReason:  "KubeletPLEGHealthy",
		defaultMessage: "kubelet PLEG relist latency and last-seen lag healthy",
		problemReason:  "KubeletPLEGUnhealthyDetected",
		stateKey:       latchdefs.LatchKubeletPLEGUnhealthy,
	},
	// --- gray-failure latch→condition surface ---
	{
		// workerhygiene's disk-slow-io disk-slow-io gray-failure guard —
		// a whole disk whose write await stays >200ms while io PSI
		// full avg60 sits >= 25% for >=5 consecutive cycles: the
		// backing device/SAN is degrading but nothing has
		// D-stormed or remounted ro yet. Consumed cluster-side by
		// node-hang-precordon and descheduler-storm-gate to keep
		// new stateful pods off the node — deliberately NOT in any
		// SNR reboot path (a shared-storage slowdown must not
		// mass-reboot the fleet).
		typ:            nodecond.DiskSlowIO,
		defaultReason:  "DiskIONormal",
		defaultMessage: "disk write await and io PSI within normal bounds",
		problemReason:  "DiskSlowIODetected",
		stateKey:       latchdefs.LatchDiskSlowIO,
	},
	{
		// workerhygiene's kernel-net-shim-hygiene guard — sustained
		// kernel socket/softnet drop growth or a containerd-shim RSS
		// breach (individual >=200MiB or total >=1.5GiB).
		typ:            nodecond.KernelNetShimDegraded,
		defaultReason:  "KernelNetShimNormal",
		defaultMessage: "kernel socket/softnet drop rates and containerd-shim RSS within normal bounds",
		problemReason:  "KernelNetShimDegradedDetected",
		stateKey:       latchdefs.LatchKernelNetShim,
	},
	// --- Clocksource latch→condition surface ---
	{
		// hostmetrics' clocksource guard — the kernel marked
		// its clocksource unstable (kmsg evidence latch) or the
		// collector found the current clocksource drifted off
		// tsc/kvm-clock. A demoted clocksource degrades every vDSO
		// clock_gettime and produces clock-skew false positives.
		typ:            nodecond.ClocksourceUnstable,
		defaultReason:  "ClocksourceStable",
		defaultMessage: "kernel clocksource stable (tsc/kvm-clock, no instability records)",
		problemReason:  "ClocksourceUnstableDetected",
		stateKey:       latchdefs.LatchClocksourceUnstable,
	},
	// --- workerhygiene cilium latch→condition surface ---
	{
		// workerhygiene's B4 MTU-drift guard — the cilium datapath,
		// the double-encap cilium_wg0 (overlay MTU minus the ~60B WG
		// header) or a stale pod lxc* veth running an MTU above the
		// nebula overlay: oversized pod packets die with FRAG_NEEDED
		// after SYN-ACK (the silent blackhole). The latch carries the
		// offending pair (e.g. "cilium_net=1500 nebula=1300") and
		// exits when the MTUs align or the overlay iface is gone.
		typ:            nodecond.CiliumMTUDrift,
		defaultReason:  "CiliumMTUAligned",
		defaultMessage: "cilium datapath MTU matches nebula overlay (no drift)",
		problemReason:  "CiliumMTUDriftDetected",
		stateKey:       latchdefs.LatchCiliumMTUDrift,
	},
	{
		// workerhygiene's cilium-wg-peer-gc WireGuard peer-gc healer — cilium_wg0
		// carries fewer live allowed-ip peers than cilium's
		// encryption-peer count (zombie peers excluded from the
		// count), so the stale WG peer state was wiped and
		// cilium-agent restarted; the latch content is
		// "allowed_ips=N expected=M" and exits once the counts match.
		typ:            nodecond.CiliumWGStale,
		defaultReason:  "CiliumWGPeersOk",
		defaultMessage: "cilium_wg0 live peers match expected encryption peers (no stale state)",
		problemReason:  "CiliumWGStaleDetected",
		stateKey:       latchdefs.LatchCiliumWGPeerWipe,
	},
	// --- inode-pressure inode-pressure latch→condition surface ---
	{
		// hostmetrics' inode-pressure inode-usage hysteresis guard — a
		// monitored mount at >=95% inode usage latches
		// state-inode-pressure; a full inode table fails new
		// file/tmpfs writes before DiskPressure ever fires. The
		// kubelet-native InodePressure spelling is reused so the
		// controller's pre-cordon and storm-gate consumers see the
		// agent-detected episodes under the same name.
		typ:            nodecond.InodePressure,
		defaultReason:  "FilesystemInodesHealthy",
		defaultMessage: "all monitored filesystems below inode-pressure thresholds",
		problemReason:  "FilesystemInodesExhausted",
		stateKey:       latchdefs.LatchInodePressure,
	},
}

// condEval is the evaluated state of one condition this cycle.
type condEval struct {
	def     conditionDef
	status  corev1.ConditionStatus
	reason  string
	message string
}

// wantedCond flattens one evaluated condition — a watchdog latch
// condition or an NPD monitor condition — to the fields the
// diff/patch pass needs.
type wantedCond struct {
	typ         corev1.NodeConditionType
	status      corev1.ConditionStatus
	reason      string
	message     string
	gaugeReason string // problem_gauge reason label
}

// syncConditions evaluates BOTH the watchdog latch conditions and
// the two NPD monitor conditions, updates problem_gauge for all of
// them, then merges every diff into ONE status patch — one Node
// GET + at most one PATCH per cycle (the two evaluators used to
// fetch and patch separately, doubling apiserver traffic). A GET
// failure skips the patch only — gauges are purely local and
// always update.
func (r *Reporter) syncConditions(ctx context.Context) error {
	var all []wantedCond
	for _, e := range r.evalConditions() {
		all = append(all, wantedCond{e.def.typ, e.status, e.reason,
			e.message, e.def.problemReason})
	}
	for _, e := range r.monitors.EvalConditions() {
		all = append(all, wantedCond{
			typ: e.Type, status: e.Status, reason: e.Reason,
			message: e.Message, gaugeReason: e.GaugeReason})
	}
	for _, w := range all {
		v := 0.0
		if w.status == corev1.ConditionTrue {
			v = 1
		}
		r.problemGauge.WithLabelValues(string(w.typ), w.gaugeReason).Set(v)
	}

	node, err := r.cfg.Client.CoreV1().Nodes().Get(ctx, r.cfg.NodeName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get node %s: %w", r.cfg.NodeName, err)
	}
	live := make(map[corev1.NodeConditionType]corev1.NodeCondition, len(node.Status.Conditions))
	for _, c := range node.Status.Conditions {
		live[c.Type] = c
	}
	now := metav1.NewTime(r.cfg.Clock.Now())

	// Zero-churn gate: PATCH only when a Status or Reason differs —
	// message-only drift (e.g. the WatchdogStale age counter ticking)
	// does not churn the API.
	changed := false
	var changedList []string
	// heartbeatDue is the gate's other trigger: lastHeartbeatTime is
	// the reporter-liveness stamp cluster-side checks trust
	// (node-hang-precordon refuses a condition whose heartbeat
	// froze — a dead reporter's True value may be a zombie). A
	// steady condition set still re-patches once per
	// HeartbeatInterval so "heartbeat fresh" keeps meaning
	// "reporter alive"; anything that writes our conditions without
	// a stamp is refreshed on the next cycle.
	heartbeatDue := false
	for _, w := range all {
		cur, ok := live[w.typ]
		if !ok || cur.Status != w.status || cur.Reason != w.reason {
			changed = true
			changedList = append(changedList, fmt.Sprintf(
				"%s=%s(%s)", w.typ, w.status, w.reason))
			continue
		}
		if now.Sub(cur.LastHeartbeatTime.Time) >= r.cfg.HeartbeatInterval {
			heartbeatDue = true
		}
	}
	if !changed && !heartbeatDue {
		return nil
	}

	// conditions carry patchStrategy=merge patchMergeKey=type — a
	// strategic merge patch updates only our entries and leaves
	// kubelet-owned conditions (Ready, *Pressure, ...) untouched.
	conds := make([]corev1.NodeCondition, 0, len(all))
	for _, w := range all {
		ltt := now
		// Transition time moves only on a status flip; a reason-only
		// change keeps the original transition timestamp (the NPD and
		// kubelet convention).
		if cur, ok := live[w.typ]; ok && cur.Status == w.status {
			ltt = cur.LastTransitionTime
		}
		conds = append(conds, corev1.NodeCondition{
			Type:               w.typ,
			Status:             w.status,
			Reason:             w.reason,
			Message:            w.message,
			LastHeartbeatTime:  now,
			LastTransitionTime: ltt,
		})
	}
	payload, err := json.Marshal(map[string]any{
		"status": map[string]any{"conditions": conds},
	})
	if err != nil {
		return fmt.Errorf("marshal status patch: %w", err)
	}
	if _, err := r.cfg.Client.CoreV1().Nodes().Patch(ctx, r.cfg.NodeName,
		types.StrategicMergePatchType, payload, metav1.PatchOptions{}, "status"); err != nil {
		return fmt.Errorf("patch node %s status: %w", r.cfg.NodeName, err)
	}
	if len(changedList) > 0 {
		logger().Info("nodereporter: node conditions updated",
			"node", r.cfg.NodeName, "changed", changedList)
	} else {
		// Routine heartbeat refresh — Debug, or the periodic
		// re-patch would read as real churn in the logs.
		logger().Debug("nodereporter: node condition heartbeats refreshed",
			"node", r.cfg.NodeName)
	}
	return nil
}

// evalConditions reads the latch files once and computes the wanted
// state of all watchdog conditions.
func (r *Reporter) evalConditions() []condEval {
	out := make([]condEval, 0, len(conditionDefs))
	for _, d := range conditionDefs {
		res := condEval{def: d, status: corev1.ConditionFalse,
			reason: d.defaultReason, message: d.defaultMessage}
		if d.stateKey == "" {
			if stale, age := r.watchdogStale(); stale {
				res.status = corev1.ConditionTrue
				res.reason = d.problemReason
				// Ported from check-watchdog-fresh.sh's echo — NHC/SNR
				// and runbooks historically matched on that string.
				res.message = fmt.Sprintf(
					"node-watchdog missed heartbeat %ds (timer dead or run failed)", age)
			}
		} else if key, since, ok := r.firstLatch(d.stateKey, d.altStateKeys); ok {
			res.status = corev1.ConditionTrue
			res.reason = d.problemReason
			// check-watchdog-state.sh echo verbatim.
			res.message = fmt.Sprintf("watchdog state %s active since %s", key, since)
		}
		out = append(out, res)
	}
	return out
}

// firstLatch probes the given latch keys in order and reports the
// first present one's key + content — multi-latch conditions name
// their fallback keys in altStateKeys (primary wins on the message).
func (r *Reporter) firstLatch(primary string, alts []string) (key, since string, ok bool) {
	for _, k := range append([]string{primary}, alts...) {
		if k == "" {
			continue
		}
		if s, found := r.stateFileSince(k); found {
			return k, s, true
		}
	}
	return "", "", false
}

// stateFileSince reports whether state-<key> exists, and its content
// (the epoch state_enter wrote; "unknown" when empty/unreadable —
// check-watchdog-state.sh's `|| echo unknown` fallback).
func (r *Reporter) stateFileSince(key string) (string, bool) {
	data, err := os.ReadFile(r.state.Path(key))
	if err != nil {
		return "", false
	}
	if s := strings.TrimSpace(string(data)); s != "" {
		return s, true
	}
	return "unknown", true
}

// watchdogStale is check-watchdog-fresh.sh ported: no `installed`
// marker → not stale (node without the watchdog must never
// false-positive). Baseline timestamp is last-run's content, falling
// back to installed's, then 0; non-numeric content parses to 0 —
// same as the shell's arithmetic treating garbage as 0. age >
// threshold → stale.
func (r *Reporter) watchdogStale() (bool, int64) {
	installedPath := filepath.Join(r.cfg.WatchdogStateDir, "installed")
	if _, err := os.Stat(installedPath); err != nil {
		return false, 0
	}
	ts := int64(0)
	if data, err := os.ReadFile(filepath.Join(r.cfg.WatchdogStateDir, "last-run")); err == nil {
		ts = parseEpoch(data)
	} else if data, err := os.ReadFile(installedPath); err == nil {
		ts = parseEpoch(data)
	}
	age := r.cfg.Clock.Now().Unix() - ts
	if age < 0 {
		age = 0 // clock skew / future timestamp → fresh
	}
	return age > int64(r.cfg.StaleThreshold.Seconds()), age
}

// parseEpoch parses a watchdog epoch file; garbage → 0 (shell parity:
// non-numeric content collapses to 0 inside $((...))).
func parseEpoch(b []byte) int64 {
	v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0
	}
	return v
}
