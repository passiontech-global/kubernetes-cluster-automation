// events_rules.go — the filelog rule tables, split out of events.go
// (which keeps the log tailing loop and the Event emitter). Pure
// move — no behavior change.
package nodereporter

import (
	"regexp"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

type logRule struct {
	reason string
	re     *regexp.Regexp
}

// logRules is the watchdog-filelog-monitor.json rules array, in order.
//
// Derivation contract: whenever an in-repo emitter writes the line a
// rule matches, the rule is BUILT from the shared latchdefs protocol
// constant (QuoteMeta / StateEnterRe / ActionEntryRe) — rewording the
// emitter is then a compile error at the emitter's own site and the
// rule follows automatically, so drift cannot strand an Event.
// Alternations matching lines nothing in this repo writes anymore
// (retired lib.sh shell modules, kernel/kubelet lines the old
// watchdog copied into the log) stay literal and are documented per
// entry — they must keep matching the retained legacy log lines.
var logRules = []logRule{
	// overlay_egress.go writes "overlay-egress unreachable"; the
	// "tinc" spelling is retired lib.sh vocabulary retained logs
	// still carry.
	{"TincEgressUnreachable", regexp.MustCompile(`(?:tinc|overlay)-egress unreachable`)},
	// overlay_egress.go writes the head from latchdefs.ActionEgress
	// ("ACTION: egress <ip> -> overlay relay table N (...)"); the
	// "tinc relay" spelling is retired lib.sh vocabulary.
	{"TincEgressFailover", regexp.MustCompile(
		regexp.QuoteMeta(latchdefs.ActionEgress) + `[0-9.]+ -> (?:tinc|overlay) relay`)},
	// hostmetrics' PSI latch writes "node-overloaded"
	// (latchdefs.LatchNodeOverloaded); "node overloaded" is retired
	// lib.sh wording.
	{nodecond.NodeOverloaded, regexp.MustCompile(`node[- ]overloaded`)},
	{"K0sworkerRestarted", regexp.MustCompile(regexp.QuoteMeta(latchdefs.ActionK0sworkerRestart))},
	{"KubeletInformerZombie", regexp.MustCompile(regexp.QuoteMeta(latchdefs.ReasonInformerZombie))},
	{"KubeletPhantomPods", regexp.MustCompile(regexp.QuoteMeta(latchdefs.ReasonPhantomPods))},
	// "ctr-task-wedged" is ctr_tasks.go's suspect keyword
	// (latchdefs.ReasonCtrTaskWedged); the other two alternations are
	// the retired shell's remediation wording.
	{"CtrTaskWedged", regexp.MustCompile(
		regexp.QuoteMeta(latchdefs.ReasonCtrTaskWedged) +
			`|ctr tasks delete|orphaned task dir`)},
	{"KonnectivityStaleId", regexp.MustCompile(
		regexp.QuoteMeta(latchdefs.ReasonKonnectivityStaleID) + `|` +
			regexp.QuoteMeta(latchdefs.ReasonKonnectivityAgentRecreate))},
	{"TincEgressRecovered", regexp.MustCompile(
		regexp.QuoteMeta(latchdefs.ActionEgress) + `[0-9.]+ -> direct underlay`)},
	{"TincEgressHeal", regexp.MustCompile(regexp.QuoteMeta(latchdefs.ActionEgressHeal))},
	{"NebulaRestarted", regexp.MustCompile(regexp.QuoteMeta(latchdefs.ActionNebulaRestart))},
	{"NebulaIsolatedEnter", latchdefs.StateEnterRe(latchdefs.LatchNebulaIsolated)},
	{"NebulaDataplaneDegraded", regexp.MustCompile(regexp.QuoteMeta(latchdefs.ReasonNebulaDataplaneDegraded))},
	{"NebulaSlowPath", regexp.MustCompile(regexp.QuoteMeta(latchdefs.ReasonNebulaDataplaneSlowpath))},
	{"NebulaSiteEdge", regexp.MustCompile(regexp.QuoteMeta(latchdefs.ReasonNebulaSiteedgeDegraded))},
	{"NebulaCertExpiring", regexp.MustCompile(regexp.QuoteMeta(latchdefs.LatchNebulaCertExpiring))},
	// WatchdogRunFailed: emitted by the retired lib.sh runner — no
	// in-repo producer.
	{"WatchdogRunFailed", regexp.MustCompile(`WATCHDOG-FAILED`)},
	// WatchdogModuleFailed: STATE-ENTER lines of the retired shell's
	// per-module failure latches ("module-failed-<id>-<name>") — the
	// prefix derives from the shared StateEnterPrefix; the
	// module-failed vocabulary has no in-repo producer.
	{"WatchdogModuleFailed", regexp.MustCompile(latchdefs.StateEnterPrefix + "module-failed-")},
	// The cilium-agent-down latch plus the "killed cilium-agent" half
	// of latchdefs.ActionCiliumAgentKill — kept at the shorter legacy
	// form, because the retired shell killed the agent without the
	// " container -" tail those lines must still match.
	{nodecond.CiliumAgentDown, regexp.MustCompile(
		regexp.QuoteMeta(latchdefs.LatchCiliumAgentDown) + `|` +
			regexp.QuoteMeta(strings.TrimPrefix(latchdefs.ActionCiliumAgentKill, latchdefs.ActionPrefix)))},
	{nodecond.KubeletRuntimeStall, regexp.MustCompile(regexp.QuoteMeta(latchdefs.LatchKubeletRuntimeStall))},
	{nodecond.DNSResolvStale, regexp.MustCompile(regexp.QuoteMeta(latchdefs.LatchDNSResolvStale))},
	{"StuckPodForceDeleted", regexp.MustCompile(regexp.QuoteMeta(latchdefs.ReasonForceDeletePod))},
	{nodecond.PodTeardownWedged, regexp.MustCompile(regexp.QuoteMeta(latchdefs.LatchPodTeardownWedged))},
	// The remediation half derives from ClockRestartUnits — the same
	// slice clock.go (and nebula_health.go's timesyncd latch line)
	// restarts from.
	{nodecond.ClockUnsynchronized, regexp.MustCompile(
		latchdefs.StateEnterRe(latchdefs.LatchClockUnsync).String() +
			`|` + latchdefs.ActionClockRestartRe().String())},
	// The nf_conntrack halves match kernel dmesg lines the retired
	// shell copied into the watchdog log — the kernel is the
	// producer, there is no in-repo wording to share.
	{nodecond.ConntrackPressure, regexp.MustCompile(
		latchdefs.StateEnterRe(latchdefs.LatchConntrackPressure).String() +
			`|nf_conntrack.*table full`)},
	// "no more IPs available" is kubelet's FailedCreatePodSandBox
	// wording — an external producer.
	{nodecond.CiliumIPAMExhausted, regexp.MustCompile(
		latchdefs.StateEnterRe(latchdefs.LatchCiliumIPAMExhausted).String() +
			`|no more IPs available`)},
	{"CorruptedImageRemoved", regexp.MustCompile(regexp.QuoteMeta(latchdefs.ActionCorruptedImageRemove))},
	{"ZombieProcessStorm", latchdefs.ActionEntryRe(latchdefs.LatchZombieStorm)},
	{"CiliumMTUExceedsOverlay", latchdefs.ActionEntryRe(latchdefs.LatchCiliumMTUDrift)},
	// cilium-wg-peer-gc: workerhygiene's cilium WireGuard peer-gc drift healer —
	// "ACTION: killed cilium-agent container - cilium_wg0 has N
	// allowed-ip peers while expected M".
	{"CiliumWireGuardPeerDrift", regexp.MustCompile(regexp.QuoteMeta(latchdefs.ActionCiliumWGKill))},
	// disk-bloat: disk-bloat runaway detector —
	// "ACTION disk-bloat: target=... bytes=... used_pct=...".
	// (nodecond constant — DiskBloatRunaway is now a condition name;
	// the reason string is unchanged.)
	{nodecond.DiskBloatRunaway, latchdefs.ActionEntryRe(latchdefs.LatchDiskBloat)},
	// journalwatch blindness latch — STATE-ENTER only (one event per
	// latch entry; the suspect:* line carrying the same detail is a
	// throttled re-reminder, matching it too would double-count).
	{nodecond.JournaldUnreadable, latchdefs.StateEnterRe(latchdefs.LatchJournalUnreadable)},
	// d-state-storm: workerhygiene's d-state-storm latch-entry line —
	// "ACTION d-state-storm: count=N runtime=M wchan=...".
	{nodecond.KernelHungTasks, latchdefs.ActionEntryRe(latchdefs.LatchDStateStorm)},
	// --- infra latch→event surface ---
	// One Event per STATE-ENTER of a latch that maps to a permanent
	// NodeCondition (conditions.go). Latches already covered by an
	// older rule (nebula-isolated → NebulaIsolatedEnter,
	// conntrack-pressure → ConntrackPressure, cilium-ipam-exhausted
	// → CiliumIPAMExhausted) are intentionally not duplicated.
	{nodecond.NebulaDegraded, latchdefs.StateEnterRe(latchdefs.LatchNebulaDegraded)},
	{nodecond.CiliumEnvoyDown, latchdefs.StateEnterRe(latchdefs.LatchCiliumEnvoyDown)},
	{nodecond.CiliumBPFMapPressure, latchdefs.StateEnterRe(latchdefs.LatchCiliumBPFMapPressure)},
	{nodecond.SpegelMirrorDegraded, latchdefs.StateEnterRe(latchdefs.LatchSpegelMirrorDegraded)},
	{nodecond.CalicoVethLeak, latchdefs.StateEnterRe(latchdefs.LatchCalicoVethLeak)},
	{nodecond.CalicoFelixDown, latchdefs.StateEnterRe(latchdefs.LatchCalicoFelixDown)},
	{nodecond.Fail2banDown, latchdefs.StateEnterRe(latchdefs.LatchFail2banDown)},
	{nodecond.KernelKeysPressure, latchdefs.StateEnterRe(latchdefs.LatchKernelKeysPressure)},
	{nodecond.ControlPlaneCertReloadStale, latchdefs.StateEnterRe(latchdefs.LatchCPCertReloadStale)},
	// Clocksource: the kernel clocksource-unstable evidence latch —
	// STATE-ENTER only (one Event per latch entry, like the other
	// infra latch→event rules).
	{nodecond.ClocksourceUnstable, latchdefs.StateEnterRe(latchdefs.LatchClocksourceUnstable)},
	// psi-memory-thrash: workerhygiene's psi-memory-thrash latch-entry line —
	// "ACTION psi-memory-thrash: avg60=... free=...".
	{"NodeMemoryPSIThrashing", latchdefs.ActionEntryRe(latchdefs.LatchPSIMemoryThrash)},
	// --- leak-pressure latch→event surface ---
	// workerhygiene's kernel-slab-leak slab-leak guard + nethealth's overlay-mtu-guard
	// DF PMTU probe — one Event per STATE-ENTER (clock-unsync is
	// already covered by the ClockUnsynchronized rule above).
	{nodecond.KernelSlabLeak, latchdefs.StateEnterRe(latchdefs.LatchKernelSlabLeak)},
	{nodecond.NebulaPMTUBlackhole, latchdefs.StateEnterRe(latchdefs.LatchNebulaPMTUBlackhole)},
	// --- latch→event surface: kernel/host deep-failure + hygiene ---
	// One Event per STATE-ENTER for the remaining registered latches.
	// containerd-corrupt and fs-readonly feed shared conditions via
	// altStateKeys in conditions.go (KubeletRuntimeStall and
	// FilesystemReadOnly respectively); the rest own their condition
	// type 1:1.
	{"ContainerdCorrupt", latchdefs.StateEnterRe(latchdefs.LatchContainerdCorrupt)},
	// FilesystemReadOnly is fed by TWO latches: the filesystem-readonly statfs
	// latch (filesystem-readonly) and the kernelfail evidence latch
	// (fs-readonly) — both registered tokens map to the one reason.
	{nodecond.FilesystemReadOnly, latchdefs.StateEnterRe(
		latchdefs.LatchFSReadonly, latchdefs.LatchFilesystemReadonly)},
	{nodecond.KernelResourceExhaustion, latchdefs.StateEnterRe(latchdefs.LatchPIDFDPressure)},
	{nodecond.ClockSkewDetected, latchdefs.StateEnterRe(latchdefs.LatchClockSkew)},
	{nodecond.KubeconfigCertExpiring, latchdefs.StateEnterRe(latchdefs.LatchKubeconfigCertExpiring)},
	{nodecond.CPUStealPressure, latchdefs.StateEnterRe(latchdefs.LatchCPUStealPressure)},
	{nodecond.CgroupDyingLeak, latchdefs.StateEnterRe(latchdefs.LatchCgroupDyingLeak)},
	{nodecond.SystemdSessionBloat, latchdefs.StateEnterRe(latchdefs.LatchSystemdSessionBloat)},
	{nodecond.SystemdUnresponsive, latchdefs.StateEnterRe(latchdefs.LatchSystemdUnresponsive)},
	// recent-latches latches that had conditions (conditions.go) but no
	// filelog rule — kubelet-pleg-unhealthy and disk-slow-io
	// previously entered without ever emitting an Event.
	{nodecond.KubeletPLEGUnhealthy, latchdefs.StateEnterRe(latchdefs.LatchKubeletPLEGUnhealthy)},
	{nodecond.DiskSlowIO, latchdefs.StateEnterRe(latchdefs.LatchDiskSlowIO)},
	{nodecond.KernelNetShimDegraded, latchdefs.StateEnterRe(latchdefs.LatchKernelNetShim)},
	// inode-pressure: hostmetrics' inode-pressure latch — a Warning on entry
	// (the STATE-ENTER line carries the offending mount + ratio); the
	// clean end of the episode earns an informational Event via
	// exitLogRules below.
	{nodecond.InodePressure, latchdefs.StateEnterRe(latchdefs.LatchInodePressure)},
	// hostmetrics' clock-warp detector line —
	// "ACTION clock-warp: delta=... tick=... (events=N)".
	{"NodeClockWarpDetected", latchdefs.ActionEntryRe(latchdefs.ActionClockWarp)},
	// --- W21 latch→event surface ---
	// The three latches whose producers emit the ACTION-entry line
	// once per episode (the disk-bloat NPD contract shape —
	// ActionEntryPrefix at the Enter site, gated on the latch
	// being absent): cilium-envoy-xds-reject (workerhygiene envoy
	// xDS-NACK streak), nebula-mtu-blackhole (nethealth routeguard
	// NM4 DF-probe blackhole) and page-alloc-failure (hostmetrics
	// kmsg buddy-allocator fragmentation evidence).
	{nodecond.CiliumEnvoyXDSReject, latchdefs.ActionEntryRe(latchdefs.LatchCiliumEnvoyXDSReject)},
	{nodecond.NebulaMTUBlackhole, latchdefs.ActionEntryRe(latchdefs.LatchNebulaMTUBlackhole)},
	{nodecond.KernelPageAllocFailure, latchdefs.ActionEntryRe(latchdefs.LatchPageAllocFailure)},
	// controllerhygiene's sig13 watch-cache wedge latch — one Event
	// per STATE-ENTER (the apiserver serving stale watch-cache data
	// is exactly when cluster-side heals must defer pod churn).
	{nodecond.ApiserverWatchCacheWedged, latchdefs.StateEnterRe(latchdefs.LatchAPIServerCacheWedged)},
}

// exitLogRules — STATE-EXIT lines that earn an informational (Normal)
// Event marking a latch episode's clean end. Entry events live in
// logRules; an exit is recovery, not a problem, so it must not render
// as a Warning. The counter for a matched exit still rides the shared
// problem_counter surface (reason = the episode's healthy reason).
var exitLogRules = []logRule{
	// inode-pressure: inode-pressure cleared — every monitored mount back to
	// <=90% inode usage.
	{"FilesystemInodesHealthy", latchdefs.StateExitRe(latchdefs.LatchInodePressure)},
}
