// latches.go — the canonical registry of state-<name> latch names.
//
// The latch names were previously bare literals scattered across
// ~8 packages, with the janitor keeping a hand-maintained copy of
// the set for its known/unknown reap classification and
// nodereporter another for its condition table. They live here now
// — next to Store, the single implementation of the file contract —
// so a new latch is registered once at the name's definition site
// and every consumer (writers, readers, the reaper, the condition
// mapper) shares it.
//
// On-disk contract: state-<name>, content = epoch of entry. The
// names below are byte-identical to the literals they replace —
// this is a code consolidation, not a contract change.
package hoststate

import "strings"

// LatchFilePrefix is the filename half every latch shares —
// "state-"+<name>.
const LatchFilePrefix = "state-"

// Latch name constants — the <name> half of state-<name>, one per
// latch an enabled check can currently produce, grouped by owning
// subsystem (the Owner column of LatchDefs). The parameterized
// families end in "-" and match by prefix.
const (
	// workerhygiene — the hygiene checks produce most of the
	// latches in the dir.
	LatchPodTeardownWedged      = "pod-teardown-wedged"      // 36
	LatchKonnectivityIPMismatch = "konnectivity-ip-mismatch" // 30
	LatchDNSResolvStale         = "dns-resolv-stale"         // 33
	LatchKubeletRuntimeStall    = "kubelet-runtime-stall"    // 05
	LatchKubeletWatchWedge      = "kubelet-watch-wedge"      // 06
	LatchKubeletHealthzDown     = "kubelet-healthz-down"     // T15 remediate
	LatchKubeletSyncloopDown    = "kubelet-syncloop-down"    // A4
	LatchContainerdSockDown     = "containerd-sock-down"     // A4
	LatchCiliumAgentDown        = "cilium-agent-down"        // 32
	LatchCiliumInitStuck        = "cilium-init-stuck"        // 35
	LatchCiliumIPAMExhausted    = "cilium-ipam-exhausted"    // 38
	LatchCiliumEnvoyDown        = "cilium-envoy-down"        // B1
	LatchCiliumEnvoyXDSReject   = "cilium-envoy-xds-reject"  // W7-H3
	LatchCiliumMTUDrift         = "cilium-mtu-drift"         // B4
	LatchCiliumBPFMapPressure   = "cilium-bpf-map-pressure"  // W8-NM3
	LatchCiliumWGPeerWipe       = "cilium-wg-peer-wipe"      // W5.6
	LatchDiskBloat              = "disk-bloat"               // W6.3
	LatchZombieStorm            = "zombie-storm"             // A2
	LatchDStateStorm            = "d-state-storm"            // W7-H1
	LatchSpegelMirrorDegraded   = "spegel-mirror-degraded"   // W7-H4
	LatchCalicoVethLeak         = "calico-veth-leak"         // W7-H7
	LatchCalicoFelixDown        = "calico-felix-down"        // W7-H7
	LatchPSIMemoryThrash        = "psi-memory-thrash"        // W2
	LatchKernelSlabLeak         = "kernel-slab-leak"         // W9-KR3
	LatchContainerdCorrupt      = "containerd-corrupt"       // W10-KR3
	LatchCgroupDyingLeak        = "cgroup-dying-leak"        // cgroup-dying-reclaim
	LatchSystemdSessionBloat    = "systemd-session-bloat"    // systemd-session-hygiene
	LatchKubeletPLEGUnhealthy   = "kubelet-pleg-unhealthy"   // kubelet-syncloop PLEG metrics
	LatchDiskSlowIO             = "disk-slow-io"             // W12-KR4 io-pressure gray failure
	// LatchJournalUnreadable is the blindness latch the shared
	// journalwatch tracker sets — produced by BOTH hygienes'
	// journal-read accounting (workerhygiene journald.go,
	// controllerhygiene journal.go).
	LatchJournalUnreadable = "journal-unreadable" // A5
	// LatchCiliumIPAMPrefix is the cilium IPAM latch family (38)
	// — LatchCiliumIPAMExhausted is the member the checks
	// currently mint; the prefix stays registered so a renamed
	// family member is never classified unknown.
	LatchCiliumIPAMPrefix = "cilium-ipam-"

	// nethealth — the DNS/overlay/nebula/fail2ban modules.
	LatchDNSFallback         = "dns-fallback"          // 20
	LatchNebulaIsolated      = "nebula-isolated"       // 13
	LatchNebulaDegraded      = "nebula-degraded"       // 13
	LatchNebulaSlowpath      = "nebula-slowpath"       // 13
	LatchNebulaSiteedge      = "nebula-siteedge"       // 13
	LatchFail2banDown        = "fail2ban-down"         // 50
	LatchClockUnsync         = "clock-unsync"          // H1
	LatchConntrackPressure   = "conntrack-pressure"    // H2
	LatchNebulaPMTUBlackhole = "nebula-pmtu-blackhole" // W9-NM1
	LatchNebulaMTUBlackhole  = "nebula-mtu-blackhole"  // routeguard NM4

	// controllerhygiene — the control-plane guards.
	LatchAPIServerCacheStale    = "apiserver-cache-stale"    // sig13
	LatchAPIServerCacheWedged   = "apiserver-cache-wedged"   // sig13
	LatchKineBackendUnreachable = "kine-backend-unreachable" // sig13
	LatchKinePoolRunaway        = "kine-pool-runaway"
	LatchKineTTLDead            = "kine-ttl-dead"
	LatchKineTTLLoop            = "kine-ttl-loop"
	LatchK0sControllerOOMLoop   = "k0scontroller-oom-loop"
	LatchCPComponentFrozen      = "cp-component-frozen"      // W8-CP3
	LatchCPCertReloadStale      = "cp-cert-reload-stale"     // W8-CP4
	LatchKubeconfigCertExpiring = "kubeconfig-cert-expiring" // W10

	// nodereporter — the kernel monitor's permanent-class evidence
	// latches, Entered on a soft-lockup / RCU-stall kmsg signature
	// and never Exited by the reporter (the janitor's max-age
	// reaper clears them once the signature stops recurring).
	LatchKernelSoftLockup = "kernel-softlockup"
	LatchKernelRCUStall   = "kernel-rcu-stall"

	// hostmetrics — the latch ticker's file-contract latches.
	LatchNodeOverloaded     = "node-overloaded"      // PSI hysteresis
	LatchFilesystemReadonly = "filesystem-readonly"  // W5.3 statfs ST_RDONLY
	LatchNebulaCertExpiring = "nebula-cert-expiring" // 13 cert parse
	LatchKernelKeysPressure = "kernel-keys-pressure" // W8-KR3
	LatchFSReadonly         = "fs-readonly"          // W10-ST1/KR1
	LatchPIDFDPressure      = "pid-fd-pressure"      // W10-KR2
	LatchClockSkew          = "clock-skew"           // W10-KR5
	LatchCPUStealPressure   = "cpu-steal-pressure"   // cpu-steal-guard

	// apiprober — the per-backend stale family; the suffix is the
	// backend IP with dots dashed (shell ${beh//./-}), minted per
	// target at write time.
	LatchAPIServerBackendStalePrefix = "apiserver-backend-stale-"
)

// LatchDef is one registry entry: the latch's <name> suffix, the
// subsystem that produces it, and whether the name is a
// parameterized family (Prefix: match by strings.HasPrefix — the
// suffix is minted per target at write time, e.g.
// state-apiserver-backend-stale-<ip-dashed>).
type LatchDef struct {
	Name   string // the <name> half of state-<name>
	Owner  string // owning subsystem
	Prefix bool   // parameterized family — suffix minted per target
	// Owners lists every producer id that may hold the latch
	// simultaneously through Store.EnterFrom/Store.ExitFrom —
	// non-nil only for shared latches. hoststate is the leaf both
	// producers import, so the declared ids are the contract the
	// calls must match (store.go's ExitFrom seeds a synthetic hold
	// set from this list for owner-less legacy files).
	Owners []string
}

// LatchDefs is every state-<name> latch an enabled check can
// currently produce — the registry the janitor's known/unknown reap
// classification consults (it used to maintain a hand-copied map of
// exactly this set):
//
//	workerhygiene (stateEnter callers):
//	  pod-teardown-wedged (36), konnectivity-ip-mismatch (30),
//	  dns-resolv-stale (33), kubelet-runtime-stall (05),
//	  kubelet-watch-wedge (06), cilium-agent-down (32),
//	  cilium-init-stuck (35), kubelet-healthz-down (T15 remediate),
//	  kubelet-syncloop-down / containerd-sock-down (A4),
//	  cilium-envoy-down (B1), cilium-mtu-drift (B4),
//	  zombie-storm (A2), d-state-storm (W7-H1),
//	  cilium-envoy-xds-reject (W7-H3), spegel-mirror-degraded (W7-H4),
//	  calico-veth-leak / calico-felix-down (W7-H7),
//	  cilium-bpf-map-pressure (W8-NM3), psi-memory-thrash (W2),
//	  kernel-slab-leak (W9-KR3)
//	nethealth: dns-fallback (20), nebula-isolated/-degraded/-slowpath/
//	  -siteedge (13), fail2ban-down (50), clock-unsync (H1),
//	  conntrack-pressure (H2), nebula-pmtu-blackhole (W9-NM1)
//	controllerhygiene: apiserver-cache-stale/-wedged (sig13),
//	  kine-backend-unreachable, kine-pool-runaway, kine-ttl-dead,
//	  kine-ttl-loop, k0scontroller-oom-loop, cp-cert-reload-stale (W8-CP4),
//	  cp-component-frozen (W8-CP3)
//	controllerhygiene + workerhygiene (shared journalwatch tracker):
//	  journal-unreadable
//	hostmetrics: node-overloaded (PSI hysteresis), filesystem-readonly,
//	  nebula-cert-expiring, kernel-keys-pressure (W8-KR3)
var LatchDefs = []LatchDef{
	// workerhygiene — pod-teardown-wedged is the shared latch:
	// pods.PodTeardownCheck holds it for stuck Terminating pods,
	// ctr.CtrTasksCheck for unkillable D/Z orphan shims. The
	// ids match wdeps.CheckTeardown/wdeps.CheckCtrTasks.
	{Name: LatchPodTeardownWedged, Owner: "workerhygiene",
		Owners: []string{"pod-teardown", "ctr-tasks"}},
	{Name: LatchKonnectivityIPMismatch, Owner: "workerhygiene"},
	{Name: LatchDNSResolvStale, Owner: "workerhygiene"},
	{Name: LatchKubeletRuntimeStall, Owner: "workerhygiene"},
	{Name: LatchKubeletWatchWedge, Owner: "workerhygiene"},
	{Name: LatchKubeletHealthzDown, Owner: "workerhygiene"},
	{Name: LatchKubeletSyncloopDown, Owner: "workerhygiene"},
	{Name: LatchContainerdSockDown, Owner: "workerhygiene"},
	{Name: LatchCiliumAgentDown, Owner: "workerhygiene"},
	{Name: LatchCiliumInitStuck, Owner: "workerhygiene"},
	{Name: LatchCiliumIPAMExhausted, Owner: "workerhygiene"},
	{Name: LatchCiliumEnvoyDown, Owner: "workerhygiene"},
	{Name: LatchCiliumEnvoyXDSReject, Owner: "workerhygiene"},
	{Name: LatchCiliumMTUDrift, Owner: "workerhygiene"},
	{Name: LatchCiliumBPFMapPressure, Owner: "workerhygiene"},
	{Name: LatchCiliumWGPeerWipe, Owner: "workerhygiene"},
	{Name: LatchDiskBloat, Owner: "workerhygiene"},
	{Name: LatchZombieStorm, Owner: "workerhygiene"},
	{Name: LatchDStateStorm, Owner: "workerhygiene"},
	{Name: LatchSpegelMirrorDegraded, Owner: "workerhygiene"},
	{Name: LatchCalicoVethLeak, Owner: "workerhygiene"},
	{Name: LatchCalicoFelixDown, Owner: "workerhygiene"},
	{Name: LatchPSIMemoryThrash, Owner: "workerhygiene"},
	{Name: LatchKernelSlabLeak, Owner: "workerhygiene"},
	{Name: LatchContainerdCorrupt, Owner: "workerhygiene"},
	{Name: LatchCgroupDyingLeak, Owner: "workerhygiene"},
	{Name: LatchSystemdSessionBloat, Owner: "workerhygiene"},
	{Name: LatchKubeletPLEGUnhealthy, Owner: "workerhygiene"},
	{Name: LatchDiskSlowIO, Owner: "workerhygiene"},
	{Name: LatchJournalUnreadable, Owner: "workerhygiene+controllerhygiene"},
	{Name: LatchCiliumIPAMPrefix, Owner: "workerhygiene", Prefix: true},

	// nethealth
	{Name: LatchDNSFallback, Owner: "nethealth"},
	{Name: LatchNebulaIsolated, Owner: "nethealth"},
	{Name: LatchNebulaDegraded, Owner: "nethealth"},
	{Name: LatchNebulaSlowpath, Owner: "nethealth"},
	{Name: LatchNebulaSiteedge, Owner: "nethealth"},
	{Name: LatchFail2banDown, Owner: "nethealth"},
	{Name: LatchClockUnsync, Owner: "nethealth"},
	{Name: LatchConntrackPressure, Owner: "nethealth"},
	{Name: LatchNebulaPMTUBlackhole, Owner: "nethealth"},
	{Name: LatchNebulaMTUBlackhole, Owner: "nethealth"},

	// controllerhygiene
	{Name: LatchAPIServerCacheStale, Owner: "controllerhygiene"},
	{Name: LatchAPIServerCacheWedged, Owner: "controllerhygiene"},
	{Name: LatchKineBackendUnreachable, Owner: "controllerhygiene"},
	{Name: LatchKinePoolRunaway, Owner: "controllerhygiene"},
	{Name: LatchKineTTLDead, Owner: "controllerhygiene"},
	{Name: LatchKineTTLLoop, Owner: "controllerhygiene"},
	{Name: LatchK0sControllerOOMLoop, Owner: "controllerhygiene"},
	{Name: LatchCPComponentFrozen, Owner: "controllerhygiene"},
	{Name: LatchCPCertReloadStale, Owner: "controllerhygiene"},
	{Name: LatchKubeconfigCertExpiring, Owner: "controllerhygiene"},

	// nodereporter
	{Name: LatchKernelSoftLockup, Owner: "nodereporter"},
	{Name: LatchKernelRCUStall, Owner: "nodereporter"},

	// hostmetrics
	{Name: LatchNodeOverloaded, Owner: "hostmetrics"},
	{Name: LatchFilesystemReadonly, Owner: "hostmetrics"},
	{Name: LatchNebulaCertExpiring, Owner: "hostmetrics"},
	{Name: LatchKernelKeysPressure, Owner: "hostmetrics"},
	{Name: LatchFSReadonly, Owner: "hostmetrics"},
	{Name: LatchPIDFDPressure, Owner: "hostmetrics"},
	{Name: LatchClockSkew, Owner: "hostmetrics"},
	{Name: LatchCPUStealPressure, Owner: "hostmetrics"},

	// apiprober
	{Name: LatchAPIServerBackendStalePrefix, Owner: "apiprober", Prefix: true},
}

// SharedOwners returns the declared multi-owner producer ids for a
// latch — nil for every single-producer latch.
func SharedOwners(name string) []string {
	for _, d := range LatchDefs {
		if d.Name == name {
			return d.Owners
		}
	}
	return nil
}

// KnownLatchName reports whether a state-<?> suffix is in the
// registry of currently-producible latch names — an exact match on
// a LatchDef name, or a prefix match on a parameterized family.
func KnownLatchName(suffix string) bool {
	for _, d := range LatchDefs {
		if d.Prefix {
			if strings.HasPrefix(suffix, d.Name) {
				return true
			}
			continue
		}
		if suffix == d.Name {
			return true
		}
	}
	return false
}
