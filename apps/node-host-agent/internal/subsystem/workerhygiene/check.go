// check.go — the ordered check dispatch table. The checks
// themselves live in per-domain packages under workerhygiene/
// (kubelet/, pods/, ctr/, cilium/, guards/, runtime/); the shared
// dependency surface is wdeps. The ORDER is load-bearing — it
// preserves the exact sequence the checks ran before the table
// existed (and the shell runner's module order before that).
// Every check is a named field on Hygiene (tests reach their state
// through them; the checkXxx forwarders resolve without a list
// walk) and takes its place in the list here.
package workerhygiene

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/cilium"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/ctr"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/guards"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/kubelet"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/pods"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/runtime"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// initChecks builds the ordered dispatch list Cycle iterates.
func (h *Hygiene) initChecks() {
	d := h.Deps
	h.stall = kubelet.NewStall(d)
	h.watch = kubelet.NewWatchWedge(d)
	h.teardown = pods.NewPodTeardown(d)
	h.konn = pods.NewKonn(d)
	h.dns = pods.NewDNSResolv(d)
	h.syncloop = kubelet.NewSyncloop(d)
	h.ctrsock = kubelet.NewCtrsock(d)
	h.ctrTasks = ctr.NewCtrTasks(d)
	h.ingestGC = ctr.NewIngestGC(d)
	h.cilium = cilium.NewCilium(d)
	h.ciliumInit = cilium.NewCiliumInit(d)
	h.ctrImages = ctr.NewCtrImages(d)
	h.ciliumIPAM = cilium.NewCiliumIPAM(d)
	h.ciliumEnvoy = cilium.NewCiliumEnvoy(d)
	h.ciliumMTU = cilium.NewCiliumMTU(d)
	h.ciliumWG = cilium.NewCiliumWG(d)
	h.diskBloat = runtime.NewDiskBloat(d)
	h.journald = guards.NewJournald(d)
	h.zombies = guards.NewZombieStorm(d)
	h.dstate = guards.NewDstate(d)
	h.scopes = guards.NewScopes(d)
	h.ciliumLRP = cilium.NewCiliumLRP(d)
	h.spegel = guards.NewSpegel(d)
	h.calico = guards.NewCalico(d)
	h.cniNetns = guards.NewCNINetns(d)
	h.psiThrash = guards.NewPSIThrash(d)
	h.ctrMeta = ctr.NewCtrMeta(d)
	h.hostOOM = runtime.NewHostOOM(d)
	h.orphanHP = runtime.NewOrphanHP(d)
	h.cgroupDying = runtime.NewCgroupDying(d)
	h.systemdSessions = runtime.NewSystemdSession(d)
	h.overlayFSStale = runtime.NewOverlayFSStale(d)
	h.ioPressure = runtime.NewIOPressure(d)
	h.conntrackLiberal = runtime.NewConntrackLiberal(d)
	h.clockJump = runtime.NewClockJump(d)
	h.unlinkedFDs = runtime.NewUnlinkedOpenFiles(d)
	h.cgroupSwap = runtime.NewCgroupSwap(d)
	h.checks = []wdeps.Check{
		h.stall,       // wdeps.CheckStall
		h.watch,       // wdeps.CheckWatch
		h.teardown,    // wdeps.CheckTeardown
		h.konn,        // wdeps.CheckKonn
		h.dns,         // wdeps.CheckDNS
		h.syncloop,    // wdeps.CheckSyncloop
		h.ctrsock,     // wdeps.CheckCtrSock
		h.ctrTasks,    // wdeps.CheckCtrTasks
		h.ingestGC,    // wdeps.CheckIngestGC
		h.cilium,      // wdeps.CheckCilium
		h.ciliumInit,  // wdeps.CheckCiliumInit
		h.ctrImages,   // wdeps.CheckCtrImages
		h.ciliumIPAM,  // wdeps.CheckCiliumIPAM
		h.ciliumEnvoy, // wdeps.CheckCiliumEnvoy
		h.ciliumMTU,   // wdeps.CheckCiliumMTU
		h.ciliumWG,    // wdeps.CheckCiliumWG
		h.diskBloat,   // wdeps.CheckDiskBloat
		h.zombies,     // wdeps.CheckZombieStorm
		h.journald,    // wdeps.CheckJournald
		h.dstate,      // wdeps.CheckDState
		h.scopes,      // wdeps.CheckSysScopes
		h.ciliumLRP,   // wdeps.CheckCiliumLRP
		h.spegel,      // wdeps.CheckSpegel
		h.calico,      // wdeps.CheckCalico
		h.cniNetns,    // wdeps.CheckCNINetns
		h.psiThrash,   // wdeps.CheckPSIThrash
		h.ctrMeta,     // wdeps.CheckCtrMeta
		h.hostOOM,     // wdeps.CheckHostOOM
		h.orphanHP,    // wdeps.CheckOrphanHP
		// Runtime-resource guards run last: they consume only
		// their own host-side evidence (cgroup.stat, sessions dir,
		// diskstats, sysctls, the pod LIST) so nothing downstream
		// depends on their output this cycle.
		h.cgroupDying,      // wdeps.CheckCgroupDying
		h.systemdSessions,  // wdeps.CheckSystemdSessions
		h.overlayFSStale,   // wdeps.CheckOverlayFSStale
		h.ioPressure,       // wdeps.CheckIOPressure
		h.conntrackLiberal, // wdeps.CheckConntrackLiberal
		h.clockJump,        // wdeps.CheckClockJump
		h.unlinkedFDs,      // wdeps.CheckUnlinkedOpenFiles
		h.cgroupSwap,       // wdeps.CheckCgroupSwap
	}
}
