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
	h.checks = []wdeps.Check{
		h.stall,       // checkStall
		h.watch,       // checkWatch
		h.teardown,    // checkTeardown
		h.konn,        // checkKonn
		h.dns,         // checkDNS
		h.syncloop,    // checkSyncloop
		h.ctrsock,     // checkCtrSock
		h.ctrTasks,    // checkCtrTasks
		h.ingestGC,    // checkIngestGC
		h.cilium,      // checkCilium
		h.ciliumInit,  // checkCiliumInit
		h.ctrImages,   // checkCtrImages
		h.ciliumIPAM,  // checkCiliumIPAM
		h.ciliumEnvoy, // checkCiliumEnvoy
		h.ciliumMTU,   // checkCiliumMTU
		h.ciliumWG,    // checkCiliumWG
		h.diskBloat,   // checkDiskBloat
		h.zombies,     // checkZombieStorm
		h.journald,    // checkJournald
		h.dstate,      // checkDState
		h.scopes,      // checkSysScopes
		h.ciliumLRP,   // checkCiliumLRP
		h.spegel,      // checkSpegel
		h.calico,      // checkCalico
		h.cniNetns,    // checkCNINetns
		h.psiThrash,   // checkPSIThrash
		h.ctrMeta,     // checkCtrMeta
		h.hostOOM,     // checkHostOOM
		h.orphanHP,    // checkOrphanHP
		// Runtime-resource guards run last: they consume only
		// their own host-side evidence (cgroup.stat, sessions dir,
		// diskstats, sysctls, the pod LIST) so nothing downstream
		// depends on their output this cycle.
		h.cgroupDying,      // checkCgroupDying
		h.systemdSessions,  // checkSystemdSessions
		h.overlayFSStale,   // checkOverlayFSStale
		h.ioPressure,       // checkIOPressure
		h.conntrackLiberal, // checkConntrackLiberal
		h.clockJump,        // checkClockJump
	}
}
