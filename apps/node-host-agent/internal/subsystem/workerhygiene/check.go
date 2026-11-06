// check.go — the ordered check dispatch table. The checks
// themselves live in per-domain packages under workerhygiene/
// (kubelet/, pods/, ctr/, cilium/, guards/, runtime/); the shared
// dependency surface is wdeps. The ORDER is load-bearing — it
// preserves the exact sequence the checks ran before the table
// existed (and the shell runner's module order before that).
// Every check is a named field on Hygiene (tests reach their state
// through them; the checkXxx forwarders resolve without a list
// walk) and takes its place in the list via a single add() call —
// the registration sequence below IS the dispatch order.
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

// add is the single-registration seam for one check: *slot keeps
// the named Hygiene field tests poke (h.stall, h.ciliumWG, …) and
// the append takes the check's place in the ordered dispatch list.
// One call does both so the field and the list entry can never
// drift — the previous ctor-line + slice-literal bookkeeping let a
// check land in one place and not the other.
func add[C wdeps.Check](h *Hygiene, slot *C, c C) {
	*slot = c
	h.checks = append(h.checks, c)
}

// initChecks builds the ordered dispatch list Cycle iterates —
// the add() sequence below IS the order, preserved verbatim from
// the pre-table run sequence (see the file header).
func (h *Hygiene) initChecks() {
	d := h.Deps
	add(h, &h.stall, kubelet.NewStall(d))            // wdeps.CheckStall
	add(h, &h.watch, kubelet.NewWatchWedge(d))       // wdeps.CheckWatch
	add(h, &h.teardown, pods.NewPodTeardown(d))      // wdeps.CheckTeardown
	add(h, &h.konn, pods.NewKonn(d))                 // wdeps.CheckKonn
	add(h, &h.dns, pods.NewDNSResolv(d))             // wdeps.CheckDNS
	add(h, &h.syncloop, kubelet.NewSyncloop(d))      // wdeps.CheckSyncloop
	add(h, &h.ctrsock, kubelet.NewCtrsock(d))        // wdeps.CheckCtrSock
	add(h, &h.ctrTasks, ctr.NewCtrTasks(d))          // wdeps.CheckCtrTasks
	add(h, &h.ingestGC, ctr.NewIngestGC(d))          // wdeps.CheckIngestGC
	add(h, &h.cilium, cilium.NewCilium(d))           // wdeps.CheckCilium
	add(h, &h.ciliumInit, cilium.NewCiliumInit(d))   // wdeps.CheckCiliumInit
	add(h, &h.ctrImages, ctr.NewCtrImages(d))        // wdeps.CheckCtrImages
	add(h, &h.ciliumIPAM, cilium.NewCiliumIPAM(d))   // wdeps.CheckCiliumIPAM
	add(h, &h.ciliumEnvoy, cilium.NewCiliumEnvoy(d)) // wdeps.CheckCiliumEnvoy
	add(h, &h.ciliumMTU, cilium.NewCiliumMTU(d))     // wdeps.CheckCiliumMTU
	add(h, &h.ciliumWG, cilium.NewCiliumWG(d))       // wdeps.CheckCiliumWG
	add(h, &h.diskBloat, runtime.NewDiskBloat(d))    // wdeps.CheckDiskBloat
	add(h, &h.zombies, guards.NewZombieStorm(d))     // wdeps.CheckZombieStorm
	add(h, &h.journald, guards.NewJournald(d))       // wdeps.CheckJournald
	add(h, &h.dstate, guards.NewDstate(d))           // wdeps.CheckDState
	add(h, &h.scopes, guards.NewScopes(d))           // wdeps.CheckSysScopes
	add(h, &h.ciliumLRP, cilium.NewCiliumLRP(d))     // wdeps.CheckCiliumLRP
	add(h, &h.spegel, guards.NewSpegel(d))           // wdeps.CheckSpegel
	add(h, &h.calico, guards.NewCalico(d))           // wdeps.CheckCalico
	add(h, &h.cniNetns, guards.NewCNINetns(d))       // wdeps.CheckCNINetns
	add(h, &h.psiThrash, guards.NewPSIThrash(d))     // wdeps.CheckPSIThrash
	add(h, &h.ctrMeta, ctr.NewCtrMeta(d))            // wdeps.CheckCtrMeta
	add(h, &h.hostOOM, runtime.NewHostOOM(d))        // wdeps.CheckHostOOM
	add(h, &h.orphanHP, runtime.NewOrphanHP(d))      // wdeps.CheckOrphanHP
	// Runtime-resource guards run last: they consume only
	// their own host-side evidence (cgroup.stat, sessions dir,
	// diskstats, sysctls, the pod LIST) so nothing downstream
	// depends on their output this cycle.
	add(h, &h.cgroupDying, runtime.NewCgroupDying(d))           // wdeps.CheckCgroupDying
	add(h, &h.systemdSessions, runtime.NewSystemdSession(d))    // wdeps.CheckSystemdSessions
	add(h, &h.overlayFSStale, runtime.NewOverlayFSStale(d))     // wdeps.CheckOverlayFSStale
	add(h, &h.ioPressure, runtime.NewIOPressure(d))             // wdeps.CheckIOPressure
	add(h, &h.conntrackLiberal, runtime.NewConntrackLiberal(d)) // wdeps.CheckConntrackLiberal
	add(h, &h.clockJump, runtime.NewClockJump(d))               // wdeps.CheckClockJump
	add(h, &h.unlinkedFDs, runtime.NewUnlinkedOpenFiles(d))     // wdeps.CheckUnlinkedOpenFiles
	add(h, &h.cgroupSwap, runtime.NewCgroupSwap(d))             // wdeps.CheckCgroupSwap
}
