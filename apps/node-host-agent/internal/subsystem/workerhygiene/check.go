// check.go — the ordered check dispatch table. The checks
// themselves live in per-domain packages under workerhygiene/
// (kubelet/, pods/, ctr/, cilium/, guards/, runtime/); the shared
// dependency surface is wdeps. The ORDER is load-bearing — it
// preserves the exact sequence the checks ran before the table
// existed (and the shell runner's module order before that).
// Each check registers once via add(): it lands in h.checks (the
// Check(name) lookup the domain tests use) AND in the static
// checks.Entry table Cycle dispatches — the registration sequence
// below IS the dispatch order.
package workerhygiene

import (
	"context"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/checks"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/cilium"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/ctr"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/guards"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/kubelet"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/pods"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/runtime"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// initChecks builds the ordered dispatch table Cycle drives — the
// add() sequence below IS the order, preserved verbatim from the
// pre-table run sequence (see the file header). The entries are
// built ONCE here (the controllerhygiene/nethealth static-table
// pattern): each Run closes over its check and h.envCell — the
// per-cycle CycleEnv Cycle refreshes — so nothing is rebuilt per
// Interval.
func (h *Hygiene) initChecks() {
	d := h.Deps
	var entries []checks.Entry
	// add is the single-registration seam for one check: the check
	// lands in h.checks (Check(name) walks it for the domain test
	// packages) AND takes its place in the static dispatch table —
	// one call so the two views can never drift. c is a parameter,
	// so each entry's Run closure binds its own check.
	add := func(c wdeps.Check) {
		h.checks = append(h.checks, c)
		entries = append(entries, checks.Entry{
			Name: c.Name(),
			Run:  func(ctx context.Context) { c.Run(ctx, h.envCell) },
		})
	}
	add(kubelet.NewStall(d))      // wdeps.CheckStall
	add(kubelet.NewWatchWedge(d)) // wdeps.CheckWatch
	add(pods.NewPodTeardown(d))   // wdeps.CheckTeardown
	add(pods.NewKonn(d))          // wdeps.CheckKonn
	add(pods.NewDNSResolv(d))     // wdeps.CheckDNS
	add(kubelet.NewSyncloop(d))   // wdeps.CheckSyncloop
	add(kubelet.NewCtrsock(d))    // wdeps.CheckCtrSock
	add(ctr.NewCtrTasks(d))       // wdeps.CheckCtrTasks
	add(ctr.NewMountinfo(d))      // wdeps.CheckMountinfo
	add(ctr.NewIngestGC(d))       // wdeps.CheckIngestGC
	add(cilium.NewCilium(d))      // wdeps.CheckCilium
	add(cilium.NewCiliumInit(d))  // wdeps.CheckCiliumInit
	add(ctr.NewCtrImages(d))      // wdeps.CheckCtrImages
	add(cilium.NewCiliumIPAM(d))  // wdeps.CheckCiliumIPAM
	add(cilium.NewCiliumEnvoy(d)) // wdeps.CheckCiliumEnvoy
	add(cilium.NewCiliumMTU(d))   // wdeps.CheckCiliumMTU
	add(cilium.NewCiliumWG(d))    // wdeps.CheckCiliumWG
	// Disk side-guards keep the intra-Run order they had inside
	// DiskBloatCheck.Run: run-tmpfs → dev-shm → localpv-quota →
	// coredump-gc → writable-layer-scan → disk-bloat walk.
	add(runtime.NewRunTmpfs(d))      // wdeps.CheckRunTmpfs
	add(runtime.NewDevShm(d))        // wdeps.CheckDevShm
	add(runtime.NewLocalPVQuota(d))  // wdeps.CheckLocalPVQuota
	add(runtime.NewCoredumpGC(d))    // wdeps.CheckCoredumpGC
	add(runtime.NewWritableLayer(d)) // wdeps.CheckWritableLayer
	add(runtime.NewDiskBloat(d))     // wdeps.CheckDiskBloat
	add(guards.NewZombieStorm(d))    // wdeps.CheckZombieStorm
	add(guards.NewJournald(d))       // wdeps.CheckJournald
	add(guards.NewDstate(d))         // wdeps.CheckDState
	add(guards.NewScopes(d))         // wdeps.CheckSysScopes
	add(cilium.NewCiliumLRP(d))      // wdeps.CheckCiliumLRP
	add(guards.NewSpegel(d))         // wdeps.CheckSpegel
	add(guards.NewCalico(d))         // wdeps.CheckCalico
	add(guards.NewCNINetns(d))       // wdeps.CheckCNINetns
	add(guards.NewPSIThrash(d))      // wdeps.CheckPSIThrash
	add(ctr.NewCtrMeta(d))           // wdeps.CheckCtrMeta
	add(runtime.NewHostOOM(d))       // wdeps.CheckHostOOM
	add(runtime.NewOrphanHP(d))      // wdeps.CheckOrphanHP
	// Runtime-resource guards run last: they consume only
	// their own host-side evidence (cgroup.stat, sessions dir,
	// diskstats, sysctls, the pod LIST) so nothing downstream
	// depends on their output this cycle.
	add(runtime.NewCgroupDying(d))       // wdeps.CheckCgroupDying
	add(runtime.NewSystemdSession(d))    // wdeps.CheckSystemdSessions
	add(runtime.NewOverlayFSStale(d))    // wdeps.CheckOverlayFSStale
	add(runtime.NewIOPressure(d))        // wdeps.CheckIOPressure
	add(runtime.NewConntrackLiberal(d))  // wdeps.CheckConntrackLiberal
	add(runtime.NewClockJump(d))         // wdeps.CheckClockJump
	add(runtime.NewUnlinkedOpenFiles(d)) // wdeps.CheckUnlinkedOpenFiles
	add(runtime.NewCgroupSwap(d))        // wdeps.CheckCgroupSwap
	add(runtime.NewCgroupThrottle(d))    // wdeps.CheckCgroupThrottle
	add(runtime.NewSubprocOOM(d))        // wdeps.CheckSubprocOOM
	add(runtime.NewSATokenTTL(d))        // wdeps.CheckSATokenTTL
	// kernel-net-shim-hygiene — kernel socket/softnet drop growth +
	// containerd shim RSS; last in the runtime-resource group (it
	// reads the shared per-cycle pid snapshot).
	add(runtime.NewKernelNetShim(d)) // wdeps.CheckKernelNetShim
	// A single UNGATED group: the unit-file and uptime gates return
	// early in Cycle and workerActive gates inside each check
	// (per-check cycles{check,"gated"}) — none map onto
	// Group.GateOK, whose skip counts "uptime_gate" and would
	// starve the "disabled" count of a kill-switched check.
	h.groups = []checks.Group{{Entries: entries}}
}
