package workerhygiene

import (
	"context"

	corev1 "k8s.io/api/core/v1"
)

// cycleEnv is the per-cycle shared context Cycle hands to every
// Check: the node-pod LIST + apiserver reachability verdict, the
// k0sworker active gate (WD_REQUIRES: k0sworker — a worker that is
// intentionally down skips every check), and the lazy
// once-per-cycle snapshots the checks share — the containerd task
// map, the /proc pid sweep and the k0sworker journal window — so
// each stays built at most once per cycle, only when a check
// actually pulls it. All fields are read-only to the checks; the
// once-funcs are idempotent.
type cycleEnv struct {
	pods         []corev1.Pod
	apiOK        bool
	workerActive bool
	tasksOnce    func() (map[string][]ctrTask, bool)
	pidsOnce     func() []int
	journalOnce  func() string
}

// Check is one hygiene probe+remedy pair. Name() is the prometheus
// `check` label AND the WD_SIG_<NAME> kill-switch key — it must
// equal the check* constant the counters/logs already use so latch
// names, metric label values and log lines stay identical. Run
// executes one round: implementations reach the shared seams
// (kube client, procfs view, state store, metrics, cfg knobs)
// through their Hygiene back-ref and own their own streak/latch
// bookkeeping.
type Check interface {
	Name() string
	Run(ctx context.Context, e *cycleEnv)
}

// initChecks builds the ordered dispatch list Cycle iterates. The
// ORDER is load-bearing — it preserves the exact sequence the
// checks ran before the table existed (and the shell runner's
// module order before that). Every check is a named field on
// Hygiene (tests reach their state through them; the checkXxx
// forwarders resolve without a list walk) and takes its place in
// the list here.
func (h *Hygiene) initChecks() {
	h.stall = &stallCheck{h: h}
	h.watch = &watchWedgeCheck{h: h}
	h.teardown = &podTeardownCheck{h: h}
	h.konn = &konnCheck{h: h}
	h.dns = &dnsResolvCheck{h: h}
	h.syncloop = &syncloopCheck{h: h}
	h.ctrsock = &ctrsockCheck{h: h}
	h.ctrTasks = &ctrTasksCheck{h: h}
	h.ingestGC = &ingestGCCheck{h: h}
	h.cilium = &ciliumCheck{h: h}
	h.ciliumInit = &ciliumInitCheck{h: h}
	h.ctrImages = &ctrImagesCheck{h: h}
	h.ciliumIPAM = &ciliumIPAMCheck{h: h}
	h.ciliumEnvoy = &ciliumEnvoyCheck{h: h}
	h.ciliumMTU = &ciliumMTUCheck{h: h}
	h.ciliumWG = &ciliumWGCheck{h: h}
	h.diskBloat = &diskBloatCheck{h: h}
	h.journald = &journaldCheck{h: h}
	h.zombies = &zombieStormCheck{h: h, streaks: map[zombieParent]int{}}
	h.dstate = &dstateCheck{h: h}
	h.scopes = &scopesCheck{h: h}
	h.ciliumLRP = &ciliumLRPCheck{h: h}
	h.spegel = &spegelCheck{h: h}
	h.calico = &calicoCheck{h: h}
	h.cniNetns = &cniNetnsCheck{h: h}
	h.psiThrash = &psiThrashCheck{h: h}
	h.ctrMeta = &ctrMetaCheck{h: h}
	h.hostOOM = &hostOOMCheck{h: h}
	h.orphanHP = &orphanHPCheck{h: h}
	h.checks = []Check{
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
	}
}
