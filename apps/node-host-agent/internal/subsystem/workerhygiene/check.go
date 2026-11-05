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
// through their *deps (deps.go — the check-facing dependency
// surface) and own their own streak/latch bookkeeping.
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
	h.stall = &stallCheck{d: h.deps}
	h.watch = &watchWedgeCheck{d: h.deps}
	h.teardown = &podTeardownCheck{d: h.deps}
	h.konn = &konnCheck{d: h.deps}
	h.dns = &dnsResolvCheck{d: h.deps}
	h.syncloop = &syncloopCheck{d: h.deps}
	h.ctrsock = &ctrsockCheck{d: h.deps}
	h.ctrTasks = &ctrTasksCheck{d: h.deps}
	h.ingestGC = &ingestGCCheck{d: h.deps}
	h.cilium = &ciliumCheck{d: h.deps}
	h.ciliumInit = &ciliumInitCheck{d: h.deps}
	h.ctrImages = &ctrImagesCheck{d: h.deps}
	h.ciliumIPAM = &ciliumIPAMCheck{d: h.deps}
	h.ciliumEnvoy = &ciliumEnvoyCheck{d: h.deps}
	h.ciliumMTU = &ciliumMTUCheck{d: h.deps}
	h.ciliumWG = &ciliumWGCheck{d: h.deps}
	h.diskBloat = &diskBloatCheck{d: h.deps}
	h.journald = &journaldCheck{d: h.deps}
	h.zombies = &zombieStormCheck{d: h.deps, streaks: map[zombieParent]int{}}
	h.dstate = &dstateCheck{d: h.deps}
	h.scopes = &scopesCheck{d: h.deps}
	h.ciliumLRP = &ciliumLRPCheck{d: h.deps}
	h.spegel = &spegelCheck{d: h.deps}
	h.calico = &calicoCheck{d: h.deps}
	h.cniNetns = &cniNetnsCheck{d: h.deps}
	h.psiThrash = &psiThrashCheck{d: h.deps}
	h.ctrMeta = &ctrMetaCheck{d: h.deps}
	h.hostOOM = &hostOOMCheck{d: h.deps}
	h.orphanHP = &orphanHPCheck{d: h.deps}
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
