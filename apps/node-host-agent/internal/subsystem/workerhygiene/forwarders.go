// forwarders.go — the pre-Check test contract: tests written before
// the Check interface existed call the old method-shaped entry
// points on *Hygiene. Each forwarder builds the minimal CycleEnv
// the old call site implied and runs the domain check — nothing
// else. The feeder forwarders hand the embedded *wdeps.Deps to the
// kubelet package's exported feeder entry points.
package workerhygiene

import (
	"context"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/kubelet"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// --- T15 feeder forwarders ---

func (h *Hygiene) runKubeletFeeder(ctx context.Context) {
	kubelet.RunKubeletFeeder(ctx, h.Deps)
}

func (h *Hygiene) kubeletFeederActive() bool {
	return kubelet.KubeletFeederActive(h.Deps)
}

func (h *Hygiene) kubeletFeedTick(ctx context.Context) {
	kubelet.KubeletFeedTick(ctx, h.Deps)
}

// --- check forwarders (old method shape → Check.Run) ---

func (h *Hygiene) checkCiliumBPFMaps(ctx context.Context) {
	h.cilium.CheckBPFMaps(ctx)
}

func (h *Hygiene) checkCiliumEnvoy(ctx context.Context, workerActive bool) {
	h.ciliumEnvoy.Run(ctx, &wdeps.CycleEnv{WorkerActive: workerActive})
}

func (h *Hygiene) checkCiliumLRPDNS(ctx context.Context, pods []corev1.Pod,
	apiOK, workerActive bool) {
	h.ciliumLRP.Run(ctx, &wdeps.CycleEnv{
		Pods: pods, APIOK: apiOK, WorkerActive: workerActive})
}

func (h *Hygiene) checkCiliumMTU(workerActive bool) {
	h.ciliumMTU.Run(context.Background(), &wdeps.CycleEnv{WorkerActive: workerActive})
}

func (h *Hygiene) checkCiliumWGPeers(ctx context.Context, apiOK, workerActive bool) {
	h.ciliumWG.Run(ctx, &wdeps.CycleEnv{APIOK: apiOK, WorkerActive: workerActive})
}

func (h *Hygiene) checkCtrIngestGC(ctx context.Context, workerActive bool) {
	h.ingestGC.Run(ctx, &wdeps.CycleEnv{WorkerActive: workerActive})
}

func (h *Hygiene) checkContainerdHealth(ctx context.Context,
	pidsOnce func() []int, workerActive bool) {
	h.ctrMeta.Run(ctx, &wdeps.CycleEnv{
		PidsOnce: pidsOnce, WorkerActive: workerActive})
}

func (h *Hygiene) checkHostOOMVictims(ctx context.Context) {
	h.hostOOM.Run(ctx, &wdeps.CycleEnv{})
}

func (h *Hygiene) checkOrphanedHostPathVolumes(ctx context.Context,
	workerActive bool) {
	h.orphanHP.Run(ctx, &wdeps.CycleEnv{WorkerActive: workerActive})
}

func (h *Hygiene) checkDiskBloat(ctx context.Context, pods []corev1.Pod,
	apiOK, workerActive bool) {
	h.diskBloat.Run(ctx, &wdeps.CycleEnv{
		Pods: pods, APIOK: apiOK, WorkerActive: workerActive})
}

func (h *Hygiene) checkDStateTasks(pidsOnce func() []int, workerActive bool) {
	h.dstate.Run(context.Background(), &wdeps.CycleEnv{
		PidsOnce: pidsOnce, WorkerActive: workerActive})
}

func (h *Hygiene) checkSystemdScopes(ctx context.Context, workerActive bool) {
	h.scopes.Run(ctx, &wdeps.CycleEnv{WorkerActive: workerActive})
}

func (h *Hygiene) checkPSIThrash(ctx context.Context, pods []corev1.Pod,
	apiOK bool, pidsOnce func() []int, workerActive bool) {
	h.psiThrash.Run(ctx, &wdeps.CycleEnv{
		Pods: pods, APIOK: apiOK, PidsOnce: pidsOnce,
		WorkerActive: workerActive})
}

func (h *Hygiene) checkSpegelMirror(ctx context.Context, pods []corev1.Pod,
	apiOK, workerActive bool) {
	h.spegel.Run(ctx, &wdeps.CycleEnv{
		Pods: pods, APIOK: apiOK, WorkerActive: workerActive})
}

func (h *Hygiene) checkCalicoHygiene(ctx context.Context, pods []corev1.Pod,
	apiOK, workerActive bool) {
	h.calico.Run(ctx, &wdeps.CycleEnv{
		Pods: pods, APIOK: apiOK, WorkerActive: workerActive})
}

func (h *Hygiene) checkOrphanCNINetns(ctx context.Context,
	pidsOnce func() []int, workerActive bool) {
	h.cniNetns.Run(ctx, &wdeps.CycleEnv{
		PidsOnce: pidsOnce, WorkerActive: workerActive})
}
