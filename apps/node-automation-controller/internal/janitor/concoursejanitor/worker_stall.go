// worker_stall.go — the concourse-worker-stall verdict of the
// concourse work-dir janitor: WHY a steady-state worker pod must be
// replaced despite an under-cap cache (TSA stalled state, Garden
// max-containers, baggageclaim volume-create failures read off a
// bounded log tail). Detection only — the recovery itself is the
// standard drain → delete → prune → waitReady chain processPod
// already runs (split out of concourse_janitor.go — see its header
// for the module contract).
package concoursejanitor

import (
	"context"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// waitReady chain processPod already runs.
// ---------------------------------------------------------------------------

// staleWorkerReason reports WHY a steady-state worker pod must be
// replaced despite an under-cap cache, "" when it is healthy (or the
// check is inconclusive — an inconclusive read never wipes the
// cache). A Ready pod must have been steady >= minAge; a not-Ready pod
// wedged past minAge (init-rm done) is replaced outright as
// "worker-not-ready". Gated on flyOK: without ATC login neither the TSA state nor
// a landed drain is available, and the wipe chain would lose the
// land step the stalled worker needs.
func (j *concourseWorkdirJanitor) staleWorkerReason(ctx context.Context,
	pod *corev1.Pod, podName string, flyOK bool, log logr.Logger) string {
	if !flyOK {
		return ""
	}
	var readyAt time.Time
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady {
			readyAt = c.LastTransitionTime.Time
		}
	}
	if kube.PodReadyCond(pod) {
		// Ready pod: steady-state means Ready for at least minAge;
		// younger Ready pods are still churning.
		if readyAt.IsZero() || j.now.Now().Sub(readyAt) < cjSteadyWorkerMinAge {
			return ""
		}
	} else {
		// concourse-worker-stall parity: a pod that is NOT Ready and
		// has stayed that way past minAge is wedged — its worker takes
		// no builds while the cache looks healthy, so the under-cap
		// branch would skip it forever (readyAt was previously only
		// captured on Ready=True, forcing these pods to "" forever).
		// Pods still inside init-rm (init containers not yet done) and
		// freshly created pods are excluded: the mid-init-rm guard in
		// processPod owns that window, and replacing mid-wipe would
		// restart the wipe without freeing anything new.
		for _, s := range pod.Status.InitContainerStatuses {
			if s.State.Terminated == nil {
				return ""
			}
		}
		if readyAt.IsZero() || j.now.Now().Sub(readyAt) < cjSteadyWorkerMinAge {
			// Young/never-ready pods are inside init-rm or churn — the
			// mid-init-rm guard downstream covers them; detection here
			// must not compound it.
			return ""
		}
		return "worker-not-ready"
	}
	if state, err := j.atc.workerState(ctx, podName); err != nil {
		log.Info("WARN: worker state read failed — stalled detection degrades to the log tail",
			"pod", podName, "error", err)
	} else if state == "stalled" {
		return "tsa-state-stalled"
	}
	tail := j.workerLogTail
	if tail == nil {
		tail = j.fetchWorkerLogTail
	}
	logs, err := tail(ctx, pod)
	if err != nil {
		log.Info("WARN: worker log tail read failed — Garden fault detection inconclusive",
			"pod", podName, "error", err)
		return ""
	}
	return workerGardenFault(logs)
}

// fetchWorkerLogTail is the production half of the workerLogTail
// seam: a bounded GetLogs tail of the concourse-worker container.
func (j *concourseWorkdirJanitor) fetchWorkerLogTail(ctx context.Context,
	pod *corev1.Pod) (string, error) {
	return kube.ReadPodLogText(ctx, j.cs, pod, kube.PodLogOpts{
		Container: cjWorkerContainer,
		TailLines: cjWorkerLogTailLine,
		MaxBytes:  256 << 10,
		Timeout:   j.cfg.reqTimeout,
	})
}

// workerGardenFault matches the observed Garden/baggageclaim fault
// signatures (case-insensitive): the worker hit the container
// ceiling, or baggageclaim cannot create new volumes (full disk /
// leaked volumes). "" is healthy-or-inconclusive.
func workerGardenFault(logs string) string {
	l := strings.ToLower(logs)
	if strings.Contains(l, "max containers reached") {
		return "garden-max-containers"
	}
	if strings.Contains(l, "baggageclaim: failed to create volume") {
		return "baggageclaim-volume-create-failed"
	}
	return ""
}
