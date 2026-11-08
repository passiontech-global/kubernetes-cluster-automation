// evicted-pod-janitor — port of hooks/85-evicted-pod-janitor.sh.
//
// Deletes Pods stuck in phase=Failed with an eviction-flavored
// status.reason for more than 1h. Kubelet evictions (DiskPressure /
// MemoryPressure), node-loss and admission rejections all leave the
// Pod object behind permanently — Kubernetes never garbage-collects
// them (kubernetes/kubernetes#55051), so they pile up in
// `kubectl get pods` output and inflate etcd storage forever.
//
// Safety: only phase=Failed AND a reason in the known-terminal set —
// running/pending/succeeded pods are never touched. Pods already
// being deleted (DeletionTimestamp set) are skipped, and pods younger
// than 1h are kept so a fresh eviction is still inspectable. Capped
// at 10 deletions per run to bound churn.
package evictedpodjanitor

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/reap"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

const (
	evictedPodMaxAge = time.Hour
	evictedPodCap    = 10 // bound delete churn per run
)

// evictedPodReasons is the set of terminal status.reason values that
// leave a Failed pod behind with no controller to clean it up
// (k8s#55051 — "Preempted" is the same shape: scheduler preemption
// leaves a Failed pod nobody owns). Anything else —
// ContainerStatusUnknown, ImagePull backoff that ended in Failed,
// etc. — is kept for debugging.
var evictedPodReasons = map[string]struct{}{
	"Evicted":                  {},
	"NodeAffinity":             {},
	"NodeLost":                 {},
	"Preempted":                {},
	"Shutdown":                 {},
	"UnexpectedAdmissionError": {},
	"OutOfcpu":                 {},
	"OutOfmemory":              {},
	"OutOfephemeral-storage":   {},
}

type evictedPodJanitor struct {
	cs kubernetes.Interface
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the periodic's name and every IncError label
	// come from one place.
	queue string
	// now is the clock seam — tests pin it so the 1h keep window is
	// deterministic. nil → time.Now.
	now shared.Clock
}

// Setup registers the 10-minute sweep. The gate rides
// shared.SetupNoConfig like every module: Deps.Disabled registers
// nothing (no knobs to parse — SetupNoConfig is the module's shape).
func Setup(d shared.Deps) error {
	return shared.SetupNoConfig(d, func() error {
		j := &evictedPodJanitor{cs: d.CS, queue: d.Name, now: shared.SystemClock}
		return shared.AddPeriodic(d.Mgr, j.queue, 10*time.Minute, j.run)
	})
}

func (j *evictedPodJanitor) run(ctx context.Context) error {
	log := logf.FromContext(ctx)

	// Server-side phase filter: only Failed pods can carry an
	// eviction reason, so without this the sweep deserializes every
	// Running/Pending pod in the cluster to throw them away below.
	// The in-code phase check stays — fake clientsets ignore field
	// selectors and the belt costs nothing.
	pods, err := kube.ListAll(ctx, metav1.ListOptions{
		FieldSelector: "status.phase=" + string(corev1.PodFailed),
		Limit:         kube.DefaultListPageSize,
	}, kube.Pods(j.cs, metav1.NamespaceAll))
	if err != nil {
		return fmt.Errorf("list failed pods: %w", err) // periodic wrapper IncErrors j.queue
	}

	type target struct {
		ns, name, node, reason string
		uid                    types.UID
		ageHours               int
	}
	var targets []target
	for i := range pods {
		pod := &pods[i]
		if pod.Status.Phase != corev1.PodFailed {
			continue
		}
		if _, ok := evictedPodReasons[pod.Status.Reason]; !ok {
			continue
		}
		if pod.DeletionTimestamp != nil {
			continue // already terminating — the API owns it now
		}
		// The eviction happened when the containers died, not when
		// the pod object was created — a pod can live for weeks
		// before eviction, and CreationTimestamp-based aging would
		// reap a minutes-old eviction the operator has not seen.
		age := j.now.Now().Sub(evictionTime(pod))
		if age <= evictedPodMaxAge {
			continue // fresh eviction — keep it inspectable
		}
		targets = append(targets, target{
			ns:       pod.Namespace,
			name:     pod.Name,
			node:     pod.Spec.NodeName,
			reason:   pod.Status.Reason,
			uid:      pod.UID,
			ageHours: int(age.Hours()),
		})
	}
	// Release the pod slice before issuing Delete calls.
	pods = nil

	deleted, failed, capped := reap.Sweep(ctx, log, targets, reap.Options[target]{
		// The cap bounds delete attempts (failed deletes churn the
		// apiserver the same way) — leftover targets drain next run.
		Cap: evictedPodCap,
		LogTarget: func(log logr.Logger, t target) {
			log.Info("DELETE: evicted pod past retention",
				"pod", t.ns+"/"+t.name, "node", t.node,
				"reason", t.reason, "ageHours", t.ageHours)
		},
		Delete: func(ctx context.Context, t target) error {
			// UID precondition: the listed object is what we vetted —
			// a same-named pod recreated in between is not ours to reap.
			return j.cs.CoreV1().Pods(t.ns).Delete(ctx, t.name,
				kube.UIDDeleteOptions(t.uid, metav1.DeletePropagationBackground))
		},
		OnError: func(log logr.Logger, t target, err error) {
			switch {
			case apierrors.IsNotFound(err):
				// The pod was deleted under us — raced with an
				// external cleanup; nothing failed.
				log.Info("SKIP: pod already gone — raced with an external delete",
					"pod", t.ns+"/"+t.name)
			case apierrors.IsConflict(err):
				// The UID precondition fired — a same-named pod was
				// recreated since the list; not ours to reap.
				log.Info("SKIP: pod recreated since the list — UID precondition fired",
					"pod", t.ns+"/"+t.name)
			default:
				metrics.IncError(j.queue)
				log.Error(err, "pod delete failed",
					"pod", t.ns+"/"+t.name, "node", t.node, "reason", t.reason)
			}
		},
	})
	if capped {
		log.Info("SKIP rest: cap reached", "cap", evictedPodCap)
	}
	log.Info("sweep done", "deleted", deleted, "failed", failed)
	return nil
}

// evictionTime is the moment the pod's containers actually died —
// the latest containerStatuses[].state.terminated.finishedAt — or
// the CreationTimestamp when no terminated state is recorded. The
// finishedAt fallback ordering matters: a long-lived pod evicted an
// hour ago must read as fresh even though its object is old.
// InitContainerStatuses are scanned too: a pod evicted DURING init
// never populates containerStatuses, so without it the eviction
// clock wrongly anchors at CreationTimestamp and a minutes-old
// eviction could be reaped inside the 1h keep window.
func evictionTime(pod *corev1.Pod) time.Time {
	latest := pod.CreationTimestamp.Time
	for _, statuses := range [][]corev1.ContainerStatus{
		pod.Status.ContainerStatuses, pod.Status.InitContainerStatuses,
	} {
		for i := range statuses {
			if t := statuses[i].State.Terminated; t != nil &&
				t.FinishedAt.After(latest) {
				latest = t.FinishedAt.Time
			}
		}
	}
	return latest
}
