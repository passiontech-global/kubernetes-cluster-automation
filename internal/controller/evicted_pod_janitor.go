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
package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/node-automation-controller/internal/metrics"
)

const (
	evictedPodQueue  = "evicted-pod-janitor"
	evictedPodMaxAge = time.Hour
	evictedPodCap    = 10 // bound delete churn per run
)

// evictedPodReasons is the set of terminal status.reason values that
// leave a Failed pod behind with no controller to clean it up
// (k8s#55051). Anything else — ContainerStatusUnknown, ImagePull
// backoff that ended in Failed, etc. — is kept for debugging.
var evictedPodReasons = map[string]struct{}{
	"Evicted":                  {},
	"NodeAffinity":             {},
	"NodeLost":                 {},
	"Shutdown":                 {},
	"UnexpectedAdmissionError": {},
	"OutOfcpu":                 {},
	"OutOfmemory":              {},
	"OutOfephemeral-storage":   {},
}

type evictedPodJanitor struct {
	cs kubernetes.Interface
}

// SetupEvictedPodJanitor registers the 10-minute sweep.
func SetupEvictedPodJanitor(mgr ctrl.Manager, cs kubernetes.Interface) error {
	j := &evictedPodJanitor{cs: cs}
	return addPeriodic(mgr, evictedPodQueue, 10*time.Minute, j.run)
}

func (j *evictedPodJanitor) run(ctx context.Context) error {
	log := logf.FromContext(ctx)

	pods, err := j.cs.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err // periodic wrapper IncErrors evictedPodQueue
	}

	background := metav1.DeletePropagationBackground
	deleted := 0
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Status.Phase != corev1.PodFailed {
			continue
		}
		if _, ok := evictedPodReasons[pod.Status.Reason]; !ok {
			continue
		}
		if pod.DeletionTimestamp != nil {
			continue // already terminating — the API owns it now
		}
		age := time.Since(pod.CreationTimestamp.Time)
		if age <= evictedPodMaxAge {
			continue // fresh eviction — keep it inspectable
		}
		if deleted >= evictedPodCap {
			log.Info(fmt.Sprintf("SKIP rest: cap=%d reached", evictedPodCap))
			break
		}
		log.Info(fmt.Sprintf("DELETE %s/%s on %s: reason=%s age=%dh",
			pod.Namespace, pod.Name, pod.Spec.NodeName,
			pod.Status.Reason, int(age.Hours())))
		if err := j.cs.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name,
			metav1.DeleteOptions{PropagationPolicy: &background}); err != nil {
			metrics.IncError(evictedPodQueue)
			log.Error(err, "pod delete failed", "pod", pod.Namespace+"/"+pod.Name)
		}
		deleted++ // count the attempt against the cap too
	}
	log.Info("sweep done")
	return nil
}
