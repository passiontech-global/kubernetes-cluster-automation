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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
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

// Setup registers the 10-minute sweep.
func Setup(mgr ctrl.Manager, cs kubernetes.Interface) error {
	j := &evictedPodJanitor{cs: cs}
	return shared.AddPeriodic(mgr, evictedPodQueue, 10*time.Minute, j.run)
}

func (j *evictedPodJanitor) run(ctx context.Context) error {
	log := logf.FromContext(ctx)

	// Server-side phase filter: only Failed pods can carry an
	// eviction reason, so without this the sweep deserializes every
	// Running/Pending pod in the cluster to throw them away below.
	// The in-code phase check stays — fake clientsets ignore field
	// selectors and the belt costs nothing.
	pods, err := j.cs.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{
		FieldSelector: "status.phase=" + string(corev1.PodFailed),
	})
	if err != nil {
		return fmt.Errorf("list failed pods: %w", err) // periodic wrapper IncErrors evictedPodQueue
	}

	type target struct {
		ns, name, node, reason string
		ageHours               int
	}
	var targets []target
	capped := false
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
		if len(targets) >= evictedPodCap {
			capped = true
			break
		}
		targets = append(targets, target{
			ns:       pod.Namespace,
			name:     pod.Name,
			node:     pod.Spec.NodeName,
			reason:   pod.Status.Reason,
			ageHours: int(age.Hours()),
		})
	}
	// Release the PodList before issuing Delete calls.
	pods = nil

	background := metav1.DeletePropagationBackground
	deleted, failed := 0, 0
	for _, t := range targets {
		log.Info(fmt.Sprintf("DELETE %s/%s on %s: reason=%s age=%dh",
			t.ns, t.name, t.node, t.reason, t.ageHours))
		if err := j.cs.CoreV1().Pods(t.ns).Delete(ctx, t.name,
			metav1.DeleteOptions{PropagationPolicy: &background}); err != nil {
			metrics.IncError(evictedPodQueue)
			log.Error(err, "pod delete failed",
				"pod", t.ns+"/"+t.name, "node", t.node, "reason", t.reason)
			failed++
			continue
		}
		deleted++
	}
	if capped {
		log.Info(fmt.Sprintf("SKIP rest: cap=%d reached", evictedPodCap))
	}
	log.Info("sweep done", "deleted", deleted, "failed", failed)
	return nil
}
