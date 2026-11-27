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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/maintenance"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/reap"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

const (
	evictedPodMaxAge = time.Hour
	evictedPodCap    = 10 // bound delete churn per run

	// unknownPodMinAge is how long a controller-owned pod must remain
	// stranded in ContainerStatusUnknown / PodUnknown on a Ready node
	// before reaping — long enough for a kubelet reconnect to resolve
	// transient Unknown states on its own.
	unknownPodMinAge = 15 * time.Minute
	unknownPodCap    = 10
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
	cs         kubernetes.Interface
	dyn        dynamic.Interface
	nodeReader kube.CachedNodeReader
	verdict    *maintenance.Verdict
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the periodic's name and every IncError label
	// come from one place.
	queue string
	// now is the clock seam — tests pin it so the 1h keep window is
	// deterministic. nil → time.Now.
	now shared.Clock
	// unknownSeen tracks first observation of controller-owned pods
	// stranded in ContainerStatusUnknown/PodUnknown on Ready nodes.
	unknownSeen state.FirstSeenLedger
}

// Setup registers the 10-minute sweep. The gate rides
// shared.SetupNoConfig like every module: Deps.Disabled registers
// nothing (no knobs to parse — SetupNoConfig is the module's shape).
func Setup(d shared.Deps) error {
	return shared.SetupNoConfig(d, func() error {
		j := &evictedPodJanitor{
			cs:         d.CS,
			dyn:        d.Dyn,
			nodeReader: d.CachedClient(),
			verdict:    d.Maintenance,
			queue:      d.Name,
			now:        shared.SystemClock,
		}
		return shared.AddPeriodic(d.Mgr, j.queue, 10*time.Minute, j.run)
	})
}

func (j *evictedPodJanitor) run(ctx context.Context) error {
	log := logf.FromContext(ctx)

	// Server-side phase filter: only Failed pods can carry an
	// eviction reason, so without this the sweep deserializes every
	// Running/Pending pod in the cluster to throw them away below.
	// The in-code phase check stays — fake clientsets ignore field
	// selectors and the belt costs nothing. The filter pass runs
	// INSIDE the page visit: it needs Status (metadata-only lists
	// cannot serve it) but only the tiny target tuples survive, so
	// each page's pod bodies die with the page instead of pinning
	// the cluster's failed pods until the deletes run.
	type target struct {
		ns, name, node, reason string
		uid                    types.UID
		ageHours               int
	}
	var targets []target
	err := kube.ListEach(ctx, metav1.ListOptions{
		FieldSelector:   "status.phase=" + string(corev1.PodFailed),
		Limit:           kube.DefaultListPageSize,
		ResourceVersion: "0",
	}, kube.Pods(j.cs, metav1.NamespaceAll),
		func(page []corev1.Pod) error {
			for i := range page {
				pod := &page[i]
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
			return nil
		})
	if err != nil {
		return fmt.Errorf("list failed pods: %w", err) // periodic wrapper IncErrors j.queue
	}

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
		OnError: reap.DeleteErrorHandler("pod", func(t target) string { return t.ns + "/" + t.name },
			func() { metrics.IncError(j.queue) }),
	})
	if capped {
		log.Info("SKIP rest: cap reached", "cap", evictedPodCap)
	}
	log.Info("sweep done", "deleted", deleted, "failed", failed)
	return j.reapUnknownPodsOnReadyNodes(ctx, log)
}

// reapUnknownPodsOnReadyNodes cleans up controller-owned pods stranded
// in ContainerStatusUnknown / PodUnknown on Ready nodes after
// unknownPodMinAge. After an ungraceful node reboot or kubelet/runtime
// disruption, pods left in ContainerStatusUnknown are dead husks that
// controllers never garbage-collect (and StatefulSet/DaemonSet pods
// stay wedged until deleted). Standalone (ownerless) pods are kept
// untouched for debugging, and maintenance-active clusters hold deletes.
func (j *evictedPodJanitor) reapUnknownPodsOnReadyNodes(ctx context.Context, log logr.Logger) error {
	now := j.now.Now()
	nodes, err := kube.ListNodesCached(ctx, j.nodeReader, j.cs)
	if err != nil {
		return fmt.Errorf("list nodes: %w", err)
	}
	readyNodes := make(map[string]bool, len(nodes))
	for i := range nodes {
		if kube.NodeReady(&nodes[i]) {
			readyNodes[nodes[i].Name] = true
		}
	}
	if len(readyNodes) == 0 {
		j.unknownSeen.Prune(func(string) bool { return false })
		return nil
	}

	type target struct {
		ns, name, node, phase, reason string
		uid                           types.UID
		ageMinutes                    int
	}
	var targets []target
	keep := map[string]bool{}
	err = kube.ListEach(ctx, metav1.ListOptions{
		FieldSelector:   "status.phase!=Running,status.phase!=Succeeded,status.phase!=Pending",
		Limit:           kube.DefaultListPageSize,
		ResourceVersion: "0",
	}, kube.Pods(j.cs, metav1.NamespaceAll),
		func(page []corev1.Pod) error {
			for i := range page {
				pod := &page[i]
				if !isStrandedUnknownPod(pod) || !readyNodes[pod.Spec.NodeName] {
					continue
				}
				sig := pod.Namespace + "/" + pod.Name + "/" + string(pod.UID)
				keep[sig] = true
				first, _ := j.unknownSeen.Observe(sig, now)
				age := now.Sub(first)
				if age < unknownPodMinAge {
					continue
				}
				targets = append(targets, target{
					ns:         pod.Namespace,
					name:       pod.Name,
					node:       pod.Spec.NodeName,
					phase:      string(pod.Status.Phase),
					reason:     pod.Status.Reason,
					uid:        pod.UID,
					ageMinutes: int(age.Minutes()),
				})
			}
			return nil
		})
	if err != nil {
		return fmt.Errorf("list unknown pods: %w", err)
	}
	j.unknownSeen.Prune(func(k string) bool { return keep[k] })
	if len(targets) == 0 {
		return nil
	}

	if j.verdict != nil {
		held, why, verr := j.verdict.Active(ctx, j.cs, j.dyn, now)
		if verr != nil {
			log.Info("WARN: maintenance mutex unverifiable — holding unknown-pod deletes", "error", verr)
			metrics.IncError(j.queue)
			return nil
		}
		if held {
			log.Info("SKIP unknown-pod reap: maintenance active", "why", why, "candidates", len(targets))
			return nil
		}
	}

	deleted, failed, capped := reap.Sweep(ctx, log, targets, reap.Options[target]{
		Cap: unknownPodCap,
		LogTarget: func(log logr.Logger, t target) {
			log.Info("DELETE: stranded ContainerStatusUnknown pod on Ready node",
				"pod", t.ns+"/"+t.name, "node", t.node,
				"phase", t.phase, "reason", t.reason, "ageMinutes", t.ageMinutes)
		},
		Delete: func(ctx context.Context, t target) error {
			return j.cs.CoreV1().Pods(t.ns).Delete(ctx, t.name,
				kube.UIDDeleteOptions(t.uid, metav1.DeletePropagationBackground))
		},
		OnError: reap.DeleteErrorHandler("pod", func(t target) string { return t.ns + "/" + t.name },
			func() { metrics.IncError(j.queue) }),
	})
	if capped {
		log.Info("SKIP rest unknown-pods: cap reached", "cap", unknownPodCap)
	}
	log.Info("unknown-pod sweep done", "deleted", deleted, "failed", failed)
	return nil
}

// isStrandedUnknownPod reports whether pod is a controller-owned
// (non-static, non-standalone) pod stuck in PodUnknown or
// ContainerStatusUnknown with no container running.
func isStrandedUnknownPod(pod *corev1.Pod) bool {
	if pod.DeletionTimestamp != nil || pod.Spec.NodeName == "" {
		return false
	}
	if pod.Status.Phase != corev1.PodFailed && pod.Status.Phase != corev1.PodUnknown {
		return false
	}
	if pod.Annotations["kubernetes.io/config.mirror"] != "" {
		return false
	}
	ctrl := metav1.GetControllerOf(pod)
	if ctrl == nil || ctrl.Kind == "Node" {
		return false
	}
	hasUnknownContainer := false
	for _, statuses := range [][]corev1.ContainerStatus{
		pod.Status.ContainerStatuses, pod.Status.InitContainerStatuses,
	} {
		for i := range statuses {
			if statuses[i].State.Running != nil {
				return false
			}
			if t := statuses[i].State.Terminated; t != nil && t.Reason == "ContainerStatusUnknown" {
				hasUnknownContainer = true
			}
		}
	}
	return pod.Status.Phase == corev1.PodUnknown ||
		pod.Status.Reason == "ContainerStatusUnknown" ||
		hasUnknownContainer
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
