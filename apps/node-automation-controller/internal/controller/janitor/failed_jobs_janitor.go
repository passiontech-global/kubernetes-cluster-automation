// Port of hooks/80-failed-jobs-janitor.sh, plus the C3b
// stuck-Terminating auditor.
//
// Deletes Jobs stuck in Failed=True for >24h. CronJob
// failedJobsHistoryLimit only keeps the N most recent failures — manual
// jobs and jobs that failed before the limit existed linger forever,
// wasting storage and cluttering `kubectl get jobs` (nonprod 2026-09-22).
//
// Safety: only Failed=True with a lastTransitionTime older than 24h —
// Active retries and fresh failures (still worth debugging) are kept,
// Complete/Running are never touched. Capped at 50 deletions per run.
//
// auditStuckTerminating (C3b — detect-only): Namespaces and PVCs can
// wedge in Terminating forever when the controller that owns a
// finalizer is gone or itself deadlocked (namespace-controller cannot
// finish an ns whose remaining resources need a deleted API service;
// kubernetes.io/pvc-protection waits on a pod that will never exit).
// Nothing in-tree alerts on it — the object just sits there for days.
// The audit marks each resource Terminating >2h on
// node_automation_stuck_terminating_resources and logs its finalizer
// list — the finalizer names the controller that stopped draining, so
// it is the debugging payload. Detection only: finalizers are never
// stripped automatically (a stripped finalizer on a still-mounted
// volume is a data-loss vector).
package janitor

import (
	"context"
	"fmt"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/controller/shared"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
)

const (
	failedJobQueue  = "failed-jobs-janitor"
	failedJobMaxAge = 24 * time.Hour
	failedJobCap    = 50 // bound delete churn per run

	// stuckTerminatingMaxAge: a DeletionTimestamp older than this is
	// genuinely stuck — every legitimate finalizer drain (pod exit,
	// PVC unprotect, resourcequota reconcile) finishes in seconds to
	// a couple of minutes.
	stuckTerminatingMaxAge = 2 * time.Hour
)

// stuckTerminatingKey identifies one emitted
// StuckTerminatingResources series — the label triple needed to
// delete it again once the resource finishes terminating.
type stuckTerminatingKey struct {
	kind, ns, name string
}

type failedJobsJanitor struct {
	cs kubernetes.Interface
	// nowFn is the clock seam — tests pin it to a fixed instant.
	nowFn func() time.Time
	// stuckEmitted: the kind/ns/name triples the audit marked on the
	// previous sweep. A resource that finished terminating (or
	// vanished) gets its series deleted so /metrics never leaks a
	// stale "stuck" series.
	stuckEmitted map[stuckTerminatingKey]struct{}
}

// SetupFailedJobsJanitor registers the hourly sweep (was crontab 17 * * * *).
func SetupFailedJobsJanitor(mgr ctrl.Manager, cs kubernetes.Interface) error {
	j := &failedJobsJanitor{
		cs:           cs,
		nowFn:        time.Now,
		stuckEmitted: map[stuckTerminatingKey]struct{}{},
	}
	return shared.AddPeriodic(mgr, failedJobQueue, 60*time.Minute, j.run)
}

func (j *failedJobsJanitor) run(ctx context.Context) error {
	log := logf.FromContext(ctx)

	jobs, err := j.cs.BatchV1().Jobs(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	type target struct {
		ns, name string
		ageHours int
	}
	var targets []target
	capped := false
	for i := range jobs.Items {
		job := &jobs.Items[i]
		var failedAt *metav1.Time
		for ci := range job.Status.Conditions {
			c := &job.Status.Conditions[ci]
			if c.Type == batchv1.JobFailed && c.Status == corev1.ConditionTrue && !c.LastTransitionTime.IsZero() {
				failedAt = &c.LastTransitionTime
				break
			}
		}
		if failedAt == nil {
			continue // not failed, or no timestamp — keep
		}
		age := j.nowFn().Sub(failedAt.Time)
		if age <= failedJobMaxAge {
			continue
		}
		if len(targets) >= failedJobCap {
			capped = true
			break
		}
		targets = append(targets, target{
			ns:       job.Namespace,
			name:     job.Name,
			ageHours: int(age.Hours()),
		})
	}
	// Release the cluster-wide JobList before issuing Delete calls.
	jobs = nil

	background := metav1.DeletePropagationBackground
	deleted, failed := 0, 0
	for _, t := range targets {
		log.Info(fmt.Sprintf("DELETE %s/%s: Failed for %dh", t.ns, t.name, t.ageHours))
		if err := j.cs.BatchV1().Jobs(t.ns).Delete(ctx, t.name,
			metav1.DeleteOptions{PropagationPolicy: &background}); err != nil {
			metrics.IncError(failedJobQueue)
			log.Error(err, "job delete failed", "job", t.ns+"/"+t.name)
			failed++
			continue
		}
		deleted++
	}
	if capped {
		log.Info(fmt.Sprintf("SKIP rest: cap=%d reached", failedJobCap))
	}
	log.Info("sweep done", "deleted", deleted, "failed", failed)

	// C3b audit rides the same hourly tick — detect-only, it shares
	// neither the job list nor the delete cap.
	return j.auditStuckTerminating(ctx)
}

// auditStuckTerminating marks every namespace/PVC stuck in
// Terminating past stuckTerminatingMaxAge on
// metrics.StuckTerminatingResources and logs its finalizers — the
// finalizer list is the debugging payload: it names the controller
// that stopped draining (kubernetes.io/pvc-protection, a deleted
// operator's custom finalizer, ...). Detect-only — finalizers are
// never stripped automatically.
//
// Label convention: kind is "Namespace" or "PersistentVolumeClaim".
// For kind=Namespace (cluster-scoped) the "namespace" label is the
// empty string — there is no containing namespace, and repeating the
// object name would only make the two labels redundant.
func (j *failedJobsJanitor) auditStuckTerminating(ctx context.Context) error {
	log := logf.FromContext(ctx)
	now := j.nowFn()

	// Both lists land before any series is emitted — a failed second
	// list must not leave the gauge half-populated for an hour.
	nss, err := j.cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	pvcs, err := j.cs.CoreV1().PersistentVolumeClaims(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	current := map[stuckTerminatingKey]struct{}{}
	mark := func(kind, ns, name string, terminatingSince *metav1.Time, finalizers []string) {
		if terminatingSince == nil ||
			now.Sub(terminatingSince.Time) <= stuckTerminatingMaxAge {
			return // not terminating, or still inside the grace window
		}
		current[stuckTerminatingKey{kind: kind, ns: ns, name: name}] = struct{}{}
		metrics.StuckTerminatingResources.WithLabelValues(kind, ns, name).Set(1)
		log.Info("STUCK: still Terminating past threshold — inspect finalizers",
			"kind", kind, "namespace", ns, "name", name,
			"terminatingFor", now.Sub(terminatingSince.Time).Truncate(time.Minute),
			"finalizers", finalizers)
	}
	for i := range nss.Items {
		n := &nss.Items[i]
		// spec.finalizers is the list the namespace controller drains
		// (metadata.finalizers is not what wedges a Terminating ns).
		mark("Namespace", "", n.Name, n.DeletionTimestamp, nsFinalizerNames(n))
	}
	nss = nil
	for i := range pvcs.Items {
		p := &pvcs.Items[i]
		mark("PersistentVolumeClaim", p.Namespace, p.Name, p.DeletionTimestamp, p.Finalizers)
	}
	pvcs = nil

	// Hygiene: series for resources that finished terminating are
	// deleted, not zeroed — a Set(0) leaves the label triple in
	// /metrics forever, which Prometheus still treats as a live
	// series. Same convention as metrics.ForgetAPIBackend.
	for key := range j.stuckEmitted {
		if _, ok := current[key]; !ok {
			metrics.StuckTerminatingResources.DeleteLabelValues(
				key.kind, key.ns, key.name)
		}
	}
	j.stuckEmitted = current

	log.Info("stuck-terminating audit done", "stuck", len(current))
	return nil
}

// nsFinalizerNames renders .spec.finalizers — the list that actually
// blocks a Terminating namespace — as plain strings for logging.
func nsFinalizerNames(n *corev1.Namespace) []string {
	out := make([]string, 0, len(n.Spec.Finalizers))
	for _, f := range n.Spec.Finalizers {
		out = append(out, string(f))
	}
	return out
}
