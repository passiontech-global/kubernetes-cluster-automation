// Port of hooks/80-failed-jobs-janitor.sh.
//
// Deletes Jobs stuck in Failed=True for >24h. CronJob
// failedJobsHistoryLimit only keeps the N most recent failures — manual
// jobs and jobs that failed before the limit existed linger forever,
// wasting storage and cluttering `kubectl get jobs` (nonprod 2026-09-22).
//
// Safety: only Failed=True with a lastTransitionTime older than 24h —
// Active retries and fresh failures (still worth debugging) are kept,
// Complete/Running are never touched. Capped at 50 deletions per run.
package controller

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

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
)

const (
	failedJobQueue  = "failed-jobs-janitor"
	failedJobMaxAge = 24 * time.Hour
	failedJobCap    = 50 // bound delete churn per run
)

type failedJobsJanitor struct {
	cs kubernetes.Interface
}

// SetupFailedJobsJanitor registers the hourly sweep (was crontab 17 * * * *).
func SetupFailedJobsJanitor(mgr ctrl.Manager, cs kubernetes.Interface) error {
	j := &failedJobsJanitor{cs: cs}
	return addPeriodic(mgr, failedJobQueue, 60*time.Minute, j.run)
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
		age := time.Since(failedAt.Time)
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
	return nil
}
