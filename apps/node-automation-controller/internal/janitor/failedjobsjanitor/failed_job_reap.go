// failed_job_reap.go — duty 1 of failed-jobs-janitor: the failed-Job
// retention sweep (port of hooks/80-failed-jobs-janitor.sh).
//
// Deletes Jobs stuck in Failed=True for >24h. Safety: only Failed=True
// with a lastTransitionTime older than 24h — Active retries and fresh
// failures (still worth debugging) are kept, Complete/Running are
// never touched. Capped at 50 delete attempts per run to bound churn.
package failedjobsjanitor

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/reap"
)

const (
	failedJobMaxAge = 24 * time.Hour
	failedJobCap    = 50 // bound delete churn per run
)

// failedJobTarget is one vetted Job past retention — everything the
// delete + log lines need carried forward from the filter pass.
type failedJobTarget struct {
	ns, name string
	uid      types.UID
	ageHours int
}

func (j *failedJobsJanitor) sweepFailedJobs(ctx context.Context) error {
	log := logf.FromContext(ctx)

	// Streamed pages, not a materialized cluster-wide job slice: the
	// filter pass needs Status.Conditions (metadata-only lists cannot
	// serve it), but it only ever extracts the tiny failedJobTarget
	// tuples — each page's objects die with the page instead of
	// pinning every Job in the cluster until the deletes run.
	var targets []failedJobTarget
	err := kube.ListEach(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.Jobs(j.cs, metav1.NamespaceAll),
		func(page []batchv1.Job) error {
			for i := range page {
				job := &page[i]
				if job.DeletionTimestamp != nil {
					continue // already terminating — a second delete just burns a cap slot
				}
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
				age := j.now.Now().Sub(failedAt.Time)
				if age <= failedJobMaxAge {
					continue
				}
				targets = append(targets, failedJobTarget{
					ns:       job.Namespace,
					name:     job.Name,
					uid:      job.UID,
					ageHours: int(age.Hours()),
				})
			}
			return nil
		})
	if err != nil {
		return fmt.Errorf("list jobs: %w", err)
	}

	deleted, failed, capped := reap.Sweep(ctx, log, targets, reap.Options[failedJobTarget]{
		// The cap bounds delete attempts (failed deletes churn the
		// apiserver the same way) — leftover targets drain next run.
		Cap: failedJobCap,
		LogTarget: func(log logr.Logger, t failedJobTarget) {
			log.Info("DELETE: Failed past retention",
				"job", t.ns+"/"+t.name, "failedForHours", t.ageHours)
		},
		Delete: func(ctx context.Context, t failedJobTarget) error {
			// UID precondition: the listed object is what we vetted — a
			// same-named Job recreated in between must not inherit the
			// delete.
			return j.cs.BatchV1().Jobs(t.ns).Delete(ctx, t.name,
				kube.UIDDeleteOptions(t.uid, metav1.DeletePropagationBackground))
		},
		OnError: func(log logr.Logger, t failedJobTarget, err error) {
			switch {
			case apierrors.IsNotFound(err):
				// The Job was deleted under us — raced with an
				// external cleanup; nothing failed.
				log.Info("SKIP: job already gone — raced with an external delete",
					"job", t.ns+"/"+t.name)
			case apierrors.IsConflict(err):
				// The UID precondition fired — a same-named Job was
				// recreated since the list; not ours to reap.
				log.Info("SKIP: job recreated since the list — UID precondition fired",
					"job", t.ns+"/"+t.name)
			default:
				metrics.IncError(j.queue)
				log.Error(err, "job delete failed",
					"job", t.ns+"/"+t.name, "failedForHours", t.ageHours)
			}
		},
	})
	if capped {
		log.Info("SKIP rest: cap reached", "cap", failedJobCap)
	}
	log.Info("sweep done", "deleted", deleted, "failed", failed)
	return nil
}
