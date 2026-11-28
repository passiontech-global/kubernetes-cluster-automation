// cronjob-catchup spawn: clone the CronJob's JobTemplate into a
// catch-up Job and enforce the in-memory 1-per-cronjob-per-day cap.
// split from cronjob_catchup.go (see its header for the module contract).
package cronjobcatchup

import (
	"context"
	"fmt"
	"maps"
	"strings"

	"github.com/go-logr/logr"
	batchv1 "k8s.io/api/batch/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
)

// capped enforces the in-memory 1-catchup-per-cronjob-per-day limit
// and prunes expired prior-day entries so lastCatchup stays bounded.
func (c *cronJobCatchup) capped(key string) bool {
	today := c.now.Now().UTC().Format("2006-01-02")
	if c.lastCatchup == nil {
		c.lastCatchup = map[string]string{}
		return false
	}
	for k, day := range c.lastCatchup {
		if day != today {
			delete(c.lastCatchup, k)
		}
	}
	// The day stamp comes from the clock seam so a pinned now really
	// pins "today" — tests call capped() on a literally-built struct.
	return c.lastCatchup[key] == today
}

// spawn clones the CronJob's JobTemplate into a <cj>-catchup-<unix>
// Job in the CronJob's own namespace — the kubectl create job
// --from=cronjob equivalent (labels/annotations cloned, spec
// DeepCopy'd, cronjob.kubernetes.io/instantiate: manual stamped),
// plus the missed-catchup label that powers dedupe. A create failure
// is metered+logged but does not abort the sweep or arm the daily
// cap — the next tick retries. Reports whether the Job was created.
func (c *cronJobCatchup) spawn(ctx context.Context, log logr.Logger, cj *batchv1.CronJob, key string) bool {
	// Live quorum confirm: the sweep's CronJob list reads the watch
	// cache (RV="0"), so re-confirm against the live apiserver before
	// cloning a Job (zero steady-state cost — runs only on a spawn).
	liveCJ, err := c.cs.BatchV1().CronJobs(cj.Namespace).Get(ctx, cj.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		log.Info("skip: cronjob gone before catch-up spawn", "cronjob", key)
		return false
	}
	if err != nil {
		metrics.IncError(c.queue)
		log.Error(err, "live cronjob get failed — catch-up spawn skipped (fail closed)",
			"cronjob", key)
		return false
	}
	if liveCJ.DeletionTimestamp != nil ||
		(liveCJ.Spec.Suspend != nil && *liveCJ.Spec.Suspend) ||
		liveCJ.Annotations[catchupAnno] != "true" ||
		len(liveCJ.Status.Active) > 0 {
		log.Info("skip: live cronjob no longer eligible for catch-up", "cronjob", key)
		return false
	}
	if stale, ok := c.stale(log, liveCJ); !ok || !stale {
		log.Info("skip: live cronjob no longer stale for catch-up", "cronjob", key)
		return false
	}

	// One read of the clock seam feeds both the Job-name suffix and
	// the daily-cap stamp — a pinned now (tests) must pin both,
	// and on a real clock the two can never straddle midnight.
	now := c.now.Now()
	labels := maps.Clone(liveCJ.Spec.JobTemplate.Labels)
	if labels == nil {
		labels = map[string]string{}
	}
	labels[catchupLabel] = liveCJ.Name
	annotations := maps.Clone(liveCJ.Spec.JobTemplate.Annotations)
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations["cronjob.kubernetes.io/instantiate"] = "manual"
	// DNS-1123 subdomain caps the Job name at 63 chars but a CronJob
	// name can reach 52 — a naive "<cj>-catchup-<unix>" overflows and
	// Create fails Invalid forever. Truncate the CronJob-name portion
	// so the always-meaningful suffix fits, and drop trailing
	// separators so the name still ends alphanumeric.
	suffix := fmt.Sprintf("-catchup-%d", now.Unix())
	name := liveCJ.Name
	if max := catchupJobNameMax - len(suffix); len(name) > max {
		name = strings.TrimRight(name[:max], "-.")
	}
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name + suffix,
			Namespace:   liveCJ.Namespace,
			Labels:      labels,
			Annotations: annotations,
			// Owner the catch-up Job to its CronJob: the Job
			// controller's concurrencyPolicy (Forbid/Replace)
			// counts only owned Jobs, and ownerRef GC reaps the
			// catch-up with its CronJob instead of stranding it.
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(liveCJ,
					batchv1.SchemeGroupVersion.WithKind("CronJob")),
			},
		},
		Spec: *liveCJ.Spec.JobTemplate.Spec.DeepCopy(),
	}
	if _, err := c.cs.BatchV1().Jobs(liveCJ.Namespace).Create(ctx, job, metav1.CreateOptions{}); err != nil {
		metrics.IncError(c.queue)
		log.Error(err, "create catch-up job failed",
			"cronjob", liveCJ.Namespace+"/"+liveCJ.Name, "job", job.Name)
		return false
	}
	if c.lastCatchup == nil {
		c.lastCatchup = map[string]string{}
	}
	c.lastCatchup[key] = now.UTC().Format("2006-01-02")
	log.Info("CATCHUP job", "job", job.Name,
		"cronjob", liveCJ.Namespace+"/"+liveCJ.Name,
		"lastSchedule", liveCJ.Status.LastScheduleTime)
	return true
}
