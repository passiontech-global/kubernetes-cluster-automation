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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
)

// capped enforces the in-memory 1-catchup-per-cronjob-per-day limit.
func (c *cronJobCatchup) capped(key string) bool {
	if c.lastCatchup == nil {
		c.lastCatchup = map[string]string{}
	}
	// The day stamp comes from the clock seam so a pinned now really
	// pins "today" — tests call capped() on a literally-built struct.
	return c.lastCatchup[key] == c.now.Now().UTC().Format("2006-01-02")
}

// spawn clones the CronJob's JobTemplate into a <cj>-catchup-<unix>
// Job in the CronJob's own namespace — the kubectl create job
// --from=cronjob equivalent (labels/annotations cloned, spec
// DeepCopy'd, cronjob.kubernetes.io/instantiate: manual stamped),
// plus the missed-catchup label that powers dedupe. A create failure
// is metered+logged but does not abort the sweep or arm the daily
// cap — the next tick retries. Reports whether the Job was created.
func (c *cronJobCatchup) spawn(ctx context.Context, log logr.Logger, cj *batchv1.CronJob, key string) bool {
	// One read of the clock seam feeds both the Job-name suffix and
	// the daily-cap stamp — a pinned now (tests) must pin both,
	// and on a real clock the two can never straddle midnight.
	now := c.now.Now()
	labels := maps.Clone(cj.Spec.JobTemplate.Labels)
	if labels == nil {
		labels = map[string]string{}
	}
	labels[catchupLabel] = cj.Name
	annotations := maps.Clone(cj.Spec.JobTemplate.Annotations)
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
	name := cj.Name
	if max := catchupJobNameMax - len(suffix); len(name) > max {
		name = strings.TrimRight(name[:max], "-.")
	}
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name + suffix,
			Namespace:   cj.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: *cj.Spec.JobTemplate.Spec.DeepCopy(),
	}
	if _, err := c.cs.BatchV1().Jobs(cj.Namespace).Create(ctx, job, metav1.CreateOptions{}); err != nil {
		metrics.IncError(c.queue)
		log.Error(err, "create catch-up job failed",
			"cronjob", cj.Namespace+"/"+cj.Name, "job", job.Name)
		return false
	}
	c.lastCatchup[key] = now.UTC().Format("2006-01-02")
	log.Info("CATCHUP job", "job", job.Name,
		"cronjob", cj.Namespace+"/"+cj.Name,
		"lastSchedule", cj.Status.LastScheduleTime)
	return true
}
