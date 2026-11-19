// cronjob-catchup TooManyMissedStarts auto-unfreezer: stamp
// startingDeadlineSeconds on CronJobs the controller permanently
// skipped past the >100-missed-starts cap.
// split from cronjob_catchup.go (see its header for the module contract).
package cronjobcatchup

import (
	"context"
	json "encoding/json/v2"
	"time"

	"github.com/go-logr/logr"
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// unfreezeDeadline stamps spec.startingDeadlineSeconds=3600 plus the
// provenance annotation onto a CronJob that crossed the >100-missed
// cap — the controller treats the deadline as "count misses only
// inside the window", so the job schedules again instead of being
// skipped forever. Merge patch: the annotation adds a single key and
// the spec field cannot clobber a concurrent writer's spec edits
// (merge preserves every key not named). A patch failure is
// metered+logged but absorbed — the next sweep retries. Reports
// whether the patch landed so the caller can skip its own catch-up
// spawn this cycle (KCM creates the recovery Job itself).
func (c *cronJobCatchup) unfreezeDeadline(ctx context.Context, log logr.Logger, cj *batchv1.CronJob, now time.Time) bool {
	// MergePatchAnnos builds the annotations half; the spec field is
	// grafted onto the same doc so the provenance stamp and the
	// deadline land in ONE merge patch (merge preserves every key
	// not named, so a concurrent spec writer is not clobbered).
	payload, err := kube.MergePatchAnnos(map[string]any{
		deadlinePatchedAnno: now.UTC().Format(time.RFC3339),
	})
	if err == nil {
		var doc map[string]any
		if err = json.Unmarshal(payload, &doc); err == nil {
			doc["spec"] = map[string]any{
				"startingDeadlineSeconds": deadlinePatchSeconds,
			}
			payload, err = json.Marshal(doc)
		}
	}
	if err != nil {
		metrics.IncError(c.queue)
		log.Error(err, "marshal deadline patch",
			"cronjob", cj.Namespace+"/"+cj.Name)
		return false
	}
	// Flux-owned CronJobs get their spec reverted by the GitOps
	// reconcile — stamping startingDeadlineSeconds on one is the
	// patch half of a Heal-Revert Loop, so the shared conflict gate
	// decides (report, never fight).
	if !heal.FluxPatchGate("cronjob", cj, cj.Namespace+"/"+cj.Name, now) {
		log.Info("skip: startingDeadlineSeconds patch gated — Flux owns this CronJob",
			"cronjob", cj.Namespace+"/"+cj.Name)
		return false
	}
	if _, err := c.cs.BatchV1().CronJobs(cj.Namespace).Patch(ctx, cj.Name,
		types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		metrics.IncError(c.queue)
		log.Error(err, "startingDeadlineSeconds patch failed",
			"cronjob", cj.Namespace+"/"+cj.Name)
		return false
	}
	log.Info("PATCH: startingDeadlineSeconds=3600 — CronJob crossed the >100 missed-start cap",
		"cronjob", cj.Namespace+"/"+cj.Name,
		"schedule", cj.Spec.Schedule)
	return true
}
