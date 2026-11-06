// buildrun_reap.go — duty 2 of failed-jobs-janitor: the W9-GO2
// Shipwright BuildRun TTL sweep — same 24h retention horizon as
// failed Jobs.
package failedjobsjanitor

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/reap"
)

// buildRunTTL is the W9-GO2 retention window for completed
// Shipwright BuildRuns — same 24h horizon as failed Jobs.
const buildRunTTL = 24 * time.Hour

// buildRunGVR is the Shipwright BuildRun CRD — absent on clusters
// without the Shipwright operator, in which case the sweep is a quiet
// no-op (404/NoMatch tolerated, same contract as the Velero audit).
var buildRunGVR = kube.GVRShipwrightBuildRun

// buildRunTarget is one vetted completed-past-TTL BuildRun.
type buildRunTarget struct {
	ns, name     string
	uid          types.UID
	completedFor time.Duration
}

// sweepBuildRuns deletes completed Shipwright BuildRuns whose
// status.completionTime is older than buildRunTTL. "Completed" means
// status.conditions carries Succeeded=True OR Succeeded=False — both
// are terminal; a build still running or one that never reported a
// condition is kept. Deletes carry the UID precondition like every
// other delete in this module, and the whole sweep is a quiet no-op
// when the Shipwright CRD is absent.
func (j *failedJobsJanitor) sweepBuildRuns(ctx context.Context) error {
	if j.dyn == nil {
		return nil // no dynamic client wired — typed sweeps unaffected
	}
	log := logf.FromContext(ctx)
	brs, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.DynamicPage(j.dyn.Resource(buildRunGVR)))
	if err != nil {
		if apierrors.IsNotFound(err) || meta.IsNoMatchError(err) {
			return nil // Shipwright not installed — nothing to reap
		}
		return fmt.Errorf("list buildruns: %w", err)
	}
	now := j.now.Now()
	var targets []buildRunTarget
	for i := range brs {
		br := &brs[i]
		if br.GetDeletionTimestamp() != nil || !buildRunCompleted(br) {
			continue
		}
		ct, found := kube.NestedString(
			br.Object, "status", "completionTime")
		if !found {
			continue // completed but no timestamp — can't age it, keep
		}
		completedAt, err := time.Parse(time.RFC3339, ct)
		if err != nil || now.Sub(completedAt) <= buildRunTTL {
			continue
		}
		targets = append(targets, buildRunTarget{
			ns:           br.GetNamespace(),
			name:         br.GetName(),
			uid:          br.GetUID(),
			completedFor: now.Sub(completedAt),
		})
	}
	brs = nil

	deleted, _, _ := reap.Sweep(ctx, log, targets, reap.Options[buildRunTarget]{
		LogTarget: func(log logr.Logger, t buildRunTarget) {
			log.Info("DELETE buildrun: completed past TTL",
				"buildrun", t.ns+"/"+t.name,
				"completedFor", t.completedFor.Truncate(time.Hour))
		},
		Delete: func(ctx context.Context, t buildRunTarget) error {
			return j.dyn.Resource(buildRunGVR).
				Namespace(t.ns).Delete(ctx, t.name,
				kube.UIDDeleteOptions(t.uid, ""))
		},
		OnError: func(log logr.Logger, t buildRunTarget, err error) {
			metrics.IncError(j.queue)
			log.Error(err, "buildrun delete failed",
				"buildrun", t.ns+"/"+t.name)
		},
	})
	if deleted > 0 {
		log.Info("buildrun TTL sweep done", "deleted", deleted)
	}
	return nil
}

// buildRunCompleted reports whether the BuildRun reached a terminal
// state — status.conditions contains type=Succeeded with status
// True (passed) or False (failed). Running builds and builds whose
// controller never wrote the condition stay.
func buildRunCompleted(br *unstructured.Unstructured) bool {
	c, found := kube.ConditionOf(br.Object, "Succeeded")
	return found && (c.Status == "True" || c.Status == "False")
}
