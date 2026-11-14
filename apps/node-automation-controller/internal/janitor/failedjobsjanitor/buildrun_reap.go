// buildrun_reap.go — duty 2a of failed-jobs-janitor: the
// buildrun-ttl-sweep completed-run retention sweep (Shipwright
// BuildRuns and Tekton PipelineRuns/TaskRuns reaped past the shared
// 24h horizon under the same retention contract as failed Jobs).
// The orphaned run-workspace PVC reaper those runs leave behind
// lives in workspace_pvc.go.
//
// Shipwright BuildRuns and Tekton PipelineRuns/TaskRuns all report a
// knative-style terminal condition (Succeeded — Failed/Completed are
// accepted too for run kinds that write those instead) plus a
// status.completionTime: anything resolved past the shared 24h horizon
// is reaped under the same retention contract as failed Jobs.
package failedjobsjanitor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/reap"
)

const (
	// completedRunTTL is the shared retention window for terminal CI
	// runs — the original buildrun-ttl-sweep BuildRun horizon, now covering the
	// Tekton run kinds too.
	completedRunTTL = 24 * time.Hour

	// workspacePVCMinAge bounds the orphan-PVC reaper: a claim younger
	// than this may still be a just-finished run's scratch space
	// someone is about to inspect — older, with a gone/terminal owner
	// and no mounting pod, it is pure quota/disk waste.
	workspacePVCMinAge = 6 * time.Hour

	// workspacePVCCap bounds delete attempts per sweep — same churn
	// contract as the failed-Job sweep.
	workspacePVCCap = 50

	// failedJobsDeleteCap bounds the completed-run TTL sweep's delete
	// attempts per sweep: a Tekton pipeline gone unwatched for weeks
	// can park thousands of terminal runs, and uncapped churn would
	// hammer the apiserver for one run — 500 per hourly sweep drains
	// even a four-figure backlog inside a day.
	failedJobsDeleteCap = 500
)

// runTTLKinds is the completed-run retention table. Every kind below
// writes a knative-style terminal condition plus status.completionTime,
// so one filter covers all of them; an absent CRD is a quiet no-op
// (same contract as the Velero audit).
var runTTLKinds = []struct {
	gvr  schema.GroupVersionResource
	kind string
}{
	{kube.GVRShipwrightBuildRun, "buildrun"},
	{kube.GVRTektonPipelineRun, "pipelinerun"},
	{kube.GVRTektonTaskRun, "taskrun"},
}

// runTarget is one vetted terminal-past-TTL run object — everything the
// delete + log lines need carried forward from the filter pass.
type runTarget struct {
	kind         string
	ns, name     string
	uid          types.UID
	completedFor time.Duration
}

// sweepCompletedRuns walks the runTTLKinds table — a failure on one
// kind is joined into the run error without skipping the others (the
// CRDs are independent installs; Tekton can be present without
// Shipwright and vice versa).
func (j *failedJobsJanitor) sweepCompletedRuns(ctx context.Context) error {
	if j.dyn == nil {
		return nil // no dynamic client wired — typed sweeps unaffected
	}
	errs := make([]error, 0, len(runTTLKinds))
	for _, rk := range runTTLKinds {
		errs = append(errs, j.sweepCompletedRunKind(ctx, rk.gvr, rk.kind))
	}
	return errors.Join(errs...)
}

// sweepCompletedRunKind deletes terminal run objects of one kind whose
// finish stamp is older than completedRunTTL. Deletes carry the UID
// precondition like every other delete in this module.
func (j *failedJobsJanitor) sweepCompletedRunKind(ctx context.Context,
	gvr schema.GroupVersionResource, kind string) error {
	log := logf.FromContext(ctx)
	// Streamed pages: the TTL filter extracts only the tiny
	// runTarget tuples (needs status conditions + completionTime, so
	// metadata-only lists cannot serve it), and each page's run
	// bodies die with the page — a four-figure terminal-run backlog
	// no longer materializes as one unstructured slice.
	now := j.now.Now()
	var targets []runTarget
	err := kube.ListEach(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.DynamicPage(j.dyn.Resource(gvr)),
		func(page []unstructured.Unstructured) error {
			for i := range page {
				r := &page[i]
				if r.GetDeletionTimestamp() != nil || !runTerminal(r) {
					continue
				}
				finishedAt, ok := runFinishedAt(r)
				if !ok || now.Sub(finishedAt) <= completedRunTTL {
					continue // resolved but undateable (keep) or inside TTL
				}
				targets = append(targets, runTarget{
					kind:         kind,
					ns:           r.GetNamespace(),
					name:         r.GetName(),
					uid:          r.GetUID(),
					completedFor: now.Sub(finishedAt),
				})
			}
			return nil
		})
	if err != nil {
		if kube.IsCRDAbsent(err) {
			return nil // operator not installed — nothing to reap
		}
		return fmt.Errorf("list %ss: %w", kind, err)
	}

	deleted, _, capped := reap.Sweep(ctx, log, targets, reap.Options[runTarget]{
		Cap: failedJobsDeleteCap,
		LogTarget: func(log logr.Logger, t runTarget) {
			log.Info("DELETE "+t.kind+": completed past TTL",
				t.kind, t.ns+"/"+t.name,
				"completedFor", t.completedFor.Truncate(time.Hour))
		},
		Delete: func(ctx context.Context, t runTarget) error {
			return j.dyn.Resource(gvr).
				Namespace(t.ns).Delete(ctx, t.name,
				kube.UIDDeleteOptions(t.uid, ""))
		},
		OnError: reap.DeleteErrorHandler(kind,
			func(t runTarget) string { return t.ns + "/" + t.name },
			func() { metrics.IncError(j.queue) }),
	})
	if capped {
		log.Info("SKIP rest: cap reached", "cap", failedJobsDeleteCap)
	}
	if deleted > 0 {
		log.Info(kind+" TTL sweep done", "deleted", deleted)
	}
	return nil
}

// runTerminal reports whether a PipelineRun/TaskRun/BuildRun reached a
// terminal state — the knative-style condition set Tekton and
// Shipwright both write. Any of Succeeded/Failed/Completed present
// with status True OR False is a resolved answer; a run still working
// reports Unknown or carries no such condition and stays.
func runTerminal(obj *unstructured.Unstructured) bool {
	for _, condType := range []string{"Succeeded", "Failed", "Completed"} {
		c, found := kube.ConditionOf(obj.Object, condType)
		if found && (c.Status == "True" || c.Status == "False") {
			return true
		}
	}
	return false
}

// runFinishedAt returns when the run resolved: status.completionTime
// first, then the terminal condition's own lastTransitionTime — the
// fallback ages objects whose controller resolved the run without
// stamping completionTime (older Shipwright/Tekton builds), which the
// BuildRun-only sweep used to keep forever.
func runFinishedAt(obj *unstructured.Unstructured) (time.Time, bool) {
	if t, found := kube.NestedTime(obj.Object, "status", "completionTime"); found {
		return t, true
	}
	for _, condType := range []string{"Succeeded", "Failed", "Completed"} {
		c, found := kube.ConditionOf(obj.Object, condType)
		if found && (c.Status == "True" || c.Status == "False") &&
			!c.LastTransitionTime.IsZero() {
			return c.LastTransitionTime, true
		}
	}
	return time.Time{}, false
}
