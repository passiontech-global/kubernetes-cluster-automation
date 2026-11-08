// buildrun_reap.go — duty 2 of failed-jobs-janitor: the W9-GO2/W12-GO2
// completed-run retention sweep plus the orphaned run-workspace PVC
// reaper.
//
// Shipwright BuildRuns and Tekton PipelineRuns/TaskRuns all report a
// knative-style terminal condition (Succeeded — Failed/Completed are
// accepted too for run kinds that write those instead) plus a
// status.completionTime: anything resolved past the shared 24h horizon
// is reaped under the same retention contract as failed Jobs.
//
// The second half reaps the workspace PVCs those runs leave behind: a
// volumeClaimTemplate claim whose owning run (PipelineRun, TaskRun,
// BuildRun or Job — resolved through ownerReferences AND the
// tekton.dev/shipwright.io workspace labels, because some Tekton paths
// create the claim without an ownerReference, or the ownerRef outlives
// the object it points at) is gone or terminal, which no non-terminal
// pod mounts, and which is older than 6h is pure ResourceQuota/disk
// waste — on the cicd cluster these pile up until every new build
// pends (W12-GO2).
package failedjobsjanitor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
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
	// runs — the original W9-GO2 BuildRun horizon, now covering the
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
	runs, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.DynamicPage(j.dyn.Resource(gvr)))
	if err != nil {
		if apierrors.IsNotFound(err) || meta.IsNoMatchError(err) {
			return nil // operator not installed — nothing to reap
		}
		return fmt.Errorf("list %ss: %w", kind, err)
	}
	now := j.now.Now()
	var targets []runTarget
	for i := range runs {
		r := &runs[i]
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
	runs = nil

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
		OnError: func(log logr.Logger, t runTarget, err error) {
			switch {
			case apierrors.IsNotFound(err):
				// The run was deleted under us — raced with its
				// operator's own TTL cleaner; nothing failed.
				log.Info("SKIP: "+kind+" already gone — raced with an external delete",
					kind, t.ns+"/"+t.name)
			case apierrors.IsConflict(err):
				// The UID precondition fired — a same-named run was
				// recreated since the list; not ours to reap.
				log.Info("SKIP: "+kind+" recreated since the list — UID precondition fired",
					kind, t.ns+"/"+t.name)
			default:
				metrics.IncError(j.queue)
				log.Error(err, kind+" delete failed",
					kind, t.ns+"/"+t.name)
			}
		},
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
	if ct, found := kube.NestedString(obj.Object, "status", "completionTime"); found {
		if t, err := time.Parse(time.RFC3339, ct); err == nil {
			return t, true
		}
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

// ---------------------------------------------------------------------------
// W12-GO2 — orphaned run-workspace PVC reaper
// ---------------------------------------------------------------------------

// workspacePVCRef is one owning-run pointer harvested from a PVC — an
// ownerReference of a run kind, or a workspace label Tekton/Shipwright
// stamp on their volumeClaimTemplate claims. The labels matter as much
// as the ownerReferences: some Tekton paths create the workspace claim
// with labels only, and a label is what survives when the ownerRef's
// UID target is already gone.
type workspacePVCRef struct {
	kind string // "PipelineRun", "TaskRun", "BuildRun" or "Job"
	name string
}

// workspacePVCRefs harvests every run-object pointer a PVC carries:
// ownerReferences of the run kinds plus the tekton.dev/pipelineRun,
// tekton.dev/taskRun, shipwright.io/buildRun and
// buildrun.shipwright.io/name labels (the two Shipwright spellings
// both appear in the wild — the annotation-style label is what the
// controller stamps on generated resources).
func workspacePVCRefs(pvc *corev1.PersistentVolumeClaim) []workspacePVCRef {
	var refs []workspacePVCRef
	seen := map[workspacePVCRef]bool{}
	add := func(kind, name string) {
		ref := workspacePVCRef{kind: kind, name: name}
		if name == "" || seen[ref] {
			return
		}
		seen[ref] = true
		refs = append(refs, ref)
	}
	for _, or := range pvc.OwnerReferences {
		switch or.Kind {
		case "PipelineRun", "TaskRun", "BuildRun", "Job":
			add(or.Kind, or.Name)
		}
	}
	labels := pvc.Labels
	add("PipelineRun", labels["tekton.dev/pipelineRun"])
	add("TaskRun", labels["tekton.dev/taskRun"])
	add("BuildRun", labels["shipwright.io/buildRun"])
	add("BuildRun", labels["buildrun.shipwright.io/name"])
	return refs
}

// runRefGVR maps an ownerReference/label run kind to its serving GVR —
// Job resolves through the typed clientset instead and never reaches
// this table.
func runRefGVR(kind string) (schema.GroupVersionResource, bool) {
	switch kind {
	case "PipelineRun":
		return kube.GVRTektonPipelineRun, true
	case "TaskRun":
		return kube.GVRTektonTaskRun, true
	case "BuildRun":
		return kube.GVRShipwrightBuildRun, true
	}
	return schema.GroupVersionResource{}, false
}

// runRefDone reports whether the run a PVC ref points at is gone from
// the API server or already terminal — the "nobody will read this
// workspace again" verdict. A non-NotFound lookup error is "cannot
// prove": the caller keeps the claim (fail closed). An uninstalled
// CRD reads as gone: a PipelineRun cannot be live where tekton.dev
// does not exist.
func (j *failedJobsJanitor) runRefDone(ctx context.Context, ns string,
	ref workspacePVCRef) (bool, error) {
	if ref.kind == "Job" {
		job, err := j.cs.BatchV1().Jobs(ns).Get(ctx, ref.name, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			return true, nil
		case err != nil:
			return false, err
		}
		if job.DeletionTimestamp != nil {
			return true, nil // already on its way out
		}
		for _, c := range job.Status.Conditions {
			if (c.Type == batchv1.JobComplete || c.Type == batchv1.JobFailed) &&
				c.Status == corev1.ConditionTrue {
				return true, nil
			}
		}
		return false, nil
	}
	gvr, ok := runRefGVR(ref.kind)
	if !ok || j.dyn == nil {
		// Unknown kind (never happens — refs are built from the same
		// table) or no dyn client: cannot prove the owner is gone, so
		// the claim is kept rather than risk a live workspace.
		return false, nil
	}
	obj, err := j.dyn.Resource(gvr).Namespace(ns).Get(ctx, ref.name, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		return true, nil
	case err != nil:
		return false, err
	}
	if obj.GetDeletionTimestamp() != nil {
		return true, nil
	}
	return runTerminal(obj), nil
}

// claimedPVCNames lists the claim names non-terminal pods in ns still
// reference — the same per-namespace scan the W4 pvc-protection
// unstick runs (Succeeded/Failed pods released their volumes; every
// other phase — including Pending pods not yet mounted — counts as a
// claimant, fail closed). Generic ephemeral volumes count too: their
// implicit <pod>-<volume> claim carries the same kubelet
// pvc-protection finalizer a pre-provisioned claim does.
func (j *failedJobsJanitor) claimedPVCNames(ctx context.Context,
	ns string) (map[string]bool, error) {
	pods, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.Pods(j.cs, ns))
	if err != nil {
		return nil, err
	}
	claims := map[string]bool{}
	for i := range pods {
		p := &pods[i]
		if p.Status.Phase == corev1.PodSucceeded ||
			p.Status.Phase == corev1.PodFailed {
			continue
		}
		for _, v := range p.Spec.Volumes {
			switch {
			case v.PersistentVolumeClaim != nil:
				claims[v.PersistentVolumeClaim.ClaimName] = true
			case v.Ephemeral != nil:
				// The ephemeral controller names the claim
				// <pod>-<volume>; treating it as unclaimed could strip
				// its protection finalizer while the pod still mounts it.
				claims[p.Name+"-"+v.Name] = true
			}
		}
	}
	return claims, nil
}

// orphanWorkspaceTarget is one candidate claim: old enough, carrying
// at least one run ref, unmounted at collect time. Confirm re-vets
// the owner refs live before the delete.
type orphanWorkspaceTarget struct {
	ns, name string
	uid      types.UID
	refs     []workspacePVCRef
	age      time.Duration
}

// sweepOrphanWorkspacePVCs deletes workspace PVCs whose every run ref
// is gone or terminal and which no non-terminal pod mounts. Orphan
// collection is exempt from the maintenance mutex like every GC in
// this module — the mutex defers heal churn, not cleanup. census is
// the run-shared PVC/pod-scan read share (see pvcCensus); nil means
// an unshared private census (test fixtures driving one duty).
func (j *failedJobsJanitor) sweepOrphanWorkspacePVCs(ctx context.Context,
	census *pvcCensus) error {
	if census == nil {
		census = &pvcCensus{}
	}
	log := logf.FromContext(ctx)
	now := j.now.Now()
	pvcs, err := census.listPVCs(ctx, j)
	if err != nil {
		return fmt.Errorf("list persistentvolumeclaims: %w", err)
	}

	// claimsCache lazily fills one "who still claims what" pod scan per
	// candidate namespace — shared between the collect filter and the
	// stuck-terminating audit so a namespace is listed at most once per
	// RUN, not once per duty. Confirm deliberately does NOT ride the
	// cache: its verdict re-queries pods fresh, because the snapshot
	// from sweep start goes stale as this run's own deletes land.
	claimsCache := census.claims()
	claimed := func(ns, name string) bool {
		pr, ok := claimsCache[ns]
		if !ok {
			pr = pvcUseProbe{}
			pr.claims, pr.err = j.claimedPVCNames(ctx, ns)
			if pr.err != nil {
				metrics.IncError(j.queue)
				log.Error(pr.err, "pod list failed — treating claims as mounted (fail closed)",
					"namespace", ns)
			}
			claimsCache[ns] = pr
		}
		// An unverifiable namespace reads as "still mounted" — the
		// claim is kept rather than risk deleting live storage.
		return pr.err != nil || pr.claims[name]
	}

	var targets []orphanWorkspaceTarget
	for i := range pvcs {
		pvc := &pvcs[i]
		if pvc.DeletionTimestamp != nil {
			continue // already terminating — a second delete burns a cap slot
		}
		age := now.Sub(pvc.CreationTimestamp.Time)
		if age <= workspacePVCMinAge {
			continue // too fresh to call orphaned
		}
		refs := workspacePVCRefs(pvc)
		if len(refs) == 0 {
			continue // not a run-workspace claim at all
		}
		if claimed(pvc.Namespace, pvc.Name) {
			continue
		}
		targets = append(targets, orphanWorkspaceTarget{
			ns: pvc.Namespace, name: pvc.Name, uid: pvc.UID,
			refs: refs, age: age,
		})
	}
	pvcs = nil

	deleted, _, capped := reap.Sweep(ctx, log, targets, reap.Options[orphanWorkspaceTarget]{
		Cap: workspacePVCCap,
		// Deterministic victims: a capped sweep reaps the same
		// namespace/name-ordered claims every cycle.
		Less: func(a, b orphanWorkspaceTarget) bool {
			if a.ns != b.ns {
				return a.ns < b.ns
			}
			return a.name < b.name
		},
		// Confirm re-vets live state close to the delete: a FRESH
		// per-namespace pod re-query (the collect-time claimsCache
		// predates this run's deletes and the minutes since), and
		// EVERY owner ref still gone-or-terminal (a run recreated or
		// re-Resumed since the list keeps its workspace).
		Confirm: func(ctx context.Context, t orphanWorkspaceTarget) (bool, error) {
			freshClaims, err := j.claimedPVCNames(ctx, t.ns)
			if err != nil {
				return false, err // cannot prove — keep, report via OnError
			}
			if freshClaims[t.name] {
				return false, nil // a pod mounted the claim since collect
			}
			for _, ref := range t.refs {
				done, err := j.runRefDone(ctx, t.ns, ref)
				if err != nil {
					return false, err // cannot prove — keep, report via OnError
				}
				if !done {
					return false, nil
				}
			}
			return true, nil
		},
		LogTarget: func(log logr.Logger, t orphanWorkspaceTarget) {
			log.Info("DELETE pvc: orphaned run-workspace claim — owner gone/terminal",
				"pvc", t.ns+"/"+t.name,
				"age", t.age.Truncate(time.Hour),
				"owners", t.refs)
		},
		Delete: func(ctx context.Context, t orphanWorkspaceTarget) error {
			return j.cs.CoreV1().PersistentVolumeClaims(t.ns).Delete(ctx, t.name,
				kube.UIDDeleteOptions(t.uid, metav1.DeletePropagationBackground))
		},
		OnError: func(log logr.Logger, t orphanWorkspaceTarget, err error) {
			switch {
			case apierrors.IsNotFound(err):
				// The PVC was deleted under us — raced with its
				// owner's workspace cleanup; nothing failed.
				log.Info("SKIP: pvc already gone — raced with an external delete",
					"pvc", t.ns+"/"+t.name)
			case apierrors.IsConflict(err):
				// The UID precondition fired — a same-named claim was
				// recreated since the list; not ours to reap.
				log.Info("SKIP: pvc recreated since the list — UID precondition fired",
					"pvc", t.ns+"/"+t.name)
			default:
				metrics.IncError(j.queue)
				log.Error(err, "orphan workspace pvc sweep failed",
					"pvc", t.ns+"/"+t.name)
			}
		},
	})
	if capped {
		log.Info("SKIP rest: cap reached", "cap", workspacePVCCap)
	}
	if deleted > 0 {
		log.Info("orphan workspace pvc sweep done", "deleted", deleted)
	}
	return nil
}
