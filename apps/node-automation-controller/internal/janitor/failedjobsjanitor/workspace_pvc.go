// workspace_pvc.go — duty 2b of failed-jobs-janitor: the
// run-workspace-reaper half of the buildrun sweep — the orphaned
// run-workspace PVC reaper (split out of buildrun_reap.go — see its
// header for the run-retention contract and the run kinds).
package failedjobsjanitor

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/reap"
)

// ---------------------------------------------------------------------------
// run-workspace-reaper — orphaned run-workspace PVC reaper
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
// controller stamps on generated resources). All of it is ObjectMeta,
// so the census's PartialObjectMetadata objects feed it directly.
func workspacePVCRefs(pvc *metav1.PartialObjectMetadata) []workspacePVCRef {
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
		return kube.JobTerminal(job), nil
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
	case kube.IsCRDAbsent(err):
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
// reference — the same per-namespace scan the va-stuck-terminating pvc-protection
// unstick runs (Succeeded/Failed pods released their volumes; every
// other phase — including Pending pods not yet mounted — counts as a
// claimant, fail closed). Generic ephemeral volumes count too: their
// implicit <pod>-<volume> claim carries the same kubelet
// pvc-protection finalizer a pre-provisioned claim does.
func (j *failedJobsJanitor) claimedPVCNames(ctx context.Context,
	ns string) (map[string]bool, error) {
	claims := map[string]bool{}
	// Streamed pages — the scan only accumulates claim names, so each
	// page's pod bodies die with the page (needs Spec.Volumes +
	// Status.Phase, so metadata lists cannot serve it).
	err := kube.ListEach(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.Pods(j.cs, ns),
		func(page []corev1.Pod) error {
			for i := range page {
				p := &page[i]
				if p.Status.Phase == corev1.PodSucceeded ||
					p.Status.Phase == corev1.PodFailed {
					continue
				}
				for _, claim := range kube.PodClaimedPVCs(p) {
					claims[claim] = true
				}
			}
			return nil
		})
	if err != nil {
		return nil, err
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
		OnError: reap.DeleteErrorHandler("pvc",
			func(t orphanWorkspaceTarget) string { return t.ns + "/" + t.name },
			func() { metrics.IncError(j.queue) }),
	})
	if capped {
		log.Info("SKIP rest: cap reached", "cap", workspacePVCCap)
	}
	if deleted > 0 {
		log.Info("orphan workspace pvc sweep done", "deleted", deleted)
	}
	return nil
}
