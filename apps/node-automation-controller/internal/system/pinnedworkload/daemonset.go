// daemonset.go — DaemonSetSpec: the shared reconcile skeleton for the
// pinned-DaemonSet patchers (konnectivity-agent): Get → NotFound skip
// → Drifted → missing-container guard → Settled rollout gate →
// strategic-merge Patch → 15m requeue. Same shape as DeploymentSpec
// minus the replica pin, plus the Settled gate a DaemonSet needs —
// patching mid-rollout would stack a second rolling restart (the
// double flap the bash hook avoided).
package pinnedworkload

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// DaemonSetSpec is one pinned DaemonSet the framework reconciles.
type DaemonSetSpec struct {
	// CS is the direct (uncached) clientset — module reads go through
	// it, not the manager cache.
	CS kubernetes.Interface
	// Queue is the module's ops name — every metrics.IncError label
	// comes from it.
	Queue string
	// Namespace/Name locate the pinned DaemonSet — they also fill the
	// "daemonset" log key and every wrapped error string.
	Namespace string
	Name      string
	// Container is the pod-spec container the patch merges by name —
	// a spec missing it must SKIP, not patch: a name-only merge entry
	// has no image and the apiserver rejects it forever.
	Container string
	// NoDriftLog is the drift-free log line — module-owned so each
	// patcher names the fields it pins.
	NoDriftLog string
	// PatchLog is the "drifted — restoring pinned spec" line emitted
	// right before the patch — module-owned, like NoDriftLog.
	PatchLog string
	// Settled gates the patch on rollout state; nil means patch
	// whenever drifted. Konnectivity passes kube.DaemonSetSettled —
	// patching while a rollout is in flight would stack a second
	// rolling restart.
	Settled func(ds *appsv1.DaemonSet) bool
	// Drifted reports whether the fetched DaemonSet lacks any pinned
	// field.
	Drifted func(ds *appsv1.DaemonSet) bool
	// Patch is the static strategic-merge patch body — DaemonSet
	// pins carry no computed fields, so no renderer is needed.
	Patch []byte
}

// Reconcile is the pinned-DaemonSet reconcile loop: get → skip on
// NotFound → patch only on drift, and only once the rollout has
// settled. NotFound, no-drift and the skip paths return nil on the
// 15m requeue; every other failure IncErrors Queue once and returns
// the error for workqueue backoff.
func (s DaemonSetSpec) Reconcile(ctx context.Context) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	res := ctrl.Result{RequeueAfter: RequeueInterval}
	ref := s.Namespace + "/" + s.Name

	ds, err := s.CS.AppsV1().DaemonSets(s.Namespace).
		Get(ctx, s.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		// DS may not exist (cluster without the addon)
		log.Info("SKIP: daemonset not found", "daemonset", ref)
		return res, nil
	}
	if err != nil {
		metrics.IncError(s.Queue)
		return ctrl.Result{}, fmt.Errorf("get daemonset %s: %w", ref, err)
	}

	if !s.Drifted(ds) {
		log.Info(s.NoDriftLog, "daemonset", ref)
		return res, nil
	}
	// A missing container reads as drift, but the strategic-merge
	// patch merges containers BY NAME — applied to a spec without it,
	// it would append a container entry with no image that the
	// apiserver rejects forever. We cannot reconstruct the image, so
	// warn and leave the DS for the stack applier rather than
	// emitting a guaranteed-invalid patch.
	if !kube.PodSpecHasContainer(&ds.Spec.Template.Spec, s.Container) {
		log.Info("WARN: "+s.Container+" container missing from pod spec — "+
			"skipping patch (strategic merge cannot create it without an image)",
			"daemonset", ref)
		return res, nil
	}
	if s.Settled != nil && !s.Settled(ds) {
		log.Info("SKIP: drifted but rollout in progress",
			"daemonset", ref,
			"generation", ds.Generation,
			"observedGeneration", ds.Status.ObservedGeneration,
			"updated", ds.Status.UpdatedNumberScheduled,
			"ready", ds.Status.NumberReady,
			"desired", ds.Status.DesiredNumberScheduled)
		return res, nil
	}

	log.Info(s.PatchLog, "daemonset", ref)
	if _, err := s.CS.AppsV1().DaemonSets(s.Namespace).Patch(ctx,
		s.Name, types.StrategicMergePatchType,
		s.Patch, metav1.PatchOptions{}); err != nil {
		metrics.IncError(s.Queue)
		return ctrl.Result{}, fmt.Errorf("patch daemonset %s: %w", ref, err)
	}
	return res, nil
}
