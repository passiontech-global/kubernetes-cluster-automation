// daemonset.go — DaemonSetSpec: the shared reconcile skeleton for the
// pinned-DaemonSet patchers (konnectivity-agent): cached-or-direct
// Get → NotFound skip → Drifted → direct-CS drift confirm (when the
// cache served the Get) → missing-container guard → Settled rollout
// gate → strategic-merge Patch → 15m requeue. Same shape as DeploymentSpec
// minus the replica pin, plus the Settled gate a DaemonSet needs —
// patching mid-rollout would stack a second rolling restart (the
// double flap the bash hook avoided). Returned errors are counted
// once by the shared.CountReconcile wrapper at the module's
// builder.Complete — never IncError here (that would double-count).
package pinnedworkload

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// DaemonSetSpec is one pinned DaemonSet the framework reconciles.
type DaemonSetSpec struct {
	// CS is the direct (uncached) clientset — destructive paths
	// (the drift-confirm re-Get and the Patch) go through it.
	CS kubernetes.Interface
	// Reader is the optional informer-cache reader (mgr.GetClient()
	// at module Setup) for the initial drift-detection Get. Only
	// valid while the manager's DaemonSet informer can see the object
	// (buildCacheOptions scopes it to kube-system/konnectivity-agent
	// today); nil falls back to a direct CS Get. The destructive
	// patch still confirms on CS when Reader is set — see
	// DeploymentSpec.Reader for the full contract.
	Reader kube.CachedObjectReader
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
// 15m requeue; every other failure returns the error for workqueue
// backoff — the shared.CountReconcile wrapper at the module's
// builder.Complete IncErrors it exactly once.
func (s DaemonSetSpec) Reconcile(ctx context.Context) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	res := ctrl.Result{RequeueAfter: RequeueInterval}
	ref := s.Namespace + "/" + s.Name

	ds, err := kube.GetDaemonSetCached(ctx, s.Reader, s.CS, s.Namespace, s.Name)
	if apierrors.IsNotFound(err) {
		// DS may not exist (cluster without the addon)
		log.Info("SKIP: daemonset not found", "daemonset", ref)
		return res, nil
	}
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("get daemonset %s: %w", ref, err)
	}

	if !s.Drifted(ds) {
		log.Info(s.NoDriftLog, "daemonset", ref)
		return res, nil
	}
	// Confirm the cache-served drift verdict on the direct clientset
	// before the patch — same contract as DeploymentSpec.Reader.
	if s.Reader != nil {
		var proceed bool
		ds, proceed, err = confirmDirect(ctx, log, "daemonset", ref, s.NoDriftLog,
			func(ctx context.Context) (*appsv1.DaemonSet, error) {
				return s.CS.AppsV1().DaemonSets(s.Namespace).Get(ctx, s.Name, metav1.GetOptions{})
			}, s.Drifted)
		if err != nil {
			return ctrl.Result{}, err
		}
		if !proceed {
			return res, nil
		}
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
		return ctrl.Result{}, fmt.Errorf("patch daemonset %s: %w", ref, err)
	}
	return res, nil
}

// confirmDirect re-fetches an object from the direct clientset when
// the initial read came from an informer cache, skipping if the object
// vanished or no longer shows drift.
func confirmDirect[T any](ctx context.Context, log logr.Logger, kind, ref, noDriftLog string,
	get func(context.Context) (T, error), drifted func(T) bool, extraKV ...any) (T, bool, error) {
	obj, err := get(ctx)
	if apierrors.IsNotFound(err) {
		log.Info("SKIP: "+kind+" gone between cache read and confirm", kind, ref)
		var zero T
		return zero, false, nil
	}
	if err != nil {
		var zero T
		return zero, false, fmt.Errorf("confirm %s %s on direct client: %w", kind, ref, err)
	}
	if !drifted(obj) {
		kv := append([]any{kind, ref}, extraKV...)
		log.Info(noDriftLog+" (confirmed on direct client)", kv...)
		return obj, false, nil
	}
	return obj, true, nil
}
