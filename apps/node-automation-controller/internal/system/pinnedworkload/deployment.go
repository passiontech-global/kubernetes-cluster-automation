// deployment.go — DeploymentSpec: the shared reconcile skeleton for
// the pinned-Deployment patchers (coredns, metrics-server):
// cached-or-direct Get → NotFound skip → proportional wantReplicas →
// Drifted → direct-CS drift confirm (when the cache served the Get)
// → missing-container guard → PatchBody → strategic-merge Patch →
// 15m requeue. The module supplies the ops surface — drift check,
// patch body, the drift-free log line; this file owns the flow and
// the fixed error shape every error path shares. Returned errors are
// counted once by the shared.CountReconcile wrapper at each module's
// builder.Complete — never IncError here (that would double-count).
package pinnedworkload

import (
	"context"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// RequeueInterval is the safety-net requeue every pinned-workload
// reconcile returns — the drift watch re-pins in <1s; this replaces
// the hourly crontab the shell modules ran.
const RequeueInterval = 15 * time.Minute

// DeploymentSpec is one pinned Deployment the framework reconciles —
// the coredns/metrics-server modules build it per Reconcile call from
// their env-resolved knobs.
type DeploymentSpec struct {
	// CS is the direct (uncached) clientset — destructive paths
	// (the drift-confirm re-Get and the Patch) go through it.
	CS kubernetes.Interface
	// Reader is the optional informer-cache reader (mgr.GetClient()
	// at module Setup) for the initial drift-detection Get — the
	// reconcile rides the Deployment watch the module already
	// registers instead of an apiserver GET per event. nil (tests,
	// StubManager) falls back to a direct CS Get. The destructive
	// patch still confirms on CS: when Reader is set and drift was
	// detected on the cached object, the skeleton re-Gets on CS and
	// re-evaluates Drifted before patching — a stale cache must not
	// fire a patch the live object no longer needs.
	Reader kube.CachedObjectReader
	// NodeReader is the optional informer-backed node census for the
	// replica pin (mgr.GetClient() at module Setup); nil falls back
	// to a direct ListNodes — the zero value keeps tests on the
	// fake clientset.
	NodeReader kube.CachedNodeReader
	// Namespace/Name locate the pinned Deployment (kube-system/<addon>
	// today) — they also fill the "deployment" log key and every
	// wrapped error string ("get deployment <ns>/<name>: ...").
	Namespace string
	Name      string
	// Container is the pod-spec container the patch merges by name —
	// a spec missing it must SKIP, not patch: a name-only merge entry
	// has no image and the apiserver rejects it forever.
	Container string
	// Replicas is the proportional replica pin — see ReplicaPin.
	Replicas ReplicaPin
	// NoDriftLog is the "<fields> already pinned - nothing to do" log
	// line for the drift-free path — module-owned so each patcher
	// names the fields it pins.
	NoDriftLog string
	// Drifted reports whether the fetched Deployment lacks any pinned
	// field; wantReplicas>0 also means ".spec.replicas is pinned —
	// count it as drift when it differs".
	Drifted func(d *appsv1.Deployment, wantReplicas int32) bool
	// PatchBody renders the strategic-merge patch; wantReplicas<=0
	// must leave spec.replicas out of the body (strategic merge keeps
	// the current count, so disabled scaling never fights an external
	// autoscaler).
	PatchBody func(wantReplicas int32) ([]byte, error)
}

// Reconcile is the pinned-Deployment reconcile loop both Deployment
// patchers run: get → skip on NotFound → compute wantReplicas →
// patch only on drift. NotFound, no-drift and the skip paths return
// nil on the 15m requeue; every other failure returns the error for
// workqueue backoff — the shared.CountReconcile wrapper at the
// module's builder.Complete IncErrors it exactly once.
func (s DeploymentSpec) Reconcile(ctx context.Context) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	res := ctrl.Result{RequeueAfter: RequeueInterval}
	ref := s.Namespace + "/" + s.Name

	d, err := kube.GetDeploymentCached(ctx, s.Reader, s.CS, s.Namespace, s.Name)
	if apierrors.IsNotFound(err) {
		// cluster without this k0s addon
		log.Info("SKIP: deployment not found", "deployment", ref)
		return res, nil
	}
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("get deployment %s: %w", ref, err)
	}

	// Proportional replica pin — disabled when MinReplicas<=0
	// (wantReplicas stays 0: neither Drifted nor the patch body
	// touches .spec.replicas then).
	wantReplicas, err := s.Replicas.WantFrom(ctx, s.NodeReader, s.CS)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("list nodes for proportional replica count: %w", err)
	}

	if !s.Drifted(d, wantReplicas) {
		log.Info(s.NoDriftLog, "deployment", ref, "wantReplicas", wantReplicas)
		return res, nil
	}
	// The drift verdict came off the informer cache when Reader is
	// wired — milliseconds stale is fine for detection, not for a
	// patch: confirm on the direct clientset (the k0s stack applier
	// may have re-applied the pinned spec between the watch event and
	// this reconcile). A confirmed-fresh object skips; a confirmed
	// drift patches against the live spec.
	if s.Reader != nil {
		d, err = s.CS.AppsV1().Deployments(s.Namespace).
			Get(ctx, s.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			log.Info("SKIP: deployment gone between cache read and confirm", "deployment", ref)
			return res, nil
		}
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("confirm deployment %s on direct client: %w", ref, err)
		}
		if !s.Drifted(d, wantReplicas) {
			log.Info(s.NoDriftLog+" (confirmed on direct client)",
				"deployment", ref, "wantReplicas", wantReplicas)
			return res, nil
		}
	}
	// A missing container reads as drift, but the strategic-merge
	// patch merges containers BY NAME — applied to a spec without it,
	// it would append a container entry with no image that the
	// apiserver rejects forever. We cannot reconstruct the image, so
	// warn and leave the Deployment for the stack applier rather than
	// emitting a guaranteed-invalid patch.
	if !kube.PodSpecHasContainer(&d.Spec.Template.Spec, s.Container) {
		log.Info("WARN: "+s.Container+" container missing from pod spec — "+
			"skipping patch (strategic merge cannot create it without an image)",
			"deployment", ref)
		return res, nil
	}
	patch, err := s.PatchBody(wantReplicas)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("render patch body for deployment %s: %w", ref, err)
	}
	log.Info("PATCH: "+s.Name+" drifted — restoring pinned spec",
		"deployment", ref, "wantReplicas", wantReplicas)
	if _, err := s.CS.AppsV1().Deployments(s.Namespace).Patch(ctx,
		s.Name, types.StrategicMergePatchType,
		patch, metav1.PatchOptions{}); err != nil {
		return ctrl.Result{}, fmt.Errorf("patch deployment %s: %w", ref, err)
	}
	return res, nil
}
