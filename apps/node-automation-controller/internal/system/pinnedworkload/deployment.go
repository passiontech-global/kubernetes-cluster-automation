// deployment.go — DeploymentSpec: the shared reconcile skeleton for
// the pinned-Deployment patchers (coredns, metrics-server):
// Get → NotFound skip → proportional wantReplicas → Drifted →
// missing-container guard → PatchBody → strategic-merge Patch →
// 15m requeue. The module supplies the ops surface — queue name,
// drift check, patch body, the drift-free log line; this file owns
// the flow and the fixed error/metric shape every error path shares.
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

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
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
	// CS is the direct (uncached) clientset — module reads go through
	// it, not the manager cache.
	CS kubernetes.Interface
	// Queue is the module's ops name — every metrics.IncError label
	// comes from it.
	Queue string
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
// nil on the 15m requeue; every other failure IncErrors Queue once
// and returns the error for workqueue backoff.
func (s DeploymentSpec) Reconcile(ctx context.Context) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	res := ctrl.Result{RequeueAfter: RequeueInterval}
	ref := s.Namespace + "/" + s.Name

	d, err := s.CS.AppsV1().Deployments(s.Namespace).
		Get(ctx, s.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		// cluster without this k0s addon
		log.Info("SKIP: deployment not found", "deployment", ref)
		return res, nil
	}
	if err != nil {
		metrics.IncError(s.Queue)
		return ctrl.Result{}, fmt.Errorf("get deployment %s: %w", ref, err)
	}

	// Proportional replica pin — disabled when MinReplicas<=0
	// (wantReplicas stays 0: neither Drifted nor the patch body
	// touches .spec.replicas then).
	wantReplicas, err := s.Replicas.Want(ctx, s.CS)
	if err != nil {
		metrics.IncError(s.Queue)
		return ctrl.Result{}, fmt.Errorf("list nodes for proportional replica count: %w", err)
	}

	if !s.Drifted(d, wantReplicas) {
		log.Info(s.NoDriftLog, "deployment", ref, "wantReplicas", wantReplicas)
		return res, nil
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
		metrics.IncError(s.Queue)
		return ctrl.Result{}, fmt.Errorf("render patch body for deployment %s: %w", ref, err)
	}
	log.Info("PATCH: "+s.Name+" drifted — restoring pinned spec",
		"deployment", ref, "wantReplicas", wantReplicas)
	if _, err := s.CS.AppsV1().Deployments(s.Namespace).Patch(ctx,
		s.Name, types.StrategicMergePatchType,
		patch, metav1.PatchOptions{}); err != nil {
		metrics.IncError(s.Queue)
		return ctrl.Result{}, fmt.Errorf("patch deployment %s: %w", ref, err)
	}
	return res, nil
}
