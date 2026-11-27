// calico_controllers_patcher.go — reconciles the kube-system/calico-kube-controllers
// Deployment to pin container "calico-kube-controllers" readinessProbe to
// timeoutSeconds=5 and failureThreshold=6.
//
// Calico is a built-in k0s stack addon on Calico clusters (cicd): k0s reverts
// the stock manifest on every stack apply, and stock readinessProbe defaults
// (1s timeout / 3 failures) flap under transient apiserver latency, causing
// needless controller unready/restart churn. On Cilium clusters (nonprod,
// production), kube-system/calico-kube-controllers does not exist and
// DeploymentSpec.Reconcile skips cleanly on NotFound.
//
// Unlike coredns-patcher and metrics-server-patcher, this reconciler does NOT
// pin .spec.replicas — calico-kube-controllers is a leader-elected singleton.
package calicocontrollerspatcher

import (
	"context"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/system/pinnedworkload"
)

const (
	calicoControllersNamespace = "kube-system"
	calicoControllersName      = "calico-kube-controllers"
	calicoControllersContainer = "calico-kube-controllers"

	calicoNodeName      = "calico-node"
	calicoNodeContainer = "calico-node"
	calicoIPAutoEnvName = "IP_AUTODETECTION_METHOD"
	calicoIPAutoEnvWant = "kubernetes-internal-ip"

	calicoReadinessTimeoutSeconds   int32 = 5
	calicoReadinessFailureThreshold int32 = 6
)

// Strategic-merge patch targeting container "calico-kube-controllers" by name.
// Merges only timeoutSeconds and failureThreshold inside readinessProbe so the
// probe handler (exec/httpGet) and other fields remain untouched.
var calicoControllersPatch = []byte(`{"spec":{"template":{"spec":{"containers":[{"name":"calico-kube-controllers","readinessProbe":{"timeoutSeconds":5,"failureThreshold":6}}]}}}}`)

// Strategic-merge patch targeting container "calico-node" by name to pin
// IP_AUTODETECTION_METHOD=kubernetes-internal-ip so Calico binds the node's
// declared InternalIP instead of auto-detecting neb1 (2026-11-27 cicd incident).
var calicoNodePatch = []byte(`{"spec":{"template":{"spec":{"containers":[{"name":"calico-node","env":[{"name":"IP_AUTODETECTION_METHOD","value":"kubernetes-internal-ip"}]}]}}}}`)

// onlyCalicoControllersDeployment pins the For() watch to
// kube-system/calico-kube-controllers — the informer sees every kube-system
// Deployment.
var onlyCalicoControllersDeployment = pinnedworkload.OnlyNamespacedName(
	calicoControllersNamespace, calicoControllersName)

type calicoControllersPatcher struct {
	cs     kubernetes.Interface
	reader kube.CachedObjectReader
}

// Setup reconciles kube-system/calico-kube-controllers.
// CALICO_CONTROLLERS_PATCHER_ENABLED=false (resolved by SetupModules into
// Deps.Disabled) skips registration entirely.
func Setup(d shared.Deps) error {
	return shared.SetupNoConfig(d, func() error {
		logf.Log.WithName(d.Name).Info("registered")
		r := &calicoControllersPatcher{
			cs:     d.CS,
			reader: d.CachedClient(),
		}
		return ctrl.NewControllerManagedBy(d.Mgr).
			Named(d.Name).
			For(&appsv1.Deployment{}, builder.WithPredicates(onlyCalicoControllersDeployment)).
			Complete(shared.CountReconcile(d.Name, r.Reconcile))
	})
}

// Reconcile delegates to the shared pinned-Deployment skeleton for
// calico-kube-controllers (replicas left zero so .spec.replicas is never
// pinned) and then reconciles kube-system/calico-node DaemonSet to keep
// IP_AUTODETECTION_METHOD=kubernetes-internal-ip pinned against k0s stack
// applier reverts. Both skip cleanly on NotFound (Cilium clusters).
func (r *calicoControllersPatcher) Reconcile(ctx context.Context, _ reconcile.Request) (ctrl.Result, error) {
	res, err := pinnedworkload.DeploymentSpec{
		CS:         r.cs,
		Reader:     r.reader,
		Namespace:  calicoControllersNamespace,
		Name:       calicoControllersName,
		Container:  calicoControllersContainer,
		NoDriftLog: "readinessProbe already pinned - nothing to do",
		Drifted:    calicoControllersNeedsPatch,
		PatchBody:  calicoControllersPatchBody,
	}.Reconcile(ctx)
	if err != nil {
		return res, err
	}
	if _, dsErr := (pinnedworkload.DaemonSetSpec{
		CS:         r.cs,
		Namespace:  calicoControllersNamespace,
		Name:       calicoNodeName,
		Container:  calicoNodeContainer,
		NoDriftLog: "IP_AUTODETECTION_METHOD already pinned - nothing to do",
		PatchLog:   "PATCH: calico-node IP_AUTODETECTION_METHOD drifted — rollout settled, restoring kubernetes-internal-ip",
		Settled:    kube.DaemonSetSettled,
		Drifted:    calicoNodeNeedsPatch,
		Patch:      calicoNodePatch,
	}).Reconcile(ctx); dsErr != nil {
		return ctrl.Result{}, dsErr
	}
	return res, nil
}

// calicoNodeNeedsPatch reports whether kube-system/calico-node lacks
// IP_AUTODETECTION_METHOD=kubernetes-internal-ip on the calico-node container.
func calicoNodeNeedsPatch(ds *appsv1.DaemonSet) bool {
	for i := range ds.Spec.Template.Spec.Containers {
		c := &ds.Spec.Template.Spec.Containers[i]
		if c.Name != calicoNodeContainer {
			continue
		}
		for _, env := range c.Env {
			if env.Name == calicoIPAutoEnvName {
				return env.Value != calicoIPAutoEnvWant
			}
		}
		return true
	}
	return true
}

func calicoControllersPatchBody(_ int32) ([]byte, error) {
	return calicoControllersPatch, nil
}

// calicoControllersNeedsPatch reports whether the Deployment's
// calico-kube-controllers container has a readinessProbe lacking the pinned
// timeoutSeconds=5 / failureThreshold=6. A nil readinessProbe returns false
// because merging only timeoutSeconds/failureThreshold without a probe handler
// is rejected by the API server (422 Invalid). A missing container counts as
// drifted so DeploymentSpec.Reconcile hits its missing-container safety skip.
func calicoControllersNeedsPatch(d *appsv1.Deployment, _ int32) bool {
	for i := range d.Spec.Template.Spec.Containers {
		c := &d.Spec.Template.Spec.Containers[i]
		if c.Name != calicoControllersContainer {
			continue
		}
		if c.ReadinessProbe == nil {
			return false
		}
		return c.ReadinessProbe.TimeoutSeconds != calicoReadinessTimeoutSeconds ||
			c.ReadinessProbe.FailureThreshold != calicoReadinessFailureThreshold
	}
	return true
}
