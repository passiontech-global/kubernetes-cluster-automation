// nodeproxy.go — the kubelet /healthz fetch through the apiserver's
// node proxy subresource, shared by every module that needs a "is
// :10250 actually serving" verdict (kubelet-liveness-reaper,
// dead-node-sweeper). One GET /api/v1/nodes/<node>/proxy/healthz —
// the request rides the konnectivity tunnel to the node's kubelet,
// so no direct node network access is needed.
package kube

import (
	"context"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// kubeletHealthzTimeout bounds one fetch through the proxy — long
// enough to span the konnectivity hop, short enough that a wedged
// proxy path cannot hold a probe loop hostage. Both callers probed
// at 8s before this helper existed (the dead node sweeper's timeout
// was defined as "same as the kubelet reaper's"), so the value
// consolidates here with the call itself.
const kubeletHealthzTimeout = 8 * time.Second

// KubeletHealthz GETs /api/v1/nodes/<node>/proxy/healthz through the
// apiserver and returns the raw body. Healthy kubelets answer "ok";
// a dead kubelet makes the apiserver serve "error trying to reach
// service: ..." (or the request errors outright). Reading the "ok"
// prefix off the body and any retry cadence are caller POLICY —
// kubelet-liveness-reaper wants four consecutive failures while
// dead-node-sweeper takes a single shot behind its 30m Unknown
// window — so they stay in the modules; this is only the fetch both
// were duplicating.
//
// Deliberately node-scoped rather than a generic proxy primitive:
// the only other proxy-subresource caller (zombie-sidecar-reaper)
// POSTs to the namespaced pods/<name>:<port>/proxy path and ignores
// the body — a shared verb+namespace+port-suffix signature would
// just re-skin the rest.Request builder.
func KubeletHealthz(ctx context.Context, cs kubernetes.Interface, node string) ([]byte, error) {
	return cs.CoreV1().RESTClient().Get().
		AbsPath("/api/v1/nodes", node, "proxy", "healthz").
		Timeout(kubeletHealthzTimeout).
		DoRaw(ctx)
}

// CoreRESTClient returns cs.CoreV1().RESTClient() if usable, guarding against
// nil clientsets and the typed-nil *rest.RESTClient returned by fake.Clientset.
func CoreRESTClient(cs kubernetes.Interface) (rest.Interface, bool) {
	if cs == nil {
		return nil, false
	}
	rc := cs.CoreV1().RESTClient()
	if rc == nil {
		return nil, false
	}
	if restClient, ok := rc.(*rest.RESTClient); ok && restClient == nil {
		return nil, false
	}
	return rc, true
}
