// store_readiness.go — SecretStore / ClusterSecretStore listing and
// readiness for externalsecret-nudge: listFirst/listES page the first
// serving GVR of each candidate set (the ESO API exists at v1 AND
// v1beta1), and esStoreReady + esStoreRefs answer whether every store
// an ExternalSecret can pull from is tracked AND currently Ready=True.
package externalsecretnudge

import (
	"context"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// listFirst lists the first working GVR of a candidate set — the ESO
// API serves v1 on current installs and v1beta1 on older ones; a
// not-installed candidate is skipped, the first listable wins.
func (n *externalSecretNudge) listFirst(ctx context.Context,
	gvrs []schema.GroupVersionResource) (*unstructured.UnstructuredList, error) {
	var lastErr error
	for _, gvr := range gvrs {
		items, err := kube.ListAll(ctx,
			metav1.ListOptions{Limit: kube.DefaultListPageSize},
			kube.DynamicPage(n.dyn.Resource(gvr)))
		if err == nil {
			return &unstructured.UnstructuredList{Items: items}, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// gvrForPatch returns the GVR the ES list answered on — patches must
// land on the same served version.
func (n *externalSecretNudge) listES(ctx context.Context) (*unstructured.UnstructuredList, schema.GroupVersionResource, error) {
	var lastErr error
	for _, gvr := range externalSecretGVRs {
		items, err := kube.ListAll(ctx,
			metav1.ListOptions{Limit: kube.DefaultListPageSize},
			kube.DynamicPage(n.dyn.Resource(gvr)))
		if err == nil {
			return &unstructured.UnstructuredList{Items: items}, gvr, nil
		}
		lastErr = err
	}
	return nil, schema.GroupVersionResource{}, lastErr
}

// esStoreReady reports whether every store the ES can pull from is
// tracked AND currently Ready=True — ClusterSecretStore by name, or a
// namespaced SecretStore in the ES's own namespace (ESO defaults an
// unset kind to SecretStore). ALL referenced stores must qualify: an
// absent ref set or a store we have never seen is "can't tell" →
// false.
func (n *externalSecretNudge) esStoreReady(es *unstructured.Unstructured) bool {
	any, ready := false, true
	esStoreRefs(es, func(name, kind string) {
		key := ""
		switch kind {
		case "ClusterSecretStore":
			key = "ClusterSecretStore//" + name
		case "", "SecretStore":
			key = "SecretStore/" + es.GetNamespace() + "/" + name
		default:
			ready = false
			return
		}
		r, tracked := n.storeReady[key]
		if !tracked || !r {
			ready = false
			return
		}
		any = true
	})
	return any && ready
}

// esStoreRefs walks every store reference the ExternalSecret carries —
// spec.secretStoreRef (the default store) plus each
// spec.dataFrom[].sourceRef.storeRef AND spec.data[].sourceRef.storeRef
// per-entry override — invoking fn(name, kind) for each ref that names
// a store. Refs without a name are genuinely absent; generator refs
// (sourceRef.generatorRef) are not stores and never reach fn.
func esStoreRefs(es *unstructured.Unstructured, fn func(name, kind string)) {
	if name, ok := kube.NestedString(
		es.Object, "spec", "secretStoreRef", "name"); ok && name != "" {
		kind, _ := kube.NestedString(
			es.Object, "spec", "secretStoreRef", "kind")
		fn(name, kind)
	}
	// dataFrom[].sourceRef.storeRef and data[].sourceRef.storeRef are
	// the same per-entry override shape under two parent lists.
	for _, field := range []string{"dataFrom", "data"} {
		entries, _ := kube.NestedSlice(es.Object, "spec", field)
		for _, e := range entries {
			m, ok := e.(map[string]any)
			if !ok {
				continue
			}
			if name, ok := kube.NestedString(
				m, "sourceRef", "storeRef", "name"); ok && name != "" {
				kind, _ := kube.NestedString(
					m, "sourceRef", "storeRef", "kind")
				fn(name, kind)
			}
		}
	}
}
