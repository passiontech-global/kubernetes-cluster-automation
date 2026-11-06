// fixture.go — the one-liner unstructured CR builder behind the
// ~50 near-identical &unstructured.Unstructured{Object: ...}
// literals scattered across module tests.
package testhelp

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Unstructured builds a bare CR fixture: apiVersion/kind from gvk,
// metadata.namespace/name from the args, and fields merged in at the
// top level of Object — pass spec/status blobs as nested maps:
//
//	testutil.Unstructured(gvk, "apps", "hr-1", map[string]any{
//		"status": map[string]any{"conditions": []any{...}},
//	})
//
// ns/name accept "" for cluster-scoped objects. Tests needing shapes
// the literal can't express (computed keys, typed metadata beyond
// ns/name) keep building the literal by hand.
func Unstructured(gvk schema.GroupVersionKind, ns, name string,
	fields map[string]any) *unstructured.Unstructured {
	o := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": gvk.GroupVersion().String(),
		"kind":       gvk.Kind,
	}}
	if ns != "" {
		o.SetNamespace(ns)
	}
	if name != "" {
		o.SetName(name)
	}
	for k, v := range fields {
		o.Object[k] = v
	}
	return o
}
