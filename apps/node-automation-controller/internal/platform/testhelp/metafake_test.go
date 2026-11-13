// metafake_test.go — the metadata fake's contract: a fresh
// NewTestScheme with meta types registered must LIST seeded
// PartialObjectMetadata without panicking (the unregistered-scheme
// shape used to die inside the fake's tracker on the first read).
package testhelp

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestNewMetaClientListsPartialMetadata(t *testing.T) {
	om := metav1.ObjectMeta{
		Namespace: "ns1", Name: "rs-0",
		Labels: map[string]string{"app": "web"},
	}
	meta := NewMetaClient(MetaObj("apps/v1", "ReplicaSet", om))

	gvr := schema.GroupVersionResource{
		Group: "apps", Version: "v1", Resource: "replicasets"}
	list, err := meta.Resource(gvr).Namespace("ns1").List(
		t.Context(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("metadata list: %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(list.Items))
	}
	got := list.Items[0]
	if got.GetName() != "rs-0" || got.GetNamespace() != "ns1" ||
		got.GetLabels()["app"] != "web" {
		t.Fatalf("seeded object lost its metadata: %+v", got.ObjectMeta)
	}
}
