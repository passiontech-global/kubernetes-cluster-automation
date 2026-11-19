package kube

import (
	"context"
	json "encoding/json/v2"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

func TestOverlayObjKeyAndEffectiveAnnos(t *testing.T) {
	t.Run("overlayObjKey_variants", func(t *testing.T) {
		withUID := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: "u-123", Namespace: "ns", Name: "p"}}
		if got := overlayObjKey(withUID); got != types.UID("u-123") {
			t.Fatalf("withUID: got %q, want u-123", got)
		}

		unstr := &unstructured.Unstructured{}
		unstr.SetKind("Widget")
		unstr.SetNamespace("ns1")
		unstr.SetName("w1")
		if got := overlayObjKey(unstr); got != types.UID("Widget/ns1/w1") {
			t.Fatalf("unstructured: got %q, want Widget/ns1/w1", got)
		}

		typedNoMeta := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns2", Name: "p2"}}
		if got := overlayObjKey(typedNoMeta); got != types.UID("Pod/ns2/p2") {
			t.Fatalf("typedNoMeta: got %q, want Pod/ns2/p2", got)
		}
	})

	t.Run("effective_annos_nil_and_overlay", func(t *testing.T) {
		ctx := context.Background()
		if got := EffectiveAnnos(ctx, nil); got != nil {
			t.Fatalf("EffectiveAnnos(nil) = %v, want nil", got)
		}

		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				UID:         "pod-uid-1",
				Namespace:   "default",
				Name:        "web",
				Annotations: map[string]string{"keep": "1", "drop": "2", "edit": "old"},
			},
		}
		// Outside a sweep: returns a copy of object's own annotations.
		plain := EffectiveAnnos(ctx, pod)
		if plain["keep"] != "1" || plain["drop"] != "2" || plain["edit"] != "old" {
			t.Fatalf("plain EffectiveAnnos = %v", plain)
		}

		// Inside a sweep: overlay adds, edits, and deletes keys.
		ovCtx := WithSweepOverlay(ctx)
		RecordAnnoPatch(ovCtx, pod, []byte(`{"metadata":{"annotations":{"edit":"new","add":"3","drop":null}}}`))
		got := EffectiveAnnos(ovCtx, pod)
		if got["keep"] != "1" || got["edit"] != "new" || got["add"] != "3" {
			t.Fatalf("overlay EffectiveAnnos = %v", got)
		}
		if _, exists := got["drop"]; exists {
			t.Fatalf("deleted key 'drop' still present in EffectiveAnnos: %v", got)
		}
	})
}

func TestJSONSizeVariants(t *testing.T) {
	obj := map[string]any{"k": "v", "n": 42}
	wantBytes, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	want := int64(len(wantBytes))

	t.Run("unstructured_ptr", func(t *testing.T) {
		u := &unstructured.Unstructured{Object: obj}
		got, err := JSONSize(u)
		if err != nil || got != want {
			t.Fatalf("JSONSize(*Unstructured) = (%d, %v), want (%d, nil)", got, err, want)
		}
	})

	t.Run("unstructured_val", func(t *testing.T) {
		u := unstructured.Unstructured{Object: obj}
		got, err := JSONSize(u)
		if err != nil || got != want {
			t.Fatalf("JSONSize(Unstructured) = (%d, %v), want (%d, nil)", got, err, want)
		}
	})

	t.Run("encode_error", func(t *testing.T) {
		if _, err := JSONSize(func() {}); err == nil {
			t.Fatal("expected error for unmarshalable func, got nil")
		}
	})
}
