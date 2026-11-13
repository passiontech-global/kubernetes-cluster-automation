// kube_primitives_test.go — the new-listing/parse/restart builders:
// ListAllUnstructured's paging + error passthrough, ParseCommaSet's
// trim-and-skip-empty semantics (mirroring guardstate's circuit
// annotation parser), and RestartTemplatePatch's exact nested doc.
package kube

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/testhelp"
)

func TestListAllUnstructuredPagesAndRewraps(t *testing.T) {
	dyn := testhelp.NewDynamicClient(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "a"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "b"}},
	)
	gvr := corev1.SchemeGroupVersion.WithResource("namespaces")

	list, err := ListAllUnstructured(t.Context(),
		dyn.Resource(gvr), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("ListAllUnstructured: %v", err)
	}
	if len(list.Items) != 2 {
		t.Fatalf("ListAllUnstructured = %d items, want 2", len(list.Items))
	}
	for _, item := range list.Items {
		if item.GetKind() != "Namespace" || item.GetName() == "" {
			t.Fatalf("item not rewrapped as unstructured: %v", item)
		}
	}

	// A list failure surfaces verbatim — the nil-list contract of
	// the hand-rolled wrappers it replaces.
	dyn.PrependReactor("list", "namespaces",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("list boom")
		})
	if list, err = ListAllUnstructured(t.Context(),
		dyn.Resource(gvr), metav1.ListOptions{}); err == nil || list != nil {
		t.Fatalf("failed list = (%v, %v), want (nil, error)", list, err)
	}
}

// TestListFirstGVR walks the candidate-GVR fallback contract: first
// success wins with its GVR, benign NotFound/NoMatch misses are
// skipped, a real error beats benign misses when nothing lists, and
// an empty candidate set is a caller bug.
func TestListFirstGVR(t *testing.T) {
	gvrA := schema.GroupVersionResource{Group: "x.io", Version: "v1", Resource: "foos"}
	gvrB := schema.GroupVersionResource{Group: "x.io", Version: "v1beta1", Resource: "foos"}
	benign := apierrors.NewNotFound(schema.GroupResource{Group: "x.io", Resource: "foos"}, "")
	real := apierrors.NewForbidden(schema.GroupResource{Group: "x.io", Resource: "foos"}, "", errors.New("rbac"))

	t.Run("first candidate answers", func(t *testing.T) {
		items, gvr, err := ListFirstGVR(t.Context(),
			[]schema.GroupVersionResource{gvrA, gvrB},
			func(_ context.Context, g schema.GroupVersionResource) (string, error) {
				if g != gvrA {
					t.Fatalf("listed %v, want first candidate %v", g, gvrA)
				}
				return "items-a", nil
			})
		if err != nil || items != "items-a" || gvr != gvrA {
			t.Fatalf("ListFirstGVR = (%q, %v, %v), want (items-a, %v, nil)",
				items, gvr, err, gvrA)
		}
	})

	t.Run("benign miss falls through to next GVR", func(t *testing.T) {
		items, gvr, err := ListFirstGVR(t.Context(),
			[]schema.GroupVersionResource{gvrA, gvrB},
			func(_ context.Context, g schema.GroupVersionResource) (string, error) {
				if g == gvrA {
					return "", benign
				}
				return "items-b", nil
			})
		if err != nil || items != "items-b" || gvr != gvrB {
			t.Fatalf("ListFirstGVR = (%q, %v, %v), want (items-b, %v, nil)",
				items, gvr, err, gvrB)
		}
	})

	t.Run("real error still falls through — later success wins", func(t *testing.T) {
		items, gvr, err := ListFirstGVR(t.Context(),
			[]schema.GroupVersionResource{gvrA, gvrB},
			func(_ context.Context, g schema.GroupVersionResource) (string, error) {
				if g == gvrA {
					return "", real
				}
				return "items-b", nil
			})
		if err != nil || items != "items-b" || gvr != gvrB {
			t.Fatalf("ListFirstGVR = (%q, %v, %v), want (items-b, %v, nil)",
				items, gvr, err, gvrB)
		}
	})

	t.Run("all benign returns the first benign error", func(t *testing.T) {
		_, _, err := ListFirstGVR(t.Context(),
			[]schema.GroupVersionResource{gvrA, gvrB},
			func(context.Context, schema.GroupVersionResource) (string, error) {
				return "", benign
			})
		if !apierrors.IsNotFound(err) {
			t.Fatalf("ListFirstGVR err = %v, want NotFound", err)
		}
	})

	t.Run("real error beats benign misses", func(t *testing.T) {
		_, _, err := ListFirstGVR(t.Context(),
			[]schema.GroupVersionResource{gvrA, gvrB},
			func(_ context.Context, g schema.GroupVersionResource) (string, error) {
				if g == gvrA {
					return "", benign
				}
				return "", real
			})
		if !apierrors.IsForbidden(err) {
			t.Fatalf("ListFirstGVR err = %v, want Forbidden", err)
		}
	})

	t.Run("empty candidates is a caller bug", func(t *testing.T) {
		if _, _, err := ListFirstGVR(t.Context(),
			nil, func(context.Context, schema.GroupVersionResource) (string, error) {
				return "", nil
			}); err == nil {
			t.Fatal("ListFirstGVR with no candidates returned nil error")
		}
	})
}

// TestListFirstUnstructured exercises the dyn-bound convenience
// wrapper end to end: a candidate whose LIST the apiserver 404s is
// skipped and the next registered GVR answers.
func TestListFirstUnstructured(t *testing.T) {
	dyn := testhelp.NewDynamicClient(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "a"}},
	)
	// secrets is registered in the fake's list-kind table; the
	// reactor makes its LIST answer NotFound — the "not served"
	// shape a v1beta1-fallback probe sees on a cluster without the
	// older API.
	dyn.PrependReactor("list", "secrets",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewNotFound(
				corev1.Resource("secrets"), "")
		})
	gvrA := corev1.SchemeGroupVersion.WithResource("secrets")
	gvrB := corev1.SchemeGroupVersion.WithResource("namespaces")

	list, gvr, err := ListFirstUnstructured(t.Context(), dyn,
		[]schema.GroupVersionResource{gvrA, gvrB}, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("ListFirstUnstructured: %v", err)
	}
	if gvr != gvrB || len(list.Items) != 1 {
		t.Fatalf("ListFirstUnstructured = (gvr %v, %d items), want (%v, 1)",
			gvr, len(list.Items), gvrB)
	}
}

func TestParseCommaSet(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		want     map[string]bool
	}{
		{"empty string", "", map[string]bool{}},
		{"single", "webhook-a", map[string]bool{"webhook-a": true}},
		{
			"trims and skips empties",
			" a , b,,  c ,",
			map[string]bool{"a": true, "b": true, "c": true},
		},
		{"dedupes", "x,x, x", map[string]bool{"x": true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseCommaSet(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("ParseCommaSet(%q) = %v, want %v", tc.in, got, tc.want)
			}
			for k := range tc.want {
				if !got[k] {
					t.Fatalf("ParseCommaSet(%q) missing %q: %v", tc.in, k, got)
				}
			}
		})
	}
}

func TestRestartTemplatePatch(t *testing.T) {
	ts := time.Date(2026, 11, 8, 10, 30, 0, 0, time.FixedZone("CET", 3600))

	var doc map[string]any
	if err := json.Unmarshal(RestartTemplatePatch(ts), &doc); err != nil {
		t.Fatalf("patch is not valid JSON: %v", err)
	}
	spec, _ := doc["spec"].(map[string]any)
	tmpl, _ := spec["template"].(map[string]any)
	meta, _ := tmpl["metadata"].(map[string]any)
	annos, _ := meta["annotations"].(map[string]any)
	if annos == nil {
		t.Fatalf("patch missing spec.template.metadata.annotations: %v", doc)
	}
	// The stamp is always RFC3339 UTC — CET 10:30 lands at 09:30Z.
	want := ts.UTC().Format(time.RFC3339)
	if got, _ := annos[RestartedAtAnno].(string); got != want {
		t.Fatalf("restartedAt = %q, want %q", got, want)
	}
	// No sibling keys may leak into the doc — a metadata-level stamp
	// in the shared builder would roll objects the caller never meant
	// to touch.
	if len(doc) != 1 {
		t.Fatalf("patch carries extra top-level keys: %v", doc)
	}
}
