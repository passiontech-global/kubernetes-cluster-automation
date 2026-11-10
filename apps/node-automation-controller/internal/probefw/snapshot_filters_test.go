// snapshot_filters_test.go — the client-side census filters:
// PodsIn (namespace), PodsMatching (namespace + label selector,
// "" = cluster-wide, unparseable selector errors) and AllNamespaces
// (the cluster-scoped twin). Each rides the shared AllPods/AllNamespaces
// LIST — the filters themselves re-run free per call.
package probefw

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestPodsInAndPodsMatching(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "web-1",
			Labels: map[string]string{"app": "web"}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "web-2",
			Labels: map[string]string{"app": "web", "tier": "fe"}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "db-1",
			Labels: map[string]string{"app": "db"}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: "other", Name: "web-9",
			Labels: map[string]string{"app": "web"}}},
	)
	d := &Deps{CS: cs}
	ctx := WithSweepSnapshot(context.Background())

	in, err := d.PodsIn(ctx, "apps")
	if err != nil {
		t.Fatal(err)
	}
	if len(in) != 3 {
		t.Fatalf("PodsIn(apps) = %d pods, want 3", len(in))
	}
	for _, p := range in {
		if p.Namespace != "apps" {
			t.Fatalf("PodsIn leaked %s/%s", p.Namespace, p.Name)
		}
	}

	// Namespace + selector — the client-side equivalent of a
	// LabelSelector list.
	matched, err := d.PodsMatching(ctx, "apps", "app=web,tier=fe")
	if err != nil {
		t.Fatal(err)
	}
	if len(matched) != 1 || matched[0].Name != "web-2" {
		t.Fatalf("PodsMatching(apps, app=web,tier=fe) = %v", matched)
	}

	// "" namespace is cluster-wide — the other-ns web pod joins.
	matched, err = d.PodsMatching(ctx, "", "app=web")
	if err != nil {
		t.Fatal(err)
	}
	if len(matched) != 3 {
		t.Fatalf("PodsMatching(\"\", app=web) = %d, want 3", len(matched))
	}

	// An unparseable selector is a caller bug surfaced as an error —
	// the apiserver would have rejected it too.
	if _, err := d.PodsMatching(ctx, "apps", "app in ("); err == nil {
		t.Fatal("PodsMatching with a malformed selector = nil error")
	}
}

func TestAllNamespaces(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "apps"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "terminating"}},
	)
	d := &Deps{CS: cs}
	ctx := WithSweepSnapshot(context.Background())

	ns, err := d.AllNamespaces(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(ns) != 3 {
		t.Fatalf("AllNamespaces = %d, want 3", len(ns))
	}
	// The census memoizes — a second call is served by the snapshot,
	// and the filter-free read still returns the same objects.
	again, err := d.AllNamespaces(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != len(ns) {
		t.Fatalf("second AllNamespaces = %d, want %d", len(again), len(ns))
	}
}
