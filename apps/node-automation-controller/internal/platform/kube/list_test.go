package kube

import (
	"context"
	"errors"
	"fmt"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/testhelp"
)

// scriptPage returns a PageFunc that serves the given pages in order,
// recording the Continue token each call was invoked with.
func scriptPage[T any](pages [][]T, seen *[]string) PageFunc[T] {
	calls := 0
	return func(_ context.Context, opts metav1.ListOptions) ([]T, string, error) {
		*seen = append(*seen, opts.Continue)
		if calls >= len(pages) {
			return nil, "", errors.New("script exhausted")
		}
		items := pages[calls]
		calls++
		next := ""
		if calls < len(pages) {
			next = fmt.Sprintf("tok-%d", calls)
		}
		return items, next, nil
	}
}

func TestListEachThreadsContinueTokens(t *testing.T) {
	var seen []string
	page := scriptPage([][]int{{1, 2}, {3}, {}}, &seen)

	var visited [][]int
	err := ListEach(ctx, metav1.ListOptions{Limit: 2}, page,
		func(items []int) error {
			visited = append(visited, items)
			return nil
		})
	if err != nil {
		t.Fatalf("ListEach: %v", err)
	}
	// First call sees the caller's opts verbatim (Continue==""); each
	// later call carries the previous page's token.
	wantSeen := []string{"", "tok-1", "tok-2"}
	if fmt.Sprint(seen) != fmt.Sprint(wantSeen) {
		t.Fatalf("continue tokens = %v, want %v", seen, wantSeen)
	}
	if len(visited) != 3 || len(visited[0]) != 2 || visited[2] == nil {
		t.Fatalf("visited = %v", visited)
	}
}

func TestListEachPropagatesFetchError(t *testing.T) {
	calls := 0
	page := func(context.Context, metav1.ListOptions) ([]int, string, error) {
		calls++
		if calls == 2 {
			return nil, "", errors.New("api flap")
		}
		return []int{calls}, "more", nil
	}
	var visited int
	err := ListEach(ctx, metav1.ListOptions{}, page, func([]int) error {
		visited++
		return nil
	})
	if err == nil || err.Error() != "api flap" {
		t.Fatalf("err = %v, want api flap", err)
	}
	if visited != 1 {
		t.Fatalf("visit ran %d times, want 1 (only the good page)", visited)
	}
}

func TestListEachPropagatesVisitError(t *testing.T) {
	calls := 0
	page := func(context.Context, metav1.ListOptions) ([]int, string, error) {
		calls++
		return []int{calls}, "more", nil
	}
	boom := errors.New("visit failed")
	err := ListEach(ctx, metav1.ListOptions{}, page,
		func([]int) error { return boom })
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want visit error", err)
	}
	if calls != 1 {
		t.Fatalf("fetch ran %d times after visit error, want 1", calls)
	}
}

func TestListAllAccumulatesPages(t *testing.T) {
	var seen []string
	page := scriptPage([][]string{{"a", "b"}, {"c"}, {"d", "e"}}, &seen)
	got, err := ListAll(ctx, metav1.ListOptions{}, page)
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if fmt.Sprint(got) != "[a b c d e]" {
		t.Fatalf("items = %v", got)
	}
}

func TestListAllEmptyResult(t *testing.T) {
	page := func(context.Context, metav1.ListOptions) ([]int, string, error) {
		return nil, "", nil
	}
	got, err := ListAll(ctx, metav1.ListOptions{}, page)
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if got != nil {
		t.Fatalf("items = %v, want nil", got)
	}
}

func TestListAllFirstPageError(t *testing.T) {
	page := func(context.Context, metav1.ListOptions) ([]int, string, error) {
		return nil, "", errors.New("denied")
	}
	if _, err := ListAll(ctx, metav1.ListOptions{}, page); err == nil {
		t.Fatal("expected error")
	}
}

// The typed adapter must return the page's Items and Continue token —
// exercised against the fake clientset (which serves everything in one
// page, so Continue is always "").
func TestPodsPageFunc(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "ns"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p2", Namespace: "ns"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p3", Namespace: "other"}},
	)
	pods, err := ListAll(ctx, metav1.ListOptions{}, Pods(cs, "ns"))
	if err != nil {
		t.Fatalf("ListAll Pods: %v", err)
	}
	if len(pods) != 2 {
		t.Fatalf("got %d pods in ns, want 2", len(pods))
	}
}

func TestResourceQuotasPageFunc(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&corev1.ResourceQuota{ObjectMeta: metav1.ObjectMeta{Name: "q1", Namespace: "ns"}},
		&corev1.ResourceQuota{ObjectMeta: metav1.ObjectMeta{Name: "q2", Namespace: "other"}},
	)
	quotas, err := ListAll(ctx, metav1.ListOptions{}, ResourceQuotas(cs, "ns"))
	if err != nil {
		t.Fatalf("ListAll ResourceQuotas: %v", err)
	}
	if len(quotas) != 1 || quotas[0].Name != "q1" {
		t.Fatalf("quotas = %+v", quotas)
	}
}

func TestVolumeAttachmentsPageFunc(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&storagev1.VolumeAttachment{ObjectMeta: metav1.ObjectMeta{Name: "va-1"}},
	)
	vas, err := ListAll(ctx, metav1.ListOptions{}, VolumeAttachments(cs))
	if err != nil {
		t.Fatalf("ListAll VolumeAttachments: %v", err)
	}
	if len(vas) != 1 || vas[0].Name != "va-1" {
		t.Fatalf("vas = %+v", vas)
	}
}

// The Apps workload constructors the snapshot censuses read through
// (probefw AllDeployments/AllDaemonSets) — namespace scoping + Items
// extraction, same single-page fake posture as the other adapters.
func TestDeploymentsPageFunc(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "d1", Namespace: "ns"}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "d2", Namespace: "other"}},
	)
	deps, err := ListAll(ctx, metav1.ListOptions{}, Deployments(cs, "ns"))
	if err != nil {
		t.Fatalf("ListAll Deployments: %v", err)
	}
	if len(deps) != 1 || deps[0].Name != "d1" {
		t.Fatalf("deployments = %+v", deps)
	}
}

func TestDaemonSetsPageFunc(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "ds1", Namespace: "ns"}},
	)
	dsets, err := ListAll(ctx, metav1.ListOptions{}, DaemonSets(cs, metav1.NamespaceAll))
	if err != nil {
		t.Fatalf("ListAll DaemonSets: %v", err)
	}
	if len(dsets) != 1 || dsets[0].Name != "ds1" {
		t.Fatalf("daemonsets = %+v", dsets)
	}
}

func TestDynamicPage(t *testing.T) {
	gvr := schema.GroupVersionResource{Group: "example.com", Version: "v1", Resource: "foos"}
	mk := func(name string) *unstructured.Unstructured {
		return testhelp.Unstructured(
			gvr.GroupVersion().WithKind("Foo"), "ns", name, nil)
	}
	dyn := testhelp.NewFakeDyn(
		map[schema.GroupVersionResource]string{gvr: "FooList"},
		mk("f1"), mk("f2"))

	items, err := ListAll(ctx, metav1.ListOptions{}, DynamicPage(dyn.Resource(gvr).Namespace("ns")))
	if err != nil {
		t.Fatalf("ListAll DynamicPage: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("got %d items, want 2", len(items))
	}
	names := map[string]bool{items[0].GetName(): true, items[1].GetName(): true}
	if !names["f1"] || !names["f2"] {
		t.Fatalf("unexpected items: %v %v", items[0].GetName(), items[1].GetName())
	}
}
