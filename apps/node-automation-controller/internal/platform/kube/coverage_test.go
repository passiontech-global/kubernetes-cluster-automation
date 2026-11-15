package kube

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestEmitWarningEvent(t *testing.T) {
	cs := fake.NewSimpleClientset()
	now := time.Unix(1700000000, 0).UTC()
	err := EmitWarningEvent(context.Background(), cs, WarningEvent{
		Namespace:         "default",
		Name:              "warn-1",
		Reason:            "ZoneStarvation",
		Note:              "zone-a has no endpoints",
		ReportingInstance: "ctrl-0",
		Now:               now,
		Regarding: corev1.ObjectReference{
			Kind:      "Service",
			Namespace: "default",
			Name:      "web",
		},
	})
	if err != nil {
		t.Fatalf("EmitWarningEvent: %v", err)
	}
	ev, err := cs.EventsV1().Events("default").Get(context.Background(), "warn-1", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get event: %v", err)
	}
	if ev.Reason != "ZoneStarvation" || ev.Type != corev1.EventTypeWarning || ev.ReportingController != "node-automation-controller" {
		t.Fatalf("unexpected event: %+v", ev)
	}
}

func TestCoreRESTClient(t *testing.T) {
	if _, ok := CoreRESTClient(nil); ok {
		t.Fatal("nil clientset should return false")
	}
	if _, ok := CoreRESTClient(fake.NewSimpleClientset()); ok {
		t.Fatal("fake clientset typed-nil RESTClient should return false")
	}
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	cs, err := kubernetes.NewForConfig(&rest.Config{Host: srv.URL})
	if err != nil {
		t.Fatalf("NewForConfig: %v", err)
	}
	if rc, ok := CoreRESTClient(cs); !ok || rc == nil {
		t.Fatalf("real clientset CoreRESTClient = (%v,%v), want (non-nil,true)", rc, ok)
	}
}

type fakePodReader struct {
	items []corev1.Pod
	err   error
}

func (f fakePodReader) Get(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error {
	return nil
}

func (f fakePodReader) List(_ context.Context, list client.ObjectList, _ ...client.ListOption) error {
	if f.err != nil {
		return f.err
	}
	list.(*corev1.PodList).Items = append([]corev1.Pod(nil), f.items...)
	return nil
}

func TestListPodsCached(t *testing.T) {
	p1 := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "cilium-1", Labels: map[string]string{"k8s-app": "cilium"}}}
	cs := fake.NewSimpleClientset(&p1)
	sel := labels.SelectorFromSet(labels.Set{"k8s-app": "cilium"})

	// Nil reader falls back to direct clientset list.
	got, err := ListPodsCached(context.Background(), nil, cs, "kube-system", sel)
	if err != nil || len(got) != 1 || got[0].Name != "cilium-1" {
		t.Fatalf("nil reader ListPodsCached = (%+v,%v)", got, err)
	}

	// Non-nil reader uses cached List.
	got, err = ListPodsCached(context.Background(), fakePodReader{items: []corev1.Pod{p1}}, cs, "kube-system", sel)
	if err != nil || len(got) != 1 {
		t.Fatalf("cached ListPodsCached = (%+v,%v)", got, err)
	}

	// Reader error propagates.
	if _, err := ListPodsCached(context.Background(), fakePodReader{err: errors.New("cache not started")}, cs, "kube-system", sel); err == nil {
		t.Fatal("expected cached reader error")
	}
}

func TestPodLogLineTSAndReadPodLogTailTimed(t *testing.T) {
	if ts, ok := PodLogLineTS("2026-01-02T03:04:05.123456789Z hello world"); !ok || ts.Year() != 2026 {
		t.Fatalf("PodLogLineTS valid = (%v,%v)", ts, ok)
	}
	if _, ok := PodLogLineTS("nospace"); ok {
		t.Fatal("expected ok=false without space")
	}
	if _, ok := PodLogLineTS("not-a-ts hello"); ok {
		t.Fatal("expected ok=false for bad timestamp")
	}

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "p1"}}
	cs := fake.NewSimpleClientset(pod)
	matched, newest, streamNewest, err := ReadPodLogTailTimed(context.Background(), cs, pod, PodLogOpts{Timestamps: true}, func(line string) bool {
		return line == "fake logs"
	})
	if err != nil || !matched || !newest.IsZero() || !streamNewest.IsZero() {
		t.Fatalf("ReadPodLogTailTimed = (%v,%v,%v,%v), want (true,0,0,nil)", matched, newest, streamNewest, err)
	}
}

func TestPodHelpers(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0"},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "pvc-1"}}},
				{Name: "scratch", VolumeSource: corev1.VolumeSource{Ephemeral: &corev1.EphemeralVolumeSource{}}},
				{Name: "empty", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
			},
		},
	}
	if got := PodClaimedPVCs(pod); !slices.Equal(got, []string{"pvc-1", "web-0-scratch"}) {
		t.Fatalf("PodClaimedPVCs = %v", got)
	}

	if got := LeaseHolderPodCandidates(nil); got != nil {
		t.Fatalf("nil lease = %v, want nil", got)
	}
	h1 := "ctrl-abc_1234-5678"
	if got := LeaseHolderPodCandidates(&coordinationv1.Lease{Spec: coordinationv1.LeaseSpec{HolderIdentity: &h1}}); !slices.Equal(got, []string{"ctrl-abc", "ctrl-abc_1234-5678"}) {
		t.Fatalf("LeaseHolderPodCandidates(uuid) = %v", got)
	}
	h2 := "plain-holder"
	if got := LeaseHolderPodCandidates(&coordinationv1.Lease{Spec: coordinationv1.LeaseSpec{HolderIdentity: &h2}}); !slices.Equal(got, []string{"plain-holder"}) {
		t.Fatalf("LeaseHolderPodCandidates(plain) = %v", got)
	}

	activeJob := &batchv1.Job{}
	completeJob := &batchv1.Job{Status: batchv1.JobStatus{Conditions: []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}}}
	failedJob := &batchv1.Job{Status: batchv1.JobStatus{Conditions: []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue}}}}
	if JobTerminal(activeJob) || !JobTerminal(completeJob) || !JobTerminal(failedJob) {
		t.Fatal("JobTerminal mismatch")
	}
}

func TestSweepOverlayPVCTombstonesAndNodeLookup(t *testing.T) {
	pvcs := []corev1.PersistentVolumeClaim{
		{ObjectMeta: metav1.ObjectMeta{Name: "p1", UID: types.UID("u1")}},
		{ObjectMeta: metav1.ObjectMeta{Name: "p2", UID: types.UID("u2")}},
	}
	// Outside a sweep: no-op.
	MarkPVCDeleted(context.Background(), types.UID("u1"))
	if got := FilterPVCTombstones(context.Background(), pvcs); len(got) != 2 {
		t.Fatalf("outside sweep FilterPVCTombstones len = %d, want 2", len(got))
	}

	ctx := WithSweepOverlay(context.Background())
	if got := FilterPVCTombstones(ctx, pvcs); len(got) != 2 {
		t.Fatalf("empty tombstones len = %d, want 2", len(got))
	}
	MarkPVCDeleted(ctx, types.UID("u1"))
	got := FilterPVCTombstones(ctx, pvcs)
	if len(got) != 1 || got[0].Name != "p2" {
		t.Fatalf("FilterPVCTombstones = %+v, want [p2]", got)
	}

	if fn := SweepNodeLookup(context.Background()); fn != nil {
		t.Fatal("expected nil SweepNodeLookup outside sweep")
	}
	wantNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}}
	ctx = WithSweepNodeLookup(ctx, func(_ context.Context, name string) (*corev1.Node, error) {
		if name == "n1" {
			return wantNode, nil
		}
		return nil, nil
	})
	fn := SweepNodeLookup(ctx)
	if fn == nil {
		t.Fatal("expected non-nil SweepNodeLookup")
	}
	if n, err := fn(ctx, "n1"); err != nil || n != wantNode {
		t.Fatalf("lookup(n1) = (%v,%v)", n, err)
	}
}

func TestNestedTimeAndNestedStatusTimeOrCreated(t *testing.T) {
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	u := &unstructured.Unstructured{
		Object: map[string]any{
			"status": map[string]any{
				"badTime":  "not-rfc3339",
				"goodTime": "2026-02-03T04:05:06Z",
			},
		},
	}
	u.SetCreationTimestamp(metav1.NewTime(created))

	if _, ok := NestedTime(u.Object, "status", "missing"); ok {
		t.Fatal("expected missing time to return false")
	}
	if _, ok := NestedTime(u.Object, "status", "badTime"); ok {
		t.Fatal("expected invalid time to return false")
	}
	if got, ok := NestedTime(u.Object, "status", "goodTime"); !ok || got.Month() != time.February {
		t.Fatalf("NestedTime = (%v,%v)", got, ok)
	}

	if got := NestedStatusTimeOrCreated(u, "badTime", "goodTime"); got.Month() != time.February {
		t.Fatalf("NestedStatusTimeOrCreated = %v, want Feb", got)
	}
	if got := NestedStatusTimeOrCreated(u, "badTime", "missing"); !got.Equal(created) {
		t.Fatalf("NestedStatusTimeOrCreated fallback = %v, want %v", got, created)
	}
}
