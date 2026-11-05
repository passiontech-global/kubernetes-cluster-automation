package orphanendpointslicecleaner

import (
	"errors"
	"testing"
	"time"

	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
)

// ---------------------------------------------------------------------------
// Builders (oesc-prefixed)
// ---------------------------------------------------------------------------

func oescService(ns, name string) *corev1.Service {
	return &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
}

func oescSlice(ns, name, svcName string, age time.Duration) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name, UID: types.UID("uid-" + name),
			Labels:            map[string]string{discoveryv1.LabelServiceName: svcName},
			CreationTimestamp: metav1.NewTime(time.Now().Add(-age)),
		},
	}
}

func oescSliceExists(t *testing.T, cs *fake.Clientset, ns, name string) bool {
	t.Helper()
	_, err := cs.DiscoveryV1().EndpointSlices(ns).Get(ctx, name, metav1.GetOptions{})
	return err == nil
}

func oescCleaner(cs *fake.Clientset) *orphanEndpointSliceCleaner {
	return &orphanEndpointSliceCleaner{cs: cs, now: time.Now,
		absentStreak: map[string]int{}}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// The two-cycle gate: a slice whose Service is absent survives the
// first sighting and is reaped on the second consecutive one —
// re-confirmed by a live Get first.
func TestOrphanEndpointSliceTwoCycleReap(t *testing.T) {
	metrics.OrphanEndpointSlicesCleanedTotal.DeleteLabelValues("apps")
	t.Cleanup(func() {
		metrics.OrphanEndpointSlicesCleanedTotal.DeleteLabelValues("apps")
	})

	cs := fake.NewSimpleClientset(
		oescService("default", "kubernetes"),
		oescSlice("apps", "gone-abc", "gone", 30*time.Minute))
	c := oescCleaner(cs)

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !oescSliceExists(t, cs, "apps", "gone-abc") {
		t.Fatal("slice reaped on first sighting — streak gate failed")
	}
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if oescSliceExists(t, cs, "apps", "gone-abc") {
		t.Fatal("orphan slice not reaped after 2 consecutive absent cycles")
	}
	if got := ptestutil.ToFloat64(
		metrics.OrphanEndpointSlicesCleanedTotal.WithLabelValues("apps")); got != 1 {
		t.Fatalf("cleaned counter = %v, want 1", got)
	}
}

// A Service that reappears between cycles resets the streak — the
// slice re-arms from zero.
func TestOrphanEndpointSliceStreakResets(t *testing.T) {
	svc := oescService("apps", "flap")
	cs := fake.NewSimpleClientset(
		oescService("default", "kubernetes"),
		oescSlice("apps", "flap-abc", "flap", 30*time.Minute))
	c := oescCleaner(cs)

	if err := c.run(ctx); err != nil {
		t.Fatal(err) // streak = 1
	}
	// Service lands mid-window — snapshot sees it again.
	if _, err := cs.CoreV1().Services("apps").Create(ctx, svc, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if len(c.absentStreak) != 0 {
		t.Fatal("streak kept after the Service reappeared")
	}
	// Service vanishes again — the count starts over, so the next
	// two sightings are required before any delete.
	if err := cs.CoreV1().Services("apps").Delete(ctx, "flap", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !oescSliceExists(t, cs, "apps", "flap-abc") {
		t.Fatal("slice reaped on a restarted streak of 1")
	}
}

// A slice younger than 15m is never reaped — created-before-service
// races resolve inside the window.
func TestOrphanEndpointSliceTooFresh(t *testing.T) {
	cs := fake.NewSimpleClientset(
		oescService("default", "kubernetes"),
		oescSlice("apps", "young-abc", "young", 5*time.Minute))
	c := oescCleaner(cs)

	for i := 0; i < 3; i++ {
		if err := c.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if !oescSliceExists(t, cs, "apps", "young-abc") {
		t.Fatal("fresh slice reaped despite the age gate")
	}
}

// default/kubernetes* is control-plane — never a candidate, streak
// or delete.
func TestOrphanEndpointSliceSkipsDefaultKubernetes(t *testing.T) {
	cs := fake.NewSimpleClientset(
		oescSlice("default", "kubernetes", "kubernetes", time.Hour))
	c := oescCleaner(cs)

	// Note: NO services at all except none — wait, the fail-closed
	// gate needs a non-empty service list. Add an unrelated service.
	if _, err := cs.CoreV1().Services("apps").Create(ctx,
		oescService("apps", "web"), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := c.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if !oescSliceExists(t, cs, "default", "kubernetes") {
		t.Fatal("control-plane slice reaped")
	}
	if len(c.absentStreak) != 0 {
		t.Fatal("control-plane slice tracked as absent")
	}
}

// An empty Service list is an API flap — abort with error, delete
// nothing.
func TestOrphanEndpointSliceEmptyServiceList(t *testing.T) {
	cs := fake.NewSimpleClientset(
		oescSlice("apps", "gone-abc", "gone", 30*time.Minute))
	c := oescCleaner(cs)
	if err := c.run(ctx); err == nil {
		t.Fatal("expected abort on an empty service snapshot")
	}
	if !oescSliceExists(t, cs, "apps", "gone-abc") {
		t.Fatal("slice deleted on an empty service snapshot")
	}
}

// A service-list error is a real run error — fail closed.
func TestOrphanEndpointSliceServiceListError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "services",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	c := oescCleaner(cs)
	if err := c.run(ctx); err == nil {
		t.Fatal("expected error when the service list fails")
	}
}

// A live Get that finds the Service (snapshot was stale) clears the
// streak instead of deleting.
func TestOrphanEndpointSliceStaleSnapshotConfirmKeeps(t *testing.T) {
	slice := oescSlice("apps", "flaky-abc", "flaky", 30*time.Minute)
	cs := fake.NewSimpleClientset(
		oescService("default", "kubernetes"),
		oescService("apps", "flaky"), // exists, hidden from List below
		slice)
	cs.PrependReactor("list", "services",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, &corev1.ServiceList{Items: []corev1.Service{
				*oescService("default", "kubernetes"),
			}}, nil
		})
	c := oescCleaner(cs)

	// Cycle 1 streaks to 1; cycle 2 reaches the confirm gate where
	// the live Get finds the Service — the streak clears instead
	// of deleting.
	for i := 0; i < 2; i++ {
		if err := c.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if !oescSliceExists(t, cs, "apps", "flaky-abc") {
		t.Fatal("slice deleted on a stale snapshot — Get re-confirm failed")
	}
	if len(c.absentStreak) != 0 {
		t.Fatal("streak kept after Get found the Service")
	}
}

// The delete carries a UID precondition — a same-named slice
// recreated between the IsNotFound re-confirm and the delete is not
// the object this sweep vetted.
func TestOrphanEndpointSliceDeleteUIDPrecondition(t *testing.T) {
	slice := oescSlice("apps", "gone-abc", "gone", 30*time.Minute)
	cs := fake.NewSimpleClientset(
		oescService("default", "kubernetes"), slice)
	var gotUID *types.UID
	cs.PrependReactor("delete", "endpointslices",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			opts := a.(ktesting.DeleteAction).GetDeleteOptions()
			if opts.Preconditions != nil {
				gotUID = opts.Preconditions.UID
			}
			return false, nil, nil // fall through to the tracker
		})
	c := oescCleaner(cs)
	for i := 0; i < 2; i++ {
		if err := c.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if gotUID == nil || *gotUID != slice.UID {
		t.Fatalf("delete missing the UID precondition: %v", gotUID)
	}
	if oescSliceExists(t, cs, "apps", "gone-abc") {
		t.Fatal("orphan slice not reaped")
	}
}

// A slice already Terminating is skipped entirely — the API owns it
// now, so it must not accrue absent-streak cycles nor consume a
// delete attempt.
func TestOrphanEndpointSliceSkipsTerminating(t *testing.T) {
	slice := oescSlice("apps", "gone-abc", "gone", 30*time.Minute)
	ts := metav1.NewTime(time.Now())
	slice.DeletionTimestamp = &ts
	cs := fake.NewSimpleClientset(
		oescService("default", "kubernetes"), slice)
	var deletes int
	cs.PrependReactor("delete", "endpointslices",
		func(ktesting.Action) (bool, runtime.Object, error) {
			deletes++
			return false, nil, nil
		})
	c := oescCleaner(cs)
	for i := 0; i < 3; i++ {
		if err := c.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if deletes != 0 {
		t.Fatalf("terminating slice consumed %d delete attempt(s)", deletes)
	}
	if len(c.absentStreak) != 0 {
		t.Fatal("terminating slice accrued an absent streak")
	}
	if !oescSliceExists(t, cs, "apps", "gone-abc") {
		t.Fatal("terminating slice vanished")
	}
}

// Slices without the service-name label are ignored entirely.
func TestOrphanEndpointSliceIgnoresUnlabeled(t *testing.T) {
	plain := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{
		Namespace: "apps", Name: "manual", UID: "uid-manual",
		CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour))}}
	cs := fake.NewSimpleClientset(
		oescService("default", "kubernetes"), plain)
	c := oescCleaner(cs)
	for i := 0; i < 3; i++ {
		if err := c.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if !oescSliceExists(t, cs, "apps", "manual") {
		t.Fatal("unlabeled slice reaped")
	}
}
