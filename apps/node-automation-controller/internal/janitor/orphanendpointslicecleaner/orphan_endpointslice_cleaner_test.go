package orphanendpointslicecleaner

import (
	"context"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	typeddiscoveryv1 "k8s.io/client-go/kubernetes/typed/discovery/v1"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
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
	return &orphanEndpointSliceCleaner{cs: cs, now: time.Now}
}

// oescStreakKey is the absentStreak ledger key run() builds for a
// slice — "ns/name/uid".
func oescStreakKey(s *discoveryv1.EndpointSlice) string {
	return s.Namespace + "/" + s.Name + "/" + string(s.UID)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// The two-cycle gate: a slice whose Service is absent survives the
// first sighting and is reaped on the second consecutive one —
// re-confirmed by a live Get first.
func TestOrphanEndpointSliceTwoCycleReap(t *testing.T) {
	testutil.CleanupMetric(t, metrics.OrphanEndpointSlicesCleanedTotal, "apps")

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
	slice := oescSlice("apps", "flap-abc", "flap", 30*time.Minute)
	cs := fake.NewSimpleClientset(
		oescService("default", "kubernetes"), slice)
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
	if c.absentStreak.Count(oescStreakKey(slice)) != 0 {
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
	slice := oescSlice("default", "kubernetes", "kubernetes", time.Hour)
	cs := fake.NewSimpleClientset(slice)
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
	if c.absentStreak.Count(oescStreakKey(slice)) != 0 {
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
	if c.absentStreak.Count(oescStreakKey(slice)) != 0 {
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

// A benign delete race is not a run error: NotFound (the vetted
// slice was already gone) and Conflict (the UID precondition caught
// a same-named slice recreated between the census and the delete)
// both mean the object we vetted is no longer on the cluster — the
// sweep stays green, IncError stays silent, and the cleaned counter
// does not credit a delete we did not deliver.
func TestOrphanEndpointSliceBenignDeleteRaces(t *testing.T) {
	for name, delErr := range map[string]error{
		"notFound": apierrors.NewNotFound(
			discoveryv1.Resource("endpointslices"), "gone-abc"),
		"conflict": apierrors.NewConflict(
			discoveryv1.Resource("endpointslices"), "gone-abc",
			errors.New("object was modified")),
	} {
		t.Run(name, func(t *testing.T) {
			testutil.CleanupMetric(t, metrics.OrphanEndpointSlicesCleanedTotal, "apps")
			slice := oescSlice("apps", "gone-abc", "gone", 30*time.Minute)
			cs := fake.NewSimpleClientset(
				oescService("default", "kubernetes"), slice)
			cs.PrependReactor("delete", "endpointslices",
				func(ktesting.Action) (bool, runtime.Object, error) {
					return true, nil, delErr
				})
			c := oescCleaner(cs)
			c.queue = "orphan-endpointslice-cleaner" // the IncError label the assertion reads
			before := testutil.QueueErrorCount(t, c.queue)
			for range 2 {
				if err := c.run(ctx); err != nil {
					t.Fatalf("benign race must not fail the run: %v", err)
				}
			}
			if got := testutil.QueueErrorCount(t, c.queue); got != before {
				t.Fatalf("benign delete race IncError'd: delta %v", got-before)
			}
			if got := ptestutil.ToFloat64(
				metrics.OrphanEndpointSlicesCleanedTotal.WithLabelValues("apps")); got != 0 {
				t.Fatalf("cleaned counter = %v on a refused delete, want 0", got)
			}
		})
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
	if c.absentStreak.Count(oescStreakKey(slice)) != 0 {
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

// ---------------------------------------------------------------------------
// Delete cap, streak bookkeeping, fail-closed confirm
// ---------------------------------------------------------------------------

// oescTrackedCount reports how many keys the absentStreak ledger
// holds — the ledger exposes no Len, so a keep-all Prune counts it.
func oescTrackedCount(l *state.StreakLedger) int {
	n := 0
	l.Prune(func(string) bool { return true })
	return n
}

// The delete cap bounds churn at orphanEndpointSliceDeleteCap per
// sweep even with more streak-qualified orphans: exactly the cap
// number of slices go (deterministically the ns/name-sorted head),
// the survivors keep their full streak (NOT re-armed to 1), and reap
// on the very next cycle.
func TestOrphanEndpointSliceDeleteCap(t *testing.T) {
	testutil.CleanupMetric(t, metrics.OrphanEndpointSlicesCleanedTotal, "apps")
	objs := []runtime.Object{oescService("default", "kubernetes")}
	var slices []*discoveryv1.EndpointSlice
	for i := 0; i < orphanEndpointSliceDeleteCap+2; i++ {
		s := oescSlice("apps", fmt.Sprintf("cap-%02d-xyz", i), "gone", 30*time.Minute)
		slices = append(slices, s)
		objs = append(objs, s)
	}
	cs := fake.NewSimpleClientset(objs...)
	c := oescCleaner(cs)

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	} // streak 1 for all
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	remaining := 0
	for _, s := range slices {
		if oescSliceExists(t, cs, "apps", s.Name) {
			remaining++
			// Survivors must carry their FULL streak into the next
			// cycle — a re-armed streak would add another 2-cycle
			// delay on top of the cap.
			if got := c.absentStreak.Count(oescStreakKey(s)); got != 2 {
				t.Fatalf("survivor %s streak = %d, want 2", s.Name, got)
			}
		}
	}
	if remaining != 2 {
		t.Fatalf("survivors after cap = %d, want 2", remaining)
	}
	// The deterministic ns/name ordering means the sorted head went:
	// cap-50/cap-51 (names cap-00..cap-51) survive.
	for _, name := range []string{"cap-50-xyz", "cap-51-xyz"} {
		if !oescSliceExists(t, cs, "apps", name) {
			t.Fatalf("slice %s deleted despite sorting after the cap boundary", name)
		}
	}
	if got := ptestutil.ToFloat64(
		metrics.OrphanEndpointSlicesCleanedTotal.WithLabelValues("apps")); got != orphanEndpointSliceDeleteCap {
		t.Fatalf("cleaned counter = %v, want %d", got, orphanEndpointSliceDeleteCap)
	}
	// Cycle 3: the two survivors reap immediately.
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if oescSliceExists(t, cs, "apps", "cap-50-xyz") || oescSliceExists(t, cs, "apps", "cap-51-xyz") {
		t.Fatal("capped survivors not reaped on the following cycle")
	}
}

// A slice deleted externally between cycles must not leave a stale
// streak entry behind — the per-sweep prune drops ledger keys that
// no longer appear in the orphan census.
func TestOrphanEndpointSliceStreakPrunedWhenSliceVanishes(t *testing.T) {
	slice := oescSlice("apps", "vanish-xyz", "gone", 30*time.Minute)
	cs := fake.NewSimpleClientset(
		oescService("default", "kubernetes"), slice)
	c := oescCleaner(cs)

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if c.absentStreak.Count(oescStreakKey(slice)) != 1 {
		t.Fatal("first sighting not recorded")
	}
	// External cleanup removes the slice between cycles.
	if err := cs.DiscoveryV1().EndpointSlices("apps").
		Delete(ctx, slice.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := oescTrackedCount(&c.absentStreak); got != 0 {
		t.Fatalf("streak ledger holds %d entries after the slice vanished, want 0", got)
	}
}

// A non-NotFound Service Get failure at the live re-confirm keeps the
// slice (fail closed), meters the error, and retains the streak —
// the next cycle retries the delete instead of re-arming 2 cycles.
func TestOrphanEndpointSliceConfirmErrorFailsClosed(t *testing.T) {
	testutil.CleanupMetric(t, metrics.OrphanEndpointSlicesCleanedTotal, "apps")
	slice := oescSlice("apps", "confirm-xyz", "gone", 30*time.Minute)
	cs := fake.NewSimpleClientset(
		oescService("default", "kubernetes"), slice)
	c := oescCleaner(cs)
	c.queue = "orphan-endpointslice-cleaner"
	c.absentStreak.Set(oescStreakKey(slice), orphanEndpointSliceStreak-1)

	cs.PrependReactor("get", "services",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	before := testutil.QueueErrorCount(t, "orphan-endpointslice-cleaner")
	if err := c.run(ctx); err != nil {
		t.Fatalf("confirm failure must not error the run: %v", err)
	}
	if !oescSliceExists(t, cs, "apps", slice.Name) {
		t.Fatal("slice deleted when the Service confirm failed")
	}
	if got := testutil.QueueErrorCount(t, "orphan-endpointslice-cleaner") - before; got != 1 {
		t.Fatalf("confirm failure not metered: error delta = %v, want 1", got)
	}
	if got := c.absentStreak.Count(oescStreakKey(slice)); got != orphanEndpointSliceStreak {
		t.Fatalf("streak not retained after failed confirm: %d, want %d",
			got, orphanEndpointSliceStreak)
	}
}

type oescRecordingCS struct {
	kubernetes.Interface
	svcListOpts   []metav1.ListOptions
	sliceListOpts []metav1.ListOptions
	podListOpts   []metav1.ListOptions
	svcGetOpts    []metav1.GetOptions
	sliceGetOpts  []metav1.GetOptions
	podGetOpts    []metav1.GetOptions
}

type oescRecordingCoreV1 struct {
	typedcorev1.CoreV1Interface
	parent *oescRecordingCS
}

type oescRecordingServices struct {
	typedcorev1.ServiceInterface
	parent *oescRecordingCS
}

type oescRecordingPods struct {
	typedcorev1.PodInterface
	parent *oescRecordingCS
}

type oescRecordingDiscoveryV1 struct {
	typeddiscoveryv1.DiscoveryV1Interface
	parent *oescRecordingCS
}

type oescRecordingSlices struct {
	typeddiscoveryv1.EndpointSliceInterface
	parent *oescRecordingCS
}

func (c *oescRecordingCS) CoreV1() typedcorev1.CoreV1Interface {
	return &oescRecordingCoreV1{CoreV1Interface: c.Interface.CoreV1(), parent: c}
}

func (c *oescRecordingCS) DiscoveryV1() typeddiscoveryv1.DiscoveryV1Interface {
	return &oescRecordingDiscoveryV1{DiscoveryV1Interface: c.Interface.DiscoveryV1(), parent: c}
}

func (c *oescRecordingCoreV1) Services(ns string) typedcorev1.ServiceInterface {
	return &oescRecordingServices{ServiceInterface: c.CoreV1Interface.Services(ns), parent: c.parent}
}

func (c *oescRecordingCoreV1) Pods(ns string) typedcorev1.PodInterface {
	return &oescRecordingPods{PodInterface: c.CoreV1Interface.Pods(ns), parent: c.parent}
}

func (s *oescRecordingServices) List(ctx context.Context, opts metav1.ListOptions) (*corev1.ServiceList, error) {
	s.parent.svcListOpts = append(s.parent.svcListOpts, opts)
	return s.ServiceInterface.List(ctx, opts)
}

func (s *oescRecordingServices) Get(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.Service, error) {
	s.parent.svcGetOpts = append(s.parent.svcGetOpts, opts)
	return s.ServiceInterface.Get(ctx, name, opts)
}

func (p *oescRecordingPods) List(ctx context.Context, opts metav1.ListOptions) (*corev1.PodList, error) {
	p.parent.podListOpts = append(p.parent.podListOpts, opts)
	return p.PodInterface.List(ctx, opts)
}

func (p *oescRecordingPods) Get(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.Pod, error) {
	p.parent.podGetOpts = append(p.parent.podGetOpts, opts)
	return p.PodInterface.Get(ctx, name, opts)
}

func (d *oescRecordingDiscoveryV1) EndpointSlices(ns string) typeddiscoveryv1.EndpointSliceInterface {
	return &oescRecordingSlices{EndpointSliceInterface: d.DiscoveryV1Interface.EndpointSlices(ns), parent: d.parent}
}

func (s *oescRecordingSlices) List(ctx context.Context, opts metav1.ListOptions) (*discoveryv1.EndpointSliceList, error) {
	s.parent.sliceListOpts = append(s.parent.sliceListOpts, opts)
	return s.EndpointSliceInterface.List(ctx, opts)
}

func (s *oescRecordingSlices) Get(ctx context.Context, name string, opts metav1.GetOptions) (*discoveryv1.EndpointSlice, error) {
	s.parent.sliceGetOpts = append(s.parent.sliceGetOpts, opts)
	return s.EndpointSliceInterface.Get(ctx, name, opts)
}

// Both census LISTs (Services and EndpointSlices) read from the watch cache
// (ResourceVersion="0", Limit=0 via pageOpts), while Confirm still issues a
// live quorum Services.Get (ResourceVersion="").
func TestOrphanEndpointSliceResourceVersionZeroAndLiveConfirm(t *testing.T) {
	testutil.CleanupMetric(t, metrics.OrphanEndpointSlicesCleanedTotal, "apps")
	fakeCS := fake.NewSimpleClientset(
		oescService("default", "kubernetes"),
		oescSlice("apps", "gone-abc", "gone", 30*time.Minute))
	rec := &oescRecordingCS{Interface: fakeCS}
	c := &orphanEndpointSliceCleaner{cs: rec, now: time.Now}

	for range 2 {
		if err := c.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if len(rec.svcListOpts) != 2 || len(rec.sliceListOpts) != 2 {
		t.Fatalf("list counts = (services=%d, slices=%d), want (2, 2)",
			len(rec.svcListOpts), len(rec.sliceListOpts))
	}
	for i, opts := range rec.svcListOpts {
		if opts.ResourceVersion != "0" || opts.Limit != 0 {
			t.Fatalf("service list %d = (RV=%q, Limit=%d), want (\"0\", 0)",
				i, opts.ResourceVersion, opts.Limit)
		}
	}
	for i, opts := range rec.sliceListOpts {
		if opts.ResourceVersion != "0" || opts.Limit != 0 || opts.LabelSelector != discoveryv1.LabelServiceName {
			t.Fatalf("endpointslice list %d = (RV=%q, Limit=%d, Label=%q), want (\"0\", 0, %q)",
				i, opts.ResourceVersion, opts.Limit, opts.LabelSelector, discoveryv1.LabelServiceName)
		}
	}
	if len(rec.svcGetOpts) != 1 || rec.svcGetOpts[0].ResourceVersion != "" {
		t.Fatalf("confirm Service.Get opts = %+v, want 1 live Get with RV=\"\"", rec.svcGetOpts)
	}
	if oescSliceExists(t, fakeCS, "apps", "gone-abc") {
		t.Fatal("orphan slice not reaped")
	}
}

// ---------------------------------------------------------------------------
// R6-K8: Ghost Pod UID detection & remediation tests
// ---------------------------------------------------------------------------

func oescPod(ns, name, uid string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID(uid)},
	}
}

func oescPodEndpoint(ip, ns, name, uid string) discoveryv1.Endpoint {
	ready := true
	return discoveryv1.Endpoint{
		Addresses:  []string{ip},
		Conditions: discoveryv1.EndpointConditions{Ready: &ready},
		TargetRef: &corev1.ObjectReference{
			Kind:      "Pod",
			Namespace: ns,
			Name:      name,
			UID:       types.UID(uid),
		},
	}
}

func oescGhostKey(s *discoveryv1.EndpointSlice, podUID types.UID) string {
	return "ghost:" + s.Namespace + "/" + s.Name + "/" + string(s.UID) + "/" + string(podUID)
}

func TestOrphanEndpointSliceGhostEndpoints(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "streak 1 only keeps ghost endpoint and sets streak=1",
			run: func(t *testing.T) {
				slice := oescSlice("apps", "web-slice", "web", 30*time.Minute)
				slice.Endpoints = []discoveryv1.Endpoint{
					oescPodEndpoint("10.0.0.1", "apps", "web-live", "uid-live"),
					oescPodEndpoint("10.0.0.2", "apps", "web-dead", "uid-dead"),
				}
				cs := fake.NewSimpleClientset(
					oescService("default", "kubernetes"),
					oescService("apps", "web"),
					oescPod("apps", "web-live", "uid-live"),
					slice,
				)
				c := oescCleaner(cs)
				if err := c.run(ctx); err != nil {
					t.Fatal(err)
				}
				got, err := cs.DiscoveryV1().EndpointSlices("apps").Get(ctx, "web-slice", metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if len(got.Endpoints) != 2 {
					t.Fatalf("endpoints after cycle 1 = %d, want 2", len(got.Endpoints))
				}
				if gotStreak := c.ghostStreak.Count(oescGhostKey(slice, "uid-dead")); gotStreak != 1 {
					t.Fatalf("ghost streak = %d, want 1", gotStreak)
				}
			},
		},
		{
			name: "fresh slice (<15m) is never patched or deleted despite streak >= 2",
			run: func(t *testing.T) {
				slice := oescSlice("apps", "young-slice", "web", 5*time.Minute)
				slice.Endpoints = []discoveryv1.Endpoint{
					oescPodEndpoint("10.0.0.2", "apps", "web-dead", "uid-dead"),
				}
				cs := fake.NewSimpleClientset(
					oescService("default", "kubernetes"),
					oescService("apps", "web"),
					oescPod("kube-system", "coredns", "uid-coredns"),
					slice,
				)
				c := oescCleaner(cs)
				for range 3 {
					if err := c.run(ctx); err != nil {
						t.Fatal(err)
					}
				}
				if !oescSliceExists(t, cs, "apps", "young-slice") {
					t.Fatal("fresh slice with ghost Pod was deleted")
				}
			},
		},
		{
			name: "partial ghost slice patches with MergePatchType + resourceVersion and preserves non-ghost endpoints",
			run: func(t *testing.T) {
				testutil.CleanupMetric(t, metrics.OrphanEndpointSlicesCleanedTotal, "apps")
				slice := oescSlice("apps", "mixed-slice", "web", 30*time.Minute)
				slice.ResourceVersion = "42"
				ready := true
				slice.Endpoints = []discoveryv1.Endpoint{
					oescPodEndpoint("10.0.0.1", "apps", "web-live", "uid-live"),
					oescPodEndpoint("10.0.0.2", "", "web-dead-empty-ns", "uid-dead"),
					{
						Addresses:  []string{"192.0.2.10"},
						Conditions: discoveryv1.EndpointConditions{Ready: &ready},
					},
					{
						Addresses: []string{"10.0.0.3"},
						TargetRef: &corev1.ObjectReference{Kind: "Node", Name: "worker-1", UID: "node-uid-1"},
					},
					{
						Addresses: []string{"10.0.0.4"},
						TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: "apps", Name: "no-uid"},
					},
				}
				cs := fake.NewSimpleClientset(
					oescService("default", "kubernetes"),
					oescService("apps", "web"),
					oescPod("apps", "web-live", "uid-live"),
					slice,
				)
				var patchType types.PatchType
				var patchBody []byte
				cs.PrependReactor("patch", "endpointslices",
					func(a ktesting.Action) (bool, runtime.Object, error) {
						pa := a.(ktesting.PatchAction)
						patchType = pa.GetPatchType()
						patchBody = pa.GetPatch()
						return false, nil, nil
					})
				c := oescCleaner(cs)
				for range 2 {
					if err := c.run(ctx); err != nil {
						t.Fatal(err)
					}
				}
				if patchType != types.MergePatchType {
					t.Fatalf("patchType = %v, want MergePatchType", patchType)
				}
				var parsed map[string]any
				if err := json.Unmarshal(patchBody, &parsed); err != nil {
					t.Fatalf("unmarshal patch body: %v", err)
				}
				metaMap, _ := parsed["metadata"].(map[string]any)
				if metaMap["resourceVersion"] != "42" {
					t.Fatalf("patch metadata.resourceVersion = %v, want \"42\"", metaMap["resourceVersion"])
				}
				got, err := cs.DiscoveryV1().EndpointSlices("apps").Get(ctx, "mixed-slice", metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if len(got.Endpoints) != 4 {
					t.Fatalf("remaining endpoints = %d, want 4: %+v", len(got.Endpoints), got.Endpoints)
				}
				for _, ep := range got.Endpoints {
					if ep.TargetRef != nil && ep.TargetRef.UID == "uid-dead" {
						t.Fatalf("ghost endpoint still present after patch: %+v", ep)
					}
				}
				if cnt := ptestutil.ToFloat64(metrics.OrphanEndpointSlicesCleanedTotal.WithLabelValues("apps")); cnt != 0 {
					t.Fatalf("cleaned counter = %v, want 0 on partial patch", cnt)
				}
				if c.ghostStreak.Count(oescGhostKey(slice, "uid-dead")) != 0 {
					t.Fatal("ghost streak not cleared after successful patch")
				}
			},
		},
		{
			name: "all-ghost slice deletes with UID precondition and increments cleaned counter",
			run: func(t *testing.T) {
				testutil.CleanupMetric(t, metrics.OrphanEndpointSlicesCleanedTotal, "apps")
				slice := oescSlice("apps", "all-ghost", "web", 30*time.Minute)
				slice.Endpoints = []discoveryv1.Endpoint{
					oescPodEndpoint("10.0.0.2", "apps", "web-dead-1", "uid-dead-1"),
					oescPodEndpoint("10.0.0.3", "apps", "web-dead-2", "uid-dead-2"),
				}
				cs := fake.NewSimpleClientset(
					oescService("default", "kubernetes"),
					oescService("apps", "web"),
					oescPod("kube-system", "coredns", "uid-coredns"),
					slice,
				)
				var gotUID *types.UID
				cs.PrependReactor("delete", "endpointslices",
					func(a ktesting.Action) (bool, runtime.Object, error) {
						opts := a.(ktesting.DeleteAction).GetDeleteOptions()
						if opts.Preconditions != nil {
							gotUID = opts.Preconditions.UID
						}
						return false, nil, nil
					})
				c := oescCleaner(cs)
				for range 2 {
					if err := c.run(ctx); err != nil {
						t.Fatal(err)
					}
				}
				if gotUID == nil || *gotUID != slice.UID {
					t.Fatalf("delete missing UID precondition: %v", gotUID)
				}
				if oescSliceExists(t, cs, "apps", "all-ghost") {
					t.Fatal("all-ghost slice not deleted")
				}
				if cnt := ptestutil.ToFloat64(metrics.OrphanEndpointSlicesCleanedTotal.WithLabelValues("apps")); cnt != 1 {
					t.Fatalf("cleaned counter = %v, want 1", cnt)
				}
				if c.ghostStreak.Len() != 0 {
					t.Fatalf("ghostStreak len = %d, want 0", c.ghostStreak.Len())
				}
			},
		},
		{
			name: "same Pod name recreated with new UID strips old UID endpoint",
			run: func(t *testing.T) {
				slice := oescSlice("apps", "recreated-pod-slice", "web", 30*time.Minute)
				slice.Endpoints = []discoveryv1.Endpoint{
					oescPodEndpoint("10.0.0.1", "apps", "web-0", "uid-old"),
					oescPodEndpoint("10.0.0.2", "apps", "web-0", "uid-new"),
				}
				cs := fake.NewSimpleClientset(
					oescService("default", "kubernetes"),
					oescService("apps", "web"),
					oescPod("apps", "web-0", "uid-new"),
					slice,
				)
				c := oescCleaner(cs)
				for range 2 {
					if err := c.run(ctx); err != nil {
						t.Fatal(err)
					}
				}
				got, err := cs.DiscoveryV1().EndpointSlices("apps").Get(ctx, "recreated-pod-slice", metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if len(got.Endpoints) != 1 || got.Endpoints[0].TargetRef.UID != "uid-new" {
					t.Fatalf("endpoints = %+v, want only uid-new", got.Endpoints)
				}
			},
		},
		{
			name: "stale Pod list confirmed alive by live Pod.Get keeps endpoint and clears streak",
			run: func(t *testing.T) {
				slice := oescSlice("apps", "stale-pod-slice", "web", 30*time.Minute)
				slice.Endpoints = []discoveryv1.Endpoint{
					oescPodEndpoint("10.0.0.1", "apps", "web-0", "uid-live"),
				}
				cs := fake.NewSimpleClientset(
					oescService("default", "kubernetes"),
					oescService("apps", "web"),
					oescPod("apps", "web-0", "uid-live"),
					slice,
				)
				cs.PrependReactor("list", "pods",
					func(ktesting.Action) (bool, runtime.Object, error) {
						return true, &corev1.PodList{}, nil
					})
				c := oescCleaner(cs)
				for range 2 {
					if err := c.run(ctx); err != nil {
						t.Fatal(err)
					}
				}
				got, err := cs.DiscoveryV1().EndpointSlices("apps").Get(ctx, "stale-pod-slice", metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if len(got.Endpoints) != 1 {
					t.Fatalf("endpoints = %d, want 1", len(got.Endpoints))
				}
				if c.ghostStreak.Count(oescGhostKey(slice, "uid-live")) != 0 {
					t.Fatal("ghost streak not cleared after live Pod.Get match")
				}
			},
		},
		{
			name: "live Pod.Get error fails closed and IncErrors once",
			run: func(t *testing.T) {
				slice := oescSlice("apps", "pod-get-err", "web", 30*time.Minute)
				slice.Endpoints = []discoveryv1.Endpoint{
					oescPodEndpoint("10.0.0.2", "apps", "web-dead", "uid-dead"),
				}
				cs := fake.NewSimpleClientset(
					oescService("default", "kubernetes"),
					oescService("apps", "web"),
					slice,
				)
				cs.PrependReactor("get", "pods",
					func(ktesting.Action) (bool, runtime.Object, error) {
						return true, nil, errors.New("pod get timeout")
					})
				c := oescCleaner(cs)
				c.queue = "oesc-ghost-pod-get-err"
				c.ghostStreak.Set(oescGhostKey(slice, "uid-dead"), orphanEndpointSliceStreak-1)
				before := testutil.QueueErrorCount(t, c.queue)
				if err := c.run(ctx); err != nil {
					t.Fatalf("pod confirm failure must not fail run: %v", err)
				}
				if delta := testutil.QueueErrorCount(t, c.queue) - before; delta != 1 {
					t.Fatalf("IncError delta = %v, want 1", delta)
				}
				if !oescSliceExists(t, cs, "apps", "pod-get-err") {
					t.Fatal("slice deleted despite Pod.Get failure")
				}
				if got := c.ghostStreak.Count(oescGhostKey(slice, "uid-dead")); got != orphanEndpointSliceStreak {
					t.Fatalf("ghost streak = %d, want %d", got, orphanEndpointSliceStreak)
				}
			},
		},
		{
			name: "live EndpointSlice.Get error fails closed and IncErrors once",
			run: func(t *testing.T) {
				slice := oescSlice("apps", "es-get-err", "web", 30*time.Minute)
				slice.Endpoints = []discoveryv1.Endpoint{
					oescPodEndpoint("10.0.0.2", "apps", "web-dead", "uid-dead"),
				}
				cs := fake.NewSimpleClientset(
					oescService("default", "kubernetes"),
					oescService("apps", "web"),
					slice,
				)
				failGet := true
				var mutations int
				cs.PrependReactor("get", "endpointslices",
					func(ktesting.Action) (bool, runtime.Object, error) {
						if failGet {
							return true, nil, errors.New("slice get timeout")
						}
						return false, nil, nil
					})
				cs.PrependReactor("delete", "endpointslices",
					func(ktesting.Action) (bool, runtime.Object, error) {
						mutations++
						return false, nil, nil
					})
				cs.PrependReactor("patch", "endpointslices",
					func(ktesting.Action) (bool, runtime.Object, error) {
						mutations++
						return false, nil, nil
					})
				c := oescCleaner(cs)
				c.queue = "oesc-ghost-slice-get-err"
				c.ghostStreak.Set(oescGhostKey(slice, "uid-dead"), orphanEndpointSliceStreak-1)
				before := testutil.QueueErrorCount(t, c.queue)
				if err := c.run(ctx); err != nil {
					t.Fatalf("slice confirm failure must not fail run: %v", err)
				}
				if delta := testutil.QueueErrorCount(t, c.queue) - before; delta != 1 {
					t.Fatalf("IncError delta = %v, want 1", delta)
				}
				if mutations != 0 {
					t.Fatalf("mutations = %d, want 0", mutations)
				}
				failGet = false
				if !oescSliceExists(t, cs, "apps", "es-get-err") {
					t.Fatal("slice deleted despite EndpointSlice.Get failure")
				}
			},
		},
		{
			name: "benign Patch races (409 Conflict and 404 NotFound) do not IncError",
			run: func(t *testing.T) {
				for kind, patchErr := range map[string]error{
					"conflict": apierrors.NewConflict(discoveryv1.Resource("endpointslices"), "mixed-race", errors.New("rv mismatch")),
					"notFound": apierrors.NewNotFound(discoveryv1.Resource("endpointslices"), "mixed-race"),
				} {
					t.Run(kind, func(t *testing.T) {
						slice := oescSlice("apps", "mixed-race", "web", 30*time.Minute)
						slice.Endpoints = []discoveryv1.Endpoint{
							oescPodEndpoint("10.0.0.1", "apps", "web-live", "uid-live"),
							oescPodEndpoint("10.0.0.2", "apps", "web-dead", "uid-dead"),
						}
						cs := fake.NewSimpleClientset(
							oescService("default", "kubernetes"),
							oescService("apps", "web"),
							oescPod("apps", "web-live", "uid-live"),
							slice,
						)
						cs.PrependReactor("patch", "endpointslices",
							func(ktesting.Action) (bool, runtime.Object, error) {
								return true, nil, patchErr
							})
						c := oescCleaner(cs)
						c.queue = "oesc-patch-race-" + kind
						before := testutil.QueueErrorCount(t, c.queue)
						for range 2 {
							if err := c.run(ctx); err != nil {
								t.Fatalf("benign patch race must not fail run: %v", err)
							}
						}
						if delta := testutil.QueueErrorCount(t, c.queue) - before; delta != 0 {
							t.Fatalf("benign patch race IncError delta = %v, want 0", delta)
						}
						if got := c.ghostStreak.Count(oescGhostKey(slice, "uid-dead")); got != orphanEndpointSliceStreak {
							t.Fatalf("streak after benign patch race = %d, want %d", got, orphanEndpointSliceStreak)
						}
					})
				}
			},
		},
		{
			name: "Pod list error aborts Track 2 without blocking Track 1 or pruning ghostStreak",
			run: func(t *testing.T) {
				testutil.CleanupMetric(t, metrics.OrphanEndpointSlicesCleanedTotal, "apps")
				orphanSlice := oescSlice("apps", "orphan-svc", "deleted-svc", 30*time.Minute)
				liveSlice := oescSlice("apps", "web-slice", "web", 30*time.Minute)
				liveSlice.Endpoints = []discoveryv1.Endpoint{
					oescPodEndpoint("10.0.0.2", "apps", "web-dead", "uid-dead"),
				}
				cs := fake.NewSimpleClientset(
					oescService("default", "kubernetes"),
					oescService("apps", "web"),
					orphanSlice,
					liveSlice,
				)
				cs.PrependReactor("list", "pods",
					func(ktesting.Action) (bool, runtime.Object, error) {
						return true, nil, errors.New("pods list unavailable")
					})
				c := oescCleaner(cs)
				c.absentStreak.Set(oescStreakKey(orphanSlice), orphanEndpointSliceStreak-1)
				c.ghostStreak.Set(oescGhostKey(liveSlice, "uid-dead"), 1)

				err := c.run(ctx)
				if err == nil || !strings.Contains(err.Error(), "list pods") {
					t.Fatalf("expected pod list error, got %v", err)
				}
				if oescSliceExists(t, cs, "apps", "orphan-svc") {
					t.Fatal("Track 1 orphan-Service slice must still be reaped before Track 2 error")
				}
				if got := c.ghostStreak.Count(oescGhostKey(liveSlice, "uid-dead")); got != 1 {
					t.Fatalf("ghostStreak pruned on Pod list error: got %d, want 1", got)
				}
			},
		},
		{
			name: "empty Pod list does not fail closed and still confirms via live Pod.Get",
			run: func(t *testing.T) {
				testutil.CleanupMetric(t, metrics.OrphanEndpointSlicesCleanedTotal, "apps")
				slice := oescSlice("apps", "no-pods-slice", "web", 30*time.Minute)
				slice.Endpoints = []discoveryv1.Endpoint{
					oescPodEndpoint("10.0.0.2", "apps", "web-dead", "uid-dead"),
				}
				cs := fake.NewSimpleClientset(
					oescService("default", "kubernetes"),
					oescService("apps", "web"),
					slice,
				)
				c := oescCleaner(cs)
				for range 2 {
					if err := c.run(ctx); err != nil {
						t.Fatalf("empty pod list must not abort run: %v", err)
					}
				}
				if oescSliceExists(t, cs, "apps", "no-pods-slice") {
					t.Fatal("all-ghost slice with 0 pods in cluster not cleaned after live Pod.Get confirm")
				}
			},
		},
		{
			name: "default/kubernetes slice with ghost Pod UID is never touched",
			run: func(t *testing.T) {
				kubeSlice := oescSlice("default", "kubernetes", "kubernetes", time.Hour)
				kubeSlice.Endpoints = []discoveryv1.Endpoint{
					oescPodEndpoint("10.0.0.1", "default", "ghost-apiserver", "uid-kube-ghost"),
				}
				cs := fake.NewSimpleClientset(
					oescService("default", "kubernetes"),
					kubeSlice,
				)
				c := oescCleaner(cs)
				for range 3 {
					if err := c.run(ctx); err != nil {
						t.Fatal(err)
					}
				}
				got, err := cs.DiscoveryV1().EndpointSlices("default").Get(ctx, "kubernetes", metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if len(got.Endpoints) != 1 {
					t.Fatalf("default/kubernetes endpoints mutated: %+v", got.Endpoints)
				}
				if c.ghostStreak.Len() != 0 {
					t.Fatalf("default/kubernetes fed ghostStreak: len=%d", c.ghostStreak.Len())
				}
			},
		},
		{
			name: "watch-cache RV=0 on Pods & EndpointSlices and live RV=\"\" on Get confirms",
			run: func(t *testing.T) {
				testutil.CleanupMetric(t, metrics.OrphanEndpointSlicesCleanedTotal, "apps")
				slice := oescSlice("apps", "rv-check", "web", 30*time.Minute)
				slice.Endpoints = []discoveryv1.Endpoint{
					oescPodEndpoint("10.0.0.2", "apps", "web-dead", "uid-dead"),
				}
				fakeCS := fake.NewSimpleClientset(
					oescService("default", "kubernetes"),
					oescService("apps", "web"),
					oescPod("kube-system", "coredns", "uid-coredns"),
					slice,
				)
				rec := &oescRecordingCS{Interface: fakeCS}
				c := &orphanEndpointSliceCleaner{cs: rec, now: time.Now}
				for range 2 {
					if err := c.run(ctx); err != nil {
						t.Fatal(err)
					}
				}
				if len(rec.podListOpts) != 2 {
					t.Fatalf("pod list count = %d, want 2", len(rec.podListOpts))
				}
				for i, opts := range rec.podListOpts {
					if opts.ResourceVersion != "0" || opts.Limit != 0 {
						t.Fatalf("pod list %d = (RV=%q, Limit=%d), want (\"0\", 0)", i, opts.ResourceVersion, opts.Limit)
					}
				}
				if len(rec.sliceGetOpts) != 1 || rec.sliceGetOpts[0].ResourceVersion != "" {
					t.Fatalf("slice Get opts = %+v, want 1 live Get with RV=\"\"", rec.sliceGetOpts)
				}
				if len(rec.podGetOpts) != 1 || rec.podGetOpts[0].ResourceVersion != "" {
					t.Fatalf("pod Get opts = %+v, want 1 live Get with RV=\"\"", rec.podGetOpts)
				}
			},
		},
		{
			name: "deterministic ns/name cap (50) and ghostStreak pruning when slice vanishes",
			run: func(t *testing.T) {
				testutil.CleanupMetric(t, metrics.OrphanEndpointSlicesCleanedTotal, "apps")
				objs := []runtime.Object{
					oescService("default", "kubernetes"),
					oescService("apps", "web"),
					oescPod("kube-system", "coredns", "uid-coredns"),
				}
				for i := 0; i < orphanEndpointSliceDeleteCap+2; i++ {
					s := oescSlice("apps", fmt.Sprintf("g-%02d-slice", i), "web", 30*time.Minute)
					s.Endpoints = []discoveryv1.Endpoint{
						oescPodEndpoint("10.0.0.2", "apps", fmt.Sprintf("dead-%02d", i), fmt.Sprintf("uid-dead-%02d", i)),
					}
					objs = append(objs, s)
				}
				cs := fake.NewSimpleClientset(objs...)
				c := oescCleaner(cs)
				for range 2 {
					if err := c.run(ctx); err != nil {
						t.Fatal(err)
					}
				}
				for _, name := range []string{"g-50-slice", "g-51-slice"} {
					if !oescSliceExists(t, cs, "apps", name) {
						t.Fatalf("slice %s past cap boundary was remediated early", name)
					}
				}
				if got := ptestutil.ToFloat64(metrics.OrphanEndpointSlicesCleanedTotal.WithLabelValues("apps")); got != orphanEndpointSliceDeleteCap {
					t.Fatalf("cleaned counter = %v, want %d", got, orphanEndpointSliceDeleteCap)
				}
				// Delete g-50-slice externally; g-51-slice remediates on cycle 3,
				// and g-50-slice's streak is pruned.
				if err := cs.DiscoveryV1().EndpointSlices("apps").Delete(ctx, "g-50-slice", metav1.DeleteOptions{}); err != nil {
					t.Fatal(err)
				}
				if err := c.run(ctx); err != nil {
					t.Fatal(err)
				}
				if oescSliceExists(t, cs, "apps", "g-51-slice") {
					t.Fatal("g-51-slice survivor not remediated on cycle 3")
				}
				if c.ghostStreak.Len() != 0 {
					t.Fatalf("ghostStreak len = %d after cleanup and prune, want 0", c.ghostStreak.Len())
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, tc.run)
	}
}

// Package-wide test context shared by this package's _test files.
var ctx = context.Background()
