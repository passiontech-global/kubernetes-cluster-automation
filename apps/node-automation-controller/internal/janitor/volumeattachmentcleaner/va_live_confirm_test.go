// va_live_confirm_test.go — the stale-informer guard: the census
// verdict re-checked against a live node Get, with the live answer
// winning and failures closing the gate.
package volumeattachmentcleaner

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// Live confirm on the direct clientset (stale-informer guard)
// ---------------------------------------------------------------------------

// staleNodes is a CachedNodeReader stub playing the informer cache:
// it returns exactly the nodes handed to it, independent of the
// fake clientset that plays the live apiserver — a census/live
// split the direct confirm must resolve.
type staleNodes struct{ items []corev1.Node }

func (s *staleNodes) List(_ context.Context, list client.ObjectList,
	_ ...client.ListOption) error {
	nl := list.(*corev1.NodeList)
	nl.Items = append(nl.Items, s.items...)
	return nil
}

// The informer census has dropped the node but the live Get still
// finds it: the LIVE answer wins — the VA survives, the stale
// orphan sighting re-arms, and nothing is metered.
func TestVACleanerLiveConfirmOverridesStaleMissingNode(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacAttachment("va-stale", "live-node", now.Add(-time.Hour)),
		vacNode("live-node", corev1.ConditionTrue),
		vacNode("other", corev1.ConditionTrue), // keeps the census non-empty
	)
	c := newVACleaner(cs, func() time.Time { return now })
	// The cache plays stale: live-node is missing from it.
	c.nodeReader = &staleNodes{items: []corev1.Node{
		*vacNode("other", corev1.ConditionTrue)}}
	// The orphan sighting predates this cycle, so the census verdict
	// is destructive and the direct confirm actually runs.
	c.orphanFirstSeen.Seed("va-stale", now.Add(-time.Minute))

	before := testutil.QueueErrorCount(t, "volumeattachment-cleaner")
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !vaExists(t, cs, "va-stale") {
		t.Fatal("VA deleted while the live apiserver still has the node")
	}
	if _, ok := c.orphanFirstSeen.Seen("va-stale", now); ok {
		t.Fatal("stale orphan sighting not re-armed after the live confirm")
	}
	if got := testutil.QueueErrorCount(t, "volumeattachment-cleaner") - before; got != 0 {
		t.Fatalf("stale-snapshot save not metered as an error: delta = %v, want 0", got)
	}
}

// Same split on the out-of-service branch: the census still shows
// the node fenced and past the not-Ready window, but the live node
// is Ready again — the gate re-runs on the LIVE node and keeps the
// VA.
func TestVACleanerLiveConfirmOverridesStaleFencedNode(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacAttachment("va-flap", "flap", now.Add(-time.Hour)),
		vacNode("flap", corev1.ConditionTrue, outOfService), // live: recovered
		vacNode("other", corev1.ConditionTrue),
	)
	c := newVACleaner(cs, func() time.Time { return now })
	c.nodeReader = &staleNodes{items: []corev1.Node{
		*vacNode("flap", corev1.ConditionFalse, outOfService)}} // census: dead
	c.nodeNotReadySince.Seed("flap", now.Add(-20*time.Minute))

	before := testutil.QueueErrorCount(t, "volumeattachment-cleaner")
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !vaExists(t, cs, "va-flap") {
		t.Fatal("VA deleted while the live node is Ready again")
	}
	if got := testutil.QueueErrorCount(t, "volumeattachment-cleaner") - before; got != 0 {
		t.Fatalf("stale-snapshot save not metered as an error: delta = %v, want 0", got)
	}
}

// A live node Get that fails keeps the VA (fail closed) and meters
// once — an unverifiable confirm must never detach a volume.
func TestVACleanerLiveConfirmErrorFailsClosed(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacAttachment("va-orphan", "gone-node", now.Add(-time.Hour)),
		vacNode("alive", corev1.ConditionTrue),
	)
	cs.PrependReactor("get", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	c := newVACleaner(cs, func() time.Time { return now })
	c.orphanFirstSeen.Seed("va-orphan", now.Add(-time.Minute))

	before := testutil.QueueErrorCount(t, "volumeattachment-cleaner")
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !vaExists(t, cs, "va-orphan") {
		t.Fatal("VA deleted when the live confirm itself failed")
	}
	if got := testutil.QueueErrorCount(t, "volumeattachment-cleaner") - before; got != 1 {
		t.Fatalf("failed confirm not metered: error delta = %v, want 1", got)
	}
}

// The strip branch live-wins too: the census dropped the node, but
// the live apiserver has it Ready with no prior unused-volume
// sighting — the finalizers stay.
func TestVACleanerLiveConfirmOverridesStaleStrip(t *testing.T) {
	now := time.Now()
	va := vacAttachment("va-stuck", "w1", now.Add(-time.Hour))
	termAt := metav1.NewTime(now.Add(-30 * time.Minute))
	va.DeletionTimestamp = &termAt
	va.Finalizers = []string{"external-attacher/csi-test"}
	cs := fake.NewSimpleClientset(va,
		vacNode("w1", corev1.ConditionTrue),
		vacNode("other", corev1.ConditionTrue))
	c := newVACleaner(cs, func() time.Time { return now })
	c.nodeReader = &staleNodes{items: []corev1.Node{
		*vacNode("other", corev1.ConditionTrue)}} // census: w1 gone

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := cs.StorageV1().VolumeAttachments().Get(ctx, "va-stuck", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Finalizers) == 0 {
		t.Fatal("finalizers stripped while the live apiserver still has the node")
	}
}
