// va_live_va_confirm_test.go — the second half of the sweep's live
// confirm: the VA object itself is re-Get before any delete or
// finalizer strip (the census list is a snapshot, and CSI csi-hash
// names are deterministic), every mismatch keeps the object, and a
// still-Attached VA on a live node is never detached by us.
package volumeattachmentcleaner

import (
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// The write-site guard: stripFinalizers refuses a VA that is no
// longer Terminating even if a stale verdict reaches it.
func TestVAStripFinalizersRefusesLiveVA(t *testing.T) {
	va := vacAttachment("va-live", "w1", time.Now().Add(-time.Hour))
	va.Finalizers = []string{"external-attacher/csi-test"}
	cs := fake.NewSimpleClientset(va)
	c := newVACleaner(cs, time.Now)
	if err := c.stripFinalizers(ctx, va); err != nil {
		t.Fatal(err)
	}
	got, err := cs.StorageV1().VolumeAttachments().Get(ctx, "va-live", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Finalizers) == 0 {
		t.Fatal("finalizers stripped off a VA with no DeletionTimestamp")
	}
}

// A same-named VA recreated under a fresh UID must not inherit the
// dead object's orphan verdict: the live confirm compares UIDs and
// drops the destructive branch on a mismatch.
func TestVACleanerLiveVAUIDMismatchKeeps(t *testing.T) {
	now := time.Now()
	va := vacAttachment("va-recreated", "gone-node", now.Add(-time.Hour))
	va.UID = "uid-census"
	cs := fake.NewSimpleClientset(va,
		vacNode("alive", corev1.ConditionTrue))
	cs.PrependReactor("get", "volumeattachments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			live := va.DeepCopy()
			live.UID = "uid-live"
			return true, live, nil
		})
	c := newVACleaner(cs, func() time.Time { return now })
	c.orphanFirstSeen.Seed("va-recreated", now.Add(-time.Minute))

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !vaExists(t, cs, "va-recreated") {
		t.Fatal("recreated VA deleted on the old object's verdict")
	}
}

// An out-of-service VA whose live object still reports Attached is
// left to the external-attacher: while the apiserver still has the
// node, deleting the VA would remove the detach trigger itself and
// turn a stale status into a split-brain.
func TestVACleanerAttachedVAOnLiveNodeKeeps(t *testing.T) {
	now := time.Now()
	va := vacAttachment("va-attached", "dead", now.Add(-time.Hour))
	va.Status.Attached = true
	cs := fake.NewSimpleClientset(
		vacNode("dead", corev1.ConditionFalse, outOfService),
		vacNode("alive", corev1.ConditionTrue), va)
	c := newVACleaner(cs, func() time.Time { return now })
	c.nodeNotReadySince.Seed("dead", now.Add(-20*time.Minute))

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !vaExists(t, cs, "va-attached") {
		t.Fatal("VA still reporting Attached on a live node was deleted")
	}
}

// The strongest proof — the apiserver itself answering NotFound for
// the node — still wins: with no live writer left, even an Attached
// VA is safe to delete (the module's primary missing-node use case).
func TestVACleanerAttachedVAOnGoneNodeDeleted(t *testing.T) {
	now := time.Now()
	va := vacAttachment("va-attached-gone", "gone-node", now.Add(-time.Hour))
	va.Status.Attached = true
	cs := fake.NewSimpleClientset(va,
		vacNode("alive", corev1.ConditionTrue))
	c := newVACleaner(cs, func() time.Time { return now })

	for range 2 {
		if err := c.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if vaExists(t, cs, "va-attached-gone") {
		t.Fatal("orphan VA on a gone node not deleted — the attached guard overreached")
	}
}

// A failing live VA Get fails closed (metered once) — an
// unverifiable identity is never enough to detach a volume.
func TestVACleanerLiveVAGetErrorFailsClosed(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacAttachment("va-orphan", "gone-node", now.Add(-time.Hour)),
		vacNode("alive", corev1.ConditionTrue))
	failGet := true
	cs.PrependReactor("get", "volumeattachments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			if failGet {
				return true, nil, errors.New("api down")
			}
			return false, nil, nil
		})
	c := newVACleaner(cs, func() time.Time { return now })
	c.orphanFirstSeen.Seed("va-orphan", now.Add(-time.Minute))

	before := testutil.QueueErrorCount(t, "volumeattachment-cleaner")
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	failGet = false // let the assertion below read the object back
	if !vaExists(t, cs, "va-orphan") {
		t.Fatal("VA deleted while its live confirm itself failed")
	}
	if got := testutil.QueueErrorCount(t, "volumeattachment-cleaner") - before; got != 1 {
		t.Fatalf("failed live VA confirm not metered once: delta = %v", got)
	}
}

// The strip verdict rides on DeletionTimestamp: a stuck-Terminating
// VA that stopped terminating between the list and the confirm must
// keep its attacher finalizers.
func TestVACleanerStripVerdictStaleDeletionStateKeeps(t *testing.T) {
	now := time.Now()
	va := vacAttachment("va-stuck", "gone-node", now.Add(-time.Hour))
	term := metav1.NewTime(now.Add(-30 * time.Minute))
	va.DeletionTimestamp = &term
	va.Finalizers = []string{"external-attacher/csi-test"}
	cs := fake.NewSimpleClientset(va,
		vacNode("alive", corev1.ConditionTrue))
	cs.PrependReactor("get", "volumeattachments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			live := va.DeepCopy()
			live.DeletionTimestamp = nil
			return true, live, nil
		})
	c := newVACleaner(cs, func() time.Time { return now })

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := cs.StorageV1().VolumeAttachments().Get(ctx, "va-stuck", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Finalizers) == 0 {
		t.Fatal("finalizers stripped although the VA is no longer terminating")
	}
}
