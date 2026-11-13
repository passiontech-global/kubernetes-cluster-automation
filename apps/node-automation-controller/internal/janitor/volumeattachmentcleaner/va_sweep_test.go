// va_sweep_test.go — the sweep's hard bounds and error paths: the
// per-cycle delete cap, list failures, UID-preconditioned deletes,
// tolerated delete errors and the NotFound/Conflict race
// classification, plus the first-seen key's UID disambiguation.
package volumeattachmentcleaner

import (
	"errors"
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// Hard bounds & error paths
// ---------------------------------------------------------------------------

// The cap bounds detach churn at vaDeleteCap per cycle even when more
// VAs are eligible.
func TestVACleanerCap(t *testing.T) {
	now := time.Now()
	objs := []runtime.Object{vacNode("alive", corev1.ConditionTrue)}
	for i := range vaDeleteCap + 2 {
		objs = append(objs, vacAttachment(
			fmt.Sprintf("va-%02d", i), "gone-node", now.Add(-time.Hour)))
	}
	cs := fake.NewSimpleClientset(objs...)
	c := newVACleaner(cs, func() time.Time { return now })

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	} // first sighting for all
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	remaining, err := cs.StorageV1().VolumeAttachments().List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining.Items) != 2 {
		t.Fatalf("expected exactly 2 survivors after cap=%d, got %d",
			vaDeleteCap, len(remaining.Items))
	}
}

// Zero nodes means the apiserver/RBAC broke — every VA would look
// orphaned, so nothing is evaluated or recorded. The refusal is
// deliberately non-fatal (nil return) but MUST be metered — a
// persistently-empty node list is broken RBAC, invisible otherwise.
func TestVACleanerEmptyNodeListAborts(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacAttachment("va-orphan", "gone-node", now.Add(-time.Hour)))
	c := newVACleaner(cs, func() time.Time { return now })

	before := testutil.QueueErrorCount(t, "volumeattachment-cleaner")
	if err := c.run(ctx); err != nil {
		t.Fatalf("empty node list must abort cleanly, got %v", err)
	}
	if !vaExists(t, cs, "va-orphan") {
		t.Fatal("VA deleted with an empty node list")
	}
	if vaTrackedCount(&c.orphanFirstSeen) != 0 {
		t.Fatal("orphan sightings recorded on an aborted run")
	}
	if got := testutil.QueueErrorCount(t, "volumeattachment-cleaner") - before; got != 1 {
		t.Fatalf("empty node list not metered: error delta = %v, want 1", got)
	}
}

// A node list failure is a real error — the periodic wrapper meters it.
func TestVACleanerNodeListError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	c := newVACleaner(cs, time.Now)
	if err := c.run(ctx); err == nil {
		t.Fatal("expected error when the node list fails")
	}
}

// A VA list failure is likewise a real error.
func TestVACleanerVAListError(t *testing.T) {
	cs := fake.NewSimpleClientset(vacNode("alive", corev1.ConditionTrue))
	cs.PrependReactor("list", "volumeattachments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	c := newVACleaner(cs, time.Now)
	if err := c.run(ctx); err == nil {
		t.Fatal("expected error when the volumeattachment list fails")
	}
}

// A pod list failure on the out-of-service path fails closed: the VA
// is kept and the run itself does not error.
func TestVACleanerPodListErrorFailsClosed(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacNode("dead", corev1.ConditionFalse, outOfService),
		vacAttachment("va-fenced", "dead", now.Add(-time.Hour)),
	)
	c := newVACleaner(cs, func() time.Time { return now })

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	now = now.Add(20 * time.Minute)
	cs.PrependReactor("list", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	before := testutil.QueueErrorCount(t, "volumeattachment-cleaner")
	if err := c.run(ctx); err != nil {
		t.Fatalf("pod list failure must not error the run: %v", err)
	}
	if !vaExists(t, cs, "va-fenced") {
		t.Fatal("VA deleted when the pod count could not be confirmed")
	}
	if got := testutil.QueueErrorCount(t, "volumeattachment-cleaner") - before; got != 1 {
		t.Fatalf("queue error delta = %v, want 1", got)
	}
}

// The delete carries a UID precondition — VA names are deterministic
// csi-hash names, so a re-attachment between list and delete recreates
// the SAME name and only the vetted object may be removed.
func TestVACleanerDeleteUIDPrecondition(t *testing.T) {
	now := time.Now()
	va := vacAttachment("va-orphan", "gone-node", now.Add(-time.Hour))
	va.UID = "uid-va-orphan"
	cs := fake.NewSimpleClientset(
		vacNode("alive", corev1.ConditionTrue), va)
	var gotUID *types.UID
	cs.PrependReactor("delete", "volumeattachments",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			opts := a.(ktesting.DeleteAction).GetDeleteOptions()
			if opts.Preconditions != nil {
				gotUID = opts.Preconditions.UID
			}
			return false, nil, nil // fall through to the tracker
		})
	c := newVACleaner(cs, func() time.Time { return now })

	for range 2 {
		if err := c.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if gotUID == nil || *gotUID != va.UID {
		t.Fatalf("delete missing the UID precondition: %v", gotUID)
	}
	if vaExists(t, cs, "va-orphan") {
		t.Fatal("orphan VA not deleted")
	}
}

// A failed VA delete is tolerated (logged + metered) — the run still
// nils out and the VA survives for the next sweep.
func TestVACleanerDeleteErrorTolerated(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacNode("alive", corev1.ConditionTrue),
		vacAttachment("va-orphan", "gone-node", now.Add(-time.Hour)))
	c := newVACleaner(cs, func() time.Time { return now })

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	} // first sighting
	cs.PrependReactor("delete", "volumeattachments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("delete rejected")
		})
	if err := c.run(ctx); err != nil {
		t.Fatalf("VA delete failures must not error the run: %v", err)
	}
	if !vaExists(t, cs, "va-orphan") {
		t.Fatal("VA deleted despite the failing delete call")
	}
}

// ---------------------------------------------------------------------------
// OnError race classification (NotFound / Conflict are not failures)
// ---------------------------------------------------------------------------

// A delete answered NotFound raced an external cleanup — logged as a
// skip, not metered as an error.
func TestVACleanerDeleteNotFoundNotMetered(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacAttachment("va-raced", "gone-node", now.Add(-time.Hour)),
		vacNode("alive", corev1.ConditionTrue),
	)
	cs.PrependReactor("delete", "volumeattachments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewNotFound(
				storagev1.Resource("volumeattachments"), "va-raced")
		})
	c := newVACleaner(cs, func() time.Time { return now })
	c.orphanFirstSeen.Seed("va-raced", now.Add(-time.Minute))

	before := testutil.QueueErrorCount(t, "volumeattachment-cleaner")
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := testutil.QueueErrorCount(t, "volumeattachment-cleaner") - before; got != 0 {
		t.Fatalf("NotFound race metered as an error: delta = %v, want 0", got)
	}
	if !vaExists(t, cs, "va-raced") {
		t.Fatal("VA vanished despite the rejected delete")
	}
}

// A Conflict answer is the UID precondition firing on a recreated
// same-name VA — equally a race, equally not an error.
func TestVACleanerDeleteConflictNotMetered(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacAttachment("va-raced", "gone-node", now.Add(-time.Hour)),
		vacNode("alive", corev1.ConditionTrue),
	)
	cs.PrependReactor("delete", "volumeattachments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewConflict(
				storagev1.Resource("volumeattachments"), "va-raced",
				errors.New("uid mismatch"))
		})
	c := newVACleaner(cs, func() time.Time { return now })
	c.orphanFirstSeen.Seed("va-raced", now.Add(-time.Minute))

	before := testutil.QueueErrorCount(t, "volumeattachment-cleaner")
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := testutil.QueueErrorCount(t, "volumeattachment-cleaner") - before; got != 0 {
		t.Fatalf("Conflict race metered as an error: delta = %v, want 0", got)
	}
	if !vaExists(t, cs, "va-raced") {
		t.Fatal("VA vanished despite the rejected delete")
	}
}

// vaFirstSeenKey must distinguish a recreated VA (same deterministic
// csi-hash name, new UID) from the dead object — otherwise the
// replacement inherits the sighting window and detaches on cycle
// one. UID-less fixtures keep the bare-name key.
func TestVAFirstSeenKeyUIDDisambiguation(t *testing.T) {
	va1 := &storagev1.VolumeAttachment{ObjectMeta: metav1.ObjectMeta{
		Name: "csi-abc", UID: "uid-1"}}
	va2 := &storagev1.VolumeAttachment{ObjectMeta: metav1.ObjectMeta{
		Name: "csi-abc", UID: "uid-2"}}
	if vaFirstSeenKey(va1) == vaFirstSeenKey(va2) {
		t.Fatal("same-name VAs with different UIDs share a ledger key")
	}
	if got := vaLedgerName(vaFirstSeenKey(va1)); got != "csi-abc" {
		t.Fatalf("vaLedgerName = %q, want csi-abc", got)
	}
	bare := &storagev1.VolumeAttachment{ObjectMeta: metav1.ObjectMeta{Name: "csi-abc"}}
	if vaFirstSeenKey(bare) != "csi-abc" {
		t.Fatalf("UID-less key = %q, want bare name", vaFirstSeenKey(bare))
	}
}
