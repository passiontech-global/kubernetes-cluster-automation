// va_missing_node_test.go — the missing-node gate: the two-sighting
// grace window, the 5m age gate, node reappearances resetting the
// window and the Terminating skip.
package volumeattachmentcleaner

import (
	"testing"
	"time"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
)

// ---------------------------------------------------------------------------
// missing_node
// ---------------------------------------------------------------------------

// A VA pointing at a deleted node is recorded on the first sighting
// and only reaped on the second — a one-off node List gap must never
// detach a volume.
func TestVACleanerMissingNodeTwoSightings(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacNode("alive", corev1.ConditionTrue),
		vacAttachment("va-orphan", "gone-node", now.Add(-10*time.Minute)),
	)
	c := newVACleaner(cs, func() time.Time { return now })
	before := promtest.ToFloat64(
		metrics.VolumeAttachmentsCleanedTotal.WithLabelValues("missing_node"))

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !vaExists(t, cs, "va-orphan") {
		t.Fatal("VA deleted on first orphan sighting")
	}
	if _, ok := c.orphanFirstSeen.Seen("va-orphan", time.Now()); !ok {
		t.Fatal("first sighting not recorded in orphanFirstSeen")
	}

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if vaExists(t, cs, "va-orphan") {
		t.Fatal("VA not deleted on second consecutive sighting")
	}
	if got := promtest.ToFloat64(
		metrics.VolumeAttachmentsCleanedTotal.WithLabelValues("missing_node")) - before; got != 1 {
		t.Fatalf("missing_node counter delta = %v, want 1", got)
	}
	if _, ok := c.orphanFirstSeen.Seen("va-orphan", time.Now()); ok {
		t.Fatal("deleted VA still tracked in orphanFirstSeen")
	}
}

// The 5m age gate holds even on a second sighting — a fresh VA may
// still be racing its node create.
func TestVACleanerMissingNodeTooYoung(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacNode("alive", corev1.ConditionTrue),
		vacAttachment("va-young", "gone-node", now.Add(-2*time.Minute)),
	)
	c := newVACleaner(cs, func() time.Time { return now })

	for range 2 {
		if err := c.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if !vaExists(t, cs, "va-young") {
		t.Fatal("VA younger than 5m deleted despite second sighting")
	}
	// Past the age gate the next sighting reaps it.
	now = now.Add(4 * time.Minute)
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if vaExists(t, cs, "va-young") {
		t.Fatal("VA kept after both age gate and sightings passed")
	}
}

// A node that reappears resets the two-sighting window — the VA must
// be seen orphaned twice again before it is eligible.
func TestVACleanerNodeReappearsResetsGrace(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacAttachment("va-flap", "flap-node", now.Add(-30*time.Minute)),
		vacNode("alive", corev1.ConditionTrue),
	)
	c := newVACleaner(cs, func() time.Time { return now })

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	} // first sighting
	if _, err := cs.CoreV1().Nodes().Create(ctx,
		vacNode("flap-node", corev1.ConditionTrue), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.orphanFirstSeen.Seen("va-flap", time.Now()); ok {
		t.Fatal("orphan tracking not pruned when the node reappeared")
	}
	if err := cs.CoreV1().Nodes().Delete(ctx, "flap-node", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !vaExists(t, cs, "va-flap") {
		t.Fatal("VA deleted on first sighting after node re-flapped away")
	}
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if vaExists(t, cs, "va-flap") {
		t.Fatal("VA not deleted on second consecutive sighting")
	}
}

// A VA already in Terminating is never touched — a second delete
// cannot unstick its finalizer anyway.
func TestVACleanerSkipsTerminatingVA(t *testing.T) {
	now := time.Now()
	ts := metav1.NewTime(now.Add(-time.Hour))
	va := vacAttachment("va-terminating", "gone-node", now.Add(-30*time.Minute))
	va.DeletionTimestamp = &ts
	cs := fake.NewSimpleClientset(
		vacNode("alive", corev1.ConditionTrue), va)
	c := newVACleaner(cs, func() time.Time { return now })

	for range 3 {
		if err := c.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if !vaExists(t, cs, "va-terminating") {
		t.Fatal("terminating VA touched")
	}
	if _, ok := c.orphanFirstSeen.Seen("va-terminating", time.Now()); ok {
		t.Fatal("terminating VA tracked as orphan")
	}
}
