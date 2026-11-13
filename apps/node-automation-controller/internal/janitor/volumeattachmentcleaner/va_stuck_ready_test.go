// va_stuck_ready_test.go — the stuck-terminating strip and the
// ready-node unused-volume branch (fast-reboot dangling VA): the
// two-cycle unused proof and its blockers.
package volumeattachmentcleaner

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"
)

// va-stuck-terminating — a VolumeAttachment Terminating >15m whose node is gone has its
// finalizers stripped (the attacher-side detach can never drain).
func TestVACleanerStuckTerminatingFinalizerStrip(t *testing.T) {
	now := time.Now()
	va := vacAttachment("va-stuck", "node-gone", now.Add(-time.Hour))
	termAt := metav1.NewTime(now.Add(-30 * time.Minute))
	va.DeletionTimestamp = &termAt
	va.Finalizers = []string{"external-attacher/csi-test"}
	cs := fake.NewSimpleClientset(va,
		vacNode("w-live", corev1.ConditionTrue)) // va's node-gone absent from the live list
	c := newVACleaner(cs, func() time.Time { return now })
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := cs.StorageV1().VolumeAttachments().Get(ctx, "va-stuck", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Finalizers) != 0 {
		t.Fatalf("stuck VA finalizers not stripped: %v", got.Finalizers)
	}
}

// Same shape but inside the 15m grace window — left for the
// stuck-terminating audit, not stripped.
func TestVACleanerStuckTerminatingTooYoung(t *testing.T) {
	now := time.Now()
	va := vacAttachment("va-fresh", "node-gone", now.Add(-time.Hour))
	termAt := metav1.NewTime(now.Add(-5 * time.Minute))
	va.DeletionTimestamp = &termAt
	va.Finalizers = []string{"external-attacher/csi-test"}
	cs := fake.NewSimpleClientset(va,
		vacNode("w-live", corev1.ConditionTrue))
	c := newVACleaner(cs, func() time.Time { return now })
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := cs.StorageV1().VolumeAttachments().Get(ctx, "va-fresh", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Finalizers) == 0 {
		t.Fatal("finalizers stripped inside the grace window")
	}
}

// ---------------------------------------------------------------------------
// Ready-node unused-volume branch (fast-reboot dangling VA)
// ---------------------------------------------------------------------------

// A VA stuck Terminating >=15m on a node that rebooted back to Ready
// (no out-of-service taint) gets its finalizers stripped — but only
// when the unused-volume proof held in TWO consecutive cycles: no
// non-terminal pod mounts the PV and the volume is absent from
// VolumesInUse/VolumesAttached.
func TestVolumeAttachmentCleanerStuckReadyNodeUnused(t *testing.T) {
	now := time.Now()
	va := vacAttachment("va-stuck-ready", "w1", now.Add(-time.Hour))
	termAt := metav1.NewTime(now.Add(-30 * time.Minute))
	va.DeletionTimestamp = &termAt
	va.Finalizers = []string{"external-attacher/csi-test"}
	va.Spec.Source.PersistentVolumeName = ptr.To("pv-data")
	node := vacNode("w1", corev1.ConditionTrue)
	// The kubelet no longer reports the volume anywhere.
	cs := fake.NewSimpleClientset(va, node, vacPV("pv-data", "csi.test", "vol-1"),
		vacPod("infra", "agent", "w1", corev1.PodRunning))
	c := newVACleaner(cs, func() time.Time { return now })

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := cs.StorageV1().VolumeAttachments().Get(ctx, "va-stuck-ready", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Finalizers) == 0 {
		t.Fatal("finalizers stripped on the first sighting — needs 2 cycles")
	}
	if _, ok := c.stuckReadyFirstSeen.Seen("va-stuck-ready", time.Now()); !ok {
		t.Fatal("ready-node sighting not recorded")
	}

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	got, err = cs.StorageV1().VolumeAttachments().Get(ctx, "va-stuck-ready", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Finalizers) != 0 {
		t.Fatalf("stuck finalizers not stripped on second sighting: %v", got.Finalizers)
	}
}

// A non-terminal pod still mounting the PV (through its PVC) blocks
// the strip — the mount may still be real.
func TestVolumeAttachmentCleanerStuckReadyPodBlocks(t *testing.T) {
	now := time.Now()
	va := vacAttachment("va-blocked", "w1", now.Add(-time.Hour))
	termAt := metav1.NewTime(now.Add(-30 * time.Minute))
	va.DeletionTimestamp = &termAt
	va.Finalizers = []string{"external-attacher/csi-test"}
	va.Spec.Source.PersistentVolumeName = ptr.To("pv-data")
	cs := fake.NewSimpleClientset(va, vacNode("w1", corev1.ConditionTrue),
		vacPV("pv-data", "csi.test", "vol-1"),
		vacClaim("data", "claim-a", "pv-data"),
		vacPVCUser("data", "writer", "w1", "claim-a"))
	c := newVACleaner(cs, func() time.Time { return now })
	for range 3 {
		if err := c.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	got, err := cs.StorageV1().VolumeAttachments().Get(ctx, "va-blocked", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Finalizers) == 0 {
		t.Fatal("finalizers stripped while a pod still mounts the PV")
	}
}

// A volume still present in node.Status.VolumesInUse blocks the
// strip — the kubelet's own ledger says the mount may still exist.
func TestVolumeAttachmentCleanerStuckReadyVolumeInUseBlocks(t *testing.T) {
	now := time.Now()
	va := vacAttachment("va-inuse", "w1", now.Add(-time.Hour))
	termAt := metav1.NewTime(now.Add(-30 * time.Minute))
	va.DeletionTimestamp = &termAt
	va.Finalizers = []string{"external-attacher/csi-test"}
	va.Spec.Source.PersistentVolumeName = ptr.To("pv-data")
	node := vacNode("w1", corev1.ConditionTrue)
	node.Status.VolumesInUse = []corev1.UniqueVolumeName{
		"kubernetes.io/csi/csi.test^vol-1"}
	node.Status.VolumesAttached = []corev1.AttachedVolume{{
		Name: "kubernetes.io/csi/csi.test^vol-1", DevicePath: "/var/x"}}
	cs := fake.NewSimpleClientset(va, node,
		vacPV("pv-data", "csi.test", "vol-1"))
	c := newVACleaner(cs, func() time.Time { return now })
	for range 3 {
		if err := c.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	got, err := cs.StorageV1().VolumeAttachments().Get(ctx, "va-inuse", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Finalizers) == 0 {
		t.Fatal("finalizers stripped while the volume is still in-use on the node")
	}
}
