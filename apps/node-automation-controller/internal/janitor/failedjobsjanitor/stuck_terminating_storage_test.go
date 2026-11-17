package failedjobsjanitor

import (
	"testing"
	"time"

	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func TestStuckTerminatingPVProtectionFiveGates(t *testing.T) {
	metrics.StuckTerminatingResources.Reset()
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	oldDel := metav1.NewTime(now.Add(-3 * time.Hour))

	// 1. Orphan PV -> all 5 gates pass -> pv-protection stripped!
	pvOrphan := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pv-orphan",
			ResourceVersion:   "10",
			DeletionTimestamp: &oldDel,
			Finalizers:        []string{pvProtectionFinalizer},
		},
		Spec: corev1.PersistentVolumeSpec{
			ClaimRef: &corev1.ObjectReference{Namespace: "apps", Name: "gone-pvc"},
		},
	}
	// 2. PV whose ClaimRef PVC still exists -> fail closed, keep finalizer & emit gauge.
	pvcLive := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "live-pvc"},
	}
	pvLiveClaim := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pv-live-claim",
			ResourceVersion:   "11",
			DeletionTimestamp: &oldDel,
			Finalizers:        []string{pvProtectionFinalizer},
		},
		Spec: corev1.PersistentVolumeSpec{
			ClaimRef: &corev1.ObjectReference{Namespace: "apps", Name: "live-pvc"},
		},
	}
	// 3. PV still attached by VolumeAttachment -> keep finalizer.
	pvNameAtt := "pv-attached"
	pvAttached := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name:              pvNameAtt,
			ResourceVersion:   "12",
			DeletionTimestamp: &oldDel,
			Finalizers:        []string{pvProtectionFinalizer},
		},
		Spec: corev1.PersistentVolumeSpec{
			ClaimRef: &corev1.ObjectReference{Namespace: "apps", Name: "gone-pvc-2"},
		},
	}
	va := &storagev1.VolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: "va-1"},
		Spec:       storagev1.VolumeAttachmentSpec{Source: storagev1.VolumeAttachmentSource{PersistentVolumeName: &pvNameAtt}},
		Status:     storagev1.VolumeAttachmentStatus{Attached: true},
	}
	// 4. PV referenced by Failed pod on NotReady node -> keep finalizer.
	deadNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "dead-node"},
		Status:     corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionFalse}}},
	}
	failedPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "dead-pod"},
		Spec: corev1.PodSpec{
			NodeName: "dead-node",
			Volumes: []corev1.Volume{{
				Name:         "data",
				VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "dead-node-pvc"}},
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodFailed},
	}
	pvDeadNode := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pv-dead-node",
			ResourceVersion:   "13",
			DeletionTimestamp: &oldDel,
			Finalizers:        []string{pvProtectionFinalizer},
		},
		Spec: corev1.PersistentVolumeSpec{
			ClaimRef: &corev1.ObjectReference{Namespace: "apps", Name: "dead-node-pvc"},
		},
	}

	cs := fake.NewSimpleClientset(pvOrphan, pvcLive, pvLiveClaim, pvAttached, va, deadNode, failedPod, pvDeadNode)
	j := &failedJobsJanitor{
		cs:  cs,
		dyn: testutil.NewDynamicClient(),
		now: func() time.Time { return now },
	}
	if err := j.auditStuckTerminating(ctx, nil); err != nil {
		t.Fatalf("auditStuckTerminating: %v", err)
	}

	gotOrphan, _ := cs.CoreV1().PersistentVolumes().Get(ctx, "pv-orphan", metav1.GetOptions{})
	if len(gotOrphan.Finalizers) != 0 {
		t.Fatalf("expected pv-orphan finalizers stripped, got %v", gotOrphan.Finalizers)
	}
	for _, kept := range []string{"pv-live-claim", "pv-attached", "pv-dead-node"} {
		pv, _ := cs.CoreV1().PersistentVolumes().Get(ctx, kept, metav1.GetOptions{})
		if len(pv.Finalizers) != 1 || pv.Finalizers[0] != pvProtectionFinalizer {
			t.Fatalf("%s must retain pv-protection, got %v", kept, pv.Finalizers)
		}
		if v := ptestutil.ToFloat64(metrics.StuckTerminatingResources.WithLabelValues("PersistentVolume", "", kept)); v != 1 {
			t.Fatalf("expected StuckTerminatingResources=1 for %s, got %v", kept, v)
		}
	}
	if v := ptestutil.ToFloat64(metrics.StuckTerminatingResources.WithLabelValues("PersistentVolume", "", "pv-orphan")); v != 0 {
		t.Fatalf("unblocked pv-orphan should not emit stuck gauge, got %v", v)
	}
}

func TestStuckTerminatingVolumeSnapshotSelectiveUnstick(t *testing.T) {
	metrics.StuckTerminatingResources.Reset()
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	oldDel := metav1.NewTime(now.Add(-3 * time.Hour))

	// VS whose bound VSC is gone -> removes ONLY volumesnapshot-bound-protection, keeps as-source-protection!
	vsUnstick := testutil.Unstructured(kube.GVRVolumeSnapshot.GroupVersion().WithKind("VolumeSnapshot"), "apps", "snap-orphan", nil)
	vsUnstick.SetDeletionTimestamp(&oldDel)
	vsUnstick.SetFinalizers([]string{vsBoundProtectionFinalizer, "snapshot.storage.kubernetes.io/volumesnapshot-as-source-protection"})
	vsUnstick.Object["metadata"].(map[string]any)["resourceVersion"] = "21"
	_ = unstructured.SetNestedField(vsUnstick.Object, "vsc-gone", "status", "boundVolumeSnapshotContentName")

	// VSC whose bound VS is gone -> removes ONLY volumesnapshotcontent-bound-protection, keeps delete-finalizer!
	vscUnstick := testutil.Unstructured(kube.GVRVolumeSnapshotContent.GroupVersion().WithKind("VolumeSnapshotContent"), "", "vsc-orphan", nil)
	vscUnstick.SetDeletionTimestamp(&oldDel)
	vscUnstick.SetFinalizers([]string{vscBoundProtectionFinalizer, "csi-snapshotter-delete"})
	vscUnstick.Object["metadata"].(map[string]any)["resourceVersion"] = "22"
	_ = unstructured.SetNestedMap(vscUnstick.Object, map[string]any{"namespace": "apps", "name": "vs-gone"}, "spec", "volumeSnapshotRef")

	// Live VS/VSC pair -> counterpart exists, must keep bound-protection!
	vsLive := testutil.Unstructured(kube.GVRVolumeSnapshot.GroupVersion().WithKind("VolumeSnapshot"), "apps", "snap-live", nil)
	vsLive.SetDeletionTimestamp(&oldDel)
	vsLive.SetFinalizers([]string{vsBoundProtectionFinalizer})
	vsLive.Object["metadata"].(map[string]any)["resourceVersion"] = "23"
	_ = unstructured.SetNestedField(vsLive.Object, "vsc-live", "status", "boundVolumeSnapshotContentName")

	vscLive := testutil.Unstructured(kube.GVRVolumeSnapshotContent.GroupVersion().WithKind("VolumeSnapshotContent"), "", "vsc-live", nil)

	cs := fake.NewSimpleClientset()
	dyn := testutil.NewDynamicClient(vsUnstick, vscUnstick, vsLive, vscLive)
	j := &failedJobsJanitor{
		cs:  cs,
		dyn: dyn,
		now: func() time.Time { return now },
	}
	if err := j.auditStuckTerminating(ctx, nil); err != nil {
		t.Fatalf("auditStuckTerminating: %v", err)
	}

	gotVS, _ := dyn.Resource(kube.GVRVolumeSnapshot).Namespace("apps").Get(ctx, "snap-orphan", metav1.GetOptions{})
	if len(gotVS.GetFinalizers()) != 1 || gotVS.GetFinalizers()[0] != "snapshot.storage.kubernetes.io/volumesnapshot-as-source-protection" {
		t.Fatalf("expected only as-source-protection remaining on snap-orphan, got %v", gotVS.GetFinalizers())
	}
	gotVSC, _ := dyn.Resource(kube.GVRVolumeSnapshotContent).Get(ctx, "vsc-orphan", metav1.GetOptions{})
	if len(gotVSC.GetFinalizers()) != 1 || gotVSC.GetFinalizers()[0] != "csi-snapshotter-delete" {
		t.Fatalf("expected only csi-snapshotter-delete remaining on vsc-orphan, got %v", gotVSC.GetFinalizers())
	}
	gotLiveVS, _ := dyn.Resource(kube.GVRVolumeSnapshot).Namespace("apps").Get(ctx, "snap-live", metav1.GetOptions{})
	if len(gotLiveVS.GetFinalizers()) != 1 || gotLiveVS.GetFinalizers()[0] != vsBoundProtectionFinalizer {
		t.Fatalf("snap-live with existing VSC must keep bound-protection, got %v", gotLiveVS.GetFinalizers())
	}
}

func TestStuckTerminatingEmptyCounterpartRefsFailClosed(t *testing.T) {
	metrics.StuckTerminatingResources.Reset()
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	oldDel := metav1.NewTime(now.Add(-3 * time.Hour))

	// PV with partial ClaimRef (missing Name) -> must fail closed and keep pv-protection.
	pvPartialRef := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pv-partial-ref",
			ResourceVersion:   "30",
			DeletionTimestamp: &oldDel,
			Finalizers:        []string{pvProtectionFinalizer},
		},
		Spec: corev1.PersistentVolumeSpec{
			ClaimRef: &corev1.ObjectReference{Namespace: "apps", Name: ""},
		},
	}

	// VS with empty boundVolumeSnapshotContentName/source -> fail closed.
	vsEmptyRef := testutil.Unstructured(kube.GVRVolumeSnapshot.GroupVersion().WithKind("VolumeSnapshot"), "apps", "snap-empty-ref", nil)
	vsEmptyRef.SetDeletionTimestamp(&oldDel)
	vsEmptyRef.SetFinalizers([]string{vsBoundProtectionFinalizer})
	vsEmptyRef.Object["metadata"].(map[string]any)["resourceVersion"] = "31"

	// VSC with empty volumeSnapshotRef -> fail closed.
	vscEmptyRef := testutil.Unstructured(kube.GVRVolumeSnapshotContent.GroupVersion().WithKind("VolumeSnapshotContent"), "", "vsc-empty-ref", nil)
	vscEmptyRef.SetDeletionTimestamp(&oldDel)
	vscEmptyRef.SetFinalizers([]string{vscBoundProtectionFinalizer})
	vscEmptyRef.Object["metadata"].(map[string]any)["resourceVersion"] = "32"

	cs := fake.NewSimpleClientset(pvPartialRef)
	dyn := testutil.NewDynamicClient(vsEmptyRef, vscEmptyRef)
	j := &failedJobsJanitor{
		cs:  cs,
		dyn: dyn,
		now: func() time.Time { return now },
	}
	if err := j.auditStuckTerminating(ctx, nil); err != nil {
		t.Fatalf("auditStuckTerminating: %v", err)
	}

	gotPV, _ := cs.CoreV1().PersistentVolumes().Get(ctx, "pv-partial-ref", metav1.GetOptions{})
	if len(gotPV.Finalizers) != 1 || gotPV.Finalizers[0] != pvProtectionFinalizer {
		t.Fatalf("pv-partial-ref must keep pv-protection, got %v", gotPV.Finalizers)
	}
	gotVS, _ := dyn.Resource(kube.GVRVolumeSnapshot).Namespace("apps").Get(ctx, "snap-empty-ref", metav1.GetOptions{})
	if len(gotVS.GetFinalizers()) != 1 || gotVS.GetFinalizers()[0] != vsBoundProtectionFinalizer {
		t.Fatalf("snap-empty-ref must keep bound-protection, got %v", gotVS.GetFinalizers())
	}
	gotVSC, _ := dyn.Resource(kube.GVRVolumeSnapshotContent).Get(ctx, "vsc-empty-ref", metav1.GetOptions{})
	if len(gotVSC.GetFinalizers()) != 1 || gotVSC.GetFinalizers()[0] != vscBoundProtectionFinalizer {
		t.Fatalf("vsc-empty-ref must keep bound-protection, got %v", gotVSC.GetFinalizers())
	}
}
