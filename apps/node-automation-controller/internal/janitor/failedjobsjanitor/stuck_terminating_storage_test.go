package failedjobsjanitor

import (
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

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

// An unbound PV (no ClaimRef) and a still-Bound PV are not orphans even
// when their pv-protection finalizer is the only one left. Both must
// fail closed; a 403 on the snapshot CRDs must not abort the PVC/PV
// half of the audit either.
func TestStuckTerminatingUnboundAndBoundPVFailClosedWithForbiddenSnapshots(t *testing.T) {
	metrics.StuckTerminatingResources.Reset()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	oldDel := metav1.NewTime(now.Add(-3 * time.Hour))

	pvNoRef := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "pv-no-ref", ResourceVersion: "40",
			DeletionTimestamp: &oldDel, Finalizers: []string{pvProtectionFinalizer},
		},
	}
	pvBound := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "pv-bound", ResourceVersion: "41",
			DeletionTimestamp: &oldDel, Finalizers: []string{pvProtectionFinalizer},
		},
		Spec: corev1.PersistentVolumeSpec{
			ClaimRef: &corev1.ObjectReference{Namespace: "apps", Name: "claimed-pvc"},
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
	}

	cs := fake.NewSimpleClientset(pvNoRef, pvBound)
	dyn := testutil.NewDynamicClient()
	dyn.PrependReactor("list", "volumesnapshots", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(
			schema.GroupResource{Group: "snapshot.storage.k8s.io", Resource: "volumesnapshots"}, "",
			errors.New("forbidden"))
	})
	const queue = "stuck-storage-pv-forbidden-test"
	before := hookRunErrorCount(t, queue)
	j := &failedJobsJanitor{
		cs: cs, dyn: dyn,
		now:   func() time.Time { return now },
		queue: queue,
	}
	if err := j.auditStuckTerminating(ctx, nil); err != nil {
		t.Fatalf("forbidden snapshot list must not abort auditStuckTerminating: %v", err)
	}
	for _, name := range []string{"pv-no-ref", "pv-bound"} {
		pv, _ := cs.CoreV1().PersistentVolumes().Get(ctx, name, metav1.GetOptions{})
		if len(pv.Finalizers) != 1 || pv.Finalizers[0] != pvProtectionFinalizer {
			t.Fatalf("%s must keep pv-protection, got %v", name, pv.Finalizers)
		}
	}
	if after := hookRunErrorCount(t, queue); after != before {
		t.Fatalf("tolerated forbidden snapshot list must not IncError: before=%v after=%v", before, after)
	}
}

// A 403 on the counterpart Get is also a tolerated RBAC sub-failure:
// both unstickers must keep their bound-protection finalizer (fail
// closed) and must NOT bump the run-error counter, because the audit
// absorbs the sub-failure and returns no error to the wrapper.
func TestStuckTerminatingForbiddenCounterpartGetFailsClosed(t *testing.T) {
	metrics.StuckTerminatingResources.Reset()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	oldDel := metav1.NewTime(now.Add(-3 * time.Hour))

	vs := testutil.Unstructured(kube.GVRVolumeSnapshot.GroupVersion().WithKind("VolumeSnapshot"), "apps", "snap-forbidden", nil)
	vs.SetDeletionTimestamp(&oldDel)
	vs.SetFinalizers([]string{vsBoundProtectionFinalizer})
	vs.Object["metadata"].(map[string]any)["resourceVersion"] = "50"
	_ = unstructured.SetNestedField(vs.Object, "vsc-forbidden-lookup", "status", "boundVolumeSnapshotContentName")

	vsc := testutil.Unstructured(kube.GVRVolumeSnapshotContent.GroupVersion().WithKind("VolumeSnapshotContent"), "", "vsc-forbidden", nil)
	vsc.SetDeletionTimestamp(&oldDel)
	vsc.SetFinalizers([]string{vscBoundProtectionFinalizer})
	vsc.Object["metadata"].(map[string]any)["resourceVersion"] = "51"
	_ = unstructured.SetNestedMap(vsc.Object, map[string]any{"namespace": "apps", "name": "vs-forbidden-lookup"}, "spec", "volumeSnapshotRef")

	cs := fake.NewSimpleClientset()
	dyn := testutil.NewDynamicClient(vs, vsc)
	// Fail ONLY the counterpart lookups by name; the test's own final
	// verification Get must still reach the tracker.
	forbidden := func(resource, target string) k8stesting.ReactionFunc {
		return func(a k8stesting.Action) (bool, runtime.Object, error) {
			get, ok := a.(k8stesting.GetAction)
			if !ok || get.GetName() != target {
				return false, nil, nil
			}
			return true, nil, apierrors.NewForbidden(
				schema.GroupResource{Group: kube.GVRVolumeSnapshot.Group, Resource: resource}, "",
				errors.New("forbidden"))
		}
	}
	dyn.PrependReactor("get", "volumesnapshotcontents", forbidden("volumesnapshotcontents", "vsc-forbidden-lookup"))
	dyn.PrependReactor("get", "volumesnapshots", forbidden("volumesnapshots", "vs-forbidden-lookup"))

	const queue = "stuck-storage-counterpart-forbidden-test"
	before := hookRunErrorCount(t, queue)
	j := &failedJobsJanitor{
		cs: cs, dyn: dyn,
		now:   func() time.Time { return now },
		queue: queue,
	}
	if err := j.auditStuckTerminating(ctx, nil); err != nil {
		t.Fatalf("forbidden counterpart Get must not abort auditStuckTerminating: %v", err)
	}

	for _, tc := range []struct {
		obj    *unstructured.Unstructured
		gvr    schema.GroupVersionResource
		ns     string
		name   string
		keep   string
		gaugeK string
	}{
		{vs, kube.GVRVolumeSnapshot, "apps", "snap-forbidden", vsBoundProtectionFinalizer, "VolumeSnapshot"},
		{vsc, kube.GVRVolumeSnapshotContent, "", "vsc-forbidden", vscBoundProtectionFinalizer, "VolumeSnapshotContent"},
	} {
		got, err := dyn.Resource(tc.gvr).Namespace(tc.ns).Get(ctx, tc.name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get %s/%s: %v", tc.ns, tc.name, err)
		}
		if f := got.GetFinalizers(); len(f) != 1 || f[0] != tc.keep {
			t.Fatalf("%s must keep %q after forbidden counterpart Get, got %v", tc.name, tc.keep, f)
		}
		if v := ptestutil.ToFloat64(metrics.StuckTerminatingResources.WithLabelValues(tc.gaugeK, tc.ns, tc.name)); v != 1 {
			t.Fatalf("expected StuckTerminatingResources=1 for %s, got %v", tc.name, v)
		}
	}
	if after := hookRunErrorCount(t, queue); after != before {
		t.Fatalf("tolerated forbidden counterpart Get must not IncError: before=%v after=%v", before, after)
	}
}

// A 403 on the PV LIST must skip ONLY the PV half of the audit: a stuck
// VolumeSnapshot on the same sweep still gets its bound-protection
// finalizer stripped, and the tolerated 403 must not IncError.
func TestStuckTerminatingPVListForbiddenStillUnsticksVolumeSnapshot(t *testing.T) {
	metrics.StuckTerminatingResources.Reset()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	oldDel := metav1.NewTime(now.Add(-3 * time.Hour))
	vs := testutil.Unstructured(kube.GVRVolumeSnapshot.GroupVersion().WithKind("VolumeSnapshot"),
		"apps", "snap-after-pv-403", nil)
	vs.SetDeletionTimestamp(&oldDel)
	vs.SetFinalizers([]string{vsBoundProtectionFinalizer})
	vs.Object["metadata"].(map[string]any)["resourceVersion"] = "60"
	// Counterpart VSC is absent from the fake — the live Get returns
	// NotFound, so the snapshot is genuinely unblocked.
	_ = unstructured.SetNestedField(vs.Object, "vsc-gone", "status", "boundVolumeSnapshotContentName")

	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "persistentvolumes", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(
			schema.GroupResource{Resource: "persistentvolumes"}, "", errors.New("forbidden"))
	})
	dyn := testutil.NewDynamicClient(vs)
	const queue = "stuck-storage-pv-list-forbidden-test"
	before := hookRunErrorCount(t, queue)
	j := &failedJobsJanitor{
		cs: cs, dyn: dyn,
		now:   func() time.Time { return now },
		queue: queue,
	}
	if err := j.auditStuckTerminating(ctx, nil); err != nil {
		t.Fatalf("forbidden PV list must not abort the snapshot half: %v", err)
	}
	got, err := dyn.Resource(kube.GVRVolumeSnapshot).Namespace("apps").
		Get(ctx, "snap-after-pv-403", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get stuck VolumeSnapshot: %v", err)
	}
	if f := got.GetFinalizers(); len(f) != 0 {
		t.Fatalf("VolumeSnapshot bound-protection must be stripped despite PV list 403, got %v", f)
	}
	if v := ptestutil.ToFloat64(metrics.StuckTerminatingResources.WithLabelValues(
		"VolumeSnapshot", "apps", "snap-after-pv-403")); v != 0 {
		t.Fatalf("unstuck VolumeSnapshot must not emit stuck gauge, got %v", v)
	}
	if after := hookRunErrorCount(t, queue); after != before {
		t.Fatalf("tolerated forbidden PV list must not IncError: before=%v after=%v", before, after)
	}
}

// hookRunErrorCount reads the shared shell-operator-compatible run-error
// counter from controller-runtime's registry; metrics.IncError owns the
// vector, so tests can only observe it via Gather.
func hookRunErrorCount(t *testing.T, queue string) float64 {
	t.Helper()
	families, err := ctrlmetrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, mf := range families {
		if mf.GetName() != "shell_operator_hook_run_errors_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "queue" && l.GetValue() == queue {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

// VolumeAttachments (full typed list) and Nodes are cached once per
// sweep across multiple stuck Terminating PVCs and PVs, while a fresh
// sweep observes updated cluster state.
func TestAuditStuckTerminatingCachesVolumeAttachmentsAndNodesPerSweep(t *testing.T) {
	metrics.StuckTerminatingResources.Reset()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	oldDel := metav1.NewTime(now.Add(-3 * time.Hour))

	objs := []runtime.Object{
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "ready-node"},
			Status:     corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}},
		},
	}
	for i := range 3 {
		pvcName := fmt.Sprintf("stuck-pvc-%d", i)
		pvName := fmt.Sprintf("bound-pv-%d", i)
		objs = append(objs, &corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:         "apps",
				Name:              pvcName,
				ResourceVersion:   fmt.Sprintf("%d", 10+i),
				DeletionTimestamp: &oldDel,
				Finalizers:        []string{pvcProtectionFinalizer},
			},
			Spec: corev1.PersistentVolumeClaimSpec{VolumeName: pvName},
		})
	}
	for i := range 2 {
		objs = append(objs, &corev1.PersistentVolume{
			ObjectMeta: metav1.ObjectMeta{
				Name:              fmt.Sprintf("stuck-pv-%d", i),
				ResourceVersion:   fmt.Sprintf("%d", 20+i),
				DeletionTimestamp: &oldDel,
				Finalizers:        []string{pvProtectionFinalizer},
			},
			Spec: corev1.PersistentVolumeSpec{
				ClaimRef: &corev1.ObjectReference{
					Namespace: "apps",
					Name:      fmt.Sprintf("gone-pvc-%d", i),
				},
			},
		})
	}

	cs := fake.NewSimpleClientset(objs...)
	var vaLists, nodeLists atomic.Int32
	cs.PrependReactor("list", "volumeattachments", func(k8stesting.Action) (bool, runtime.Object, error) {
		vaLists.Add(1)
		return false, nil, nil
	})
	cs.PrependReactor("list", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
		nodeLists.Add(1)
		return false, nil, nil
	})

	j := &failedJobsJanitor{
		cs:    cs,
		dyn:   testutil.NewDynamicClient(),
		now:   func() time.Time { return now },
		queue: "stuck-cache-sweep-test",
	}
	if err := j.auditStuckTerminating(ctx, nil); err != nil {
		t.Fatalf("sweep 1: %v", err)
	}
	// 1 metadata-only audit VA list (fallback on cs because meta==nil)
	// + at most 1 full VA list in census.listVolumeAttachments across 3 PVCs + 2 PVs = 2 total.
	if got := vaLists.Load(); got != 2 {
		t.Fatalf("volumeattachments list count = %d, want 2 (1 audit + 1 cached across 5 candidates)", got)
	}
	if got := nodeLists.Load(); got != 1 {
		t.Fatalf("nodes list count = %d, want 1 (cached across 5 candidates)", got)
	}
	for i := range 3 {
		pvc, err := cs.CoreV1().PersistentVolumeClaims("apps").Get(ctx, fmt.Sprintf("stuck-pvc-%d", i), metav1.GetOptions{})
		if err != nil || len(pvc.Finalizers) != 0 {
			t.Fatalf("stuck-pvc-%d finalizers = %v (err=%v), want stripped", i, pvc.Finalizers, err)
		}
	}
	for i := range 2 {
		pv, err := cs.CoreV1().PersistentVolumes().Get(ctx, fmt.Sprintf("stuck-pv-%d", i), metav1.GetOptions{})
		if err != nil || len(pv.Finalizers) != 0 {
			t.Fatalf("stuck-pv-%d finalizers = %v (err=%v), want stripped", i, pv.Finalizers, err)
		}
	}

	// Second sweep: add a new stuck PVC whose PV now has an attached VA
	// and a new stuck PV whose ClaimRef is held by a Failed pod on a newly
	// added dead node — proves per-sweep lifetime (fresh state observed).
	attachedPV := "fresh-pv-attached"
	freshPVC := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "apps",
			Name:              "fresh-stuck-pvc",
			ResourceVersion:   "30",
			DeletionTimestamp: &oldDel,
			Finalizers:        []string{pvcProtectionFinalizer},
		},
		Spec: corev1.PersistentVolumeClaimSpec{VolumeName: attachedPV},
	}
	freshVA := &storagev1.VolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: "fresh-va"},
		Spec:       storagev1.VolumeAttachmentSpec{Source: storagev1.VolumeAttachmentSource{PersistentVolumeName: &attachedPV}},
		Status:     storagev1.VolumeAttachmentStatus{Attached: true},
	}
	freshPV := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "fresh-stuck-pv",
			ResourceVersion:   "31",
			DeletionTimestamp: &oldDel,
			Finalizers:        []string{pvProtectionFinalizer},
		},
		Spec: corev1.PersistentVolumeSpec{
			ClaimRef: &corev1.ObjectReference{Namespace: "apps", Name: "dead-pod-pvc"},
		},
	}
	deadNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "new-dead-node"},
		Status:     corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionFalse}}},
	}
	deadPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "dead-pod"},
		Spec: corev1.PodSpec{
			NodeName: "new-dead-node",
			Volumes: []corev1.Volume{{
				Name:         "v",
				VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "dead-pod-pvc"}},
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodFailed},
	}
	for _, obj := range []runtime.Object{freshPVC, freshVA, freshPV, deadNode, deadPod} {
		if err := cs.Tracker().Add(obj); err != nil {
			t.Fatal(err)
		}
	}

	if err := j.auditStuckTerminating(ctx, nil); err != nil {
		t.Fatalf("sweep 2: %v", err)
	}
	if got := vaLists.Load(); got != 4 {
		t.Fatalf("volumeattachments list count after 2 sweeps = %d, want 4", got)
	}
	if got := nodeLists.Load(); got != 2 {
		t.Fatalf("nodes list count after 2 sweeps = %d, want 2", got)
	}
	gotFreshPVC, _ := cs.CoreV1().PersistentVolumeClaims("apps").Get(ctx, "fresh-stuck-pvc", metav1.GetOptions{})
	if len(gotFreshPVC.Finalizers) != 1 {
		t.Fatalf("fresh-stuck-pvc must keep finalizer due to new VA, got %v", gotFreshPVC.Finalizers)
	}
	gotFreshPV, _ := cs.CoreV1().PersistentVolumes().Get(ctx, "fresh-stuck-pv", metav1.GetOptions{})
	if len(gotFreshPV.Finalizers) != 1 {
		t.Fatalf("fresh-stuck-pv must keep finalizer due to new dead-node pod, got %v", gotFreshPV.Finalizers)
	}
}

// When the cached VolumeAttachment or Node list fails, every stuck PVC
// and PV fails closed (retains its protection finalizer) while
// metrics.IncError increments exactly once per broken list.
func TestAuditStuckTerminatingCachedVAAndNodeListErrorsFailClosedOnce(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	oldDel := metav1.NewTime(now.Add(-3 * time.Hour))

	makeObjs := func() []runtime.Object {
		var objs []runtime.Object
		for i := range 2 {
			objs = append(objs, &corev1.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:         "apps",
					Name:              fmt.Sprintf("err-pvc-%d", i),
					ResourceVersion:   fmt.Sprintf("%d", 10+i),
					DeletionTimestamp: &oldDel,
					Finalizers:        []string{pvcProtectionFinalizer},
				},
				Spec: corev1.PersistentVolumeClaimSpec{VolumeName: fmt.Sprintf("bound-pv-%d", i)},
			})
			objs = append(objs, &corev1.PersistentVolume{
				ObjectMeta: metav1.ObjectMeta{
					Name:              fmt.Sprintf("err-pv-%d", i),
					ResourceVersion:   fmt.Sprintf("%d", 20+i),
					DeletionTimestamp: &oldDel,
					Finalizers:        []string{pvProtectionFinalizer},
				},
				Spec: corev1.PersistentVolumeSpec{
					ClaimRef: &corev1.ObjectReference{
						Namespace: "apps",
						Name:      fmt.Sprintf("gone-pvc-%d", i),
					},
				},
			})
		}
		return objs
	}

	t.Run("VolumeAttachments list error fails closed and IncErrors once", func(t *testing.T) {
		metrics.StuckTerminatingResources.Reset()
		cs := fake.NewSimpleClientset(makeObjs()...)
		var vaCalls atomic.Int32
		cs.PrependReactor("list", "volumeattachments", func(k8stesting.Action) (bool, runtime.Object, error) {
			// 1st call is auditStuckTerminating's metadata list; 2nd is census.listVolumeAttachments.
			if vaCalls.Add(1) >= 2 {
				return true, nil, errors.New("va list failed")
			}
			return false, nil, nil
		})
		const queue = "stuck-va-err-once-test"
		before := hookRunErrorCount(t, queue)
		j := &failedJobsJanitor{
			cs:    cs,
			dyn:   testutil.NewDynamicClient(),
			now:   func() time.Time { return now },
			queue: queue,
		}
		if err := j.auditStuckTerminating(ctx, nil); err != nil {
			t.Fatalf("auditStuckTerminating: %v", err)
		}
		if got := vaCalls.Load(); got != 2 {
			t.Fatalf("vaCalls = %d, want 2 (1 audit + 1 cached census list)", got)
		}
		if after := hookRunErrorCount(t, queue); after-before != 1 {
			t.Fatalf("IncError delta = %v, want 1 across 4 candidates", after-before)
		}
		for i := range 2 {
			pvc, _ := cs.CoreV1().PersistentVolumeClaims("apps").Get(ctx, fmt.Sprintf("err-pvc-%d", i), metav1.GetOptions{})
			if len(pvc.Finalizers) != 1 {
				t.Fatalf("err-pvc-%d lost finalizer on VA error: %v", i, pvc.Finalizers)
			}
			pv, _ := cs.CoreV1().PersistentVolumes().Get(ctx, fmt.Sprintf("err-pv-%d", i), metav1.GetOptions{})
			if len(pv.Finalizers) != 1 {
				t.Fatalf("err-pv-%d lost finalizer on VA error: %v", i, pv.Finalizers)
			}
		}
	})

	t.Run("Nodes list error fails closed and IncErrors once", func(t *testing.T) {
		metrics.StuckTerminatingResources.Reset()
		cs := fake.NewSimpleClientset(makeObjs()...)
		var nodeCalls atomic.Int32
		cs.PrependReactor("list", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
			nodeCalls.Add(1)
			return true, nil, errors.New("nodes list failed")
		})
		const queue = "stuck-nodes-err-once-test"
		before := hookRunErrorCount(t, queue)
		j := &failedJobsJanitor{
			cs:    cs,
			dyn:   testutil.NewDynamicClient(),
			now:   func() time.Time { return now },
			queue: queue,
		}
		if err := j.auditStuckTerminating(ctx, nil); err != nil {
			t.Fatalf("auditStuckTerminating: %v", err)
		}
		if got := nodeCalls.Load(); got != 1 {
			t.Fatalf("nodeCalls = %d, want 1", got)
		}
		if after := hookRunErrorCount(t, queue); after-before != 1 {
			t.Fatalf("IncError delta = %v, want 1 across 4 candidates", after-before)
		}
		for i := range 2 {
			pvc, _ := cs.CoreV1().PersistentVolumeClaims("apps").Get(ctx, fmt.Sprintf("err-pvc-%d", i), metav1.GetOptions{})
			if len(pvc.Finalizers) != 1 {
				t.Fatalf("err-pvc-%d lost finalizer on Nodes error: %v", i, pvc.Finalizers)
			}
			pv, _ := cs.CoreV1().PersistentVolumes().Get(ctx, fmt.Sprintf("err-pv-%d", i), metav1.GetOptions{})
			if len(pv.Finalizers) != 1 {
				t.Fatalf("err-pv-%d lost finalizer on Nodes error: %v", i, pv.Finalizers)
			}
		}
	})
}

// Direct single-call (nil-census) wrappers work standalone as documented
// for direct unit testing of pvcMountThreatenable, failedPodOnDeadNode,
// unstickPVProtection, and clusterPodUsesClaimRef.
func TestStuckTerminatingSingleCallWrappers(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	oldDel := metav1.NewTime(now.Add(-3 * time.Hour))

	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "claim-1", ResourceVersion: "1",
			DeletionTimestamp: &oldDel, Finalizers: []string{pvcProtectionFinalizer},
		},
		Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "pv-1"},
	}
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "pv-1", ResourceVersion: "2",
			DeletionTimestamp: &oldDel, Finalizers: []string{pvProtectionFinalizer},
		},
		Spec: corev1.PersistentVolumeSpec{
			ClaimRef: &corev1.ObjectReference{Namespace: "apps", Name: "gone-claim"},
		},
	}
	deadNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "dead-n"},
		Status:     corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionFalse}}},
	}
	deadPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "dead-p"},
		Spec: corev1.PodSpec{
			NodeName: "dead-n",
			Volumes: []corev1.Volume{{
				Name:         "v",
				VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "claim-1"}},
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodFailed},
	}

	cs := fake.NewSimpleClientset(pvc, pv, deadNode, deadPod)
	j := &failedJobsJanitor{cs: cs, now: func() time.Time { return now }, queue: "stuck-wrappers-test"}

	if got, err := j.failedPodOnDeadNode(ctx, "apps", "claim-1"); err != nil || got != "dead-p" {
		t.Fatalf("failedPodOnDeadNode = (%q, %v), want (dead-p, nil)", got, err)
	}
	if !j.pvcMountThreatenable(ctx, unstickPVCMeta(pvc)) {
		t.Fatal("pvcMountThreatenable expected true when failed pod sits on dead node")
	}
	if inUse, err := j.clusterPodUsesClaimRef(ctx, &corev1.ObjectReference{Namespace: "apps", Name: "claim-1"}); err != nil || !inUse {
		t.Fatalf("clusterPodUsesClaimRef = (%v, %v), want (true, nil)", inUse, err)
	}
	if !j.unstickPVProtection(ctx, pv) {
		t.Fatal("unstickPVProtection expected true for orphan pv-1")
	}
}
