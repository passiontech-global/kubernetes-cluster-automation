// pvc_lifecycle_guard_test.go — coverage for pvc-lifecycle-guard (#72):
// Pending PVC deadlock reasons (>=10m), Pod fsGroup chown stall (>=5m,
// OnRootMismatch/mount-error exclusions), Released PV age (> env knob),
// failed VolumeSnapshot (>2h), terminating object skips, 403/404 handling,
// lazy Pod loading on empty cluster, and GaugeLedger stale label cleanup.
package pvc

import (
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func pvcDeadlockSeries(t *testing.T, ns, pvc, reason string) (float64, bool) {
	t.Helper()
	return testutil.GaugeSeriesValue(t, "node_automation_pvc_pending_deadlock",
		map[string]string{"namespace": ns, "pvc": pvc, "reason": reason})
}

func podFSGroupStallSeries(t *testing.T, ns, pod string) (float64, bool) {
	t.Helper()
	return testutil.GaugeSeriesValue(t, "node_automation_pod_fsgroup_stall",
		map[string]string{"namespace": ns, "pod": pod})
}

func pvReleasedStaleSeries(t *testing.T, pv, sc string) (float64, bool) {
	t.Helper()
	return testutil.GaugeSeriesValue(t, "node_automation_pv_released_stale",
		map[string]string{"pv": pv, "storageclass": sc})
}

func volumeSnapshotFailedSeries(t *testing.T, ns, snap string) (float64, bool) {
	t.Helper()
	return testutil.GaugeSeriesValue(t, "node_automation_volumesnapshot_failed",
		map[string]string{"namespace": ns, "snapshot": snap})
}

func TestPVCLifecyclePendingDeadlockClassificationAndRecovery(t *testing.T) {
	now := time.Now()
	scFast := &storagev1.StorageClass{
		ObjectMeta:        metav1.ObjectMeta{Name: "fast-rbd"},
		Provisioner:       "rbd.csi.ceph.com",
		VolumeBindingMode: ptr.To(storagev1.VolumeBindingImmediate),
	}
	scWFFC := &storagev1.StorageClass{
		ObjectMeta:        metav1.ObjectMeta{Name: "local-wffc"},
		Provisioner:       "local.csi",
		VolumeBindingMode: ptr.To(storagev1.VolumeBindingWaitForFirstConsumer),
	}

	makePendingPVC := func(name, sc string, age time.Duration, terminating bool) *corev1.PersistentVolumeClaim {
		p := &corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:         "apps",
				Name:              name,
				CreationTimestamp: metav1.NewTime(now.Add(-age)),
			},
			Spec: corev1.PersistentVolumeClaimSpec{StorageClassName: ptr.To(sc)},
			Status: corev1.PersistentVolumeClaimStatus{
				Phase: corev1.ClaimPending,
			},
		}
		if terminating {
			p.DeletionTimestamp = &metav1.Time{Time: now.Add(-time.Minute)}
		}
		return p
	}

	pvcMissingSC := makePendingPVC("pvc-missing-sc", "nonexistent-sc", 15*time.Minute, false)
	pvcFailProv := makePendingPVC("pvc-fail-prov", "fast-rbd", 15*time.Minute, false)
	pvcWFFC := makePendingPVC("pvc-wffc", "local-wffc", 15*time.Minute, false)
	pvcTimeout := makePendingPVC("pvc-timeout", "fast-rbd", 15*time.Minute, false)
	pvcFresh := makePendingPVC("pvc-fresh", "nonexistent-sc", 5*time.Minute, false)
	pvcTerm := makePendingPVC("pvc-terminating", "nonexistent-sc", 20*time.Minute, true)

	evFail := &corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{Namespace: "apps", Name: "ev-fail"},
		InvolvedObject: corev1.ObjectReference{Kind: "PersistentVolumeClaim", Namespace: "apps", Name: "pvc-fail-prov"},
		Reason:         "ProvisioningFailed",
		Message:        "failed to provision volume: quota reached",
		LastTimestamp:  metav1.NewTime(now.Add(-2 * time.Minute)),
	}
	podWFFC := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "pod-wffc"},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{{
				Name:         "data",
				VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "pvc-wffc"}},
			}},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodPending,
			Conditions: []corev1.PodCondition{{
				Type:   corev1.PodScheduled,
				Status: corev1.ConditionFalse,
			}},
		},
	}

	cs := fake.NewSimpleClientset(scFast, scWFFC, pvcMissingSC, pvcFailProv, pvcWFFC, pvcTimeout, pvcFresh, pvcTerm, evFail, podWFFC)
	p := testProber(cs)
	chk := probetest.MustCheck[*pvcLifecycleGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, now)
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatal("expected failure for deadlocked pending PVCs")
	}

	for _, tc := range [][2]string{
		{"pvc-missing-sc", pvcDeadlockStorageClassNotFound},
		{"pvc-fail-prov", pvcDeadlockFailedProvisioning},
		{"pvc-wffc", pvcDeadlockWaitForFirstConsumer},
		{"pvc-timeout", pvcDeadlockPendingTimeout},
	} {
		if v, ok := pvcDeadlockSeries(t, "apps", tc[0], tc[1]); !ok || v != 1 {
			t.Fatalf("missing deadlock series for %v: v=%v ok=%v", tc, v, ok)
		}
	}
	if _, ok := pvcDeadlockSeries(t, "apps", "pvc-fresh", pvcDeadlockStorageClassNotFound); ok {
		t.Fatal("fresh pending PVC (<10m) must not flag")
	}
	if _, ok := pvcDeadlockSeries(t, "apps", "pvc-terminating", pvcDeadlockStorageClassNotFound); ok {
		t.Fatal("terminating PVC must be skipped")
	}

	// Bind all deadlocked PVCs -> stale series must be deleted.
	for _, name := range []string{"pvc-missing-sc", "pvc-fail-prov", "pvc-wffc", "pvc-timeout"} {
		u, _ := cs.CoreV1().PersistentVolumeClaims("apps").Get(ctx, name, metav1.GetOptions{})
		u.Status.Phase = corev1.ClaimBound
		_, _ = cs.CoreV1().PersistentVolumeClaims("apps").UpdateStatus(ctx, u, metav1.UpdateOptions{})
	}
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("recovered sweep must pass: %+v", res)
	}
	for _, tc := range [][2]string{
		{"pvc-missing-sc", pvcDeadlockStorageClassNotFound},
		{"pvc-fail-prov", pvcDeadlockFailedProvisioning},
		{"pvc-wffc", pvcDeadlockWaitForFirstConsumer},
		{"pvc-timeout", pvcDeadlockPendingTimeout},
	} {
		if _, ok := pvcDeadlockSeries(t, "apps", tc[0], tc[1]); ok {
			t.Fatalf("stale deadlock series not deleted for %v", tc)
		}
	}
}

func TestPVCLifecyclePodFSGroupStall(t *testing.T) {
	now := time.Now()
	boundPVC := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Namespace: "data", Name: "vol-1"},
		Status:     corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound},
	}
	makeFSGroupPod := func(name string, policy *corev1.PodFSGroupChangePolicy, scheduledAge time.Duration) *corev1.Pod {
		var conds []corev1.PodCondition
		if scheduledAge >= 0 {
			conds = append(conds, corev1.PodCondition{
				Type:               corev1.PodScheduled,
				Status:             corev1.ConditionTrue,
				LastTransitionTime: metav1.NewTime(now.Add(-scheduledAge)),
			})
		}
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "data", Name: name},
			Spec: corev1.PodSpec{
				SecurityContext: &corev1.PodSecurityContext{
					FSGroup:             ptr.To(int64(1000)),
					FSGroupChangePolicy: policy,
				},
				Volumes: []corev1.Volume{{
					Name:         "v",
					VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "vol-1"}},
				}},
			},
			Status: corev1.PodStatus{
				Phase:      corev1.PodPending,
				Conditions: conds,
				ContainerStatuses: []corev1.ContainerStatus{{
					Name:  "app",
					State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"}},
				}},
			},
		}
	}

	stalledPod := makeFSGroupPod("pod-stalled", nil, 6*time.Minute)
	freshPod := makeFSGroupPod("pod-fresh", nil, 2*time.Minute)
	optOutPolicy := corev1.FSGroupChangeOnRootMismatch
	optOutPod := makeFSGroupPod("pod-onroot", &optOutPolicy, 10*time.Minute)
	mountErrPod := makeFSGroupPod("pod-mounterr", nil, 10*time.Minute)
	mountEv := &corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{Namespace: "data", Name: "ev-mount"},
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Namespace: "data", Name: "pod-mounterr"},
		Reason:         "FailedMount",
		LastTimestamp:  metav1.NewTime(now.Add(-5 * time.Minute)),
	}

	cs := fake.NewSimpleClientset(boundPVC, stalledPod, freshPod, optOutPod, mountErrPod, mountEv)
	p := testProber(cs)
	chk := probetest.MustCheck[*pvcLifecycleGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, now)
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatal("expected failure for pod-stalled")
	}
	if v, ok := podFSGroupStallSeries(t, "data", "pod-stalled"); !ok || v != 1 {
		t.Fatalf("missing fsGroup stall series for pod-stalled: v=%v ok=%v", v, ok)
	}
	for _, name := range []string{"pod-fresh", "pod-onroot", "pod-mounterr"} {
		if _, ok := podFSGroupStallSeries(t, "data", name); ok {
			t.Fatalf("%s must not emit fsgroup stall series", name)
		}
	}

	// Transition stalledPod to Running -> series must be deleted.
	u, _ := cs.CoreV1().Pods("data").Get(ctx, "pod-stalled", metav1.GetOptions{})
	u.Status.Phase = corev1.PodRunning
	u.Status.ContainerStatuses = nil
	_, _ = cs.CoreV1().Pods("data").UpdateStatus(ctx, u, metav1.UpdateOptions{})

	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("recovered sweep must pass: %+v", res)
	}
	if _, ok := podFSGroupStallSeries(t, "data", "pod-stalled"); ok {
		t.Fatal("stale fsgroup stall series not deleted")
	}
}

func TestPVCLifecycleReleasedPVAndVolumeSnapshotAnd403_404(t *testing.T) {
	t.Setenv("NODE_AUTOMATION_PV_RELEASED_MAX_AGE", "24h")
	now := time.Now()

	pvStale := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pv-stale",
			CreationTimestamp: metav1.NewTime(now.Add(-48 * time.Hour)),
		},
		Spec:   corev1.PersistentVolumeSpec{StorageClassName: "ceph-block"},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeReleased},
	}
	pvYoung := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pv-young",
			CreationTimestamp: metav1.NewTime(now.Add(-12 * time.Hour)),
		},
		Spec:   corev1.PersistentVolumeSpec{StorageClassName: "ceph-block"},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeReleased},
	}
	pvTerminating := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pv-terminating",
			CreationTimestamp: metav1.NewTime(now.Add(-72 * time.Hour)),
			DeletionTimestamp: &metav1.Time{Time: now.Add(-time.Hour)},
		},
		Spec:   corev1.PersistentVolumeSpec{StorageClassName: "ceph-block"},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeReleased},
	}

	makeVS := func(name string, age time.Duration, ready bool, errObj map[string]any, terminating bool) *unstructured.Unstructured {
		meta := map[string]any{
			"namespace":         "apps",
			"name":              name,
			"creationTimestamp": now.Add(-age).UTC().Format(time.RFC3339),
		}
		if terminating {
			meta["deletionTimestamp"] = now.Add(-time.Minute).UTC().Format(time.RFC3339)
		}
		status := map[string]any{"readyToUse": ready}
		if errObj != nil {
			status["error"] = errObj
		}
		return &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "snapshot.storage.k8s.io/v1",
			"kind":       "VolumeSnapshot",
			"metadata":   meta,
			"status":     status,
		}}
	}

	vsFailed := makeVS("vs-failed", 3*time.Hour, false, map[string]any{"message": "snapshot error"}, false)
	vsReadyOK := makeVS("vs-ok", 3*time.Hour, true, nil, false)
	vsFresh := makeVS("vs-fresh", time.Hour, false, nil, false)
	vsTerminating := makeVS("vs-term", 5*time.Hour, false, nil, true)

	cs := fake.NewSimpleClientset(pvStale, pvYoung, pvTerminating)
	dyn := probetest.OpDyn(vsFailed, vsReadyOK, vsFresh, vsTerminating)
	p := testProberDyn(cs, dyn)
	chk := probetest.MustCheck[*pvcLifecycleGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, now)
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatal("expected failure for stale released PV and failed VolumeSnapshot")
	}
	if v, ok := pvReleasedStaleSeries(t, "pv-stale", "ceph-block"); !ok || v != 1 {
		t.Fatalf("missing pv_released_stale series: v=%v ok=%v", v, ok)
	}
	if _, ok := pvReleasedStaleSeries(t, "pv-young", "ceph-block"); ok {
		t.Fatal("young released PV must not flag")
	}
	if _, ok := pvReleasedStaleSeries(t, "pv-terminating", "ceph-block"); ok {
		t.Fatal("terminating released PV must be skipped")
	}
	if v, ok := volumeSnapshotFailedSeries(t, "apps", "vs-failed"); !ok || v != 1 {
		t.Fatalf("missing volumesnapshot_failed series: v=%v ok=%v", v, ok)
	}
	for _, name := range []string{"vs-ok", "vs-fresh", "vs-term"} {
		if _, ok := volumeSnapshotFailedSeries(t, "apps", name); ok {
			t.Fatalf("%s must not emit volumesnapshot_failed", name)
		}
	}

	// Next sweep: 403 on PVs carries pv-stale without failing; 404 on VolumeSnapshot prunes vs-failed.
	cs.PrependReactor("list", "persistentvolumes", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "persistentvolumes"}, "", errors.New("forbidden"))
	})
	dyn404 := probetest.OpDyn()
	dyn404.PrependReactor("list", "volumesnapshots", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewNotFound(schema.GroupResource{Group: "snapshot.storage.k8s.io", Resource: "volumesnapshots"}, "")
	})
	chk.Dyn = dyn404
	res403 := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if !res403.Pass || res403.Infra != nil {
		t.Fatalf("403/404 sweep must pass with nil Infra, got %+v", res403)
	}
	if _, ok := pvReleasedStaleSeries(t, "pv-stale", "ceph-block"); !ok {
		t.Fatal("403 on PVs should carry held pv-stale series")
	}
	if _, ok := volumeSnapshotFailedSeries(t, "apps", "vs-failed"); ok {
		t.Fatal("404 on VolumeSnapshot must prune stale series")
	}

	// Clean up held PV series.
	pvReleasedStaleGauge.DeleteLabelValues("pv-stale", "ceph-block")
}

func TestPVCLifecycleReleasedPVUsesLastPhaseTransitionTime(t *testing.T) {
	now := time.Now()
	t.Setenv("NODE_AUTOMATION_PV_RELEASED_MAX_AGE", "168h")

	// Long-lived PV created 720h ago, released only 5m ago -> MUST NOT flag.
	pvJustReleased := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pv-just-released",
			CreationTimestamp: metav1.NewTime(now.Add(-720 * time.Hour)),
		},
		Spec: corev1.PersistentVolumeSpec{StorageClassName: "ceph-block"},
		Status: corev1.PersistentVolumeStatus{
			Phase:                   corev1.VolumeReleased,
			LastPhaseTransitionTime: &metav1.Time{Time: now.Add(-5 * time.Minute)},
		},
	}

	// Long-lived PV created 720h ago, released 200h ago -> MUST flag.
	pvStaleTransition := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pv-stale-transition",
			CreationTimestamp: metav1.NewTime(now.Add(-720 * time.Hour)),
		},
		Spec: corev1.PersistentVolumeSpec{StorageClassName: "ceph-block"},
		Status: corev1.PersistentVolumeStatus{
			Phase:                   corev1.VolumeReleased,
			LastPhaseTransitionTime: &metav1.Time{Time: now.Add(-200 * time.Hour)},
		},
	}

	// Released PV with nil LastPhaseTransitionTime and CreationTimestamp 200h ago -> falls back and flags.
	pvNilTransition := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pv-nil-transition",
			CreationTimestamp: metav1.NewTime(now.Add(-200 * time.Hour)),
		},
		Spec: corev1.PersistentVolumeSpec{StorageClassName: "ceph-block"},
		Status: corev1.PersistentVolumeStatus{
			Phase:                   corev1.VolumeReleased,
			LastPhaseTransitionTime: nil,
		},
	}

	// Released PV with zero LastPhaseTransitionTime and CreationTimestamp 200h ago -> falls back and flags.
	pvZeroTransition := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pv-zero-transition",
			CreationTimestamp: metav1.NewTime(now.Add(-200 * time.Hour)),
		},
		Spec: corev1.PersistentVolumeSpec{StorageClassName: "ceph-block"},
		Status: corev1.PersistentVolumeStatus{
			Phase:                   corev1.VolumeReleased,
			LastPhaseTransitionTime: &metav1.Time{},
		},
	}

	cs := fake.NewSimpleClientset(pvJustReleased, pvStaleTransition, pvNilTransition, pvZeroTransition)
	p := testProber(cs)
	chk := probetest.MustCheck[*pvcLifecycleGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, now)
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass || res.Infra != nil {
		t.Fatalf("expected failure with nil Infra for stale Released PVs, got %+v", res)
	}
	if _, ok := pvReleasedStaleSeries(t, "pv-just-released", "ceph-block"); ok {
		t.Fatal("PV released 5m ago (LastPhaseTransitionTime=-5m, CreationTimestamp=-720h) must NOT flag pv_released_stale")
	}
	if v, ok := pvReleasedStaleSeries(t, "pv-stale-transition", "ceph-block"); !ok || v != 1 {
		t.Fatalf("PV with LastPhaseTransitionTime=-200h must flag pv_released_stale=1, got v=%v ok=%v", v, ok)
	}
	if v, ok := pvReleasedStaleSeries(t, "pv-nil-transition", "ceph-block"); !ok || v != 1 {
		t.Fatalf("PV with nil LastPhaseTransitionTime and CreationTimestamp=-200h must flag pv_released_stale=1, got v=%v ok=%v", v, ok)
	}
	if v, ok := pvReleasedStaleSeries(t, "pv-zero-transition", "ceph-block"); !ok || v != 1 {
		t.Fatalf("PV with zero LastPhaseTransitionTime and CreationTimestamp=-200h must flag pv_released_stale=1, got v=%v ok=%v", v, ok)
	}

	// Delete the stale PVs leaving only pv-just-released -> check must pass and prune stale series.
	_ = cs.CoreV1().PersistentVolumes().Delete(ctx, "pv-stale-transition", metav1.DeleteOptions{})
	_ = cs.CoreV1().PersistentVolumes().Delete(ctx, "pv-nil-transition", metav1.DeleteOptions{})
	_ = cs.CoreV1().PersistentVolumes().Delete(ctx, "pv-zero-transition", metav1.DeleteOptions{})
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass || res.Infra != nil {
		t.Fatalf("sweep with only pv-just-released must pass with nil Infra, got %+v", res)
	}
	for _, pvName := range []string{"pv-just-released", "pv-stale-transition", "pv-nil-transition", "pv-zero-transition"} {
		if _, ok := pvReleasedStaleSeries(t, pvName, "ceph-block"); ok {
			t.Fatalf("expected pv_released_stale series for %s to be absent/pruned", pvName)
		}
	}
}

func TestPVCLifecycleSkipsPodListOnEmptyCluster(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("pods must not be listed when no Pending/Bound PVC exists")
	})
	p := testProber(cs)
	chk := probetest.MustCheck[*pvcLifecycleGuardCheck](t, p)
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if !res.Pass || res.Infra != nil {
		t.Fatalf("empty cluster must pass without touching pods: %+v", res)
	}
}
