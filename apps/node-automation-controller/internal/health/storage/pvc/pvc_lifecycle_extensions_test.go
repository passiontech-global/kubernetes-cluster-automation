package pvc

import (
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func TestPVCLifecycleDefaultStorageClassAnomalies(t *testing.T) {
	t.Run("zero_defaults_and_multiple_defaults_emit_and_prune", func(t *testing.T) {
		t.Cleanup(func() {
			storageClassDefaultAnomalyGauge.DeleteLabelValues("zero_defaults")
			storageClassDefaultAnomalyGauge.DeleteLabelValues("multiple_defaults")
		})
		scA := &storagev1.StorageClass{ObjectMeta: metav1.ObjectMeta{Name: "sc-a"}, Provisioner: "ebs.csi"}
		scB := &storagev1.StorageClass{ObjectMeta: metav1.ObjectMeta{Name: "sc-b"}, Provisioner: "ceph.csi"}
		cs := fake.NewSimpleClientset(scA, scB)
		p := testProber(cs)
		chk := probetest.MustCheck[*pvcLifecycleGuardCheck](t, p)

		res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		if !res.Pass {
			t.Fatalf("passive default SC anomaly should not fail Pass, got %+v", res)
		}
		if v, ok := testutil.GaugeSeriesValue(t, "node_automation_storageclass_default_anomaly", map[string]string{"reason": "zero_defaults"}); !ok || v != 1 {
			t.Fatalf("zero_defaults = (%v, %v), want (1, true)", v, ok)
		}

		scA.Annotations = map[string]string{"storageclass.kubernetes.io/is-default-class": "true"}
		scB.Annotations = map[string]string{"storageclass.kubernetes.io/is-default-class": "true"}
		_, _ = cs.StorageV1().StorageClasses().Update(ctx, scA, metav1.UpdateOptions{})
		_, _ = cs.StorageV1().StorageClasses().Update(ctx, scB, metav1.UpdateOptions{})
		_ = chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		if _, ok := testutil.GaugeSeriesValue(t, "node_automation_storageclass_default_anomaly", map[string]string{"reason": "zero_defaults"}); ok {
			t.Fatal("stale zero_defaults gauge not pruned")
		}
		if v, ok := testutil.GaugeSeriesValue(t, "node_automation_storageclass_default_anomaly", map[string]string{"reason": "multiple_defaults"}); !ok || v != 1 {
			t.Fatalf("multiple_defaults = (%v, %v), want (1, true)", v, ok)
		}

		scB.Annotations = nil
		_, _ = cs.StorageV1().StorageClasses().Update(ctx, scB, metav1.UpdateOptions{})
		_ = chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		if _, ok := testutil.GaugeSeriesValue(t, "node_automation_storageclass_default_anomaly", map[string]string{"reason": "multiple_defaults"}); ok {
			t.Fatal("stale multiple_defaults gauge not pruned")
		}
	})
}

func TestPVCLifecycleRWORollingUpdateDeadlockAndOptInHeal(t *testing.T) {
	now := time.Now()
	t.Cleanup(func() {
		rwoRollingUpdateDeadlockGauge.DeleteLabelValues("apps", "stateful-api", "data-0")
	})

	scDefault := &storagev1.StorageClass{
		ObjectMeta:  metav1.ObjectMeta{Name: "fast", Annotations: map[string]string{"storageclass.kubernetes.io/is-default-class": "true"}},
		Provisioner: "rbd.csi",
	}
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-1"},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{
			{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
		}},
	}
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "stateful-api"},
		Spec: appsv1.DeploymentSpec{
			Strategy: appsv1.DeploymentStrategy{Type: appsv1.RollingUpdateDeploymentStrategyType},
		},
	}
	rsOld := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "stateful-api-old",
			OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "stateful-api"}},
		},
	}
	rsNew := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "stateful-api-new",
			OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "stateful-api"}},
		},
	}
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "data-0"},
		Spec:       corev1.PersistentVolumeClaimSpec{AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}},
		Status:     corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound},
	}
	oldPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "stateful-api-old-0", UID: "uid-old",
			CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Hour)),
			OwnerReferences:   []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "stateful-api-old"}},
		},
		Spec: corev1.PodSpec{
			NodeName: "worker-1",
			Volumes: []corev1.Volume{{
				Name:         "data",
				VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "data-0"}},
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	newPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "stateful-api-new-0", UID: "uid-new",
			CreationTimestamp: metav1.NewTime(now.Add(-20 * time.Minute)),
			OwnerReferences:   []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "stateful-api-new"}},
		},
		Spec: corev1.PodSpec{
			NodeName: "worker-2",
			Volumes: []corev1.Volume{{
				Name:         "data",
				VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "data-0"}},
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodPending},
	}
	ev := &corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{Namespace: "apps", Name: "ev-multiattach"},
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Namespace: "apps", Name: "stateful-api-new-0"},
		Reason:         "FailedAttachVolume",
		Message:        "Multi-Attach error for volume \"pvc-data-0\" Volume is already used by pod(s) stateful-api-old-0",
		FirstTimestamp: metav1.NewTime(now.Add(-15 * time.Minute)),
	}

	// Default: detect-only (no pod deletion).
	cs := fake.NewSimpleClientset(scDefault, node, dep, rsOld, rsNew, pvc, oldPod, newPod, ev)
	p := testProber(cs)
	probetest.FreezeNow(p.Deps, now)
	chk := probetest.MustCheck[*pvcLifecycleGuardCheck](t, p)
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatalf("expected RWO deadlock failure, got %+v", res)
	}
	if v, ok := testutil.GaugeSeriesValue(t, "node_automation_rwo_rollingupdate_deadlock", map[string]string{
		"namespace": "apps", "deployment": "stateful-api", "pvc": "data-0",
	}); !ok || v != 1 {
		t.Fatalf("rwo_rollingupdate_deadlock = (%v, %v), want (1, true)", v, ok)
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "stateful-api-old-0", metav1.GetOptions{}); err != nil {
		t.Fatalf("default detect-only must not delete old pod: %v", err)
	}

	// Opt-in heal enabled: UID-deletes oldPod.
	t.Setenv("NODE_AUTOMATION_RWO_DEADLOCK_HEAL_ENABLED", "true")
	p2 := testProber(cs)
	probetest.FreezeNow(p2.Deps, now)
	chk2 := probetest.MustCheck[*pvcLifecycleGuardCheck](t, p2)
	_ = chk2.Run(probetest.SweepCtx(ctx, chk2.Deps))
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "stateful-api-old-0", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("expected old pod deleted under opt-in heal, got err=%v", err)
	}
}

func TestPVCLifecycleCSINodeVolumePressureAndOptInTaint(t *testing.T) {
	now := time.Now()
	t.Cleanup(func() {
		csiVolumePressureGauge.DeleteLabelValues("worker-csi", "ebs.csi.aws.com")
	})

	scDefault := &storagev1.StorageClass{
		ObjectMeta:  metav1.ObjectMeta{Name: "fast", Annotations: map[string]string{"storageclass.kubernetes.io/is-default-class": "true"}},
		Provisioner: "ebs.csi.aws.com",
	}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-csi"}}
	csiNode := &storagev1.CSINode{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-csi"},
		Spec: storagev1.CSINodeSpec{
			Drivers: []storagev1.CSINodeDriver{{
				Name:        "ebs.csi.aws.com",
				NodeID:      "i-123",
				Allocatable: &storagev1.VolumeNodeResources{Count: ptr.To(int32(10))},
			}},
		},
	}
	cs := fake.NewSimpleClientset(scDefault, node, csiNode)
	for i := range 9 {
		_, err := cs.StorageV1().VolumeAttachments().Create(ctx, &storagev1.VolumeAttachment{
			ObjectMeta: metav1.ObjectMeta{Name: "va-" + string(rune('a'+i))},
			Spec: storagev1.VolumeAttachmentSpec{
				Attacher: "ebs.csi.aws.com",
				NodeName: "worker-csi",
			},
		}, metav1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}

	// Default: detect-only, no taint.
	p := testProber(cs)
	probetest.FreezeNow(p.Deps, now)
	chk := probetest.MustCheck[*pvcLifecycleGuardCheck](t, p)
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatalf("expected csinode volume pressure failure at 9/10 (90%%), got %+v", res)
	}
	if v, ok := testutil.GaugeSeriesValue(t, "node_automation_csinode_volume_pressure", map[string]string{
		"node": "worker-csi", "driver": "ebs.csi.aws.com",
	}); !ok || v != 1 {
		t.Fatalf("csinode_volume_pressure = (%v, %v), want (1, true)", v, ok)
	}
	gotNode, _ := cs.CoreV1().Nodes().Get(ctx, "worker-csi", metav1.GetOptions{})
	if kube.HasTaint(gotNode.Spec.Taints, csiVolumePressureTaint) {
		t.Fatal("default detect-only must not taint node")
	}

	// Opt-in taint enabled: adds PreferNoSchedule taint.
	t.Setenv("NODE_AUTOMATION_CSINODE_TAINT_ENABLED", "true")
	p2 := testProber(cs)
	probetest.FreezeNow(p2.Deps, now)
	chk2 := probetest.MustCheck[*pvcLifecycleGuardCheck](t, p2)
	_ = chk2.Run(probetest.SweepCtx(ctx, chk2.Deps))
	gotNode, _ = cs.CoreV1().Nodes().Get(ctx, "worker-csi", metav1.GetOptions{})
	if !kube.HasTaint(gotNode.Spec.Taints, csiVolumePressureTaint) {
		t.Fatalf("expected PreferNoSchedule taint %s when opt-in enabled, got %v", csiVolumePressureTaint, gotNode.Spec.Taints)
	}
}
