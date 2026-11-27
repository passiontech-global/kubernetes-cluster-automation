// operator_watchdog_far_flux_test.go — coverage for the
// fence-agents-remediation-operator v0.8.0 lease/stuck-remediation
// detection and the flux-operator target row.
package watchdogs

import (
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func TestFARWatchdogLeaseAndStuckRemediation(t *testing.T) {
	tgt := operatorTargetByName(t, "fence-agents-remediation-operator")
	if len(tgt.leaseNames) < 2 || tgt.leaseNames[0] != "cb305759.medik8s.io" {
		t.Fatalf("FAR leaseNames = %v, want v0.8.0 cb305759.medik8s.io first", tgt.leaseNames)
	}

	// Terminating FAR CR with populated status must trigger farRemediationStuck.
	now := metav1.NewTime(time.Now())
	termFAR := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "fence-agents-remediation.medik8s.io/v1alpha1",
		"kind":       "FenceAgentsRemediation",
		"status": map[string]any{
			"conditions": []any{
				map[string]any{"type": "Processing", "status": "True"},
				map[string]any{"type": "Succeeded", "status": "Unknown"},
			},
		},
	}}
	termFAR.SetNamespace("operators")
	termFAR.SetName("worker-03-dwblc")
	termFAR.SetDeletionTimestamp(&now)
	if !farRemediationStuck(termFAR) {
		t.Fatal("terminating FAR CR with populated status must read stuck")
	}

	// NHC timed-out FAR CR without Succeeded=True must read stuck.
	timedOut := &unstructured.Unstructured{Object: map[string]any{
		"status": map[string]any{
			"conditions": []any{
				map[string]any{"type": "Succeeded", "status": "Unknown"},
			},
		},
	}}
	timedOut.SetAnnotations(map[string]string{
		"remediation.medik8s.io/nhc-timed-out": "2026-11-27T12:14:55Z",
	})
	if !farRemediationStuck(timedOut) {
		t.Fatal("nhc-timed-out FAR CR without Succeeded=True must read stuck")
	}

	// NHC timed-out FAR CR that already Succeeded=True is not stuck.
	succeeded := &unstructured.Unstructured{Object: map[string]any{
		"status": map[string]any{
			"conditions": []any{
				map[string]any{"type": "Succeeded", "status": "True"},
			},
		},
	}}
	succeeded.SetAnnotations(map[string]string{
		"remediation.medik8s.io/nhc-timed-out": "2026-11-27T12:14:55Z",
	})
	if farRemediationStuck(succeeded) {
		t.Fatal("Succeeded=True FAR CR must not read stuck")
	}

	// End-to-end: FAR renewing v0.8.0 lease cb305759.medik8s.io + terminating CR
	// past stuckMinAge (and past maintenance mutex 90m horizon) flags
	// stuck_remediation and bounces the leader pod.
	base := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	termFAR.SetCreationTimestamp(metav1.NewTime(base.Add(-2 * time.Hour)))
	farPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "operators",
			Name:      "fence-agents-remediation-controller-manager-abc",
			UID:       "far-uid-1",
			Labels:    map[string]string{"app.kubernetes.io/name": "fence-agents-remediation-operator"},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "far-rs", UID: "far-rs-uid",
				Controller: ptr.To(true),
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	farLease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Namespace: "operators", Name: "cb305759.medik8s.io"},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity: ptr.To(farPod.Name + "_uuid"),
			RenewTime:      &metav1.MicroTime{Time: base},
		},
	}
	cs := fake.NewSimpleClientset(farPod, farLease)
	dyn := testutil.NewDynamicClient(termFAR)
	p := testProberDyn(cs, dyn)
	p.Now = func() time.Time { return base }
	chk := probetest.MustCheck[*operatorWorkqueueCheck](t, p)

	// First sweep arms first-seen; second sweep past stuckMinAge freezes + bounces leader.
	_ = chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	after := base.Add(operatorStuckMinAge + time.Minute)
	farLease.Spec.RenewTime = &metav1.MicroTime{Time: after}
	if _, err := cs.CoordinationV1().Leases("operators").Update(ctx, farLease, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	p.Now = func() time.Time { return after }
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatal("wedged terminating FAR CR must fail operator-workqueue-watchdog")
	}
	if testutil.PodExistsStrict(t, cs, "operators", farPod.Name) {
		t.Fatal("leader FAR pod was not deleted after stuck_remediation window")
	}
}

func TestFluxOperatorWatchdogTargetAndPlaceholderLease(t *testing.T) {
	tgt := operatorTargetByName(t, "flux-operator")
	if !tgt.leaseOptional || tgt.leaseNS != "flux-system" {
		t.Fatalf("unexpected flux-operator row: %+v", tgt)
	}

	// Reconcile-disabled annotation parks the object cleanly.
	disabled := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "fluxcd.controlplane.io/v1",
		"kind":       "ResourceSet",
		"metadata": map[string]any{
			"generation":  int64(3),
			"annotations": map[string]any{"fluxcd.controlplane.io/reconcile": "disabled"},
		},
		"status": map[string]any{"observedGeneration": int64(1)},
	}}
	if fluxOperatorStaleGen(disabled) {
		t.Fatal("reconcile=disabled ResourceSet must not read stuck")
	}

	// Active ResourceSet with stale observedGeneration + unheld placeholder Lease
	// falls back to Running pod liveness and bounces flux-operator past window.
	base := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	foPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "flux-system",
			Name:      "flux-operator-8b5fcd696-gswtc",
			UID:       "fo-uid-1",
			Labels:    map[string]string{"app.kubernetes.io/name": "flux-operator"},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "fo-rs", UID: "fo-rs-uid",
				Controller: ptr.To(true),
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	// Placeholder Lease with empty HolderIdentity and nil RenewTime (exact live shape).
	placeholderLease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Namespace: "flux-system", Name: "flux-operator"},
	}
	staleRSet := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "fluxcd.controlplane.io/v1",
		"kind":       "ResourceSet",
		"metadata": map[string]any{
			"namespace":  "flux-system",
			"name":       "cluster-addons",
			"generation": int64(4),
		},
		"status": map[string]any{"observedGeneration": int64(2)},
	}}
	cs := fake.NewSimpleClientset(foPod, placeholderLease)
	dyn := testutil.NewDynamicClient(staleRSet)
	p := testProberDyn(cs, dyn)
	p.Now = func() time.Time { return base }
	chk := probetest.MustCheck[*operatorWorkqueueCheck](t, p)

	_ = chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	p.Now = func() time.Time { return base.Add(operatorStuckMinAge + time.Minute) }
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatal("stale ResourceSet with live flux-operator must fail check")
	}
	if testutil.PodExistsStrict(t, cs, "flux-system", foPod.Name) {
		t.Fatal("wedged flux-operator pod was not deleted via Running-pod fallback")
	}
	if tgt.resources[0].gvr != kube.GVRFluxInstance {
		t.Fatalf("first resource GVR = %v, want FluxInstance", tgt.resources[0].gvr)
	}
}
