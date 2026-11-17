// hpa_scaling_guard_test.go — coverage for the hpa-scaling-guard
// check: the 15-minute unhealthy-condition persistence window, the
// gauge reasons, the cold-start zero-target rescue, the
// intentionally-downscaled veto, and the metrics-server bounce
// shape (needs BOTH a ready and an unready member).
package gitops

import (
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
)

// hpaObj builds an autoscaling/v2 HPA with the given conditions
// and scale target.
func hpaObj(ns, name, targetKind, targetName string,
	conds ...map[string]string) *unstructured.Unstructured {

	var clist []any
	for _, c := range conds {
		clist = append(clist, map[string]any{
			"type":   c["type"],
			"status": c["status"],
			"reason": c["reason"],
		})
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "autoscaling/v2",
		"kind":       "HorizontalPodAutoscaler",
		"metadata":   map[string]any{"namespace": ns, "name": name},
		"spec": map[string]any{
			"minReplicas": int64(1),
			"scaleTargetRef": map[string]any{
				"apiVersion": "apps/v1",
				"kind":       targetKind,
				"name":       targetName,
			},
		},
		"status": map[string]any{"conditions": clist},
	}}
}

// hpaDeps splits fixtures across the two fakes: unstructured HPAs
// ride the dynamic client (the check's GVR path), typed workloads
// ride the clientset.
func hpaDeps(objs ...runtime.Object) (*fake.Clientset, *hpaScalingGuardCheck) {
	var typed []runtime.Object
	var unstr []runtime.Object
	for _, o := range objs {
		if _, ok := o.(*unstructured.Unstructured); ok {
			unstr = append(unstr, o)
		} else {
			typed = append(typed, o)
		}
	}
	cs := fake.NewSimpleClientset(typed...)
	d := probetest.NewDeps(cs, probetest.OpDyn(unstr...))
	return cs, &hpaScalingGuardCheck{Deps: d}
}

func TestHPAScalingGuardPersistenceWindow(t *testing.T) {
	hpa := hpaObj("apps", "web", "Deployment", "web",
		map[string]string{"type": "AbleToScale", "status": "False",
			"reason": "ScalingDisabled"})
	_, ch := hpaDeps(hpa)
	base := time.Now()

	probetest.FreezeNow(ch.Deps, base)
	if res := ch.Run(probetest.SweepCtx(ctx)); !res.Pass {
		t.Fatalf("first sighting arms the window, must pass: %+v", res)
	}
	probetest.FreezeNow(ch.Deps, base.Add(hpaUnhealthyMinAge-time.Minute))
	ch.Run(probetest.SweepCtx(ctx))
	probetest.FreezeNow(ch.Deps, base.Add(hpaUnhealthyMinAge+time.Minute))
	res := ch.Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatal("unhealthy HPA past the window must flag")
	}
	m := probetest.FindMetric(t, "node_automation_hpa_scaling_unhealthy",
		map[string]string{"namespace": "apps", "name": "web",
			"reason": "able_to_scale_false"})
	if m == nil {
		t.Fatal("able_to_scale_false gauge missing")
	}
}

func TestHPAScalingGuardHealthyPasses(t *testing.T) {
	hpa := hpaObj("apps", "ok", "Deployment", "ok",
		map[string]string{"type": "AbleToScale", "status": "True"},
		map[string]string{"type": "ScalingActive", "status": "True"})
	_, ch := hpaDeps(hpa)
	if res := ch.Run(probetest.SweepCtx(ctx)); !res.Pass {
		t.Fatalf("healthy HPA must pass: %+v", res)
	}
}

func TestHPAScalingGuardColdStartRescue(t *testing.T) {
	// HPA unhealthy past the window + its Deployment wedged at
	// replicas=0 → the rescue lifts it to minReplicas (1).
	hpa := hpaObj("apps", "cold", "Deployment", "cold",
		map[string]string{"type": "AbleToScale", "status": "False",
			"reason": "ScalingDisabled"})
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "cold"},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(int32(0)),
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "cold"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "cold"}},
			},
		},
	}
	cs, ch := hpaDeps(hpa, dep)
	base := time.Now()
	probetest.FreezeNow(ch.Deps, base)
	ch.Run(probetest.SweepCtx(ctx))
	probetest.FreezeNow(ch.Deps, base.Add(hpaUnhealthyMinAge+time.Minute))
	ch.Run(probetest.SweepCtx(ctx))
	got, err := cs.AppsV1().Deployments("apps").Get(ctx, "cold", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get deployment: %v", err)
	}
	if got.Spec.Replicas == nil || *got.Spec.Replicas != 1 {
		t.Fatalf("rescued replicas=%v want 1 (minReplicas floor)",
			got.Spec.Replicas)
	}
}

func TestHPAScalingGuardRescueSkipsIntentionalZero(t *testing.T) {
	// The downscaler parked the target at 0 — the rescue must NOT
	// resurrect it (IsIntentionallyDownscaled veto).
	hpa := hpaObj("apps", "asleep", "Deployment", "asleep",
		map[string]string{"type": "AbleToScale", "status": "False",
			"reason": "ScalingDisabled"})
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "asleep",
			Annotations: map[string]string{
				"downscaler/uptime": "Mon-Fri 08:00-20:00",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(int32(0)),
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "asleep"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "asleep"}},
			},
		},
	}
	cs, ch := hpaDeps(hpa, dep)
	base := time.Now()
	probetest.FreezeNow(ch.Deps, base)
	ch.Run(probetest.SweepCtx(ctx))
	probetest.FreezeNow(ch.Deps, base.Add(hpaUnhealthyMinAge+time.Minute))
	ch.Run(probetest.SweepCtx(ctx))
	got, _ := cs.AppsV1().Deployments("apps").Get(ctx, "asleep", metav1.GetOptions{})
	if *got.Spec.Replicas != 0 {
		t.Fatalf("rescue resurrected an intentionally-downscaled target: %d",
			*got.Spec.Replicas)
	}
}

func TestHPAScalingGuardBouncesIsolatedUnreadyMetricsServer(t *testing.T) {
	hpa := hpaObj("apps", "api", "Deployment", "api",
		map[string]string{"type": "ScalingActive", "status": "False",
			"reason": "FailedGetResourceMetric"})
	ctrl := true
	rsOwner := metav1.OwnerReference{
		APIVersion: "apps/v1", Kind: "ReplicaSet",
		Name: "metrics-server-abc", UID: "rs-ms", Controller: &ctrl,
	}
	msReady := probetest.PodWithPhase("kube-system", "metrics-server-ready", corev1.PodRunning, true, time.Hour)
	msReady.OwnerReferences = []metav1.OwnerReference{rsOwner}
	msBad1 := probetest.PodWithPhase("kube-system", "metrics-server-bad-1", corev1.PodRunning, false, time.Hour)
	msBad1.OwnerReferences = []metav1.OwnerReference{rsOwner}
	msBad2 := probetest.PodWithPhase("kube-system", "metrics-server-bad-2", corev1.PodRunning, false, time.Hour)
	msBad2.OwnerReferences = []metav1.OwnerReference{rsOwner}

	cs, ch := hpaDeps(hpa, msReady, msBad1, msBad2)
	base := time.Now()
	probetest.FreezeNow(ch.Deps, base)
	ch.Run(probetest.SweepCtx(ctx))
	probetest.FreezeNow(ch.Deps, base.Add(hpaUnhealthyMinAge+time.Minute))
	ch.Run(probetest.SweepCtx(ctx))

	// Only one unready metrics-server pod should be deleted per sweep (sorted: bad-1).
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, "metrics-server-bad-1", metav1.GetOptions{}); err == nil {
		t.Fatal("expected first unready metrics-server pod to be bounced")
	}
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, "metrics-server-bad-2", metav1.GetOptions{}); err != nil {
		t.Fatalf("second unready metrics-server pod should wait for cooldown: %v", err)
	}
}
