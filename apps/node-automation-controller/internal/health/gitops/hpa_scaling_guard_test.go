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
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
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
	if res := ch.Run(probetest.SweepCtx(ctx, ch.Deps)); !res.Pass {
		t.Fatalf("first sighting arms the window, must pass: %+v", res)
	}
	probetest.FreezeNow(ch.Deps, base.Add(hpaUnhealthyMinAge-time.Minute))
	ch.Run(probetest.SweepCtx(ctx, ch.Deps))
	probetest.FreezeNow(ch.Deps, base.Add(hpaUnhealthyMinAge+time.Minute))
	res := ch.Run(probetest.SweepCtx(ctx, ch.Deps))
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
	if res := ch.Run(probetest.SweepCtx(ctx, ch.Deps)); !res.Pass {
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
	ch.Run(probetest.SweepCtx(ctx, ch.Deps))
	probetest.FreezeNow(ch.Deps, base.Add(hpaUnhealthyMinAge+time.Minute))
	ch.Run(probetest.SweepCtx(ctx, ch.Deps))
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
	ch.Run(probetest.SweepCtx(ctx, ch.Deps))
	probetest.FreezeNow(ch.Deps, base.Add(hpaUnhealthyMinAge+time.Minute))
	ch.Run(probetest.SweepCtx(ctx, ch.Deps))
	got, _ := cs.AppsV1().Deployments("apps").Get(ctx, "asleep", metav1.GetOptions{})
	if *got.Spec.Replicas != 0 {
		t.Fatalf("rescue resurrected an intentionally-downscaled target: %d",
			*got.Spec.Replicas)
	}
}

// spec.replicas is Git-owned on Flux-managed workloads — a rescue
// that fights Flux every sweep is exactly the Heal-Revert Loop the
// shared gate exists to stop.
func TestHPARescueRespectsFluxConflictGate(t *testing.T) {
	heal.ConfigureFluxConflictLoop(3, 30*time.Minute)
	t.Cleanup(func() { heal.ConfigureFluxConflictLoop(0, 0) })
	hpa := hpaObj("apps", "flux-cold", "Deployment", "flux-cold",
		map[string]string{"type": "AbleToScale", "status": "False",
			"reason": "ScalingDisabled"})
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "flux-cold",
			ManagedFields: []metav1.ManagedFieldsEntry{{
				Manager: "kustomize-controller", Operation: metav1.ManagedFieldsOperationApply,
			}},
		},
		Spec: appsv1.DeploymentSpec{Replicas: ptr.To(int32(0))},
	}
	cs, ch := hpaDeps(hpa, dep)
	base := time.Now()
	// Arm the gate: two allowed sightings, so the rescue's own call
	// is the third (denied) one.
	heal.FluxPatchGate("deployment", dep, "apps/flux-cold", base)
	heal.FluxPatchGate("deployment", dep, "apps/flux-cold", base)
	probetest.FreezeNow(ch.Deps, base)
	ch.Run(probetest.SweepCtx(ctx, ch.Deps))
	probetest.FreezeNow(ch.Deps, base.Add(hpaUnhealthyMinAge+time.Minute))
	ch.Run(probetest.SweepCtx(ctx, ch.Deps))
	got, _ := cs.AppsV1().Deployments("apps").Get(ctx, "flux-cold", metav1.GetOptions{})
	if got.Spec.Replicas == nil || *got.Spec.Replicas != 0 {
		t.Fatalf("flux-gated rescue must not patch replicas, got %v",
			got.Spec.Replicas)
	}
}

// A metrics-server pod that is still starting, or already terminal,
// must never be bounced as an "isolated unready sibling".
func TestHPABounceSkipsYoungAndTerminalPods(t *testing.T) {
	hpa := hpaObj("apps", "ms-api", "Deployment", "api",
		map[string]string{"type": "ScalingActive", "status": "False",
			"reason": "FailedGetResourceMetric"})
	ctrl := true
	owner := metav1.OwnerReference{
		APIVersion: "apps/v1", Kind: "ReplicaSet",
		Name: "metrics-server-abc", UID: "rs-ms", Controller: &ctrl,
	}
	ready := probetest.PodWithPhase("kube-system", "metrics-server-ready",
		corev1.PodRunning, true, time.Hour)
	ready.OwnerReferences = []metav1.OwnerReference{owner}
	base := time.Now()
	young := probetest.PodWithPhase("kube-system", "metrics-server-young",
		corev1.PodRunning, false, time.Minute)
	// Anchor to the frozen clock: the second sweep is 16m later, so
	// a system-time age would look like a long unready streak.
	young.Status.Conditions[0].LastTransitionTime = metav1.NewTime(
		base.Add(hpaUnhealthyMinAge)) // 1m before the second sweep's frozen now
	young.OwnerReferences = []metav1.OwnerReference{owner}
	terminal := probetest.PodWithPhase("kube-system", "metrics-server-done",
		corev1.PodFailed, false, time.Hour)
	terminal.OwnerReferences = []metav1.OwnerReference{owner}
	cs, ch := hpaDeps(hpa, ready, young, terminal)
	probetest.FreezeNow(ch.Deps, base)
	ch.Run(probetest.SweepCtx(ctx, ch.Deps))
	probetest.FreezeNow(ch.Deps, base.Add(hpaUnhealthyMinAge+time.Minute))
	ch.Run(probetest.SweepCtx(ctx, ch.Deps))
	for _, name := range []string{"metrics-server-young", "metrics-server-done"} {
		if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, name, metav1.GetOptions{}); err != nil {
			t.Fatalf("%s must not be bounced: %v", name, err)
		}
	}
}

// A fleet-wide HPA signature must not spend the shared heal budget
// on every action in one sweep: once a cold-start rescue has kept a
// grant, the remaining rescues AND the metrics-server bounce defer
// to the next pass (the budget itself still has room here, so this
// pins the check-local cap, not the global limiter).
func TestHPAAtMostOneBudgetedActionPerSweep(t *testing.T) {
	heal.ConfigureBudget(4, time.Hour)
	t.Cleanup(func() { heal.ConfigureBudget(0, 0) })

	unhealthy := func(name, target string) *unstructured.Unstructured {
		return hpaObj("apps", name, "Deployment", target,
			map[string]string{"type": "ScalingActive", "status": "False",
				"reason": "FailedGetResourceMetric"})
	}
	zeroDep := func(name string) *appsv1.Deployment {
		return &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: name},
			Spec: appsv1.DeploymentSpec{
				Replicas: ptr.To(int32(0)),
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": name}},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
				},
			},
		}
	}
	ctrl := true
	owner := metav1.OwnerReference{
		APIVersion: "apps/v1", Kind: "ReplicaSet",
		Name: "metrics-server-abc", UID: "rs-ms", Controller: &ctrl,
	}
	msReady := probetest.PodWithPhase("kube-system", "metrics-server-r",
		corev1.PodRunning, true, time.Hour)
	msReady.OwnerReferences = []metav1.OwnerReference{owner}
	msBad := probetest.PodWithPhase("kube-system", "metrics-server-bad",
		corev1.PodRunning, false, time.Hour)
	msBad.OwnerReferences = []metav1.OwnerReference{owner}

	cs, ch := hpaDeps(unhealthy("cold-a", "dep-a"), unhealthy("cold-b", "dep-b"),
		zeroDep("dep-a"), zeroDep("dep-b"), msReady, msBad)
	base := time.Now()
	probetest.FreezeNow(ch.Deps, base)
	ch.Run(probetest.SweepCtx(ctx, ch.Deps))
	probetest.FreezeNow(ch.Deps, base.Add(hpaUnhealthyMinAge+time.Minute))
	ch.Run(probetest.SweepCtx(ctx, ch.Deps))

	rescued := 0
	for _, name := range []string{"dep-a", "dep-b"} {
		got, err := cs.AppsV1().Deployments("apps").Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if got.Spec.Replicas != nil && *got.Spec.Replicas == 1 {
			rescued++
		}
	}
	if rescued != 1 {
		t.Fatalf("rescued %d targets in one sweep, want at most 1", rescued)
	}
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, msBad.Name,
		metav1.GetOptions{}); err != nil {
		t.Fatalf("metrics-server bounce must defer to the next sweep: %v", err)
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
	ch.Run(probetest.SweepCtx(ctx, ch.Deps))
	probetest.FreezeNow(ch.Deps, base.Add(hpaUnhealthyMinAge+time.Minute))
	ch.Run(probetest.SweepCtx(ctx, ch.Deps))

	// Only one unready metrics-server pod should be deleted per sweep (sorted: bad-1).
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, "metrics-server-bad-1", metav1.GetOptions{}); err == nil {
		t.Fatal("expected first unready metrics-server pod to be bounced")
	}
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, "metrics-server-bad-2", metav1.GetOptions{}); err != nil {
		t.Fatalf("second unready metrics-server pod should wait for cooldown: %v", err)
	}
}
