package nethealth

import (
	"strings"
	"testing"
	"time"

	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
)

func TestServiceSelectorBlackholeZeroMatchAndPortMismatch(t *testing.T) {
	serviceBlackholeGauge.Reset()
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

	// 1. Headless Service whose selector matches 0 pods (typo in selector),
	//    nearest workload is Deployment/api with app=api.
	headless := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "api-headless", UID: "s1"},
		Spec: corev1.ServiceSpec{
			ClusterIP: corev1.ClusterIPNone,
			Selector:  map[string]string{"app": "api", "track": "typo"},
			Ports:     []corev1.ServicePort{{Port: 8080}},
		},
	}
	// 2. ClusterIP Service matching Ready Pod, but named targetPort="grpc" doesn't match Pod containerPort.name="http".
	portMismatch := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web-svc", UID: "s2"},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.96.0.20",
			Selector:  map[string]string{"app": "web"},
			Ports:     []corev1.ServicePort{{Port: 80, TargetPort: intstr.FromString("grpc")}},
		},
	}
	// 3. Intentionally scaled-to-zero Service -> must NOT trigger.
	zeroReplicas := int32(0)
	scaledZeroDep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "sleep"},
		Spec: appsv1.DeploymentSpec{
			Replicas: &zeroReplicas,
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "sleep"}}},
		},
	}
	scaledZeroSvc := clusterIPService("apps", "sleep-svc", map[string]string{"app": "sleep"})

	// 4. ExternalName & default/kubernetes -> must NOT trigger.
	extSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "ext-svc"},
		Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeExternalName, ExternalName: "example.com"},
	}
	k8sSvc := clusterIPService("default", "kubernetes", map[string]string{"component": "apiserver"})

	apiDep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "api"},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "api"}}},
		},
	}
	webPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web-0", Labels: map[string]string{"app": "web"}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name:  "web",
			Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}},
		}}},
		Status: corev1.PodStatus{
			Phase:      corev1.PodRunning,
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
		},
	}

	cs := fake.NewSimpleClientset(headless, portMismatch, scaledZeroDep, scaledZeroSvc, extSvc, k8sSvc, apiDep, webPod)
	p := testProber(cs)
	p.Now = func() time.Time { return now }
	chk := probetest.MustCheck[*serviceSelectorBlackholeCheck](t, p)

	// Sweep 1 (T=0): first seen -> Pass=true, no metrics yet.
	res1 := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if !res1.Pass {
		t.Fatalf("expected Pass before 10m persistence window, got %+v", res1)
	}

	// Sweep 2 (T+10m): both blackholes persist >=10m -> flagged + Events emitted.
	now = now.Add(10 * time.Minute)
	p.InvalidatePods(ctx)
	res2 := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res2.Pass {
		t.Fatalf("expected failure after >=10m blackhole")
	}
	if v := ptestutil.ToFloat64(serviceBlackholeGauge.WithLabelValues("apps", "api-headless", "selector_zero_match")); v != 1 {
		t.Fatalf("expected selector_zero_match=1 for headless service, got %v", v)
	}
	if v := ptestutil.ToFloat64(serviceBlackholeGauge.WithLabelValues("apps", "web-svc", "target_port_mismatch")); v != 1 {
		t.Fatalf("expected target_port_mismatch=1, got %v", v)
	}
	if v := ptestutil.ToFloat64(serviceBlackholeGauge.WithLabelValues("apps", "sleep-svc", "selector_zero_match")); v != 0 {
		t.Fatalf("scaled-to-zero workload must not fire blackhole, got %v", v)
	}

	evs, err := cs.EventsV1().Events("apps").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs.Items) != 2 {
		t.Fatalf("expected 2 Warning Events, got %d", len(evs.Items))
	}
	foundHint := false
	for _, ev := range evs.Items {
		if strings.Contains(ev.Note, "Deployment/api") {
			foundHint = true
		}
	}
	if !foundHint {
		t.Fatalf("expected nearest workload hint Deployment/api in Event note, got %+v", evs.Items)
	}
}

func TestServiceSelectorBlackholeArgoRolloutScaledZeroAndNativeSidecar(t *testing.T) {
	serviceBlackholeGauge.Reset()
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	ctrl := true

	// An Argo Rollout parked at zero has no Deployment — its RS is the
	// only workload the check can see.
	rolled := clusterIPService("apps", "rollout-svc", map[string]string{"app": "rollout"})
	zeroRS := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{
		Namespace: "apps", Name: "rollout-abc123",
		Labels:      map[string]string{"app": "rollout"},
		Annotations: map[string]string{annoRolloutDesiredReplicas: "0"},
		OwnerReferences: []metav1.OwnerReference{{
			Kind: "Rollout", Name: "rollout", APIVersion: "argoproj.io/v1alpha1", Controller: &ctrl,
		}},
	}}

	// A native sidecar owns the named targetPort; a Ready main
	// container alone must not be read as a port mismatch.
	sideSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "sidecar-svc", UID: "s3"},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.96.0.30",
			Selector:  map[string]string{"app": "side"},
			Ports:     []corev1.ServicePort{{Port: 80, TargetPort: intstr.FromString("grpc")}},
		},
	}
	always := corev1.ContainerRestartPolicyAlways
	sidePod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "side-0", Labels: map[string]string{"app": "side"}},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}}}},
			InitContainers: []corev1.Container{{
				Name: "proxy", RestartPolicy: &always,
				Ports: []corev1.ContainerPort{{Name: "grpc", ContainerPort: 9090}},
			}},
		},
		Status: corev1.PodStatus{
			Phase:      corev1.PodRunning,
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
		},
	}

	cs := fake.NewSimpleClientset(rolled, zeroRS, sideSvc, sidePod)
	p := testProber(cs)
	p.Now = func() time.Time { return now }
	chk := probetest.MustCheck[*serviceSelectorBlackholeCheck](t, p)
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("unexpected finding: %+v", res)
	}
	now = now.Add(10 * time.Minute)
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("a parked Rollout / native sidecar must not be flagged: %+v", res)
	}
	for _, name := range []string{"rollout-svc", "sidecar-svc"} {
		if v := ptestutil.ToFloat64(serviceBlackholeGauge.WithLabelValues("apps", name, "selector_zero_match")); v != 0 {
			t.Errorf("%s selector_zero_match = %v, want 0", name, v)
		}
		if v := ptestutil.ToFloat64(serviceBlackholeGauge.WithLabelValues("apps", name, "target_port_mismatch")); v != 0 {
			t.Errorf("%s target_port_mismatch = %v, want 0", name, v)
		}
	}
}

// Argo leaves old revision ReplicaSets behind. If the parked Rollout's
// latest revision RS (desired-replicas=0) is outvoted by an older RS
// still carrying a stale "desired-replicas=1", the Service looks like
// a genuinely empty selector and fires a false blackhole. Only the
// highest revision per Rollout may represent current intent.
func TestServiceSelectorBlackholeOnlyLatestRolloutRevision(t *testing.T) {
	serviceBlackholeGauge.Reset()
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	ctrl := true
	owner := []metav1.OwnerReference{{
		Kind: "Rollout", Name: "rollout", APIVersion: "argoproj.io/v1alpha1", Controller: &ctrl,
	}}
	labels := map[string]string{"app": "rollout"}

	svc := clusterIPService("apps", "rollout-svc", labels)
	oldRS := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{
		Namespace: "apps", Name: "rollout-old", Labels: labels,
		Annotations: map[string]string{
			annoRolloutRevision:        "1",
			annoRolloutDesiredReplicas: "1", // stale — not actually running
		},
		OwnerReferences: owner,
	}}
	latestRS := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{
		Namespace: "apps", Name: "rollout-latest", Labels: labels,
		Annotations: map[string]string{
			annoRolloutRevision:        "2",
			annoRolloutDesiredReplicas: "0", // parked
		},
		OwnerReferences: owner,
	}}
	// A pod in the namespace keeps the Service in scope; it simply does
	// not match the selector (no EndpointSlices => 0 ready endpoints).
	otherPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "apps", Name: "other-0", Labels: map[string]string{"app": "other"},
	}}

	cs := fake.NewSimpleClientset(svc, oldRS, latestRS, otherPod)
	p := testProber(cs)
	p.Now = func() time.Time { return now }
	chk := probetest.MustCheck[*serviceSelectorBlackholeCheck](t, p)
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("T=0: %+v", res)
	}
	now = now.Add(10 * time.Minute)
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("parked Rollout must not be flagged: %+v", res)
	}
	if v := ptestutil.ToFloat64(serviceBlackholeGauge.WithLabelValues("apps", "rollout-svc", "selector_zero_match")); v != 0 {
		t.Fatalf("rollout-svc selector_zero_match = %v, want 0 — older revision RS skewed the verdict", v)
	}
}
