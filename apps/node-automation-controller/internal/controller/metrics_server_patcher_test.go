package controller

import (
	"errors"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// metricsServerDeploy builds the kube-system/metrics-server
// Deployment in the fully patched state; mutating any pinned field
// makes it drifted again.
func metricsServerDeploy() *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "metrics-server", Namespace: "kube-system",
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "metrics-server",
						Args: []string{
							"--cert-dir=/tmp",
							"--secure-port=10250",
							"--kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname",
							"--kubelet-use-node-status-port",
							"--metric-resolution=30s",
							"--kubelet-request-timeout=25s",
						},
						LivenessProbe:  &corev1.Probe{TimeoutSeconds: 5},
						ReadinessProbe: &corev1.Probe{TimeoutSeconds: 5},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("20m"),
								corev1.ResourceMemory: resource.MustParse("96Mi"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("200m"),
								corev1.ResourceMemory: resource.MustParse("384Mi"),
							},
						},
					}},
					TopologySpreadConstraints: []corev1.TopologySpreadConstraint{
						{
							MaxSkew:           1,
							TopologyKey:       "topology.kubernetes.io/zone",
							WhenUnsatisfiable: corev1.ScheduleAnyway,
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"k8s-app": "metrics-server"},
							},
						},
						{
							MaxSkew:           1,
							TopologyKey:       "kubernetes.io/hostname",
							WhenUnsatisfiable: corev1.ScheduleAnyway,
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"k8s-app": "metrics-server"},
							},
						},
					},
					Tolerations: metricsServerWantTolerations,
				},
			},
		},
	}
}

// metricsServerDeployBare is the k0s stack baseline: no spread
// constraints, 1s probe timeouts, stock resources and the wildcard
// Exists toleration that caused the drain treadmill.
func metricsServerDeployBare() *appsv1.Deployment {
	d := metricsServerDeploy()
	d.Spec.Template.Spec.TopologySpreadConstraints = nil
	d.Spec.Template.Spec.Tolerations = nil
	d.Spec.Template.Spec.Containers[0].LivenessProbe = &corev1.Probe{TimeoutSeconds: 1}
	d.Spec.Template.Spec.Containers[0].ReadinessProbe = &corev1.Probe{TimeoutSeconds: 1}
	d.Spec.Template.Spec.Containers[0].Resources = corev1.ResourceRequirements{}
	d.Spec.Template.Spec.Containers[0].Args = []string{
		"--cert-dir=/tmp", "--secure-port=4443",
		"--kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname",
	}
	return d
}

func getMetricsServerDeploy(t *testing.T, cs *fake.Clientset) *appsv1.Deployment {
	t.Helper()
	d, err := cs.AppsV1().Deployments("kube-system").
		Get(ctx, "metrics-server", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get metrics-server: %v", err)
	}
	return d
}

func TestMetricsServerNeedsPatch(t *testing.T) {
	mutate := func(fn func(*appsv1.Deployment)) *appsv1.Deployment {
		d := metricsServerDeploy()
		fn(d)
		return d
	}
	for _, tc := range []struct {
		name    string
		d       *appsv1.Deployment
		drifted bool
	}{
		{"k0s baseline", metricsServerDeployBare(), true},
		{"fully pinned", metricsServerDeploy(), false},
		{"missing metrics-server container", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Containers = nil
		}), true},
		{"kubelet-request-timeout arg missing", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Containers[0].Args =
				d.Spec.Template.Spec.Containers[0].Args[:5]
		}), true},
		{"nil liveness probe", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Containers[0].LivenessProbe = nil
		}), true},
		{"request memory drifted", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Containers[0].Resources.Requests[corev1.ResourceMemory] =
				resource.MustParse("64Mi")
		}), true},
		{"affinity back", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Affinity = &corev1.Affinity{}
		}), true},
		// The 2026-10-30 treadmill bug: a wildcard Exists toleration
		// (empty key) tolerates node.kubernetes.io/unschedulable too.
		{"wildcard toleration", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Tolerations = []corev1.Toleration{
				{Operator: corev1.TolerationOpExists},
			}
		}), true},
		{"not-ready toleration missing", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Tolerations = []corev1.Toleration{
				{Key: "node-role.kubernetes.io/control-plane",
					Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
			}
		}), true},
		{"hostname constraint missing", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.TopologySpreadConstraints =
				d.Spec.Template.Spec.TopologySpreadConstraints[:1]
		}), true},
		{"constraint turned hard", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.TopologySpreadConstraints[0].WhenUnsatisfiable =
				corev1.DoNotSchedule
		}), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := metricsServerNeedsPatch(tc.d); got != tc.drifted {
				t.Fatalf("metricsServerNeedsPatch=%v, want %v", got, tc.drifted)
			}
		})
	}
}

func TestMetricsServerPatcherAppliesPatch(t *testing.T) {
	cs := fake.NewSimpleClientset(metricsServerDeployBare())
	r := &metricsServerPatcher{cs: cs}
	res, err := r.Reconcile(ctx, reconcile.Request{})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter != 15*time.Minute {
		t.Fatalf("expected 15m requeue, got %s", res.RequeueAfter)
	}
	if metricsServerNeedsPatch(getMetricsServerDeploy(t, cs)) {
		t.Fatal("deployment still drifted after patch")
	}
	// The wildcard toleration must be gone for good.
	for _, tol := range getMetricsServerDeploy(t, cs).Spec.Template.Spec.Tolerations {
		if tol.Operator == corev1.TolerationOpExists && tol.Key == "" {
			t.Fatal("wildcard Exists toleration survived the patch")
		}
	}
}

func TestMetricsServerPatcherNoOpWhenCorrect(t *testing.T) {
	cs := fake.NewSimpleClientset(metricsServerDeploy())
	var patched bool
	forbidDeployPatch(cs, &patched)

	r := &metricsServerPatcher{cs: cs}
	res, err := r.Reconcile(ctx, reconcile.Request{})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if patched {
		t.Fatal("patched an already-correct Deployment")
	}
	if res.RequeueAfter != 15*time.Minute {
		t.Fatalf("expected 15m requeue, got %s", res.RequeueAfter)
	}
}

func TestMetricsServerPatcherMissingDeployment(t *testing.T) {
	cs := fake.NewSimpleClientset()
	r := &metricsServerPatcher{cs: cs}
	res, err := r.Reconcile(ctx, reconcile.Request{})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter != 15*time.Minute {
		t.Fatalf("expected 15m requeue, got %s", res.RequeueAfter)
	}
}

func TestMetricsServerPatcherGetError(t *testing.T) {
	cs := fake.NewSimpleClientset(metricsServerDeployBare())
	cs.PrependReactor("get", "deployments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	r := &metricsServerPatcher{cs: cs}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err == nil {
		t.Fatal("expected error when the deployment get fails")
	}
}

func TestMetricsServerPatcherPatchError(t *testing.T) {
	cs := fake.NewSimpleClientset(metricsServerDeployBare())
	cs.PrependReactor("patch", "deployments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})
	r := &metricsServerPatcher{cs: cs}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err == nil {
		t.Fatal("expected error when the drift patch fails")
	}
}

// Disabled must be a clean no-op — nothing registered, no error.
func TestSetupMetricsServerPatcherDisabled(t *testing.T) {
	m := newStubManager()
	if err := SetupMetricsServerPatcher(m, fake.NewSimpleClientset(), false); err != nil {
		t.Fatalf("disabled setup must return nil, got %v", err)
	}
	if len(m.added) != 0 {
		t.Fatalf("disabled module registered %d runnables, want 0", len(m.added))
	}
}

// The predicate pins ns/name on top of the shared Deployment
// informer — only kube-system/metrics-server may reconcile.
func TestSetupMetricsServerPatcherPredicate(t *testing.T) {
	p := forPredicate(t, func(m manager.Manager) error {
		return SetupMetricsServerPatcher(m, fake.NewSimpleClientset(), true)
	})
	ms := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Namespace: "kube-system", Name: "metrics-server"}}
	if !p.Create(event.CreateEvent{Object: ms}) {
		t.Fatal("metrics-server Deployment did not pass the predicate")
	}
	coredns := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Namespace: "kube-system", Name: "coredns"}}
	if p.Create(event.CreateEvent{Object: coredns}) {
		t.Fatal("coredns Deployment passed the metrics-server predicate")
	}
}
