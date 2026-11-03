package system

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/controller/testutil"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"
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
		name         string
		d            *appsv1.Deployment
		wantReplicas int32
		drifted      bool
	}{
		{"k0s baseline", metricsServerDeployBare(), 0, true},
		{"fully pinned", metricsServerDeploy(), 0, false},
		{"replicas nil with scaling on", metricsServerDeploy(), 3, true},
		{"replicas pinned", mutate(func(d *appsv1.Deployment) {
			d.Spec.Replicas = ptr.To(int32(3))
		}), 3, false},
		{"replicas below wanted", mutate(func(d *appsv1.Deployment) {
			d.Spec.Replicas = ptr.To(int32(1))
		}), 3, true},
		{"replicas above wanted", mutate(func(d *appsv1.Deployment) {
			d.Spec.Replicas = ptr.To(int32(6))
		}), 3, true},
		{"replicas mismatch ignored when scaling disabled",
			mutate(func(d *appsv1.Deployment) {
				d.Spec.Replicas = ptr.To(int32(9))
			}), 0, false},
		{"missing metrics-server container", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Containers = nil
		}), 0, true},
		{"kubelet-request-timeout arg missing", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Containers[0].Args =
				d.Spec.Template.Spec.Containers[0].Args[:5]
		}), 0, true},
		{"nil liveness probe", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Containers[0].LivenessProbe = nil
		}), 0, true},
		{"request memory drifted", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Containers[0].Resources.Requests[corev1.ResourceMemory] =
				resource.MustParse("64Mi")
		}), 0, true},
		{"affinity back", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Affinity = &corev1.Affinity{}
		}), 0, true},
		// The 2026-10-30 treadmill bug: a wildcard Exists toleration
		// (empty key) tolerates node.kubernetes.io/unschedulable too.
		{"wildcard toleration", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Tolerations = []corev1.Toleration{
				{Operator: corev1.TolerationOpExists},
			}
		}), 0, true},
		{"not-ready toleration missing", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Tolerations = []corev1.Toleration{
				{Key: "node-role.kubernetes.io/control-plane",
					Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
			}
		}), 0, true},
		{"hostname constraint missing", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.TopologySpreadConstraints =
				d.Spec.Template.Spec.TopologySpreadConstraints[:1]
		}), 0, true},
		{"constraint turned hard", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.TopologySpreadConstraints[0].WhenUnsatisfiable =
				corev1.DoNotSchedule
		}), 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := metricsServerNeedsPatch(tc.d, tc.wantReplicas); got != tc.drifted {
				t.Fatalf("metricsServerNeedsPatch=%v, want %v", got, tc.drifted)
			}
		})
	}
}

func TestMetricsServerPatcherAppliesPatch(t *testing.T) {
	cs := fake.NewSimpleClientset(metricsServerDeployBare())
	var got []byte
	captureDeployPatch(cs, &got)

	r := &metricsServerPatcher{cs: cs}
	res, err := r.Reconcile(ctx, reconcile.Request{})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter != 15*time.Minute {
		t.Fatalf("expected 15m requeue, got %s", res.RequeueAfter)
	}
	if strings.Contains(string(got), `"replicas"`) {
		t.Fatalf("disabled scaling must not send replicas: %s", got)
	}
	if metricsServerNeedsPatch(getMetricsServerDeploy(t, cs), 0) {
		t.Fatal("deployment still drifted after patch")
	}
	// The wildcard toleration must be gone for good.
	for _, tol := range getMetricsServerDeploy(t, cs).Spec.Template.Spec.Tolerations {
		if tol.Operator == corev1.TolerationOpExists && tol.Key == "" {
			t.Fatal("wildcard Exists toleration survived the patch")
		}
	}
}

// With proportional scaling on, the patch carries spec.replicas =
// max(min, ceil(nodes/per)) — 7 nodes / per=2 ceils to 4, above the
// min-3 floor — and the rest of the pinned body is byte-identical.
func TestMetricsServerPatcherScalesReplicas(t *testing.T) {
	cs := fake.NewSimpleClientset(metricsServerDeployBare(),
		node("n1", corev1.ConditionTrue, nil),
		node("n2", corev1.ConditionTrue, nil),
		node("n3", corev1.ConditionTrue, nil),
		node("n4", corev1.ConditionTrue, nil),
		node("n5", corev1.ConditionTrue, nil),
		node("n6", corev1.ConditionTrue, nil),
		node("n7", corev1.ConditionTrue, nil))
	var got []byte
	captureDeployPatch(cs, &got)

	r := &metricsServerPatcher{cs: cs, minReplicas: 3, nodesPerReplica: 2}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !strings.Contains(string(got), `"replicas":4`) {
		t.Fatalf("patch missing proportional replicas: %s", got)
	}
	d := getMetricsServerDeploy(t, cs)
	if d.Spec.Replicas == nil || *d.Spec.Replicas != 4 {
		t.Fatalf("deployment replicas = %v, want 4", d.Spec.Replicas)
	}
	if metricsServerNeedsPatch(d, 4) {
		t.Fatal("deployment still drifted after patch")
	}
}

// Fewer nodes than the floor: 2 nodes / per=1 ceils to 2, but the
// min-3 floor wins.
func TestMetricsServerPatcherReplicasFloor(t *testing.T) {
	cs := fake.NewSimpleClientset(metricsServerDeployBare(),
		node("n1", corev1.ConditionTrue, nil),
		node("n2", corev1.ConditionTrue, nil))
	var got []byte
	captureDeployPatch(cs, &got)

	r := &metricsServerPatcher{cs: cs, minReplicas: 3, nodesPerReplica: 1}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !strings.Contains(string(got), `"replicas":3`) {
		t.Fatalf("patch missing floor replicas: %s", got)
	}
}

// minReplicas=0 disables the pin entirely — an already-pinned
// Deployment with an odd replica count is left alone (a re-enabled
// standalone CPA owns .spec.replicas then).
func TestMetricsServerPatcherScalingDisabledKeepsReplicas(t *testing.T) {
	d := metricsServerDeploy()
	d.Spec.Replicas = ptr.To(int32(1))
	cs := fake.NewSimpleClientset(d,
		node("n1", corev1.ConditionTrue, nil),
		node("n2", corev1.ConditionTrue, nil),
		node("n3", corev1.ConditionTrue, nil),
		node("n4", corev1.ConditionTrue, nil),
		node("n5", corev1.ConditionTrue, nil),
		node("n6", corev1.ConditionTrue, nil))
	var patched bool
	forbidDeployPatch(cs, &patched)

	r := &metricsServerPatcher{cs: cs}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if patched {
		t.Fatal("disabled scaling patched .spec.replicas")
	}
	if *getMetricsServerDeploy(t, cs).Spec.Replicas != 1 {
		t.Fatal("replicas changed while scaling disabled")
	}
}

// A node list failure with scaling on must surface (the replica count
// would be computed from a partial picture otherwise).
func TestMetricsServerPatcherNodeListError(t *testing.T) {
	cs := fake.NewSimpleClientset(metricsServerDeployBare())
	cs.PrependReactor("list", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	r := &metricsServerPatcher{cs: cs, minReplicas: 3, nodesPerReplica: 1}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err == nil {
		t.Fatal("expected error when the node list fails")
	}
}

func TestMetricsServerPatcherNoOpWhenCorrect(t *testing.T) {
	// Fully pinned INCLUDING the proportional replica count — 2 nodes
	// / per=1 ceils to 2, the min-3 floor bumps it to 3.
	d := metricsServerDeploy()
	d.Spec.Replicas = ptr.To(int32(3))
	cs := fake.NewSimpleClientset(d,
		node("n1", corev1.ConditionTrue, nil),
		node("n2", corev1.ConditionTrue, nil))
	var patched bool
	forbidDeployPatch(cs, &patched)

	r := &metricsServerPatcher{cs: cs, minReplicas: 3, nodesPerReplica: 1}
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
	m := testutil.NewStubManager()
	if err := SetupMetricsServerPatcher(m, fake.NewSimpleClientset(),
		false, 3, 1); err != nil {
		t.Fatalf("disabled setup must return nil, got %v", err)
	}
	if len(m.Added) != 0 {
		t.Fatalf("disabled module registered %d runnables, want 0", len(m.Added))
	}
}

// The predicate pins ns/name on top of the shared Deployment
// informer — only kube-system/metrics-server may reconcile.
func TestSetupMetricsServerPatcherPredicate(t *testing.T) {
	p := testutil.ForPredicate(t, func(m manager.Manager) error {
		return SetupMetricsServerPatcher(m, fake.NewSimpleClientset(), true, 3, 1)
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

// The Node watch (second watch source) drives the proportional
// replica count: only create/delete may fire — includeUnschedulableNodes
// counts every Node object, so updates never change the total and
// would only add kubelet-heartbeat churn.
func TestSetupMetricsServerPatcherNodeWatch(t *testing.T) {
	m := testutil.NewStubManager()
	if err := SetupMetricsServerPatcher(m, fake.NewSimpleClientset(),
		true, 3, 1); err != nil {
		t.Fatalf("setup: %v", err)
	}
	srcs := testutil.ControllerWatches(t, m.Added[0])
	if len(srcs) != 2 {
		t.Fatalf("patcher registered %d watches, want 2 (Deployment + Node)", len(srcs))
	}
	preds, _ := testutil.KindSource(t, srcs[1])
	if len(preds) != 1 {
		t.Fatalf("Node watch carries %d predicates, want 1", len(preds))
	}
	p := preds[0]
	n1 := node("n1", corev1.ConditionTrue, nil)
	if !p.Create(event.CreateEvent{Object: n1}) {
		t.Fatal("node add did not fire")
	}
	if !p.Delete(event.DeleteEvent{Object: n1}) {
		t.Fatal("node delete did not fire")
	}
	if p.Update(testutil.UpdateEvent(n1, node("n1", corev1.ConditionFalse, nil))) {
		t.Fatal("node update fired — heartbeat/cordon churn would re-reconcile constantly")
	}
	if p.Generic(event.GenericEvent{Object: n1}) {
		t.Fatal("generic event fired")
	}
}
