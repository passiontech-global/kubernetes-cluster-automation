package corednspatcher

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/testutil"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// corednsDeploy builds the kube-system/coredns Deployment in a fully
// patched state for the given zone config; mutating any pinned field
// makes it drifted again.
func corednsDeploy(zoneWhen string, minDomains int) *appsv1.Deployment {
	zone := corev1.TopologySpreadConstraint{
		MaxSkew:            1,
		TopologyKey:        "topology.kubernetes.io/zone",
		WhenUnsatisfiable:  corev1.UnsatisfiableConstraintAction(zoneWhen),
		NodeTaintsPolicy:   ptr.To(corev1.NodeInclusionPolicyHonor),
		NodeAffinityPolicy: ptr.To(corev1.NodeInclusionPolicyHonor),
		LabelSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"k8s-app": "kube-dns"},
		},
	}
	if corednsMinDomainsWanted(zoneWhen, minDomains) {
		zone.MinDomains = ptr.To(int32(minDomains))
	}
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "coredns", Namespace: "kube-system"},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:           "coredns",
						LivenessProbe:  &corev1.Probe{TimeoutSeconds: 5},
						ReadinessProbe: &corev1.Probe{TimeoutSeconds: 5},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("25m"),
								corev1.ResourceMemory: resource.MustParse("64Mi"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("1000m"),
								corev1.ResourceMemory: resource.MustParse("256Mi"),
							},
						},
					}},
					TopologySpreadConstraints: []corev1.TopologySpreadConstraint{
						zone,
						{
							MaxSkew:            1,
							TopologyKey:        "kubernetes.io/hostname",
							WhenUnsatisfiable:  corev1.ScheduleAnyway,
							NodeTaintsPolicy:   ptr.To(corev1.NodeInclusionPolicyHonor),
							NodeAffinityPolicy: ptr.To(corev1.NodeInclusionPolicyHonor),
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"k8s-app": "kube-dns"},
							},
						},
					},
				},
			},
		},
	}
}

// corednsDeployBare is the k0s stack-applier baseline: required
// hostname anti-affinity, 1s probe timeouts, no spread constraints.
func corednsDeployBare() *appsv1.Deployment {
	d := corednsDeploy("DoNotSchedule", 2)
	d.Spec.Template.Spec.TopologySpreadConstraints = nil
	d.Spec.Template.Spec.Affinity = &corev1.Affinity{
		PodAntiAffinity: &corev1.PodAntiAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{{
				TopologyKey: "kubernetes.io/hostname",
			}},
		},
	}
	d.Spec.Template.Spec.Containers[0].LivenessProbe = &corev1.Probe{TimeoutSeconds: 1}
	d.Spec.Template.Spec.Containers[0].ReadinessProbe = &corev1.Probe{TimeoutSeconds: 1}
	d.Spec.Template.Spec.Containers[0].Resources = corev1.ResourceRequirements{}
	return d
}

func getCorednsDeploy(t *testing.T, cs *fake.Clientset) *appsv1.Deployment {
	t.Helper()
	d, err := cs.AppsV1().Deployments("kube-system").
		Get(ctx, "coredns", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get coredns: %v", err)
	}
	return d
}

func TestCorednsNeedsPatch(t *testing.T) {
	mutate := func(fn func(*appsv1.Deployment)) *appsv1.Deployment {
		d := corednsDeploy("DoNotSchedule", 2)
		fn(d)
		return d
	}
	for _, tc := range []struct {
		name         string
		d            *appsv1.Deployment
		zoneWhen     string
		minDomains   int
		wantReplicas int32
		drifted      bool
	}{
		{"k0s baseline", corednsDeployBare(), "DoNotSchedule", 2, 0, true},
		{"fully pinned", corednsDeploy("DoNotSchedule", 2), "DoNotSchedule", 2, 0, false},
		{"single-zone config fully pinned",
			corednsDeploy("ScheduleAnyway", 0), "ScheduleAnyway", 0, 0, false},
		{"replicas nil with scaling on",
			corednsDeploy("DoNotSchedule", 2), "DoNotSchedule", 2, 4, true},
		{"replicas pinned", mutate(func(d *appsv1.Deployment) {
			d.Spec.Replicas = ptr.To(int32(4))
		}), "DoNotSchedule", 2, 4, false},
		{"replicas below wanted", mutate(func(d *appsv1.Deployment) {
			d.Spec.Replicas = ptr.To(int32(2))
		}), "DoNotSchedule", 2, 4, true},
		{"replicas above wanted", mutate(func(d *appsv1.Deployment) {
			d.Spec.Replicas = ptr.To(int32(9))
		}), "DoNotSchedule", 2, 4, true},
		{"replicas mismatch ignored when scaling disabled",
			mutate(func(d *appsv1.Deployment) {
				d.Spec.Replicas = ptr.To(int32(7))
			}), "DoNotSchedule", 2, 0, false},
		{"missing coredns container", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Containers = nil
		}), "DoNotSchedule", 2, 0, true},
		{"nil probes", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Containers[0].LivenessProbe = nil
		}), "DoNotSchedule", 2, 0, true},
		{"probe timeout drifted", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Containers[0].ReadinessProbe.TimeoutSeconds = 1
		}), "DoNotSchedule", 2, 0, true},
		{"request cpu drifted", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Containers[0].Resources.Requests[corev1.ResourceCPU] =
				resource.MustParse("10m")
		}), "DoNotSchedule", 2, 0, true},
		{"limit memory drifted", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Containers[0].Resources.Limits[corev1.ResourceMemory] =
				resource.MustParse("128Mi")
		}), "DoNotSchedule", 2, 0, true},
		{"anti-affinity back", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Affinity = &corev1.Affinity{}
		}), "DoNotSchedule", 2, 0, true},
		{"zone whenUnsatisfiable drifted", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.TopologySpreadConstraints[0].WhenUnsatisfiable =
				corev1.ScheduleAnyway
		}), "DoNotSchedule", 2, 0, true},
		{"minDomains drifted", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.TopologySpreadConstraints[0].MinDomains = ptr.To(int32(1))
		}), "DoNotSchedule", 2, 0, true},
		{"minDomains lost", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.TopologySpreadConstraints[0].MinDomains = nil
		}), "DoNotSchedule", 2, 0, true},
		{"taints policy not Honor", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.TopologySpreadConstraints[0].NodeTaintsPolicy = nil
		}), "DoNotSchedule", 2, 0, true},
		{"hostname constraint missing", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.TopologySpreadConstraints =
				d.Spec.Template.Spec.TopologySpreadConstraints[:1]
		}), "DoNotSchedule", 2, 0, true},
		{"wrong selector", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.TopologySpreadConstraints[1].LabelSelector.MatchLabels =
				map[string]string{"k8s-app": "other"}
		}), "DoNotSchedule", 2, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := corednsNeedsPatch(tc.d, tc.zoneWhen, tc.minDomains,
				tc.wantReplicas); got != tc.drifted {
				t.Fatalf("corednsNeedsPatch=%v, want %v", got, tc.drifted)
			}
		})
	}
}

// proportionalReplicas is the CPA "linear" ladder — floor at
// minReplicas, ceil at totalNodes/nodesPerReplica.
func TestProportionalReplicas(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		nodes, min, nodesPerReplica int
		want                        int32
	}{
		{"zero nodes floors at min", 0, 4, 1, 4},
		{"below min floors", 3, 4, 1, 4},
		{"exact min", 4, 4, 1, 4},
		{"above min", 9, 4, 1, 9},
		{"ceil division rounds up", 9, 4, 2, 5},
		{"ceil division exact", 8, 4, 2, 4},
		{"min 1 single-zone", 5, 1, 1, 5},
		{"zero nodesPerReplica clamped", 10, 3, 0, 10},
		{"negative nodesPerReplica clamped", 10, 3, -2, 10},
		{"min 0 still ceils", 2, 0, 3, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := shared.ProportionalReplicas(tc.nodes, tc.min,
				tc.nodesPerReplica); got != tc.want {
				t.Fatalf("proportionalReplicas=%d, want %d", got, tc.want)
			}
		})
	}
}

// A drifted Deployment gets the full strategic-merge patch — the
// apiserver side lands probes/resources/constraints by name and
// clears affinity (the fake tracker applies the merge for real).
func TestCoreDNSPatcherAppliesPatch(t *testing.T) {
	cs := fake.NewSimpleClientset(corednsDeployBare())
	var got []byte
	testutil.CaptureDeployPatch(cs, &got)

	r := &corednsPatcher{cs: cs, zoneWhen: "DoNotSchedule", minDomains: 2}
	res, err := r.Reconcile(ctx, reconcile.Request{})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter != 15*time.Minute {
		t.Fatalf("expected 15m requeue, got %s", res.RequeueAfter)
	}
	if !strings.Contains(string(got), `"minDomains":2`) {
		t.Fatalf("zone constraint missing minDomains: %s", got)
	}
	if strings.Contains(string(got), `"replicas"`) {
		t.Fatalf("disabled scaling must not send replicas: %s", got)
	}
	if corednsNeedsPatch(getCorednsDeploy(t, cs), "DoNotSchedule", 2, 0) {
		t.Fatal("deployment still drifted after patch")
	}
}

// With proportional scaling on, the patch carries spec.replicas =
// max(min, ceil(nodes/per)) — 9 nodes / per=2 ceils to 5, above the
// min-4 floor — and the tracker state afterwards is drift-free.
func TestCoreDNSPatcherScalesReplicas(t *testing.T) {
	cs := fake.NewSimpleClientset(corednsDeployBare(),
		testutil.Node("n1", corev1.ConditionTrue, nil),
		testutil.Node("n2", corev1.ConditionTrue, nil),
		testutil.Node("n3", corev1.ConditionTrue, nil),
		testutil.Node("n4", corev1.ConditionTrue, nil),
		testutil.Node("n5", corev1.ConditionTrue, nil),
		testutil.Node("n6", corev1.ConditionTrue, nil),
		testutil.Node("n7", corev1.ConditionTrue, nil),
		testutil.Node("n8", corev1.ConditionTrue, nil),
		testutil.Node("n9", corev1.ConditionTrue, nil))
	var got []byte
	testutil.CaptureDeployPatch(cs, &got)

	r := &corednsPatcher{cs: cs, zoneWhen: "DoNotSchedule", minDomains: 2,
		minReplicas: 4, nodesPerReplica: 2}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !strings.Contains(string(got), `"replicas":5`) {
		t.Fatalf("patch missing proportional replicas: %s", got)
	}
	d := getCorednsDeploy(t, cs)
	if d.Spec.Replicas == nil || *d.Spec.Replicas != 5 {
		t.Fatalf("deployment replicas = %v, want 5", d.Spec.Replicas)
	}
	if corednsNeedsPatch(d, "DoNotSchedule", 2, 5) {
		t.Fatal("deployment still drifted after patch")
	}
}

// Fewer nodes than the floor: 2 nodes / per=1 ceils to 2, but the
// min-4 floor wins.
func TestCoreDNSPatcherReplicasFloor(t *testing.T) {
	cs := fake.NewSimpleClientset(corednsDeployBare(),
		testutil.Node("n1", corev1.ConditionTrue, nil),
		testutil.Node("n2", corev1.ConditionTrue, nil))
	var got []byte
	testutil.CaptureDeployPatch(cs, &got)

	r := &corednsPatcher{cs: cs, zoneWhen: "DoNotSchedule", minDomains: 2,
		minReplicas: 4, nodesPerReplica: 1}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !strings.Contains(string(got), `"replicas":4`) {
		t.Fatalf("patch missing floor replicas: %s", got)
	}
}

// minReplicas=0 disables the pin entirely — an already-pinned
// Deployment with an odd replica count is left alone (a re-enabled
// standalone CPA owns .spec.replicas then).
func TestCoreDNSPatcherScalingDisabledKeepsReplicas(t *testing.T) {
	d := corednsDeploy("DoNotSchedule", 2)
	d.Spec.Replicas = ptr.To(int32(2))
	cs := fake.NewSimpleClientset(d,
		testutil.Node("n1", corev1.ConditionTrue, nil),
		testutil.Node("n2", corev1.ConditionTrue, nil),
		testutil.Node("n3", corev1.ConditionTrue, nil),
		testutil.Node("n4", corev1.ConditionTrue, nil),
		testutil.Node("n5", corev1.ConditionTrue, nil),
		testutil.Node("n6", corev1.ConditionTrue, nil),
		testutil.Node("n7", corev1.ConditionTrue, nil),
		testutil.Node("n8", corev1.ConditionTrue, nil))
	var patched bool
	testutil.ForbidDeployPatch(cs, &patched)

	r := &corednsPatcher{cs: cs, zoneWhen: "DoNotSchedule", minDomains: 2}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if patched {
		t.Fatal("disabled scaling patched .spec.replicas")
	}
	if *getCorednsDeploy(t, cs).Spec.Replicas != 2 {
		t.Fatal("replicas changed while scaling disabled")
	}
}

// A node list failure with scaling on must surface (the replica count
// would be computed from a partial picture otherwise).
func TestCoreDNSPatcherNodeListError(t *testing.T) {
	cs := fake.NewSimpleClientset(corednsDeployBare())
	cs.PrependReactor("list", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	r := &corednsPatcher{cs: cs, zoneWhen: "DoNotSchedule", minDomains: 2,
		minReplicas: 4, nodesPerReplica: 1}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err == nil {
		t.Fatal("expected error when the node list fails")
	}
}

// cicd config (single zone): the patch must carry an explicit
// "minDomains": null on the zone constraint — strategic merge keeps a
// stale minDomains from a previous DoNotSchedule patch otherwise, and
// the API rejects the merged result under ScheduleAnyway.
func TestCoreDNSPatcherNullsMinDomainsOnScheduleAnyway(t *testing.T) {
	cs := fake.NewSimpleClientset(corednsDeployBare())
	var got []byte
	testutil.CaptureDeployPatch(cs, &got)

	r := &corednsPatcher{cs: cs, zoneWhen: "ScheduleAnyway", minDomains: 0}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !strings.Contains(string(got), `"minDomains":null`) {
		t.Fatalf("minDomains not explicitly nulled in ScheduleAnyway patch: %s", got)
	}
	zone := patchZoneConstraint(t, got)
	if zone["whenUnsatisfiable"] != "ScheduleAnyway" {
		t.Fatalf("zone whenUnsatisfiable = %v, want ScheduleAnyway",
			zone["whenUnsatisfiable"])
	}
	if v, ok := zone["minDomains"]; !ok || v != nil {
		t.Fatalf("zone constraint minDomains = %v, want explicit null", zone)
	}
}

// patchZoneConstraint extracts the topology.kubernetes.io/zone entry
// from a rendered patch body.
func patchZoneConstraint(t *testing.T, patch []byte) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(patch, &body); err != nil {
		t.Fatalf("patch is not JSON: %v", err)
	}
	tscs, ok := body["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["topologySpreadConstraints"].([]any)
	if !ok {
		t.Fatalf("patch has no topologySpreadConstraints: %s", patch)
	}
	for _, raw := range tscs {
		c := raw.(map[string]any)
		if c["topologyKey"] == "topology.kubernetes.io/zone" {
			return c
		}
	}
	t.Fatalf("no zone constraint in patch: %s", patch)
	return nil
}

func TestCoreDNSPatcherNoOpWhenCorrect(t *testing.T) {
	// Fully pinned INCLUDING the proportional replica count — 2 nodes
	// / per=1 ceils to 2, the min-4 floor bumps it to 4.
	d := corednsDeploy("DoNotSchedule", 2)
	d.Spec.Replicas = ptr.To(int32(4))
	cs := fake.NewSimpleClientset(d,
		testutil.Node("n1", corev1.ConditionTrue, nil),
		testutil.Node("n2", corev1.ConditionTrue, nil))
	var patched bool
	testutil.ForbidDeployPatch(cs, &patched)

	r := &corednsPatcher{cs: cs, zoneWhen: "DoNotSchedule", minDomains: 2,
		minReplicas: 4, nodesPerReplica: 1}
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

// A Deployment without the coredns container reads as drift, but the
// patch merges containers by name and would append a container entry
// with NO image — the apiserver rejects it forever. The reconciler
// must skip with a warn, never attempt the patch.
func TestCoreDNSPatcherMissingContainerNoPatch(t *testing.T) {
	d := corednsDeployBare()
	d.Spec.Template.Spec.Containers = nil
	cs := fake.NewSimpleClientset(d)
	var patched bool
	testutil.ForbidDeployPatch(cs, &patched)

	r := &corednsPatcher{cs: cs, zoneWhen: "DoNotSchedule", minDomains: 2}
	res, err := r.Reconcile(ctx, reconcile.Request{})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if patched {
		t.Fatal("patched a Deployment whose coredns container is absent — " +
			"the name-only container entry has no image and the apiserver rejects it")
	}
	if res.RequeueAfter != 15*time.Minute {
		t.Fatalf("expected 15m requeue, got %s", res.RequeueAfter)
	}
}

func TestCoreDNSPatcherMissingDeployment(t *testing.T) {
	cs := fake.NewSimpleClientset()
	r := &corednsPatcher{cs: cs, zoneWhen: "DoNotSchedule", minDomains: 2}
	res, err := r.Reconcile(ctx, reconcile.Request{})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter != 15*time.Minute {
		t.Fatalf("expected 15m requeue, got %s", res.RequeueAfter)
	}
}

func TestCoreDNSPatcherGetError(t *testing.T) {
	cs := fake.NewSimpleClientset(corednsDeployBare())
	cs.PrependReactor("get", "deployments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	r := &corednsPatcher{cs: cs, zoneWhen: "DoNotSchedule", minDomains: 2}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err == nil {
		t.Fatal("expected error when the deployment get fails")
	}
}

func TestCoreDNSPatcherPatchError(t *testing.T) {
	cs := fake.NewSimpleClientset(corednsDeployBare())
	cs.PrependReactor("patch", "deployments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})
	r := &corednsPatcher{cs: cs, zoneWhen: "DoNotSchedule", minDomains: 2}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err == nil {
		t.Fatal("expected error when the drift patch fails")
	}
}

// Disabled must be a clean no-op — nothing registered, no error.
func TestSetupCoreDNSPatcherDisabled(t *testing.T) {
	m := testutil.NewStubManager()
	if err := Setup(m, fake.NewSimpleClientset(),
		false, "DoNotSchedule", 2, 4, 1); err != nil {
		t.Fatalf("disabled setup must return nil, got %v", err)
	}
	if len(m.Added) != 0 {
		t.Fatalf("disabled module registered %d runnables, want 0", len(m.Added))
	}
}

// The predicate pins ns/name on top of the shared Deployment
// informer — only kube-system/coredns may reconcile.
func TestSetupCoreDNSPatcherPredicate(t *testing.T) {
	p := testutil.ForPredicate(t, func(m manager.Manager) error {
		return Setup(m, fake.NewSimpleClientset(),
			true, "DoNotSchedule", 2, 4, 1)
	})
	coredns := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Namespace: "kube-system", Name: "coredns"}}
	if !p.Create(event.CreateEvent{Object: coredns}) {
		t.Fatal("coredns Deployment did not pass the predicate")
	}
	ms := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Namespace: "kube-system", Name: "metrics-server"}}
	if p.Create(event.CreateEvent{Object: ms}) {
		t.Fatal("metrics-server Deployment passed the coredns predicate")
	}
	wrongNS := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Namespace: "default", Name: "coredns"}}
	if p.Create(event.CreateEvent{Object: wrongNS}) {
		t.Fatal("wrong-namespace Deployment passed the predicate")
	}
}

// The Node watch (second watch source) drives the proportional
// replica count: only create/delete may fire — includeUnschedulableNodes
// counts every Node object, so updates never change the total and
// would only add kubelet-heartbeat churn.
func TestSetupCoreDNSPatcherNodeWatch(t *testing.T) {
	m := testutil.NewStubManager()
	if err := Setup(m, fake.NewSimpleClientset(),
		true, "DoNotSchedule", 2, 4, 1); err != nil {
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
	n1 := testutil.Node("n1", corev1.ConditionTrue, nil)
	if !p.Create(event.CreateEvent{Object: n1}) {
		t.Fatal("node add did not fire")
	}
	if !p.Delete(event.DeleteEvent{Object: n1}) {
		t.Fatal("node delete did not fire")
	}
	if p.Update(testutil.UpdateEvent(n1, testutil.Node("n1", corev1.ConditionFalse, nil))) {
		t.Fatal("node update fired — heartbeat/cordon churn would re-reconcile constantly")
	}
	if p.Generic(event.GenericEvent{Object: n1}) {
		t.Fatal("generic event fired")
	}
}
