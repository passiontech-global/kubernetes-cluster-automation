package corednspatcher

import (
	"context"
	json "encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/system/pinnedworkload"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
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
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxUnavailable: ptr.To(intstr.FromInt(1)),
				},
			},
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "coredns",
						LivenessProbe: &corev1.Probe{
							TimeoutSeconds: 5, FailureThreshold: 5},
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
	// k0s stock declares no strategy — the RollingUpdate pin is ours.
	d.Spec.Strategy = appsv1.DeploymentStrategy{}
	return d
}

func getCorednsDeploy(t *testing.T, cs *fake.Clientset) *appsv1.Deployment {
	t.Helper()
	d, err := cs.AppsV1().Deployments("kube-system").
		Get(t.Context(), "coredns", metav1.GetOptions{})
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
		{"liveness failureThreshold drifted", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Containers[0].LivenessProbe.FailureThreshold = 3
		}), "DoNotSchedule", 2, 0, true},
		{"rollingUpdate nil", mutate(func(d *appsv1.Deployment) {
			d.Spec.Strategy.RollingUpdate = nil
		}), "DoNotSchedule", 2, 0, true},
		{"maxUnavailable percent drifted", mutate(func(d *appsv1.Deployment) {
			d.Spec.Strategy.RollingUpdate.MaxUnavailable =
				ptr.To(intstr.FromString("25%"))
		}), "DoNotSchedule", 2, 0, true},
		{"maxUnavailable int 2 drifted", mutate(func(d *appsv1.Deployment) {
			d.Spec.Strategy.RollingUpdate.MaxUnavailable =
				ptr.To(intstr.FromInt(2))
		}), "DoNotSchedule", 2, 0, true},
		{"recreate strategy drifted", mutate(func(d *appsv1.Deployment) {
			d.Spec.Strategy.Type = appsv1.RecreateDeploymentStrategyType
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
			if got := kube.ProportionalReplicas(tc.nodes, tc.min,
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
	res, err := r.Reconcile(t.Context(), reconcile.Request{})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter < 13*time.Minute+30*time.Second || res.RequeueAfter >= 16*time.Minute+30*time.Second {
		t.Fatalf("expected 15m requeue, got %s", res.RequeueAfter)
	}
	if !strings.Contains(string(got), `"minDomains":2`) {
		t.Fatalf("zone constraint missing minDomains: %s", got)
	}
	if !strings.Contains(string(got), `"failureThreshold":5`) {
		t.Fatalf("patch missing liveness failureThreshold pin: %s", got)
	}
	if !strings.Contains(string(got), `"maxUnavailable":1`) {
		t.Fatalf("patch missing rollingUpdate maxUnavailable pin: %s", got)
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
	if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err != nil {
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
	if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err != nil {
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
	if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err != nil {
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
	if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err == nil {
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
	if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err != nil {
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
	res, err := r.Reconcile(t.Context(), reconcile.Request{})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if patched {
		t.Fatal("patched an already-correct Deployment")
	}
	if res.RequeueAfter < 13*time.Minute+30*time.Second || res.RequeueAfter >= 16*time.Minute+30*time.Second {
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
	res, err := r.Reconcile(t.Context(), reconcile.Request{})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if patched {
		t.Fatal("patched a Deployment whose coredns container is absent — " +
			"the name-only container entry has no image and the apiserver rejects it")
	}
	if res.RequeueAfter < 13*time.Minute+30*time.Second || res.RequeueAfter >= 16*time.Minute+30*time.Second {
		t.Fatalf("expected 15m requeue, got %s", res.RequeueAfter)
	}
}

func TestCoreDNSPatcherMissingDeployment(t *testing.T) {
	cs := fake.NewSimpleClientset()
	r := &corednsPatcher{cs: cs, zoneWhen: "DoNotSchedule", minDomains: 2}
	res, err := r.Reconcile(t.Context(), reconcile.Request{})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter < 13*time.Minute+30*time.Second || res.RequeueAfter >= 16*time.Minute+30*time.Second {
		t.Fatalf("expected 15m requeue, got %s", res.RequeueAfter)
	}
}

// ---------------------------------------------------------------------------
// negative-cache-guard — Corefile negative-cache (denial 9984 5) reconcile
// ---------------------------------------------------------------------------

// corefileConfigMap builds the kube-system/coredns ConfigMap fixture —
// the k0s-managed object the denial-cap guard reconciles.
func corefileConfigMap(corefile string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "coredns"},
		Data:       map[string]string{"Corefile": corefile},
	}
}

// k0sCorefile is the stock k0s Corefile: a BARE `cache 30` — the
// NXDOMAIN-poisoning incident class (negative cache holds the full
// SOA TTL and kills Jobs that outrace the endpoint controller).
const k0sCorefile = `.:53 {
    errors
    health {
        lameduck 5s
    }
    ready
    kubernetes cluster.local in-addr.arpa ip6.arpa {
        pods insecure
        fallthrough in-addr.arpa ip6.arpa
        ttl 30
    }
    prometheus :9153
    forward . /etc/resolv.conf
    cache 30
    loop
    reload
    loadbalance
}
`

// patchedCorefile is the fully healed stock Corefile — denial-capped
// cache block AND the forward max_concurrent option (P1.7a).
const patchedCorefile = `.:53 {
    errors
    health {
        lameduck 5s
    }
    ready
    kubernetes cluster.local in-addr.arpa ip6.arpa {
        pods insecure
        fallthrough in-addr.arpa ip6.arpa
        ttl 30
    }
    prometheus :9153
    forward . /etc/resolv.conf {
        max_concurrent 2000
    }
    cache 30 {
        success 9984 30
        denial 9984 5
    }
    loop
    reload
    loadbalance
}
`

func getCorefile(t *testing.T, cs *fake.Clientset) string {
	t.Helper()
	cm, err := cs.CoreV1().ConfigMaps("kube-system").
		Get(t.Context(), "coredns", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get coredns configmap: %v", err)
	}
	return cm.Data["Corefile"]
}

// A bare `cache 30` gets expanded to the success+denial block —
// NXDOMAIN negative caching capped at 5s on the k0s-managed CoreDNS.
func TestCoreDNSPatcherCorefileDenialCap(t *testing.T) {
	cs := fake.NewSimpleClientset(corednsDeploy("DoNotSchedule", 2),
		corefileConfigMap(k0sCorefile))
	r := &corednsPatcher{cs: cs, zoneWhen: "DoNotSchedule", minDomains: 2}
	if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := getCorefile(t, cs)
	if !strings.Contains(got, "denial 9984 5") || !strings.Contains(got, "success 9984 30") {
		t.Fatalf("corefile not denial-capped:\n%s", got)
	}
	if !strings.Contains(got, "cache 30 {") {
		t.Fatalf("cache directive not braced:\n%s", got)
	}
	// Idempotent: a second reconcile must not touch the ConfigMap.
	if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if getCorefile(t, cs) != got {
		t.Fatal("denial-capped corefile was rewritten again — not idempotent")
	}
}

// A Corefile whose cache block already carries denial/success is
// left byte-identical — no patch action fires on configmaps.
func TestCoreDNSPatcherCorefileAlreadyCapped(t *testing.T) {
	cs := fake.NewSimpleClientset(corednsDeploy("DoNotSchedule", 2),
		corefileConfigMap(patchedCorefile))
	var patched bool
	cs.PrependReactor("patch", "configmaps",
		func(ktesting.Action) (bool, runtime.Object, error) {
			patched = true
			return true, nil, nil
		})
	r := &corednsPatcher{cs: cs, zoneWhen: "DoNotSchedule", minDomains: 2}
	if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if patched {
		t.Fatal("patched an already denial-capped Corefile")
	}
	if getCorefile(t, cs) != patchedCorefile {
		t.Fatal("capped corefile mutated")
	}
}

// A braced cache block WITHOUT denial gains just the denial line —
// existing subkeys (success/negative zones) are preserved, not
// replaced by the fixed block.
func TestCoreDNSPatcherCorefileBracedNoDenial(t *testing.T) {
	corefile := strings.Replace(k0sCorefile, "    cache 30\n",
		"    cache 30 {\n        success 9984 30\n    }\n", 1)
	cs := fake.NewSimpleClientset(corednsDeploy("DoNotSchedule", 2),
		corefileConfigMap(corefile))
	r := &corednsPatcher{cs: cs, zoneWhen: "DoNotSchedule", minDomains: 2}
	if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := getCorefile(t, cs)
	if !strings.Contains(got, "denial 9984 5") {
		t.Fatalf("braced cache block did not gain denial:\n%s", got)
	}
	if !strings.Contains(got, "success 9984 30") {
		t.Fatalf("existing success directive lost:\n%s", got)
	}
	if strings.Count(got, "cache 30 {") != 1 {
		t.Fatalf("cache block duplicated:\n%s", got)
	}
}

// The zone-qualified bare form `cache 30 cluster.local` keeps its
// zone args through the expansion.
func TestCoreDNSPatcherCorefileZoneCache(t *testing.T) {
	got, changed := corefileCacheHeal("x {\n    cache 30 cluster.local\n}\n", "")
	if !changed {
		t.Fatal("bare zone-qualified cache not rewritten")
	}
	if !strings.Contains(got, "cache 30 cluster.local {") ||
		!strings.Contains(got, "denial 9984 5") {
		t.Fatalf("zone args lost in expansion:\n%s", got)
	}
}

// Pure-parser edge cases: comments, inline single-line blocks, and
// several cache directives in one Corefile.
func TestCorefileDenialCapParser(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      string
		changed bool
		want    string // substring that must appear, "" = just !changed
	}{
		{"empty", "", false, ""},
		{"no cache", ".:53 {\n    forward . /etc/resolv.conf\n}\n", false, ""},
		{"comment is not a cache", ".:53 {\n    # cache 30\n    forward . x\n}\n", false, ""},
		{"denial commented counts as missing",
			".:53 {\n    cache 30 {\n        # denial 9984 5\n    }\n}\n", true, "denial 9984 5"},
		// A complete single-line block is still invalid Caddyfile —
		// `{` must be followed by a newline — so it is expanded even
		// though no directive is missing.
		{"complete inline block still expanded to multi-line",
			".:53 {\n    cache 30 { denial 9984 5 }\n}\n", true,
			"cache 30 {\n        denial 9984 5\n    }"},
		{"inline block without denial injected",
			".:53 {\n    cache 30 { success 9984 30 }\n}\n", true, "denial 9984 5"},
		{"two cache directives",
			".:53 {\n    cache 30\n}\ncluster.local:53 {\n    cache 60 {\n        denial 9984 5\n    }\n}\n",
			true, "cache 30 {\n        success 9984 30\n        denial 9984 5\n    }"},
		// --- comment-aware brace counting (#... stripped per line) ---
		// A `}` inside a trailing comment must NOT close the block:
		// `cache 30 { # note }` still opens a multi-line block whose
		// real close is the bare `}` below (the old depth counter read
		// the commented `}` and mis-tracked the block).
		{"brace inside trailing comment does not close",
			".:53 {\n    cache 30 { # note with a } brace\n        success 9984 30\n    }\n}\n",
			true, "denial 9984 5"},
		// A `# }` line inside the block must not close it either — the
		// block keeps scanning to the real close.
		{"comment-only close brace ignored",
			".:53 {\n    cache 30 {\n        # }\n        success 9984 30\n    }\n}\n",
			true, "denial 9984 5"},
		// A commented-out denial does not satisfy the check (already
		// covered above), and a `}` in that comment must not close.
		{"commented denial with brace ignored",
			".:53 {\n    cache 30 {\n        # denial 9984 5 }\n        success 9984 30\n    }\n}\n",
			true, "denial 9984 5"},
		// A bare cache directive with a trailing comment: the rewrite
		// keeps the note INSIDE the braces (after the `{` it would be
		// commented out of the Corefile entirely).
		{"bare cache with trailing comment",
			".:53 {\n    cache 30 # k0s default\n}\n",
			true, "cache 30 { # k0s default"},
		// An inline block whose trailing comment hides a `}`: the
		// injection targets the REAL closing brace, and the comment
		// text survives after it.
		{"inline injection with trailing comment",
			".:53 {\n    cache 30 { success 9984 30 } # tuned\n}\n",
			true, "} # tuned"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, changed := corefileCacheHeal(tc.in, "")
			if changed != tc.changed {
				t.Fatalf("changed=%v, want %v (out:\n%s)", changed, tc.changed, got)
			}
			if tc.changed && !strings.Contains(got, tc.want) {
				t.Fatalf("rewritten corefile missing %q:\n%s", tc.want, got)
			}
			if !tc.changed && got != tc.in {
				t.Fatal("unchanged corefile mutated")
			}
			// Every rewrite must itself be stable — second pass no-ops.
			again, againChanged := corefileCacheHeal(got, "")
			if againChanged || again != got {
				t.Fatalf("rewrite not idempotent: pass 2 changed=%v\n%s", againChanged, again)
			}
		})
	}
}

// A missing ConfigMap is tolerated (k0s owns it), and a get failure
// surfaces so the reconcile retries instead of leaving the cap off.
func TestCoreDNSPatcherCorefileAbsentAndGetError(t *testing.T) {
	cs := fake.NewSimpleClientset(corednsDeploy("DoNotSchedule", 2))
	r := &corednsPatcher{cs: cs, zoneWhen: "DoNotSchedule", minDomains: 2}
	if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err != nil {
		t.Fatalf("missing configmap must be tolerated: %v", err)
	}
	cs.PrependReactor("get", "configmaps",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err == nil {
		t.Fatal("expected error when the configmap get fails")
	}
}

func TestCoreDNSPatcherGetError(t *testing.T) {
	cs := fake.NewSimpleClientset(corednsDeployBare())
	cs.PrependReactor("get", "deployments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	r := &corednsPatcher{cs: cs, zoneWhen: "DoNotSchedule", minDomains: 2}
	if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err == nil {
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
	if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err == nil {
		t.Fatal("expected error when the drift patch fails")
	}
}

// Disabled must be a clean no-op — nothing registered, no error.
// Deps.Disabled is what setupModules stamps for
// COREDNS_PATCHER_ENABLED=false.
func TestSetupCoreDNSPatcherDisabled(t *testing.T) {
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{Name: "coredns-patcher", Mgr: m, CS: fake.NewSimpleClientset(),
		Dyn: testutil.StubDyn(), Disabled: true}); err != nil {
		t.Fatalf("disabled setup must return nil, got %v", err)
	}
	if len(m.Added) != 0 {
		t.Fatalf("disabled module registered %d runnables, want 0", len(m.Added))
	}
}

// The For() predicate (onlyCoreDNSDeployment — the exact predicate
// Setup installs) pins ns/name on top of the shared Deployment
// informer — only kube-system/coredns may reconcile.
func TestSetupCoreDNSPatcherPredicate(t *testing.T) {
	p := onlyCoreDNSDeployment
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

// The Node watch predicate (pinnedworkload.NodeCountChanges — the
// exact predicate.Funcs the conditional second watch installs when
// minReplicas>0) drives the proportional replica count: only
// create/delete may fire — includeUnschedulableNodes counts every
// Node object, so updates never change the total and would only add
// kubelet-heartbeat churn. The conditional registration of the watch
// itself is no longer asserted (it required introspecting
// controller-runtime internals).
func TestSetupCoreDNSPatcherNodeWatch(t *testing.T) {
	p := pinnedworkload.NodeCountChanges
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

// ---------------------------------------------------------------------------
// serve-stale — Corefile serve_stale <dur> immediate injection
// ---------------------------------------------------------------------------

// corefileCacheHealServeStale exercises the serve_stale knob across
// all three cache-block shapes: a bare directive expands with the
// window, an inline block gains only the missing directive, a
// multi-line block gains it on its own line — and every rewrite is
// idempotent on the second pass.
func TestCorefileCacheHealServeStale(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      string
		changed bool
		want    []string // substrings the rewrite must contain
		absent  []string // substrings it must NOT contain
	}{
		{"bare cache gains serve_stale",
			".:53 {\n    cache 30\n}\n", true,
			[]string{"cache 30 {", "success 9984 30", "denial 9984 5",
				"serve_stale 1h immediate"}, nil},
		{"bare cache keeps zone args",
			".:53 {\n    cache 30 cluster.local\n}\n", true,
			[]string{"cache 30 cluster.local {", "serve_stale 1h immediate"}, nil},
		{"inline block gains only serve_stale",
			".:53 {\n    cache 30 { success 9984 30 denial 9984 5 }\n}\n", true,
			[]string{"serve_stale 1h immediate"}, nil},
		{"inline block gains denial and serve_stale",
			".:53 {\n    cache 30 { success 9984 30 }\n}\n", true,
			[]string{"denial 9984 5", "serve_stale 1h immediate"}, nil},
		{"multi-line block gains serve_stale on own line",
			".:53 {\n    cache 30 {\n        success 9984 30\n        denial 9984 5\n    }\n}\n", true,
			[]string{"serve_stale 1h immediate"}, nil},
		{"existing serve_stale untouched — custom duration kept",
			".:53 {\n    cache 30 {\n        success 9984 30\n        denial 9984 5\n        serve_stale 30m\n    }\n}\n", false,
			nil, []string{"serve_stale 1h"}},
		{"commented serve_stale counts as missing",
			".:53 {\n    cache 30 {\n        # serve_stale 1h immediate\n        denial 9984 5\n    }\n}\n", true,
			[]string{"serve_stale 1h immediate"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, changed := corefileCacheHeal(tc.in, "1h")
			if changed != tc.changed {
				t.Fatalf("changed=%v, want %v:\n%s", changed, tc.changed, tc.in)
			}
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Fatalf("rewrite missing %q:\n%s", w, got)
				}
			}
			for _, a := range tc.absent {
				if strings.Contains(got, a) {
					t.Fatalf("rewrite unexpectedly contains %q:\n%s", a, got)
				}
			}
			if !changed && got != tc.in {
				t.Fatal("unchanged corefile mutated")
			}
			again, againChanged := corefileCacheHeal(got, "1h")
			if againChanged || again != got {
				t.Fatalf("serve_stale rewrite not idempotent: pass2 changed=%v\n%s",
					againChanged, again)
			}
		})
	}
}

// With the knob off ("" after corednsServeStale normalization) the
// heal still caps denial but never emits serve_stale — the
// COREDNS_SERVE_STALE_DURATION=off contract.
func TestCorefileCacheHealServeStaleDisabled(t *testing.T) {
	got, changed := corefileCacheHeal(".:53 {\n    cache 30\n}\n", "")
	if !changed {
		t.Fatal("denial heal did not fire with serve_stale disabled")
	}
	if strings.Contains(got, "serve_stale") {
		t.Fatalf("serve_stale emitted while disabled:\n%s", got)
	}
	if !strings.Contains(got, "denial 9984 5") {
		t.Fatalf("denial cap missing:\n%s", got)
	}
}

// corednsServeStale normalizes the knob: "0"/"off"/false-y spellings
// disable, real durations pass through, garbage warns and falls back
// to the 1h default rather than breaking the Corefile reload.
func TestCoreDNSServeStaleKnob(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{"1h", "1h"},
		{"30m", "30m"},
		{" 2h ", "2h"},
		{"0", ""},
		{"off", ""},
		{"OFF", ""},
		{"false", ""},
		{"", ""},
		{"banana", "1h"},
	} {
		if got := corednsServeStale(tc.in); got != tc.want {
			t.Fatalf("corednsServeStale(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Reconcile-level: a patcher carrying serveStale="1h" lands the
// serve_stale directive in the ConfigMap patch, and the healed
// Corefile is stable on the next reconcile.
func TestCoreDNSPatcherCorefileServeStale(t *testing.T) {
	cs := fake.NewSimpleClientset(corednsDeploy("DoNotSchedule", 2),
		corefileConfigMap(k0sCorefile))
	r := &corednsPatcher{cs: cs, zoneWhen: "DoNotSchedule", minDomains: 2,
		serveStale: "1h"}
	if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := getCorefile(t, cs)
	if !strings.Contains(got, "serve_stale 1h immediate") {
		t.Fatalf("corefile missing serve_stale:\n%s", got)
	}
	if !strings.Contains(got, "denial 9984 5") {
		t.Fatalf("corefile missing denial cap:\n%s", got)
	}
	if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if getCorefile(t, cs) != got {
		t.Fatal("serve_stale corefile rewritten again — not idempotent")
	}
}

// A Flux-owned ConfigMap that keeps getting reverted trips the
// heal.FluxPatchGate after fluxConflictLoopMax repeats — the
// reconcile must SKIP the patch (no write storm) rather than fight
// Git field-for-field.
func TestCoreDNSPatcherCorefileFluxLoopGate(t *testing.T) {
	heal.ConfigureFluxConflictLoop(3, 30*time.Minute)
	defer heal.ConfigureFluxConflictLoop(0, 0)

	fluxCM := corefileConfigMap(k0sCorefile)
	fluxCM.ManagedFields = []metav1.ManagedFieldsEntry{{
		Manager:    "helm-controller",
		Operation:  metav1.ManagedFieldsOperationApply,
		APIVersion: "v1",
		FieldsType: "FieldsV1",
	}}
	cs := fake.NewSimpleClientset(corednsDeploy("DoNotSchedule", 2), fluxCM)

	// Two allowed sightings on the same object key — the reconcile's
	// patch would be sighting #3 and must be denied.
	now := time.Now()
	for i := 0; i < 2; i++ {
		if !heal.FluxPatchGate("configmap", fluxCM, "kube-system/coredns", now) {
			t.Fatalf("sighting %d unexpectedly denied", i+1)
		}
	}

	r := &corednsPatcher{cs: cs, zoneWhen: "DoNotSchedule", minDomains: 2,
		serveStale: "1h"}
	if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := getCorefile(t, cs); got != k0sCorefile {
		t.Fatalf("flux-loop gate did not skip the corefile patch:\n%s", got)
	}
}

// corefileForwardHeal exercises the P1.7a forward max_concurrent
// injection across every Corefile forward shape: bare directive,
// inline block, multi-line block, declared value, and comments.
func TestCorefileForwardHeal(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      string
		changed bool
		want    []string
		absent  []string
	}{
		{"bare forward gains multi-line block",
			".:53 {\n    forward . /etc/resolv.conf\n}\n", true,
			[]string{"forward . /etc/resolv.conf {\n        max_concurrent 2000\n    }"}, nil},
		{"bare forward keeps trailing comment",
			".:53 {\n    forward . /etc/resolv.conf # upstream\n}\n", true,
			[]string{"forward . /etc/resolv.conf {\n        max_concurrent 2000\n    } # upstream"}, nil},
		{"inline block without option gains it",
			".:53 {\n    forward . 8.8.8.8 { policy sequential }\n}\n", true,
			[]string{"max_concurrent 2000"}, nil},
		{"complete inline block still expanded, value kept",
			".:53 {\n    forward . 8.8.8.8 { max_concurrent 500 }\n}\n", true,
			[]string{"forward . 8.8.8.8 {\n        max_concurrent 500\n    }"},
			[]string{"max_concurrent 2000"}},
		{"multi-line block gains directive before close",
			".:53 {\n    forward . 8.8.8.8 {\n        policy sequential\n    }\n}\n", true,
			[]string{"max_concurrent 2000"}, nil},
		{"multi-line block with option untouched",
			".:53 {\n    forward . 8.8.8.8 {\n        max_concurrent 750\n    }\n}\n", false,
			nil, nil},
		{"commented max_concurrent counts as missing",
			".:53 {\n    forward . 8.8.8.8 {\n        # max_concurrent 2000\n    }\n}\n", true,
			[]string{"max_concurrent 2000"}, nil},
		{"custom value honored",
			".:53 {\n    forward . /etc/resolv.conf\n}\n", true,
			[]string{"max_concurrent 4000"}, nil},
		{"no forward directive — untouched",
			".:53 {\n    cache 30\n}\n", false, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mc := "2000"
			if tc.name == "custom value honored" {
				mc = "4000"
			}
			got, changed := corefileForwardHeal(tc.in, mc)
			if changed != tc.changed {
				t.Fatalf("changed=%v, want %v:\n%s", changed, tc.changed, tc.in)
			}
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Fatalf("rewrite missing %q:\n%s", w, got)
				}
			}
			for _, a := range tc.absent {
				if strings.Contains(got, a) {
					t.Fatalf("rewrite unexpectedly contains %q:\n%s", a, got)
				}
			}
			if !changed && got != tc.in {
				t.Fatal("unchanged corefile mutated")
			}
			again, againChanged := corefileForwardHeal(got, mc)
			if againChanged || again != got {
				t.Fatalf("forward heal not idempotent: pass2 changed=%v\n%s",
					againChanged, again)
			}
		})
	}
}

// Caddyfile's Dispenser.NextBlock() requires a `\n` immediately after
// `{`. A bare forward OR any one-line `{ ... }` block (even one that
// already carries max_concurrent) must come out multi-line. Assert the
// whole rewritten Corefile, not just substrings, so a stray inline
// brace can never slip through.
func TestCorefileForwardHealEmitsMultilineBlocks(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
	}{
		{
			name: "bare forward",
			in:   ".:53 {\n    forward . /etc/resolv.conf\n}\n",
			want: ".:53 {\n    forward . /etc/resolv.conf {\n        max_concurrent 2000\n    }\n}\n",
		},
		{
			name: "complete single-line block",
			in:   ".:53 {\n    forward . /etc/resolv.conf { max_concurrent 2000 }\n}\n",
			want: ".:53 {\n    forward . /etc/resolv.conf {\n        max_concurrent 2000\n    }\n}\n",
		},
		{
			name: "single-line block with siblings",
			in:   ".:53 {\n    forward . 8.8.8.8 { policy sequential max_concurrent 2000 }\n}\n",
			want: ".:53 {\n    forward . 8.8.8.8 {\n        policy sequential\n        max_concurrent 2000\n    }\n}\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, changed := corefileForwardHeal(tc.in, "2000")
			if !changed {
				t.Fatal("expected a rewrite")
			}
			if got != tc.want {
				t.Fatalf("rewritten Corefile:\n%q\nwant:\n%q", got, tc.want)
			}
			for _, line := range strings.Split(got, "\n") {
				if i := strings.Index(line, "{"); i >= 0 &&
					strings.Contains(line[i:], "}") {
					t.Fatalf("single-line block survived: %q", line)
				}
			}
			again, againChanged := corefileForwardHeal(got, "2000")
			if againChanged || again != got {
				t.Fatalf("rewrite not idempotent: pass2 changed=%v\n%s",
					againChanged, again)
			}
		})
	}
}

// corednsMaxConcurrent validates the knob: positive integers pass
// through normalized, everything else warns and falls back to 2000 —
// the value lands verbatim in the Corefile.
func TestCoreDNSMaxConcurrentKnob(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"2000", "2000"},
		{" 4000 ", "4000"},
		{"0", "2000"},
		{"-5", "2000"},
		{"banana", "2000"},
		{"", "2000"},
	} {
		if got := corednsMaxConcurrent(tc.in); got != tc.want {
			t.Fatalf("corednsMaxConcurrent(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// While the saturation boost is live the 15m safety-net requeue is
// replaced by one timed at the stamp's exact expiry, so the patcher
// releases the surge the moment the window lapses instead of up to
// 15m late.
func TestCoreDNSPatcherRequeuesAtBoostExpiry(t *testing.T) {
	until := time.Now().Add(10 * time.Minute).UTC()
	d := corednsDeploy("DoNotSchedule", 2)
	d.Annotations = map[string]string{
		kube.AnnoCoreDNSBoostUntil: until.Format(time.RFC3339),
		kube.AnnoCoreDNSBoostBase:  "4",
	}
	cs := fake.NewSimpleClientset(d)
	r := &corednsPatcher{cs: cs, zoneWhen: "DoNotSchedule", minDomains: 2,
		minReplicas: 4, nodesPerReplica: 1, boostReplicas: 2}
	res, err := r.Reconcile(t.Context(), reconcile.Request{})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	want := time.Until(until)
	if res.RequeueAfter < want-time.Minute || res.RequeueAfter > want+time.Minute {
		t.Fatalf("requeue = %s, want boost expiry in ~%s (not the 15m safety net)",
			res.RequeueAfter, want)
	}
	// The surge is still pinned while the stamp is fresh.
	got := getCorednsDeploy(t, cs)
	if got.Spec.Replicas == nil || *got.Spec.Replicas != 6 {
		t.Fatalf("replicas = %v, want 6 (4 + boost 2)", got.Spec.Replicas)
	}
	if got.Annotations[kube.AnnoCoreDNSBoostUntil] == "" ||
		got.Annotations[kube.AnnoCoreDNSBoostBase] != "4" {
		t.Fatal("live boost stamps must survive the reconcile")
	}
}

// A boost window LONGER than the 15m safety net must not push the
// requeue out: keeping the shorter timer releases the surge at the
// safety-net tick instead of 15m past it.
func TestCoreDNSPatcherBoostExpiryDoesNotExtendSafetyNet(t *testing.T) {
	until := time.Now().Add(30 * time.Minute).UTC()
	d := corednsDeploy("DoNotSchedule", 2)
	d.Annotations = map[string]string{
		kube.AnnoCoreDNSBoostUntil: until.Format(time.RFC3339),
		kube.AnnoCoreDNSBoostBase:  "4",
	}
	cs := fake.NewSimpleClientset(d)
	r := &corednsPatcher{cs: cs, zoneWhen: "DoNotSchedule", minDomains: 2,
		minReplicas: 4, nodesPerReplica: 1, boostReplicas: 2}
	res, err := r.Reconcile(t.Context(), reconcile.Request{})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter < 13*time.Minute+30*time.Second ||
		res.RequeueAfter > 16*time.Minute+30*time.Second {
		t.Fatalf("requeue = %s, want the 15m safety net (boost expiry is 30m out)",
			res.RequeueAfter)
	}
}

// A lapsed boost window clears BOTH stamps in one metadata patch —
// leaving the base behind would make the next boost compound on top
// of a stale pre-boost count.
func TestCoreDNSPatcherClearsExpiredBoostStamps(t *testing.T) {
	until := time.Now().Add(-time.Minute).UTC()
	d := corednsDeploy("DoNotSchedule", 2)
	d.Spec.Replicas = ptr.To(int32(6)) // the now-expired surge
	d.Annotations = map[string]string{
		kube.AnnoCoreDNSBoostUntil: until.Format(time.RFC3339),
		kube.AnnoCoreDNSBoostBase:  "4",
	}
	cs := fake.NewSimpleClientset(d)
	r := &corednsPatcher{cs: cs, zoneWhen: "DoNotSchedule", minDomains: 2,
		minReplicas: 4, nodesPerReplica: 1, boostReplicas: 2}
	if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := getCorednsDeploy(t, cs)
	if _, ok := got.Annotations[kube.AnnoCoreDNSBoostUntil]; ok {
		t.Fatal("expired boost-until stamp was not cleared")
	}
	if _, ok := got.Annotations[kube.AnnoCoreDNSBoostBase]; ok {
		t.Fatal("expired boost-base stamp was not cleared")
	}
	if got.Spec.Replicas == nil || *got.Spec.Replicas != 4 {
		t.Fatalf("replicas = %v, want 4 (surge released)", got.Spec.Replicas)
	}
}

// corednsEffectiveReplicas applies the saturation boost only while
// the boost-until stamp is fresh and the replica pin is enabled.
func TestCoreDNSEffectiveReplicas(t *testing.T) {
	now := time.Now()
	fresh := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Annotations: map[string]string{
			kube.AnnoCoreDNSBoostUntil: now.Add(10 * time.Minute).UTC().Format(time.RFC3339),
		}}}
	stale := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Annotations: map[string]string{
			kube.AnnoCoreDNSBoostUntil: now.Add(-time.Minute).UTC().Format(time.RFC3339),
		}}}
	for _, tc := range []struct {
		name         string
		want, boost  int32
		d            *appsv1.Deployment
		wantReplicas int32
	}{
		{"boost active adds replicas", 4, 2, fresh, 6},
		{"expired stamp no boost", 4, 2, stale, 4},
		{"no stamp no boost", 4, 2, &appsv1.Deployment{}, 4},
		{"disabled pin never boosted", 0, 2, fresh, 0},
		{"zero boost replicas no-op", 4, 0, fresh, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := corednsEffectiveReplicas(tc.want, tc.boost, tc.d, now); got != tc.wantReplicas {
				t.Fatalf("corednsEffectiveReplicas = %d, want %d", got, tc.wantReplicas)
			}
		})
	}
}

type stubCoreDNSReader struct {
	dep *appsv1.Deployment
}

func (s stubCoreDNSReader) Get(_ context.Context, _ client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
	out := obj.(*appsv1.Deployment)
	*out = *s.dep.DeepCopy()
	return nil
}

func TestClearExpiredBoostUsesCachedReaderInSteadyState(t *testing.T) {
	cs := fake.NewSimpleClientset(corednsDeploy("DoNotSchedule", 2))
	var gets int
	cs.PrependReactor("get", "deployments", func(ktesting.Action) (bool, runtime.Object, error) {
		gets++
		return false, nil, nil
	})
	r := &corednsPatcher{
		cs:     cs,
		reader: stubCoreDNSReader{dep: corednsDeploy("DoNotSchedule", 2)},
	}
	if err := r.clearExpiredBoost(t.Context(), time.Now()); err != nil {
		t.Fatalf("clearExpiredBoost steady-state: %v", err)
	}
	if gets != 0 {
		t.Fatalf("steady-state clearExpiredBoost issued %d direct Deployment GETs, want 0", gets)
	}
}
