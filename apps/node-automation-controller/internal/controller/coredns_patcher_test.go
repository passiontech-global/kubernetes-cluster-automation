package controller

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

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
								corev1.ResourceCPU:    resource.MustParse("300m"),
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

// forbidDeployPatch records any patch attempt on deployments — the
// probe for "reconcile must not patch".
func forbidDeployPatch(cs *fake.Clientset, patched *bool) {
	cs.PrependReactor("patch", "deployments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			*patched = true
			return true, nil, nil
		})
}

// captureDeployPatch records the patch body but lets the default
// reactor apply it to the tracker.
func captureDeployPatch(cs *fake.Clientset, got *[]byte) {
	cs.PrependReactor("patch", "deployments",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			*got = a.(ktesting.PatchAction).GetPatch()
			return false, nil, nil
		})
}

func TestCorednsNeedsPatch(t *testing.T) {
	mutate := func(fn func(*appsv1.Deployment)) *appsv1.Deployment {
		d := corednsDeploy("DoNotSchedule", 2)
		fn(d)
		return d
	}
	for _, tc := range []struct {
		name       string
		d          *appsv1.Deployment
		zoneWhen   string
		minDomains int
		drifted    bool
	}{
		{"k0s baseline", corednsDeployBare(), "DoNotSchedule", 2, true},
		{"fully pinned", corednsDeploy("DoNotSchedule", 2), "DoNotSchedule", 2, false},
		{"single-zone config fully pinned",
			corednsDeploy("ScheduleAnyway", 0), "ScheduleAnyway", 0, false},
		{"missing coredns container", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Containers = nil
		}), "DoNotSchedule", 2, true},
		{"nil probes", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Containers[0].LivenessProbe = nil
		}), "DoNotSchedule", 2, true},
		{"probe timeout drifted", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Containers[0].ReadinessProbe.TimeoutSeconds = 1
		}), "DoNotSchedule", 2, true},
		{"request cpu drifted", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Containers[0].Resources.Requests[corev1.ResourceCPU] =
				resource.MustParse("10m")
		}), "DoNotSchedule", 2, true},
		{"limit memory drifted", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Containers[0].Resources.Limits[corev1.ResourceMemory] =
				resource.MustParse("128Mi")
		}), "DoNotSchedule", 2, true},
		{"anti-affinity back", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Affinity = &corev1.Affinity{}
		}), "DoNotSchedule", 2, true},
		{"zone whenUnsatisfiable drifted", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.TopologySpreadConstraints[0].WhenUnsatisfiable =
				corev1.ScheduleAnyway
		}), "DoNotSchedule", 2, true},
		{"minDomains drifted", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.TopologySpreadConstraints[0].MinDomains = ptr.To(int32(1))
		}), "DoNotSchedule", 2, true},
		{"minDomains lost", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.TopologySpreadConstraints[0].MinDomains = nil
		}), "DoNotSchedule", 2, true},
		{"taints policy not Honor", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.TopologySpreadConstraints[0].NodeTaintsPolicy = nil
		}), "DoNotSchedule", 2, true},
		{"hostname constraint missing", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.TopologySpreadConstraints =
				d.Spec.Template.Spec.TopologySpreadConstraints[:1]
		}), "DoNotSchedule", 2, true},
		{"wrong selector", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.TopologySpreadConstraints[1].LabelSelector.MatchLabels =
				map[string]string{"k8s-app": "other"}
		}), "DoNotSchedule", 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := corednsNeedsPatch(tc.d, tc.zoneWhen, tc.minDomains); got != tc.drifted {
				t.Fatalf("corednsNeedsPatch=%v, want %v", got, tc.drifted)
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
	captureDeployPatch(cs, &got)

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
	if corednsNeedsPatch(getCorednsDeploy(t, cs), "DoNotSchedule", 2) {
		t.Fatal("deployment still drifted after patch")
	}
}

// cicd config (single zone): the patch must carry an explicit
// "minDomains": null on the zone constraint — strategic merge keeps a
// stale minDomains from a previous DoNotSchedule patch otherwise, and
// the API rejects the merged result under ScheduleAnyway.
func TestCoreDNSPatcherNullsMinDomainsOnScheduleAnyway(t *testing.T) {
	cs := fake.NewSimpleClientset(corednsDeployBare())
	var got []byte
	captureDeployPatch(cs, &got)

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
	cs := fake.NewSimpleClientset(corednsDeploy("DoNotSchedule", 2))
	var patched bool
	forbidDeployPatch(cs, &patched)

	r := &corednsPatcher{cs: cs, zoneWhen: "DoNotSchedule", minDomains: 2}
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
	m := newStubManager()
	if err := SetupCoreDNSPatcher(m, fake.NewSimpleClientset(),
		false, "DoNotSchedule", 2); err != nil {
		t.Fatalf("disabled setup must return nil, got %v", err)
	}
	if len(m.added) != 0 {
		t.Fatalf("disabled module registered %d runnables, want 0", len(m.added))
	}
}

// The predicate pins ns/name on top of the shared Deployment
// informer — only kube-system/coredns may reconcile.
func TestSetupCoreDNSPatcherPredicate(t *testing.T) {
	p := forPredicate(t, func(m manager.Manager) error {
		return SetupCoreDNSPatcher(m, fake.NewSimpleClientset(),
			true, "DoNotSchedule", 2)
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
