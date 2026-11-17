// apiserver_write_storm_test.go — coverage for the
// apiserver-write-storm-breaker check: the client/resource
// offender labels, the 10-minute persistence window, the heal
// sub-gate (detect-only still emits gauge+event), the per-pass
// suspend cap, exempt/already-suspended/non-Ready filtering, and
// the stamped-only restore.
package watchdogs

import (
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// stormDeps wires Deps to a fake Prometheus answering the three
// signature queries: rate/p99 scalars plus the topk offender list.
func stormDeps(t *testing.T, rate, p99 float64,
	top []probetest.PromTestSample) (*probefw.Deps, *unstructured.Unstructured) {

	t.Helper()
	srv, _ := probetest.PromTestServer(t,
		func(query string) []probetest.PromTestSample {
			switch {
			case strings.Contains(query, "histogram_quantile"):
				return []probetest.PromTestSample{{Value: p99}}
			case strings.Contains(query, "topk"):
				return top
			default:
				return []probetest.PromTestSample{{Value: rate}}
			}
		})
	cs := fake.NewSimpleClientset()
	d := probetest.NewDeps(cs, probetest.OpDyn())
	d.Cfg.HTTPContent.URL = srv.URL
	d.HTTPClient = srv.Client()
	return d, nil
}

// stormCheck builds the check with heals armed — the fixture
// maintenance verdict is permissive like every other heal test.
func stormCheck(d *probefw.Deps, heal bool) *apiserverWriteStormCheck {
	return &apiserverWriteStormCheck{Deps: d, reliefDue: true, healEnabled: heal}
}

// fluxKS builds a Ready Kustomization in the given namespace.
func fluxKS(ns, name string, suspend bool, annos map[string]string,
	ready bool) *unstructured.Unstructured {

	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "kustomize.toolkit.fluxcd.io/v1",
		"kind":       "Kustomization",
		"metadata": map[string]any{
			"namespace": ns, "name": name,
		},
		"spec": map[string]any{"suspend": suspend},
	}}
	if annos != nil {
		am := map[string]any{}
		for k, v := range annos {
			am[k] = v
		}
		u.Object["metadata"].(map[string]any)["annotations"] = am
	}
	status := "False"
	if ready {
		status = "True"
	}
	_ = unstructured.SetNestedSlice(u.Object, []any{
		map[string]any{"type": "Ready", "status": status},
	}, "status", "conditions")
	return u
}

func TestWriteStormPersistenceWindow(t *testing.T) {
	top := []probetest.PromTestSample{
		{Labels: map[string]string{"client": "popeye", "resource": "pods"}, Value: 42},
	}
	d, _ := stormDeps(t, 50, 3, top)
	ch := stormCheck(d, false) // detect-only — no flux census needed
	base := time.Now()

	probetest.FreezeNow(d, base)
	if res := ch.Run(probetest.SweepCtx(ctx)); !res.Pass {
		t.Fatalf("first breaching sweep must pass inside window: %+v", res)
	}
	probetest.FreezeNow(d, base.Add(writeStormMinAge-time.Minute))
	if res := ch.Run(probetest.SweepCtx(ctx)); !res.Pass {
		t.Fatalf("inside window must pass: %+v", res)
	}
	probetest.FreezeNow(d, base.Add(writeStormMinAge+time.Minute))
	res := ch.Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatal("storm past the window must fail the sweep")
	}
	// The offender pair must be labelled by client+resource — the
	// "user" label regression reported every offender as "-/x".
	m := probetest.FindMetric(t, "node_automation_apiserver_write_storm",
		map[string]string{"client": "popeye", "resource": "pods"})
	if m == nil {
		t.Fatal("offender gauge missing client/resource labels")
	}
}

func TestWriteStormHealDisabledStillDetects(t *testing.T) {
	// healEnabled=false: the gauge + finding fire but NO Flux
	// object may be patched — detect-only mode.
	top := []probetest.PromTestSample{
		{Labels: map[string]string{"client": "flux", "resource": "kustomizations"}, Value: 9},
	}
	srv, _ := probetest.PromTestServer(t,
		func(query string) []probetest.PromTestSample {
			switch {
			case strings.Contains(query, "histogram_quantile"):
				return []probetest.PromTestSample{{Value: 3}}
			case strings.Contains(query, "topk"):
				return top
			default:
				return []probetest.PromTestSample{{Value: 50}}
			}
		})
	ks := fluxKS("apps", "stormed", false, nil, true)
	cs := fake.NewSimpleClientset()
	dyn := probetest.OpDyn(ks)
	d := probetest.NewDeps(cs, dyn)
	d.Cfg.HTTPContent.URL = srv.URL
	d.HTTPClient = srv.Client()
	probetest.FreezeNow(d, time.Now())

	ch := stormCheck(d, false)
	// Age the signature past the window directly through the
	// ledger — two sweeps 11m apart.
	base := time.Now()
	probetest.FreezeNow(d, base)
	ch.Run(probetest.SweepCtx(ctx))
	probetest.FreezeNow(d, base.Add(writeStormMinAge+time.Minute))
	res := ch.Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatal("storm past window must fail even with heals off")
	}
	got, err := dyn.Resource(kube.GVRFluxKustomization).
		Namespace("apps").Get(ctx, "stormed", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get kustomization: %v", err)
	}
	if susp, _, _ := unstructured.NestedBool(got.Object, "spec", "suspend"); susp {
		t.Fatal("heal-disabled check suspended a Flux object")
	}
}

func TestWriteStormSuspendEligibilityAndCap(t *testing.T) {
	// 12 eligible Ready Kustomizations + decoys: one in flux-system
	// (exempt NS), one already suspended, one Ready=False, one
	// carrying the exempt annotation. The cap must hold at 10.
	ksList := []*unstructured.Unstructured{}
	for i := 0; i < 12; i++ {
		ksList = append(ksList, fluxKS("apps", "ks-"+string(rune('a'+i)), false, nil, true))
	}
	ksList = append(ksList,
		fluxKS("flux-system", "core", false, nil, true), // exempt NS
		fluxKS("apps", "hands-off", false, map[string]string{kube.AnnoWriteStormExempt: "true"}, true),
		fluxKS("apps", "not-ready", false, nil, false),   // Ready=False
		fluxKS("apps", "pre-suspended", true, nil, true), // already suspended
	)
	var dynObjs []runtime.Object
	for _, u := range ksList {
		dynObjs = append(dynObjs, runtime.Object(u))
	}
	dyn := probetest.OpDyn(dynObjs...)
	d, _ := stormDeps(t, 50, 3, nil)
	d.Dyn = dyn
	probetest.FreezeNow(d, time.Now())
	ch := stormCheck(d, true)

	base := time.Now()
	probetest.FreezeNow(d, base)
	ch.Run(probetest.SweepCtx(ctx))
	probetest.FreezeNow(d, base.Add(writeStormMinAge+time.Minute))
	ch.Run(probetest.SweepCtx(ctx))

	suspended := 0
	for _, u := range ksList {
		if u.GetName() == "pre-suspended" {
			continue // already down before the storm — not our patch
		}
		got, err := dyn.Resource(kube.GVRFluxKustomization).
			Namespace(u.GetNamespace()).Get(ctx, u.GetName(), metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get %s/%s: %v", u.GetNamespace(), u.GetName(), err)
		}
		susp, _, _ := unstructured.NestedBool(got.Object, "spec", "suspend")
		if !susp {
			continue
		}
		suspended++
		stamp := kube.EffectiveAnno(ctx, got, kube.AnnoWriteStormSuspendedBy)
		if stamp == "" {
			t.Fatalf("%s/%s suspended without the check stamp",
				u.GetNamespace(), u.GetName())
		}
	}
	if suspended != writeStormMaxSuspends {
		t.Fatalf("suspended=%d want cap %d", suspended, writeStormMaxSuspends)
	}
	// The exempt-NS, exempt-anno and non-Ready objects must be
	// untouched — no suspend patch, no stamp.
	for _, name := range []string{"core", "hands-off", "not-ready"} {
		var ns string
		if name == "core" {
			ns = "flux-system"
		} else {
			ns = "apps"
		}
		got, _ := dyn.Resource(kube.GVRFluxKustomization).
			Namespace(ns).Get(ctx, name, metav1.GetOptions{})
		annos, _, _ := unstructured.NestedStringMap(got.Object, "metadata", "annotations")
		if _, stamped := annos[kube.AnnoWriteStormSuspendedBy]; stamped && name != "pre-suspended" {
			t.Fatalf("%s/%s must not carry the storm stamp", ns, name)
		}
	}
}

func TestWriteStormRestoreOnlyStamped(t *testing.T) {
	// A storm-suspended object (stamp present) restores on
	// recovery; a hand-suspended object (no stamp) stays down.
	stamped := fluxKS("apps", "was-stormed", true,
		map[string]string{kube.AnnoWriteStormSuspendedBy: "2025-01-01T00:00:00Z"}, true)
	hand := fluxKS("apps", "hand-suspended", true, nil, true)
	dyn := probetest.OpDyn(stamped, hand)
	d, _ := stormDeps(t, 0, 0, nil) // no storm — recovery path
	d.Dyn = dyn
	ch := stormCheck(d, true)
	// Arm the suspended flag the way a prior storm would have.
	ch.suspended = true
	ch.reliefDue = true

	res := ch.Run(probetest.SweepCtx(ctx))
	if !res.Pass {
		t.Fatalf("clean sweep must pass: %+v", res)
	}
	got, _ := dyn.Resource(kube.GVRFluxKustomization).
		Namespace("apps").Get(ctx, "was-stormed", metav1.GetOptions{})
	if susp, _, _ := unstructured.NestedBool(got.Object, "spec", "suspend"); susp {
		t.Fatal("stamped object was not restored after storm cleared")
	}
	got, _ = dyn.Resource(kube.GVRFluxKustomization).
		Namespace("apps").Get(ctx, "hand-suspended", metav1.GetOptions{})
	if susp, _, _ := unstructured.NestedBool(got.Object, "spec", "suspend"); !susp {
		t.Fatal("hand-suspended object was resurrected — restore must be stamped-only")
	}
}
