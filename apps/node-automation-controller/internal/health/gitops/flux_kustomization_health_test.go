// flux_kustomization_health_test.go — the flux-stuck Flux Kustomization
// stuck detector + reconcile nudger driven through the fake clientset
// + fake dynamic client.
package gitops

import (
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// ---------------------------------------------------------------------------
// flux-stuck — flux Kustomization stuck detector + requestedAt nudge
// ---------------------------------------------------------------------------

// shKust builds a Kustomization carrying a Ready condition at `since`.
func shKust(ns, name, status, reason string, since time.Time) *unstructured.Unstructured {
	k := probetest.UnstructuredObj("kustomize.toolkit.fluxcd.io/v1", "Kustomization",
		ns, name, 5, 3)
	_ = unstructured.SetNestedSlice(k.Object, []any{
		map[string]any{
			"type":               "Ready",
			"status":             status,
			"reason":             reason,
			"message":            "reconciliation failed",
			"lastTransitionTime": since.UTC().Format(time.RFC3339),
		},
	}, "status", "conditions")
	return k
}

// readyDeploy builds a Deployment reporting ready replicas.
func readyDeploy(ns, name string, replicas, ready int32) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       appsv1.DeploymentSpec{Replicas: &replicas},
		Status:     appsv1.DeploymentStatus{ReadyReplicas: ready},
	}
}

var fluxKustGVR = kube.GVRFluxKustomization

// A Kustomization parked Ready=False/ArtifactFailed for 20m gets the
// requestedAt nudge and the check FAILs.
func TestFluxKustHealthPatchesStuck(t *testing.T) {
	base := time.Now()
	k := shKust("flux-system", "apps", "False", "ArtifactFailed",
		base.Add(-20*time.Minute))
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(k))
	p.Now = func() time.Time { return base }

	res := probetest.MustCheck[*fluxKustomizationHealthCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("stuck Kustomization must FAIL")
	}
	got, err := p.Dyn.Resource(fluxKustGVR).Namespace("flux-system").
		Get(ctx, "apps", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	v, found, _ := unstructured.NestedString(
		got.Object, "metadata", "annotations", kube.AnnoFluxRequestedAt)
	if !found || v == "" {
		t.Fatalf("requestedAt not stamped: %v", got.GetAnnotations())
	}
}

// A failure younger than 15m is still inside the controller's retry
// window — quiet.
func TestFluxKustHealthFreshQuiet(t *testing.T) {
	base := time.Now()
	k := shKust("flux-system", "apps", "False", "ArtifactFailed",
		base.Add(-5*time.Minute))
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(k))
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*fluxKustomizationHealthCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("fresh failure must pass: %+v", res)
	}
}

// A dependsOn Kustomization that is itself not Ready blocks the
// nudge — detection still FAILs.
func TestFluxKustHealthDepNotReady(t *testing.T) {
	base := time.Now()
	k := shKust("flux-system", "apps", "False", "ArtifactFailed",
		base.Add(-20*time.Minute))
	_ = unstructured.SetNestedSlice(k.Object, []any{
		map[string]any{"name": "upstream"},
	}, "spec", "dependsOn")
	dep := shKust("flux-system", "upstream", "False", "ArtifactFailed",
		base.Add(-time.Hour))
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(k, dep))
	p.Now = func() time.Time { return base }

	res := probetest.MustCheck[*fluxKustomizationHealthCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("stuck Kustomization must FAIL even when nudge is deferred")
	}
	got, _ := p.Dyn.Resource(fluxKustGVR).Namespace("flux-system").
		Get(ctx, "apps", metav1.GetOptions{})
	if _, found, _ := unstructured.NestedString(
		got.Object, "metadata", "annotations", kube.AnnoFluxRequestedAt); found {
		t.Fatal("nudge applied despite unready dependsOn")
	}
}

// A Ready dependsOn chain admits the nudge.
func TestFluxKustHealthDepReady(t *testing.T) {
	base := time.Now()
	k := shKust("flux-system", "apps", "False", "SourceNotReady",
		base.Add(-20*time.Minute))
	_ = unstructured.SetNestedSlice(k.Object, []any{
		map[string]any{"name": "upstream"},
	}, "spec", "dependsOn")
	dep := shKust("flux-system", "upstream", "True", "ReconciliationSucceeded",
		base.Add(-time.Hour))
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(k, dep))
	p.Now = func() time.Time { return base }

	res := probetest.MustCheck[*fluxKustomizationHealthCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("stuck Kustomization must FAIL")
	}
	got, _ := p.Dyn.Resource(fluxKustGVR).Namespace("flux-system").
		Get(ctx, "apps", metav1.GetOptions{})
	if _, found, _ := unstructured.NestedString(
		got.Object, "metadata", "annotations", kube.AnnoFluxRequestedAt); !found {
		t.Fatal("nudge not applied with Ready dependsOn")
	}
}

// HealthCheckFailed with the applied Deployment actually Ready gets
// nudged; with it still unready, detection stands but no nudge fires.
func TestFluxKustHealthCheckFailedGate(t *testing.T) {
	base := time.Now()
	mk := func() *unstructured.Unstructured {
		k := shKust("flux-system", "apps", "False", "HealthCheckFailed",
			base.Add(-20*time.Minute))
		_ = unstructured.SetNestedSlice(k.Object, []any{
			map[string]any{"id": "apps_web_apps_Deployment", "v": "v1"},
		}, "status", "inventory", "entries")
		return k
	}

	// Workload ready → nudge lands.
	p := testProberDyn(
		fake.NewSimpleClientset(readyDeploy("apps", "web", 2, 2)),
		probetest.OpDyn(mk()))
	p.Now = func() time.Time { return base }
	if res := probetest.MustCheck[*fluxKustomizationHealthCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("stuck Kustomization must FAIL")
	}
	got, _ := p.Dyn.Resource(fluxKustGVR).Namespace("flux-system").
		Get(ctx, "apps", metav1.GetOptions{})
	if _, found, _ := unstructured.NestedString(
		got.Object, "metadata", "annotations", kube.AnnoFluxRequestedAt); !found {
		t.Fatal("HealthCheckFailed with ready workloads should be nudged")
	}

	// Workload unready → no nudge.
	p = testProberDyn(
		fake.NewSimpleClientset(readyDeploy("apps", "web", 2, 0)),
		probetest.OpDyn(mk()))
	p.Now = func() time.Time { return base }
	if res := probetest.MustCheck[*fluxKustomizationHealthCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("stuck Kustomization must FAIL")
	}
	got, _ = p.Dyn.Resource(fluxKustGVR).Namespace("flux-system").
		Get(ctx, "apps", metav1.GetOptions{})
	if _, found, _ := unstructured.NestedString(
		got.Object, "metadata", "annotations", kube.AnnoFluxRequestedAt); found {
		t.Fatal("HealthCheckFailed with unready workloads must not be nudged")
	}
}

// Non-nudgeable reasons emit but never patch.
func TestFluxKustHealthOtherReasonNoNudge(t *testing.T) {
	base := time.Now()
	k := shKust("flux-system", "apps", "False", "ValidationFailed",
		base.Add(-time.Hour))
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(k))
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*fluxKustomizationHealthCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("stuck Kustomization must FAIL")
	}
	got, _ := p.Dyn.Resource(fluxKustGVR).Namespace("flux-system").
		Get(ctx, "apps", metav1.GetOptions{})
	if _, found, _ := unstructured.NestedString(
		got.Object, "metadata", "annotations", kube.AnnoFluxRequestedAt); found {
		t.Fatal("ValidationFailed must not be nudged")
	}
}

// The 30m cooldown: a second sweep inside the window must not
// re-patch — the requestedAt stamp is the durable half.
func TestFluxKustHealthCooldown(t *testing.T) {
	base := time.Now()
	k := shKust("flux-system", "apps", "False", "ArtifactFailed",
		base.Add(-time.Hour))
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(k))
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*fluxKustomizationHealthCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("precondition: stuck Kustomization must FAIL")
	}
	first, _ := p.Dyn.Resource(fluxKustGVR).Namespace("flux-system").
		Get(ctx, "apps", metav1.GetOptions{})
	firstToken, _, _ := unstructured.NestedString(
		first.Object, "metadata", "annotations", kube.AnnoFluxRequestedAt)

	p.Now = func() time.Time { return base.Add(10 * time.Minute) }
	if res := probetest.MustCheck[*fluxKustomizationHealthCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("still-stuck Kustomization must keep FAILING")
	}
	got, _ := p.Dyn.Resource(fluxKustGVR).Namespace("flux-system").
		Get(ctx, "apps", metav1.GetOptions{})
	token, _, _ := unstructured.NestedString(
		got.Object, "metadata", "annotations", kube.AnnoFluxRequestedAt)
	if token != firstToken {
		t.Fatal("re-patched inside the 30m cooldown")
	}
}

// Suspended and Ready objects are quiet; an absent CRD is a pass.
func TestFluxKustHealthQuiet(t *testing.T) {
	base := time.Now()
	k := shKust("flux-system", "apps", "False", "ArtifactFailed",
		base.Add(-time.Hour))
	_ = unstructured.SetNestedField(k.Object, true, "spec", "suspend")
	ok := shKust("flux-system", "fine", "True", "ReconciliationSucceeded",
		base.Add(-time.Hour))
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(k, ok))
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*fluxKustomizationHealthCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("suspended/ready Kustomizations must pass: %+v", res)
	}
	p2 := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn())
	if res := probetest.MustCheck[*fluxKustomizationHealthCheck](t, p2).Run(ctx); !res.Pass {
		t.Fatalf("empty flux tree must pass: %+v", res)
	}
}

// The emitted series carries the stuck tuple.
func TestFluxKustHealthGaugeEmitted(t *testing.T) {
	base := time.Now()
	k := shKust("flux-system", "apps", "False", "ArtifactFailed",
		base.Add(-time.Hour))
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(k))
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*fluxKustomizationHealthCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("precondition: must FAIL")
	}
	m := probetest.FindMetric(t, "node_automation_flux_kustomization_stuck",
		map[string]string{"namespace": "flux-system", "name": "apps", "reason": "ArtifactFailed"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("stuck gauge missing: %v", m)
	}
}

// ---------------------------------------------------------------------------
// double-remediation guard — consumer defers while the source nudge
// (helmrelease-unlocker's last-source-nudge) is fresh
// ---------------------------------------------------------------------------

// shKustSourced builds a stuck ArtifactFailed Kustomization carrying
// a spec.sourceRef, plus its GitRepository source with the given
// last-source-nudge stamp (nil → none).
func shKustSourced(base time.Time, stamp *time.Time) (*unstructured.Unstructured, *unstructured.Unstructured) {
	k := shKust("flux-system", "apps", "False", "ArtifactFailed",
		base.Add(-20*time.Minute))
	_ = unstructured.SetNestedMap(k.Object, map[string]any{
		"kind": "GitRepository", "name": "repo",
	}, "spec", "sourceRef")
	repo := probetest.UnstructuredObj("source.toolkit.fluxcd.io/v1", "GitRepository",
		"flux-system", "repo", 1, 1)
	if stamp != nil {
		repo.SetAnnotations(map[string]string{
			kube.AnnoLastSourceNudge: stamp.UTC().Format(time.RFC3339)})
	}
	return k, repo
}

// (b) The artifact-fail signature with a FRESH last-source-nudge on
// the source: the consumer defers — detection still FAILs, but no
// requestedAt lands on the Kustomization.
func TestFluxKustHealthDefersOnFreshSourceNudge(t *testing.T) {
	base := time.Now()
	k, repo := shKustSourced(base, ptrTime(base.Add(-5*time.Minute)))
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(k, repo))
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*fluxKustomizationHealthCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("deferred Kustomization must still FAIL detection")
	}
	got, _ := p.Dyn.Resource(fluxKustGVR).Namespace("flux-system").
		Get(ctx, "apps", metav1.GetOptions{})
	if _, found, _ := unstructured.NestedString(
		got.Object, "metadata", "annotations", kube.AnnoFluxRequestedAt); found {
		t.Fatal("consumer nudged while the source nudge is fresh — must defer")
	}
}

// The artifact-fail signature with a STALE (or absent) source nudge:
// the consumer nudges as before.
func TestFluxKustHealthNudgesWhenSourceNudgeStale(t *testing.T) {
	base := time.Now()
	for name, stamp := range map[string]*time.Time{
		"no stamp":    nil,
		"stale stamp": ptrTime(base.Add(-45 * time.Minute)),
	} {
		t.Run(name, func(t *testing.T) {
			k, repo := shKustSourced(base, stamp)
			p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(k, repo))
			p.Now = func() time.Time { return base }

			if res := probetest.MustCheck[*fluxKustomizationHealthCheck](t, p).Run(ctx); res.Pass {
				t.Fatal("stuck Kustomization must FAIL")
			}
			got, _ := p.Dyn.Resource(fluxKustGVR).Namespace("flux-system").
				Get(ctx, "apps", metav1.GetOptions{})
			if _, found, _ := unstructured.NestedString(
				got.Object, "metadata", "annotations", kube.AnnoFluxRequestedAt); !found {
				t.Fatal("consumer must nudge when the source nudge is not fresh")
			}
		})
	}
}

// (c) Non-artifact reasons are never deferred by a fresh source
// nudge — HealthCheckFailed with provably-Ready workloads still gets
// the consumer-side requestedAt nudge even when the source carries a
// fresh last-source-nudge stamp.
func TestFluxKustHealthNonArtifactReasonIgnoresSourceNudge(t *testing.T) {
	base := time.Now()
	k := shKust("flux-system", "apps", "False", "HealthCheckFailed",
		base.Add(-20*time.Minute))
	_ = unstructured.SetNestedSlice(k.Object, []any{
		map[string]any{"id": "apps_web_apps_Deployment", "v": "v1"},
	}, "status", "inventory", "entries")
	_ = unstructured.SetNestedMap(k.Object, map[string]any{
		"kind": "GitRepository", "name": "repo",
	}, "spec", "sourceRef")
	repo := probetest.UnstructuredObj("source.toolkit.fluxcd.io/v1", "GitRepository",
		"flux-system", "repo", 1, 1)
	repo.SetAnnotations(map[string]string{
		kube.AnnoLastSourceNudge: base.Add(-5 * time.Minute).UTC().Format(time.RFC3339)})

	p := testProberDyn(
		fake.NewSimpleClientset(readyDeploy("apps", "web", 2, 2)),
		probetest.OpDyn(k, repo))
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*fluxKustomizationHealthCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("stuck Kustomization must FAIL")
	}
	got, _ := p.Dyn.Resource(fluxKustGVR).Namespace("flux-system").
		Get(ctx, "apps", metav1.GetOptions{})
	if _, found, _ := unstructured.NestedString(
		got.Object, "metadata", "annotations", kube.AnnoFluxRequestedAt); !found {
		t.Fatal("non-artifact reason must keep nudging despite a fresh source nudge")
	}
}

func ptrTime(t time.Time) *time.Time { return &t }
