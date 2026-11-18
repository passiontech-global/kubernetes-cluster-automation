// coredns_forward_saturation_test.go — coverage for the
// coredns-forward-saturation check: the 5-minute reject-rate
// persistence window, the replica boost honoring
// COREDNS_SATURATION_BOOST_REPLICAS (no hard-coded +2), the
// boost-window stamp acting as the persisted cooldown, and the
// FluxPatchGate + HealAllowed rails on the patch.
package nethealth

import (
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// fwdSatDeps wires Deps to a fake Prometheus answering the reject
// query with the given rate.
func fwdSatDeps(t *testing.T, rejects float64, dep *appsv1.Deployment) *probefw.Deps {
	t.Helper()
	srv, _ := probetest.PromTestServer(t,
		func(query string) []probetest.PromTestSample {
			if strings.Contains(query, "max_concurrent_rejects") {
				return []probetest.PromTestSample{{Value: rejects}}
			}
			return nil
		})
	cs := fake.NewSimpleClientset()
	if dep != nil {
		cs = fake.NewSimpleClientset(dep)
	}
	d := probetest.NewDeps(cs, probetest.OpDyn())
	d.Cfg.HTTPContent.URL = srv.URL
	d.HTTPClient = srv.Client()
	return d
}

func corednsDep(replicas int32) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "coredns"},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(replicas),
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "kube-dns"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"k8s-app": "kube-dns"}},
			},
		},
	}
}

func TestCoreDNSFwdSatPersistenceWindow(t *testing.T) {
	d := fwdSatDeps(t, 5.0, corednsDep(2))
	ch := &coreDNSForwardSaturationCheck{Deps: d, boostReplicas: 3}
	base := time.Now()

	probetest.FreezeNow(d, base)
	if res := ch.Run(probetest.SweepCtx(ctx, ch.Deps)); !res.Pass {
		t.Fatalf("first breaching sweep must pass inside window: %+v", res)
	}
	probetest.FreezeNow(d, base.Add(coreDNSFwdSatMinAge-time.Minute))
	ch.Run(probetest.SweepCtx(ctx, ch.Deps))
	probetest.FreezeNow(d, base.Add(coreDNSFwdSatMinAge+time.Minute))
	res := ch.Run(probetest.SweepCtx(ctx, ch.Deps))
	if res.Pass {
		t.Fatal("sustained rejects past the window must fail")
	}
	// Boost = configured amount, NOT a hard-coded +2: 2 + 3 = 5.
	got, err := d.CS.AppsV1().Deployments("kube-system").
		Get(ctx, "coredns", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get coredns: %v", err)
	}
	if got.Spec.Replicas == nil || *got.Spec.Replicas != 5 {
		t.Fatalf("replicas=%v want 5 (2+boostReplicas=3)", got.Spec.Replicas)
	}
	if got.Annotations[kube.AnnoCoreDNSBoostUntil] == "" {
		t.Fatal("boost-until stamp missing")
	}
	if got.Annotations[kube.AnnoCoreDNSBoostBase] != "2" {
		t.Fatalf("boost-base stamp = %q, want %q (pre-boost replicas)",
			got.Annotations[kube.AnnoCoreDNSBoostBase], "2")
	}
}

func TestCoreDNSFwdSatBoostWindowIsCooldown(t *testing.T) {
	// Second sweep inside the boost window must NOT bump again —
	// the stamp is the persisted cooldown.
	d := fwdSatDeps(t, 5.0, corednsDep(2))
	ch := &coreDNSForwardSaturationCheck{Deps: d, boostReplicas: 3}
	base := time.Now()
	probetest.FreezeNow(d, base)
	ch.Run(probetest.SweepCtx(ctx, ch.Deps))
	probetest.FreezeNow(d, base.Add(coreDNSFwdSatMinAge+time.Minute))
	ch.Run(probetest.SweepCtx(ctx, ch.Deps))
	probetest.FreezeNow(d, base.Add(coreDNSFwdSatMinAge+2*time.Minute))
	ch.Run(probetest.SweepCtx(ctx, ch.Deps))
	got, _ := d.CS.AppsV1().Deployments("kube-system").
		Get(ctx, "coredns", metav1.GetOptions{})
	if *got.Spec.Replicas != 5 {
		t.Fatalf("replicas=%d want 5 — boost window must suppress re-bump",
			*got.Spec.Replicas)
	}
}

func TestCoreDNSFwdSatNoRejectsPasses(t *testing.T) {
	d := fwdSatDeps(t, 0, corednsDep(2))
	ch := &coreDNSForwardSaturationCheck{Deps: d, boostReplicas: 2}
	if res := ch.Run(probetest.SweepCtx(ctx, ch.Deps)); !res.Pass {
		t.Fatalf("zero rejects must pass: %+v", res)
	}
}

func TestCoreDNSFwdSatFluxGateBlocksBoost(t *testing.T) {
	// Arm the conflict loop at threshold 1 — the first sighting of
	// a Flux-owned Deployment is already the ping-pong repeat.
	heal.ConfigureFluxConflictLoop(1, 30*time.Minute)
	defer heal.ConfigureFluxConflictLoop(0, 0)

	dep := corednsDep(2)
	dep.ManagedFields = []metav1.ManagedFieldsEntry{{
		Manager:    "kustomize-controller",
		Operation:  metav1.ManagedFieldsOperationApply,
		APIVersion: "apps/v1",
	}}
	d := fwdSatDeps(t, 5.0, dep)
	ch := &coreDNSForwardSaturationCheck{Deps: d, boostReplicas: 3}
	base := time.Now()
	probetest.FreezeNow(d, base)
	ch.Run(probetest.SweepCtx(ctx, ch.Deps))
	probetest.FreezeNow(d, base.Add(coreDNSFwdSatMinAge+time.Minute))
	ch.Run(probetest.SweepCtx(ctx, ch.Deps))
	got, _ := d.CS.AppsV1().Deployments("kube-system").
		Get(ctx, "coredns", metav1.GetOptions{})
	if *got.Spec.Replicas != 2 {
		t.Fatalf("replicas=%d want 2 — Flux gate must block the boost",
			*got.Spec.Replicas)
	}
	if got.Annotations[kube.AnnoCoreDNSBoostUntil] != "" {
		t.Fatal("boost stamp landed past the Flux gate")
	}
}
