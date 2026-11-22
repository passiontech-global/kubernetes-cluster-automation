// coredns_forward_saturation_test.go — coverage for the
// coredns-forward-saturation check: the 5-minute reject-rate
// persistence window, the replica boost honoring
// COREDNS_SATURATION_BOOST_REPLICAS (no hard-coded +2), the
// boost-window stamp acting as the persisted cooldown, and the
// FluxPatchGate + HealAllowed rails on the patch.
package nethealth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
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

func TestCoreDNSFwdSatFluxGateOrderingRefundAndMarshalFailure(t *testing.T) {
	fluxDep := func(replicas int32) *appsv1.Deployment {
		dep := corednsDep(replicas)
		dep.ManagedFields = []metav1.ManagedFieldsEntry{{
			Manager:    "kustomize-controller",
			Operation:  metav1.ManagedFieldsOperationApply,
			APIVersion: "apps/v1",
		}}
		return dep
	}

	cases := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "maintenance hold suppresses FluxPatchGate sightings",
			run: func(t *testing.T) {
				heal.ConfigureFluxConflictLoop(2, 30*time.Minute)
				var hookCalls int
				heal.SetFluxConflictHook(func(heal.FluxConflictSignal) { hookCalls++ })
				t.Cleanup(func() {
					heal.ConfigureFluxConflictLoop(0, 0)
					heal.SetFluxConflictHook(nil)
				})

				d := fwdSatDeps(t, 5.0, fluxDep(2))
				node := &corev1.Node{
					ObjectMeta: metav1.ObjectMeta{Name: "w-hold"},
					Spec:       corev1.NodeSpec{Unschedulable: true},
				}
				if _, err := d.CS.CoreV1().Nodes().Create(ctx, node, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
				ch := &coreDNSForwardSaturationCheck{Deps: d, boostReplicas: 3}
				base := time.Now()

				probetest.FreezeNow(d, base)
				ch.Run(probetest.SweepCtx(ctx, ch.Deps))
				probetest.FreezeNow(d, base.Add(coreDNSFwdSatMinAge+time.Minute))
				ch.Run(probetest.SweepCtx(ctx, ch.Deps))
				probetest.FreezeNow(d, base.Add(coreDNSFwdSatMinAge+2*time.Minute))
				ch.Run(probetest.SweepCtx(ctx, ch.Deps))

				if hookCalls != 0 {
					t.Fatalf("FluxConflictHook fired %d times during maintenance hold, want 0", hookCalls)
				}
				got, _ := d.CS.AppsV1().Deployments("kube-system").Get(ctx, "coredns", metav1.GetOptions{})
				if *got.Spec.Replicas != 2 {
					t.Fatalf("replicas=%d during maintenance hold, want 2", *got.Spec.Replicas)
				}

				node.Spec.Unschedulable = false
				if _, err := d.CS.CoreV1().Nodes().Update(ctx, node, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
				probetest.FreezeNow(d, base.Add(coreDNSFwdSatMinAge+3*time.Minute))
				ch.Run(probetest.SweepCtx(ctx, ch.Deps))
				got, _ = d.CS.AppsV1().Deployments("kube-system").Get(ctx, "coredns", metav1.GetOptions{})
				if *got.Spec.Replicas != 5 {
					t.Fatalf("post-hold replicas=%d, want 5 (phantom sightings leaked during hold)", *got.Spec.Replicas)
				}
			},
		},
		{
			name: "cooldown suppresses FluxPatchGate sightings",
			run: func(t *testing.T) {
				heal.ConfigureFluxConflictLoop(2, 2*time.Hour)
				var hookCalls int
				heal.SetFluxConflictHook(func(heal.FluxConflictSignal) { hookCalls++ })
				t.Cleanup(func() {
					heal.ConfigureFluxConflictLoop(0, 0)
					heal.SetFluxConflictHook(nil)
				})

				d := fwdSatDeps(t, 5.0, fluxDep(2))
				ch := &coreDNSForwardSaturationCheck{Deps: d, boostReplicas: 3}
				base := time.Now()

				probetest.FreezeNow(d, base)
				ch.Run(probetest.SweepCtx(ctx, ch.Deps))

				t1 := base.Add(coreDNSFwdSatMinAge + time.Minute)
				ch.Heals.Stamp(probefw.SelfHealKey(CheckNameCoreDNSForwardSaturation, "boost"), t1)
				probetest.FreezeNow(d, t1.Add(time.Minute))
				ch.Run(probetest.SweepCtx(ctx, ch.Deps))
				probetest.FreezeNow(d, t1.Add(2*time.Minute))
				ch.Run(probetest.SweepCtx(ctx, ch.Deps))

				if hookCalls != 0 {
					t.Fatalf("FluxConflictHook fired %d times during cooldown, want 0", hookCalls)
				}
				got, _ := d.CS.AppsV1().Deployments("kube-system").Get(ctx, "coredns", metav1.GetOptions{})
				if *got.Spec.Replicas != 2 {
					t.Fatalf("replicas=%d during cooldown, want 2", *got.Spec.Replicas)
				}

				probetest.FreezeNow(d, t1.Add(coreDNSFwdSatBoostWindow+time.Minute))
				ch.Run(probetest.SweepCtx(ctx, ch.Deps))
				got, _ = d.CS.AppsV1().Deployments("kube-system").Get(ctx, "coredns", metav1.GetOptions{})
				if *got.Spec.Replicas != 5 {
					t.Fatalf("post-cooldown replicas=%d, want 5 (phantom sightings leaked during cooldown)", *got.Spec.Replicas)
				}
			},
		},
		{
			name: "duty-prefixed keyspace isolates coredns boost from other duties and unprefixed keys",
			run: func(t *testing.T) {
				heal.ConfigureFluxConflictLoop(2, 30*time.Minute)
				t.Cleanup(func() { heal.ConfigureFluxConflictLoop(0, 0) })

				dep := fluxDep(2)
				d := fwdSatDeps(t, 5.0, dep)
				ch := &coreDNSForwardSaturationCheck{Deps: d, boostReplicas: 3}
				base := time.Now()

				heal.FluxPatchGate("deployment", dep, "deployment-rollout-wedge:kube-system/coredns", base)
				heal.FluxPatchGate("deployment", dep, "deployment-rollout-wedge:kube-system/coredns", base)
				heal.FluxPatchGate("deployment", dep, "kube-system/coredns", base)
				heal.FluxPatchGate("deployment", dep, "kube-system/coredns", base)

				probetest.FreezeNow(d, base)
				ch.Run(probetest.SweepCtx(ctx, ch.Deps))
				probetest.FreezeNow(d, base.Add(coreDNSFwdSatMinAge+time.Minute))
				ch.Run(probetest.SweepCtx(ctx, ch.Deps))

				got, _ := d.CS.AppsV1().Deployments("kube-system").Get(ctx, "coredns", metav1.GetOptions{})
				if *got.Spec.Replicas != 5 {
					t.Fatalf("isolated boost replicas=%d, want 5", *got.Spec.Replicas)
				}
			},
		},
		{
			name: "FluxPatchGate denial refunds budget grant",
			run: func(t *testing.T) {
				heal.ConfigureBudget(1, time.Hour)
				heal.ConfigureFluxConflictLoop(1, 30*time.Minute)
				t.Cleanup(func() {
					heal.ConfigureBudget(0, 0)
					heal.ConfigureFluxConflictLoop(0, 0)
				})

				d := fwdSatDeps(t, 5.0, fluxDep(2))
				ch := &coreDNSForwardSaturationCheck{Deps: d, boostReplicas: 3}
				base := time.Now()
				boostNow := base.Add(coreDNSFwdSatMinAge + time.Minute)

				probetest.FreezeNow(d, base)
				ch.Run(probetest.SweepCtx(ctx, ch.Deps))
				probetest.FreezeNow(d, boostNow)
				ch.Run(probetest.SweepCtx(ctx, ch.Deps))

				got, _ := d.CS.AppsV1().Deployments("kube-system").Get(ctx, "coredns", metav1.GetOptions{})
				if *got.Spec.Replicas != 2 {
					t.Fatalf("replicas=%d, want 2 (blocked by FluxPatchGate)", *got.Spec.Replicas)
				}
				proceed, unverifiable := heal.Gate(ctx, logr.Discard(), nil, d.CS, d.Dyn, "probe-after-flux-deny", boostNow)
				if !proceed || unverifiable {
					t.Fatalf("Gate after FluxPatchGate denial = (%v,%v), want (true,false) — grant not refunded",
						proceed, unverifiable)
				}
			},
		},
		{
			name: "marshal failure refunds budget grant and counts error",
			run: func(t *testing.T) {
				heal.ConfigureBudget(1, time.Hour)
				t.Cleanup(func() { heal.ConfigureBudget(0, 0) })

				d := fwdSatDeps(t, 5.0, corednsDep(2))
				ch := &coreDNSForwardSaturationCheck{
					Deps:          d,
					boostReplicas: 3,
					marshalFn:     func(any) ([]byte, error) { return nil, errors.New("marshal boom") },
				}
				base := time.Now()
				boostNow := base.Add(coreDNSFwdSatMinAge + time.Minute)

				probetest.FreezeNow(d, base)
				ch.Run(probetest.SweepCtx(ctx, ch.Deps))
				before := testutil.QueueErrorCount(t, d.Name)
				probetest.FreezeNow(d, boostNow)
				ch.Run(probetest.SweepCtx(ctx, ch.Deps))

				if delta := testutil.QueueErrorCount(t, d.Name) - before; delta != 1 {
					t.Fatalf("marshal failure IncError delta = %v, want 1", delta)
				}
				got, _ := d.CS.AppsV1().Deployments("kube-system").Get(ctx, "coredns", metav1.GetOptions{})
				if *got.Spec.Replicas != 2 {
					t.Fatalf("replicas=%d on marshal error, want 2", *got.Spec.Replicas)
				}
				proceed, unverifiable := heal.Gate(ctx, logr.Discard(), nil, d.CS, d.Dyn, "probe-after-marshal-err", boostNow)
				if !proceed || unverifiable {
					t.Fatalf("Gate after marshal failure = (%v,%v), want (true,false) — grant not refunded",
						proceed, unverifiable)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, tc.run)
	}
}
