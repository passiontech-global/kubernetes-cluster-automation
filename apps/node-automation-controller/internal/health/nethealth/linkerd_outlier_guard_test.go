// linkerd_outlier_guard_test.go — coverage for the
// linkerd-outlier-guard check (linkerd-outlier): the 4-condition cohort
// math (MinRPS, same-revision, outlier err, sibling median) and the
// six evict gates (persistence+age, Ready sibling, controller
// cooldown, PDB, maintenance mutex+budget, kill switch).
package nethealth

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
)

// outlierDeployPod builds a Running+Ready Deployment member pod:
// pod-template-hash label plus a ReplicaSet/<deploy>-<hash>
// controller owner — the shape linkerdDeploymentPods and
// linkerdPodMember both require. All pods of one deployment share
// the passed owner UID so ReadyByOwner counts them as siblings.
func outlierDeployPod(ns, deploy, hash, name string, ready bool,
	owner types.UID) *corev1.Pod {

	p := probetest.PodWithPhase(ns, name, corev1.PodRunning, ready, 20*time.Minute)
	p.Labels = map[string]string{
		"app":               deploy,
		"pod-template-hash": hash,
	}
	p.OwnerReferences = []metav1.OwnerReference{{
		Kind: "ReplicaSet", Name: deploy + "-" + hash,
		UID: owner, Controller: ptr.To(true)}}
	return p
}

// promSample builds one deployment-grouped vector sample.
func promSample(ns, deploy, pod string, v float64) probetest.PromTestSample {
	return probetest.PromTestSample{
		Labels: map[string]string{
			"namespace": ns, "deployment": deploy, "pod": pod,
		},
		Value: v,
	}
}

// wireProm points the prober's Prom endpoint at a test server that
// answers the failure query from fail and everything else from rps.
func wireProm(t *testing.T, p *probetest.Prober,
	rps, fail []probetest.PromTestSample) {

	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, `classification="failure"`) {
			return fail
		}
		return rps
	})
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
}

// emulateEviction teaches the fake clientset the apiserver's
// pods/eviction contract — copied from the unmeshed/statefulset-
// roller test harnesses (the tracker records the eviction CREATE
// but never deletes the pod; PDB enforcement stays apiserver-side).
func emulateEviction(cs *fake.Clientset) {
	cs.PrependReactor("create", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			ca, ok := a.(ktesting.CreateAction)
			if !ok || ca.GetSubresource() != "eviction" {
				return false, nil, nil
			}
			ev := ca.GetObject().(*policyv1.Eviction)
			return true, ev, cs.Tracker().Delete(
				corev1.SchemeGroupVersion.WithResource("pods"),
				ca.GetNamespace(), ev.Name)
		})
}

// outlierFixtures wires the canonical scene: outlier pod bad at
// ~90% err on 2rps, healthy siblings sib1/sib2 at ~1% on 1rps, all
// in deployment web hash h1.
func outlierFixtures() (*corev1.Pod, *corev1.Pod, *corev1.Pod) {
	owner := types.UID("rs-web-h1")
	return outlierDeployPod("apps", "web", "h1", "web-bad", true, owner),
		outlierDeployPod("apps", "web", "h1", "web-sib1", true, owner),
		outlierDeployPod("apps", "web", "h1", "web-sib2", true, owner)
}

func outlierRPS() []probetest.PromTestSample {
	return []probetest.PromTestSample{
		promSample("apps", "web", "web-bad", 2.0),
		promSample("apps", "web", "web-sib1", 1.0),
		promSample("apps", "web", "web-sib2", 1.0),
	}
}

func outlierFails() []probetest.PromTestSample {
	return []probetest.PromTestSample{
		promSample("apps", "web", "web-bad", 1.8), // 90% err
		promSample("apps", "web", "web-sib1", 0.01),
		promSample("apps", "web", "web-sib2", 0.01),
	}
}

// A lone pod failing 90% of real inbound traffic while both
// siblings stay healthy flags on the outlier gauge and FAILs the
// check — the pod itself survives the first sweep (inside the 5m
// persistence window).
func TestLinkerdOutlierDetected(t *testing.T) {
	bad, sib1, sib2 := outlierFixtures()
	cs := fake.NewSimpleClientset(bad, sib1, sib2)
	p := testProber(cs)
	wireProm(t, p, outlierRPS(), outlierFails())
	res := probetest.MustCheck[*linkerdOutlierGuardCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("outlier pod must fail: %+v", res)
	}
	if !strings.Contains(res.Why, "web-bad") {
		t.Fatalf("why missing pod diagnostics: %q", res.Why)
	}
	m := probetest.FindMetric(t, "node_automation_linkerd_outlier_pods",
		map[string]string{"namespace": "apps", "deployment": "web", "pod": "web-bad"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("outlier gauge = %v, want 1", m)
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-bad", metav1.GetOptions{}); err != nil {
		t.Fatalf("pod evicted inside the persistence window: %v", err)
	}
	t.Cleanup(func() {
		linkerdOutlierPodsGauge.DeleteLabelValues("apps", "web", "web-bad")
	})
}

// W16-G1 — a stable Rollout cohort (one rollouts-pod-template-hash,
// `rollout` metric label) is protected like a Deployment's: the
// gray-failed member flags, membership and uniformity resolve via
// the rollouts hash label.
func TestLinkerdOutlierRolloutCohortDetected(t *testing.T) {
	owner := types.UID("rs-api-h1")
	bad := outlierDeployPod("apps", "api", "h1", "api-bad", true, owner)
	sib := outlierDeployPod("apps", "api", "h1", "api-sib", true, owner)
	// Swap the Deployment hash label for the Rollouts one — the
	// membership/uniformity tests must accept it (W16-G1).
	bad.Labels = map[string]string{"rollouts-pod-template-hash": "h1"}
	sib.Labels = map[string]string{"rollouts-pod-template-hash": "h1"}
	cs := fake.NewSimpleClientset(bad, sib)
	p := testProber(cs)
	wireProm(t, p,
		[]probetest.PromTestSample{
			{Labels: map[string]string{"namespace": "apps", "rollout": "api", "pod": "api-bad"}, Value: 2.0},
			{Labels: map[string]string{"namespace": "apps", "rollout": "api", "pod": "api-sib"}, Value: 1.0},
		},
		[]probetest.PromTestSample{
			{Labels: map[string]string{"namespace": "apps", "rollout": "api", "pod": "api-bad"}, Value: 1.8},
			{Labels: map[string]string{"namespace": "apps", "rollout": "api", "pod": "api-sib"}, Value: 0.01},
		})
	res := probetest.MustCheck[*linkerdOutlierGuardCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("stable Rollout cohort outlier must fail: %+v", res)
	}
	if !strings.Contains(res.Why, "api-bad") {
		t.Fatalf("why missing rollout pod: %q", res.Why)
	}
	t.Cleanup(func() {
		linkerdOutlierPodsGauge.DeleteLabelValues("apps", "api", "api-bad")
	})
}

// W16-G1 — a Rollout mid-canary (>1 distinct rollouts-pod-template-
// hash) has no valid control group: stand down, no flag, no evict.
func TestLinkerdOutlierRolloutCanaryStandsDown(t *testing.T) {
	owner := types.UID("rs-api-h1")
	bad := outlierDeployPod("apps", "api", "h1", "api-bad", true, owner)
	sib := outlierDeployPod("apps", "api", "h2", "api-sib", true, types.UID("rs-api-h2"))
	bad.Labels = map[string]string{"rollouts-pod-template-hash": "h1"}
	sib.Labels = map[string]string{"rollouts-pod-template-hash": "h2"}
	cs := fake.NewSimpleClientset(bad, sib)
	p := testProber(cs)
	wireProm(t, p,
		[]probetest.PromTestSample{
			{Labels: map[string]string{"namespace": "apps", "rollout": "api", "pod": "api-bad"}, Value: 2.0},
			{Labels: map[string]string{"namespace": "apps", "rollout": "api", "pod": "api-sib"}, Value: 1.0},
		},
		[]probetest.PromTestSample{
			{Labels: map[string]string{"namespace": "apps", "rollout": "api", "pod": "api-bad"}, Value: 1.8},
			{Labels: map[string]string{"namespace": "apps", "rollout": "api", "pod": "api-sib"}, Value: 0.01},
		})
	if res := probetest.MustCheck[*linkerdOutlierGuardCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("mid-canary Rollout cohort must stand down and pass: %+v", res)
	}
	if m := probetest.FindMetric(t, "node_automation_linkerd_outlier_pods",
		map[string]string{"namespace": "apps", "deployment": "api", "pod": "api-bad"}); m != nil {
		t.Fatal("canary cohort member flagged — no valid control group")
	}
}

// Fleet-wide failure: every pod fails at ~50% — a downstream
// outage, not a gray failure. Median sibling err >= 5% stands the
// check down completely.
func TestLinkerdOutlierFleetFailureNotOutlier(t *testing.T) {
	bad, sib1, sib2 := outlierFixtures()
	cs := fake.NewSimpleClientset(bad, sib1, sib2)
	p := testProber(cs)
	wireProm(t, p, outlierRPS(), []probetest.PromTestSample{
		promSample("apps", "web", "web-bad", 1.8),
		promSample("apps", "web", "web-sib1", 0.6), // 60% err — downstream is down
		promSample("apps", "web", "web-sib2", 0.5),
	})
	res := probetest.MustCheck[*linkerdOutlierGuardCheck](t, p).Run(ctx)
	if !res.Pass {
		t.Fatalf("fleet-wide failure must not flag as outlier: %+v", res)
	}
	if m := probetest.FindMetric(t, "node_automation_linkerd_outlier_pods",
		map[string]string{"namespace": "apps", "deployment": "web", "pod": "web-bad"}); m != nil {
		t.Fatal("outlier gauge emitted for a downstream outage")
	}
}

// A pod at 100% err on 0.2 rps fails condition 1 — a 1/1-request
// failure must never read as a gray failure.
func TestLinkerdOutlierLowTrafficSkipped(t *testing.T) {
	bad, sib1, sib2 := outlierFixtures()
	cs := fake.NewSimpleClientset(bad, sib1, sib2)
	p := testProber(cs)
	wireProm(t, p, []probetest.PromTestSample{
		promSample("apps", "web", "web-bad", 0.2),
		promSample("apps", "web", "web-sib1", 1.0),
		promSample("apps", "web", "web-sib2", 1.0),
	}, []probetest.PromTestSample{
		promSample("apps", "web", "web-bad", 0.2),
		promSample("apps", "web", "web-sib1", 0.01),
		promSample("apps", "web", "web-sib2", 0.01),
	})
	if res := probetest.MustCheck[*linkerdOutlierGuardCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("sub-MinRPS pod must pass: %+v", res)
	}
}

// A mid-rollout cohort (two pod-template-hashes live at once) has
// no valid control group — the outlier is not flagged.
func TestLinkerdOutlierRolloutCohortSkipped(t *testing.T) {
	owner1, owner2 := types.UID("rs-web-h1"), types.UID("rs-web-h2")
	bad := outlierDeployPod("apps", "web", "h1", "web-bad", true, owner1)
	// The siblings carry the NEW revision hash — mixed cohort.
	sib1 := outlierDeployPod("apps", "web", "h2", "web-sib1", true, owner2)
	sib2 := outlierDeployPod("apps", "web", "h2", "web-sib2", true, owner2)
	cs := fake.NewSimpleClientset(bad, sib1, sib2)
	p := testProber(cs)
	wireProm(t, p, outlierRPS(), outlierFails())
	if res := probetest.MustCheck[*linkerdOutlierGuardCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("mixed-revision cohort must pass: %+v", res)
	}
}

// A lone replica has no control sample — err>=80% alone cannot
// prove locality, so nothing flags and nothing evicts.
func TestLinkerdOutlierNoSiblingControlSkipped(t *testing.T) {
	bad, _, _ := outlierFixtures()
	cs := fake.NewSimpleClientset(bad)
	p := testProber(cs)
	wireProm(t, p, []probetest.PromTestSample{
		promSample("apps", "web", "web-bad", 2.0),
	}, []probetest.PromTestSample{
		promSample("apps", "web", "web-bad", 1.9),
	})
	res := probetest.MustCheck[*linkerdOutlierGuardCheck](t, p).Run(ctx)
	if !res.Pass {
		t.Fatalf("no-control-sample pod must pass: %+v", res)
	}
}

// A Prometheus outage is inconclusive — the check passes with a
// WARN rather than failing blind (http-content-check owns the
// Prometheus liveness signal).
func TestLinkerdOutlierPromDownInconclusive(t *testing.T) {
	bad, sib1, sib2 := outlierFixtures()
	p := testProber(fake.NewSimpleClientset(bad, sib1, sib2)) // dead Prom endpoint
	if res := probetest.MustCheck[*linkerdOutlierGuardCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("prometheus outage must be inconclusive-pass: %+v", res)
	}
}

// ---------------------------------------------------------------------------
// The evict path — gates in order.
// ---------------------------------------------------------------------------

// Past the 5m persistence window the confirmed outlier is evicted
// through policy/v1 Eviction; the Ready siblings survive.
func TestLinkerdOutlierEvicted(t *testing.T) {
	base := time.Now()
	bad, sib1, sib2 := outlierFixtures()
	cs := fake.NewSimpleClientset(bad, sib1, sib2)
	emulateEviction(cs)
	p := testProber(cs)
	p.Cfg.Linkerd.OutlierEvictEnabled = true
	wireProm(t, p, outlierRPS(), outlierFails())
	chk := probetest.MustCheck[*linkerdOutlierGuardCheck](t, p)
	probetest.FreezeNow(p.Deps, base)
	if res := chk.Run(ctx); res.Pass {
		t.Fatal("first-seen outlier must fail (signature)")
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-bad", metav1.GetOptions{}); err != nil {
		t.Fatalf("pod evicted inside the persistence window: %v", err)
	}
	probetest.FreezeNow(p.Deps, base.Add(linkerdOutlierPersistence+time.Minute))
	res := chk.Run(ctx)
	if res.Pass {
		t.Fatal("persisted outlier must still fail")
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-bad", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("outlier pod should be evicted, err=%v", err)
	}
	for _, sib := range []string{"web-sib1", "web-sib2"} {
		if _, err := cs.CoreV1().Pods("apps").Get(ctx, sib, metav1.GetOptions{}); err != nil {
			t.Fatalf("Ready sibling %s must survive: %v", sib, err)
		}
	}
	t.Cleanup(func() {
		linkerdOutlierPodsGauge.DeleteLabelValues("apps", "web", "web-bad")
	})
}

// LINKERD_OUTLIER_EVICT_ENABLED=false gates only the actuation —
// detection and the gauge run regardless.
func TestLinkerdOutlierEvictDisabled(t *testing.T) {
	base := time.Now()
	bad, sib1, sib2 := outlierFixtures()
	cs := fake.NewSimpleClientset(bad, sib1, sib2)
	emulateEviction(cs)
	p := testProber(cs)
	p.Cfg.Linkerd.OutlierEvictEnabled = false // kill switch
	wireProm(t, p, outlierRPS(), outlierFails())
	chk := probetest.MustCheck[*linkerdOutlierGuardCheck](t, p)
	probetest.FreezeNow(p.Deps, base)
	if res := chk.Run(ctx); res.Pass {
		t.Fatal("outlier signature must still fail when evict is off")
	}
	probetest.FreezeNow(p.Deps, base.Add(linkerdOutlierPersistence+time.Minute))
	if res := chk.Run(ctx); res.Pass {
		t.Fatal("persisted outlier must still fail when evict is off")
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-bad", metav1.GetOptions{}); err != nil {
		t.Fatalf("kill switch must keep the pod alive: %v", err)
	}
	t.Cleanup(func() {
		linkerdOutlierPodsGauge.DeleteLabelValues("apps", "web", "web-bad")
	})
}

// A gray-failed pod with no Ready sibling is never evicted — the
// evict would blackhole the workload it was meant to save.
func TestLinkerdOutlierNoReadySiblingSurvives(t *testing.T) {
	base := time.Now()
	owner := types.UID("rs-web-h1")
	bad := outlierDeployPod("apps", "web", "h1", "web-bad", true, owner)
	// The siblings exist in metrics but are NOT Ready in k8s.
	sib1 := outlierDeployPod("apps", "web", "h1", "web-sib1", false, owner)
	sib2 := outlierDeployPod("apps", "web", "h1", "web-sib2", false, owner)
	cs := fake.NewSimpleClientset(bad, sib1, sib2)
	emulateEviction(cs)
	p := testProber(cs)
	p.Cfg.Linkerd.OutlierEvictEnabled = true
	wireProm(t, p, outlierRPS(), outlierFails())
	chk := probetest.MustCheck[*linkerdOutlierGuardCheck](t, p)
	probetest.FreezeNow(p.Deps, base)
	_ = chk.Run(ctx)
	probetest.FreezeNow(p.Deps, base.Add(linkerdOutlierPersistence+time.Minute))
	if res := chk.Run(ctx); res.Pass {
		t.Fatal("outlier signature must still fail")
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-bad", metav1.GetOptions{}); err != nil {
		t.Fatalf("last-Ready-replica pod must not be evicted: %v", err)
	}
	t.Cleanup(func() {
		linkerdOutlierPodsGauge.DeleteLabelValues("apps", "web", "web-bad")
	})
}

// A matching PDB with disruptionsAllowed=0 defers the evict — the
// workload is already at its replica floor.
func TestLinkerdOutlierPDBBlocksEvict(t *testing.T) {
	base := time.Now()
	bad, sib1, sib2 := outlierFixtures()
	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web-pdb"},
		Spec: policyv1.PodDisruptionBudgetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"}},
		},
		Status: policyv1.PodDisruptionBudgetStatus{DisruptionsAllowed: 0},
	}
	cs := fake.NewSimpleClientset(bad, sib1, sib2, pdb)
	emulateEviction(cs)
	p := testProber(cs)
	p.Cfg.Linkerd.OutlierEvictEnabled = true
	wireProm(t, p, outlierRPS(), outlierFails())
	chk := probetest.MustCheck[*linkerdOutlierGuardCheck](t, p)
	probetest.FreezeNow(p.Deps, base)
	_ = chk.Run(ctx)
	probetest.FreezeNow(p.Deps, base.Add(linkerdOutlierPersistence+time.Minute))
	if res := chk.Run(ctx); res.Pass {
		t.Fatal("outlier signature must still fail")
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-bad", metav1.GetOptions{}); err != nil {
		t.Fatalf("PDB-blocked pod must not be evicted: %v", err)
	}
	t.Cleanup(func() {
		linkerdOutlierPodsGauge.DeleteLabelValues("apps", "web", "web-bad")
	})
}

// The 30m controller-scoped cooldown: after web-bad is evicted, a
// DIFFERENT pod of the same ReplicaSet going outlier inside the
// window survives — at most one evict per controller per 30m.
func TestLinkerdOutlierControllerCooldown(t *testing.T) {
	base := time.Now()
	bad, sib1, sib2 := outlierFixtures()
	cs := fake.NewSimpleClientset(bad, sib1, sib2)
	emulateEviction(cs)
	p := testProber(cs)
	p.Cfg.Linkerd.OutlierEvictEnabled = true
	wireProm(t, p, outlierRPS(), outlierFails())
	chk := probetest.MustCheck[*linkerdOutlierGuardCheck](t, p)
	probetest.FreezeNow(p.Deps, base)
	_ = chk.Run(ctx)
	probetest.FreezeNow(p.Deps, base.Add(linkerdOutlierPersistence+time.Minute))
	_ = chk.Run(ctx) // evicts web-bad, stamps the RS cooldown
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-bad", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("first outlier should be evicted, err=%v", err)
	}

	// web-sib1 turns outlier on the NEXT persistence window — the
	// cooldown keyed on the shared ReplicaSet must hold it back.
	rps2 := []probetest.PromTestSample{
		promSample("apps", "web", "web-sib1", 2.0),
		promSample("apps", "web", "web-sib2", 1.0),
	}
	fail2 := []probetest.PromTestSample{
		promSample("apps", "web", "web-sib1", 1.9),
		promSample("apps", "web", "web-sib2", 0.01),
	}
	wireProm(t, p, rps2, fail2)
	probetest.FreezeNow(p.Deps, base.Add(linkerdOutlierPersistence+2*time.Minute))
	_ = chk.Run(ctx) // web-sib1 first seen
	probetest.FreezeNow(p.Deps, base.Add(2*linkerdOutlierPersistence+2*time.Minute))
	if res := chk.Run(ctx); res.Pass {
		t.Fatal("second outlier signature must still fail")
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-sib1", metav1.GetOptions{}); err != nil {
		t.Fatalf("second outlier inside the 30m controller cooldown must survive: %v", err)
	}
	t.Cleanup(func() {
		linkerdOutlierPodsGauge.DeleteLabelValues("apps", "web", "web-sib1")
	})
}

// A pod younger than PodMinAge is never evicted — startup churn is
// not a gray failure.
func TestLinkerdOutlierYoungPodSurvives(t *testing.T) {
	base := time.Now()
	owner := types.UID("rs-web-h1")
	bad := outlierDeployPod("apps", "web", "h1", "web-bad", true, owner)
	bad.CreationTimestamp = metav1.NewTime(base.Add(-time.Minute)) // too young
	sib1 := outlierDeployPod("apps", "web", "h1", "web-sib1", true, owner)
	sib2 := outlierDeployPod("apps", "web", "h1", "web-sib2", true, owner)
	cs := fake.NewSimpleClientset(bad, sib1, sib2)
	emulateEviction(cs)
	p := testProber(cs)
	p.Cfg.Linkerd.OutlierEvictEnabled = true
	wireProm(t, p, outlierRPS(), outlierFails())
	chk := probetest.MustCheck[*linkerdOutlierGuardCheck](t, p)
	probetest.FreezeNow(p.Deps, base)
	_ = chk.Run(ctx)
	probetest.FreezeNow(p.Deps, base.Add(linkerdOutlierPersistence+time.Minute))
	if res := chk.Run(ctx); res.Pass {
		t.Fatal("outlier signature must still fail")
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-bad", metav1.GetOptions{}); err != nil {
		t.Fatalf("under-age pod must not be evicted: %v", err)
	}
	t.Cleanup(func() {
		linkerdOutlierPodsGauge.DeleteLabelValues("apps", "web", "web-bad")
	})
}

// Pure helpers — median and membership.
func TestMedianF64(t *testing.T) {
	for _, tc := range []struct {
		vals []float64
		want float64
	}{
		{[]float64{0.01}, 0.01},
		{[]float64{0.01, 0.9, 0.03}, 0.03},
		{[]float64{0.01, 0.02, 0.03, 0.04}, 0.025},
		{[]float64{0.5, 0.6, 0.9}, 0.6},
	} {
		if got := medianF64(tc.vals); got != tc.want {
			t.Fatalf("medianF64(%v) = %v, want %v", tc.vals, got, tc.want)
		}
	}
}
