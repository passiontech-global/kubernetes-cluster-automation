// workload_connection_skew_guard_test.go — unit tests for
// workload-connection-skew-guard: clean/empty passes, <15m tracking without
// deletion, >=15m allowlisted single-pod rebalance + cooldown, non-allowlisted
// detect-only, ledger clearing on skew resolution, and StatefulSet exclusion.
package connectionskew

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
)

func deployPod(ns, rsName, podName string, ownerUID types.UID, ready bool) *corev1.Pod {
	p := probetest.PodWithPhase(ns, podName, corev1.PodRunning, ready, 30*time.Minute)
	p.UID = types.UID("uid-" + ns + "-" + podName)
	p.OwnerReferences = []metav1.OwnerReference{{
		Kind:       "ReplicaSet",
		Name:       rsName,
		UID:        ownerUID,
		Controller: ptr.To(true),
	}}
	return p
}

func skewSample(ns, deploy, pod string, rate float64) probetest.PromTestSample {
	return probetest.PromTestSample{
		Labels: map[string]string{
			"namespace":  ns,
			"deployment": deploy,
			"pod":        pod,
		},
		Value: rate,
	}
}

func wireProm(t *testing.T, p *probetest.Prober, samplesFn func() []probetest.PromTestSample) {
	t.Helper()
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if query == connSkewQuery {
			return samplesFn()
		}
		return nil
	})
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
}

func TestConnectionSkewEmptyRecordingRulePasses(t *testing.T) {
	cs := fake.NewSimpleClientset()
	p := testProber(cs)
	wireProm(t, p, func() []probetest.PromTestSample { return nil })

	res := probetest.MustCheck[*workloadConnectionSkewGuardCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
	if !res.Pass {
		t.Fatalf("empty recording rule must pass, got: %+v", res)
	}
}

func TestConnectionSkewNoSkewPasses(t *testing.T) {
	ns := "cloudflare-tunnel-ingress-controller"
	deploy := "controlled-cloudflared-connector"
	owner := types.UID("rs-cf")
	cs := fake.NewSimpleClientset(
		deployPod(ns, deploy+"-abc", deploy+"-1", owner, true),
		deployPod(ns, deploy+"-abc", deploy+"-2", owner, true),
		deployPod(ns, deploy+"-abc", deploy+"-3", owner, true),
	)
	p := testProber(cs)
	wireProm(t, p, func() []probetest.PromTestSample {
		return []probetest.PromTestSample{
			skewSample(ns, deploy, deploy+"-1", 5000),
			skewSample(ns, deploy, deploy+"-2", 4000),
			skewSample(ns, deploy, deploy+"-3", 6000), // 1.2x median -> healthy
		}
	})
	res := probetest.MustCheck[*workloadConnectionSkewGuardCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
	if !res.Pass {
		t.Fatalf("balanced pods must pass, got: %+v", res)
	}
}

func TestConnectionSkewUnder15mTracksOnlyNoDelete(t *testing.T) {
	ns := "cloudflare-tunnel-ingress-controller"
	deploy := "controlled-cloudflared-connector"
	owner := types.UID("rs-cf")
	cs := fake.NewSimpleClientset(
		deployPod(ns, deploy+"-abc", deploy+"-hot", owner, true),
		deployPod(ns, deploy+"-abc", deploy+"-cold1", owner, true),
		deployPod(ns, deploy+"-abc", deploy+"-cold2", owner, true),
	)
	p := testProber(cs)
	t0 := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	probetest.FreezeNow(p.Deps, t0)
	wireProm(t, p, func() []probetest.PromTestSample {
		return []probetest.PromTestSample{
			skewSample(ns, deploy, deploy+"-hot", 50000), // 25x median
			skewSample(ns, deploy, deploy+"-cold1", 2000),
			skewSample(ns, deploy, deploy+"-cold2", 2000),
		}
	})

	chk := probetest.MustCheck[*workloadConnectionSkewGuardCheck](t, p)
	// First sight: t0 -> tracks first-seen, passes, no delete.
	if res := chk.Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatalf("first sight must pass while tracking: %+v", res)
	}
	// Still under 15m (t0 + 10m): tracks only, passes, no delete.
	probetest.FreezeNow(p.Deps, t0.Add(10*time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatalf("skew <15m must pass without failing or deleting: %+v", res)
	}
	if _, err := cs.CoreV1().Pods(ns).Get(ctx, deploy+"-hot", metav1.GetOptions{}); err != nil {
		t.Fatalf("hottest pod deleted before 15m persistence: %v", err)
	}
}

func TestConnectionSkewAllowlistedDeletesSingleHottestAndRespectsCooldown(t *testing.T) {
	ns := "cloudflare-tunnel-ingress-controller"
	deploy := "controlled-cloudflared-connector"
	owner := types.UID("rs-cf")
	cs := fake.NewSimpleClientset(
		deployPod(ns, deploy+"-abc", deploy+"-hot", owner, true),
		deployPod(ns, deploy+"-abc", deploy+"-warm", owner, true),
		deployPod(ns, deploy+"-abc", deploy+"-cold1", owner, true),
		deployPod(ns, deploy+"-abc", deploy+"-cold2", owner, true),
	)
	p := testProber(cs)
	t0 := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	probetest.FreezeNow(p.Deps, t0)

	samples := []probetest.PromTestSample{
		skewSample(ns, deploy, deploy+"-hot", 60000),  // 30x median
		skewSample(ns, deploy, deploy+"-warm", 20000), // 10x median (must NOT be deleted)
		skewSample(ns, deploy, deploy+"-cold1", 2000),
		skewSample(ns, deploy, deploy+"-cold2", 2000),
	}
	wireProm(t, p, func() []probetest.PromTestSample { return samples })
	t.Cleanup(func() {
		workloadConnectionSkewGauge.DeleteLabelValues(ns, deploy, deploy+"-hot")
		workloadConnectionSkewGauge.DeleteLabelValues(ns, deploy, deploy+"-warm")
	})

	chk := probetest.MustCheck[*workloadConnectionSkewGuardCheck](t, p)
	// t0: track first-seen
	if res := chk.Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatalf("t0 must pass: %+v", res)
	}

	// t0 + 16m: persisted -> FAIL + delete ONLY the single hottest pod.
	probetest.FreezeNow(p.Deps, t0.Add(16*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, p.Deps))
	if res.Pass {
		t.Fatal("sustained skew >=15m must FAIL")
	}
	if !strings.Contains(res.Why, deploy+"-hot") {
		t.Fatalf("Why missing hottest pod: %q", res.Why)
	}
	if _, err := cs.CoreV1().Pods(ns).Get(ctx, deploy+"-hot", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("expected hottest pod deleted, got err=%v", err)
	}
	if _, err := cs.CoreV1().Pods(ns).Get(ctx, deploy+"-warm", metav1.GetOptions{}); err != nil {
		t.Fatalf("second pod must NOT be deleted on same sweep: %v", err)
	}

	// t0 + 21m (5m later, inside 30m cooldown): even if warm is now hottest,
	// cooldown blocks deleting another pod from the same controller.
	samples = []probetest.PromTestSample{
		skewSample(ns, deploy, deploy+"-warm", 20000), // 10x median
		skewSample(ns, deploy, deploy+"-cold1", 2000),
		skewSample(ns, deploy, deploy+"-cold2", 2000),
	}
	probetest.FreezeNow(p.Deps, t0.Add(21*time.Minute))
	res = chk.Run(probetest.SweepCtx(ctx, p.Deps))
	if res.Pass {
		t.Fatal("still skewed deployment must still FAIL")
	}
	if _, err := cs.CoreV1().Pods(ns).Get(ctx, deploy+"-warm", metav1.GetOptions{}); err != nil {
		t.Fatalf("cooldown violated — warm pod was deleted inside 30m window: %v", err)
	}

	// Skew resolves -> ledger clears -> next skew must wait a fresh 15m.
	samples = []probetest.PromTestSample{
		skewSample(ns, deploy, deploy+"-warm", 2500),
		skewSample(ns, deploy, deploy+"-cold1", 2000),
		skewSample(ns, deploy, deploy+"-cold2", 2000),
	}
	probetest.FreezeNow(p.Deps, t0.Add(26*time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatalf("resolved skew must pass: %+v", res)
	}

	// Re-introduce skew at t0 + 50m (past 30m cooldown): because ledger cleared,
	// first sight must pass and NOT delete immediately.
	samples = []probetest.PromTestSample{
		skewSample(ns, deploy, deploy+"-warm", 30000),
		skewSample(ns, deploy, deploy+"-cold1", 2000),
		skewSample(ns, deploy, deploy+"-cold2", 2000),
	}
	probetest.FreezeNow(p.Deps, t0.Add(50*time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatalf("re-armed skew after resolution must track fresh 15m window: %+v", res)
	}
	if _, err := cs.CoreV1().Pods(ns).Get(ctx, deploy+"-warm", metav1.GetOptions{}); err != nil {
		t.Fatalf("pod deleted without fresh 15m persistence after ledger clear: %v", err)
	}
}

func TestConnectionSkewNonAllowlistedFailsWithoutDeleting(t *testing.T) {
	ns := "apps"
	deploy := "grpc-backend"
	owner := types.UID("rs-grpc")
	cs := fake.NewSimpleClientset(
		deployPod(ns, deploy+"-abc", deploy+"-hot", owner, true),
		deployPod(ns, deploy+"-abc", deploy+"-cold1", owner, true),
		deployPod(ns, deploy+"-abc", deploy+"-cold2", owner, true),
	)
	p := testProber(cs)
	t0 := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	probetest.FreezeNow(p.Deps, t0)
	wireProm(t, p, func() []probetest.PromTestSample {
		return []probetest.PromTestSample{
			skewSample(ns, deploy, deploy+"-hot", 40000),
			skewSample(ns, deploy, deploy+"-cold1", 2000),
			skewSample(ns, deploy, deploy+"-cold2", 2000),
		}
	})
	t.Cleanup(func() {
		workloadConnectionSkewGauge.DeleteLabelValues(ns, deploy, deploy+"-hot")
	})

	chk := probetest.MustCheck[*workloadConnectionSkewGuardCheck](t, p)
	_ = chk.Run(probetest.SweepCtx(ctx, p.Deps))
	probetest.FreezeNow(p.Deps, t0.Add(16*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, p.Deps))
	if res.Pass {
		t.Fatal("non-allowlisted skewed deployment must still report FAIL")
	}
	if !strings.Contains(res.Why, "apps/grpc-backend") {
		t.Fatalf("Why missing deployment name: %q", res.Why)
	}
	if _, err := cs.CoreV1().Pods(ns).Get(ctx, deploy+"-hot", metav1.GetOptions{}); err != nil {
		t.Fatalf("non-allowlisted pod must NOT be deleted: %v", err)
	}
}

func TestConnectionSkewRebalanceGateOffDoesNotDelete(t *testing.T) {
	t.Setenv("WORKLOAD_CONNECTION_SKEW_REBALANCE_ENABLED", "false")
	ns := "cloudflare-tunnel-ingress-controller"
	deploy := "controlled-cloudflared-connector"
	owner := types.UID("rs-cf")
	cs := fake.NewSimpleClientset(
		deployPod(ns, deploy+"-abc", deploy+"-hot", owner, true),
		deployPod(ns, deploy+"-abc", deploy+"-cold1", owner, true),
		deployPod(ns, deploy+"-abc", deploy+"-cold2", owner, true),
	)
	p := testProber(cs)
	t0 := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	probetest.FreezeNow(p.Deps, t0)
	wireProm(t, p, func() []probetest.PromTestSample {
		return []probetest.PromTestSample{
			skewSample(ns, deploy, deploy+"-hot", 50000),
			skewSample(ns, deploy, deploy+"-cold1", 2000),
			skewSample(ns, deploy, deploy+"-cold2", 2000),
		}
	})
	t.Cleanup(func() {
		workloadConnectionSkewGauge.DeleteLabelValues(ns, deploy, deploy+"-hot")
	})

	chk := probetest.MustCheck[*workloadConnectionSkewGuardCheck](t, p)
	_ = chk.Run(probetest.SweepCtx(ctx, p.Deps))
	probetest.FreezeNow(p.Deps, t0.Add(16*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, p.Deps))
	if res.Pass {
		t.Fatal("skew must still FAIL when rebalance gate is false")
	}
	if _, err := cs.CoreV1().Pods(ns).Get(ctx, deploy+"-hot", metav1.GetOptions{}); err != nil {
		t.Fatalf("pod deleted while WORKLOAD_CONNECTION_SKEW_REBALANCE_ENABLED=false: %v", err)
	}
}

func TestConnectionSkewSkipsStatefulSetsAndLowMedian(t *testing.T) {
	ns := "data"
	sts := "redis"
	stsPod := func(name string) *corev1.Pod {
		pod := probetest.PodWithPhase(ns, name, corev1.PodRunning, true, 30*time.Minute)
		pod.OwnerReferences = []metav1.OwnerReference{{
			Kind:       "StatefulSet",
			Name:       sts,
			UID:        "sts-1",
			Controller: ptr.To(true),
		}}
		return pod
	}
	owner := types.UID("rs-idle")
	cs := fake.NewSimpleClientset(
		stsPod("redis-0"), stsPod("redis-1"), stsPod("redis-2"),
		deployPod("apps", "idle-abc", "idle-1", owner, true),
		deployPod("apps", "idle-abc", "idle-2", owner, true),
		deployPod("apps", "idle-abc", "idle-3", owner, true),
	)
	p := testProber(cs)
	t0 := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	probetest.FreezeNow(p.Deps, t0)
	wireProm(t, p, func() []probetest.PromTestSample {
		return []probetest.PromTestSample{
			// Skewed StatefulSet -> must be ignored.
			skewSample(ns, sts, "redis-0", 90000),
			skewSample(ns, sts, "redis-1", 2000),
			skewSample(ns, sts, "redis-2", 2000),
			// Idle Deployment (median 500 <= 1000) -> must be ignored.
			skewSample("apps", "idle", "idle-1", 10000),
			skewSample("apps", "idle", "idle-2", 500),
			skewSample("apps", "idle", "idle-3", 500),
		}
	})
	chk := probetest.MustCheck[*workloadConnectionSkewGuardCheck](t, p)
	_ = chk.Run(probetest.SweepCtx(ctx, p.Deps))
	probetest.FreezeNow(p.Deps, t0.Add(20*time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatalf("StatefulSet and low-median Deployment must pass: %+v", res)
	}
}

func TestConnectionSkewHottestPodRotationDeletesOldGaugeSeries(t *testing.T) {
	ns := "apps"
	deploy := "rotator"
	owner := types.UID("rs-rot")
	cs := fake.NewSimpleClientset(
		deployPod(ns, deploy+"-abc", "pod-a", owner, true),
		deployPod(ns, deploy+"-abc", "pod-b", owner, true),
		deployPod(ns, deploy+"-abc", "pod-c", owner, true),
		deployPod(ns, deploy+"-abc", "pod-d", owner, true),
	)
	p := testProber(cs)
	t0 := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	probetest.FreezeNow(p.Deps, t0)

	samples := []probetest.PromTestSample{
		skewSample(ns, deploy, "pod-a", 50000),
		skewSample(ns, deploy, "pod-b", 2000),
		skewSample(ns, deploy, "pod-c", 2000),
		skewSample(ns, deploy, "pod-d", 2000),
	}
	wireProm(t, p, func() []probetest.PromTestSample { return samples })
	t.Cleanup(func() {
		workloadConnectionSkewGauge.DeleteLabelValues(ns, deploy, "pod-a")
		workloadConnectionSkewGauge.DeleteLabelValues(ns, deploy, "pod-b")
	})

	chk := probetest.MustCheck[*workloadConnectionSkewGuardCheck](t, p)
	// t0: arm firstSeen for apps/rotator.
	if res := chk.Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatalf("first sight must pass: %+v", res)
	}
	// t0 + 16m: pod-a is hottest -> pod-a series emitted.
	probetest.FreezeNow(p.Deps, t0.Add(16*time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, p.Deps)); res.Pass {
		t.Fatal("expected FAIL with pod-a hottest")
	}
	if m := probetest.FindMetric(t, "node_automation_workload_connection_skew",
		map[string]string{"namespace": ns, "deployment": deploy, "pod": "pod-a"}); m == nil {
		t.Fatal("missing gauge series for pod-a")
	}

	// t0 + 17m: hottest pod rotates from pod-a to pod-b on the same Deployment.
	samples = []probetest.PromTestSample{
		skewSample(ns, deploy, "pod-a", 2000),
		skewSample(ns, deploy, "pod-b", 50000),
		skewSample(ns, deploy, "pod-c", 2000),
		skewSample(ns, deploy, "pod-d", 2000),
	}
	probetest.FreezeNow(p.Deps, t0.Add(17*time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, p.Deps)); res.Pass {
		t.Fatal("expected FAIL with pod-b hottest")
	}
	if m := probetest.FindMetric(t, "node_automation_workload_connection_skew",
		map[string]string{"namespace": ns, "deployment": deploy, "pod": "pod-a"}); m != nil {
		t.Fatal("stale gauge series for pod-a leaked after hottest pod rotated to pod-b")
	}
	if m := probetest.FindMetric(t, "node_automation_workload_connection_skew",
		map[string]string{"namespace": ns, "deployment": deploy, "pod": "pod-b"}); m == nil {
		t.Fatal("missing gauge series for pod-b after rotation")
	}
}

func TestConnectionSkewTwoReplicaDeploymentSkipped(t *testing.T) {
	ns := "apps"
	deploy := "two-pod"
	owner := types.UID("rs-two")
	cs := fake.NewSimpleClientset(
		deployPod(ns, deploy+"-abc", deploy+"-1", owner, true),
		deployPod(ns, deploy+"-abc", deploy+"-2", owner, true),
	)
	p := testProber(cs)
	t0 := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	probetest.FreezeNow(p.Deps, t0)
	wireProm(t, p, func() []probetest.PromTestSample {
		return []probetest.PromTestSample{
			skewSample(ns, deploy, deploy+"-1", 100000),
			skewSample(ns, deploy, deploy+"-2", 2000),
		}
	})
	chk := probetest.MustCheck[*workloadConnectionSkewGuardCheck](t, p)
	_ = chk.Run(probetest.SweepCtx(ctx, p.Deps))
	probetest.FreezeNow(p.Deps, t0.Add(20*time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatalf("2-replica Deployment must be skipped cleanly, got: %+v", res)
	}
}
