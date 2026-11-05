// kcm_workqueue_watchdog_test.go — the C6 kube-controller-manager
// workqueue watchdog driven through the fake clientset.
package watchdogs

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
)

// ---------------------------------------------------------------------------
// kcm-workqueue-watchdog (C6)
// ---------------------------------------------------------------------------

func kcmReadyNode() *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "n1"},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{
			Type:   corev1.NodeReady,
			Status: corev1.ConditionTrue,
		}}},
	}
}

// kcmLease builds the kube-controller-manager leader Lease with
// renewTime `age` before `at`.
func kcmLease(age time.Duration, at time.Time) *coordinationv1.Lease {
	rt := metav1.NewMicroTime(at.Add(-age))
	return &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: metav1.NamespaceSystem,
			Name:      "kube-controller-manager",
		},
		Spec: coordinationv1.LeaseSpec{RenewTime: &rt},
	}
}

// renewKCMLease moves renewTime to just before `at` — the "still
// renewing" signal the watchdog requires as test time advances.
func renewKCMLease(t *testing.T, cs *fake.Clientset, at time.Time) {
	t.Helper()
	lease, err := cs.CoordinationV1().Leases(metav1.NamespaceSystem).
		Get(ctx, "kube-controller-manager", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get lease: %v", err)
	}
	rt := metav1.NewMicroTime(at.Add(-2 * time.Second))
	lease.Spec.RenewTime = &rt
	if _, err := cs.CoordinationV1().Leases(metav1.NamespaceSystem).
		Update(ctx, lease, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("renew lease: %v", err)
	}
}

// kcmDesiredZeroDS is the freeze signature: desired dropped to 0 while
// pods remain scheduled — the DS controller stopped recomputing.
func kcmDesiredZeroDS() *appsv1.DaemonSet {
	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  metav1.NamespaceSystem,
			Name:       "cilium",
			Generation: 1,
		},
		Status: appsv1.DaemonSetStatus{
			ObservedGeneration:     1,
			DesiredNumberScheduled: 0,
			CurrentNumberScheduled: 5,
		},
	}
}

func kcmFrozenGauge(t *testing.T, reason string) (float64, bool) {
	t.Helper()
	m := probetest.FindMetric(t, "node_automation_kcm_workqueue_frozen",
		map[string]string{"reason": reason})
	if m == nil {
		return 0, false
	}
	return m.GetGauge().GetValue(), true
}

// resetKCMFrozenSeries drops the gauge's reason series: the registry
// is process-global across the package, so a value held at 1 by an
// earlier test would leak into "want absent/0" assertions here.
func resetKCMFrozenSeries(t *testing.T, reasons ...string) {
	t.Helper()
	for _, r := range reasons {
		metrics.KCMWorkqueueFrozen.DeleteLabelValues(r)
	}
}

// The freeze gauge fires only after the signature persists the full
// min-age window — first sighting and a mid-window observation pass.
func TestCheckKCMWorkqueueFreezeAfterMinAge(t *testing.T) {
	resetKCMFrozenSeries(t, "daemonset_desired_zero")
	base := time.Now()
	cs := fake.NewSimpleClientset(
		kcmReadyNode(),
		kcmLease(2*time.Second, base),
		kcmDesiredZeroDS(),
	)
	p := testProber(cs)
	p.Now = func() time.Time { return base }

	// First sighting stamps first-seen — quiet.
	if res := probetest.MustCheck[*kcmWorkqueueCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("first-seen signature must pass: %+v", res)
	}
	if _, ok := probetest.MustCheck[*kcmWorkqueueCheck](t, p).kcmFirstSeen.
		Seen("daemonset_desired_zero/daemonset/cilium", base); !ok {
		t.Fatal("signature not tracked in kcmFirstSeen")
	}
	if v, ok := kcmFrozenGauge(t, "daemonset_desired_zero"); ok && v != 0 {
		t.Fatalf("frozen gauge = %v before minAge, want absent/0", v)
	}

	// Inside the window — still quiet.
	at := base.Add(9 * time.Minute)
	renewKCMLease(t, cs, at)
	p.Now = func() time.Time { return at }
	if res := probetest.MustCheck[*kcmWorkqueueCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("signature at 9m must still pass: %+v", res)
	}
	if v, _ := kcmFrozenGauge(t, "daemonset_desired_zero"); v != 0 {
		t.Fatalf("frozen gauge = %v inside window, want 0", v)
	}

	// Past the persistence window the freeze fires.
	at = base.Add(10 * time.Minute)
	renewKCMLease(t, cs, at)
	p.Now = func() time.Time { return at }
	if res := probetest.MustCheck[*kcmWorkqueueCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("signature persisted >=10m must FAIL")
	}
	if v, _ := kcmFrozenGauge(t, "daemonset_desired_zero"); v != 1 {
		t.Fatalf("frozen gauge = %v, want 1", v)
	}
}

// A kube-system Deployment or DaemonSet whose observedGeneration lags
// generation flags stale_observed_generation once past the window.
func TestCheckKCMWorkqueueStaleObservedGeneration(t *testing.T) {
	resetKCMFrozenSeries(t, "stale_observed_generation")
	base := time.Now()
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  metav1.NamespaceSystem,
			Name:       "coredns",
			Generation: 5,
		},
		Status: appsv1.DeploymentStatus{ObservedGeneration: 3},
	}
	// A DS caught up to its spec is not a signature alongside it.
	settled := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  metav1.NamespaceSystem,
			Name:       "kube-proxy",
			Generation: 2,
		},
		Status: appsv1.DaemonSetStatus{
			ObservedGeneration:     2,
			DesiredNumberScheduled: 4,
			CurrentNumberScheduled: 4,
			NumberReady:            4,
		},
	}
	cs := fake.NewSimpleClientset(
		kcmReadyNode(),
		kcmLease(2*time.Second, base),
		dep, settled,
	)
	p := testProber(cs)
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*kcmWorkqueueCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("first-seen signature must pass: %+v", res)
	}
	if _, ok := probetest.MustCheck[*kcmWorkqueueCheck](t, p).kcmFirstSeen.
		Seen("stale_observed_generation/deployment/coredns", base); !ok {
		t.Fatal("deployment signature not tracked")
	}
	if keys := probetest.LedgerKeys(&probetest.MustCheck[*kcmWorkqueueCheck](t, p).kcmFirstSeen); len(keys) != 1 {
		t.Fatalf("settled DS must not be tracked: %v", keys)
	}

	at := base.Add(11 * time.Minute)
	renewKCMLease(t, cs, at)
	p.Now = func() time.Time { return at }
	res := probetest.MustCheck[*kcmWorkqueueCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("stale observedGeneration >=10m must FAIL")
	}
	if v, _ := kcmFrozenGauge(t, "stale_observed_generation"); v != 1 {
		t.Fatalf("frozen gauge = %v, want 1", v)
	}
	if !strings.Contains(res.Why, "stale_observed_generation") {
		t.Fatalf("why = %q, want the reason label", res.Why)
	}
}

// A stale renewTime means the KCM is DEAD — a different failure — so
// freeze-looking signatures must not fire, and any held state clears.
func TestCheckKCMWorkqueueQuietOnStaleLease(t *testing.T) {
	resetKCMFrozenSeries(t, "daemonset_desired_zero")
	base := time.Now()
	cs := fake.NewSimpleClientset(
		kcmReadyNode(),
		kcmLease(10*time.Minute, base), // renewTime far past maxAge
		kcmDesiredZeroDS(),
	)
	p := testProber(cs)
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*kcmWorkqueueCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("stale KCM lease must stay quiet: %+v", res)
	}
	if v, _ := kcmFrozenGauge(t, "daemonset_desired_zero"); v != 0 {
		t.Fatalf("frozen gauge = %v on stale lease, want absent/0", v)
	}
	if keys := probetest.LedgerKeys(&probetest.MustCheck[*kcmWorkqueueCheck](t, p).kcmFirstSeen); len(keys) != 0 {
		t.Fatalf("stale lease left %d tracked signatures", len(keys))
	}

	// A previously-frozen gauge also clears when the holder dies.
	probetest.MustCheck[*kcmWorkqueueCheck](t, p).kcmFrozenReasons["daemonset_desired_zero"] = true
	metrics.KCMWorkqueueFrozen.WithLabelValues("daemonset_desired_zero").Set(1)
	if res := probetest.MustCheck[*kcmWorkqueueCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("stale KCM lease must stay quiet: %+v", res)
	}
	if v, ok := kcmFrozenGauge(t, "daemonset_desired_zero"); !ok || v != 0 {
		t.Fatalf("held gauge on dead KCM = %v,%v want 0", v, ok)
	}

	// No Lease object at all — same quiet path.
	p = testProber(fake.NewSimpleClientset(kcmReadyNode(), kcmDesiredZeroDS()))
	p.Now = func() time.Time { return base }
	if res := probetest.MustCheck[*kcmWorkqueueCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("missing KCM lease must stay quiet: %+v", res)
	}
}

// With no Ready node the desired==0 reading is ambiguous — quiet.
func TestCheckKCMWorkqueueQuietOnNoReadyNodes(t *testing.T) {
	resetKCMFrozenSeries(t, "daemonset_desired_zero")
	base := time.Now()

	// Zero nodes at all.
	cs := fake.NewSimpleClientset(kcmLease(2*time.Second, base), kcmDesiredZeroDS())
	p := testProber(cs)
	p.Now = func() time.Time { return base }
	if res := probetest.MustCheck[*kcmWorkqueueCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("no nodes must stay quiet: %+v", res)
	}

	// Every node NotReady — same.
	notReady := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "n1"},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{
			Type:   corev1.NodeReady,
			Status: corev1.ConditionFalse,
		}}},
	}
	cs = fake.NewSimpleClientset(notReady, kcmLease(2*time.Second, base), kcmDesiredZeroDS())
	p = testProber(cs)
	p.Now = func() time.Time { return base }
	if res := probetest.MustCheck[*kcmWorkqueueCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("all nodes NotReady must stay quiet: %+v", res)
	}
	if v, _ := kcmFrozenGauge(t, "daemonset_desired_zero"); v != 0 {
		t.Fatalf("frozen gauge = %v with no ready nodes, want absent/0", v)
	}
	if keys := probetest.LedgerKeys(&probetest.MustCheck[*kcmWorkqueueCheck](t, p).kcmFirstSeen); len(keys) != 0 {
		t.Fatalf("no-ready-nodes left %d tracked signatures", len(keys))
	}
}

// Once the DS reconciles again the signature drops, first-seen is
// pruned and the gauge flips back to 0.
func TestCheckKCMWorkqueueRecoveryClearsGauge(t *testing.T) {
	resetKCMFrozenSeries(t, "daemonset_desired_zero")
	base := time.Now()
	cs := fake.NewSimpleClientset(
		kcmReadyNode(),
		kcmLease(2*time.Second, base),
		kcmDesiredZeroDS(),
	)
	p := testProber(cs)
	p.Now = func() time.Time { return base }

	// Drive past the window into frozen.
	if res := probetest.MustCheck[*kcmWorkqueueCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("first-seen signature must pass: %+v", res)
	}
	at := base.Add(11 * time.Minute)
	renewKCMLease(t, cs, at)
	p.Now = func() time.Time { return at }
	if res := probetest.MustCheck[*kcmWorkqueueCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("expected frozen FAIL")
	}
	if v, _ := kcmFrozenGauge(t, "daemonset_desired_zero"); v != 1 {
		t.Fatalf("frozen gauge = %v, want 1", v)
	}

	// KCM catches up: desired recomputed to match the scheduled pods.
	at = base.Add(12 * time.Minute)
	renewKCMLease(t, cs, at)
	p.Now = func() time.Time { return at }
	ds, err := cs.AppsV1().DaemonSets(metav1.NamespaceSystem).
		Get(ctx, "cilium", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get ds: %v", err)
	}
	ds.Status.DesiredNumberScheduled = 5
	if _, err := cs.AppsV1().DaemonSets(metav1.NamespaceSystem).
		Update(ctx, ds, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update ds: %v", err)
	}

	if res := probetest.MustCheck[*kcmWorkqueueCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("recovered signature must pass: %+v", res)
	}
	if v, ok := kcmFrozenGauge(t, "daemonset_desired_zero"); !ok || v != 0 {
		t.Fatalf("frozen gauge after recovery = %v,%v want 0", v, ok)
	}
	if keys := probetest.LedgerKeys(&probetest.MustCheck[*kcmWorkqueueCheck](t, p).kcmFirstSeen); len(keys) != 0 {
		t.Fatalf("resolved signature not pruned: %v", keys)
	}
}

// HEALTH_* env knobs: garbage strings, zero and negative values must
// not silently produce dangerous config — HEALTH_CHECK_TIMEOUT=0
// would instant-fail every probe, HEALTH_MAX_POD_RESTARTS=-1 would
// flag every container, and a 0s interval would panic the ticker.
// Each falls back to the default (and logs a warning) via the shared
// env helpers.
// desired==0 with zero pods anywhere is a legitimately-empty selector
// — not a freeze — and it must never even enter first-seen tracking.
func TestCheckKCMWorkqueueIgnoresEmptyDaemonSet(t *testing.T) {
	resetKCMFrozenSeries(t, "daemonset_desired_zero")
	base := time.Now()
	empty := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  metav1.NamespaceSystem,
			Name:       "hw-agent",
			Generation: 1,
		},
		Status: appsv1.DaemonSetStatus{
			ObservedGeneration:     1,
			DesiredNumberScheduled: 0,
			// nothing scheduled/ready/misscheduled anywhere
		},
	}
	cs := fake.NewSimpleClientset(
		kcmReadyNode(),
		kcmLease(2*time.Second, base),
		empty,
	)
	p := testProber(cs)
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*kcmWorkqueueCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("empty DaemonSet must pass: %+v", res)
	}
	at := base.Add(30 * time.Minute)
	renewKCMLease(t, cs, at)
	p.Now = func() time.Time { return at }
	if res := probetest.MustCheck[*kcmWorkqueueCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("empty DaemonSet must never freeze: %+v", res)
	}
	if v, _ := kcmFrozenGauge(t, "daemonset_desired_zero"); v != 0 {
		t.Fatalf("frozen gauge = %v, want absent/0", v)
	}
	if keys := probetest.LedgerKeys(&probetest.MustCheck[*kcmWorkqueueCheck](t, p).kcmFirstSeen); len(keys) != 0 {
		t.Fatalf("non-signature must not be tracked: %v", keys)
	}
}
