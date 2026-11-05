// operator_selfheal_test.go — the W5.8 operator-workqueue watchdog
// driven through the fake clientset + fake dynamic client (the
// self-healing checks half of the old self_healing_checks_test.go).
package watchdogs

import (
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/health/probetest"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/testutil"
)

// shLease builds a leader-election Lease renewing `age` before `at`.
func shLease(ns, name, holder string, age time.Duration, at time.Time) *coordinationv1.Lease {
	rt := metav1.NewMicroTime(at.Add(-age))
	return &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: coordinationv1.LeaseSpec{
			RenewTime:      &rt,
			HolderIdentity: &holder,
		},
	}
}

// shRenewLease moves renewTime to just before `at` — the "still
// renewing" precondition the watchdog requires as test time advances.
func shRenewLease(t *testing.T, cs *fake.Clientset, ns, name string, at time.Time) {
	t.Helper()
	lease, err := cs.CoordinationV1().Leases(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get lease %s/%s: %v", ns, name, err)
	}
	rt := metav1.NewMicroTime(at.Add(-2 * time.Second))
	lease.Spec.RenewTime = &rt
	if _, err := cs.CoordinationV1().Leases(ns).
		Update(ctx, lease, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("renew lease: %v", err)
	}
}

func shOpFrozenGauge(t *testing.T, operator, reason string) (float64, bool) {
	t.Helper()
	m := probetest.FindMetric(t, "node_automation_operator_workqueue_frozen",
		map[string]string{"operator": operator, "reason": reason})
	if m == nil {
		return 0, false
	}
	return m.GetGauge().GetValue(), true
}

func shOpHealsCount(t *testing.T, operator, reason string) float64 {
	t.Helper()
	m := probetest.FindMetric(t, "node_automation_operator_workqueue_heals_total",
		map[string]string{"operator": operator, "reason": reason})
	if m == nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

// ---------------------------------------------------------------------------
// W5.8 — stuck predicates
// ---------------------------------------------------------------------------

func TestOperatorStuckPredicates(t *testing.T) {
	stale := probetest.UnstructuredObj("scylla.scylladb.com/v1", "ScyllaCluster", "scylla", "db", 5, 3)
	if !staleObservedGeneration(stale) {
		t.Fatal("observedGeneration<generation must read as stuck")
	}
	caught := probetest.UnstructuredObj("scylla.scylladb.com/v1", "ScyllaCluster", "scylla", "db", 5, 5)
	if staleObservedGeneration(caught) {
		t.Fatal("observedGeneration==generation must not read as stuck")
	}
	// No status at all — the controller never touched the object:
	// observedGeneration reads 0 < generation → the strongest stuck
	// signal there is.
	never := probetest.UnstructuredObj("scylla.scylladb.com/v1", "ScyllaCluster", "scylla", "db", 1, 0)
	if !staleObservedGeneration(never) {
		t.Fatal("missing observedGeneration must read as stuck")
	}

	// Suspended flux objects are parked, not stuck.
	suspended := probetest.UnstructuredObj("helm.toolkit.fluxcd.io/v2", "HelmRelease", "apps", "hr", 5, 3)
	_ = unstructured.SetNestedField(suspended.Object, true, "spec", "suspend")
	if fluxUnsuspendedStaleGen(suspended) {
		t.Fatal("suspended HelmRelease must not count as stuck")
	}
	active := probetest.UnstructuredObj("helm.toolkit.fluxcd.io/v2", "HelmRelease", "apps", "hr", 5, 3)
	if !fluxUnsuspendedStaleGen(active) {
		t.Fatal("non-suspended stale HelmRelease must count as stuck")
	}

	// Gateway-API: empty/absent status.parents reads as stuck; the
	// generation signal lives inside each parent's conditions —
	// these types carry no top-level status.observedGeneration.
	route := probetest.UnstructuredObj("gateway.networking.k8s.io/v1", "HTTPRoute", "apps", "r", 1, 0)
	if !gatewayStatusStuck(route) {
		t.Fatal("route with no status.parents must read as stuck")
	}
	_ = unstructured.SetNestedSlice(route.Object,
		[]any{map[string]any{
			"parentRef": map[string]any{"name": "gw"},
			"conditions": []any{map[string]any{
				"type": "Accepted", "status": "True", "observedGeneration": int64(1)}},
		}},
		"status", "parents")
	if gatewayStatusStuck(route) {
		t.Fatal("route attached at the current generation must not read as stuck")
	}
	staleRoute := probetest.UnstructuredObj("gateway.networking.k8s.io/v1", "HTTPRoute", "apps", "r", 5, 0)
	_ = unstructured.SetNestedSlice(staleRoute.Object,
		[]any{map[string]any{
			"parentRef": map[string]any{"name": "gw"},
			"conditions": []any{map[string]any{
				"type": "Accepted", "status": "True", "observedGeneration": int64(3)}},
		}},
		"status", "parents")
	if !gatewayStatusStuck(staleRoute) {
		t.Fatal("route whose parents only saw gen 3 must read as stuck at gen 5")
	}
}

// ---------------------------------------------------------------------------
// W5.8 — operator-workqueue-watchdog
// ---------------------------------------------------------------------------

// No Lease at all → nothing to judge, the check stays quiet.
func TestCheckOperatorWorkqueuesNoLeaseQuiet(t *testing.T) {
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn())
	if res := mustCheck[*operatorWorkqueueCheck](t, p).Run(ctx); !res.Pass || res.Infra != nil {
		t.Fatalf("absent leases must pass quietly, got %+v", res)
	}
}

// A stale renewTime means the holder is GONE — a dead operator is a
// different failure class; the check neither tracks nor freezes.
func TestCheckOperatorWorkqueuesStaleLeaseQuiet(t *testing.T) {
	base := time.Now()
	cs := fake.NewSimpleClientset(
		shLease("scylla-operator", "scylla-operator-lock",
			"scylla-operator-abc_uid", 5*time.Minute, base))
	stuck := probetest.UnstructuredObj("scylla.scylladb.com/v1", "ScyllaCluster",
		"scylla", "db", 5, 3)
	p := testProberDyn(cs, probetest.OpDyn(stuck))
	p.Now = func() time.Time { return base }

	if res := mustCheck[*operatorWorkqueueCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("stale lease must pass quietly, got %+v", res)
	}
	if len(mustCheck[*operatorWorkqueueCheck](t, p).opFirstSeen) != 0 {
		t.Fatalf("stale-lease operator must not be tracked: %v", mustCheck[*operatorWorkqueueCheck](t, p).opFirstSeen)
	}
}

// A renewing Lease plus a ScyllaCluster stuck on
// observedGeneration<generation: first sighting tracks silently, past
// the 20m window the gauge goes to 1 AND the leader pod is deleted —
// holderIdentity's "<pod>_<uuid>" prefix resolves it.
func TestCheckOperatorWorkqueuesStuckThenHeals(t *testing.T) {
	metrics.OperatorWorkqueueFrozen.DeleteLabelValues("scylla-operator", kcmReasonStaleGen)
	t.Cleanup(func() {
		metrics.OperatorWorkqueueFrozen.DeleteLabelValues("scylla-operator", kcmReasonStaleGen)
	})
	base := time.Now()
	leader := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "scylla-operator", Name: "scylla-operator-7d9f",
			UID:    types.UID("leader-uid-1"),
			Labels: map[string]string{"app.kubernetes.io/name": "scylla-operator"},
		},
	}
	cs := fake.NewSimpleClientset(
		shLease("scylla-operator", "scylla-operator-lock",
			"scylla-operator-7d9f_3f2a1", 2*time.Second, base),
		leader)
	stuck := probetest.UnstructuredObj("scylla.scylladb.com/v1", "ScyllaCluster",
		"scylla", "db", 5, 3)
	p := testProberDyn(cs, probetest.OpDyn(stuck))
	p.Now = func() time.Time { return base }
	before := shOpHealsCount(t, "scylla-operator", kcmReasonStaleGen)

	// First sighting — tracked, not frozen, no heal.
	if res := mustCheck[*operatorWorkqueueCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("first-seen signature must pass: %+v", res)
	}
	if len(mustCheck[*operatorWorkqueueCheck](t, p).opFirstSeen) != 1 {
		t.Fatalf("signature not tracked: %v", mustCheck[*operatorWorkqueueCheck](t, p).opFirstSeen)
	}
	if v, ok := shOpFrozenGauge(t, "scylla-operator", kcmReasonStaleGen); ok && v != 0 {
		t.Fatalf("frozen gauge = %v before the window, want absent/0", v)
	}
	if _, err := cs.CoreV1().Pods("scylla-operator").
		Get(ctx, "scylla-operator-7d9f", metav1.GetOptions{}); err != nil {
		t.Fatal("leader pod must not be deleted before the stuck window")
	}

	// Past the 20m stuck window — frozen + healed.
	at := base.Add(21 * time.Minute)
	shRenewLease(t, cs, "scylla-operator", "scylla-operator-lock", at)
	p.Now = func() time.Time { return at }
	res := mustCheck[*operatorWorkqueueCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("stuck >=20m with a renewing lease must FAIL")
	}
	if v, _ := shOpFrozenGauge(t, "scylla-operator", kcmReasonStaleGen); v != 1 {
		t.Fatalf("frozen gauge = %v, want 1", v)
	}
	_, err := cs.CoreV1().Pods("scylla-operator").
		Get(ctx, "scylla-operator-7d9f", metav1.GetOptions{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("leader pod must be deleted, got err=%v", err)
	}
	if got := shOpHealsCount(t, "scylla-operator", kcmReasonStaleGen); got != before+1 {
		t.Fatalf("heals total = %v, want %v", got, before+1)
	}
	// The heal stamp landed on the Lease — the durable cooldown.
	gotLease, err := cs.CoordinationV1().Leases("scylla-operator").
		Get(ctx, "scylla-operator-lock", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if gotLease.Annotations[operatorHealAnno] == "" {
		t.Fatal("heal stamp annotation missing on the Lease")
	}
}

// Inside the 1h heal cooldown a replacement leader is left alone —
// the wider of the in-RAM ledger and the persisted stamp governs.
func TestCheckOperatorWorkqueuesHealCooldown(t *testing.T) {
	metrics.OperatorWorkqueueFrozen.DeleteLabelValues("scylla-operator", kcmReasonStaleGen)
	t.Cleanup(func() {
		metrics.OperatorWorkqueueFrozen.DeleteLabelValues("scylla-operator", kcmReasonStaleGen)
	})
	base := time.Now()
	cs := fake.NewSimpleClientset(
		shLease("scylla-operator", "scylla-operator-lock",
			"scylla-operator-7d9f_3f2a1", 2*time.Second, base),
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: "scylla-operator", Name: "scylla-operator-7d9f",
			UID:    types.UID("leader-uid-1"),
			Labels: map[string]string{"app.kubernetes.io/name": "scylla-operator"},
		}})
	stuck := probetest.UnstructuredObj("scylla.scylladb.com/v1", "ScyllaCluster",
		"scylla", "db", 5, 3)
	p := testProberDyn(cs, probetest.OpDyn(stuck))
	p.Now = func() time.Time { return base }
	// Seed first-seen long ago so the signature is already frozen.
	mustCheck[*operatorWorkqueueCheck](t, p).opFirstSeen["scylla-operator/scyllaclusters/scylla/db"] = base.Add(-time.Hour)

	res := mustCheck[*operatorWorkqueueCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("precondition: stuck signature must FAIL")
	}
	// Replacement leader (new name suffix, new uid) inside the
	// cooldown — must NOT be deleted.
	replacement := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "scylla-operator", Name: "scylla-operator-88zz",
		UID:    types.UID("leader-uid-2"),
		Labels: map[string]string{"app.kubernetes.io/name": "scylla-operator"},
	}}
	if _, err := cs.CoreV1().Pods("scylla-operator").
		Create(ctx, replacement, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	at := base.Add(10 * time.Minute)
	shRenewLease(t, cs, "scylla-operator", "scylla-operator-lock", at)
	lease, _ := cs.CoordinationV1().Leases("scylla-operator").
		Get(ctx, "scylla-operator-lock", metav1.GetOptions{})
	holder := "scylla-operator-88zz_9b8c"
	lease.Spec.HolderIdentity = &holder
	if _, err := cs.CoordinationV1().Leases("scylla-operator").
		Update(ctx, lease, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	p.Now = func() time.Time { return at }
	res = mustCheck[*operatorWorkqueueCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("still-stuck signature must keep FAILING")
	}
	if _, err := cs.CoreV1().Pods("scylla-operator").
		Get(ctx, "scylla-operator-88zz", metav1.GetOptions{}); err != nil {
		t.Fatal("replacement leader deleted inside the 1h cooldown")
	}
}

// A fresh prober whose opHealed ledger is empty must STILL honor the
// cooldown — the persisted Lease annotation carries it across
// operator restarts.
func TestCheckOperatorWorkqueuesPersistedCooldown(t *testing.T) {
	metrics.OperatorWorkqueueFrozen.DeleteLabelValues("scylla-operator", kcmReasonStaleGen)
	t.Cleanup(func() {
		metrics.OperatorWorkqueueFrozen.DeleteLabelValues("scylla-operator", kcmReasonStaleGen)
	})
	base := time.Now()
	lease := shLease("scylla-operator", "scylla-operator-lock",
		"scylla-operator-7d9f_3f2a1", 2*time.Second, base)
	lease.Annotations = map[string]string{
		operatorHealAnno: base.Add(-10 * time.Minute).UTC().Format(time.RFC3339),
	}
	cs := fake.NewSimpleClientset(lease,
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: "scylla-operator", Name: "scylla-operator-7d9f",
			UID:    types.UID("leader-uid-1"),
			Labels: map[string]string{"app.kubernetes.io/name": "scylla-operator"},
		}})
	stuck := probetest.UnstructuredObj("scylla.scylladb.com/v1", "ScyllaCluster",
		"scylla", "db", 5, 3)
	p := testProberDyn(cs, probetest.OpDyn(stuck))
	p.Now = func() time.Time { return base }
	mustCheck[*operatorWorkqueueCheck](t, p).opFirstSeen["scylla-operator/scyllaclusters/scylla/db"] = base.Add(-time.Hour)

	res := mustCheck[*operatorWorkqueueCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("stuck signature must FAIL regardless of heal cooldown")
	}
	if _, err := cs.CoreV1().Pods("scylla-operator").
		Get(ctx, "scylla-operator-7d9f", metav1.GetOptions{}); err != nil {
		t.Fatal("leader pod deleted inside the persisted cooldown")
	}
}

// Deliberate maintenance defers the heal: a cordoned node means a
// drain is in flight — killing a leader mid-drain is never safe.
// The frozen gauge still fires: detection and remediation are
// independent.
func TestCheckOperatorWorkqueuesMaintenanceDefers(t *testing.T) {
	metrics.OperatorWorkqueueFrozen.DeleteLabelValues("scylla-operator", kcmReasonStaleGen)
	t.Cleanup(func() {
		metrics.OperatorWorkqueueFrozen.DeleteLabelValues("scylla-operator", kcmReasonStaleGen)
	})
	base := time.Now()
	cordoned := testutil.Node("n1", corev1.ConditionTrue, nil)
	cordoned.Spec.Unschedulable = true
	cs := fake.NewSimpleClientset(cordoned,
		shLease("scylla-operator", "scylla-operator-lock",
			"scylla-operator-7d9f_3f2a1", 2*time.Second, base),
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: "scylla-operator", Name: "scylla-operator-7d9f",
			UID:    types.UID("leader-uid-1"),
			Labels: map[string]string{"app.kubernetes.io/name": "scylla-operator"},
		}})
	stuck := probetest.UnstructuredObj("scylla.scylladb.com/v1", "ScyllaCluster",
		"scylla", "db", 5, 3)
	p := testProberDyn(cs, probetest.OpDyn(stuck))
	p.Now = func() time.Time { return base }
	mustCheck[*operatorWorkqueueCheck](t, p).opFirstSeen["scylla-operator/scyllaclusters/scylla/db"] = base.Add(-time.Hour)

	res := mustCheck[*operatorWorkqueueCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("maintenance must defer the heal, not the detection")
	}
	if v, _ := shOpFrozenGauge(t, "scylla-operator", kcmReasonStaleGen); v != 1 {
		t.Fatalf("frozen gauge = %v during maintenance, want 1", v)
	}
	if _, err := cs.CoreV1().Pods("scylla-operator").
		Get(ctx, "scylla-operator-7d9f", metav1.GetOptions{}); err != nil {
		t.Fatal("leader pod deleted during maintenance")
	}
}

// A suspended HelmRelease is parked, not stuck — the flux path must
// not freeze on deliberately-suspended objects.
func TestCheckOperatorWorkqueuesSuspendedFluxIgnored(t *testing.T) {
	metrics.OperatorWorkqueueFrozen.DeleteLabelValues("helm-controller", kcmReasonStaleGen)
	base := time.Now()
	cs := fake.NewSimpleClientset(
		shLease("flux-system", "helm-controller-leader-election",
			"helm-controller-aa_uid", 2*time.Second, base))
	suspended := probetest.UnstructuredObj("helm.toolkit.fluxcd.io/v2", "HelmRelease",
		"apps", "hr", 5, 3)
	_ = unstructured.SetNestedField(suspended.Object, true, "spec", "suspend")
	p := testProberDyn(cs, probetest.OpDyn(suspended))
	p.Now = func() time.Time { return base }
	mustCheck[*operatorWorkqueueCheck](t, p).opFirstSeen["helm-controller/helmreleases/apps/hr"] = base.Add(-time.Hour)

	if res := mustCheck[*operatorWorkqueueCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("suspended HelmRelease must not freeze the check: %+v", res)
	}
	if _, ok := mustCheck[*operatorWorkqueueCheck](t, p).opFirstSeen["helm-controller/helmreleases/apps/hr"]; ok {
		t.Fatal("suspended-object tracking must be pruned")
	}
}

// When the leader can't be resolved by holderIdentity, the operator's
// pod label selector inside the Lease's namespace picks the pod.
func TestCheckOperatorWorkqueuesSelectorFallback(t *testing.T) {
	metrics.OperatorWorkqueueFrozen.DeleteLabelValues("dragonfly-operator", kcmReasonStaleGen)
	t.Cleanup(func() {
		metrics.OperatorWorkqueueFrozen.DeleteLabelValues("dragonfly-operator", kcmReasonStaleGen)
	})
	base := time.Now()
	opPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "dragonfly-operator-system",
		Name:      "dragonfly-operator-controller-manager-6f8bc-xy",
		UID:       types.UID("dr-uid-1"),
		Labels:    map[string]string{"control-plane": "controller-manager"},
	}}
	cs := fake.NewSimpleClientset(
		// Holder identity names a pod that doesn't exist (opaque
		// suffix) — the selector must resolve the real one.
		shLease("dragonfly-operator-system", "7898635c.dragonflydb.io",
			"does-not-exist_uuid", 2*time.Second, base),
		opPod)
	stuck := probetest.UnstructuredObj("dragonflydb.io/v1alpha1", "Dragonfly",
		"db", "cache", 9, 4)
	p := testProberDyn(cs, probetest.OpDyn(stuck))
	p.Now = func() time.Time { return base }
	mustCheck[*operatorWorkqueueCheck](t, p).opFirstSeen["dragonfly-operator/dragonflies/db/cache"] = base.Add(-time.Hour)

	if res := mustCheck[*operatorWorkqueueCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("stuck dragonfly must FAIL")
	}
	if _, err := cs.CoreV1().Pods("dragonfly-operator-system").
		Get(ctx, opPod.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("selector fallback must delete the resolved leader pod, err=%v", err)
	}
}

// ---------------------------------------------------------------------------
// W10-FIX2 — podNS override + leaseOptional + multi-candidate leases
// ---------------------------------------------------------------------------

// cert-manager elects its leader in kube-system but runs its pods in
// the cert-manager namespace — the heal must resolve and delete the
// pod in cert-manager, never a same-named pod in kube-system.
func TestCheckOperatorWorkqueuesCertManagerPodNS(t *testing.T) {
	base := time.Now()
	cs := fake.NewSimpleClientset(
		shLease("kube-system", "cert-manager-controller",
			"cert-manager-cm-7d9f_uid", 2*time.Second, base),
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: "cert-manager", Name: "cert-manager-cm-7d9f",
			UID:    types.UID("cm-leader-1"),
			Labels: map[string]string{"app.kubernetes.io/name": "cert-manager"},
		}},
		// Decoy: same selector, wrong namespace — must survive.
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: "kube-system", Name: "cert-manager-cm-7d9f",
			UID:    types.UID("cm-decoy"),
			Labels: map[string]string{"app.kubernetes.io/name": "cert-manager"},
		}})
	stuck := probetest.UnstructuredObj("cert-manager.io/v1", "Certificate",
		"apps", "tls", 5, 3)
	p := testProberDyn(cs, probetest.OpDyn(stuck))
	p.Now = func() time.Time { return base }
	mustCheck[*operatorWorkqueueCheck](t, p).opFirstSeen["cert-manager/certificates/apps/tls"] = base.Add(-time.Hour)

	res := mustCheck[*operatorWorkqueueCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("stuck certificate must FAIL")
	}
	if _, err := cs.CoreV1().Pods("cert-manager").
		Get(ctx, "cert-manager-cm-7d9f", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("cert-manager-ns leader pod must be deleted, err=%v", err)
	}
	if _, err := cs.CoreV1().Pods("kube-system").
		Get(ctx, "cert-manager-cm-7d9f", metav1.GetOptions{}); err != nil {
		t.Fatal("kube-system decoy pod must NOT be touched (podNS override)")
	}
}

// dragonfly-operator runs --leader-elect disabled (replicas:1): no
// Lease exists at all, so the Running-pod fallback must carry both
// the liveness proof and the heal path.
func TestCheckOperatorWorkqueuesDragonflyLeaseOptional(t *testing.T) {
	base := time.Now()
	opPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: probefw.DragonflyOperatorNS,
			Name:      "dragonfly-operator-controller-manager-6f8bc-xy",
			UID:       types.UID("dr-op-1"),
			Labels:    map[string]string{"control-plane": "controller-manager"},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	// NO lease — leaseOptional must carry the check.
	cs := fake.NewSimpleClientset(opPod)
	stuck := probetest.UnstructuredObj("dragonflydb.io/v1alpha1", "Dragonfly",
		"db", "cache", 9, 4)
	p := testProberDyn(cs, probetest.OpDyn(stuck))
	p.Now = func() time.Time { return base }
	mustCheck[*operatorWorkqueueCheck](t, p).opFirstSeen["dragonfly-operator/dragonflies/db/cache"] = base.Add(-time.Hour)

	res := mustCheck[*operatorWorkqueueCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("stuck dragonfly with live pod must FAIL (leaseOptional)")
	}
	if _, err := cs.CoreV1().Pods(probefw.DragonflyOperatorNS).
		Get(ctx, opPod.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("selector-fallback heal must delete the pod, err=%v", err)
	}
}

// operatorLease tries every candidate name — the second entry wins
// when the first is absent (Percona/medik8s election-id rotation).
func TestOperatorLeaseCandidateFallback(t *testing.T) {
	base := time.Now()
	cs := fake.NewSimpleClientset(
		shLease("operators", "second-choice",
			"holder_uid", 2*time.Second, base))
	op := operatorTarget{
		name: "x", leaseNS: "operators",
		leaseNames: []string{"missing-first", "second-choice"},
	}
	p := testProberDyn(cs, probetest.OpDyn())
	lease, err := mustCheck[*operatorWorkqueueCheck](t, p).operatorLease(ctx, op)
	if err != nil {
		t.Fatalf("operatorLease: %v", err)
	}
	if lease == nil || lease.Name != "second-choice" {
		t.Fatalf("lease = %v, want second-choice", lease)
	}
	// All candidates absent → (nil, nil), not an error.
	op.leaseNames = []string{"missing-first", "missing-second"}
	lease, err = mustCheck[*operatorWorkqueueCheck](t, p).operatorLease(ctx, op)
	if err != nil || lease != nil {
		t.Fatalf("absent candidates must give (nil,nil), got %v, %v", lease, err)
	}
}

// A W10-CP3 target end-to-end: node-healthcheck-operator's renewing
// lease plus a never-reconciled NodeHealthCheck freezes the gauge.
func TestCheckOperatorWorkqueuesMedik8sTarget(t *testing.T) {
	metrics.OperatorWorkqueueFrozen.DeleteLabelValues(
		"node-healthcheck-operator", opReasonNoStatus)
	t.Cleanup(func() {
		metrics.OperatorWorkqueueFrozen.DeleteLabelValues(
			"node-healthcheck-operator", opReasonNoStatus)
	})
	base := time.Now()
	cs := fake.NewSimpleClientset(
		shLease("operators", "e1f13584.medik8s.io",
			"nhc-aa_uid", 2*time.Second, base))
	nhc := probetest.UnstructuredObj("remediation.medik8s.io/v1alpha1",
		"NodeHealthCheck", "operators", "nhc", 3, 0)
	p := testProberDyn(cs, probetest.OpDyn(nhc))
	p.Now = func() time.Time { return base }
	mustCheck[*operatorWorkqueueCheck](t, p).opFirstSeen["node-healthcheck-operator/nodehealthchecks/operators/nhc"] =
		base.Add(-time.Hour)

	if res := mustCheck[*operatorWorkqueueCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("never-reconciled NodeHealthCheck must FAIL")
	}
	if v, _ := shOpFrozenGauge(t, "node-healthcheck-operator",
		opReasonNoStatus); v != 1 {
		t.Fatalf("frozen gauge = %v, want 1", v)
	}
}
