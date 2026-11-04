// self_healing_checks_test.go — the W5.8 operator-workqueue watchdog,
// W6.2 stateful-masterless guard and W6.4 rabbitmq suspended-listener
// healer, driven through the fake clientset + fake dynamic client.
package clusterhealthprobes

import (
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// Builders (sh-prefixed)
// ---------------------------------------------------------------------------

// shOpDyn registers every GVR the self-healing checks scan — the fake
// dynamic client PANICS on an unregistered GVR List, so every watched
// operator resource (W5.8 original five + the ten W7-C2 additions)
// plus the OLM/autopilot reads must be mapped.
func shOpDyn(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return testutil.NewFakeDyn(map[schema.GroupVersionResource]string{
		gwv1("gateways"):   "GatewayList",
		gwv1("httproutes"): "HTTPRouteList",
		gwv1("grpcroutes"): "GRPCRouteList",
		// The owns filter LISTs classes once per stuck gateway-api
		// object — unregistered GVR panics the fake.
		gwv1("gatewayclasses"): "GatewayClassList",
		{Group: "scylla.scylladb.com", Version: "v1", Resource: "scyllaclusters"}:         "ScyllaClusterList",
		{Group: "dragonflydb.io", Version: "v1alpha1", Resource: "dragonflies"}:           "DragonflyList",
		{Group: "helm.toolkit.fluxcd.io", Version: "v2", Resource: "helmreleases"}:        "HelmReleaseList",
		{Group: "kustomize.toolkit.fluxcd.io", Version: "v1", Resource: "kustomizations"}: "KustomizationList",
		// W7-C2 — the ten additional watched operators' CRDs.
		{Group: "source.toolkit.fluxcd.io", Version: "v1", Resource: "gitrepositories"}:      "GitRepositoryList",
		{Group: "source.toolkit.fluxcd.io", Version: "v1", Resource: "helmrepositories"}:     "HelmRepositoryList",
		{Group: "source.toolkit.fluxcd.io", Version: "v1", Resource: "helmcharts"}:           "HelmChartList",
		{Group: "source.toolkit.fluxcd.io", Version: "v1", Resource: "ocirepositories"}:      "OCIRepositoryList",
		{Group: "source.toolkit.fluxcd.io", Version: "v1", Resource: "buckets"}:              "BucketList",
		{Group: "notification.toolkit.fluxcd.io", Version: "v1beta3", Resource: "alerts"}:    "AlertList",
		{Group: "notification.toolkit.fluxcd.io", Version: "v1beta3", Resource: "providers"}: "ProviderList",
		{Group: "notification.toolkit.fluxcd.io", Version: "v1beta3", Resource: "receivers"}: "ReceiverList",
		{Group: "cert-manager.io", Version: "v1", Resource: "certificates"}:                  "CertificateList",
		{Group: "external-secrets.io", Version: "v1", Resource: "externalsecrets"}:           "ExternalSecretList",
		{Group: "external-secrets.io", Version: "v1beta1", Resource: "externalsecrets"}:      "ExternalSecretList",
		{Group: "rabbitmq.com", Version: "v1beta1", Resource: "rabbitmqclusters"}:            "RabbitmqClusterList",
		{Group: "keda.sh", Version: "v1alpha1", Resource: "scaledobjects"}:                   "ScaledObjectList",
		{Group: "argoproj.io", Version: "v1beta1", Resource: "argocds"}:                      "ArgoCDList",
		{Group: "kargo.akuity.io", Version: "v1alpha1", Resource: "stages"}:                  "StageList",
		{Group: "kargo.akuity.io", Version: "v1alpha1", Resource: "warehouses"}:              "WarehouseList",
		{Group: "everest.percona.com", Version: "v1alpha1", Resource: "databaseclusters"}:    "DatabaseClusterList",
		{Group: "shipwright.io", Version: "v1beta1", Resource: "builds"}:                     "BuildList",
		// W7-C5 — OLM reads.
		olmCSVGVR: "ClusterServiceVersionList",
		olmSubGVR: "SubscriptionList",
		// Maintenance mutex read.
		shared.AutopilotPlanGVR: "PlanList",
	}, objs...)
}

// shUnstructured builds a CR object carrying a generation and an
// optional status.observedGeneration (og=0 leaves the field absent).
func shUnstructured(apiVersion, kind, ns, name string, gen, og int64) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata": map[string]any{
			"namespace": ns, "name": name, "generation": gen,
		},
	}}
	if og > 0 {
		_ = unstructured.SetNestedField(obj.Object, og, "status", "observedGeneration")
	}
	return obj
}

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
	m := findMetric(t, "node_automation_operator_workqueue_frozen",
		map[string]string{"operator": operator, "reason": reason})
	if m == nil {
		return 0, false
	}
	return m.GetGauge().GetValue(), true
}

func shOpHealsCount(t *testing.T, operator, reason string) float64 {
	t.Helper()
	m := findMetric(t, "node_automation_operator_workqueue_heals_total",
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
	stale := shUnstructured("scylla.scylladb.com/v1", "ScyllaCluster", "scylla", "db", 5, 3)
	if !staleObservedGeneration(stale) {
		t.Fatal("observedGeneration<generation must read as stuck")
	}
	caught := shUnstructured("scylla.scylladb.com/v1", "ScyllaCluster", "scylla", "db", 5, 5)
	if staleObservedGeneration(caught) {
		t.Fatal("observedGeneration==generation must not read as stuck")
	}
	// No status at all — the controller never touched the object:
	// observedGeneration reads 0 < generation → the strongest stuck
	// signal there is.
	never := shUnstructured("scylla.scylladb.com/v1", "ScyllaCluster", "scylla", "db", 1, 0)
	if !staleObservedGeneration(never) {
		t.Fatal("missing observedGeneration must read as stuck")
	}

	// Suspended flux objects are parked, not stuck.
	suspended := shUnstructured("helm.toolkit.fluxcd.io/v2", "HelmRelease", "apps", "hr", 5, 3)
	_ = unstructured.SetNestedField(suspended.Object, true, "spec", "suspend")
	if fluxUnsuspendedStaleGen(suspended) {
		t.Fatal("suspended HelmRelease must not count as stuck")
	}
	active := shUnstructured("helm.toolkit.fluxcd.io/v2", "HelmRelease", "apps", "hr", 5, 3)
	if !fluxUnsuspendedStaleGen(active) {
		t.Fatal("non-suspended stale HelmRelease must count as stuck")
	}

	// Gateway-API: empty/absent status.parents reads as stuck; the
	// generation signal lives inside each parent's conditions —
	// these types carry no top-level status.observedGeneration.
	route := shUnstructured("gateway.networking.k8s.io/v1", "HTTPRoute", "apps", "r", 1, 0)
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
	staleRoute := shUnstructured("gateway.networking.k8s.io/v1", "HTTPRoute", "apps", "r", 5, 0)
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
	p := testProberDyn(fake.NewSimpleClientset(), shOpDyn())
	if res := p.checkOperatorWorkqueues(ctx); !res.pass || res.infra != nil {
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
	stuck := shUnstructured("scylla.scylladb.com/v1", "ScyllaCluster",
		"scylla", "db", 5, 3)
	p := testProberDyn(cs, shOpDyn(stuck))
	p.now = func() time.Time { return base }

	if res := p.checkOperatorWorkqueues(ctx); !res.pass {
		t.Fatalf("stale lease must pass quietly, got %+v", res)
	}
	if len(p.opFirstSeen) != 0 {
		t.Fatalf("stale-lease operator must not be tracked: %v", p.opFirstSeen)
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
	stuck := shUnstructured("scylla.scylladb.com/v1", "ScyllaCluster",
		"scylla", "db", 5, 3)
	p := testProberDyn(cs, shOpDyn(stuck))
	p.now = func() time.Time { return base }
	before := shOpHealsCount(t, "scylla-operator", kcmReasonStaleGen)

	// First sighting — tracked, not frozen, no heal.
	if res := p.checkOperatorWorkqueues(ctx); !res.pass {
		t.Fatalf("first-seen signature must pass: %+v", res)
	}
	if len(p.opFirstSeen) != 1 {
		t.Fatalf("signature not tracked: %v", p.opFirstSeen)
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
	p.now = func() time.Time { return at }
	res := p.checkOperatorWorkqueues(ctx)
	if res.pass {
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
	stuck := shUnstructured("scylla.scylladb.com/v1", "ScyllaCluster",
		"scylla", "db", 5, 3)
	p := testProberDyn(cs, shOpDyn(stuck))
	p.now = func() time.Time { return base }
	// Seed first-seen long ago so the signature is already frozen.
	p.opFirstSeen["scylla-operator/scyllaclusters/scylla/db"] = base.Add(-time.Hour)

	res := p.checkOperatorWorkqueues(ctx)
	if res.pass {
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
	p.now = func() time.Time { return at }
	res = p.checkOperatorWorkqueues(ctx)
	if res.pass {
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
	stuck := shUnstructured("scylla.scylladb.com/v1", "ScyllaCluster",
		"scylla", "db", 5, 3)
	p := testProberDyn(cs, shOpDyn(stuck))
	p.now = func() time.Time { return base }
	p.opFirstSeen["scylla-operator/scyllaclusters/scylla/db"] = base.Add(-time.Hour)

	res := p.checkOperatorWorkqueues(ctx)
	if res.pass {
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
	stuck := shUnstructured("scylla.scylladb.com/v1", "ScyllaCluster",
		"scylla", "db", 5, 3)
	p := testProberDyn(cs, shOpDyn(stuck))
	p.now = func() time.Time { return base }
	p.opFirstSeen["scylla-operator/scyllaclusters/scylla/db"] = base.Add(-time.Hour)

	res := p.checkOperatorWorkqueues(ctx)
	if res.pass {
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
	suspended := shUnstructured("helm.toolkit.fluxcd.io/v2", "HelmRelease",
		"apps", "hr", 5, 3)
	_ = unstructured.SetNestedField(suspended.Object, true, "spec", "suspend")
	p := testProberDyn(cs, shOpDyn(suspended))
	p.now = func() time.Time { return base }
	p.opFirstSeen["helm-controller/helmreleases/apps/hr"] = base.Add(-time.Hour)

	if res := p.checkOperatorWorkqueues(ctx); !res.pass {
		t.Fatalf("suspended HelmRelease must not freeze the check: %+v", res)
	}
	if _, ok := p.opFirstSeen["helm-controller/helmreleases/apps/hr"]; ok {
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
	stuck := shUnstructured("dragonflydb.io/v1alpha1", "Dragonfly",
		"db", "cache", 9, 4)
	p := testProberDyn(cs, shOpDyn(stuck))
	p.now = func() time.Time { return base }
	p.opFirstSeen["dragonfly-operator/dragonflies/db/cache"] = base.Add(-time.Hour)

	if res := p.checkOperatorWorkqueues(ctx); res.pass {
		t.Fatal("stuck dragonfly must FAIL")
	}
	if _, err := cs.CoreV1().Pods("dragonfly-operator-system").
		Get(ctx, opPod.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("selector fallback must delete the resolved leader pod, err=%v", err)
	}
}

// ---------------------------------------------------------------------------
// W6.2 — stateful-masterless-services
// ---------------------------------------------------------------------------

// shSTS builds a ready StatefulSet with pod-template labels.
func shSTS(ns, name string, ready int32, labels map[string]string) *appsv1.StatefulSet {
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name, Labels: labels,
		},
		Spec: appsv1.StatefulSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
			},
		},
		Status: appsv1.StatefulSetStatus{ReadyReplicas: ready},
	}
}

// shMasterSvc builds a ClusterIP Service whose selector routes to the
// STS pods under a master role key.
func shMasterSvc(ns, name string, selector map[string]string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.96.0.10",
			Selector:  selector,
		},
	}
}

func shStatefulZeroGauge(t *testing.T, ns, svc, sts string) (float64, bool) {
	t.Helper()
	m := findMetric(t, "node_automation_stateful_service_zero_endpoints",
		map[string]string{"namespace": ns, "service": svc, "statefulset": sts})
	if m == nil {
		return 0, false
	}
	return m.GetGauge().GetValue(), true
}

// A master-role Service on a ready STS with 0 Ready endpoints: tracked
// first, gauge at 3m — and because the STS is Dragonfly-owned the
// operator leader gets bounced at 5m to force re-election.
func TestCheckStatefulMasterlessZeroEndpoints(t *testing.T) {
	metrics.StatefulServiceZeroEndpoints.DeleteLabelValues("db", "dragonfly-master", "dragonfly")
	t.Cleanup(func() {
		metrics.StatefulServiceZeroEndpoints.DeleteLabelValues("db", "dragonfly-master", "dragonfly")
	})
	base := time.Now()
	sts := shSTS("db", "dragonfly", 3,
		map[string]string{"app": "dragonfly", "app.kubernetes.io/part-of": "dragonfly"})
	svc := shMasterSvc("db", "dragonfly-master",
		map[string]string{"app": "dragonfly", "role": "master"})
	opPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: dragonflyOperatorNS,
		Name:      dragonflyOperatorPodPrefix + "-6f8bc-xy",
		UID:       types.UID("dr-op-1"),
	}}
	cs := fake.NewSimpleClientset(sts, svc, opPod)
	p := testProberDyn(cs, shOpDyn())
	p.now = func() time.Time { return base }

	// First sighting — tracked, quiet.
	if res := p.checkStatefulMasterlessServices(ctx); !res.pass {
		t.Fatalf("first-seen zero endpoints must pass: %+v", res)
	}
	key := "db/dragonfly-master/dragonfly"
	if _, ok := p.stsZeroSince[key]; !ok {
		t.Fatal("zero-endpoint tuple not tracked")
	}

	// 4m in — gauge fires, but under the 5m heal window.
	at := base.Add(4 * time.Minute)
	p.now = func() time.Time { return at }
	if res := p.checkStatefulMasterlessServices(ctx); res.pass {
		t.Fatal("zero endpoints >=3m must FAIL")
	}
	if v, _ := shStatefulZeroGauge(t, "db", "dragonfly-master", "dragonfly"); v != 1 {
		t.Fatalf("zero-endpoints gauge = %v, want 1", v)
	}
	if _, err := cs.CoreV1().Pods(dragonflyOperatorNS).
		Get(ctx, opPod.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("operator pod deleted before the 5m heal window")
	}

	// 6m in — the dragonfly operator leader is bounced.
	at = base.Add(6 * time.Minute)
	p.now = func() time.Time { return at }
	if res := p.checkStatefulMasterlessServices(ctx); res.pass {
		t.Fatal("still masterless — must keep FAILING")
	}
	if _, err := cs.CoreV1().Pods(dragonflyOperatorNS).
		Get(ctx, opPod.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("dragonfly operator pod must be deleted past 5m, err=%v", err)
	}
}

// A masterless non-Dragonfly service fires the gauge but never
// touches any operator pod.
func TestCheckStatefulMasterlessNonDragonflyNoHeal(t *testing.T) {
	metrics.StatefulServiceZeroEndpoints.DeleteLabelValues("cache", "redis-master", "redis")
	t.Cleanup(func() {
		metrics.StatefulServiceZeroEndpoints.DeleteLabelValues("cache", "redis-master", "redis")
	})
	base := time.Now()
	sts := shSTS("cache", "redis", 2, map[string]string{"app": "redis"})
	// Role key on the Service LABELS this time — selector stays the
	// plain app set.
	svc := shMasterSvc("cache", "redis-master", map[string]string{"app": "redis"})
	svc.Labels = map[string]string{"app.kubernetes.io/role": "master"}
	opPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: dragonflyOperatorNS,
		Name:      dragonflyOperatorPodPrefix + "-6f8bc-xy",
	}}
	cs := fake.NewSimpleClientset(sts, svc, opPod)
	p := testProberDyn(cs, shOpDyn())
	p.now = func() time.Time { return base }
	p.stsZeroSince["cache/redis-master/redis"] = base.Add(-time.Hour)

	if res := p.checkStatefulMasterlessServices(ctx); res.pass {
		t.Fatal("masterless redis must FAIL")
	}
	if v, _ := shStatefulZeroGauge(t, "cache", "redis-master", "redis"); v != 1 {
		t.Fatalf("zero-endpoints gauge = %v, want 1", v)
	}
	if _, err := cs.CoreV1().Pods(dragonflyOperatorNS).
		Get(ctx, opPod.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("non-dragonfly STS must not bounce the dragonfly operator")
	}
}

// Recovery: once the Service has a Ready endpoint again the tuple
// leaves the ledger and its gauge series is deleted, not parked at 1.
func TestCheckStatefulMasterlessRecovers(t *testing.T) {
	metrics.StatefulServiceZeroEndpoints.DeleteLabelValues("db", "dragonfly-master", "dragonfly")
	base := time.Now()
	sts := shSTS("db", "dragonfly", 3,
		map[string]string{"app": "dragonfly", "app.kubernetes.io/part-of": "dragonfly"})
	svc := shMasterSvc("db", "dragonfly-master",
		map[string]string{"app": "dragonfly", "role": "master"})
	cs := fake.NewSimpleClientset(sts, svc)
	p := testProberDyn(cs, shOpDyn())
	p.now = func() time.Time { return base }
	p.stsZeroSince["db/dragonfly-master/dragonfly"] = base.Add(-time.Hour)

	if res := p.checkStatefulMasterlessServices(ctx); res.pass {
		t.Fatal("precondition: masterless service must FAIL")
	}
	// Endpoint comes back.
	up := true
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "db", Name: "dragonfly-master-abc",
			Labels: map[string]string{discoveryv1.LabelServiceName: "dragonfly-master"},
		},
		Endpoints: []discoveryv1.Endpoint{{
			Addresses:  []string{"10.0.0.9"},
			Conditions: discoveryv1.EndpointConditions{Ready: &up},
		}},
	}
	if _, err := cs.DiscoveryV1().EndpointSlices("db").
		Create(ctx, slice, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	at := base.Add(time.Minute)
	p.now = func() time.Time { return at }
	if res := p.checkStatefulMasterlessServices(ctx); !res.pass {
		t.Fatalf("recovered master must pass: %+v", res)
	}
	if _, ok := p.stsZeroSince["db/dragonfly-master/dragonfly"]; ok {
		t.Fatal("recovered tuple must leave the first-seen ledger")
	}
	if metrics.StatefulServiceZeroEndpoints.DeleteLabelValues("db", "dragonfly-master", "dragonfly") {
		t.Fatal("zero-endpoints series must be pruned on recovery")
	}
}

// Non-matching Services never classify: headless, no role key, wrong
// selector, or the STS itself not ready.
func TestCheckStatefulMasterlessNonCandidates(t *testing.T) {
	base := time.Now()
	sts := shSTS("db", "dragonfly", 3, map[string]string{"app": "dragonfly"})
	notReadySTS := shSTS("db", "other", 0, map[string]string{"app": "other"})
	headless := shMasterSvc("db", "hs",
		map[string]string{"app": "dragonfly", "role": "master"})
	headless.Spec.ClusterIP = corev1.ClusterIPNone
	noRole := shMasterSvc("db", "plain", map[string]string{"app": "dragonfly"})
	wrongSel := shMasterSvc("db", "other-master",
		map[string]string{"app": "other", "role": "master"})
	roleOnly := shMasterSvc("db", "roleonly", map[string]string{"role": "master"})
	p := testProberDyn(fake.NewSimpleClientset(
		sts, notReadySTS, headless, noRole, wrongSel, roleOnly), shOpDyn())
	p.now = func() time.Time { return base }

	if res := p.checkStatefulMasterlessServices(ctx); !res.pass {
		t.Fatalf("non-candidates must pass, got %+v", res)
	}
	if len(p.stsZeroSince) != 0 {
		t.Fatalf("non-candidates must not be tracked: %v", p.stsZeroSince)
	}
}

// ---------------------------------------------------------------------------
// W6.4 — rabbitmq-suspended-listener
// ---------------------------------------------------------------------------

// shRabbitPod builds a rabbitmq-labeled pod in the suspended-listener
// wedge (Running, started-but-never-Ready) unless overridden.
func shRabbitPod(ns, name string, uid types.UID, started, ready bool) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name, UID: uid,
			Labels: map[string]string{"app.kubernetes.io/component": "rabbitmq"},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "StatefulSet",
				Name: "rabbitmq", Controller: ptr.To(true),
			}},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{{
				Type:   corev1.PodReady,
				Status: map[bool]corev1.ConditionStatus{true: corev1.ConditionTrue, false: corev1.ConditionFalse}[ready],
			}},
			ContainerStatuses: []corev1.ContainerStatus{{
				Name: "rabbitmq", Started: ptr.To(started), Ready: ready,
			}},
		},
	}
}

// The signature itself: Running + every container started + none
// Ready — a still-starting container (Started=nil) or a terminal
// pod is never flagged.
func TestRabbitSuspendedSignature(t *testing.T) {
	if !rabbitSuspended(shRabbitPod("mq", "rabbitmq-0", "u1", true, false)) {
		t.Fatal("started-but-unready running pod must flag")
	}
	if rabbitSuspended(shRabbitPod("mq", "rabbitmq-0", "u1", true, true)) {
		t.Fatal("a ready pod must not flag")
	}
	unstarted := shRabbitPod("mq", "rabbitmq-0", "u1", true, false)
	unstarted.Status.ContainerStatuses[0].Started = nil
	if rabbitSuspended(unstarted) {
		t.Fatal("a container still starting must not flag")
	}
	pending := shRabbitPod("mq", "rabbitmq-0", "u1", true, false)
	pending.Status.Phase = corev1.PodPending
	if rabbitSuspended(pending) {
		t.Fatal("a pending pod must not flag")
	}
}

// Stuck >=10m with all peers Ready → the suspended pod is deleted and
// the heals counter moves; the check FAILs either way.
func TestCheckRabbitMQSuspendedHeals(t *testing.T) {
	base := time.Now()
	replicas := int32(3)
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "mq", Name: "rabbitmq"},
		Spec: appsv1.StatefulSetSpec{
			// BUG-C2: quorum is verified against spec.replicas — a
			// fixture without it is refused outright.
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app.kubernetes.io/component": "rabbitmq"}},
		},
	}
	stuck := shRabbitPod("mq", "rabbitmq-0", "u0", true, false)
	peer1 := shRabbitPod("mq", "rabbitmq-1", "u1", true, true)
	peer2 := shRabbitPod("mq", "rabbitmq-2", "u2", true, true)
	cs := fake.NewSimpleClientset(sts, stuck, peer1, peer2)
	p := testProberDyn(cs, shOpDyn())
	p.now = func() time.Time { return base }
	before := func() float64 {
		m := findMetric(t, "node_automation_rabbitmq_suspended_heals_total",
			map[string]string{"namespace": "mq", "pod": "rabbitmq-0"})
		if m == nil {
			return 0
		}
		return m.GetCounter().GetValue()
	}()
	t.Cleanup(func() {
		metrics.RabbitMQSuspendedHealsTotal.DeleteLabelValues("mq", "rabbitmq-0")
	})

	// First sighting — tracked, quiet, pod kept.
	if res := p.checkRabbitMQSuspendedPods(ctx); !res.pass {
		t.Fatalf("first-seen suspended pod must pass: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "rabbitmq-0", metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted before the 10m window")
	}

	at := base.Add(11 * time.Minute)
	p.now = func() time.Time { return at }
	if res := p.checkRabbitMQSuspendedPods(ctx); res.pass {
		t.Fatal("suspended >=10m with quorum safe must FAIL")
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "rabbitmq-0", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("suspended pod must be deleted, err=%v", err)
	}
	m := findMetric(t, "node_automation_rabbitmq_suspended_heals_total",
		map[string]string{"namespace": "mq", "pod": "rabbitmq-0"})
	var got float64
	if m != nil {
		got = m.GetCounter().GetValue()
	}
	if got != before+1 {
		t.Fatalf("heals total = %v, want %v", got, before+1)
	}
}

// A suspended pod whose peers are NOT all Ready is kept — the delete
// could take the cluster below quorum; the FAIL series keeps alerting.
func TestCheckRabbitMQSuspendedQuorumUnsafe(t *testing.T) {
	base := time.Now()
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "mq", Name: "rabbitmq"},
		Spec: appsv1.StatefulSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app.kubernetes.io/component": "rabbitmq"}},
		},
	}
	stuck := shRabbitPod("mq", "rabbitmq-0", "u0", true, false)
	peerDown := shRabbitPod("mq", "rabbitmq-1", "u1", true, false) // also unready
	cs := fake.NewSimpleClientset(sts, stuck, peerDown)
	p := testProberDyn(cs, shOpDyn())
	p.now = func() time.Time { return base }
	p.rbSuspendedSince["mq/rabbitmq-0/u0"] = base.Add(-time.Hour)

	if res := p.checkRabbitMQSuspendedPods(ctx); res.pass {
		t.Fatal("suspended pod must still FAIL — quorum gate only blocks the heal")
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "rabbitmq-0", metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted with a peer down — quorum unsafe")
	}
}

// A pod not owned by a StatefulSet cannot have its quorum verified —
// the heal stands down.
func TestCheckRabbitMQSuspendedNoSTSOwner(t *testing.T) {
	base := time.Now()
	stuck := shRabbitPod("mq", "rabbitmq-0", "u0", true, false)
	stuck.OwnerReferences = nil // bare pod — no quorum chain
	cs := fake.NewSimpleClientset(stuck)
	p := testProberDyn(cs, shOpDyn())
	p.now = func() time.Time { return base }
	p.rbSuspendedSince["mq/rabbitmq-0/u0"] = base.Add(-time.Hour)

	if res := p.checkRabbitMQSuspendedPods(ctx); res.pass {
		t.Fatal("suspended pod must FAIL")
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "rabbitmq-0", metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted with no StatefulSet owner — quorum unverifiable")
	}
}

// Inside the 30m heal cooldown a same-named suspended pod is kept.
func TestCheckRabbitMQSuspendedCooldown(t *testing.T) {
	base := time.Now()
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "mq", Name: "rabbitmq"},
		Spec: appsv1.StatefulSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app.kubernetes.io/component": "rabbitmq"}},
		},
	}
	stuck := shRabbitPod("mq", "rabbitmq-0", "u0", true, false)
	peer := shRabbitPod("mq", "rabbitmq-1", "u1", true, true)
	cs := fake.NewSimpleClientset(sts, stuck, peer)
	p := testProberDyn(cs, shOpDyn())
	p.now = func() time.Time { return base }
	p.rbSuspendedSince["mq/rabbitmq-0/u0"] = base.Add(-time.Hour)
	p.rbHealed["mq/rabbitmq-0"] = base.Add(-10 * time.Minute)

	if res := p.checkRabbitMQSuspendedPods(ctx); res.pass {
		t.Fatal("suspended pod must FAIL even inside the heal cooldown")
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "rabbitmq-0", metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted inside the 30m heal cooldown")
	}
}
