package integration

import (
	"errors"
	"fmt"
	"testing"
	"time"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/controller/testutil"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
)

var ciliumAuditListKinds = map[schema.GroupVersionResource]string{
	ciliumIdentityGVR: "CiliumIdentityList",
	ciliumEndpointGVR: "CiliumEndpointList",
}

func ciliumIdentity(name string) *unstructured.Unstructured {
	o := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "cilium.io/v2",
		"kind":       "CiliumIdentity",
	}}
	o.SetName(name)
	return o
}

// ciliumIdentityAged is ciliumIdentity with a controlled
// creationTimestamp — the GC minAge gate reads it.
func ciliumIdentityAged(name string, created time.Time) *unstructured.Unstructured {
	o := ciliumIdentity(name)
	o.SetCreationTimestamp(metav1.NewTime(created))
	return o
}

func ciliumEndpoint(ns, name string, id int64) *unstructured.Unstructured {
	o := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "cilium.io/v2",
		"kind":       "CiliumEndpoint",
	}}
	o.SetNamespace(ns)
	o.SetName(name)
	_ = unstructured.SetNestedField(o.Object, id, "status", "identity", "id")
	return o
}

func identityPod(ns, name, identityID string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace:   ns,
		Name:        name,
		Annotations: map[string]string{ciliumIDAnnotation: identityID},
	}}
}

func TestCiliumIdentityAuditorSetupDisabled(t *testing.T) {
	if err := SetupCiliumIdentityAuditor(nil, nil, nil, false); err != nil {
		t.Fatalf("disabled setup must return nil, got %v", err)
	}
}

// Identity referenced by a CiliumEndpoint or a pod annotation is used;
// the rest are orphans — below the threshold they log only (no error).
// The fixture leaves gcEnabled=false, so nothing is ever deleted.
func TestCiliumIdentityAuditorDetectsOrphansBelowThreshold(t *testing.T) {
	dyn := newFakeDyn(ciliumAuditListKinds,
		ciliumIdentity("100"), ciliumIdentity("200"), ciliumIdentity("300"),
		ciliumEndpoint("app", "cep-1", 100))
	cs := fake.NewSimpleClientset(identityPod("app", "p-1", "200"))
	a := &ciliumIdentityAuditor{cs: cs, dyn: dyn}
	before := testutil.QueueErrorCount(t, ciliumAuditQueue)
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := testutil.QueueErrorCount(t, ciliumAuditQueue) - before; got != 0 {
		t.Fatalf("below-threshold orphans must not IncError, delta %v", got)
	}
	// Detect-only fixture (gcEnabled=false): nothing is ever deleted.
	for _, name := range []string{"100", "200", "300"} {
		if _, err := dyn.Resource(ciliumIdentityGVR).
			Get(ctx, name, metav1.GetOptions{}); err != nil {
			t.Fatalf("identity %s missing — auditor must never delete: %v", name, err)
		}
	}
}

// Clean cluster: every identity referenced -> no orphans.
func TestCiliumIdentityAuditorCleanCluster(t *testing.T) {
	dyn := newFakeDyn(ciliumAuditListKinds,
		ciliumIdentity("1"), ciliumIdentity("2"),
		ciliumEndpoint("a", "cep-1", 1),
		ciliumEndpoint("b", "cep-2", 2))
	a := &ciliumIdentityAuditor{cs: fake.NewSimpleClientset(), dyn: dyn}
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
}

// Orphans above the threshold surface through the legacy error counter
// (existing alert path) — and still no deletion with gcEnabled=false.
func TestCiliumIdentityAuditorOrphanThreshold(t *testing.T) {
	objs := make([]runtime.Object, 0, ciliumOrphanMax+1)
	for i := 0; i < ciliumOrphanMax+1; i++ {
		objs = append(objs, ciliumIdentity(fmt.Sprintf("%d", 5000+i)))
	}
	dyn := newFakeDyn(ciliumAuditListKinds, objs...)
	a := &ciliumIdentityAuditor{cs: fake.NewSimpleClientset(), dyn: dyn}
	before := testutil.QueueErrorCount(t, ciliumAuditQueue)
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := testutil.QueueErrorCount(t, ciliumAuditQueue) - before; got != 1 {
		t.Fatalf("expected exactly 1 IncError above threshold, got %v", got)
	}
	list, err := dyn.Resource(ciliumIdentityGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != ciliumOrphanMax+1 {
		t.Fatalf("auditor deleted identities in detect-only mode: %d left",
			len(list.Items))
	}
}

func TestCiliumIdentityAuditorAPIError(t *testing.T) {
	dyn := newFakeDyn(ciliumAuditListKinds)
	dyn.PrependReactor("list", "ciliumidentities",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	a := &ciliumIdentityAuditor{cs: fake.NewSimpleClientset(), dyn: dyn}
	// run() only returns the error — run-level IncError is the
	// periodic wrapper's job (proven end-to-end by shared's
	// TestPeriodicErrorIncrementsErrorMetric), so this test asserts
	// the return, not the counter.
	if err := a.run(ctx); err == nil {
		t.Fatal("expected error when identity list fails")
	}
}

// The endpoint list feeds the "used" set — its failure aborts rather
// than flag every identity as orphaned on empty data.
func TestCiliumIdentityAuditorEndpointListError(t *testing.T) {
	dyn := newFakeDyn(ciliumAuditListKinds, ciliumIdentity("100"))
	dyn.PrependReactor("list", "ciliumendpoints",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	a := &ciliumIdentityAuditor{cs: fake.NewSimpleClientset(), dyn: dyn}
	if err := a.run(ctx); err == nil {
		t.Fatal("expected error when the ciliumendpoint list fails")
	}
}

// The pod annotation feed is also mandatory — same abort-on-empty rule.
func TestCiliumIdentityAuditorPodListError(t *testing.T) {
	dyn := newFakeDyn(ciliumAuditListKinds,
		ciliumIdentity("100"), ciliumEndpoint("app", "cep-1", 100))
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "pods",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	a := &ciliumIdentityAuditor{cs: cs, dyn: dyn}
	if err := a.run(ctx); err == nil {
		t.Fatal("expected error when the pod list fails")
	}
}

// .status.identity.id arrives as int64 in real objects, float64 in
// hand-built fixtures — anything else yields "".
func TestEndpointIdentityID(t *testing.T) {
	withID := func(v any) *unstructured.Unstructured {
		o := &unstructured.Unstructured{Object: map[string]interface{}{
			"apiVersion": "cilium.io/v2",
			"kind":       "CiliumEndpoint",
		}}
		if v != nil {
			_ = unstructured.SetNestedField(o.Object, v, "status", "identity", "id")
		}
		return o
	}
	for _, tc := range []struct {
		name string
		id   any
		want string
	}{
		{"int64", int64(12345), "12345"},
		{"float64", float64(6789), "6789"},
		{"absent", nil, ""},
		{"non-numeric string", "abc", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := endpointIdentityID(withID(tc.id)); got != tc.want {
				t.Fatalf("endpointIdentityID = %q, want %q", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// v2 two-pass safe GC
// ---------------------------------------------------------------------------

func readyNode(name string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{
			Type: corev1.NodeReady, Status: corev1.ConditionTrue}}},
	}
}

func notReadyNode(name string) *corev1.Node {
	n := readyNode(name)
	n.Status.Conditions[0].Status = corev1.ConditionFalse
	return n
}

// newGCAuditor builds the v2 auditor with GC armed and a pinned clock —
// the grace/minAge gates need deterministic nowFn in tests.
func newGCAuditor(cs kubernetes.Interface, dyn dynamic.Interface, now time.Time) *ciliumIdentityAuditor {
	return &ciliumIdentityAuditor{
		cs:              cs,
		dyn:             dyn,
		gcEnabled:       true,
		orphanFirstSeen: map[string]time.Time{},
		nowFn:           func() time.Time { return now },
	}
}

func identityExists(t *testing.T, dyn dynamic.Interface, name string) bool {
	t.Helper()
	_, err := dyn.Resource(ciliumIdentityGVR).Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		return true
	}
	if !apierrors.IsNotFound(err) {
		t.Fatalf("get identity %s: %v", name, err)
	}
	return false
}

// Happy path: an identity past BOTH the orphan-grace and min-age gates
// on a fully-Ready cluster is deleted and counted; a used identity and
// a too-young orphan are kept.
func TestCiliumIdentityAuditorGCDeletesEligibleOrphan(t *testing.T) {
	now := time.Now()
	old := now.Add(-time.Hour) // past ciliumOrphanMinAge
	dyn := newFakeDyn(ciliumAuditListKinds,
		ciliumIdentityAged("5001", old),                     // eligible orphan
		ciliumIdentityAged("5002", old),                     // used — kept
		ciliumIdentityAged("5003", now.Add(-5*time.Minute)), // orphan but too young
		ciliumEndpoint("app", "cep-1", 5002))
	cs := fake.NewSimpleClientset(readyNode("n1"), readyNode("n2"))
	a := newGCAuditor(cs, dyn, now)
	a.orphanFirstSeen["5001"] = now.Add(-ciliumOrphanGracePeriod - time.Minute)
	a.orphanFirstSeen["5003"] = now.Add(-time.Hour) // orphaned long — but too young

	before := promtestutil.ToFloat64(metrics.CiliumIdentitiesCollectedTotal)
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if identityExists(t, dyn, "5001") {
		t.Fatal("eligible orphan identity not collected")
	}
	if !identityExists(t, dyn, "5002") {
		t.Fatal("used identity deleted")
	}
	if !identityExists(t, dyn, "5003") {
		t.Fatal("orphan younger than minAge deleted")
	}
	if got := promtestutil.ToFloat64(metrics.CiliumIdentitiesCollectedTotal) - before; got != 1 {
		t.Fatalf("CiliumIdentitiesCollectedTotal delta = %v, want 1", got)
	}
}

// The grace gate: a first-sweep orphan is tracked, never deleted; only
// the SECOND sweep past the grace period collects it.
func TestCiliumIdentityAuditorGCGracePeriod(t *testing.T) {
	now := time.Now()
	dyn := newFakeDyn(ciliumAuditListKinds,
		ciliumIdentityAged("7001", now.Add(-time.Hour)))
	cs := fake.NewSimpleClientset(readyNode("n1"))
	a := newGCAuditor(cs, dyn, now)

	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.orphanFirstSeen["7001"]; !ok {
		t.Fatal("first-sweep orphan not tracked in orphanFirstSeen")
	}
	if !identityExists(t, dyn, "7001") {
		t.Fatal("orphan deleted on first sighting — grace gate broken")
	}

	// Advance the clock past the grace window — the second sweep collects.
	later := now.Add(ciliumOrphanGracePeriod + time.Minute)
	a.nowFn = func() time.Time { return later }
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if identityExists(t, dyn, "7001") {
		t.Fatal("orphan past grace period not collected on second sweep")
	}
}

// The storm gate: ANY NotReady node freezes deletion — its pods may
// still hold identities the API cannot see.
func TestCiliumIdentityAuditorGCAbortsOnNotReadyNode(t *testing.T) {
	now := time.Now()
	dyn := newFakeDyn(ciliumAuditListKinds,
		ciliumIdentityAged("8001", now.Add(-time.Hour)))
	cs := fake.NewSimpleClientset(readyNode("n1"), notReadyNode("n2"))
	a := newGCAuditor(cs, dyn, now)
	a.orphanFirstSeen["8001"] = now.Add(-time.Hour)

	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !identityExists(t, dyn, "8001") {
		t.Fatal("identity deleted while a node was NotReady")
	}
}

// No nodes at all means the cluster is too broken to judge — the
// "all Ready" check must not vacuously pass on an empty list.
func TestCiliumIdentityAuditorGCAbortsOnZeroNodes(t *testing.T) {
	now := time.Now()
	dyn := newFakeDyn(ciliumAuditListKinds,
		ciliumIdentityAged("8002", now.Add(-time.Hour)))
	a := newGCAuditor(fake.NewSimpleClientset(), dyn, now)
	a.orphanFirstSeen["8002"] = now.Add(-time.Hour)

	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !identityExists(t, dyn, "8002") {
		t.Fatal("identity deleted with zero nodes in the cluster")
	}
}

// gcEnabled=false keeps v1 detect-only behavior: even a fully eligible
// orphan on a healthy cluster is never deleted.
func TestCiliumIdentityAuditorGCDisabledNeverDeletes(t *testing.T) {
	now := time.Now()
	dyn := newFakeDyn(ciliumAuditListKinds,
		ciliumIdentityAged("9001", now.Add(-time.Hour)))
	cs := fake.NewSimpleClientset(readyNode("n1"))
	a := newGCAuditor(cs, dyn, now)
	a.gcEnabled = false
	a.orphanFirstSeen["9001"] = now.Add(-time.Hour)

	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !identityExists(t, dyn, "9001") {
		t.Fatal("identity deleted while gcEnabled=false")
	}
	// The ledger still accrues — flipping GC on later collects immediately.
	if _, ok := a.orphanFirstSeen["9001"]; !ok {
		t.Fatal("orphan tracking lost while GC disabled")
	}
}

// The per-cycle cap: more than ciliumGCMaxDelete eligible orphans drain
// gradually — exactly the cap leaves, the rest wait for the next sweep.
func TestCiliumIdentityAuditorGCMaxDeleteCap(t *testing.T) {
	now := time.Now()
	old := now.Add(-time.Hour)
	objs := make([]runtime.Object, 0, ciliumGCMaxDelete+10)
	for i := 0; i < ciliumGCMaxDelete+10; i++ {
		name := fmt.Sprintf("%d", 20000+i)
		objs = append(objs, ciliumIdentityAged(name, old))
	}
	dyn := newFakeDyn(ciliumAuditListKinds, objs...)
	cs := fake.NewSimpleClientset(readyNode("n1"))
	a := newGCAuditor(cs, dyn, now)
	for i := 0; i < ciliumGCMaxDelete+10; i++ {
		a.orphanFirstSeen[fmt.Sprintf("%d", 20000+i)] = now.Add(-time.Hour)
	}

	before := promtestutil.ToFloat64(metrics.CiliumIdentitiesCollectedTotal)
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	list, err := dyn.Resource(ciliumIdentityGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 10 {
		t.Fatalf("identities left = %d, want 10 (cap %d of %d)",
			len(list.Items), ciliumGCMaxDelete, ciliumGCMaxDelete+10)
	}
	if got := promtestutil.ToFloat64(metrics.CiliumIdentitiesCollectedTotal) - before; got != ciliumGCMaxDelete {
		t.Fatalf("CiliumIdentitiesCollectedTotal delta = %v, want %d", got, ciliumGCMaxDelete)
	}
}

// The ledger prunes entries whose identity is referenced again or
// whose object vanished — a re-orphan must re-arm the full grace
// window instead of inheriting a stale stamp.
func TestCiliumIdentityAuditorGCPrunesOrphanLedger(t *testing.T) {
	now := time.Now()
	old := now.Add(-time.Hour)
	dyn := newFakeDyn(ciliumAuditListKinds,
		ciliumIdentityAged("6001", old)) // orphan — tracked
	cs := fake.NewSimpleClientset(readyNode("n1"))
	a := newGCAuditor(cs, dyn, now)
	// Seed stale entries: one for an identity that will reappear
	// (endpoint created below), one for an object that does not exist.
	a.orphanFirstSeen["6001"] = now.Add(-5 * time.Minute)
	a.orphanFirstSeen["9999"] = now.Add(-time.Hour) // vanished object

	if _, err := dyn.Resource(ciliumEndpointGVR).Namespace("app").
		Create(ctx, ciliumEndpoint("app", "cep-x", 6001), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.orphanFirstSeen["6001"]; ok {
		t.Fatal("re-referenced identity kept its orphan stamp")
	}
	if _, ok := a.orphanFirstSeen["9999"]; ok {
		t.Fatal("vanished identity kept its orphan stamp")
	}
}
