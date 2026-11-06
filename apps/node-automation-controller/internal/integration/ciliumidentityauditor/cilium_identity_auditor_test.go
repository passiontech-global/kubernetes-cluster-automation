package ciliumidentityauditor

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr/funcr"
	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func ciliumIdentity(name string) *unstructured.Unstructured {
	return testutil.Unstructured(
		ciliumIdentityGVR.GroupVersion().WithKind("CiliumIdentity"), "", name, nil)
}

// ciliumIdentityAged is ciliumIdentity with a controlled
// creationTimestamp — the GC minAge gate reads it.
func ciliumIdentityAged(name string, created time.Time) *unstructured.Unstructured {
	o := ciliumIdentity(name)
	o.SetCreationTimestamp(metav1.NewTime(created))
	return o
}

func ciliumEndpoint(ns, name string, id int64) *unstructured.Unstructured {
	o := testutil.Unstructured(
		ciliumEndpointGVR.GroupVersion().WithKind("CiliumEndpoint"), ns, name, nil)
	_ = unstructured.SetNestedField(o.Object, id, "status", "identity", "id")
	return o
}

// ciliumEndpointSlice builds a v2alpha1 CiliumEndpointSlice whose
// .spec.endpoints[] each carry identity.id — the usage record on
// CES-enabled clusters.
func ciliumEndpointSlice(ns, name string, ids ...int64) *unstructured.Unstructured {
	eps := make([]any, 0, len(ids))
	for _, id := range ids {
		eps = append(eps, map[string]any{
			"name":     "cep-x",
			"identity": map[string]any{"id": id},
		})
	}
	o := testutil.Unstructured(
		ciliumEndpointSliceGVR.GroupVersion().WithKind("CiliumEndpointSlice"), ns, name, nil)
	_ = unstructured.SetNestedSlice(o.Object, eps, "spec", "endpoints")
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
	// Deps.Disabled is what setupModules stamps when
	// CILIUM_IDENTITY_AUDITOR_ENABLED gates the module off — a
	// disabled Setup must return nil without touching the (nil)
	// manager.
	if err := Setup(shared.Deps{Name: "cilium-identity-auditor", Disabled: true}); err != nil {
		t.Fatalf("disabled setup must return nil, got %v", err)
	}
}

// Identity referenced by a CiliumEndpoint or a pod annotation is used;
// the rest are orphans — below the threshold they log only (no error).
// The fixture leaves gcEnabled=false, so nothing is ever deleted.
func TestCiliumIdentityAuditorDetectsOrphansBelowThreshold(t *testing.T) {
	dyn := testutil.NewDynamicClient(ciliumIdentity("1000"), ciliumIdentity("2000"), ciliumIdentity("3000"),
		ciliumEndpoint("app", "cep-1", 1000))
	cs := fake.NewSimpleClientset(identityPod("app", "p-1", "2000"))
	a := &ciliumIdentityAuditor{queue: "cilium-identity-auditor", cs: cs, dyn: dyn}
	before := testutil.QueueErrorCount(t, "cilium-identity-auditor")
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := testutil.QueueErrorCount(t, "cilium-identity-auditor") - before; got != 0 {
		t.Fatalf("below-threshold orphans must not IncError, delta %v", got)
	}
	// Detect-only fixture (gcEnabled=false): nothing is ever deleted.
	for _, name := range []string{"1000", "2000", "3000"} {
		if _, err := dyn.Resource(ciliumIdentityGVR).
			Get(ctx, name, metav1.GetOptions{}); err != nil {
			t.Fatalf("identity %s missing — auditor must never delete: %v", name, err)
		}
	}
}

// Clean cluster: every identity referenced -> no orphans.
func TestCiliumIdentityAuditorCleanCluster(t *testing.T) {
	dyn := testutil.NewDynamicClient(ciliumIdentity("1001"), ciliumIdentity("1002"),
		ciliumEndpoint("a", "cep-1", 1001),
		ciliumEndpoint("b", "cep-2", 1002))
	a := &ciliumIdentityAuditor{queue: "cilium-identity-auditor", cs: fake.NewSimpleClientset(), dyn: dyn}
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
}

// Orphans above the threshold surface through the legacy error counter
// (existing alert path) — and still no deletion with gcEnabled=false.
func TestCiliumIdentityAuditorOrphanThreshold(t *testing.T) {
	objs := make([]runtime.Object, 0, ciliumOrphanMax+1)
	for i := 0; i < ciliumOrphanMax+1; i++ {
		objs = append(objs, ciliumIdentity(strconv.Itoa(5000+i)))
	}
	dyn := testutil.NewDynamicClient(objs...)
	a := &ciliumIdentityAuditor{queue: "cilium-identity-auditor", cs: fake.NewSimpleClientset(), dyn: dyn}
	before := testutil.QueueErrorCount(t, "cilium-identity-auditor")
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := testutil.QueueErrorCount(t, "cilium-identity-auditor") - before; got != 1 {
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
	dyn := testutil.NewDynamicClient()
	dyn.PrependReactor("list", "ciliumidentities",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	a := &ciliumIdentityAuditor{queue: "cilium-identity-auditor", cs: fake.NewSimpleClientset(), dyn: dyn}
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
	dyn := testutil.NewDynamicClient(ciliumIdentity("100"))
	dyn.PrependReactor("list", "ciliumendpoints",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	a := &ciliumIdentityAuditor{queue: "cilium-identity-auditor", cs: fake.NewSimpleClientset(), dyn: dyn}
	if err := a.run(ctx); err == nil {
		t.Fatal("expected error when the ciliumendpoint list fails")
	}
}

// The pod annotation feed is also mandatory — same abort-on-empty rule.
func TestCiliumIdentityAuditorPodListError(t *testing.T) {
	dyn := testutil.NewDynamicClient(ciliumIdentity("100"), ciliumEndpoint("app", "cep-1", 100))
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "pods",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	a := &ciliumIdentityAuditor{queue: "cilium-identity-auditor", cs: cs, dyn: dyn}
	if err := a.run(ctx); err == nil {
		t.Fatal("expected error when the pod list fails")
	}
}

// .status.identity.id arrives as int64 in real objects, float64 in
// hand-built fixtures — anything else yields "".
func TestEndpointIdentityID(t *testing.T) {
	withID := func(v any) *unstructured.Unstructured {
		o := testutil.Unstructured(
			ciliumEndpointGVR.GroupVersion().WithKind("CiliumEndpoint"), "", "", nil)
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
// the grace/minAge gates need deterministic now in tests.
func newGCAuditor(cs kubernetes.Interface, dyn dynamic.Interface, now time.Time) *ciliumIdentityAuditor {
	return &ciliumIdentityAuditor{queue: "cilium-identity-auditor",
		cs:        cs,
		dyn:       dyn,
		gcEnabled: true,
		now:       func() time.Time { return now },
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
	old := now.Add(-time.Hour)                                        // past ciliumOrphanMinAge
	dyn := testutil.NewDynamicClient(ciliumIdentityAged("5001", old), // eligible orphan
		ciliumIdentityAged("5002", old),                     // used — kept
		ciliumIdentityAged("5003", now.Add(-5*time.Minute)), // orphan but too young
		ciliumEndpoint("app", "cep-1", 5002))
	cs := fake.NewSimpleClientset(readyNode("n1"), readyNode("n2"))
	a := newGCAuditor(cs, dyn, now)
	a.orphanFirstSeen.Observe("5001", now.Add(-ciliumOrphanGracePeriod-time.Minute))
	a.orphanFirstSeen.Observe("5003", now.Add(-time.Hour)) // orphaned long — but too young

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
	dyn := testutil.NewDynamicClient(ciliumIdentityAged("7001", now.Add(-time.Hour)))
	cs := fake.NewSimpleClientset(readyNode("n1"))
	a := newGCAuditor(cs, dyn, now)

	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.orphanFirstSeen.Seen("7001", now); !ok {
		t.Fatal("first-sweep orphan not tracked in orphanFirstSeen")
	}
	if !identityExists(t, dyn, "7001") {
		t.Fatal("orphan deleted on first sighting — grace gate broken")
	}

	// Advance the clock past the grace window — the second sweep collects.
	later := now.Add(ciliumOrphanGracePeriod + time.Minute)
	a.now = func() time.Time { return later }
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
	dyn := testutil.NewDynamicClient(ciliumIdentityAged("8001", now.Add(-time.Hour)))
	cs := fake.NewSimpleClientset(readyNode("n1"), notReadyNode("n2"))
	a := newGCAuditor(cs, dyn, now)
	a.orphanFirstSeen.Observe("8001", now.Add(-time.Hour))

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
	dyn := testutil.NewDynamicClient(ciliumIdentityAged("8002", now.Add(-time.Hour)))
	a := newGCAuditor(fake.NewSimpleClientset(), dyn, now)
	a.orphanFirstSeen.Observe("8002", now.Add(-time.Hour))

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
	dyn := testutil.NewDynamicClient(ciliumIdentityAged("9001", now.Add(-time.Hour)))
	cs := fake.NewSimpleClientset(readyNode("n1"))
	a := newGCAuditor(cs, dyn, now)
	a.gcEnabled = false
	a.orphanFirstSeen.Observe("9001", now.Add(-time.Hour))

	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !identityExists(t, dyn, "9001") {
		t.Fatal("identity deleted while gcEnabled=false")
	}
	// The ledger still accrues — flipping GC on later collects immediately.
	if _, ok := a.orphanFirstSeen.Seen("9001", now); !ok {
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
		name := strconv.Itoa(20000 + i)
		objs = append(objs, ciliumIdentityAged(name, old))
	}
	dyn := testutil.NewDynamicClient(objs...)
	cs := fake.NewSimpleClientset(readyNode("n1"))
	a := newGCAuditor(cs, dyn, now)
	for i := 0; i < ciliumGCMaxDelete+10; i++ {
		a.orphanFirstSeen.Observe(strconv.Itoa(20000+i), now.Add(-time.Hour))
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

// The GC delete carries a UID precondition — a same-named identity
// recreated between the orphan list and the delete is not the object
// this sweep vetted (the list→delete TOCTOU).
func TestCiliumIdentityAuditorGCDeleteUIDPrecondition(t *testing.T) {
	now := time.Now()
	orphan := ciliumIdentityAged("5001", now.Add(-time.Hour))
	orphan.SetUID("uid-5001")
	dyn := testutil.NewDynamicClient(orphan)
	cs := fake.NewSimpleClientset(readyNode("n1"))
	a := newGCAuditor(cs, dyn, now)
	a.orphanFirstSeen.Observe("5001", now.Add(-time.Hour))

	var gotUID *types.UID
	dyn.PrependReactor("delete", "ciliumidentities",
		func(act clienttesting.Action) (bool, runtime.Object, error) {
			opts := act.(clienttesting.DeleteAction).GetDeleteOptions()
			if opts.Preconditions != nil {
				gotUID = opts.Preconditions.UID
			}
			return false, nil, nil // fall through to the tracker
		})
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if gotUID == nil || *gotUID != "uid-5001" {
		t.Fatalf("delete UID precondition = %v, want uid-5001", gotUID)
	}
	if identityExists(t, dyn, "5001") {
		t.Fatal("identity still exists — delete never landed")
	}
}

// A Conflict on the delete — the UID precondition firing on a
// recreated identity — is a raced skip like NotFound: logged, not
// IncError'd, and the run still succeeds.
func TestCiliumIdentityAuditorGCConflictSkipsDelete(t *testing.T) {
	now := time.Now()
	dyn := testutil.NewDynamicClient(ciliumIdentityAged("5002", now.Add(-time.Hour)))
	dyn.PrependReactor("delete", "ciliumidentities",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewConflict(
				schema.GroupResource{
					Group: "cilium.io", Resource: "ciliumidentities"},
				"5002", errors.New("uid mismatch"))
		})
	cs := fake.NewSimpleClientset(readyNode("n1"))
	a := newGCAuditor(cs, dyn, now)
	a.orphanFirstSeen.Observe("5002", now.Add(-time.Hour))

	before := testutil.QueueErrorCount(t, "cilium-identity-auditor")
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := testutil.QueueErrorCount(t, "cilium-identity-auditor") - before; got != 0 {
		t.Fatalf("a raced delete must not IncError, delta %v", got)
	}
	if !identityExists(t, dyn, "5002") {
		t.Fatal("conflict-rejected delete removed the identity")
	}
}

// The ledger prunes entries whose identity is referenced again or
// whose object vanished — a re-orphan must re-arm the full grace
// window instead of inheriting a stale stamp.
func TestCiliumIdentityAuditorGCPrunesOrphanLedger(t *testing.T) {
	now := time.Now()
	old := now.Add(-time.Hour)
	dyn := testutil.NewDynamicClient(ciliumIdentityAged("6001", old)) // orphan — tracked
	cs := fake.NewSimpleClientset(readyNode("n1"))
	a := newGCAuditor(cs, dyn, now)
	// Seed stale entries: one for an identity that will reappear
	// (endpoint created below), one for an object that does not exist.
	a.orphanFirstSeen.Observe("6001", now.Add(-5*time.Minute))
	a.orphanFirstSeen.Observe("9999", now.Add(-time.Hour)) // vanished object

	if _, err := dyn.Resource(ciliumEndpointGVR).Namespace("app").
		Create(ctx, ciliumEndpoint("app", "cep-x", 6001), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.orphanFirstSeen.Seen("6001", now); ok {
		t.Fatal("re-referenced identity kept its orphan stamp")
	}
	if _, ok := a.orphanFirstSeen.Seen("9999", now); ok {
		t.Fatal("vanished identity kept its orphan stamp")
	}
}

// ---------------------------------------------------------------------------
// Reserved identities + CiliumEndpointSlice usage
// ---------------------------------------------------------------------------

// Cilium's reserved range (numeric names <=255) and `reserved:`-
// labelled identities are exempt from upstream GC — they must never
// enter orphan accounting even when nothing references them, even
// past every GC gate. A normal orphan alongside them is still
// collected (the skip is surgical, not a blanket pass).
func TestCiliumIdentityAuditorSkipsReservedIdentities(t *testing.T) {
	now := time.Now()
	old := now.Add(-time.Hour)
	labeled := ciliumIdentityAged("30000", old)
	labeled.SetLabels(map[string]string{"reserved:host": ""})
	dyn := testutil.NewDynamicClient(ciliumIdentityAged("1", old), // reserved range — host
		ciliumIdentityAged("255", old),  // top of the reserved range
		labeled,                         // reserved: label — exempt too
		ciliumIdentityAged("4000", old)) // ordinary orphan — collectible
	cs := fake.NewSimpleClientset(readyNode("n1"))
	a := newGCAuditor(cs, dyn, now)
	for _, name := range []string{"1", "255", "30000", "4000"} {
		a.orphanFirstSeen.Observe(name, now.Add(-time.Hour)) // past every gate
	}

	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"1", "255", "30000"} {
		if !identityExists(t, dyn, name) {
			t.Fatalf("reserved identity %s was collected", name)
		}
		if _, ok := a.orphanFirstSeen.Seen(name, now); ok {
			t.Fatalf("reserved identity %s entered orphan tracking", name)
		}
	}
	if identityExists(t, dyn, "4000") {
		t.Fatal("ordinary orphan was not collected alongside the reserved skips")
	}
}

// On CES-enabled clusters the CiliumEndpointSlice is the usage record
// (the agent stops writing CiliumEndpoints): an identity referenced
// via .spec.endpoints[].identity.id must read USED, not orphaned —
// without this read the GC would reap live identities.
func TestCiliumIdentityAuditorCESCountsAsUsed(t *testing.T) {
	now := time.Now()
	old := now.Add(-time.Hour)
	dyn := testutil.NewDynamicClient(ciliumIdentityAged("4001", old),
		ciliumEndpointSlice("app", "ces-1", 4001))
	cs := fake.NewSimpleClientset(readyNode("n1"))
	a := newGCAuditor(cs, dyn, now)
	a.orphanFirstSeen.Observe("4001", now.Add(-time.Hour))

	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !identityExists(t, dyn, "4001") {
		t.Fatal("identity referenced only by a CiliumEndpointSlice was collected")
	}
	if _, ok := a.orphanFirstSeen.Seen("4001", now); ok {
		t.Fatal("CES-referenced identity stayed in orphan tracking")
	}
}

// A failed CES list makes identity usage indeterminate — the run
// errors out (wrapper IncErrors) and never reaches the GC path.
func TestCiliumIdentityAuditorCESListErrorFailsClosed(t *testing.T) {
	now := time.Now()
	old := now.Add(-time.Hour)
	dyn := testutil.NewDynamicClient(ciliumIdentityAged("4002", old))
	dyn.PrependReactor("list", "ciliumendpointslices",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("ces list boom")
		})
	cs := fake.NewSimpleClientset(readyNode("n1"))
	a := newGCAuditor(cs, dyn, now)
	a.orphanFirstSeen.Observe("4002", now.Add(-time.Hour))

	if err := a.run(ctx); err == nil {
		t.Fatal("expected error when the ciliumendpointslice list fails")
	}
	if !identityExists(t, dyn, "4002") {
		t.Fatal("identity deleted on an indeterminate usage read")
	}
}

// ---------------------------------------------------------------------------
// Active-identity occupancy gauge + high-cardinality analysis
// ---------------------------------------------------------------------------

// ciliumIdentityLabeled is ciliumIdentity plus a
// .spec.security-labels map — the label set the cardinality
// profiler reads.
func ciliumIdentityLabeled(name string, labels map[string]string) *unstructured.Unstructured {
	o := ciliumIdentity(name)
	_ = unstructured.SetNestedStringMap(
		o.Object, labels, "spec", "security-labels")
	return o
}

// The gauge mirrors the total listed identity count — below the
// warn threshold no cardinality profiling runs.
func TestCiliumIdentityAuditorActiveIdentitiesGauge(t *testing.T) {
	dyn := testutil.NewDynamicClient(
		ciliumIdentity("1000"), ciliumIdentity("2000"),
		ciliumEndpoint("app", "cep-1", 1000),
		ciliumEndpoint("app", "cep-2", 2000))
	a := &ciliumIdentityAuditor{queue: "cilium-identity-auditor",
		cs: fake.NewSimpleClientset(), dyn: dyn}
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := promtestutil.ToFloat64(ciliumActiveIdentities); got != 2 {
		t.Fatalf("active identities gauge = %v, want 2", got)
	}
}

// topSecurityLabelKeys ranks keys by DISTINCT-VALUE count, capped
// at n, deterministic on ties (key-asc).
func TestTopSecurityLabelKeys(t *testing.T) {
	var ids []unstructured.Unstructured
	for i := 0; i < 10; i++ {
		ids = append(ids, *ciliumIdentityLabeled(strconv.Itoa(40000+i),
			map[string]string{
				// every identity carries a UNIQUE pod name — the
				// high-cardinality culprit.
				"k8s:io.cilium.pod.name":          fmt.Sprintf("pod-%d", i),
				"k8s:app":                         fmt.Sprintf("app-%d", i%3),
				"k8s:io.kubernetes.pod.namespace": "app",
			}))
	}
	got := topSecurityLabelKeys(ids, 3)
	want := []string{
		"k8s:io.cilium.pod.name(10)",
		"k8s:app(3)",
		"k8s:io.kubernetes.pod.namespace(1)",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("top keys = %v, want %v", got, want)
	}
	// n larger than the key count just returns what exists.
	if got := topSecurityLabelKeys(ids, 10); len(got) != 3 {
		t.Fatalf("n>keys returned %v", got)
	}
	// Identities with no security-labels profile to nothing.
	if got := topSecurityLabelKeys(
		[]unstructured.Unstructured{*ciliumIdentity("50000")}, 3); len(got) != 0 {
		t.Fatalf("unlabeled identity produced keys: %v", got)
	}
}

// Above ciliumActiveIdentityWarn the sweep profiles security-label
// cardinality and names the inflating key in the log — the gauge
// still reads the full count.
func TestCiliumIdentityAuditorHighCardinalityWarn(t *testing.T) {
	objs := make([]runtime.Object, 0, ciliumActiveIdentityWarn+1)
	for i := 0; i < ciliumActiveIdentityWarn+1; i++ {
		name := strconv.Itoa(30000 + i)
		objs = append(objs, ciliumIdentityLabeled(name,
			map[string]string{
				"k8s:io.cilium.pod.name":          "pod-" + name,
				"k8s:io.kubernetes.pod.namespace": "app",
			}))
	}
	dyn := testutil.NewDynamicClient(objs...)
	a := &ciliumIdentityAuditor{queue: "cilium-identity-auditor",
		cs: fake.NewSimpleClientset(), dyn: dyn}

	var logs []string
	l := funcr.New(func(_, args string) {
		logs = append(logs, args)
	}, funcr.Options{})
	lctx := logf.IntoContext(ctx, l)
	if err := a.run(lctx); err != nil {
		t.Fatal(err)
	}
	if got := promtestutil.ToFloat64(ciliumActiveIdentities); got != ciliumActiveIdentityWarn+1 {
		t.Fatalf("active identities gauge = %v, want %d", got, ciliumActiveIdentityWarn+1)
	}
	joined := strings.Join(logs, "\n")
	if !strings.Contains(joined, "above warn threshold") {
		t.Fatalf("no cardinality warning logged:\n%s", joined)
	}
	if !strings.Contains(joined, "k8s:io.cilium.pod.name") {
		t.Fatalf("top cardinality key not named:\n%s", joined)
	}
}
