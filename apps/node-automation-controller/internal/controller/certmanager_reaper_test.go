package controller

import (
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// ---------------------------------------------------------------------------
// Shared dynamic-fake helpers
// ---------------------------------------------------------------------------

// newFakeDyn builds a dynamic fake client with explicit GVR->ListKind
// mappings (required for List on unregistered CRDs).
func newFakeDyn(kinds map[schema.GroupVersionResource]string,
	objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(), kinds, objs...)
}

var cmrListKinds = map[schema.GroupVersionResource]string{
	certificateGVR: "CertificateList",
	orderGVR:       "OrderList",
	challengeGVR:   "ChallengeList",
}

// queueErrorCount reads the legacy hook-error counter for a queue —
// IncError deltas are the observable side-effect for refuse/error paths.
func queueErrorCount(t *testing.T, queue string) float64 {
	t.Helper()
	fams, err := ctrlmetrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, f := range fams {
		if f.GetName() != "shell_operator_hook_run_errors_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "queue" && l.GetValue() == queue {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

// ---------------------------------------------------------------------------
// certmanager-reaper builders
// ---------------------------------------------------------------------------

// cmrCert builds an unstructured Certificate. readyStatus is the Ready
// condition's status string ("" = no conditions); renewalTime is an
// RFC3339 spec.renewalTime ("" = absent).
func cmrCert(ns, name, readyStatus, renewalTime string) *unstructured.Unstructured {
	o := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "cert-manager.io/v1",
		"kind":       "Certificate",
	}}
	o.SetNamespace(ns)
	o.SetName(name)
	if readyStatus != "" {
		_ = unstructured.SetNestedSlice(o.Object, []interface{}{
			map[string]interface{}{"type": "Ready", "status": readyStatus},
		}, "status", "conditions")
	}
	if renewalTime != "" {
		_ = unstructured.SetNestedField(o.Object, renewalTime, "spec", "renewalTime")
	}
	return o
}

func cmrOrder(ns, name, state string, age time.Duration) *unstructured.Unstructured {
	o := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "acme.cert-manager.io/v1",
		"kind":       "Order",
	}}
	o.SetNamespace(ns)
	o.SetName(name)
	o.SetCreationTimestamp(metav1.NewTime(time.Now().Add(-age)))
	if state != "" {
		_ = unstructured.SetNestedField(o.Object, state, "status", "state")
	}
	return o
}

// cmrChallenge builds an unstructured Challenge; transitionAgo ages
// status.lastTransitionTime, orderOwner sets the ownerReference name.
func cmrChallenge(ns, name string, presented, processing bool,
	transitionAgo time.Duration, orderOwner string) *unstructured.Unstructured {
	o := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "acme.cert-manager.io/v1",
		"kind":       "Challenge",
	}}
	o.SetNamespace(ns)
	o.SetName(name)
	o.SetCreationTimestamp(metav1.NewTime(time.Now().Add(-transitionAgo)))
	_ = unstructured.SetNestedField(o.Object, presented, "status", "presented")
	_ = unstructured.SetNestedField(o.Object, processing, "status", "processing")
	_ = unstructured.SetNestedField(o.Object,
		time.Now().Add(-transitionAgo).UTC().Format(time.RFC3339),
		"status", "lastTransitionTime")
	if orderOwner != "" {
		o.SetOwnerReferences([]metav1.OwnerReference{{Name: orderOwner}})
	}
	return o
}

func cmrOrderExists(t *testing.T, dyn *dynamicfake.FakeDynamicClient, ns, name string) bool {
	t.Helper()
	_, err := dyn.Resource(orderGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false
	}
	if err != nil {
		t.Fatalf("get order %s/%s: %v", ns, name, err)
	}
	return true
}

// stuckFixture is the full wedge: Ready=False cert + pending>30m order
// + presented/processing challenge with an old transition.
func stuckFixture(ns, certName, orderName string) []runtime.Object {
	return []runtime.Object{
		cmrCert(ns, certName, "False", ""),
		cmrOrder(ns, orderName, "pending", 45*time.Minute),
		cmrChallenge(ns, orderName+"-ch", true, true, time.Hour, orderName),
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestCertManagerReaperSetupDisabled(t *testing.T) {
	if err := SetupCertManagerReaper(nil, nil, nil, false); err != nil {
		t.Fatalf("disabled setup must return nil, got %v", err)
	}
}

func TestCertManagerReaperDeletesStuckOrder(t *testing.T) {
	dyn := newFakeDyn(cmrListKinds, stuckFixture("app", "tls-a", "order-a")...)
	r := &certManagerReaper{cs: fake.NewSimpleClientset(), dyn: dyn,
		resets: map[string]*certReset{}}
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if cmrOrderExists(t, dyn, "app", "order-a") {
		t.Fatal("stuck pending order was not deleted")
	}
	st := r.resets["app/tls-a"]
	if st == nil || st.total != 1 {
		t.Fatalf("expected reset total=1 for app/tls-a, got %+v", st)
	}
}

// Renewal-time candidacy: Ready=True but renewalTime inside 7d.
func TestCertManagerReaperRenewalWindowCandidate(t *testing.T) {
	dyn := newFakeDyn(cmrListKinds,
		cmrCert("app", "tls-b", "True",
			time.Now().Add(48*time.Hour).UTC().Format(time.RFC3339)),
		cmrOrder("app", "order-b", "pending", 45*time.Minute),
		cmrChallenge("app", "order-b-ch", true, true, time.Hour, "order-b"))
	r := &certManagerReaper{cs: fake.NewSimpleClientset(), dyn: dyn,
		resets: map[string]*certReset{}}
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if cmrOrderExists(t, dyn, "app", "order-b") {
		t.Fatal("order under a renewal-window cert was not deleted")
	}
}

// Healthy cert, renewal far out: not a candidate, order never touched.
func TestCertManagerReaperKeepsHealthyCert(t *testing.T) {
	dyn := newFakeDyn(cmrListKinds,
		cmrCert("app", "tls-ok", "True",
			time.Now().Add(30*24*time.Hour).UTC().Format(time.RFC3339)),
		cmrOrder("app", "order-ok", "pending", 45*time.Minute),
		cmrChallenge("app", "order-ok-ch", true, true, time.Hour, "order-ok"))
	r := &certManagerReaper{cs: fake.NewSimpleClientset(), dyn: dyn,
		resets: map[string]*certReset{}}
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !cmrOrderExists(t, dyn, "app", "order-ok") {
		t.Fatal("order deleted for a healthy non-renewing cert")
	}
}

// Order must be BOTH pending and >30m old.
func TestCertManagerReaperOrderGates(t *testing.T) {
	dyn := newFakeDyn(cmrListKinds,
		cmrCert("app", "tls-a", "False", ""),
		cmrOrder("app", "young", "pending", 10*time.Minute), // fresh
		cmrOrder("app", "valid", "valid", 45*time.Minute),   // not pending
		cmrChallenge("app", "ch", true, true, time.Hour, "young"))
	r := &certManagerReaper{cs: fake.NewSimpleClientset(), dyn: dyn,
		resets: map[string]*certReset{}}
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"young", "valid"} {
		if !cmrOrderExists(t, dyn, "app", name) {
			t.Fatalf("order %s deleted despite failing the pending/age gate", name)
		}
	}
}

// A pending>30m order with no wedged challenge is still progressing.
func TestCertManagerReaperKeepsOrderWhenChallengeProgressing(t *testing.T) {
	dyn := newFakeDyn(cmrListKinds,
		cmrCert("app", "tls-a", "False", ""),
		cmrOrder("app", "order-a", "pending", 45*time.Minute),
		// presented but not processing — still moving.
		cmrChallenge("app", "ch-a", true, false, time.Hour, "order-a"))
	r := &certManagerReaper{cs: fake.NewSimpleClientset(), dyn: dyn,
		resets: map[string]*certReset{}}
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !cmrOrderExists(t, dyn, "app", "order-a") {
		t.Fatal("order deleted while challenge still progressing")
	}
}

// A wedged challenge owned by a DIFFERENT order must not justify
// deleting this order — the cross-check is per-order linkage, not
// "any wedged challenge in the namespace".
func TestCertManagerReaperIgnoresForeignChallenge(t *testing.T) {
	dyn := newFakeDyn(cmrListKinds,
		cmrCert("app", "tls-a", "False", ""),
		cmrOrder("app", "order-a", "pending", 45*time.Minute),
		cmrChallenge("app", "ch-b", true, true, time.Hour, "other-order"))
	r := &certManagerReaper{cs: fake.NewSimpleClientset(), dyn: dyn,
		resets: map[string]*certReset{}}
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !cmrOrderExists(t, dyn, "app", "order-a") {
		t.Fatal("order-a deleted on the strength of a foreign challenge")
	}
}

// Max 1 reset per cert per hour: a second stuck order inside the hour
// is kept; after the gap it is reset again (total 2).
func TestCertManagerReaperHourlyRateLimit(t *testing.T) {
	dyn := newFakeDyn(cmrListKinds, stuckFixture("app", "tls-a", "order-1")...)
	r := &certManagerReaper{cs: fake.NewSimpleClientset(), dyn: dyn,
		resets: map[string]*certReset{}}
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	// cert-manager recreated the order (with a fresh challenge);
	// it wedged again.
	recreated := cmrOrder("app", "order-2", "pending", 45*time.Minute)
	if _, err := dyn.Resource(orderGVR).Namespace("app").
		Create(ctx, recreated, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := dyn.Resource(challengeGVR).Namespace("app").Create(ctx,
		cmrChallenge("app", "order-2-ch", true, true, time.Hour, "order-2"),
		metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !cmrOrderExists(t, dyn, "app", "order-2") {
		t.Fatal("rate limit broken — second reset inside the hour")
	}
	// An hour passes.
	r.resets["app/tls-a"].last = time.Now().Add(-2 * time.Hour)
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if cmrOrderExists(t, dyn, "app", "order-2") {
		t.Fatal("order-2 should be reset after the hourly gap")
	}
	if r.resets["app/tls-a"].total != 2 {
		t.Fatalf("expected total=2, got %d", r.resets["app/tls-a"].total)
	}
}

// After 3 total resets the reaper refuses: order kept, IncError fires
// exactly once even across repeated runs.
func TestCertManagerReaperResetBudgetExhausted(t *testing.T) {
	dyn := newFakeDyn(cmrListKinds, stuckFixture("app", "tls-a", "order-a")...)
	r := &certManagerReaper{cs: fake.NewSimpleClientset(), dyn: dyn,
		resets: map[string]*certReset{
			"app/tls-a": {total: certReaperMaxReset, last: time.Now().Add(-2 * time.Hour)},
		}}
	before := queueErrorCount(t, certReaperQueue)
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !cmrOrderExists(t, dyn, "app", "order-a") {
		t.Fatal("order deleted despite exhausted reset budget")
	}
	if got := queueErrorCount(t, certReaperQueue) - before; got != 1 {
		t.Fatalf("expected exactly 1 IncError on budget exhaustion, got %v", got)
	}
	// Second run: still refused, no second IncError.
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := queueErrorCount(t, certReaperQueue) - before; got != 1 {
		t.Fatalf("IncError repeated after gaveUp, total delta %v", got)
	}
}

// Per-item failure logs + continues: a failing orders List in ns "bad"
// must not prevent the healthy ns "good" cert from being processed.
func TestCertManagerReaperContinuesOnItemError(t *testing.T) {
	dyn := newFakeDyn(cmrListKinds, append(
		stuckFixture("good", "tls-good", "order-good"),
		cmrCert("bad", "tls-bad", "False", ""))...)
	dyn.PrependReactor("list", "orders",
		func(a clienttesting.Action) (bool, runtime.Object, error) {
			if la, ok := a.(clienttesting.ListAction); ok && la.GetNamespace() == "bad" {
				return true, nil, errors.New("boom")
			}
			return false, nil, nil
		})
	r := &certManagerReaper{cs: fake.NewSimpleClientset(), dyn: dyn,
		resets: map[string]*certReset{}}
	before := queueErrorCount(t, certReaperQueue)
	if err := r.run(ctx); err != nil {
		t.Fatalf("per-item failure must not abort the run: %v", err)
	}
	if cmrOrderExists(t, dyn, "good", "order-good") {
		t.Fatal("healthy cert's stuck order not deleted after a sibling item failed")
	}
	if got := queueErrorCount(t, certReaperQueue) - before; got < 1 {
		t.Fatal("per-item API failure did not IncError")
	}
}

// Top-level certificate list failure is a real error.
func TestCertManagerReaperListError(t *testing.T) {
	dyn := newFakeDyn(cmrListKinds)
	dyn.PrependReactor("list", "certificates",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, fmt.Errorf("api down")
		})
	r := &certManagerReaper{cs: fake.NewSimpleClientset(), dyn: dyn,
		resets: map[string]*certReset{}}
	if err := r.run(ctx); err == nil {
		t.Fatal("expected error when certificate list fails")
	}
}

// A challenge list failure is a per-item IncError + keep: the order
// must NOT be deleted on an unreadable cross-check.
func TestCertManagerReaperChallengeListError(t *testing.T) {
	dyn := newFakeDyn(cmrListKinds, stuckFixture("app", "tls-a", "order-a")...)
	dyn.PrependReactor("list", "challenges",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("challenges unreachable")
		})
	r := &certManagerReaper{cs: fake.NewSimpleClientset(), dyn: dyn,
		resets: map[string]*certReset{}}
	before := queueErrorCount(t, certReaperQueue)
	if err := r.run(ctx); err != nil {
		t.Fatalf("per-item failure must not abort the run: %v", err)
	}
	if !cmrOrderExists(t, dyn, "app", "order-a") {
		t.Fatal("order deleted although the challenge cross-check failed")
	}
	if got := queueErrorCount(t, certReaperQueue) - before; got != 1 {
		t.Fatalf("challenge list failure did not IncError once, delta %v", got)
	}
}

// A failed order delete IncErrors but does NOT consume reset budget —
// the next run retries the same order.
func TestCertManagerReaperOrderDeleteError(t *testing.T) {
	dyn := newFakeDyn(cmrListKinds, stuckFixture("app", "tls-a", "order-a")...)
	var failOnce atomic.Bool
	failOnce.Store(true)
	dyn.PrependReactor("delete", "orders",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			if failOnce.CompareAndSwap(true, false) {
				return true, nil, errors.New("delete rejected")
			}
			return false, nil, nil
		})
	r := &certManagerReaper{cs: fake.NewSimpleClientset(), dyn: dyn,
		resets: map[string]*certReset{}}
	before := queueErrorCount(t, certReaperQueue)
	if err := r.run(ctx); err != nil {
		t.Fatalf("per-item failure must not abort the run: %v", err)
	}
	if !cmrOrderExists(t, dyn, "app", "order-a") {
		t.Fatal("order deleted despite the failing delete call")
	}
	if st := r.resets["app/tls-a"]; st == nil || st.total != 0 {
		t.Fatalf("reset budget consumed by a failed delete: %+v", st)
	}
	if got := queueErrorCount(t, certReaperQueue) - before; got != 1 {
		t.Fatalf("order delete failure did not IncError once, delta %v", got)
	}

	// Retry succeeds and now consumes the budget.
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if cmrOrderExists(t, dyn, "app", "order-a") {
		t.Fatal("order not deleted on the retry")
	}
	if st := r.resets["app/tls-a"]; st.total != 1 {
		t.Fatalf("expected total=1 after the retried delete, got %+v", st)
	}
}

// challengeLinkedToOrder: ownerReferences and the acme order-name label
// are linkage — a linked challenge must point at THIS order; linkage-
// free challenges fall back to the same-namespace match.
func TestChallengeLinkedToOrder(t *testing.T) {
	order := cmrOrder("app", "order-a", "pending", 45*time.Minute)

	withLabel := func(name, orderLabel string) *unstructured.Unstructured {
		ch := cmrChallenge("app", name, true, true, time.Hour, "")
		if orderLabel != "" {
			ch.SetLabels(map[string]string{"acme.cert-manager.io/order-name": orderLabel})
		}
		return ch
	}

	for _, tc := range []struct {
		name string
		ch   *unstructured.Unstructured
		want bool
	}{
		{"label points at order", withLabel("ch-1", "order-a"), true},
		{"label points elsewhere", withLabel("ch-2", "order-b"), false},
		{"ownerRef points at order",
			cmrChallenge("app", "ch-3", true, true, time.Hour, "order-a"), true},
		{"ownerRef points elsewhere",
			cmrChallenge("app", "ch-4", true, true, time.Hour, "order-b"), false},
		{"no linkage — namespace fallback", withLabel("ch-5", ""), true},
		{"ownerRef right + label wrong wins on ownerRef", func() *unstructured.Unstructured {
			ch := cmrChallenge("app", "ch-6", true, true, time.Hour, "order-a")
			ch.SetLabels(map[string]string{"acme.cert-manager.io/order-name": "order-b"})
			return ch
		}(), true},
		{"ownerRef wrong + label right wins on label", func() *unstructured.Unstructured {
			ch := cmrChallenge("app", "ch-7", true, true, time.Hour, "order-b")
			ch.SetLabels(map[string]string{"acme.cert-manager.io/order-name": "order-a"})
			return ch
		}(), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := challengeLinkedToOrder(tc.ch, order); got != tc.want {
				t.Fatalf("challengeLinkedToOrder = %v, want %v", got, tc.want)
			}
		})
	}
}
