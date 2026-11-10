package certmanagerreaper

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// certmanager-reaper builders
// ---------------------------------------------------------------------------

// cmrCert builds an unstructured Certificate. readyStatus is the Ready
// condition's status string ("" = no conditions); renewalTime is an
// RFC3339 status.renewalTime ("" = absent) — where cert-manager
// actually publishes the next renewal.
func cmrCert(ns, name, readyStatus, renewalTime string) *unstructured.Unstructured {
	o := testutil.Unstructured(
		certificateGVR.GroupVersion().WithKind("Certificate"), ns, name, nil)
	if readyStatus != "" {
		_ = unstructured.SetNestedSlice(o.Object, []interface{}{
			map[string]interface{}{"type": "Ready", "status": readyStatus},
		}, "status", "conditions")
	}
	if renewalTime != "" {
		_ = unstructured.SetNestedField(o.Object, renewalTime, "status", "renewalTime")
	}
	return o
}

func cmrOrder(ns, name, state string, age time.Duration) *unstructured.Unstructured {
	o := testutil.Unstructured(
		orderGVR.GroupVersion().WithKind("Order"), ns, name, nil)
	o.SetCreationTimestamp(metav1.NewTime(time.Now().Add(-age)))
	if state != "" {
		_ = unstructured.SetNestedField(o.Object, state, "status", "state")
	}
	return o
}

// cmrOrderOwned wires the Order's CertificateRequest ownerRef — the
// first hop of the Order→CR→Certificate attribution chain.
func cmrOrderOwned(ns, name, state string, age time.Duration, crName string) *unstructured.Unstructured {
	o := cmrOrder(ns, name, state, age)
	o.SetOwnerReferences([]metav1.OwnerReference{{
		APIVersion: "acme.cert-manager.io/v1",
		Kind:       "CertificateRequest",
		Name:       crName,
	}})
	return o
}

// cmrCertRequest builds a CertificateRequest owned by certName — the
// second hop of the attribution chain (cert-manager sets the
// Certificate ownerRef on every CR it creates). Freshly created and
// Ready-True: a stuck Ready=False/old CR is built inline by the
// stuck-CR-reap tests instead.
func cmrCertRequest(ns, name, certName string) *unstructured.Unstructured {
	o := testutil.Unstructured(
		certificateRequestGVR.GroupVersion().WithKind("CertificateRequest"), ns, name, nil)
	o.SetCreationTimestamp(metav1.NewTime(time.Now()))
	o.SetOwnerReferences([]metav1.OwnerReference{{
		APIVersion: "cert-manager.io/v1",
		Kind:       "Certificate",
		Name:       certName,
	}})
	return o
}

// cmrCertRequestStuck is the stuck-CR wedge: Ready=False (Pending/Failed)
// for >30m under certName — reaped by reapStuckCR.
func cmrCertRequestStuck(ns, name, certName string, age time.Duration) *unstructured.Unstructured {
	o := cmrCertRequest(ns, name, certName)
	o.SetCreationTimestamp(metav1.NewTime(time.Now().Add(-age)))
	_ = unstructured.SetNestedSlice(o.Object, []interface{}{
		map[string]interface{}{"type": "Ready", "status": "False",
			"lastTransitionTime": time.Now().Add(-age).UTC().Format(time.RFC3339)},
	}, "status", "conditions")
	return o
}

// cmrChallenge builds an unstructured Challenge; transitionAgo ages
// status.lastTransitionTime, orderOwner sets the ownerReference name.
func cmrChallenge(ns, name string, presented, processing bool,
	transitionAgo time.Duration, orderOwner string) *unstructured.Unstructured {
	o := testutil.Unstructured(
		challengeGVR.GroupVersion().WithKind("Challenge"), ns, name, nil)
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

// stuckFixture is the full wedge: Ready=False cert + its
// CertificateRequest + pending>30m order owned by that CR +
// presented/processing challenge with an old transition.
func stuckFixture(ns, certName, orderName string) []runtime.Object {
	return []runtime.Object{
		cmrCert(ns, certName, "False", ""),
		cmrCertRequest(ns, orderName+"-cr", certName),
		cmrOrderOwned(ns, orderName, "pending", 45*time.Minute, orderName+"-cr"),
		cmrChallenge(ns, orderName+"-ch", true, true, time.Hour, orderName),
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestCertManagerReaperSetupDisabled(t *testing.T) {
	// Deps.Disabled is what setupModules stamps when
	// CERTMANAGER_REAPER_ENABLED gates the module off — a disabled
	// Setup must return nil without touching the (nil) manager.
	if err := Setup(shared.Deps{Name: "certmanager-reaper", Disabled: true}); err != nil {
		t.Fatalf("disabled setup must return nil, got %v", err)
	}
}

func TestCertManagerReaperDeletesStuckOrder(t *testing.T) {
	dyn := testutil.NewDynamicClient(stuckFixture("app", "tls-a", "order-a")...)
	r := &certManagerReaper{dyn: dyn, queue: "certmanager-reaper",
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
	dyn := testutil.NewDynamicClient(cmrCert("app", "tls-b", "True",
		time.Now().Add(48*time.Hour).UTC().Format(time.RFC3339)),
		cmrCertRequest("app", "order-b-cr", "tls-b"),
		cmrOrderOwned("app", "order-b", "pending", 45*time.Minute, "order-b-cr"),
		cmrChallenge("app", "order-b-ch", true, true, time.Hour, "order-b"))
	r := &certManagerReaper{dyn: dyn, queue: "certmanager-reaper",
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
	dyn := testutil.NewDynamicClient(cmrCert("app", "tls-ok", "True",
		time.Now().Add(30*24*time.Hour).UTC().Format(time.RFC3339)),
		cmrCertRequest("app", "order-ok-cr", "tls-ok"),
		cmrOrderOwned("app", "order-ok", "pending", 45*time.Minute, "order-ok-cr"),
		cmrChallenge("app", "order-ok-ch", true, true, time.Hour, "order-ok"))
	r := &certManagerReaper{dyn: dyn, queue: "certmanager-reaper",
		resets: map[string]*certReset{}}
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !cmrOrderExists(t, dyn, "app", "order-ok") {
		t.Fatal("order deleted for a healthy non-renewing cert")
	}
}

// Order must be BOTH pending and >30m old — and owned by this cert's
// CertificateRequest before the gates even apply.
func TestCertManagerReaperOrderGates(t *testing.T) {
	dyn := testutil.NewDynamicClient(cmrCert("app", "tls-a", "False", ""),
		cmrCertRequest("app", "cr-a", "tls-a"),
		cmrOrderOwned("app", "young", "pending", 10*time.Minute, "cr-a"), // fresh
		cmrOrderOwned("app", "valid", "valid", 45*time.Minute, "cr-a"),   // not pending
		cmrChallenge("app", "ch", true, true, time.Hour, "young"))
	r := &certManagerReaper{dyn: dyn, queue: "certmanager-reaper",
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
	dyn := testutil.NewDynamicClient(cmrCert("app", "tls-a", "False", ""),
		cmrCertRequest("app", "order-a-cr", "tls-a"),
		cmrOrderOwned("app", "order-a", "pending", 45*time.Minute, "order-a-cr"),
		// presented but not processing — still moving.
		cmrChallenge("app", "ch-a", true, false, time.Hour, "order-a"))
	r := &certManagerReaper{dyn: dyn, queue: "certmanager-reaper",
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
	dyn := testutil.NewDynamicClient(cmrCert("app", "tls-a", "False", ""),
		cmrCertRequest("app", "order-a-cr", "tls-a"),
		cmrOrderOwned("app", "order-a", "pending", 45*time.Minute, "order-a-cr"),
		cmrChallenge("app", "ch-b", true, true, time.Hour, "other-order"))
	r := &certManagerReaper{dyn: dyn, queue: "certmanager-reaper",
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
	dyn := testutil.NewDynamicClient(stuckFixture("app", "tls-a", "order-1")...)
	r := &certManagerReaper{dyn: dyn, queue: "certmanager-reaper",
		resets: map[string]*certReset{}}
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	// cert-manager recreated the order (with a fresh challenge);
	// it wedged again — owned by the same cert's request.
	recreated := cmrOrderOwned("app", "order-2", "pending", 45*time.Minute, "order-1-cr")
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
	dyn := testutil.NewDynamicClient(stuckFixture("app", "tls-a", "order-a")...)
	r := &certManagerReaper{dyn: dyn, queue: "certmanager-reaper",
		resets: map[string]*certReset{
			"app/tls-a": {total: certReaperMaxReset, last: time.Now().Add(-2 * time.Hour)},
		}}
	before := testutil.QueueErrorCount(t, "certmanager-reaper")
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !cmrOrderExists(t, dyn, "app", "order-a") {
		t.Fatal("order deleted despite exhausted reset budget")
	}
	if got := testutil.QueueErrorCount(t, "certmanager-reaper") - before; got != 1 {
		t.Fatalf("expected exactly 1 IncError on budget exhaustion, got %v", got)
	}
	// Second run: still refused, no second IncError.
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := testutil.QueueErrorCount(t, "certmanager-reaper") - before; got != 1 {
		t.Fatalf("IncError repeated after gaveUp, total delta %v", got)
	}
}

// Ready=True earns a clean slate only once NOTHING is still pending:
// a renewal-window candidate reports Ready=True the whole time its
// next Order wedges (the old cert is still valid) — wiping the budget
// there would bypass the hourly gap and the 3-reset cap every sweep.
func TestCertManagerReaperRenewalKeepsResetBudget(t *testing.T) {
	dyn := testutil.NewDynamicClient(cmrCert("app", "tls-renew", "True",
		time.Now().Add(48*time.Hour).UTC().Format(time.RFC3339)),
		cmrCertRequest("app", "order-r-cr", "tls-renew"),
		cmrOrderOwned("app", "order-r", "pending", 45*time.Minute, "order-r-cr"),
		cmrChallenge("app", "order-r-ch", true, true, time.Hour, "order-r"))
	r := &certManagerReaper{dyn: dyn, queue: "certmanager-reaper",
		resets: map[string]*certReset{
			"app/tls-renew": {total: certReaperMaxReset, gaveUp: true},
		}}
	before := testutil.QueueErrorCount(t, "certmanager-reaper")
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !cmrOrderExists(t, dyn, "app", "order-r") {
		t.Fatal("budget wiped for a renewal-window cert — order deleted past the cap")
	}
	if _, ok := r.resets["app/tls-renew"]; !ok {
		t.Fatal("reset budget cleared while the cert is still a reap candidate")
	}
	if got := testutil.QueueErrorCount(t, "certmanager-reaper") - before; got != 0 {
		t.Fatalf("gaveUp must not re-fire IncError while the budget persists, delta %v", got)
	}
}

// A cert recovered to Ready=True with no pending candidacy gets a
// clean slate, and a budget for a deleted Certificate is dropped.
func TestCertManagerReaperPrunesResetBudgets(t *testing.T) {
	dyn := testutil.NewDynamicClient(cmrCert("app", "tls-ok", "True",
		time.Now().Add(30*24*time.Hour).UTC().Format(time.RFC3339)),
		// A second cert still Ready=False keeps its budget.
		cmrCert("app", "pending", "False", ""))
	r := &certManagerReaper{dyn: dyn, queue: "certmanager-reaper",
		resets: map[string]*certReset{
			"app/tls-ok":  {total: certReaperMaxReset, gaveUp: true},
			"gone/tls-x":  {total: 1},
			"app/pending": {total: 1}, // cert exists, still failing
		}}
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.resets["app/tls-ok"]; ok {
		t.Fatal("recovered cert kept its exhausted reset budget")
	}
	if _, ok := r.resets["gone/tls-x"]; ok {
		t.Fatal("deleted cert kept its reset budget")
	}
	if _, ok := r.resets["app/pending"]; !ok {
		t.Fatal("failing cert lost its reset budget")
	}
}

// Per-item failure logs + continues: a failing orders List in ns "bad"
// must not prevent the healthy ns "good" cert from being processed.
func TestCertManagerReaperContinuesOnItemError(t *testing.T) {
	dyn := testutil.NewDynamicClient(append(
		stuckFixture("good", "tls-good", "order-good"),
		cmrCert("bad", "tls-bad", "False", ""))...)
	dyn.PrependReactor("list", "orders",
		func(a clienttesting.Action) (bool, runtime.Object, error) {
			if la, ok := a.(clienttesting.ListAction); ok && la.GetNamespace() == "bad" {
				return true, nil, errors.New("boom")
			}
			return false, nil, nil
		})
	r := &certManagerReaper{dyn: dyn, queue: "certmanager-reaper",
		resets: map[string]*certReset{}}
	before := testutil.QueueErrorCount(t, "certmanager-reaper")
	if err := r.run(ctx); err != nil {
		t.Fatalf("per-item failure must not abort the run: %v", err)
	}
	if cmrOrderExists(t, dyn, "good", "order-good") {
		t.Fatal("healthy cert's stuck order not deleted after a sibling item failed")
	}
	if got := testutil.QueueErrorCount(t, "certmanager-reaper") - before; got < 1 {
		t.Fatal("per-item API failure did not IncError")
	}
}

// Top-level certificate list failure is a real error.
func TestCertManagerReaperListError(t *testing.T) {
	dyn := testutil.NewDynamicClient()
	dyn.PrependReactor("list", "certificates",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	r := &certManagerReaper{dyn: dyn, queue: "certmanager-reaper",
		resets: map[string]*certReset{}}
	if err := r.run(ctx); err == nil {
		t.Fatal("expected error when certificate list fails")
	}
}

// A challenge list failure is a per-item IncError + keep: the order
// must NOT be deleted on an unreadable cross-check.
func TestCertManagerReaperChallengeListError(t *testing.T) {
	dyn := testutil.NewDynamicClient(stuckFixture("app", "tls-a", "order-a")...)
	dyn.PrependReactor("list", "challenges",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("challenges unreachable")
		})
	r := &certManagerReaper{dyn: dyn, queue: "certmanager-reaper",
		resets: map[string]*certReset{}}
	before := testutil.QueueErrorCount(t, "certmanager-reaper")
	if err := r.run(ctx); err != nil {
		t.Fatalf("per-item failure must not abort the run: %v", err)
	}
	if !cmrOrderExists(t, dyn, "app", "order-a") {
		t.Fatal("order deleted although the challenge cross-check failed")
	}
	if got := testutil.QueueErrorCount(t, "certmanager-reaper") - before; got != 1 {
		t.Fatalf("challenge list failure did not IncError once, delta %v", got)
	}
}

// A failed order delete IncErrors but does NOT consume reset budget —
// the next run retries the same order.
func TestCertManagerReaperOrderDeleteError(t *testing.T) {
	dyn := testutil.NewDynamicClient(stuckFixture("app", "tls-a", "order-a")...)
	var failOnce atomic.Bool
	failOnce.Store(true)
	dyn.PrependReactor("delete", "orders",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			if failOnce.CompareAndSwap(true, false) {
				return true, nil, errors.New("delete rejected")
			}
			return false, nil, nil
		})
	r := &certManagerReaper{dyn: dyn, queue: "certmanager-reaper",
		resets: map[string]*certReset{}}
	before := testutil.QueueErrorCount(t, "certmanager-reaper")
	if err := r.run(ctx); err != nil {
		t.Fatalf("per-item failure must not abort the run: %v", err)
	}
	if !cmrOrderExists(t, dyn, "app", "order-a") {
		t.Fatal("order deleted despite the failing delete call")
	}
	if st := r.resets["app/tls-a"]; st == nil || st.total != 0 {
		t.Fatalf("reset budget consumed by a failed delete: %+v", st)
	}
	if got := testutil.QueueErrorCount(t, "certmanager-reaper") - before; got != 1 {
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

// challengeLinkedToOrder: ownerReferences and the acme order-name
// label/annotation are linkage — a linked challenge must point at THIS
// order; a linkage-free challenge is ambiguous in a shared namespace
// and does NOT count (fail closed).
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
		{"annotation points at order", func() *unstructured.Unstructured {
			ch := cmrChallenge("app", "ch-anno", true, true, time.Hour, "")
			ch.SetAnnotations(map[string]string{"acme.cert-manager.io/order-name": "order-a"})
			return ch
		}(), true},
		{"ownerRef points at order",
			cmrChallenge("app", "ch-3", true, true, time.Hour, "order-a"), true},
		{"ownerRef points elsewhere",
			cmrChallenge("app", "ch-4", true, true, time.Hour, "order-b"), false},
		{"no linkage — ambiguous, not ours", withLabel("ch-5", ""), false},
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

// Order attribution is per-cert through the Order→CertificateRequest→
// Certificate owner chain: a pending>30m order owned by a DIFFERENT
// cert's CR — or carrying no ownerRef at all — is never reaped on
// this cert's candidacy (and never charges its budget).
func TestCertManagerReaperIgnoresForeignOrder(t *testing.T) {
	dyn := testutil.NewDynamicClient(cmrCert("app", "tls-a", "False", ""),
		cmrCert("app", "tls-x", "True",
			time.Now().Add(48*time.Hour).UTC().Format(time.RFC3339)),
		cmrCertRequest("app", "cr-a", "tls-a"),
		cmrCertRequest("app", "cr-x", "tls-x"),
		// tls-a's own stuck order — the only reappable one.
		cmrOrderOwned("app", "order-a", "pending", 45*time.Minute, "cr-a"),
		cmrChallenge("app", "order-a-ch", true, true, time.Hour, "order-a"),
		// A foreign cert's pending order — never tls-a's to reap.
		cmrOrderOwned("app", "order-x", "pending", 45*time.Minute, "cr-x"),
		// An ownerless pending order — unattributable, kept.
		cmrOrder("app", "order-free", "pending", 45*time.Minute))
	r := &certManagerReaper{dyn: dyn, queue: "certmanager-reaper",
		resets: map[string]*certReset{}}
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if cmrOrderExists(t, dyn, "app", "order-a") {
		t.Fatal("tls-a's own stuck order was not deleted")
	}
	for _, name := range []string{"order-x", "order-free"} {
		if !cmrOrderExists(t, dyn, "app", name) {
			t.Fatalf("order %s deleted — only this cert's orders may be reaped", name)
		}
	}
}

// The Order List is memoized ONE list per namespace per sweep (same
// shape as the CertificateRequest cache): two candidate certs sharing
// "app" each reap their own wedged order, but the namespace pays a
// single orders List — and a single certificaterequests List — no
// matter how many cert candidates walk it.
func TestCertManagerReaperMemoizesOrderListsPerNamespace(t *testing.T) {
	dyn := testutil.NewDynamicClient(append(
		stuckFixture("app", "tls-a", "order-a"),
		stuckFixture("app", "tls-b", "order-b")...)...)
	var orderLists, crLists atomic.Int64
	dyn.PrependReactor("list", "orders",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			orderLists.Add(1)
			return false, nil, nil
		})
	dyn.PrependReactor("list", "certificaterequests",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			crLists.Add(1)
			return false, nil, nil
		})
	r := &certManagerReaper{dyn: dyn, queue: "certmanager-reaper",
		resets: map[string]*certReset{}}
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"order-a", "order-b"} {
		if cmrOrderExists(t, dyn, "app", name) {
			t.Fatalf("order %s not reaped — memoization changed the verdict", name)
		}
	}
	if n := orderLists.Load(); n != 1 {
		t.Fatalf("orders List calls = %d, want 1 per namespace per sweep", n)
	}
	if n := crLists.Load(); n != 1 {
		t.Fatalf("certificaterequests List calls = %d, want 1 per namespace per sweep", n)
	}
	// Each cert still charged exactly its own reset budget — the index
	// attributes per-cert, never per-namespace.
	if st := r.resets["app/tls-a"]; st == nil || st.total != 1 {
		t.Fatalf("tls-a budget = %+v, want total 1", st)
	}
	if st := r.resets["app/tls-b"]; st == nil || st.total != 1 {
		t.Fatalf("tls-b budget = %+v, want total 1", st)
	}
}

// A CertificateRequest list failure makes attribution indeterminate —
// per-item IncError + keep, same posture as the order/challenge lists.
func TestCertManagerReaperCRListError(t *testing.T) {
	dyn := testutil.NewDynamicClient(stuckFixture("app", "tls-a", "order-a")...)
	dyn.PrependReactor("list", "certificaterequests",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("cr list boom")
		})
	r := &certManagerReaper{dyn: dyn, queue: "certmanager-reaper",
		resets: map[string]*certReset{}}
	before := testutil.QueueErrorCount(t, "certmanager-reaper")
	if err := r.run(ctx); err != nil {
		t.Fatalf("per-item failure must not abort the run: %v", err)
	}
	if !cmrOrderExists(t, dyn, "app", "order-a") {
		t.Fatal("order deleted although attribution could not be established")
	}
	if got := testutil.QueueErrorCount(t, "certmanager-reaper") - before; got != 1 {
		t.Fatalf("CR list failure did not IncError once, delta %v", got)
	}
}

// Malformed condition entries (non-map elements in
// status.conditions) are skipped, not crashed on — cert objects
// straight from unstructured conversion can carry anything.
func TestCertNeedsReapNonMapCondition(t *testing.T) {
	cert := &unstructured.Unstructured{Object: map[string]any{
		"status": map[string]any{
			"conditions": []any{
				"garbage",
				42.0,
				true,
				map[string]any{"type": "Other", "status": "False"},
			},
		},
	}}
	if certNeedsReap(cert, time.Now()) {
		t.Fatal("non-Ready / malformed conditions influenced the verdict")
	}
}

// ---------------------------------------------------------------------------
// 2.1 — reset budget annotation persistence
// ---------------------------------------------------------------------------

func cmrCertAnnotation(t *testing.T, dyn *dynamicfake.FakeDynamicClient, ns, name, anno string) string {
	t.Helper()
	u, err := dyn.Resource(certificateGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get certificate %s/%s: %v", ns, name, err)
	}
	return u.GetAnnotations()[anno]
}

// Every consumed reset is persisted on the Certificate
// ("<total>,<lastRFC3339>") so a restart cannot refund the budget.
func TestCertManagerReaperPersistsResetAnnotation(t *testing.T) {
	dyn := testutil.NewDynamicClient(stuckFixture("app", "tls-a", "order-a")...)
	r := &certManagerReaper{dyn: dyn, queue: "certmanager-reaper",
		resets: map[string]*certReset{}}
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	got := cmrCertAnnotation(t, dyn, "app", "tls-a", acmeResetsAnno)
	total, _, ok := strings.Cut(got, ",")
	if !ok || total != "1" {
		t.Fatalf("acme-resets annotation = %q, want \"1,<RFC3339>\"", got)
	}
}

// Restart simulation: a fresh reaper (empty r.resets) hydrates the
// exhausted budget from the annotation and refuses immediately.
func TestCertManagerReaperHydratesBudgetFromAnnotation(t *testing.T) {
	cert := cmrCert("app", "tls-a", "False", "")
	cert.SetAnnotations(map[string]string{
		acmeResetsAnno: fmt.Sprintf("%d,%s", certReaperMaxReset,
			time.Now().Add(-2*time.Hour).UTC().Format(time.RFC3339)),
	})
	dyn := testutil.NewDynamicClient(cert,
		cmrCertRequest("app", "order-a-cr", "tls-a"),
		cmrOrderOwned("app", "order-a", "pending", 45*time.Minute, "order-a-cr"),
		cmrChallenge("app", "ch-a", true, true, time.Hour, "order-a"))
	r := &certManagerReaper{dyn: dyn, queue: "certmanager-reaper",
		resets: map[string]*certReset{}}
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !cmrOrderExists(t, dyn, "app", "order-a") {
		t.Fatal("order deleted although the persisted budget is exhausted")
	}
	if st := r.resets["app/tls-a"]; st == nil || st.total != certReaperMaxReset {
		t.Fatalf("budget not hydrated from annotation: %+v", st)
	}
}

// A healed cert clears BOTH the map entry and the annotation — its
// next renewal cycle starts with a full budget again.
func TestCertManagerReaperClearsPersistedBudgetOnHeal(t *testing.T) {
	cert := cmrCert("app", "tls-ok", "True",
		time.Now().Add(30*24*time.Hour).UTC().Format(time.RFC3339))
	cert.SetAnnotations(map[string]string{acmeResetsAnno: "2,2026-01-01T00:00:00Z"})
	dyn := testutil.NewDynamicClient(cert)
	r := &certManagerReaper{dyn: dyn, queue: "certmanager-reaper",
		resets: map[string]*certReset{}}
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := cmrCertAnnotation(t, dyn, "app", "tls-ok", acmeResetsAnno); got != "" {
		t.Fatalf("acme-resets annotation not cleared on heal: %q", got)
	}
}

// certResetFromAnnotation: valid formats hydrate, malformed values
// degrade to a zero budget (never MORE resets than recorded). The two
// halves hydrate independently — a malformed total does not poison a
// parseable timestamp and vice versa; both failure modes stay
// conservative (a zero total re-earns resets one at a time, a parsed
// "last" can only rate-limit, never refund).
func TestCertResetFromAnnotation(t *testing.T) {
	parse := func(v string) *certReset {
		c := cmrCert("app", "c", "False", "")
		if v != "" {
			c.SetAnnotations(map[string]string{acmeResetsAnno: v})
		}
		return certResetFromAnnotation(c)
	}
	if st := parse(""); st.total != 0 || !st.last.IsZero() {
		t.Fatalf("absent annotation hydrated to %+v", st)
	}
	for _, tc := range []struct {
		in        string
		wantTotal int
		wantLast  bool // a timestamp hydrated into st.last
	}{
		{"2,2026-11-04T00:00:00Z", 2, true},
		{"garbage", 0, false},               // no comma — whole value dropped
		{"2", 0, false},                     // total without the last half
		{"x,2026-11-04T00:00:00Z", 0, true}, // bad total, valid time still parses
		{"-3,2026-11-04T00:00:00Z", 0, true},
		{"2,not-a-time", 2, false}, // good total, timestamp half dropped
		{"2,2026-11-04T00:00:00Z,trailing", 2, false},
	} {
		st := parse(tc.in)
		if st.total != tc.wantTotal || (st.total < 0 || st.total > certReaperMaxReset) {
			t.Fatalf("annotation %q hydrated total=%d, want %d", tc.in, st.total, tc.wantTotal)
		}
		if gotLast := !st.last.IsZero(); gotLast != tc.wantLast {
			t.Fatalf("annotation %q hydrated last=%v, want present=%v",
				tc.in, st.last, tc.wantLast)
		}
	}
}

// stuck-CR-reap — a CertificateRequest wedged Ready=False >30m under a
// Ready=False Certificate is deleted (budget-charged), so
// cert-manager re-issues on the next sync.
func TestCertManagerReaperStuckCertificateRequest(t *testing.T) {
	objs := []runtime.Object{
		cmrCert("app", "tls-stuck", "False", ""),
		cmrCertRequestStuck("app", "cr-stuck", "tls-stuck", time.Hour),
	}
	dyn := testutil.NewDynamicClient(objs...)
	r := &certManagerReaper{dyn: dyn, queue: "certmanager-reaper",
		resets: map[string]*certReset{}}
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := dyn.Resource(certificateRequestGVR).Namespace("app").
		Get(ctx, "cr-stuck", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatal("stuck CertificateRequest not deleted")
	}
	if st := r.resets["app/tls-stuck"]; st == nil || st.total != 1 {
		t.Fatalf("CR reap did not charge the shared budget: %+v", st)
	}
	// The 6h gap blocks an immediate second reap.
	if r.reapStuckCR(ctx, cmrCert("app", "tls-stuck", "False", ""), time.Now()) {
		t.Fatal("second CR reap fired inside the 6h cooldown")
	}
}

// certNameForCR resolves the Certificate a CertificateRequest serves:
// the Certificate ownerRef cert-manager always sets wins; the
// cert-manager.io/certificate-name label then annotation are the
// fallback for owner-stripped CRs. ok=false means unattributable —
// the CR's Orders then match nothing and the reaper leaves it alone.
func TestCertNameForCR(t *testing.T) {
	cr := func() *unstructured.Unstructured {
		return testutil.Unstructured(
			certificateRequestGVR.GroupVersion().WithKind("CertificateRequest"),
			"app", "cr-1", nil)
	}
	withOwner := func(kind, name string) *unstructured.Unstructured {
		o := cr()
		o.SetOwnerReferences([]metav1.OwnerReference{{
			APIVersion: "cert-manager.io/v1", Kind: kind, Name: name}})
		return o
	}
	cases := []struct {
		name   string
		obj    *unstructured.Unstructured
		want   string
		wantOK bool
	}{
		{"certificate owner ref",
			withOwner("Certificate", "tls-a"), "tls-a", true},
		{"owner ref wins over labels",
			func() *unstructured.Unstructured {
				o := withOwner("Certificate", "tls-a")
				o.SetLabels(map[string]string{
					"cert-manager.io/certificate-name": "tls-label"})
				return o
			}(), "tls-a", true},
		{"empty-name owner ref falls through to label",
			func() *unstructured.Unstructured {
				o := withOwner("Certificate", "")
				o.SetLabels(map[string]string{
					"cert-manager.io/certificate-name": "tls-label"})
				return o
			}(), "tls-label", true},
		{"non-certificate owner ref falls through to label",
			func() *unstructured.Unstructured {
				o := withOwner("Order", "ord-1")
				o.SetLabels(map[string]string{
					"cert-manager.io/certificate-name": "tls-label"})
				return o
			}(), "tls-label", true},
		{"label fallback",
			func() *unstructured.Unstructured {
				o := cr()
				o.SetLabels(map[string]string{
					"cert-manager.io/certificate-name": "tls-label"})
				return o
			}(), "tls-label", true},
		{"annotation fallback",
			func() *unstructured.Unstructured {
				o := cr()
				o.SetAnnotations(map[string]string{
					"cert-manager.io/certificate-name": "tls-anno"})
				return o
			}(), "tls-anno", true},
		{"label beats annotation",
			func() *unstructured.Unstructured {
				o := cr()
				o.SetLabels(map[string]string{
					"cert-manager.io/certificate-name": "tls-label"})
				o.SetAnnotations(map[string]string{
					"cert-manager.io/certificate-name": "tls-anno"})
				return o
			}(), "tls-label", true},
		{"unattributable",
			cr(), "", false},
	}
	for _, tc := range cases {
		got, ok := certNameForCR(tc.obj)
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("%s: certNameForCR=(%q,%v), want (%q,%v)",
				tc.name, got, ok, tc.want, tc.wantOK)
		}
	}
}
