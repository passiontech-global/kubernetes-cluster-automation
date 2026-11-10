// stuck_certificaterequest_reap_test.go — branch coverage for
// reapStuckCR: the candidacy gates (healthy vs expiring cert), the
// CR-scan skips, the owned-pending-Order challenge cross-check, the
// shared reset budget's exhausted/rate-limited refusals, and the
// delete/annotation failure tails.
package certmanagerreaper

import (
	"errors"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// newStuckCRReaper builds a reaper with the per-sweep caches armed —
// run() does this lazily, but direct reapStuckCR calls write through
// crCache/orderCache immediately.
func newStuckCRReaper(dyn *dynamicfake.FakeDynamicClient) *certManagerReaper {
	return &certManagerReaper{dyn: dyn, queue: "certmanager-reaper",
		resets:     map[string]*certReset{},
		crCache:    map[string]crListResult{},
		orderCache: map[string]*orderIndex{}}
}

func cmrCRExists(t *testing.T, dyn *dynamicfake.FakeDynamicClient, ns, name string) bool {
	t.Helper()
	_, err := dyn.Resource(certificateRequestGVR).Namespace(ns).
		Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false
	}
	if err != nil {
		t.Fatalf("get certificaterequest %s/%s: %v", ns, name, err)
	}
	return true
}

// cmrCertRequestReady is a CR carrying Ready=True — issued, never a
// stuck-CR candidate no matter its age.
func cmrCertRequestReady(ns, name, certName string, age time.Duration) *unstructured.Unstructured {
	cr := cmrCertRequest(ns, name, certName)
	cr.SetCreationTimestamp(metav1.NewTime(time.Now().Add(-age)))
	_ = unstructured.SetNestedSlice(cr.Object, []interface{}{
		map[string]interface{}{
			"type": "Ready", "status": "True",
			"lastTransitionTime": time.Now().Add(-age).UTC().Format(time.RFC3339),
		},
	}, "status", "conditions")
	return cr
}

// A cert that is neither Ready=False nor expiring <14d is not a
// stuck-CR candidate at all — the function returns before spending a
// single CR List.
func TestReapStuckCRSkipsHealthyCert(t *testing.T) {
	var crLists int
	dyn := testutil.NewDynamicClient(
		cmrCert("app", "tls-ok", "True",
			time.Now().Add(30*24*time.Hour).UTC().Format(time.RFC3339)))
	dyn.PrependReactor("list", "certificaterequests",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			crLists++
			return false, nil, nil
		})
	r := newStuckCRReaper(dyn)
	now := time.Now()
	if r.reapStuckCR(ctx, cmrCert("app", "tls-ok", "True",
		time.Now().Add(30*24*time.Hour).UTC().Format(time.RFC3339)), now) {
		t.Fatal("healthy cert reaped a stuck CR")
	}
	if crLists != 0 {
		t.Fatalf("CR Lists issued = %d, want 0 — the candidacy gate must fire first", crLists)
	}
}

// The other candidacy half: certExpiringSoon. A Ready=True cert whose
// notAfter lands inside 14d still reaps a wedged CR — a renewal that
// silently died.
func TestReapStuckCRExpiringCertCandidate(t *testing.T) {
	cert := cmrCert("app", "tls-exp", "True",
		time.Now().Add(30*24*time.Hour).UTC().Format(time.RFC3339))
	_ = unstructured.SetNestedField(cert.Object,
		time.Now().Add(7*24*time.Hour).UTC().Format(time.RFC3339),
		"status", "notAfter")
	dyn := testutil.NewDynamicClient(cert,
		cmrCertRequestStuck("app", "cr-stuck", "tls-exp", time.Hour))
	r := newStuckCRReaper(dyn)

	if !r.reapStuckCR(ctx, cert, time.Now()) {
		t.Fatal("expiring cert's wedged CR was not reaped")
	}
	if cmrCRExists(t, dyn, "app", "cr-stuck") {
		t.Fatal("stuck CR still present after the expiring-cert reap")
	}
	if st := r.resets["app/tls-exp"]; st == nil || st.total != 1 {
		t.Fatalf("CR reap did not charge the shared budget: %+v", st)
	}
}

// A failed CR List makes the wedge scan indeterminate — fail closed,
// keep everything, IncError once (listCRs owns the meter).
func TestReapStuckCRListError(t *testing.T) {
	cert := cmrCert("app", "tls-a", "False", "")
	dyn := testutil.NewDynamicClient(cert,
		cmrCertRequestStuck("app", "cr-stuck", "tls-a", time.Hour))
	dyn.PrependReactor("list", "certificaterequests",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("cr list boom")
		})
	r := newStuckCRReaper(dyn)
	before := testutil.QueueErrorCount(t, "certmanager-reaper")

	if r.reapStuckCR(ctx, cert, time.Now()) {
		t.Fatal("reaped on an unreadable CR list")
	}
	if !cmrCRExists(t, dyn, "app", "cr-stuck") {
		t.Fatal("CR deleted although the scan could not run")
	}
	if got := testutil.QueueErrorCount(t, "certmanager-reaper") - before; got != 1 {
		t.Fatalf("CR list failure did not IncError once, delta %v", got)
	}
}

// Every non-stuck CR shape is skipped: unattributable (no owner, no
// certificate-name marker), attributed to a DIFFERENT cert, issued
// (Ready=True), and wedged-but-young. With nothing left the function
// returns before touching the Order index.
func TestReapStuckCRNoStuckCR(t *testing.T) {
	naked := testutil.Unstructured(
		certificateRequestGVR.GroupVersion().WithKind("CertificateRequest"),
		"app", "cr-naked", nil)
	cert := cmrCert("app", "tls-a", "False", "")
	dyn := testutil.NewDynamicClient(cert,
		naked,
		cmrCertRequestStuck("app", "cr-other-cert", "tls-other", time.Hour),
		cmrCertRequestReady("app", "cr-ready", "tls-a", time.Hour),
		cmrCertRequestStuck("app", "cr-young", "tls-a", 5*time.Minute))
	r := newStuckCRReaper(dyn)

	if r.reapStuckCR(ctx, cert, time.Now()) {
		t.Fatal("reaped with no stuck CR for this cert")
	}
	for _, name := range []string{"cr-naked", "cr-other-cert", "cr-ready", "cr-young"} {
		if !cmrCRExists(t, dyn, "app", name) {
			t.Fatalf("CR %s deleted — only a >30m Ready!=True CR of THIS cert is reapable", name)
		}
	}
}

// A CR that never reported a Ready condition still wedges on its
// creationTimestamp — the "never-reported" half of the age rule.
func TestReapStuckCRConditionlessOldCR(t *testing.T) {
	cr := cmrCertRequest("app", "cr-quiet", "tls-a")
	cr.SetCreationTimestamp(metav1.NewTime(time.Now().Add(-time.Hour)))
	cert := cmrCert("app", "tls-a", "False", "")
	dyn := testutil.NewDynamicClient(cert, cr)
	r := newStuckCRReaper(dyn)

	if !r.reapStuckCR(ctx, cert, time.Now()) {
		t.Fatal("condition-less hour-old CR was not treated as wedged")
	}
	if cmrCRExists(t, dyn, "app", "cr-quiet") {
		t.Fatal("condition-less wedged CR not deleted")
	}
}

// A failed Order List makes the owned-pending-Order cross-check
// indeterminate — fail closed, keep the CR.
func TestReapStuckCROrderAttributionError(t *testing.T) {
	cert := cmrCert("app", "tls-a", "False", "")
	dyn := testutil.NewDynamicClient(cert,
		cmrCertRequestStuck("app", "cr-stuck", "tls-a", time.Hour))
	dyn.PrependReactor("list", "orders",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("order list boom")
		})
	r := newStuckCRReaper(dyn)
	before := testutil.QueueErrorCount(t, "certmanager-reaper")

	if r.reapStuckCR(ctx, cert, time.Now()) {
		t.Fatal("reaped although order attribution could not run")
	}
	if !cmrCRExists(t, dyn, "app", "cr-stuck") {
		t.Fatal("CR deleted on an indeterminate order cross-check")
	}
	if got := testutil.QueueErrorCount(t, "certmanager-reaper") - before; got < 1 {
		t.Fatalf("order list failure did not IncError, delta %v", got)
	}
}

// The stuck CR owns a pending Order whose Challenge is still
// progressing (presented, not processing): deleting the CR would
// cascade-kill healthy issuance — KEEP.
func TestReapStuckCRKeepsProgressingOrder(t *testing.T) {
	cert := cmrCert("app", "tls-a", "False", "")
	dyn := testutil.NewDynamicClient(cert,
		cmrCertRequestStuck("app", "cr-stuck", "tls-a", time.Hour),
		cmrOrderOwned("app", "order-a", "pending", 45*time.Minute, "cr-stuck"),
		cmrChallenge("app", "order-a-ch", true, false, time.Hour, "order-a"))
	r := newStuckCRReaper(dyn)

	if r.reapStuckCR(ctx, cert, time.Now()) {
		t.Fatal("reaped a CR whose pending Order challenge still progresses")
	}
	if !cmrCRExists(t, dyn, "app", "cr-stuck") {
		t.Fatal("CR deleted while its Order's challenge is healthy")
	}
}

// Same shape but the Challenge IS wedged (presented+processing, no
// transition >30m): the cross-check passes and the CR is reaped.
func TestReapStuckCRReapsWedgedOrder(t *testing.T) {
	cert := cmrCert("app", "tls-a", "False", "")
	dyn := testutil.NewDynamicClient(cert,
		cmrCertRequestStuck("app", "cr-stuck", "tls-a", time.Hour),
		cmrOrderOwned("app", "order-a", "pending", 45*time.Minute, "cr-stuck"),
		cmrChallenge("app", "order-a-ch", true, true, time.Hour, "order-a"))
	r := newStuckCRReaper(dyn)

	if !r.reapStuckCR(ctx, cert, time.Now()) {
		t.Fatal("wedged-Order CR was not reaped")
	}
	if cmrCRExists(t, dyn, "app", "cr-stuck") {
		t.Fatal("stuck CR not deleted despite the wedged challenge")
	}
}

// A failed Challenge List inside the live-Order branch fails closed —
// the cross-check could not run, so the CR stays.
func TestReapStuckCRChallengeListError(t *testing.T) {
	cert := cmrCert("app", "tls-a", "False", "")
	dyn := testutil.NewDynamicClient(cert,
		cmrCertRequestStuck("app", "cr-stuck", "tls-a", time.Hour),
		cmrOrderOwned("app", "order-a", "pending", 45*time.Minute, "cr-stuck"),
		cmrChallenge("app", "order-a-ch", true, true, time.Hour, "order-a"))
	dyn.PrependReactor("list", "challenges",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("challenge list boom")
		})
	r := newStuckCRReaper(dyn)
	before := testutil.QueueErrorCount(t, "certmanager-reaper")

	if r.reapStuckCR(ctx, cert, time.Now()) {
		t.Fatal("reaped although the challenge cross-check could not run")
	}
	if !cmrCRExists(t, dyn, "app", "cr-stuck") {
		t.Fatal("CR deleted on an unreadable challenge list")
	}
	if got := testutil.QueueErrorCount(t, "certmanager-reaper") - before; got != 1 {
		t.Fatalf("challenge list failure did not IncError once, delta %v", got)
	}
}

// Orders that do NOT keep the CR alive: one owned by a sibling CR of
// the same cert (not the stuck one), and one owned by the stuck CR
// but already settled (state != pending). Neither sets liveOrder —
// the reap proceeds.
func TestReapStuckCRIgnoresForeignAndSettledOrders(t *testing.T) {
	cert := cmrCert("app", "tls-a", "False", "")
	dyn := testutil.NewDynamicClient(cert,
		cmrCertRequestStuck("app", "cr-stuck", "tls-a", time.Hour),
		cmrCertRequest("app", "cr-sibling", "tls-a"),
		cmrOrderOwned("app", "order-sibling", "pending", 45*time.Minute, "cr-sibling"),
		cmrOrderOwned("app", "order-settled", "valid", 45*time.Minute, "cr-stuck"))
	r := newStuckCRReaper(dyn)

	if !r.reapStuckCR(ctx, cert, time.Now()) {
		t.Fatal("foreign/settled orders blocked the reap")
	}
	if cmrCRExists(t, dyn, "app", "cr-stuck") {
		t.Fatal("stuck CR not deleted")
	}
	if !cmrCRExists(t, dyn, "app", "cr-sibling") {
		t.Fatal("sibling CR deleted — only the wedged one is reapable")
	}
}

// The shared acme-order-resets budget applies to the CR path too:
// exhausted → refuse, IncError exactly once across repeated calls.
func TestReapStuckCRBudgetExhausted(t *testing.T) {
	cert := cmrCert("app", "tls-a", "False", "")
	dyn := testutil.NewDynamicClient(cert,
		cmrCertRequestStuck("app", "cr-stuck", "tls-a", time.Hour))
	r := newStuckCRReaper(dyn)
	r.resets["app/tls-a"] = &certReset{total: certReaperMaxReset}
	before := testutil.QueueErrorCount(t, "certmanager-reaper")

	for i := 0; i < 2; i++ {
		if r.reapStuckCR(ctx, cert, time.Now()) {
			t.Fatal("reaped despite the exhausted reset budget")
		}
	}
	if !cmrCRExists(t, dyn, "app", "cr-stuck") {
		t.Fatal("CR deleted past the reset cap")
	}
	if got := testutil.QueueErrorCount(t, "certmanager-reaper") - before; got != 1 {
		t.Fatalf("budget exhaustion IncError delta = %v, want exactly 1", got)
	}
}

// The persisted half of the budget rate-limits on the wider 6h CR
// gap: a reset stamped 1h ago (inside 6h, outside the 1h order gap)
// still refuses — silently, no IncError.
func TestReapStuckCRPersistedRateLimit(t *testing.T) {
	cert := cmrCert("app", "tls-a", "False", "")
	dyn := testutil.NewDynamicClient(cert,
		cmrCertRequestStuck("app", "cr-stuck", "tls-a", time.Hour))
	r := newStuckCRReaper(dyn)
	r.resets["app/tls-a"] = &certReset{
		total: 1, last: time.Now().Add(-time.Hour)}
	before := testutil.QueueErrorCount(t, "certmanager-reaper")

	if r.reapStuckCR(ctx, cert, time.Now()) {
		t.Fatal("reaped inside the persisted 6h CR gap")
	}
	if !cmrCRExists(t, dyn, "app", "cr-stuck") {
		t.Fatal("CR deleted inside the rate-limit window")
	}
	if got := testutil.QueueErrorCount(t, "certmanager-reaper") - before; got != 0 {
		t.Fatalf("rate-limit skip IncErrored, delta %v — a cooldown is not an error", got)
	}
}

// A failed CR delete tallies failed — deleted==0 keeps the budget
// unspent and reports through OnError.
func TestReapStuckCRDeleteError(t *testing.T) {
	cert := cmrCert("app", "tls-a", "False", "")
	dyn := testutil.NewDynamicClient(cert,
		cmrCertRequestStuck("app", "cr-stuck", "tls-a", time.Hour))
	dyn.PrependReactor("delete", "certificaterequests",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("delete rejected")
		})
	r := newStuckCRReaper(dyn)
	before := testutil.QueueErrorCount(t, "certmanager-reaper")

	if r.reapStuckCR(ctx, cert, time.Now()) {
		t.Fatal("reported a reap on a failed delete")
	}
	if !cmrCRExists(t, dyn, "app", "cr-stuck") {
		t.Fatal("CR vanished despite the failing delete")
	}
	if st := r.resets["app/tls-a"]; st == nil || st.total != 0 {
		t.Fatalf("reset budget consumed by a failed delete: %+v", st)
	}
	if got := testutil.QueueErrorCount(t, "certmanager-reaper") - before; got != 1 {
		t.Fatalf("CR delete failure did not IncError once, delta %v", got)
	}
}

// The delete landed but the budget-annotation write failed: the reap
// still reports true (the CR is gone) and the failure is metered —
// best-effort persistence must not mask a delivered heal.
func TestReapStuckCRAnnotationWriteError(t *testing.T) {
	cert := cmrCert("app", "tls-a", "False", "")
	dyn := testutil.NewDynamicClient(cert,
		cmrCertRequestStuck("app", "cr-stuck", "tls-a", time.Hour))
	dyn.PrependReactor("patch", "certificates",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})
	r := newStuckCRReaper(dyn)
	before := testutil.QueueErrorCount(t, "certmanager-reaper")

	if !r.reapStuckCR(ctx, cert, time.Now()) {
		t.Fatal("delivered delete reported as failed on the annotation write")
	}
	if cmrCRExists(t, dyn, "app", "cr-stuck") {
		t.Fatal("CR not deleted")
	}
	if got := testutil.QueueErrorCount(t, "certmanager-reaper") - before; got != 1 {
		t.Fatalf("annotation write failure did not IncError once, delta %v", got)
	}
}
