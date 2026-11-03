package csrwatcher

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/testutil"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

// csr builds a pending CertificateSigningRequest; decided=true adds a
// terminal Approved condition.
func csr(name, signer, username string, age time.Duration,
	decided bool) *certificatesv1.CertificateSigningRequest {
	o := &certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			CreationTimestamp: metav1.NewTime(time.Now().Add(-age)),
		},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			SignerName: signer,
			Username:   username,
		},
	}
	if decided {
		o.Status.Conditions = append(o.Status.Conditions,
			certificatesv1.CertificateSigningRequestCondition{
				Type:   certificatesv1.CertificateApproved,
				Status: corev1.ConditionTrue,
			})
	}
	return o
}

func newCSRWatcher(cs *fake.Clientset, approve bool) *csrWatcher {
	return &csrWatcher{cs: cs, approve: approve,
		warned: map[string]struct{}{}, reported: map[string]struct{}{}}
}

func csrApproved(t *testing.T, cs *fake.Clientset, name string) (approved bool, reason string) {
	t.Helper()
	got, err := cs.CertificatesV1().CertificateSigningRequests().
		Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get csr %s: %v", name, err)
	}
	for _, c := range got.Status.Conditions {
		if c.Type == certificatesv1.CertificateApproved {
			return true, c.Reason
		}
	}
	return false, ""
}

// Detect mode: warn-log once per CSR, take no action, never IncError.
func TestCSRWatcherDetectOnly(t *testing.T) {
	old := csr("csr-1", kubeletServingSigner, "system:node:n1", time.Hour, false)
	cs := fake.NewSimpleClientset(old)
	w := newCSRWatcher(cs, false)
	before := testutil.QueueErrorCount(t, csrWatcherQueue)
	for i := 0; i < 2; i++ { // warn-once set must not break the second run
		if err := w.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if ok, _ := csrApproved(t, cs, "csr-1"); ok {
		t.Fatal("detect mode approved a CSR")
	}
	if got := testutil.QueueErrorCount(t, csrWatcherQueue) - before; got != 0 {
		t.Fatalf("pending CSR in detect mode is not an error, delta %v", got)
	}
	if _, ok := w.warned["csr-1"]; !ok {
		t.Fatal("CSR not recorded in the warn-once set")
	}
}

// Approve mode happy path: valid system:node user + existing Node.
func TestCSRWatcherApprovesValid(t *testing.T) {
	old := csr("csr-1", kubeletServingSigner, "system:node:n1", time.Hour, false)
	cs := fake.NewSimpleClientset(old,
		testutil.Node("n1", corev1.ConditionTrue, nil))
	w := newCSRWatcher(cs, true)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	ok, reason := csrApproved(t, cs, "csr-1")
	if !ok {
		t.Fatal("valid kubelet-serving CSR not approved")
	}
	if reason != "NodeOpsAutoApprove" {
		t.Fatalf("unexpected approval reason %q", reason)
	}
}

// Skips: wrong signer, already-decided, too fresh.
func TestCSRWatcherSkipsNonCandidates(t *testing.T) {
	cs := fake.NewSimpleClientset(
		csr("wrong-signer", "kubernetes.io/kube-apiserver-client",
			"system:node:n1", time.Hour, false),
		csr("decided", kubeletServingSigner, "system:node:n1", time.Hour, true),
		csr("fresh", kubeletServingSigner, "system:node:n1", 5*time.Minute, false),
		testutil.Node("n1", corev1.ConditionTrue, nil))
	w := newCSRWatcher(cs, true)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"wrong-signer", "fresh"} {
		if ok, _ := csrApproved(t, cs, name); ok {
			t.Fatalf("csr %s wrongly approved", name)
		}
	}
	got, err := cs.CertificatesV1().CertificateSigningRequests().
		Get(ctx, "decided", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Status.Conditions) != 1 {
		t.Fatal("decided CSR gained a second condition")
	}
}

// Username mismatch (not system:node:*): warn+skip, IncError exactly
// once across repeated runs.
func TestCSRWatcherUsernameMismatch(t *testing.T) {
	bad := csr("csr-evil", kubeletServingSigner,
		"system:serviceaccount:kube-system:privesc", time.Hour, false)
	cs := fake.NewSimpleClientset(bad)
	w := newCSRWatcher(cs, true)
	before := testutil.QueueErrorCount(t, csrWatcherQueue)
	for i := 0; i < 2; i++ {
		if err := w.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if ok, _ := csrApproved(t, cs, "csr-evil"); ok {
		t.Fatal("CSR with non-node username was approved")
	}
	if got := testutil.QueueErrorCount(t, csrWatcherQueue) - before; got != 1 {
		t.Fatalf("expected exactly 1 IncError for bad username, delta %v", got)
	}
}

// Node named in the username does not exist -> validation fails.
func TestCSRWatcherNodeMissing(t *testing.T) {
	cs := fake.NewSimpleClientset(
		csr("csr-ghost", kubeletServingSigner, "system:node:ghost", time.Hour, false))
	w := newCSRWatcher(cs, true)
	before := testutil.QueueErrorCount(t, csrWatcherQueue)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if ok, _ := csrApproved(t, cs, "csr-ghost"); ok {
		t.Fatal("CSR approved for a nonexistent node")
	}
	if got := testutil.QueueErrorCount(t, csrWatcherQueue) - before; got != 1 {
		t.Fatalf("expected IncError for missing node, delta %v", got)
	}
}

// Per-run cap: at most csrMaxApprovalsRun approvals per cycle; the
// remainder wait for the next run.
func TestCSRWatcherApprovalCap(t *testing.T) {
	objs := []runtime.Object{}
	for i := 0; i < csrMaxApprovalsRun+2; i++ {
		name := fmt.Sprintf("n%02d", i)
		objs = append(objs,
			csr("csr-"+name, kubeletServingSigner,
				"system:node:"+name, time.Hour, false),
			testutil.Node(name, corev1.ConditionTrue, nil))
	}
	cs := fake.NewSimpleClientset(objs...)
	w := newCSRWatcher(cs, true)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	list, err := cs.CertificatesV1().CertificateSigningRequests().
		List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	approved := 0
	for _, c := range list.Items {
		if csrDecided(&c) {
			approved++
		}
	}
	if approved != csrMaxApprovalsRun {
		t.Fatalf("expected cap=%d approvals, got %d", csrMaxApprovalsRun, approved)
	}
}

// A vanished CSR is forgotten: the warn-once set must not pin a
// csr-xxxxx name forever — a same-named replacement warns again.
func TestCSRWatcherPrunesWarnedForDeletedCSR(t *testing.T) {
	old := csr("csr-1", kubeletServingSigner, "system:node:n1", time.Hour, false)
	cs := fake.NewSimpleClientset(old)
	w := newCSRWatcher(cs, false)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.warned["csr-1"]; !ok {
		t.Fatal("pending CSR not recorded in the warn-once set")
	}
	if err := cs.CertificatesV1().CertificateSigningRequests().
		Delete(ctx, "csr-1", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.warned["csr-1"]; ok {
		t.Fatal("deleted CSR still pinned in the warn-once set")
	}
	// Recreated under the same name: warns (re-records) again.
	if _, err := cs.CertificatesV1().CertificateSigningRequests().
		Create(ctx, old, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.warned["csr-1"]; !ok {
		t.Fatal("recreated CSR not re-warned — stale prune kept the name")
	}
}

// Same prune for the IncError-once set: a deleted CSR releases its
// reported slot so a same-named replacement may report once more.
func TestCSRWatcherPrunesReportedForDeletedCSR(t *testing.T) {
	bad := csr("csr-evil", kubeletServingSigner,
		"system:serviceaccount:kube-system:privesc", time.Hour, false)
	cs := fake.NewSimpleClientset(bad)
	w := newCSRWatcher(cs, true)
	before := testutil.QueueErrorCount(t, csrWatcherQueue)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.reported["csr-evil"]; !ok {
		t.Fatal("validation failure not recorded in reported")
	}
	if err := cs.CertificatesV1().CertificateSigningRequests().
		Delete(ctx, "csr-evil", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.reported["csr-evil"]; ok {
		t.Fatal("deleted CSR still pinned in reported")
	}
	if _, err := cs.CertificatesV1().CertificateSigningRequests().
		Create(ctx, bad, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := testutil.QueueErrorCount(t, csrWatcherQueue) - before; got != 2 {
		t.Fatalf("recreated CSR did not re-report once, total delta %v", got)
	}
}

func TestCSRWatcherListError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "certificatesigningrequests",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	w := newCSRWatcher(cs, true)
	if err := w.run(ctx); err == nil {
		t.Fatal("expected error when CSR list fails")
	}
}

// An UpdateApproval failure IncErrors + continues: the run stays nil
// and the sibling CSR is still approved.
func TestCSRWatcherApprovalErrorContinues(t *testing.T) {
	cs := fake.NewSimpleClientset(
		csr("csr-bad", kubeletServingSigner, "system:node:n1", time.Hour, false),
		csr("csr-good", kubeletServingSigner, "system:node:n2", time.Hour, false),
		testutil.Node("n1", corev1.ConditionTrue, nil),
		testutil.Node("n2", corev1.ConditionTrue, nil))
	cs.PrependReactor("update", "certificatesigningrequests",
		func(a clienttesting.Action) (bool, runtime.Object, error) {
			ua, ok := a.(clienttesting.UpdateAction)
			if !ok || ua.GetSubresource() != "approval" {
				return false, nil, nil
			}
			if ua.GetObject().(*certificatesv1.CertificateSigningRequest).Name == "csr-bad" {
				return true, nil, errors.New("approval write rejected")
			}
			return false, nil, nil
		})
	w := newCSRWatcher(cs, true)
	before := testutil.QueueErrorCount(t, csrWatcherQueue)
	if err := w.run(ctx); err != nil {
		t.Fatalf("an approval write failure must not error the run: %v", err)
	}
	if ok, _ := csrApproved(t, cs, "csr-bad"); ok {
		t.Fatal("csr-bad approved despite the failing UpdateApproval")
	}
	if ok, _ := csrApproved(t, cs, "csr-good"); !ok {
		t.Fatal("csr-good skipped after the sibling approval failed")
	}
	if got := testutil.QueueErrorCount(t, csrWatcherQueue) - before; got < 1 {
		t.Fatalf("approval write failure did not IncError, delta %v", got)
	}
}
