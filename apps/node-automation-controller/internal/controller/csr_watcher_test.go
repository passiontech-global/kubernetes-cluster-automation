package controller

import (
	"errors"
	"fmt"
	"testing"
	"time"

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
	before := queueErrorCount(t, csrWatcherQueue)
	for i := 0; i < 2; i++ { // warn-once set must not break the second run
		if err := w.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if ok, _ := csrApproved(t, cs, "csr-1"); ok {
		t.Fatal("detect mode approved a CSR")
	}
	if got := queueErrorCount(t, csrWatcherQueue) - before; got != 0 {
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
		node("n1", corev1.ConditionTrue, nil))
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
		node("n1", corev1.ConditionTrue, nil))
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
	before := queueErrorCount(t, csrWatcherQueue)
	for i := 0; i < 2; i++ {
		if err := w.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if ok, _ := csrApproved(t, cs, "csr-evil"); ok {
		t.Fatal("CSR with non-node username was approved")
	}
	if got := queueErrorCount(t, csrWatcherQueue) - before; got != 1 {
		t.Fatalf("expected exactly 1 IncError for bad username, delta %v", got)
	}
}

// Node named in the username does not exist -> validation fails.
func TestCSRWatcherNodeMissing(t *testing.T) {
	cs := fake.NewSimpleClientset(
		csr("csr-ghost", kubeletServingSigner, "system:node:ghost", time.Hour, false))
	w := newCSRWatcher(cs, true)
	before := queueErrorCount(t, csrWatcherQueue)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if ok, _ := csrApproved(t, cs, "csr-ghost"); ok {
		t.Fatal("CSR approved for a nonexistent node")
	}
	if got := queueErrorCount(t, csrWatcherQueue) - before; got != 1 {
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
			node(name, corev1.ConditionTrue, nil))
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
