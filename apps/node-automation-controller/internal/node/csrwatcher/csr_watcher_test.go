package csrwatcher

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
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

// csrPEM mints a real, signature-valid PEM x509 CSR — the
// kubelet-serving validation parses spec.request, so test fixtures
// cannot fake it with placeholder bytes.
func csrPEM(t *testing.T, cn string, org, dnsNames, ips []string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn, Organization: org},
		DNSNames: dnsNames,
	}
	for _, s := range ips {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(s))
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// servingCSR builds a kubelet-serving CSR that passes every
// validNodeCSR check for the named node: correct username, the
// system:nodes group, the serving usage triple, and a PEM x509 CSR
// whose CN/O/SANs match. Tests mutate individual fields to probe a
// specific rejection path.
func servingCSR(t *testing.T, name, nodeName string, age time.Duration,
	dnsNames, ips []string) *certificatesv1.CertificateSigningRequest {
	c := csr(name, kubeletServingSigner, nodeUserPrefix+nodeName, age, false)
	c.Spec.Groups = []string{nodesGroup, "system:authenticated"}
	c.Spec.Usages = []certificatesv1.KeyUsage{
		certificatesv1.UsageDigitalSignature,
		certificatesv1.UsageKeyEncipherment,
		certificatesv1.UsageServerAuth,
	}
	c.Spec.Request = csrPEM(t, nodeUserPrefix+nodeName,
		[]string{nodesGroup}, dnsNames, ips)
	return c
}

// addressedNode is testutil.Node plus status.addresses — the SAN ⊆
// addresses check needs real addresses to match (or reject) against.
func addressedNode(name string, addrs ...corev1.NodeAddress) *corev1.Node {
	n := testutil.Node(name, corev1.ConditionTrue, nil)
	n.Status.Addresses = addrs
	return n
}

func newCSRWatcher(cs *fake.Clientset, approve bool) *csrWatcher {
	return &csrWatcher{cs: cs, approve: approve, queue: "csr-watcher"}
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
	before := testutil.QueueErrorCount(t, "csr-watcher")
	for i := 0; i < 2; i++ { // warn-once set must not break the second run
		if err := w.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if ok, _ := csrApproved(t, cs, "csr-1"); ok {
		t.Fatal("detect mode approved a CSR")
	}
	if got := testutil.QueueErrorCount(t, "csr-watcher") - before; got != 0 {
		t.Fatalf("pending CSR in detect mode is not an error, delta %v", got)
	}
	if !w.warned.Has("csr-1") {
		t.Fatal("CSR not recorded in the warn-once set")
	}
}

// Approve mode happy path: a fully conformant kubelet-serving CSR —
// correct username + groups + usages, PEM CSR naming the node, SANs
// drawn from the node's own status.addresses.
func TestCSRWatcherApprovesValid(t *testing.T) {
	old := servingCSR(t, "csr-1", "n1", time.Hour,
		[]string{"n1.internal", "n1.example.com"}, []string{"10.0.0.1"})
	cs := fake.NewSimpleClientset(old,
		addressedNode("n1",
			corev1.NodeAddress{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
			corev1.NodeAddress{Type: corev1.NodeExternalIP, Address: "192.0.2.1"},
			corev1.NodeAddress{Type: corev1.NodeInternalDNS, Address: "n1.internal"},
			corev1.NodeAddress{Type: corev1.NodeHostName, Address: "n1.example.com"}))
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
	// In-tree approver parity: the Approved condition must stamp
	// LastTransitionTime, not just LastUpdateTime.
	got, err := cs.CertificatesV1().CertificateSigningRequests().
		Get(ctx, "csr-1", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range got.Status.Conditions {
		if c.Type == certificatesv1.CertificateApproved &&
			c.LastTransitionTime.IsZero() {
			t.Fatal("approved condition missing LastTransitionTime")
		}
	}
}

// A CSR with zero SANs is also acceptable — ⊆ holds vacuously (the
// kubelet's real CSRs always carry SANs, but nothing in the binding
// requires them).
func TestCSRWatcherApprovesSANlessCSR(t *testing.T) {
	old := servingCSR(t, "csr-1", "n1", time.Hour, nil, nil)
	cs := fake.NewSimpleClientset(old,
		testutil.Node("n1", corev1.ConditionTrue, nil))
	w := newCSRWatcher(cs, true)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if ok, _ := csrApproved(t, cs, "csr-1"); !ok {
		t.Fatal("SAN-less kubelet-serving CSR not approved")
	}
}

// Every kubelet-serving validation wall rejects — and every rejection
// skips the CSR (fail closed) while IncError'ing exactly once.
func TestCSRWatcherValidationRejections(t *testing.T) {
	node := func() *corev1.Node {
		return addressedNode("n1",
			corev1.NodeAddress{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
			corev1.NodeAddress{Type: corev1.NodeInternalDNS, Address: "n1.internal"})
	}

	t.Run("client-auth usage is rejected", func(t *testing.T) {
		c := servingCSR(t, "csr-client", "n1", time.Hour, nil, nil)
		c.Spec.Usages = append(c.Spec.Usages, certificatesv1.UsageClientAuth)
		cs := fake.NewSimpleClientset(c, node())
		w := newCSRWatcher(cs, true)
		if err := w.run(ctx); err != nil {
			t.Fatal(err)
		}
		if ok, _ := csrApproved(t, cs, "csr-client"); ok {
			t.Fatal("CSR with client-auth usage was approved")
		}
	})

	t.Run("strict-subset usages are rejected", func(t *testing.T) {
		// The in-tree approver requires the EXACT serving triple —
		// a CSR asking for only server auth is malformed, not
		// "allowed usages only".
		c := servingCSR(t, "csr-subset", "n1", time.Hour, nil, nil)
		c.Spec.Usages = []certificatesv1.KeyUsage{
			certificatesv1.UsageServerAuth}
		cs := fake.NewSimpleClientset(c, node())
		w := newCSRWatcher(cs, true)
		if err := w.run(ctx); err != nil {
			t.Fatal(err)
		}
		if ok, _ := csrApproved(t, cs, "csr-subset"); ok {
			t.Fatal("CSR with a strict-subset usage list was approved")
		}
	})

	t.Run("empty usages are rejected", func(t *testing.T) {
		c := servingCSR(t, "csr-nousage", "n1", time.Hour, nil, nil)
		c.Spec.Usages = nil
		cs := fake.NewSimpleClientset(c, node())
		w := newCSRWatcher(cs, true)
		if err := w.run(ctx); err != nil {
			t.Fatal(err)
		}
		if ok, _ := csrApproved(t, cs, "csr-nousage"); ok {
			t.Fatal("CSR with an empty usage list was approved")
		}
	})

	t.Run("requester outside system:nodes is rejected", func(t *testing.T) {
		c := servingCSR(t, "csr-groups", "n1", time.Hour, nil, nil)
		c.Spec.Groups = []string{"system:authenticated"}
		cs := fake.NewSimpleClientset(c, node())
		w := newCSRWatcher(cs, true)
		if err := w.run(ctx); err != nil {
			t.Fatal(err)
		}
		if ok, _ := csrApproved(t, cs, "csr-groups"); ok {
			t.Fatal("CSR from a non-system:nodes requester was approved")
		}
	})

	t.Run("CN mismatch is rejected", func(t *testing.T) {
		c := servingCSR(t, "csr-cn", "n1", time.Hour, nil, nil)
		// Username says n1, the CSR asks for a DIFFERENT node —
		// classic serving-cert impersonation.
		c.Spec.Request = csrPEM(t, nodeUserPrefix+"n2",
			[]string{nodesGroup}, nil, nil)
		cs := fake.NewSimpleClientset(c, node())
		w := newCSRWatcher(cs, true)
		if err := w.run(ctx); err != nil {
			t.Fatal(err)
		}
		if ok, _ := csrApproved(t, cs, "csr-cn"); ok {
			t.Fatal("CSR asking for another node's identity was approved")
		}
	})

	t.Run("missing O=system:nodes is rejected", func(t *testing.T) {
		c := servingCSR(t, "csr-org", "n1", time.Hour, nil, nil)
		c.Spec.Request = csrPEM(t, nodeUserPrefix+"n1", nil, nil, nil)
		cs := fake.NewSimpleClientset(c, node())
		w := newCSRWatcher(cs, true)
		if err := w.run(ctx); err != nil {
			t.Fatal(err)
		}
		if ok, _ := csrApproved(t, cs, "csr-org"); ok {
			t.Fatal("CSR without O=system:nodes was approved")
		}
	})

	t.Run("foreign DNS SAN is rejected", func(t *testing.T) {
		c := servingCSR(t, "csr-dns", "n1", time.Hour,
			[]string{"n1.internal", "other.internal"}, nil)
		cs := fake.NewSimpleClientset(c, node())
		w := newCSRWatcher(cs, true)
		if err := w.run(ctx); err != nil {
			t.Fatal(err)
		}
		if ok, _ := csrApproved(t, cs, "csr-dns"); ok {
			t.Fatal("CSR with a foreign DNS SAN was approved")
		}
	})

	t.Run("foreign IP SAN is rejected", func(t *testing.T) {
		c := servingCSR(t, "csr-ip", "n1", time.Hour,
			nil, []string{"10.0.0.1", "10.0.0.99"})
		cs := fake.NewSimpleClientset(c, node())
		w := newCSRWatcher(cs, true)
		if err := w.run(ctx); err != nil {
			t.Fatal(err)
		}
		if ok, _ := csrApproved(t, cs, "csr-ip"); ok {
			t.Fatal("CSR with a foreign IP SAN was approved")
		}
	})

	t.Run("unparseable request fails closed", func(t *testing.T) {
		c := servingCSR(t, "csr-pem", "n1", time.Hour, nil, nil)
		c.Spec.Request = []byte("not a pem block")
		cs := fake.NewSimpleClientset(c, node())
		w := newCSRWatcher(cs, true)
		if err := w.run(ctx); err != nil {
			t.Fatal(err)
		}
		if ok, _ := csrApproved(t, cs, "csr-pem"); ok {
			t.Fatal("CSR with a non-PEM request was approved")
		}
	})
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
	before := testutil.QueueErrorCount(t, "csr-watcher")
	for i := 0; i < 2; i++ {
		if err := w.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if ok, _ := csrApproved(t, cs, "csr-evil"); ok {
		t.Fatal("CSR with non-node username was approved")
	}
	if got := testutil.QueueErrorCount(t, "csr-watcher") - before; got != 1 {
		t.Fatalf("expected exactly 1 IncError for bad username, delta %v", got)
	}
}

// Node named in the username does not exist -> validation fails.
func TestCSRWatcherNodeMissing(t *testing.T) {
	cs := fake.NewSimpleClientset(
		servingCSR(t, "csr-ghost", "ghost", time.Hour, nil, nil))
	w := newCSRWatcher(cs, true)
	before := testutil.QueueErrorCount(t, "csr-watcher")
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if ok, _ := csrApproved(t, cs, "csr-ghost"); ok {
		t.Fatal("CSR approved for a nonexistent node")
	}
	if got := testutil.QueueErrorCount(t, "csr-watcher") - before; got != 1 {
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
			servingCSR(t, "csr-"+name, name, time.Hour, nil, nil),
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
	if !w.warned.Has("csr-1") {
		t.Fatal("pending CSR not recorded in the warn-once set")
	}
	if err := cs.CertificatesV1().CertificateSigningRequests().
		Delete(ctx, "csr-1", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if w.warned.Has("csr-1") {
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
	if !w.warned.Has("csr-1") {
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
	before := testutil.QueueErrorCount(t, "csr-watcher")
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !w.reported.Has("csr-evil") {
		t.Fatal("validation failure not recorded in reported")
	}
	if err := cs.CertificatesV1().CertificateSigningRequests().
		Delete(ctx, "csr-evil", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if w.reported.Has("csr-evil") {
		t.Fatal("deleted CSR still pinned in reported")
	}
	if _, err := cs.CertificatesV1().CertificateSigningRequests().
		Create(ctx, bad, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := testutil.QueueErrorCount(t, "csr-watcher") - before; got != 2 {
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
		servingCSR(t, "csr-bad", "n1", time.Hour, nil, nil),
		servingCSR(t, "csr-good", "n2", time.Hour, nil, nil),
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
	before := testutil.QueueErrorCount(t, "csr-watcher")
	if err := w.run(ctx); err != nil {
		t.Fatalf("an approval write failure must not error the run: %v", err)
	}
	if ok, _ := csrApproved(t, cs, "csr-bad"); ok {
		t.Fatal("csr-bad approved despite the failing UpdateApproval")
	}
	if ok, _ := csrApproved(t, cs, "csr-good"); !ok {
		t.Fatal("csr-good skipped after the sibling approval failed")
	}
	if got := testutil.QueueErrorCount(t, "csr-watcher") - before; got < 1 {
		t.Fatalf("approval write failure did not IncError, delta %v", got)
	}
}

// Package-wide test context shared by this package's _test files.
var ctx = context.Background()
