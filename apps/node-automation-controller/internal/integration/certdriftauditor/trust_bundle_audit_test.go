// trust_bundle_audit_test.go — coverage for the W19-NM2
// issuer↔trust-roots chain verification: verifyLinkerdIssuerChain
// unit cases plus the auditTrustAnchorSkew gauge wiring.
package certdriftauditor

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
)

// chainCA issues a self-signed CA — returns key, parsed cert and PEM.
func chainCA(t *testing.T, cn string, ski []byte) (*ecdsa.PrivateKey,
	*x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		SubjectKeyId:          ski,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl,
		&key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	return key, cert, pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// chainIssue signs an issuer (non-CA) cert under parent — aki
// overrides the AuthorityKeyId (nil lets CreateCertificate inherit
// the parent's SubjectKeyId, the honest chain shape).
func chainIssue(t *testing.T, parent *x509.Certificate,
	parentKey *ecdsa.PrivateKey, cn string, aki []byte) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(time.Now().UnixNano()),
		Subject:        pkix.Name{CommonName: cn},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		AuthorityKeyId: aki,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent,
		&key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("create issuer cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestVerifyLinkerdIssuerChain(t *testing.T) {
	rootKey, rootCert, rootPEM := chainCA(t, "trust-root", []byte{1, 2, 3, 4})
	goodIssuer := chainIssue(t, rootCert, rootKey, "issuer", nil)
	otherKey, otherCert, otherRootPEM := chainCA(t, "other-root", []byte{5, 6, 7, 8})
	unrelatedIssuer := chainIssue(t, otherCert, otherKey, "unrelated-issuer", nil)

	for _, tc := range []struct {
		name    string
		roots   []byte
		issuer  []byte
		skew    bool
		checked bool
	}{
		{"honest chain", rootPEM, goodIssuer, false, true},
		{"issuer signed by a different root", rootPEM, unrelatedIssuer, true, true},
		{"bundle root instead of issuer cert", rootPEM, otherRootPEM, true, true},
		{"unparseable roots", []byte("not pem"), goodIssuer, false, false},
		{"unparseable issuer", rootPEM, []byte("not pem"), false, false},
		{"empty issuer", rootPEM, nil, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			skew, checked := verifyLinkerdIssuerChain(tc.roots, tc.issuer)
			if skew != tc.skew || checked != tc.checked {
				t.Fatalf("verifyLinkerdIssuerChain = (%v,%v), want (%v,%v)",
					skew, checked, tc.skew, tc.checked)
			}
		})
	}
}

// The audit lands the skew verdict on the gauge: a properly chained
// issuer reads 0, an issuer signed by an unrelated root reads 1,
// and a missing issuer secret reads 0 (no pair, no skew).
func TestCertDriftAuditorTrustAnchorSkew(t *testing.T) {
	defer metrics.LinkerdTrustAnchorSkew.Set(0)
	rootKey, rootCert, rootPEM := chainCA(t, "trust-root", []byte{1, 2, 3, 4})
	goodIssuer := chainIssue(t, rootCert, rootKey, "issuer", nil)

	trustRootsCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "linkerd", Name: "linkerd-identity-trust-roots"},
		Data: map[string]string{"ca-bundle.crt": string(rootPEM)},
	}
	issuerSecret := func(crt []byte) *corev1.Secret {
		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "linkerd", Name: "linkerd-identity-issuer"},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{"crt.pem": crt},
		}
	}

	// Honest chain → 0.
	cs := fake.NewSimpleClientset(trustRootsCM, issuerSecret(goodIssuer))
	a := newCertDriftAuditor(cs, cdaDyn(), time.Now())
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := promtestutil.ToFloat64(metrics.LinkerdTrustAnchorSkew); got != 0 {
		t.Fatalf("skew gauge = %v, want 0 on a valid chain", got)
	}

	// Issuer signed by an unrelated root → 1.
	otherKey, otherCert, _ := chainCA(t, "other-root", []byte{5, 6, 7, 8})
	unrelated := chainIssue(t, otherCert, otherKey, "unrelated", nil)
	cs = fake.NewSimpleClientset(trustRootsCM, issuerSecret(unrelated))
	a = newCertDriftAuditor(cs, cdaDyn(), time.Now())
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := promtestutil.ToFloat64(metrics.LinkerdTrustAnchorSkew); got != 1 {
		t.Fatalf("skew gauge = %v, want 1 on a broken chain", got)
	}

	// No issuer secret at all → 0 (the pair cannot skew).
	cs = fake.NewSimpleClientset(trustRootsCM)
	a = newCertDriftAuditor(cs, cdaDyn(), time.Now())
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := promtestutil.ToFloat64(metrics.LinkerdTrustAnchorSkew); got != 0 {
		t.Fatalf("skew gauge = %v, want 0 with no issuer", got)
	}
}
