// seams_cert_rotation_test.go — the etcd /metrics mTLS client must reload
// the apiserver-etcd-client pair through GetClientCertificate on every
// handshake: a cert pinned at client construction breaks every scrape
// permanently after a k0s rotation.
package cdeps

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeEtcdClientCertPair(t *testing.T, k0sDir string, serial int64) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "apiserver-etcd-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pki := filepath.Join(k0sDir, "pki")
	if err := os.MkdirAll(filepath.Join(pki, "etcd"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(path string, block *pem.Block) {
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(pki, "apiserver-etcd-client.crt"), &pem.Block{Type: "CERTIFICATE", Bytes: der})
	write(filepath.Join(pki, "apiserver-etcd-client.key"), &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	write(filepath.Join(pki, "etcd", "ca.crt"), &pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestEtcdMetricsClientReloadsRotatedCert(t *testing.T) {
	dir := t.TempDir()
	writeEtcdClientCertPair(t, dir, 1001)

	client := etcdMetricsClient(dir)
	if client == nil {
		t.Fatal("expected mTLS client for a readable cert triple")
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil ||
		transport.TLSClientConfig.GetClientCertificate == nil {
		t.Fatal("etcd metrics client must source its cert via GetClientCertificate")
	}
	getSerial := func() *big.Int {
		t.Helper()
		cert, err := transport.TLSClientConfig.GetClientCertificate(&tls.CertificateRequestInfo{})
		if err != nil {
			t.Fatal(err)
		}
		if len(cert.Certificate) == 0 {
			t.Fatal("no leaf certificate presented")
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		return leaf.SerialNumber
	}
	if got := getSerial(); got.Cmp(big.NewInt(1001)) != 0 {
		t.Fatalf("initial client serial=%s, want 1001", got)
	}

	// Rotate the on-disk pair. The SAME client must present the new cert on
	// its next handshake — no restart, no permanently broken scrape.
	writeEtcdClientCertPair(t, dir, 2002)
	if got := getSerial(); got.Cmp(big.NewInt(2002)) != 0 {
		t.Fatalf("client serial after rotation=%s, want 2002 (stale cert pinned)", got)
	}
}

// TestLazyEtcdMetricsClientRetriesUntilPKIReady: at boot the PKI
// triple may not exist yet. The lazy resolver must keep retrying on
// later scrapes (rather than pinning the insecure fallback in
// applyDefaults), then cache the one client so each scrape does not
// churn a new pooled transport. The Plan-v8 per-handshake cert reload
// must still work on that cached client.
func TestLazyEtcdMetricsClientRetriesUntilPKIReady(t *testing.T) {
	dir := t.TempDir()
	get := lazyEtcdMetricsClient(dir)
	if c := get(); c != nil {
		t.Fatal("mTLS client built before the PKI triple exists — want insecure fallback")
	}

	// k0scontroller finishes writing the certs after agent startup.
	writeEtcdClientCertPair(t, dir, 3003)
	c := get()
	if c == nil {
		t.Fatal("lazy client did not retry — stuck on the insecure fallback after PKI appeared")
	}
	if again := get(); again != c {
		t.Fatal("client rebuilt on every scrape — the lazy resolver must cache the first success")
	}

	transport, ok := c.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig.GetClientCertificate == nil {
		t.Fatal("cached client lost the per-handshake cert reload")
	}
	writeEtcdClientCertPair(t, dir, 4004)
	cert, err := transport.TLSClientConfig.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if got := leaf.SerialNumber; got.Cmp(big.NewInt(4004)) != 0 {
		t.Fatalf("rotated serial=%s, want 4004", got)
	}
}

func TestEtcdMetricsClientInsecureFallbackWithoutCerts(t *testing.T) {
	if c := etcdMetricsClient(""); c != nil {
		t.Fatal("empty k0sDir must fall back to the insecure probe")
	}
	if c := etcdMetricsClient(t.TempDir()); c != nil {
		t.Fatal("missing cert triple must fall back to the insecure probe")
	}
}
