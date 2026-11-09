// collect_pki_test.go — PKI cert days-left series.

package hostmetrics

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// --- collector tests: 2.4 PKI certs, A1 inotify, A2 zombie/cgroup, B4 MTU ---

// mkTestCertPEM generates a throwaway self-signed cert expiring at
// notAfter — enough for the pki-cert-days-left parse path.
func mkTestCertPEM(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl,
		&key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestPKICertDaysLeft(t *testing.T) {
	cfg, _ := fixture(t)
	pkiDir := cfg.PKICertPaths[0]
	if err := os.MkdirAll(pkiDir, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(pkiDir, "ca.crt"),
		string(mkTestCertPEM(t, time.Now().Add(40*24*time.Hour))))
	testutil.WriteFile(t, filepath.Join(pkiDir, "notacert.key"), "PRIVATE KEY")
	c := New(cfg)
	got, ok := metricValue(t, c, "node_host_agent_pki_cert_days_left",
		map[string]string{"node": "node-a",
			"path": filepath.Join(pkiDir, "ca.crt")})
	if !ok {
		t.Fatal("pki_cert_days_left{ca.crt} absent")
	}
	if got < 39 || got > 41 {
		t.Fatalf("days_left=%v want ~40", got)
	}
	if _, ok := metricValue(t, c, "node_host_agent_pki_cert_days_left",
		map[string]string{"node": "node-a",
			"path": filepath.Join(pkiDir, "notacert.key")}); ok {
		t.Fatal("non-cert file must not emit a series")
	}
}

func TestPKICertDaysLeftStandaloneFile(t *testing.T) {
	cfg, _ := fixture(t)
	f := filepath.Join(t.TempDir(), "kubelet-client-current.pem")
	testutil.WriteFile(t, f, string(mkTestCertPEM(t, time.Now().Add(10*24*time.Hour))))
	cfg.PKICertPaths = []string{f}
	c := New(cfg)
	got, ok := metricValue(t, c, "node_host_agent_pki_cert_days_left",
		map[string]string{"node": "node-a", "path": f})
	if !ok || got < 9 || got > 11 {
		t.Fatalf("single-file PKI source: days=%v ok=%v want ~10", got, ok)
	}
}

// TestPKICertPathLabelLeadingSlash pins the {path} label shape:
// HostRoot="/" (standalone) must emit the SAME series a pod with
// HostRoot="/host" does — TrimPrefix would otherwise strip the
// leading slash and split the series by run mode.
func TestPKICertPathLabelLeadingSlash(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.HostRoot = "/"
	pkiDir := t.TempDir()
	testutil.WriteFile(t, filepath.Join(pkiDir, "ca.crt"),
		string(mkTestCertPEM(t, time.Now().Add(40*24*time.Hour))))
	cfg.PKICertPaths = []string{pkiDir}
	c := New(cfg)
	want := filepath.Join(pkiDir, "ca.crt") // absolute, leading slash kept
	if _, ok := metricValue(t, c, "node_host_agent_pki_cert_days_left",
		map[string]string{"node": "node-a", "path": want}); !ok {
		t.Fatalf("series with path=%s absent — leading slash must be kept", want)
	}
}

// TestPKICertDaysLeftExpiredFloors: an expired cert's negative
// days-left must floor (−1.9d → −2), not truncate toward zero.
func TestPKICertDaysLeftExpiredFloors(t *testing.T) {
	cfg, _ := fixture(t)
	pkiDir := cfg.PKICertPaths[0]
	if err := os.MkdirAll(pkiDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// ~45h past expiry → −1.875d.
	testutil.WriteFile(t, filepath.Join(pkiDir, "expired.crt"),
		string(mkTestCertPEM(t, time.Now().Add(-45*time.Hour))))
	c := New(cfg)
	got, ok := metricValue(t, c, "node_host_agent_pki_cert_days_left",
		map[string]string{"node": "node-a",
			"path": filepath.Join(pkiDir, "expired.crt")})
	if !ok || got != -2 {
		t.Fatalf("days_left=%v ok=%v want -2 (floor, not truncation)", got, ok)
	}
}

// --- sa-pub-key-fingerprint: sa.pub ServiceAccount signer-key fingerprint ---

// saPubHashOf returns the expected {sha256} label value for a file
// content — mirrors sha256FileHex so the label assertion is exact.
func saPubHashOf(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// metricFamilyAbsent gathers the collector once and reports whether
// the named family produced no series at all.
func metricFamilyAbsent(t *testing.T, c *Collector, name string) bool {
	t.Helper()
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() == name && len(mf.Metric) > 0 {
			return false
		}
	}
	return true
}

func TestSAPubFingerprintEmitsOnController(t *testing.T) {
	cfg, _ := fixture(t)
	testutil.WriteFile(t, cfg.K0sUnitFile, "[Unit]\n")
	saPub := filepath.Join(cfg.HostRoot, "var/lib/k0s/pki/sa.pub")
	testutil.WriteFile(t, saPub, "PUBKEY-BYTES-1")
	c := New(cfg)
	got, ok := metricValue(t, c, "node_k0s_sa_pub_fingerprint_hash",
		map[string]string{"node": "node-a",
			"sha256": saPubHashOf("PUBKEY-BYTES-1")})
	if !ok || got != 1 {
		t.Fatalf("fingerprint=%v ok=%v want 1", got, ok)
	}
	// A drifted file must change the fingerprint label — the whole
	// point of the series (cross-CP count_by(sha256)).
	testutil.WriteFile(t, saPub, "PUBKEY-BYTES-2")
	if _, ok := metricValue(t, c, "node_k0s_sa_pub_fingerprint_hash",
		map[string]string{"node": "node-a",
			"sha256": saPubHashOf("PUBKEY-BYTES-2")}); !ok {
		t.Fatal("drifted sa.pub fingerprint not exported")
	}
}

func TestSAPubFingerprintAbsentOnWorker(t *testing.T) {
	cfg, _ := fixture(t)
	// No k0scontroller unit file → worker → no series even though
	// the file exists on disk.
	testutil.WriteFile(t,
		filepath.Join(cfg.HostRoot, "var/lib/k0s/pki/sa.pub"), "PUBKEY-BYTES")
	c := New(cfg)
	if !metricFamilyAbsent(t, c, "node_k0s_sa_pub_fingerprint_hash") {
		t.Fatal("fingerprint emitted on a non-controller node")
	}
}

func TestSAPubFingerprintAbsentWhenFileMissing(t *testing.T) {
	cfg, _ := fixture(t)
	testutil.WriteFile(t, cfg.K0sUnitFile, "[Unit]\n")
	// Controller, but sa.pub is absent → no series, never a fake hash.
	c := New(cfg)
	if !metricFamilyAbsent(t, c, "node_k0s_sa_pub_fingerprint_hash") {
		t.Fatal("fingerprint emitted for a missing sa.pub")
	}
}
