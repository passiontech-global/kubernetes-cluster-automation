package pki_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdepstest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/pki"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// textfileSample reads <dir>/<file> and returns the value of the
// `metric value` sample line (HELP/TYPE lines never match — they
// start with '#').
func textfileSample(t *testing.T, dir, file, metric string) (float64, bool) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, file))
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if !strings.HasPrefix(line, metric+" ") {
			continue
		}
		v, err := strconv.ParseFloat(
			strings.TrimSpace(strings.TrimPrefix(line, metric)), 64)
		if err != nil {
			t.Fatalf("unparseable sample %q: %v", line, err)
		}
		return v, true
	}
	return 0, false
}

// --- kubeconfig-cert-expiry: checkKubeconfigCertExpiry ---

// testClientCertPEM mints a self-signed ECDSA cert PEM with the
// given NotAfter — fast enough for tests (P256, no RSA).
func testClientCertPEM(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl,
		&key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// kubeconfigWithCert renders a minimal valid kubeconfig embedding
// the cert PEM as client-certificate-data.
func kubeconfigWithCert(t *testing.T, certPEM []byte) string {
	t.Helper()
	return "apiVersion: v1\nkind: Config\n" +
		"clusters:\n- name: c\n  cluster:\n" +
		"    server: https://127.0.0.1:6443\n" +
		"    insecure-skip-tls-verify: true\n" +
		"users:\n- name: u\n  user:\n" +
		"    client-certificate-data: " +
		base64.StdEncoding.EncodeToString(certPEM) + "\n"
}

func TestKubeconfigCertExpiry(t *testing.T) {
	e := fixture(t)
	root := t.TempDir()
	k0s := filepath.Join(root, "k0s")
	pkiDir := filepath.Join(k0s, "pki")
	if err := os.MkdirAll(pkiDir, 0o755); err != nil {
		t.Fatal(err)
	}
	e.H.Cfg.K0sDir = k0s
	e.H.Cfg.TextfileDir = filepath.Join(root, "textfile")

	// admin.conf cert expiring in 5 days → inside the 14d window.
	testutil.WriteFile(t, filepath.Join(pkiDir, "admin.conf"),
		kubeconfigWithCert(t, testClientCertPEM(t,
			e.Now.Add(5*24*time.Hour))))
	// scheduler.conf cert healthy at 60 days — min stays 5d.
	testutil.WriteFile(t, filepath.Join(pkiDir, "scheduler.conf"),
		kubeconfigWithCert(t, testClientCertPEM(t,
			e.Now.Add(60*24*time.Hour))))
	// Garbage file → skipped gracefully.
	testutil.WriteFile(t, filepath.Join(k0s, "kubelet.conf"), "not yaml: [")

	cdepstest.Check[*pki.KubeCertCheck](e.H, cdeps.CheckKubeCert).Run(context.Background())
	if !e.HasState(cdeps.StateKubeCertExpiring) {
		t.Fatal("kubeconfig-cert-expiring latch missing")
	}
	// x509 truncates NotAfter to seconds — allow sub-day slop.
	v, ok := textfileSample(t, e.H.Cfg.TextfileDir,
		"node-agent-kubeconfig-cert.prom", pki.CertDaysMetric)
	if !ok || v <= 4.9 || v > 5.0 {
		t.Fatalf("min-days=%v ok=%v want ~5", v, ok)
	}

	// Rotate to a healthy cert → latch clears, sample ~60d.
	testutil.WriteFile(t, filepath.Join(pkiDir, "admin.conf"),
		kubeconfigWithCert(t, testClientCertPEM(t,
			e.Now.Add(60*24*time.Hour))))
	cdepstest.Check[*pki.KubeCertCheck](e.H, cdeps.CheckKubeCert).Run(context.Background())
	if e.HasState(cdeps.StateKubeCertExpiring) {
		t.Fatal("latch still held on healthy certs")
	}
	v, ok = textfileSample(t, e.H.Cfg.TextfileDir,
		"node-agent-kubeconfig-cert.prom", pki.CertDaysMetric)
	if !ok || v <= 59.9 || v > 60.0 {
		t.Fatalf("min-days=%v ok=%v want ~60", v, ok)
	}
}

func TestKubeconfigCertExpiryNoCerts(t *testing.T) {
	e := fixture(t)
	root := t.TempDir()
	e.H.Cfg.K0sDir = filepath.Join(root, "k0s") // no kubeconfigs at all
	e.H.Cfg.TextfileDir = filepath.Join(root, "textfile")

	cdepstest.Check[*pki.KubeCertCheck](e.H, cdeps.CheckKubeCert).Run(context.Background()) // no panic
	if e.HasState(cdeps.StateKubeCertExpiring) {
		t.Fatal("latch on a host with no kubeconfigs")
	}
	prom, err := os.ReadFile(filepath.Join(
		e.H.Cfg.TextfileDir, "node-agent-kubeconfig-cert.prom"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(prom),
		"\nnode_agent_kubeconfig_cert_min_days_remaining ") {
		t.Fatalf("no-cert host emitted a days sample:\n%s", prom)
	}
}

// kubeconfigWithFileRef renders a minimal valid kubeconfig whose user
// carries a file-referenced client-certificate path (loadCreds
// parity — resolved relative to the kubeconfig dir).
func kubeconfigWithFileRef(ref string) string {
	return "apiVersion: v1\nkind: Config\n" +
		"clusters:\n- name: c\n  cluster:\n" +
		"    server: https://127.0.0.1:6443\n" +
		"    insecure-skip-tls-verify: true\n" +
		"users:\n- name: u\n  user:\n" +
		"    client-certificate: " + ref + "\n"
}

// kubeconfigWithPEMData renders a kubeconfig embedding arbitrary PEM
// bytes (not necessarily a single parseable cert) as
// client-certificate-data.
func kubeconfigWithPEMData(pemBytes []byte) string {
	return "apiVersion: v1\nkind: Config\n" +
		"clusters:\n- name: c\n  cluster:\n" +
		"    server: https://127.0.0.1:6443\n" +
		"    insecure-skip-tls-verify: true\n" +
		"users:\n- name: u\n  user:\n" +
		"    client-certificate-data: " +
		base64.StdEncoding.EncodeToString(pemBytes) + "\n"
}

// File-referenced client-certificate paths are read (relative to the
// kubeconfig dir), a missing reference skips just that user, and
// non-CERTIFICATE / unparseable PEM blocks are skipped while a valid
// block after them still counts.
func TestKubeconfigCertFileReference(t *testing.T) {
	e := fixture(t)
	root := t.TempDir()
	k0s := filepath.Join(root, "k0s")
	pkiDir := filepath.Join(k0s, "pki")
	e.H.Cfg.K0sDir = k0s
	e.H.Cfg.TextfileDir = filepath.Join(root, "textfile")

	// Phase 1: client.pem next to admin.conf — the referenced file's
	// NotAfter drives the metric (40d, outside the warn window).
	testutil.WriteFile(t, filepath.Join(pkiDir, "client.pem"),
		string(testClientCertPEM(t, e.Now.Add(40*24*time.Hour))))
	testutil.WriteFile(t, filepath.Join(pkiDir, "admin.conf"),
		kubeconfigWithFileRef("client.pem"))
	cdepstest.Check[*pki.KubeCertCheck](e.H, cdeps.CheckKubeCert).Run(context.Background())
	if e.HasState(cdeps.StateKubeCertExpiring) {
		t.Fatal("file-referenced cert inside the window was missed")
	}
	v, ok := textfileSample(t, e.H.Cfg.TextfileDir,
		"node-agent-kubeconfig-cert.prom", pki.CertDaysMetric)
	if !ok || v <= 39.9 || v > 40.0 {
		t.Fatalf("min-days=%v ok=%v want ~40 (referenced file unread)", v, ok)
	}

	// Phase 2: one user points at a missing file, a second user
	// embeds a healthy cert — the broken reference must skip only
	// itself, not fail the file (50d ⇒ only the embedded user counted).
	testutil.WriteFile(t, filepath.Join(pkiDir, "admin.conf"),
		"apiVersion: v1\nkind: Config\n"+
			"clusters:\n- name: c\n  cluster:\n"+
			"    server: https://127.0.0.1:6443\n"+
			"    insecure-skip-tls-verify: true\n"+
			"users:\n"+
			"- name: broken\n  user:\n"+
			"    client-certificate: gone.pem\n"+
			"- name: good\n  user:\n"+
			"    client-certificate-data: "+
			base64.StdEncoding.EncodeToString(
				testClientCertPEM(t, e.Now.Add(50*24*time.Hour)))+"\n")
	cdepstest.Check[*pki.KubeCertCheck](e.H, cdeps.CheckKubeCert).Run(context.Background())
	v, ok = textfileSample(t, e.H.Cfg.TextfileDir,
		"node-agent-kubeconfig-cert.prom", pki.CertDaysMetric)
	if !ok || v <= 49.9 || v > 50.0 {
		t.Fatalf("min-days=%v ok=%v want ~50 (missing ref not skipped)", v, ok)
	}

	// Phase 3: junk blocks (foreign PEM type, unparseable DER)
	// preceding the real certificate are skipped, the real one is
	// parsed — and at 9d inside the warn window it latches.
	junk := pem.EncodeToMemory(&pem.Block{
		Type: "PRIVATE KEY", Bytes: []byte("not a key")})
	junk = append(junk, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: []byte("not der")})...)
	junk = append(junk, testClientCertPEM(t, e.Now.Add(9*24*time.Hour))...)
	testutil.WriteFile(t, filepath.Join(pkiDir, "admin.conf"),
		kubeconfigWithPEMData(junk))
	cdepstest.Check[*pki.KubeCertCheck](e.H, cdeps.CheckKubeCert).Run(context.Background())
	if !e.HasState(cdeps.StateKubeCertExpiring) {
		t.Fatal("valid cert after junk blocks missed the warn window")
	}
	v, ok = textfileSample(t, e.H.Cfg.TextfileDir,
		"node-agent-kubeconfig-cert.prom", pki.CertDaysMetric)
	if !ok || v <= 8.9 || v > 9.0 {
		t.Fatalf("min-days=%v ok=%v want ~9 (junk blocks misparsed)", v, ok)
	}
}

// A kubeconfig whose users carry no client cert at all (token
// auth) contributes nothing — no sample, no latch, no_certs cycle.
func TestKubeconfigCertUserWithoutCert(t *testing.T) {
	e := fixture(t)
	root := t.TempDir()
	k0s := filepath.Join(root, "k0s")
	pkiDir := filepath.Join(k0s, "pki")
	e.H.Cfg.K0sDir = k0s
	e.H.Cfg.TextfileDir = filepath.Join(root, "textfile")

	testutil.WriteFile(t, filepath.Join(pkiDir, "scheduler.conf"),
		"apiVersion: v1\nkind: Config\n"+
			"clusters:\n- name: c\n  cluster:\n"+
			"    server: https://127.0.0.1:6443\n"+
			"    insecure-skip-tls-verify: true\n"+
			"users:\n- name: u\n  user:\n    token: secret-token\n")

	cdepstest.Check[*pki.KubeCertCheck](e.H, cdeps.CheckKubeCert).Run(context.Background())

	if e.HasState(cdeps.StateKubeCertExpiring) {
		t.Fatal("cert-less kubeconfig latched the expiry state")
	}
	prom, err := os.ReadFile(filepath.Join(
		e.H.Cfg.TextfileDir, "node-agent-kubeconfig-cert.prom"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(prom),
		"\nnode_agent_kubeconfig_cert_min_days_remaining ") {
		t.Fatalf("token-only user emitted a days sample:\n%s", prom)
	}
	if v := promtest.ToFloat64(e.H.Cycles.WithLabelValues(cdeps.CheckKubeCert, "no_certs")); v != 1 {
		t.Fatalf("no_certs counter=%v want 1", v)
	}
}
