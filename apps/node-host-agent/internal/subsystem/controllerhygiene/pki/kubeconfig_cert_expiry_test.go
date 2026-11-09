package pki_test

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdepstest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/pki"

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
	for _, line := range strings.Split(string(data), "\n") {
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
	oldTD := cdeps.TextfileDirOverride
	cdeps.TextfileDirOverride = filepath.Join(root, "textfile")
	defer func() { cdeps.TextfileDirOverride = oldTD }()

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
	v, ok := textfileSample(t, cdeps.TextfileDirOverride,
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
	v, ok = textfileSample(t, cdeps.TextfileDirOverride,
		"node-agent-kubeconfig-cert.prom", pki.CertDaysMetric)
	if !ok || v <= 59.9 || v > 60.0 {
		t.Fatalf("min-days=%v ok=%v want ~60", v, ok)
	}
}

func TestKubeconfigCertExpiryNoCerts(t *testing.T) {
	e := fixture(t)
	root := t.TempDir()
	e.H.Cfg.K0sDir = filepath.Join(root, "k0s") // no kubeconfigs at all
	oldTD := cdeps.TextfileDirOverride
	cdeps.TextfileDirOverride = filepath.Join(root, "textfile")
	defer func() { cdeps.TextfileDirOverride = oldTD }()

	cdepstest.Check[*pki.KubeCertCheck](e.H, cdeps.CheckKubeCert).Run(context.Background()) // no panic
	if e.HasState(cdeps.StateKubeCertExpiring) {
		t.Fatal("latch on a host with no kubeconfigs")
	}
	prom, err := os.ReadFile(filepath.Join(
		cdeps.TextfileDirOverride, "node-agent-kubeconfig-cert.prom"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(prom),
		"\nnode_agent_kubeconfig_cert_min_days_remaining ") {
		t.Fatalf("no-cert host emitted a days sample:\n%s", prom)
	}
}
