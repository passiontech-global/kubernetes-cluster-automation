package controllerhygiene

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

func mkCert(serial int64, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		NotAfter:     notAfter,
		Subject:      pkix.Name{CommonName: "x"},
	}
}

func TestCertNewerThan(t *testing.T) {
	old := mkCert(1, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	newer := mkCert(2, time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
	if !certNewerThan(newer, old) {
		t.Fatal("rotated-newer disk cert not flagged")
	}
	if certNewerThan(old, newer) {
		t.Fatal("older disk cert flagged as drift")
	}
	if certNewerThan(old, old) {
		t.Fatal("identical cert flagged as drift")
	}
	// Same window, different serial (re-issue keeping dates) → drift.
	same := mkCert(3, old.NotAfter)
	if !certNewerThan(same, old) {
		t.Fatal("re-issued cert (new serial, same window) not flagged")
	}
}

// --- W12-CP4a: sa.pub ServiceAccount signer-key fingerprint ---

func TestSAPubFingerprintTextfile(t *testing.T) {
	e := fixture(t)
	root := t.TempDir()
	k0s := filepath.Join(root, "k0s")
	e.h.cfg.K0sDir = k0s
	oldTD := textfileDirOverride
	textfileDirOverride = filepath.Join(root, "textfile")
	defer func() { textfileDirOverride = oldTD }()
	testutil.WriteFile(t, filepath.Join(k0s, "pki", "sa.pub"), "PUBKEY-BYTES")

	e.h.pkiDrift.Run(context.Background())
	data, err := os.ReadFile(filepath.Join(textfileDirOverride, saPubPromFile))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("PUBKEY-BYTES"))
	want := saPubMetric + `{sha256="` + hex.EncodeToString(sum[:]) + `"} 1`
	if !strings.Contains(string(data), want) {
		t.Fatalf("textfile missing %q:\n%s", want, data)
	}

	// A drifted sa.pub rewrites the series with the new hash.
	testutil.WriteFile(t, filepath.Join(k0s, "pki", "sa.pub"), "PUBKEY-BYTES-2")
	e.h.pkiDrift.Run(context.Background())
	data, err = os.ReadFile(filepath.Join(textfileDirOverride, saPubPromFile))
	if err != nil {
		t.Fatal(err)
	}
	sum2 := sha256.Sum256([]byte("PUBKEY-BYTES-2"))
	want2 := saPubMetric + `{sha256="` + hex.EncodeToString(sum2[:]) + `"} 1`
	if !strings.Contains(string(data), want2) {
		t.Fatalf("drifted fingerprint not exported:\n%s", data)
	}
}

// A missing sa.pub emits headers-only — the series goes absent,
// never a fabricated hash.
func TestSAPubFingerprintMissingFile(t *testing.T) {
	e := fixture(t)
	root := t.TempDir()
	e.h.cfg.K0sDir = filepath.Join(root, "k0s") // no sa.pub
	oldTD := textfileDirOverride
	textfileDirOverride = filepath.Join(root, "textfile")
	defer func() { textfileDirOverride = oldTD }()

	e.h.pkiDrift.Run(context.Background())
	data, err := os.ReadFile(filepath.Join(textfileDirOverride, saPubPromFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "# TYPE "+saPubMetric) {
		t.Fatalf("header missing:\n%s", data)
	}
	for _, l := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(l, saPubMetric+"{") ||
			strings.HasPrefix(l, saPubMetric+" ") {
			t.Fatalf("fake sample emitted for a missing sa.pub:\n%s", data)
		}
	}
}
