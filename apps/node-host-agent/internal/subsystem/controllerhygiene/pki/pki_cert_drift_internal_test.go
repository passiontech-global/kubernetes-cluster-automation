package pki

// readLeafCert is unexported and the bundle-selection fix is
// cert-structure plumbing — drive it directly in an internal test
// (the *_internal_test.go convention).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// mkRealCertPEM mints one self-signed (CA when requested) PEM block.
func mkRealCertPEM(t *testing.T, isCA bool, serial int64) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "test"},
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl,
		&key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestReadLeafCertPrefersNonCA(t *testing.T) {
	ca := mkRealCertPEM(t, true, 1)
	leaf := mkRealCertPEM(t, false, 2)

	// Bundle with the leaf AFTER the chain — the old first-block parse
	// would return the CA.
	p := filepath.Join(t.TempDir(), "bundle.pem")
	if err := os.WriteFile(p, append(append(append([]byte{},
		ca...), ca...), leaf...), 0o600); err != nil {
		t.Fatal(err)
	}
	crt, err := readLeafCert(p)
	if err != nil {
		t.Fatal(err)
	}
	if crt.IsCA {
		t.Fatal("bundle parse returned a CA cert, not the leaf")
	}
	if crt.SerialNumber.Int64() != 2 {
		t.Fatalf("serial=%v want the leaf (2)", crt.SerialNumber)
	}

	// Leaf first still selects the leaf.
	p2 := filepath.Join(t.TempDir(), "leaf-first.pem")
	if err := os.WriteFile(p2, append(append([]byte{}, leaf...), ca...),
		0o600); err != nil {
		t.Fatal(err)
	}
	crt2, err := readLeafCert(p2)
	if err != nil {
		t.Fatal(err)
	}
	if crt2.IsCA || crt2.SerialNumber.Int64() != 2 {
		t.Fatalf("leaf-first parse = serial %v IsCA %v", crt2.SerialNumber, crt2.IsCA)
	}

	// CA-only file falls back to the first block.
	p3 := filepath.Join(t.TempDir(), "ca-only.pem")
	if err := os.WriteFile(p3, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	crt3, err := readLeafCert(p3)
	if err != nil {
		t.Fatal(err)
	}
	if !crt3.IsCA {
		t.Fatal("CA-only file lost its cert")
	}

	// No cert at all still errors.
	p4 := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(p4, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readLeafCert(p4); err == nil {
		t.Fatal("non-PEM file must error")
	}
}
