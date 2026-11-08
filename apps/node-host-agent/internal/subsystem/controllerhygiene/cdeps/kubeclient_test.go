// kubeclient_test.go — the apiserver credential loading + rv LIST
// probe: kubeconfig-embedded vs flat-triple creds, the rotation
// fingerprint rebuild, the injected-client short-circuit, and the
// ?resourceVersion= LIST parse riding the scripted HTTPClient seam.
package cdeps

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
)

// genTestCert mints a throwaway self-signed cert/key/CA PEM triple.
func genTestCert(t *testing.T, cn string) (certPEM, keyPEM, caPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl,
		&key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	return certPEM, keyPEM, certPEM // self-signed → cert doubles as CA
}

func newKubeDeps(t *testing.T) *Deps {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "watchdog.log")
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	d := &Deps{
		Cfg: Config{
			AdminKubeconfig: filepath.Join(dir, "pki", "admin.conf"),
			AdminCert:       filepath.Join(dir, "pki", "admin.crt"),
			AdminKey:        filepath.Join(dir, "pki", "admin.key"),
			AdminCA:         filepath.Join(dir, "pki", "ca.crt"),
			InsecureTLS:     true,
			APIPath:         "/api/v1/namespaces/default/services",
			QueryTimeout:    5 * time.Second,
		},
		State: hoststate.New(stateDir, log, nil, nil),
	}
	return d
}

func writePEMs(t *testing.T, d *Deps, certPEM, keyPEM, caPEM []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(d.Cfg.AdminCert), 0o755); err != nil {
		t.Fatal(err)
	}
	for path, b := range map[string][]byte{
		d.Cfg.AdminCert: certPEM,
		d.Cfg.AdminKey:  keyPEM,
		d.Cfg.AdminCA:   caPEM,
	} {
		if b == nil {
			continue
		}
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestResolveRel(t *testing.T) {
	kc := "/etc/k0s/pki/admin.conf"
	cases := []struct{ ref, want string }{
		{"/abs/path.crt", "/abs/path.crt"},        // absolute: verbatim
		{"client.crt", "/etc/k0s/pki/client.crt"}, // relative: kubeconfig dir
		{"../ca/ca.crt", "/etc/k0s/ca/ca.crt"},    // .. resolves through Join
	}
	for _, c := range cases {
		if got := ResolveRel(kc, c.ref); got != c.want {
			t.Errorf("ResolveRel(%q)=%q want %q", c.ref, got, c.want)
		}
	}
}

func TestEnsureClientInjectedShortCircuit(t *testing.T) {
	d := newKubeDeps(t) // no credential files anywhere
	injected := &http.Client{}
	d.Cfg.HTTPClient = injected
	d.Client = injected
	if got := d.EnsureClient(); got != injected {
		t.Fatal("injected HTTPClient seam was rebuilt instead of passed through")
	}
}

func TestEnsureClientBuildsAndRebuildsOnRotation(t *testing.T) {
	d := newKubeDeps(t)
	certPEM, keyPEM, _ := genTestCert(t, "admin")
	writePEMs(t, d, certPEM, keyPEM, nil)

	c1 := d.EnsureClient()
	if c1 == nil {
		t.Fatal("client not built from a present cert triple")
	}
	if d.CredFP == "" {
		t.Fatal("credential fingerprint not stamped")
	}
	// Cached: same pointer while the fingerprint holds.
	if c2 := d.EnsureClient(); c2 != c1 {
		t.Fatal("client rebuilt without a credential change")
	}
	// Rotate: rewrite the key (new size → new fingerprint) → rebuild.
	if err := os.WriteFile(d.Cfg.AdminKey, append(keyPEM, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	c3 := d.EnsureClient()
	if c3 == nil || c3 == c1 {
		t.Fatal("client not rebuilt after credential rotation")
	}
}

func TestEnsureClientAbsentCreds(t *testing.T) {
	d := newKubeDeps(t)
	// The absent-host path returns nil quietly (a non-controller
	// host is idle, not broken — the load ERROR path warns instead).
	if c := d.EnsureClient(); c != nil {
		t.Fatalf("client built without credentials: %v", c)
	}
	if d.CredFP != "" {
		t.Fatalf("fingerprint stamped without credentials: %q", d.CredFP)
	}
}

func TestBuildClient(t *testing.T) {
	certPEM, keyPEM, caPEM := genTestCert(t, "admin")

	t.Run("bad key pair", func(t *testing.T) {
		d := newKubeDeps(t)
		writePEMs(t, d, certPEM, []byte("not a key\n"), nil)
		if _, err := d.buildClient(); err == nil ||
			!strings.Contains(err.Error(), "admin client cert") {
			t.Fatalf("err=%v want admin client cert error", err)
		}
	})
	t.Run("no creds", func(t *testing.T) {
		d := newKubeDeps(t)
		c, err := d.buildClient()
		if c != nil || err != nil {
			t.Fatalf("client=%v err=%v want nil,nil with no creds", c, err)
		}
	})
	t.Run("insecure with pair", func(t *testing.T) {
		d := newKubeDeps(t)
		d.Cfg.InsecureTLS = true
		writePEMs(t, d, certPEM, keyPEM, nil)
		c, err := d.buildClient()
		if err != nil || c == nil {
			t.Fatalf("client=%v err=%v", c, err)
		}
	})
	t.Run("pinned CA ok", func(t *testing.T) {
		d := newKubeDeps(t)
		d.Cfg.InsecureTLS = false
		writePEMs(t, d, certPEM, keyPEM, caPEM)
		c, err := d.buildClient()
		if err != nil || c == nil {
			t.Fatalf("client=%v err=%v", c, err)
		}
	})
	t.Run("garbage CA", func(t *testing.T) {
		d := newKubeDeps(t)
		d.Cfg.InsecureTLS = false
		writePEMs(t, d, certPEM, keyPEM, []byte("not pem\n"))
		if _, err := d.buildClient(); err == nil ||
			!strings.Contains(err.Error(), "no certificates in CA data") {
			t.Fatalf("err=%v want CA parse error", err)
		}
	})
}

func TestLoadCredsKubeconfigEmbedded(t *testing.T) {
	d := newKubeDeps(t)
	certPEM, keyPEM, caPEM := genTestCert(t, "admin")
	writeKubeconfig(t, d.Cfg.AdminKubeconfig,
		base64.StdEncoding.EncodeToString(certPEM),
		base64.StdEncoding.EncodeToString(keyPEM),
		base64.StdEncoding.EncodeToString(caPEM), "")

	cert, key, ca, err := d.loadCreds()
	if err != nil {
		t.Fatalf("loadCreds err=%v", err)
	}
	if !bytes.Equal(cert, certPEM) || !bytes.Equal(key, keyPEM) ||
		!bytes.Equal(ca, caPEM) {
		t.Fatal("embedded kubeconfig creds not returned verbatim")
	}
}

func TestLoadCredsKubeconfigFileRefs(t *testing.T) {
	d := newKubeDeps(t)
	certPEM, keyPEM, caPEM := genTestCert(t, "admin")
	if err := os.MkdirAll(filepath.Dir(d.Cfg.AdminKubeconfig), 0o755); err != nil {
		t.Fatal(err)
	}
	// Relative refs resolve against the kubeconfig dir.
	writeFileT(t, filepath.Join(filepath.Dir(d.Cfg.AdminKubeconfig), "client.crt"), certPEM)
	writeFileT(t, filepath.Join(filepath.Dir(d.Cfg.AdminKubeconfig), "client.key"), keyPEM)
	writeFileT(t, filepath.Join(filepath.Dir(d.Cfg.AdminKubeconfig), "ca.crt"), caPEM)
	writeKubeconfig(t, d.Cfg.AdminKubeconfig, "", "", "", "refs")

	cert, key, ca, err := d.loadCreds()
	if err != nil {
		t.Fatalf("loadCreds err=%v", err)
	}
	if !bytes.Equal(cert, certPEM) || !bytes.Equal(key, keyPEM) ||
		!bytes.Equal(ca, caPEM) {
		t.Fatal("file-ref kubeconfig creds not resolved relative to the kubeconfig dir")
	}
}

func TestLoadCredsKubeconfigUnreadableRefWarns(t *testing.T) {
	d := newKubeDeps(t)
	writeKubeconfig(t, d.Cfg.AdminKubeconfig, "", "", "", "refs")

	cert, key, _, err := d.loadCreds()
	if err != nil {
		t.Fatalf("loadCreds err=%v", err)
	}
	if cert != nil || key != nil {
		t.Fatal("unreadable refs produced creds")
	}
	log := readFile(t, d.State.LogFile)
	if !strings.Contains(log, "client-cert") ||
		!strings.Contains(log, "unreadable") {
		t.Fatalf("unreadable ref not warned:\n%s", log)
	}
}

func TestLoadCredsAbsent(t *testing.T) {
	d := newKubeDeps(t)
	cert, key, ca, err := d.loadCreds()
	if cert != nil || key != nil || ca != nil || err != nil {
		t.Fatalf("absent host: cert=%v key=%v ca=%v err=%v want all nil",
			cert, key, ca, err)
	}
}

func TestLoadCredsFlatTriple(t *testing.T) {
	d := newKubeDeps(t)
	certPEM, keyPEM, caPEM := genTestCert(t, "admin")
	writePEMs(t, d, certPEM, keyPEM, caPEM)

	cert, key, ca, err := d.loadCreds()
	if err != nil {
		t.Fatalf("loadCreds err=%v", err)
	}
	if !bytes.Equal(cert, certPEM) || !bytes.Equal(key, keyPEM) ||
		!bytes.Equal(ca, caPEM) {
		t.Fatal("flat cert/key/ca triple not read verbatim")
	}
}

func TestCredFingerprint(t *testing.T) {
	d := newKubeDeps(t)
	if fp := d.credFingerprint(); fp != "" {
		t.Fatalf("fingerprint without files=%q want empty", fp)
	}
	certPEM, keyPEM, _ := genTestCert(t, "admin")
	writePEMs(t, d, certPEM, keyPEM, nil)
	fp1 := d.credFingerprint()
	if fp1 == "" {
		t.Fatal("fingerprint empty with files present")
	}
	if fp2 := d.credFingerprint(); fp2 != fp1 {
		t.Fatal("fingerprint not stable across identical stats")
	}
	if err := os.WriteFile(d.Cfg.AdminCert, append(certPEM, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if fp3 := d.credFingerprint(); fp3 == fp1 {
		t.Fatal("fingerprint did not change after a file grew")
	}
}

// capRT is a scripted RoundTripper: one canned answer per case plus
// the request it saw.
type capRT struct {
	gotURL string
	code   int
	body   string
	err    error
}

func (rt *capRT) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.gotURL = req.URL.String()
	if rt.err != nil {
		return nil, rt.err
	}
	return &http.Response{
		Status:     fmt.Sprintf("%d", rt.code),
		StatusCode: rt.code,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(rt.body)),
		Request:    req,
	}, nil
}

// writeKubeconfig writes a minimal kubeconfig: embedded base64
// *-data fields when b64 args are set, file references (mode="refs")
// otherwise.
func writeKubeconfig(t *testing.T, path, certB64, keyB64, caB64, mode string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	var cert, key, ca string
	switch mode {
	case "refs":
		cert, key, ca = "client.crt", "client.key", "ca.crt"
	default:
		cert, key, ca = certB64, keyB64, caB64
	}
	var fields string
	if cert != "" {
		if mode == "refs" {
			fields += "    client-certificate: " + cert + "\n"
		} else {
			fields += "    client-certificate-data: " + cert + "\n"
		}
	}
	if key != "" {
		if mode == "refs" {
			fields += "    client-key: " + key + "\n"
		} else {
			fields += "    client-key-data: " + key + "\n"
		}
	}
	var clusterFields string
	if ca != "" {
		if mode == "refs" {
			clusterFields += "    certificate-authority: " + ca + "\n"
		} else {
			clusterFields += "    certificate-authority-data: " + ca + "\n"
		}
	}
	cfg := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- cluster:
%s    server: https://127.0.0.1:6443
  name: c
contexts:
- context:
    cluster: c
    user: admin
  name: ctx
current-context: ctx
users:
- user:
%s  name: admin
`, clusterFields, fields)
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeFileT(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// listRVCase drives one scripted probe and asserts the verdict.
func listRVCase(t *testing.T, rt *capRT, cached bool, wantRV int64, wantOK bool) {
	t.Helper()
	d := newKubeDeps(t)
	client := &http.Client{Transport: rt}
	d.Cfg.HTTPClient = client
	d.Client = client

	rv, ok := d.ListRV(context.Background(), "127.0.0.1:6443", cached)
	if rv != wantRV || ok != wantOK {
		t.Fatalf("ListRV(cached=%v)=(%d,%v) want (%d,%v) [url=%s]",
			cached, rv, ok, wantRV, wantOK, rt.gotURL)
	}
}

func TestListRVQueriesAndParses(t *testing.T) {
	rt := &capRT{code: http.StatusOK, body: `{"metadata":{"resourceVersion":"42"}}`}
	listRVCase(t, rt, true, 42, true)
	if q := rt.gotURL; !strings.Contains(q, "resourceVersion=0") ||
		!strings.HasPrefix(q, "https://127.0.0.1:6443"+"/api/v1/namespaces/default/services?") ||
		!strings.Contains(q, "limit=1") {
		t.Fatalf("cached probe URL=%q", q)
	}

	rt2 := &capRT{code: http.StatusOK, body: `{"metadata":{"resourceVersion":"43"}}`}
	listRVCase(t, rt2, false, 43, true)
	if strings.Contains(rt2.gotURL, "resourceVersion=0") {
		t.Fatalf("consistent probe used the watch-cache read: %q", rt2.gotURL)
	}
	if !strings.Contains(rt2.gotURL, "resourceVersion=&") {
		t.Fatalf("consistent probe missing empty resourceVersion: %q", rt2.gotURL)
	}
}

func TestListRVFailures(t *testing.T) {
	cases := map[string]*capRT{
		"transport error": {err: errors.New("connection refused")},
		"non-200":         {code: http.StatusForbidden, body: "{}"},
		"bad json":        {code: http.StatusOK, body: "not json"},
		"bad rv":          {code: http.StatusOK, body: `{"metadata":{"resourceVersion":"abc"}}`},
	}
	for name, rt := range cases {
		t.Run(name, func(t *testing.T) {
			listRVCase(t, rt, true, 0, false)
		})
	}
}

func TestListRVNoClient(t *testing.T) {
	d := newKubeDeps(t) // no creds, no injected client
	if rv, ok := d.ListRV(context.Background(), "127.0.0.1:6443", true); rv != 0 || ok {
		t.Fatalf("ListRV without a client=(%d,%v) want (0,false)", rv, ok)
	}
}
