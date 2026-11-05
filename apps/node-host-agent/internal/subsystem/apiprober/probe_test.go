// probe_test.go — apiserver probe path: TCP preflight, listRV
// responses/failure classes (failClass, classifyTransport), the
// body-drain read cap, and TLS-error classification.
package apiprober

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestTCPPreflightRealDial(t *testing.T) {
	// No TCPCheck seam → the real TCP dial runs.
	p, err := New(Config{HTTPClient: newAPIStub(t).srv.Client()},
		prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := p.tcpPreflight(context.Background(), addr); err != nil {
		t.Fatalf("tcpPreflight(%s) err=%v want nil", addr, err)
	}
	_ = ln.Close()
	// Nothing listens now — the dial must fail fast (conn refused).
	if err := p.tcpPreflight(context.Background(), addr); err == nil {
		t.Fatalf("tcpPreflight(%s) after close want error", addr)
	}
}

func TestListRV(t *testing.T) {
	var gotAuth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"metadata":{"resourceVersion":"42"}}`)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")

	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("tok-abc\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// HTTPClient==nil exercises the production path: TLS client built
	// from InsecureTLS + per-query bearer token read.
	p, err := New(Config{InsecureTLS: true, TokenFile: tokenFile},
		prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	rv, fc, ferr := p.listRV(context.Background(), addr, "/api/v1/nodes?limit=1")
	if fc != failNone || rv != 42 {
		t.Fatalf("listRV = %d, %v, %v want 42, failNone, nil", rv, fc, ferr)
	}
	if gotAuth != "Bearer tok-abc" {
		t.Fatalf("Authorization=%q want %q", gotAuth, "Bearer tok-abc")
	}

	// Unreadable token file → query fails closed as failToken
	// (probe-side). Cycle refreshes p.eff from cfg every round —
	// refresh here to pick the change up.
	p.cfg.TokenFile = filepath.Join(t.TempDir(), "absent")
	p.refreshGuard()
	if rv, fc, _ := p.listRV(context.Background(), addr, "/x"); fc != failToken || rv != 0 {
		t.Fatalf("listRV(bad token) = %d, %v want 0, failToken", rv, fc)
	}
}

func TestListRVFailureModes(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		wantFC failClass
	}{
		{"non-200", http.StatusServiceUnavailable, `{"metadata":{"resourceVersion":"1"}}`, failStatus},
		{"unauthorized", http.StatusUnauthorized, ``, failAuth},
		{"forbidden", http.StatusForbidden, ``, failAuth},
		{"not-json", http.StatusOK, `this is not json`, failParse},
		{"non-numeric-rv", http.StatusOK, `{"metadata":{"resourceVersion":"abc"}}`, failParse},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer srv.Close()
			// HTTPClient==nil exercises the production path — a
			// readable token file is required or the query fails at
			// failToken before the request is even sent.
			tokenFile := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(tokenFile, []byte("tok\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			p, err := New(Config{InsecureTLS: true, TokenFile: tokenFile},
				prometheus.NewRegistry())
			if err != nil {
				t.Fatal(err)
			}
			rv, fc, _ := p.listRV(context.Background(),
				strings.TrimPrefix(srv.URL, "https://"), "/x")
			if fc != tc.wantFC || rv != 0 {
				t.Fatalf("listRV = %d, %v want 0, %v", rv, fc, tc.wantFC)
			}
		})
	}
}

// rtFunc adapts a func to http.RoundTripper for transport error
// injection.
type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// errBody is a response body that fails on Read.
type errBody struct{}

func (errBody) Read([]byte) (int, error) { return 0, errors.New("body read boom") }
func (errBody) Close() error             { return nil }

func TestListRVTransportErrors(t *testing.T) {
	boom := errors.New("transport boom")

	t.Run("bad url", func(t *testing.T) {
		p, err := New(Config{
			HTTPClient: newAPIStub(t).srv.Client(),
		}, prometheus.NewRegistry())
		if err != nil {
			t.Fatal(err)
		}
		// A space in the host makes http.NewRequest fail before any
		// dial — covers the request-build error return.
		if rv, fc, _ := p.listRV(context.Background(), "bad addr", "/x"); fc != failRequest || rv != 0 {
			t.Fatalf("listRV(bad url) = %d, %v want 0, failRequest", rv, fc)
		}
	})

	t.Run("roundtrip error", func(t *testing.T) {
		p, err := New(Config{
			HTTPClient: &http.Client{Transport: rtFunc(
				func(*http.Request) (*http.Response, error) { return nil, boom })},
		}, prometheus.NewRegistry())
		if err != nil {
			t.Fatal(err)
		}
		if rv, fc, _ := p.listRV(context.Background(), "127.0.0.1:6443", "/x"); fc != failTransp || rv != 0 {
			t.Fatalf("listRV(transport err) = %d, %v want 0, failTransp", rv, fc)
		}
	})

	t.Run("body read error", func(t *testing.T) {
		p, err := New(Config{
			HTTPClient: &http.Client{Transport: rtFunc(
				func(*http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       errBody{},
					}, nil
				})},
		}, prometheus.NewRegistry())
		if err != nil {
			t.Fatal(err)
		}
		if rv, fc, _ := p.listRV(context.Background(), "127.0.0.1:6443", "/x"); fc != failBody || rv != 0 {
			t.Fatalf("listRV(body err) = %d, %v want 0, failBody", rv, fc)
		}
	})
}

func TestListRVParseAndTimeout(t *testing.T) {
	// Inject each server client so the token-file branch is skipped —
	// the failures under test happen after the response arrives.
	mkProber := func(t *testing.T, body string) (*Prober, string) {
		t.Helper()
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, body)
		}))
		t.Cleanup(srv.Close)
		p, err := New(Config{HTTPClient: srv.Client()}, prometheus.NewRegistry())
		if err != nil {
			t.Fatal(err)
		}
		return p, strings.TrimPrefix(srv.URL, "https://")
	}

	t.Run("unparseable json", func(t *testing.T) {
		p, addr := mkProber(t, `this is not json`)
		if rv, fc, _ := p.listRV(context.Background(), addr, "/x"); fc != failParse || rv != 0 {
			t.Fatalf("listRV(not json) = %d, %v want 0, failParse", rv, fc)
		}
	})

	t.Run("non numeric rv", func(t *testing.T) {
		p, addr := mkProber(t, `{"metadata":{"resourceVersion":"abc"}}`)
		if rv, fc, _ := p.listRV(context.Background(), addr, "/x"); fc != failParse || rv != 0 {
			t.Fatalf("listRV(non-numeric rv) = %d, %v want 0, failParse", rv, fc)
		}
	})

	t.Run("non-200 with injected client", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer srv.Close()
		p, err := New(Config{HTTPClient: srv.Client()}, prometheus.NewRegistry())
		if err != nil {
			t.Fatal(err)
		}
		if rv, fc, _ := p.listRV(context.Background(),
			strings.TrimPrefix(srv.URL, "https://"), "/x"); fc != failStatus || rv != 0 {
			t.Fatalf("listRV(503) = %d, %v want 0, failStatus", rv, fc)
		}
	})

	t.Run("query timeout", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-r.Context().Done() // hang until the client gives up
		}))
		defer srv.Close()
		p, err := New(Config{HTTPClient: srv.Client()}, prometheus.NewRegistry())
		if err != nil {
			t.Fatal(err)
		}
		p.cfg.QueryTimeout = 30 * time.Millisecond
		if rv, fc, _ := p.listRV(context.Background(),
			strings.TrimPrefix(srv.URL, "https://"), "/x"); fc != failTimeout || rv != 0 {
			t.Fatalf("listRV(timeout) = %d, %v want 0, failTimeout", rv, fc)
		}
	})
}

func TestListRVSendsPartialObjectMetadataAccept(t *testing.T) {
	var gotAccept string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		_, _ = io.WriteString(w, `{"metadata":{"resourceVersion":"42"}}`)
	}))
	defer srv.Close()
	p, err := New(Config{HTTPClient: srv.Client()}, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	rv, fc, _ := p.listRV(context.Background(),
		strings.TrimPrefix(srv.URL, "https://"), "/api/v1/nodes?limit=1")
	if fc != failNone || rv != 42 {
		t.Fatalf("listRV = %d, %v want 42, failNone", rv, fc)
	}
	const want = "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1"
	if gotAccept != want {
		t.Fatalf("Accept=%q want %q", gotAccept, want)
	}
}

// readTracker wraps a reader, recording total bytes consumed — proves
// listRV drains the response body to EOF past the 1 MiB decode cap so
// keep-alive can reuse the connection.
type readTracker struct {
	r     io.Reader
	total int64
}

func (t *readTracker) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	t.total += int64(n)
	return n, err
}

func (t *readTracker) Close() error { return nil }

func TestListRVDrainsBodyPastReadCap(t *testing.T) {
	// Valid JSON up front, then >1 MiB of trailing whitespace (legal
	// for json.Unmarshal): the capped read captures the document and
	// the drain must consume the rest to EOF.
	payload := `{"metadata":{"resourceVersion":"42"}}` +
		strings.Repeat(" ", 2<<20)
	body := &readTracker{r: strings.NewReader(payload)}
	p, err := New(Config{
		HTTPClient: &http.Client{Transport: rtFunc(
			func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode:    http.StatusOK,
					Header:        make(http.Header),
					Body:          body,
					ContentLength: int64(len(payload)),
				}, nil
			})},
	}, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	rv, fc, _ := p.listRV(context.Background(), "127.0.0.1:6443", "/x")
	if fc != failNone || rv != 42 {
		t.Fatalf("listRV = %d, %v want 42, failNone", rv, fc)
	}
	if body.total != int64(len(payload)) {
		t.Fatalf("body read %d/%d bytes — tail past the cap not drained",
			body.total, len(payload))
	}
}

// --- probe-side vs apiserver-side failure classification ---
// The DEAD verdict must only fire on apiserver-side evidence —
// credential/TLS/request-build faults are probe-side (failClass.
// probeSide) and make the cycle inconclusive, like TCP-unreachable.
// Field incident this guards: an api-lb-vm guard credential problem
// failed every query for ~12.5h and logged DEAD the whole time
// while HAProxy marked the backend UP and kubectl over the VIP
// worked — "API queries failing" alone could not tell a broken
// probe from a dead apiserver.

func TestFailClassProbeSide(t *testing.T) {
	for _, c := range []failClass{failToken, failAuth, failTLS, failRequest} {
		if !c.probeSide() {
			t.Fatalf("%v.probeSide() = false want true", c)
		}
	}
	for _, c := range []failClass{failNone, failTimeout, failRefused,
		failConn, failTransp, failStatus, failBody, failParse} {
		if c.probeSide() {
			t.Fatalf("%v.probeSide() = true want false", c)
		}
	}
}

func TestClassifyTransport(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want failClass
	}{
		{"context deadline", context.DeadlineExceeded, failTimeout},
		{"wrapped deadline",
			fmt.Errorf("Get: %w", context.DeadlineExceeded), failTimeout},
		{"net.Error timeout",
			&net.DNSError{IsTimeout: true, Name: "x"}, failTimeout},
		{"conn refused",
			fmt.Errorf("dial: %w", syscall.ECONNREFUSED), failRefused},
		{"op error refused", &net.OpError{Op: "dial",
			Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}},
			failRefused},
		{"conn reset", fmt.Errorf("read: %w", syscall.ECONNRESET), failConn},
		{"conn aborted", fmt.Errorf("read: %w", syscall.ECONNABORTED), failConn},
		{"eof mid-request", fmt.Errorf("read: %w", io.EOF), failConn},
		{"unknown authority", x509.UnknownAuthorityError{}, failTLS},
		{"hostname mismatch", x509.HostnameError{}, failTLS},
		{"cert verification", &tls.CertificateVerificationError{}, failTLS},
		{"cert invalid", x509.CertificateInvalidError{}, failTLS},
		{"tls string",
			errors.New("remote error: tls: bad certificate"), failTLS},
		{"x509 string",
			errors.New("x509: certificate has expired"), failTLS},
		{"generic transport", errors.New("boom"), failTransp},
	}
	for _, tc := range cases {
		if got := classifyTransport(tc.err); got != tc.want {
			t.Fatalf("classifyTransport(%s) = %v want %v", tc.name, got, tc.want)
		}
	}
}

// wrongCAPEM renders a self-signed CA cert that does NOT sign the
// httptest servers' certificates — a valid bundle that produces a
// real x509 unknown-authority failure when used as CAFile.
func wrongCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "wrong-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl,
		&key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestListRVTLSErrorClass(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("tok\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("x509 unknown authority", func(t *testing.T) {
		// Verify-TLS against a CA that did not sign the apiserver's
		// cert → failTLS (probe-side) — the cert-mismatch case.
		srv := httptest.NewTLSServer(http.HandlerFunc(
			func(w http.ResponseWriter, _ *http.Request) {}))
		defer srv.Close()
		caFile := filepath.Join(t.TempDir(), "ca.crt")
		if err := os.WriteFile(caFile, wrongCAPEM(t), 0o644); err != nil {
			t.Fatal(err)
		}
		p, err := New(Config{
			InsecureTLS: false, CAFile: caFile, TokenFile: tokenFile,
		}, prometheus.NewRegistry())
		if err != nil {
			t.Fatal(err)
		}
		rv, fc, _ := p.listRV(context.Background(),
			strings.TrimPrefix(srv.URL, "https://"), "/x")
		if fc != failTLS || rv != 0 {
			t.Fatalf("listRV(wrong CA) = %d, %v want 0, failTLS", rv, fc)
		}
	})

	t.Run("endpoint not TLS", func(t *testing.T) {
		// A plain-HTTP endpoint under the HTTPS probe → the
		// transport's protocol-mismatch error → failTLS.
		srv := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, _ *http.Request) {}))
		defer srv.Close()
		p, err := New(Config{InsecureTLS: true, TokenFile: tokenFile},
			prometheus.NewRegistry())
		if err != nil {
			t.Fatal(err)
		}
		rv, fc, _ := p.listRV(context.Background(),
			strings.TrimPrefix(srv.URL, "http://"), "/x")
		if fc != failTLS || rv != 0 {
			t.Fatalf("listRV(plain http) = %d, %v want 0, failTLS", rv, fc)
		}
	})
}
