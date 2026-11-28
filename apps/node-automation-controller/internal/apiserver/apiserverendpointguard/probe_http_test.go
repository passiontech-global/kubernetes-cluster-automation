// probe_http_test.go — coverage for the raw :6443 list calls the
// endpoint guard makes against each apiserver backend: a stub
// RoundTripper answers in-process, no bytes leave it.
package apiserverendpointguard

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
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/rest"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// fetchListRV — one raw :6443 list against a single apiserver backend.
// ---------------------------------------------------------------------------

func TestFetchListRV(t *testing.T) {
	t.Run("parses metadata.resourceVersion", func(t *testing.T) {
		var gotURL string
		rt := &testutil.StubTransport{Fn: func(r *http.Request) (*http.Response, error) {
			gotURL = r.URL.String()
			return testutil.ProbeResponse(200, testutil.ProbeRVJSON(12345)), nil
		}}
		rv, err := fetchListRV(ctx, &http.Client{Transport: rt}, "10.0.0.1",
			"/api/v1/nodes?limit=1&resourceVersion=0")
		if err != nil {
			t.Fatal(err)
		}
		if rv != 12345 {
			t.Fatalf("rv = %d, want 12345", rv)
		}
		// Backend IP + fixed apiserver port, no Service VIP — the
		// whole point is pinning ONE backend.
		want := "https://10.0.0.1:6443/api/v1/nodes?limit=1&resourceVersion=0"
		if gotURL != want {
			t.Fatalf("request URL = %q, want %q", gotURL, want)
		}
	})

	t.Run("non-2xx is a wedge signal", func(t *testing.T) {
		rt := &testutil.StubTransport{Fn: func(*http.Request) (*http.Response, error) {
			return testutil.ProbeResponse(http.StatusInternalServerError, "boom"), nil
		}}
		_, err := fetchListRV(ctx, &http.Client{Transport: rt}, "10.0.0.1", "/x")
		if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
			t.Fatalf("expected HTTP 500 error, got %v", err)
		}
	})

	t.Run("undecodable body", func(t *testing.T) {
		rt := &testutil.StubTransport{Fn: func(*http.Request) (*http.Response, error) {
			return testutil.ProbeResponse(200, "this is not json{"), nil
		}}
		if _, err := fetchListRV(ctx, &http.Client{Transport: rt}, "10.0.0.1", "/x"); err == nil {
			t.Fatal("expected JSON decode error")
		}
	})

	t.Run("rejects invalid UTF-8 strictly", func(t *testing.T) {
		for _, body := range []string{
			`{"kind":"PartialObjectMetadataList","note":"\uD800","metadata":{"resourceVersion":"123"}}`,
			`{"metadata":{"resourceVersion":"123"},"note":"` + "\xff" + `"}`,
		} {
			rt := &testutil.StubTransport{Fn: func(*http.Request) (*http.Response, error) {
				return testutil.ProbeResponse(200, body), nil
			}}
			if _, err := fetchListRV(ctx, &http.Client{Transport: rt}, "10.0.0.1", "/x"); err == nil {
				t.Fatalf("expected strict json/v2 error for invalid UTF-8 payload %q", body)
			}
		}
	})

	t.Run("rejects duplicate object keys strictly", func(t *testing.T) {
		rt := &testutil.StubTransport{Fn: func(*http.Request) (*http.Response, error) {
			return testutil.ProbeResponse(200, `{"metadata":{"resourceVersion":"1","resourceVersion":"2"}}`), nil
		}}
		if _, err := fetchListRV(ctx, &http.Client{Transport: rt}, "10.0.0.1", "/x"); err == nil {
			t.Fatal("expected strict json/v2 error for duplicate object keys")
		}
	})

	t.Run("rejects truncated JSON strictly", func(t *testing.T) {
		rt := &testutil.StubTransport{Fn: func(*http.Request) (*http.Response, error) {
			return testutil.ProbeResponse(200, `{"metadata":{"resourceVersion":"123"`), nil
		}}
		if _, err := fetchListRV(ctx, &http.Client{Transport: rt}, "10.0.0.1", "/x"); err == nil {
			t.Fatal("expected strict json/v2 error for truncated JSON")
		}
	})

	t.Run("non-numeric resourceVersion", func(t *testing.T) {
		rt := &testutil.StubTransport{Fn: func(*http.Request) (*http.Response, error) {
			return testutil.ProbeResponse(200, `{"metadata":{"resourceVersion":"abc"}}`), nil
		}}
		if _, err := fetchListRV(ctx, &http.Client{Transport: rt}, "10.0.0.1", "/x"); err == nil {
			t.Fatal("expected resourceVersion parse error")
		}
	})

	t.Run("transport error propagates", func(t *testing.T) {
		rt := &testutil.StubTransport{Fn: func(*http.Request) (*http.Response, error) {
			return nil, errors.New("connection refused")
		}}
		_, err := fetchListRV(ctx, &http.Client{Transport: rt}, "10.0.0.1", "/x")
		if err == nil || !strings.Contains(err.Error(), "connection refused") {
			t.Fatalf("transport error not surfaced: %v", err)
		}
	})

	t.Run("unparseable backend IP fails request build", func(t *testing.T) {
		rt := &testutil.StubTransport{Fn: func(*http.Request) (*http.Response, error) {
			return testutil.ProbeResponse(200, testutil.ProbeRVJSON(1)), nil
		}}
		// A space survives net.JoinHostPort but is rejected by
		// http.NewRequest — the error must surface, not panic.
		if _, err := fetchListRV(ctx, &http.Client{Transport: rt}, "bad ip", "/x"); err == nil {
			t.Fatal("expected URL construction error for a bad backend IP")
		}
	})

	t.Run("asks for PartialObjectMetadataList", func(t *testing.T) {
		var accept string
		rt := &testutil.StubTransport{Fn: func(r *http.Request) (*http.Response, error) {
			accept = r.Header.Get("Accept")
			return testutil.ProbeResponse(200, testutil.ProbeRVJSON(42)), nil
		}}
		rv, err := fetchListRV(ctx, &http.Client{Transport: rt}, "10.0.0.1", "/x")
		if err != nil {
			t.Fatal(err)
		}
		if rv != 42 {
			t.Fatalf("rv = %d, want 42", rv)
		}
		// The metadata-only envelope carries the same list-level
		// resourceVersion — the decoder stays identical while the
		// apiserver skips serializing full objects.
		for _, part := range []string{"as=PartialObjectMetadataList", "g=meta.k8s.io"} {
			if !strings.Contains(accept, part) {
				t.Fatalf("Accept = %q, must contain %q", accept, part)
			}
		}
	})

	t.Run("body fully drained before close", func(t *testing.T) {
		// An undrained body kills keep-alive on the shared transport
		// — the drain must run on success AND on non-2xx paths.
		for _, status := range []int{200, 500} {
			payload := testutil.ProbeRVJSON(777)
			body := &testutil.TrackingBody{R: strings.NewReader(payload)}
			rt := &testutil.StubTransport{Fn: func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: status, Body: body, Header: http.Header{},
				}, nil
			}}
			_, _ = fetchListRV(ctx, &http.Client{Transport: rt}, "10.0.0.1", "/x")
			if !body.Closed {
				t.Fatalf("status %d: response body never closed", status)
			}
			if body.N != len(payload) {
				t.Fatalf("status %d: read %d of %d body bytes — drain missing",
					status, body.N, len(payload))
			}
		}
	})
}

// ---------------------------------------------------------------------------
// apiServerEndpointGuard.probe / transport / Start.
// ---------------------------------------------------------------------------

func TestEndpointGuardProbeHTTP(t *testing.T) {
	g := &apiServerEndpointGuard{rt: testutil.ProbeRVSplit(4800, 5000)}
	res := g.probe(ctx, "10.0.0.1")
	if res.err != nil {
		t.Fatalf("probe: %v", res.err)
	}
	if res.liveRV != 5000 || res.cacheRV != 4800 {
		t.Fatalf("live=%d cache=%d, want 5000/4800", res.liveRV, res.cacheRV)
	}
}

func TestEndpointGuardProbeFailures(t *testing.T) {
	// Live list fails -> error tagged "live rv".
	g := &apiServerEndpointGuard{rt: &testutil.StubTransport{Fn: func(*http.Request) (*http.Response, error) {
		return nil, errors.New("backend down")
	}}}
	if res := g.probe(ctx, "10.0.0.1"); res.err == nil ||
		!strings.Contains(res.err.Error(), "live rv") {
		t.Fatalf("expected live-rv failure, got %+v", res)
	}

	// Live ok, cache list fails -> error tagged "cache rv".
	g = &apiServerEndpointGuard{rt: &testutil.StubTransport{Fn: func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("resourceVersion") == "0" {
			return nil, errors.New("cache wedged")
		}
		return testutil.ProbeResponse(200, testutil.ProbeRVJSON(5000)), nil
	}}}
	if res := g.probe(ctx, "10.0.0.1"); res.err == nil ||
		!strings.Contains(res.err.Error(), "cache rv") {
		t.Fatalf("expected cache-rv failure, got %+v", res)
	}
}

func TestEndpointGuardTransport(t *testing.T) {
	rt := &testutil.StubTransport{Fn: func(*http.Request) (*http.Response, error) {
		return testutil.ProbeResponse(200, "{}"), nil
	}}
	g := &apiServerEndpointGuard{rt: rt}
	got, err := g.transport()
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	if got != rt {
		t.Fatal("cached RoundTripper not returned")
	}

	// No in-cluster env: InClusterConfig must error — the guard then
	// fails closed (every backend "wedged", last-healthy check blocks
	// all edits) rather than crashing at Setup.
	g = &apiServerEndpointGuard{}
	if _, err := g.transport(); err == nil {
		t.Fatal("expected InClusterConfig error outside a cluster")
	}
}

// probeClient wraps the (possibly test-injected) RoundTripper with the
// probe timeout exactly once — the shared client is what makes the
// drained-body keep-alive policy effective across backends.
func TestEndpointGuardProbeClient(t *testing.T) {
	rt := &testutil.StubTransport{Fn: func(*http.Request) (*http.Response, error) {
		return testutil.ProbeResponse(200, testutil.ProbeRVJSON(1)), nil
	}}
	g := &apiServerEndpointGuard{rt: rt}
	c, err := g.probeClient()
	if err != nil {
		t.Fatalf("probeClient: %v", err)
	}
	if c.Transport != rt {
		t.Fatal("probe client does not wrap the injected transport")
	}
	if c.Timeout != endpointGuardProbeTO {
		t.Fatalf("probe client timeout = %s, want %s", c.Timeout, endpointGuardProbeTO)
	}
	c2, err := g.probeClient()
	if err != nil || c2 != c {
		t.Fatal("probeClient did not return the cached client")
	}

	// No transport and no in-cluster env -> error, and g.client stays
	// nil so a later probe retries instead of caching a broken client.
	g = &apiServerEndpointGuard{}
	if _, err := g.probeClient(); err == nil {
		t.Fatal("expected InClusterConfig error outside a cluster")
	}
	if g.client != nil {
		t.Fatal("failed probeClient cached a client")
	}
}

// A cancelled context must exit before the first 30s tick — the test
// would hang for the full interval if ctx.Done() lost the select.
func TestEndpointGuardStartCancelled(t *testing.T) {
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	g := &apiServerEndpointGuard{}
	done := make(chan error, 1)
	go func() { done <- g.Start(cctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return on a cancelled context")
	}
}

// ---------------------------------------------------------------------------
// fetchJWKSKIDs — /openid/v1/jwks key-id census per backend.
// ---------------------------------------------------------------------------

// Identical kid sets compare equal as strings — the census sorts and
// space-joins so sa.pub/sa.key rotation skew reads as a diff. Empty
// kid entries are dropped (a JWKS row without a kid signs nothing).
func TestFetchJWKSKIDs(t *testing.T) {
	t.Run("sorted join, empty kids dropped", func(t *testing.T) {
		var gotURL string
		rt := &testutil.StubTransport{Fn: func(r *http.Request) (*http.Response, error) {
			gotURL = r.URL.String()
			return testutil.ProbeResponse(200,
				`{"keys":[{"kid":"b-2"},{"kid":""},{"kid":"a-1"}]}`), nil
		}}
		got, err := fetchJWKSKIDs(ctx, &http.Client{Transport: rt}, "10.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		if got != "a-1 b-2" {
			t.Fatalf("kids = %q, want %q", got, "a-1 b-2")
		}
		if want := "https://10.0.0.1:6443/openid/v1/jwks"; gotURL != want {
			t.Fatalf("request URL = %q, want %q", gotURL, want)
		}
	})

	t.Run("non-2xx is a wedge signal", func(t *testing.T) {
		rt := &testutil.StubTransport{Fn: func(*http.Request) (*http.Response, error) {
			return testutil.ProbeResponse(http.StatusInternalServerError, "boom"), nil
		}}
		if _, err := fetchJWKSKIDs(ctx, &http.Client{Transport: rt}, "10.0.0.1"); err == nil {
			t.Fatal("expected HTTP error to propagate")
		}
	})

	t.Run("rejects invalid UTF-8 strictly", func(t *testing.T) {
		for _, body := range []string{
			`{"keys":[{"kid":"\uD800"}]}`,
			`{"keys":[{"kid":"` + "\xff" + `"}]}`,
		} {
			rt := &testutil.StubTransport{Fn: func(*http.Request) (*http.Response, error) {
				return testutil.ProbeResponse(200, body), nil
			}}
			if _, err := fetchJWKSKIDs(ctx, &http.Client{Transport: rt}, "10.0.0.1"); err == nil {
				t.Fatalf("expected strict json/v2 error for invalid UTF-8 JWKS %q", body)
			}
		}
	})

	t.Run("rejects duplicate keys and truncated JSON strictly", func(t *testing.T) {
		for _, body := range []string{
			`{"keys":[{"kid":"a","kid":"b"}]}`,
			`{"keys":[`,
		} {
			rt := &testutil.StubTransport{Fn: func(*http.Request) (*http.Response, error) {
				return testutil.ProbeResponse(200, body), nil
			}}
			if _, err := fetchJWKSKIDs(ctx, &http.Client{Transport: rt}, "10.0.0.1"); err == nil {
				t.Fatalf("expected strict json/v2 error for malformed JWKS %q", body)
			}
		}
	})
}

// transport reuses the cached in-cluster RoundTripper once built —
// the SA token + CA wiring happens exactly once per guard.
func TestTransportReturnsCachedRT(t *testing.T) {
	cached := &testutil.StubTransport{Fn: func(*http.Request) (*http.Response, error) {
		return testutil.ProbeResponse(200, "{}"), nil
	}}
	g := &apiServerEndpointGuard{rt: cached}
	rt, err := g.transport()
	if err != nil {
		t.Fatal(err)
	}
	if rt != cached {
		t.Fatal("transport() rebuilt the RoundTripper instead of returning the cached one")
	}
}

func TestEndpointGuardTransportTLS(t *testing.T) {
	newCA := func(cn string) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		return cert, key, caPEM
	}

	newLeaf := func(ca *x509.Certificate, caKey *ecdsa.PrivateKey, dnsNames []string, ips []net.IP) tls.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: "kube-apiserver"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:     dnsNames,
			IPAddresses:  ips,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return tlsCert
	}

	trustedCA, trustedKey, trustedCAPEM := newCA("trusted-cluster-ca")
	rogueCA, rogueKey, _ := newCA("rogue-mitm-ca")

	startTLS := func(cert tls.Certificate, gotAuth *string, hits *int) *httptest.Server {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*hits++
			*gotAuth = r.Header.Get("Authorization")
			_, _ = w.Write([]byte(testutil.ProbeRVJSON(99)))
		}))
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
		srv.StartTLS()
		t.Cleanup(srv.Close)
		return srv
	}

	t.Run("valid CA and kubernetes.default.svc SAN on raw IP dial", func(t *testing.T) {
		var gotAuth string
		var hits int
		// Serving cert has ONLY kubernetes.default.svc (no 127.0.0.1 IP SAN).
		cert := newLeaf(trustedCA, trustedKey, []string{"kubernetes.default.svc"}, nil)
		srv := startTLS(cert, &gotAuth, &hits)

		g := &apiServerEndpointGuard{
			inClusterConfigFn: func() (*rest.Config, error) {
				return &rest.Config{
					Host:        srv.URL,
					BearerToken: "sa-secret",
					// Pre-set Insecure=true to prove transport() forces Insecure=false.
					TLSClientConfig: rest.TLSClientConfig{
						Insecure: true,
						CAData:   trustedCAPEM,
					},
				}, nil
			},
		}
		rt, err := g.transport()
		if err != nil {
			t.Fatalf("transport: %v", err)
		}
		client := &http.Client{Transport: rt, Timeout: 5 * time.Second}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/apis/coordination.k8s.io/v1/leases?limit=1", nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("TLS request failed: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		if hits != 1 || gotAuth != "Bearer sa-secret" {
			t.Fatalf("hits=%d gotAuth=%q, want 1 and Bearer sa-secret", hits, gotAuth)
		}
	})

	t.Run("CAFile preserved from InClusterConfig", func(t *testing.T) {
		var gotAuth string
		var hits int
		cert := newLeaf(trustedCA, trustedKey, []string{"kubernetes.default.svc"}, nil)
		srv := startTLS(cert, &gotAuth, &hits)
		caPath := filepath.Join(t.TempDir(), "ca.crt")
		if err := os.WriteFile(caPath, trustedCAPEM, 0o600); err != nil {
			t.Fatal(err)
		}

		g := &apiServerEndpointGuard{
			inClusterConfigFn: func() (*rest.Config, error) {
				return &rest.Config{
					Host:        srv.URL,
					BearerToken: "sa-file-secret",
					TLSClientConfig: rest.TLSClientConfig{
						Insecure: true,
						CAFile:   caPath,
					},
				}, nil
			},
		}
		rt, err := g.transport()
		if err != nil {
			t.Fatalf("transport: %v", err)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		resp, err := (&http.Client{Transport: rt, Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			t.Fatalf("TLS request with CAFile failed: %v", err)
		}
		_ = resp.Body.Close()
		if hits != 1 || gotAuth != "Bearer sa-file-secret" {
			t.Fatalf("hits=%d gotAuth=%q, want 1 and Bearer sa-file-secret", hits, gotAuth)
		}
	})

	t.Run("untrusted CA rejected without sending Bearer token", func(t *testing.T) {
		var gotAuth string
		var hits int
		rogueCert := newLeaf(rogueCA, rogueKey, []string{"kubernetes.default.svc"}, []net.IP{net.ParseIP("127.0.0.1")})
		srv := startTLS(rogueCert, &gotAuth, &hits)

		g := &apiServerEndpointGuard{
			inClusterConfigFn: func() (*rest.Config, error) {
				return &rest.Config{
					Host:            srv.URL,
					BearerToken:     "sa-secret-never-leak",
					TLSClientConfig: rest.TLSClientConfig{CAData: trustedCAPEM},
				}, nil
			},
		}
		rt, err := g.transport()
		if err != nil {
			t.Fatalf("transport: %v", err)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		resp, err := (&http.Client{Transport: rt, Timeout: 5 * time.Second}).Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err == nil {
			t.Fatal("expected TLS verification error against untrusted CA")
		}
		if hits != 0 || gotAuth != "" {
			t.Fatalf("bearer token leaked to untrusted server: hits=%d auth=%q", hits, gotAuth)
		}
	})

	t.Run("wrong SAN rejected even under trusted CA", func(t *testing.T) {
		var gotAuth string
		var hits int
		wrongSANCert := newLeaf(trustedCA, trustedKey, []string{"evil.example.com"}, []net.IP{net.ParseIP("127.0.0.1")})
		srv := startTLS(wrongSANCert, &gotAuth, &hits)

		g := &apiServerEndpointGuard{
			inClusterConfigFn: func() (*rest.Config, error) {
				return &rest.Config{
					Host:            srv.URL,
					BearerToken:     "sa-secret-never-leak",
					TLSClientConfig: rest.TLSClientConfig{CAData: trustedCAPEM},
				}, nil
			},
		}
		rt, err := g.transport()
		if err != nil {
			t.Fatalf("transport: %v", err)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		resp, err := (&http.Client{Transport: rt, Timeout: 5 * time.Second}).Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err == nil {
			t.Fatal("expected TLS SAN verification error when kubernetes.default.svc missing")
		}
		if hits != 0 || gotAuth != "" {
			t.Fatalf("bearer token leaked on wrong SAN: hits=%d auth=%q", hits, gotAuth)
		}
	})

	t.Run("nil config fails closed", func(t *testing.T) {
		if _, err := probeTransportFromConfig(nil); err == nil {
			t.Fatal("expected error for nil config")
		}
	})
}

func TestFetchJSONBounds(t *testing.T) {
	t.Run("200 oversized JSON object rejected within byte bound", func(t *testing.T) {
		oversized := `{"metadata":{"resourceVersion":"1"},"pad":"` +
			strings.Repeat("a", endpointGuardMaxBodyBytes+128<<10) + `"}`
		body := &testutil.TrackingBody{R: strings.NewReader(oversized)}
		rt := &testutil.StubTransport{Fn: func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: body, Header: http.Header{}}, nil
		}}
		if _, err := fetchListRV(ctx, &http.Client{Transport: rt}, "10.0.0.1", "/x"); err == nil {
			t.Fatal("expected oversized response body error")
		}
		if !body.Closed {
			t.Fatal("oversized response body never closed")
		}
		maxRead := endpointGuardMaxBodyBytes + 1 + endpointGuardMaxDrainBytes
		if body.N > maxRead {
			t.Fatalf("read %d bytes > bound %d", body.N, maxRead)
		}
	})

	t.Run("200 valid JSON with oversized trailing data rejected", func(t *testing.T) {
		prefix := testutil.ProbeRVJSON(42)
		payload := prefix + strings.Repeat(" ", endpointGuardMaxBodyBytes+128<<10)
		body := &testutil.TrackingBody{R: strings.NewReader(payload)}
		rt := &testutil.StubTransport{Fn: func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: body, Header: http.Header{}}, nil
		}}
		if _, err := fetchListRV(ctx, &http.Client{Transport: rt}, "10.0.0.1", "/x"); err == nil {
			t.Fatal("expected oversized trailing-data error")
		}
		if !body.Closed {
			t.Fatal("response body never closed")
		}
		maxRead := endpointGuardMaxBodyBytes + 1 + endpointGuardMaxDrainBytes
		if body.N > maxRead {
			t.Fatalf("read %d bytes > bound %d", body.N, maxRead)
		}
	})

	t.Run("200 exact 4 MiB body accepted", func(t *testing.T) {
		prefix := testutil.ProbeRVJSON(42)
		payload := prefix + strings.Repeat(" ", endpointGuardMaxBodyBytes-len(prefix))
		body := &testutil.TrackingBody{R: strings.NewReader(payload)}
		rt := &testutil.StubTransport{Fn: func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: body, Header: http.Header{}}, nil
		}}
		rv, err := fetchListRV(ctx, &http.Client{Transport: rt}, "10.0.0.1", "/x")
		if err != nil {
			t.Fatalf("exact 4 MiB body rejected: %v", err)
		}
		if rv != 42 {
			t.Fatalf("rv = %d, want 42", rv)
		}
		if !body.Closed {
			t.Fatal("response body never closed")
		}
	})

	t.Run("non-200 drain capped at 64 KiB", func(t *testing.T) {
		payload := strings.Repeat("x", 1<<20) // 1 MiB error body
		body := &testutil.TrackingBody{R: strings.NewReader(payload)}
		rt := &testutil.StubTransport{Fn: func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusInternalServerError, Body: body, Header: http.Header{}}, nil
		}}
		_, err := fetchListRV(ctx, &http.Client{Transport: rt}, "10.0.0.1", "/x")
		if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
			t.Fatalf("expected HTTP 500 error, got %v", err)
		}
		if !body.Closed {
			t.Fatal("response body never closed")
		}
		if body.N != endpointGuardMaxDrainBytes {
			t.Fatalf("drained %d bytes on 500 response, want %d", body.N, endpointGuardMaxDrainBytes)
		}
	})
}
