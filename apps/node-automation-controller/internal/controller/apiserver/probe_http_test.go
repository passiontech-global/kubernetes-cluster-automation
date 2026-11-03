// probe_http_test.go — coverage for the raw :6443 list calls the
// endpoint guard makes against each apiserver backend: a stub
// RoundTripper answers in-process, no bytes leave it.
package apiserver

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/controller/testutil"
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
