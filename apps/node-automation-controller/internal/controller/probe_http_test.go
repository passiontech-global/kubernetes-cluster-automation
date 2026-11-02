// probe_http_test.go — coverage for the HTTP/REST-backed probes that
// the fake clientset cannot serve:
//   - fetchListRV / apiServerEndpointGuard.probe: raw :6443 list calls
//     against a stub RoundTripper (no bytes leave the process).
//   - kubeletReaper.probe / deadNodeSweeper.probe: node/proxy/healthz
//     through a REAL clientset pointed at httptest — the fake
//     clientset's CoreV1().RESTClient() is nil.
//   - coreDNSWatchdog.panics/logHit/dnsProbe/probeFQDN: :9153/metrics
//     scrape via injected http.Client, pod logs via reactor, and the
//     negative paths for UDP :53 / Service listing.
package controller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	ktesting "k8s.io/client-go/testing"
)

// stubTransport answers HTTP requests in-process: probes build real
// *http.Request objects (URL assertions included) but nothing dials.
type stubTransport struct {
	fn func(*http.Request) (*http.Response, error)
}

func (s *stubTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return s.fn(r)
}

// probeResponse is the minimal *http.Response the probe code reads.
func probeResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{},
	}
}

// probeRVJSON is the list-envelope shape fetchListRV decodes.
func probeRVJSON(rv int64) string {
	return fmt.Sprintf(
		`{"apiVersion":"v1","kind":"List","metadata":{"resourceVersion":"%d"},"items":[]}`, rv)
}

// ---------------------------------------------------------------------------
// fetchListRV — one raw :6443 list against a single apiserver backend.
// ---------------------------------------------------------------------------

func TestFetchListRV(t *testing.T) {
	t.Run("parses metadata.resourceVersion", func(t *testing.T) {
		var gotURL string
		rt := &stubTransport{fn: func(r *http.Request) (*http.Response, error) {
			gotURL = r.URL.String()
			return probeResponse(200, probeRVJSON(12345)), nil
		}}
		rv, err := fetchListRV(ctx, rt, "10.0.0.1",
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
		rt := &stubTransport{fn: func(*http.Request) (*http.Response, error) {
			return probeResponse(http.StatusInternalServerError, "boom"), nil
		}}
		_, err := fetchListRV(ctx, rt, "10.0.0.1", "/x")
		if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
			t.Fatalf("expected HTTP 500 error, got %v", err)
		}
	})

	t.Run("undecodable body", func(t *testing.T) {
		rt := &stubTransport{fn: func(*http.Request) (*http.Response, error) {
			return probeResponse(200, "this is not json{"), nil
		}}
		if _, err := fetchListRV(ctx, rt, "10.0.0.1", "/x"); err == nil {
			t.Fatal("expected JSON decode error")
		}
	})

	t.Run("non-numeric resourceVersion", func(t *testing.T) {
		rt := &stubTransport{fn: func(*http.Request) (*http.Response, error) {
			return probeResponse(200, `{"metadata":{"resourceVersion":"abc"}}`), nil
		}}
		if _, err := fetchListRV(ctx, rt, "10.0.0.1", "/x"); err == nil {
			t.Fatal("expected resourceVersion parse error")
		}
	})

	t.Run("transport error propagates", func(t *testing.T) {
		rt := &stubTransport{fn: func(*http.Request) (*http.Response, error) {
			return nil, errors.New("connection refused")
		}}
		_, err := fetchListRV(ctx, rt, "10.0.0.1", "/x")
		if err == nil || !strings.Contains(err.Error(), "connection refused") {
			t.Fatalf("transport error not surfaced: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// apiServerEndpointGuard.probe / transport / Start.
// ---------------------------------------------------------------------------

// resourceVersion=0 is served from the apiserver's watch cache; any
// other list is a quorum read. The stub mirrors that split — the gap
// between the two RVs is the wedge signal.
func probeRVSplit(cacheRV, liveRV int64) *stubTransport {
	return &stubTransport{fn: func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("resourceVersion") == "0" {
			return probeResponse(200, probeRVJSON(cacheRV)), nil
		}
		return probeResponse(200, probeRVJSON(liveRV)), nil
	}}
}

func TestEndpointGuardProbeHTTP(t *testing.T) {
	g := &apiServerEndpointGuard{rt: probeRVSplit(4800, 5000)}
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
	g := &apiServerEndpointGuard{rt: &stubTransport{fn: func(*http.Request) (*http.Response, error) {
		return nil, errors.New("backend down")
	}}}
	if res := g.probe(ctx, "10.0.0.1"); res.err == nil ||
		!strings.Contains(res.err.Error(), "live rv") {
		t.Fatalf("expected live-rv failure, got %+v", res)
	}

	// Live ok, cache list fails -> error tagged "cache rv".
	g = &apiServerEndpointGuard{rt: &stubTransport{fn: func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("resourceVersion") == "0" {
			return nil, errors.New("cache wedged")
		}
		return probeResponse(200, probeRVJSON(5000)), nil
	}}}
	if res := g.probe(ctx, "10.0.0.1"); res.err == nil ||
		!strings.Contains(res.err.Error(), "cache rv") {
		t.Fatalf("expected cache-rv failure, got %+v", res)
	}
}

func TestEndpointGuardTransport(t *testing.T) {
	rt := &stubTransport{fn: func(*http.Request) (*http.Response, error) {
		return probeResponse(200, "{}"), nil
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
// kubeletReaper.probe / deadNodeSweeper.probe — real REST client,
// fake apiserver. The node/proxy/healthz path only exists on a real
// RESTClient; the fake clientset returns nil there.
// ---------------------------------------------------------------------------

// probeClientset points a real clientset at an httptest apiserver.
func probeClientset(t *testing.T, h http.HandlerFunc) *kubernetes.Clientset {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	cs, err := kubernetes.NewForConfig(&rest.Config{Host: srv.URL})
	if err != nil {
		t.Fatalf("NewForConfig: %v", err)
	}
	return cs
}

// probeHealthzHandler serves the kubelet healthz path both probes
// hit through the apiserver proxy.
func probeHealthzHandler(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/nodes/w1/proxy/healthz" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}
}

func TestKubeletReaperProbeHTTP(t *testing.T) {
	// "ok" after TrimSpace-prefix is healthy — covers plain, trailing
	// newline and a longer word starting with "ok".
	for _, body := range []string{"ok", "ok\n", "okay"} {
		r := &kubeletReaper{cs: probeClientset(t, probeHealthzHandler(200, body))}
		if !r.probe(ctx, "w1") {
			t.Fatalf("body %q must count as healthy", body)
		}
	}

	// Unhealthy answer: the probe would retry 4x at a 10s gap — run
	// it async and cancel once the first attempt landed, forcing the
	// ctx.Done() branch between retries instead of a 30s test sleep.
	t.Run("unhealthy retries then fails on cancel", func(t *testing.T) {
		hit := make(chan struct{}, 4)
		cs := probeClientset(t, func(w http.ResponseWriter, r *http.Request) {
			select {
			case hit <- struct{}{}:
			default:
			}
			w.WriteHeader(200)
			fmt.Fprint(w, "error trying to reach service")
		})
		r := &kubeletReaper{cs: cs}
		pctx, cancel := context.WithCancel(ctx)
		done := make(chan bool, 1)
		go func() { done <- r.probe(pctx, "w1") }()
		<-hit
		cancel()
		select {
		case ok := <-done:
			if ok {
				t.Fatal("unhealthy body reported healthy")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("probe ignored context cancel between retries")
		}
	})

	// Pre-cancelled: first DoRaw errors, the inter-probe select then
	// returns on ctx.Done — no goroutine needed.
	t.Run("pre-cancelled context fails fast", func(t *testing.T) {
		r := &kubeletReaper{cs: probeClientset(t, probeHealthzHandler(200, "ok"))}
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		if r.probe(cctx, "w1") {
			t.Fatal("probe succeeded on a cancelled context")
		}
	})
}

func TestDeadNodeSweeperProbeHTTP(t *testing.T) {
	// Single attempt: "ok" body is the only healthy verdict.
	s := &deadNodeSweeper{cs: probeClientset(t, probeHealthzHandler(200, "ok"))}
	if ok, err := s.probe(ctx, "w1"); err != nil || !ok {
		t.Fatalf("ok=%v err=%v, want true/nil", ok, err)
	}

	// A 200 without "ok" is a clean negative, NOT an error — the
	// apiserver served the request, the kubelet didn't.
	s = &deadNodeSweeper{cs: probeClientset(t,
		probeHealthzHandler(200, "error trying to reach service: connection refused"))}
	if ok, err := s.probe(ctx, "w1"); err != nil || ok {
		t.Fatalf("ok=%v err=%v, want false/nil", ok, err)
	}

	// 5xx surfaces as a DoRaw error — still a failed probe.
	s = &deadNodeSweeper{cs: probeClientset(t, probeHealthzHandler(500, "oops"))}
	if ok, err := s.probe(ctx, "w1"); err == nil || ok {
		t.Fatalf("ok=%v err=%v, want false/err", ok, err)
	}
}

// ---------------------------------------------------------------------------
// coreDNSWatchdog.panics — the :9153/metrics scrape.
// ---------------------------------------------------------------------------

func TestCoreDNSPanics(t *testing.T) {
	newWatchdog := func(status int, body string, rtErr error) (*coreDNSWatchdog, *string) {
		var gotURL string
		httpc := &http.Client{Transport: &stubTransport{fn: func(r *http.Request) (*http.Response, error) {
			gotURL = r.URL.String()
			if rtErr != nil {
				return nil, rtErr
			}
			return probeResponse(status, body), nil
		}}}
		return &coreDNSWatchdog{http: httpc}, &gotURL
	}

	t.Run("sums every label variant", func(t *testing.T) {
		w, gotURL := newWatchdog(200,
			"coredns_panics_total 3\ncoredns_panics_total{pod=\"a\"} 2\n", nil)
		sum, ok := w.panics(ctx, "10.9.9.9")
		if !ok || sum != 5 {
			t.Fatalf("sum=%v ok=%v, want 5/true", sum, ok)
		}
		// The scrape is hardcoded to the pod's own :9153 endpoint.
		if *gotURL != "http://10.9.9.9:9153/metrics" {
			t.Fatalf("metrics URL = %q", *gotURL)
		}
	})

	t.Run("malformed values are skipped", func(t *testing.T) {
		w, _ := newWatchdog(200,
			"coredns_panics_total nope\ncoredns_panics_total 4\n", nil)
		if sum, ok := w.panics(ctx, "10.9.9.9"); !ok || sum != 4 {
			t.Fatalf("sum=%v ok=%v, want 4/true", sum, ok)
		}
	})

	t.Run("no panic lines is zero not unknown", func(t *testing.T) {
		w, _ := newWatchdog(200, "# HELP x\nother_metric 9\n", nil)
		if sum, ok := w.panics(ctx, "10.9.9.9"); !ok || sum != 0 {
			t.Fatalf("sum=%v ok=%v, want 0/true", sum, ok)
		}
	})

	t.Run("http error is unknown", func(t *testing.T) {
		w, _ := newWatchdog(500, "", nil)
		if _, ok := w.panics(ctx, "10.9.9.9"); ok {
			t.Fatal("5xx scrape reported as known")
		}
	})

	t.Run("transport error is unknown", func(t *testing.T) {
		w, _ := newWatchdog(0, "", errors.New("refused"))
		if _, ok := w.panics(ctx, "10.9.9.9"); ok {
			t.Fatal("transport error reported as known")
		}
	})
}

// ---------------------------------------------------------------------------
// coreDNSWatchdog.logHit — pod logs arrive through a get/pods/log
// reactor returning *runtime.Unknown (the fake GetLogs contract).
// ---------------------------------------------------------------------------

// probeLogReactor answers get/pods subresource=log; anything else
// falls through to the tracker.
func probeLogReactor(body string, err error) ktesting.ReactionFunc {
	return func(a ktesting.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() != "log" {
			return false, nil, nil
		}
		if err != nil {
			return true, nil, err
		}
		return true, &runtime.Unknown{Raw: []byte(body)}, nil
	}
}

func TestCoreDNSLogHit(t *testing.T) {
	// The informer-death alternation: the matching LINE is returned
	// verbatim for the operator log.
	t.Run("signature line returned", func(t *testing.T) {
		cs := fake.NewSimpleClientset()
		cs.Fake.PrependReactor("get", "pods", probeLogReactor(
			"INFO booted\nFailed to watch *v1.Endpoints: failed to list: Unauthorized\n",
			nil))
		w := &coreDNSWatchdog{cs: cs}
		if hit := w.logHit(ctx, "coredns-abc"); hit == "" {
			t.Fatal("death signature not matched")
		}
	})

	t.Run("clean logs return empty", func(t *testing.T) {
		cs := fake.NewSimpleClientset()
		cs.Fake.PrependReactor("get", "pods", probeLogReactor(
			"INFO booted\nINFO plugin ready\n", nil))
		w := &coreDNSWatchdog{cs: cs}
		if hit := w.logHit(ctx, "coredns-abc"); hit != "" {
			t.Fatalf("clean log produced a hit: %q", hit)
		}
	})

	// Unreadable logs (API flap) are inconclusive, never a false stale.
	t.Run("log fetch error returns empty", func(t *testing.T) {
		cs := fake.NewSimpleClientset()
		cs.Fake.PrependReactor("get", "pods",
			probeLogReactor("", errors.New("api down")))
		w := &coreDNSWatchdog{cs: cs}
		if hit := w.logHit(ctx, "coredns-abc"); hit != "" {
			t.Fatalf("error path produced a hit: %q", hit)
		}
	})
}

// ---------------------------------------------------------------------------
// coreDNSWatchdog.dnsProbe / probeFQDN — negative paths only (a real
// UDP:53 answer can't be faked deterministically; cancel must still
// cut the 4s lookup budget short).
// ---------------------------------------------------------------------------

func TestCoreDNSDNSProbeCancelled(t *testing.T) {
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	w := &coreDNSWatchdog{}
	start := time.Now()
	if w.dnsProbe(cctx, "10.9.9.9", "svc.ns.svc.cluster.local") {
		t.Fatal("cancelled probe resolved an fqdn")
	}
	if d := time.Since(start); d > 4*time.Second {
		t.Fatalf("cancelled probe took %s — must beat the 4s budget", d)
	}
}

func TestCoreDNSProbeFQDNListError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.Fake.PrependReactor("list", "services",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	w := &coreDNSWatchdog{cs: cs}
	if got := w.probeFQDN(ctx); got != "" {
		t.Fatalf("service list error produced fqdn %q", got)
	}
}
