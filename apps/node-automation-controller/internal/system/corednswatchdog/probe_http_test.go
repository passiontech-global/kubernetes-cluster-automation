// probe_http_test.go — coverage for the CoreDNS watchdog's probes the
// fake clientset cannot serve: the :9153/metrics scrape via injected
// http.Client, pod logs via a get/pods/log reactor, and the negative
// paths for UDP :53 / Service listing.
package corednswatchdog

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// coreDNSWatchdog.panics — the :9153/metrics scrape.
// ---------------------------------------------------------------------------

func TestCoreDNSPanics(t *testing.T) {
	newWatchdog := func(status int, body string, rtErr error) (*coreDNSWatchdog, *string) {
		var gotURL string
		httpc := &http.Client{Transport: &testutil.StubTransport{Fn: func(r *http.Request) (*http.Response, error) {
			gotURL = r.URL.String()
			if rtErr != nil {
				return nil, rtErr
			}
			return testutil.ProbeResponse(status, body), nil
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

	t.Run("scrape timestamp is not the count", func(t *testing.T) {
		// OpenMetrics lines can carry a trailing timestamp — the
		// value is always the SECOND field; reading the last field
		// mistook the timestamp for the panic count.
		w, _ := newWatchdog(200,
			"coredns_panics_total 5 1731450000000\ncoredns_panics_total{pod=\"a\"} 2 1731450000000\n", nil)
		if sum, ok := w.panics(ctx, "10.9.9.9"); !ok || sum != 7 {
			t.Fatalf("sum=%v ok=%v, want 7/true", sum, ok)
		}
	})

	t.Run("prefix-sharing metric names do not count", func(t *testing.T) {
		// The match must end at a name boundary (' ' or '{') — a
		// different metric sharing the prefix must contribute zero.
		w, _ := newWatchdog(200,
			"coredns_panics_total_something 99\ncoredns_panics_total_b{pod=\"a\"} 1\ncoredns_panics_total 3\n", nil)
		if sum, ok := w.panics(ctx, "10.9.9.9"); !ok || sum != 3 {
			t.Fatalf("sum=%v ok=%v, want 3/true", sum, ok)
		}
	})

	t.Run("NaN and Inf values are rejected", func(t *testing.T) {
		w, _ := newWatchdog(200,
			"coredns_panics_total NaN\ncoredns_panics_total +Inf\ncoredns_panics_total -Inf\ncoredns_panics_total 6\n", nil)
		if sum, ok := w.panics(ctx, "10.9.9.9"); !ok || sum != 6 {
			t.Fatalf("sum=%v ok=%v, want 6/true", sum, ok)
		}
	})

	t.Run("body over the 4MiB scan cap is invalid not partial", func(t *testing.T) {
		// A body at the cap ends the scan cleanly at the cut — a
		// partial document's sum must never read as known (it would
		// understate panics, the silent-stale direction).
		filler := strings.Repeat("# padding\n", 100)
		body := filler + "coredns_panics_total 9\n" + strings.Repeat("x", 5*1024*1024)
		w, _ := newWatchdog(200, body, nil)
		if _, ok := w.panics(ctx, "10.9.9.9"); ok {
			t.Fatal("truncated-over-cap scrape reported a known sum")
		}
	})

	t.Run("no panic lines is zero not unknown", func(t *testing.T) {
		w, _ := newWatchdog(200, "# HELP x\nother_metric 9\n", nil)
		if sum, ok := w.panics(ctx, "10.9.9.9"); !ok || sum != 0 {
			t.Fatalf("sum=%v ok=%v, want 0/true", sum, ok)
		}
	})

	t.Run("line over 64KiB still scans", func(t *testing.T) {
		// bufio.Scanner's default token cap is 64KiB — a single long
		// line must not end the scan early (the buffer was raised to
		// 1MiB for exactly this case).
		w, _ := newWatchdog(200,
			"# "+strings.Repeat("x", 200*1024)+"\ncoredns_panics_total 7\n", nil)
		if sum, ok := w.panics(ctx, "10.9.9.9"); !ok || sum != 7 {
			t.Fatalf("sum=%v ok=%v, want 7/true", sum, ok)
		}
	})

	t.Run("line over 1MiB is unknown not truncated", func(t *testing.T) {
		// Past the raised cap the scanner errors — same UNKNOWN
		// verdict as a failed body read, never a partial sum.
		w, _ := newWatchdog(200,
			"coredns_panics_total 3\n# "+strings.Repeat("x", 2*1024*1024)+"\n", nil)
		if _, ok := w.panics(ctx, "10.9.9.9"); ok {
			t.Fatal("oversized metric line reported a known sum")
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

	t.Run("unbuildable request is unknown", func(t *testing.T) {
		w, _ := newWatchdog(200, "coredns_panics_total 9\n", nil)
		// A space in the podIP makes NewRequest reject the URL —
		// same UNKNOWN verdict as a transport error.
		if _, ok := w.panics(ctx, "bad ip"); ok {
			t.Fatal("unparseable podIP reported as known")
		}
	})

	t.Run("non-200 body still drained before close", func(t *testing.T) {
		// The early status return must not skip the drain — an
		// unread body makes the connection unreusable, which
		// silently defeats keep-alive on the shared transport.
		body := strings.Repeat("e", 64*1024)
		tb := &testutil.TrackingBody{R: strings.NewReader(body)}
		httpc := &http.Client{Transport: &testutil.StubTransport{Fn: func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusInternalServerError, Body: tb, Header: http.Header{}}, nil
		}}}
		w := &coreDNSWatchdog{http: httpc}
		if _, ok := w.panics(ctx, "10.9.9.9"); ok {
			t.Fatal("5xx scrape reported as known")
		}
		if !tb.Closed {
			t.Fatal("body never closed")
		}
		if tb.N != len(body) {
			t.Fatalf("closed after %d/%d bytes — undrained body defeats keep-alive",
				tb.N, len(body))
		}
	})

	t.Run("oversized body tail drained before close", func(t *testing.T) {
		// The scanner stops at the 4MiB cap; the deferred drain must
		// still consume the tail so keep-alive survives a fat scrape.
		body := strings.Repeat("x", 5*1024*1024)
		tb := &testutil.TrackingBody{R: strings.NewReader(body)}
		httpc := &http.Client{Transport: &testutil.StubTransport{Fn: func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: tb, Header: http.Header{}}, nil
		}}}
		w := &coreDNSWatchdog{http: httpc}
		_, _ = w.panics(ctx, "10.9.9.9")
		if !tb.Closed {
			t.Fatal("body never closed")
		}
		if tb.N != len(body) {
			t.Fatalf("closed after %d/%d bytes — undrained tail defeats keep-alive",
				tb.N, len(body))
		}
	})

	t.Run("truncated body is unknown", func(t *testing.T) {
		httpc := &http.Client{Transport: &testutil.StubTransport{Fn: func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       testutil.ErrReadCloser{},
				Header:     http.Header{},
			}, nil
		}}}
		w := &coreDNSWatchdog{http: httpc}
		if _, ok := w.panics(ctx, "10.9.9.9"); ok {
			t.Fatal("body read failure reported as known")
		}
	})
}

// ---------------------------------------------------------------------------
// coreDNSWatchdog.logHit — pod logs arrive through a get/pods/log
// reactor returning *runtime.Unknown (the fake GetLogs contract).
// ---------------------------------------------------------------------------

func TestCoreDNSLogHit(t *testing.T) {
	// The informer-death alternation: the matching LINE is returned
	// verbatim for the operator log.
	t.Run("signature line returned", func(t *testing.T) {
		cs := fake.NewSimpleClientset()
		cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
			"INFO booted\nFailed to watch *v1.Endpoints: failed to list: Unauthorized\n",
			nil))
		w := &coreDNSWatchdog{cs: cs}
		if hit := w.logHit(ctx, "coredns-abc"); hit == "" {
			t.Fatal("death signature not matched")
		}
	})

	t.Run("clean logs return empty", func(t *testing.T) {
		cs := fake.NewSimpleClientset()
		cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
			"INFO booted\nINFO plugin ready\n", nil))
		w := &coreDNSWatchdog{cs: cs}
		if hit := w.logHit(ctx, "coredns-abc"); hit != "" {
			t.Fatalf("clean log produced a hit: %q", hit)
		}
	})

	// Unreadable logs (API flap) are inconclusive, never a false stale.
	t.Run("log fetch error returns empty", func(t *testing.T) {
		cs := fake.NewSimpleClientset()
		cs.PrependReactor("get", "pods",
			testutil.ProbeLogReactor("", errors.New("api down")))
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
	if ips, err := w.dnsProbe(cctx, "10.9.9.9", "svc.ns.svc.cluster.local"); err == nil && len(ips) > 0 {
		t.Fatal("cancelled probe resolved an fqdn")
	}
	if d := time.Since(start); d > 4*time.Second {
		t.Fatalf("cancelled probe took %s — must beat the 4s budget", d)
	}
}

func TestCoreDNSProbeFQDNListError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "services",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	w := &coreDNSWatchdog{cs: cs}
	if got, _ := w.probeFQDN(ctx); got != "" {
		t.Fatalf("service list error produced fqdn %q", got)
	}
}
