// probe_http_test.go — coverage for the kubelet healthz probes the
// liveness sweeper makes through the apiserver proxy: the
// nodes/proxy/healthz REST path only exists on a real clientset
// pointed at httptest (the fake clientset's CoreV1().RESTClient() is
// nil).
package kubeletreaper

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/testutil"
)

func TestKubeletReaperProbeHTTP(t *testing.T) {
	// "ok" after TrimSpace-prefix is healthy — covers plain, trailing
	// newline and a longer word starting with "ok".
	for _, body := range []string{"ok", "ok\n", "okay"} {
		r := &kubeletReaper{cs: testutil.ProbeClientset(t, testutil.ProbeHealthzHandler(200, body))}
		if !r.probe(ctx, "w1") {
			t.Fatalf("body %q must count as healthy", body)
		}
	}

	// Unhealthy answer: the probe would retry 4x at a 10s gap — run
	// it async and cancel once the first attempt landed, forcing the
	// ctx.Done() branch between retries instead of a 30s test sleep.
	t.Run("unhealthy retries then fails on cancel", func(t *testing.T) {
		hit := make(chan struct{}, 4)
		cs := testutil.ProbeClientset(t, func(w http.ResponseWriter, r *http.Request) {
			select {
			case hit <- struct{}{}:
			default:
			}
			w.WriteHeader(200)
			_, _ = fmt.Fprint(w, "error trying to reach service")
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
		r := &kubeletReaper{cs: testutil.ProbeClientset(t, testutil.ProbeHealthzHandler(200, "ok"))}
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		if r.probe(cctx, "w1") {
			t.Fatal("probe succeeded on a cancelled context")
		}
	})

	// All four probes failing -> false, after the real 10s backoff
	// gaps (~30s of wall time — the retry cadence IS the code under
	// test; a kubelet restart must not be punished by a single blip).
	t.Run("four consecutive failures return false", func(t *testing.T) {
		var attempts atomic.Int32
		cs := testutil.ProbeClientset(t, func(w http.ResponseWriter, r *http.Request) {
			attempts.Add(1)
			w.WriteHeader(200)
			_, _ = fmt.Fprint(w, "error trying to reach service")
		})
		r := &kubeletReaper{cs: cs}
		done := make(chan bool, 1)
		go func() { done <- r.probe(ctx, "w1") }()
		select {
		case ok := <-done:
			if ok {
				t.Fatal("four failed probes reported healthy")
			}
			if n := attempts.Load(); n != kubeletReaperProbes {
				t.Fatalf("attempts = %d, want %d", n, kubeletReaperProbes)
			}
		case <-time.After(kubeletReaperProbes*kubeletReaperProbeGap + 20*time.Second):
			t.Fatal("probe did not exhaust retries")
		}
	})

	// A kubelet that recovers between retries is healthy on the NEXT
	// attempt — covers success after a timer gap.
	t.Run("recovery between retries reports healthy", func(t *testing.T) {
		var attempts atomic.Int32
		cs := testutil.ProbeClientset(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			if attempts.Add(1) >= 2 {
				_, _ = fmt.Fprint(w, "ok")
				return
			}
			_, _ = fmt.Fprint(w, "error trying to reach service")
		})
		r := &kubeletReaper{cs: cs}
		done := make(chan bool, 1)
		go func() { done <- r.probe(ctx, "w1") }()
		select {
		case ok := <-done:
			if !ok {
				t.Fatal("kubelet healthy on attempt 2 reported dead")
			}
			if n := attempts.Load(); n != 2 {
				t.Fatalf("attempts = %d, want 2", n)
			}
		case <-time.After(kubeletReaperProbeGap + 20*time.Second):
			t.Fatal("probe did not retry")
		}
	})
}
