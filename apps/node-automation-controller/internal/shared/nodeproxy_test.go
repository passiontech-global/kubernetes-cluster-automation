// nodeproxy_test.go — KubeletHealthz coverage. The nodes/proxy/
// healthz REST path only exists on a real clientset pointed at
// httptest (the fake clientset's CoreV1().RESTClient() is nil), and
// that clientset is built locally — not via testutil.ProbeClientset —
// because shared must stay a leaf: testutil already imports shared.
package shared

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// healthzClientset is a local copy of testutil.ProbeClientset (see the
// file header for why testutil cannot be imported here).
func healthzClientset(t *testing.T, h http.HandlerFunc) *kubernetes.Clientset {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	cs, err := kubernetes.NewForConfig(&rest.Config{Host: srv.URL})
	if err != nil {
		t.Fatalf("NewForConfig: %v", err)
	}
	return cs
}

func TestKubeletHealthz(t *testing.T) {
	// The request must land on the exact apiserver proxy path the
	// kubelets are reached through — a wrong segment 404s.
	t.Run("hits nodes/<n>/proxy/healthz and returns the raw body", func(t *testing.T) {
		cs := healthzClientset(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/nodes/w1/proxy/healthz" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(200)
			_, _ = fmt.Fprint(w, "ok")
		})
		body, err := KubeletHealthz(ctx, cs, "w1")
		if err != nil {
			t.Fatalf("KubeletHealthz: %v", err)
		}
		if string(body) != "ok" {
			t.Fatalf("body = %q, want %q", body, "ok")
		}
	})

	// The node name goes into the path — a per-node verdict needs a
	// per-node URL.
	t.Run("node name is interpolated into the path", func(t *testing.T) {
		cs := healthzClientset(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/nodes/w2/proxy/healthz" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(200)
			_, _ = fmt.Fprint(w, "ok")
		})
		if _, err := KubeletHealthz(ctx, cs, "w2"); err != nil {
			t.Fatalf("KubeletHealthz(w2): %v", err)
		}
	})

	// A dead kubelet surfaces as a DoRaw error (the apiserver's 5xx
	// is not a 200 body) — the helper propagates it for the caller's
	// policy to weigh.
	t.Run("5xx propagates as an error", func(t *testing.T) {
		cs := healthzClientset(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(500)
			_, _ = fmt.Fprint(w, "error trying to reach service")
		})
		if _, err := KubeletHealthz(ctx, cs, "w1"); err == nil {
			t.Fatal("expected an error on a 500 healthz response")
		}
	})
}
