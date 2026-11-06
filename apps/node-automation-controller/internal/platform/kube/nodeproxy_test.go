// nodeproxy_test.go — KubeletHealthz coverage. The nodes/proxy/
// healthz REST path only exists on a real clientset pointed at
// httptest (the fake clientset's CoreV1().RESTClient() is nil), so
// the suite goes through platform/testhelp — the leaf-level home for
// the probe fakes internal/testutil cannot host (testutil imports
// internal/shared and platform stays a leaf).
package kube

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/testhelp"
)

func TestKubeletHealthz(t *testing.T) {
	// The request must land on the exact apiserver proxy path the
	// kubelets are reached through — a wrong segment 404s.
	t.Run("hits nodes/<n>/proxy/healthz and returns the raw body", func(t *testing.T) {
		cs := testhelp.ProbeClientset(t, testhelp.ProbeHealthzHandler(200, "ok"))
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
		cs := testhelp.ProbeClientset(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/nodes/w2/proxy/healthz" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
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
		cs := testhelp.ProbeClientset(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprint(w, "error trying to reach service")
		})
		if _, err := KubeletHealthz(ctx, cs, "w1"); err == nil {
			t.Fatal("expected an error on a 500 healthz response")
		}
	})
}
