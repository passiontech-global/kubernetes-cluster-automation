package main

import (
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
)

// TestTransportIsolationHTTP2AndTLS verifies that tuneClientConfig,
// buildKubeClients, and buildLeaderLock yield three genuinely separate
// TCP + HTTP/2 connection pools (fleet, probe, leader-election) while
// preserving TLS verification against the configured CA.
func TestTransportIsolationHTTP2AndTLS(t *testing.T) {
	var newConns atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/leases/") {
			_, _ = w.Write([]byte(`{"apiVersion":"coordination.k8s.io/v1","kind":"Lease","metadata":{"name":"` + leaderElectionID + `","namespace":"node-ops"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"apiVersion":"v1","kind":"Node","metadata":{"name":"n1"}}`))
	}))
	srv.EnableHTTP2 = true
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			newConns.Add(1)
		}
	}
	srv.StartTLS()
	defer srv.Close()

	caPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: srv.Certificate().Raw,
	})
	cfg := &rest.Config{
		Host: srv.URL,
		TLSClientConfig: rest.TLSClientConfig{
			CAData: caPEM,
		},
	}
	if err := tuneClientConfig(cfg); err != nil {
		t.Fatalf("tuneClientConfig: %v", err)
	}
	if cfg.Transport == nil {
		t.Fatal("tuneClientConfig left cfg.Transport nil")
	}

	clients, err := buildKubeClients(cfg)
	if err != nil {
		t.Fatalf("buildKubeClients: %v", err)
	}

	var stolen atomic.Bool
	done := make(chan struct{})
	defer close(done)
	t.Setenv("POD_NAME", "nac-test-pod")
	leaderLock, err := buildLeaderLock(cfg, runtime.NewScheme(), "node-ops",
		10*time.Second, &stolen, done)
	if err != nil {
		t.Fatalf("buildLeaderLock: %v", err)
	}

	if _, err := clients.cs.CoreV1().Nodes().Get(t.Context(), "n1", metav1.GetOptions{}); err != nil {
		t.Fatalf("fleet cs request failed: %v", err)
	}
	if _, err := clients.probeCS.CoreV1().Nodes().Get(t.Context(), "n1", metav1.GetOptions{}); err != nil {
		t.Fatalf("probe cs request failed: %v", err)
	}
	if _, _, err := leaderLock.Get(t.Context()); err != nil {
		t.Fatalf("leaderLock.Get failed: %v", err)
	}

	if got := newConns.Load(); got != 3 {
		t.Fatalf("TLS HTTP/2 StateNew connections = %d, want 3 (fleet, probe, leader-election must not share pools)", got)
	}
}

func TestIsolatedTransportEdgeCases(t *testing.T) {
	t.Run("nil transport builds from rest.Config", func(t *testing.T) {
		cfg := &rest.Config{Host: "https://127.0.0.1:6443"}
		tr, err := isolatedTransport(cfg)
		if err != nil {
			t.Fatalf("isolatedTransport(nil): %v", err)
		}
		if tr == nil {
			t.Fatal("isolatedTransport returned nil")
		}
	})

	t.Run("custom non-*http.Transport RoundTripper preserved", func(t *testing.T) {
		custom := roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return nil, nil
		})
		cfg := &rest.Config{Host: "https://127.0.0.1:6443", Transport: custom}
		tr, err := isolatedTransport(cfg)
		if err != nil {
			t.Fatalf("isolatedTransport(custom): %v", err)
		}
		if tr == nil {
			t.Fatal("isolatedTransport returned nil")
		}
	})
}
