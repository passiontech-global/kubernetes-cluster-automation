package evpurge

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// eventServer fakes the apiserver: two paginated /api/v1/events pages
// and a DELETE handler that fails only for the event named "bad".
type eventServer struct {
	mu      sync.Mutex
	deleted []string
}

func (s *eventServer) handler(t *testing.T) http.HandlerFunc {
	ev := func(ns, name, ts string) map[string]any {
		return map[string]any{"metadata": map[string]any{
			"namespace": ns, "name": name, "creationTimestamp": ts}}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/events" && r.Method == http.MethodGet:
			q := r.URL.Query()
			if q.Get("limit") != "500" || q.Get("resourceVersion") != "0" {
				t.Errorf("unexpected list query: %s", r.URL.RawQuery)
			}
			w.Header().Set("Content-Type", "application/json")
			if q.Get("continue") == "page2" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"metadata": map[string]any{},
					"items": []any{
						ev("default", "old-2", "2020-01-01T00:00:00Z"),
						ev("kube-system", "bad", "2020-01-01T00:00:00Z"),
					},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"metadata": map[string]any{"continue": "page2"},
				"items": []any{
					ev("default", "old-1", "2020-01-01T00:00:00Z"),
					// Exactly at the cutoff: NOT deleted (strict <).
					ev("default", "at-cutoff", "2026-08-23T04:27:00Z"),
					ev("default", "new-1", "2027-01-01T00:00:00Z"),
				},
			})
		case strings.HasPrefix(r.URL.Path, "/api/v1/namespaces/") &&
			r.Method == http.MethodDelete:
			s.mu.Lock()
			s.deleted = append(s.deleted, r.URL.Path)
			s.mu.Unlock()
			if strings.HasSuffix(r.URL.Path, "/bad") {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"kind":"Status","status":"Success"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func (s *eventServer) deletedPaths() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]string{}, s.deleted...)
	return out
}

func TestRunPurgesStaleEvents(t *testing.T) {
	fake := &eventServer{}
	srv := httptest.NewTLSServer(fake.handler(t))
	defer srv.Close()

	cutoff, err := time.Parse(time.RFC3339, "2026-08-23T04:27:00Z")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Run(context.Background(), Config{
		API:     srv.URL,
		Client:  srv.Client(),
		Workers: 4,
	}, cutoff, &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	// 3 stale events (old-1, old-2, bad); at-cutoff and new-1 survive.
	if !strings.Contains(got, "to delete: 3") {
		t.Fatalf("output missing list count:\n%s", got)
	}
	if !strings.Contains(got, "deleted=2 errors=1") {
		t.Fatalf("output missing delete tally:\n%s", got)
	}
	deleted := fake.deletedPaths()
	if len(deleted) != 3 {
		t.Fatalf("deleted=%v", deleted)
	}
	for _, p := range deleted {
		if strings.Contains(p, "at-cutoff") || strings.Contains(p, "new-1") {
			t.Fatalf("deleted a fresh event: %v", deleted)
		}
	}
}

func TestRunContinuesAllPages(t *testing.T) {
	// Verify the continue token is honoured: without it the second
	// page would never be fetched and old-2/bad would survive.
	fake := &eventServer{}
	srv := httptest.NewTLSServer(fake.handler(t))
	defer srv.Close()
	cutoff, err := time.Parse(time.RFC3339, "2030-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Run(context.Background(), Config{
		API:    srv.URL,
		Client: srv.Client(),
	}, cutoff, &out); err != nil {
		t.Fatal(err)
	}
	// Future cutoff deletes every event on both pages (5 total).
	if !strings.Contains(out.String(), "to delete: 5") {
		t.Fatalf("pagination missed:\n%s", out.String())
	}
	if len(fake.deletedPaths()) != 5 {
		t.Fatalf("deleted=%v", fake.deletedPaths())
	}
}

func TestDefaultCAFallback(t *testing.T) {
	// On a dev box /var/lib/k0s/pki/ca.crt does not exist → the etcd
	// CA path is the fallback. When it does exist the primary wins.
	got := DefaultCA()
	if _, err := os.Stat(defaultCAFile); err == nil {
		if got != defaultCAFile {
			t.Fatalf("DefaultCA=%q want %q", got, defaultCAFile)
		}
	} else if got != fallbackCAFile {
		t.Fatalf("DefaultCA=%q want %q", got, fallbackCAFile)
	}
}
