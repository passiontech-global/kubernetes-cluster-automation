package eventpurge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
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
	// "bad" is retried under the 429/5xx policy, so raw attempts
	// exceed the event count — assert distinct targeted events.
	slices.Sort(deleted)
	unique := slices.Compact(deleted)
	if len(unique) != 3 {
		t.Fatalf("targeted=%v want 3 distinct events", unique)
	}
	for _, p := range unique {
		if strings.Contains(p, "at-cutoff") || strings.Contains(p, "new-1") {
			t.Fatalf("deleted a fresh event: %v", unique)
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
	// "bad" is retried under the 429/5xx policy — count distinct
	// targeted events, not raw attempts.
	deleted := fake.deletedPaths()
	slices.Sort(deleted)
	unique := slices.Compact(deleted)
	if len(unique) != 5 {
		t.Fatalf("targeted=%v want 5 distinct events", unique)
	}
}

// A body over the 8MiB cap fails naming the cap — a truncated page
// must not surface as a misleading JSON syntax error.
func TestListRejectsOversizeResponse(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(bytes.Repeat([]byte("x"), maxResponseBytes+1))
		}))
	defer srv.Close()

	_, err := listStale(context.Background(), srv.Client(), srv.URL,
		time.Now())
	if err == nil || !strings.Contains(err.Error(), "8MiB cap") {
		t.Fatalf("err=%v want the 8MiB-cap message", err)
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

// TestRunCapsDeletes — the LIST always runs fully, but only the
// first MaxDeletes stale paths feed the worker pool; the overflow is
// reported as skipped_by_cap=N (printed only when the cap bit — the
// script's exact 2-line output otherwise).
func TestRunCapsDeletes(t *testing.T) {
	var deleted []string
	var mu sync.Mutex
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/events", func(w http.ResponseWriter, r *http.Request) {
		items := make([]any, 0, 5)
		for i := 0; i < 5; i++ {
			items = append(items, map[string]any{"metadata": map[string]any{
				"namespace": "default", "name": fmt.Sprintf("old-%d", i),
				"creationTimestamp": "2020-01-01T00:00:00Z"}})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"metadata": map[string]any{}, "items": items})
	})
	mux.HandleFunc("/api/v1/namespaces/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		deleted = append(deleted, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	cutoff, err := time.Parse(time.RFC3339, "2026-08-23T04:27:00Z")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Run(context.Background(), Config{
		API: srv.URL, Client: srv.Client(),
		Workers: 4, MaxDeletes: 3,
	}, cutoff, &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "to delete: 5\n") ||
		!strings.Contains(got, "deleted=3 errors=0\n") ||
		!strings.Contains(got, "skipped_by_cap=2\n") {
		t.Fatalf("capped output wrong:\n%s", got)
	}
	mu.Lock()
	if len(deleted) != 3 {
		n := len(deleted)
		mu.Unlock()
		t.Fatalf("deleted=%d want exactly the cap (3)", n)
	}
	mu.Unlock()

	// Uncapped run: the extra line must NOT appear (script parity).
	mu.Lock()
	deleted = nil
	mu.Unlock()
	out.Reset()
	if err := Run(context.Background(), Config{
		API: srv.URL, Client: srv.Client(),
		Workers: 4, MaxDeletes: 5000,
	}, cutoff, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "skipped_by_cap") {
		t.Fatalf("cap line printed on an uncapped run:\n%s", out.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(deleted) != 5 {
		t.Fatalf("uncapped run deleted=%d want 5", len(deleted))
	}
}

// staleList writes a single-page LIST carrying n stale events named
// old-0..old-<n-1> — the minimal feed for the DELETE-policy tests.
func staleList(w http.ResponseWriter, n int) {
	items := make([]any, n)
	for i := range n {
		items[i] = map[string]any{"metadata": map[string]any{
			"namespace": "default", "name": fmt.Sprintf("old-%d", i),
			"creationTimestamp": "2020-01-01T00:00:00Z"}}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"metadata": map[string]any{}, "items": items})
}

// TestRunAbortsOnCancelledContext — SIGTERM or a caller's bounded
// deadline killing the run mid-purge must not read as a clean purge:
// the old code returned nil after a partial delete, so the ops layer
// exited 0. Run must surface the cancellation and mark the tally
// aborted.
func TestRunAbortsOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	started := make(chan string, 1)
	var mu sync.Mutex
	var deleted []string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/events", func(w http.ResponseWriter, _ *http.Request) {
		staleList(w, 2)
	})
	mux.HandleFunc("/api/v1/namespaces/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		deleted = append(deleted, r.URL.Path)
		mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "/old-1") {
			started <- r.URL.Path
			// Hold the request open until the client's ctx dies, so
			// the in-flight DELETE fails on cancellation instead of
			// racing its response through the cancel.
			<-r.Context().Done()
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	// cancel() must fire while Run occupies the test goroutine — the
	// held old-1 request only unblocks when the client ctx dies.
	go func() {
		<-started
		cancel()
	}()

	var out bytes.Buffer
	err := Run(ctx, Config{
		API: srv.URL, Client: srv.Client(), Workers: 1,
	}, time.Now().Add(time.Minute), &out)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v want a wrapped context.Canceled", err)
	}
	got := out.String()
	if !strings.Contains(got, "deleted=1 errors=1\n") || !strings.Contains(got, "aborted") {
		t.Fatalf("partial delete not marked aborted:\n%s", got)
	}
	mu.Lock()
	defer mu.Unlock()
	// old-0 done, old-1 in flight when the cancel landed; the feed
	// must have stopped there — nothing after old-1.
	if len(deleted) != 2 {
		t.Fatalf("attempted %v after cancel, want exactly old-0, old-1", deleted)
	}
}

// TestDelete429HonorsRetryAfter — a throttled DELETE waits out the
// server's Retry-After (not full speed, not the shorter 500ms
// exponential step) and then lands clean.
func TestDelete429HonorsRetryAfter(t *testing.T) {
	var mu sync.Mutex
	var attempts []time.Time
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/events", func(w http.ResponseWriter, _ *http.Request) {
		staleList(w, 1)
	})
	mux.HandleFunc("/api/v1/namespaces/", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		attempts = append(attempts, time.Now())
		n := len(attempts)
		mu.Unlock()
		if n < 3 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	var out bytes.Buffer
	if err := Run(context.Background(), Config{
		API: srv.URL, Client: srv.Client(), Workers: 1,
	}, time.Now().Add(time.Minute), &out); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "deleted=1 errors=0\n") {
		t.Fatalf("retried delete did not land clean:\n%s", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(attempts) != 3 {
		t.Fatalf("attempts=%d want exactly 3", len(attempts))
	}
	// Both gaps ≥ the 1s Retry-After (small slack for scheduler
	// jitter) — full-speed retrying or the 500ms exponential step
	// would land well under.
	for i := 1; i < len(attempts); i++ {
		if gap := attempts[i].Sub(attempts[i-1]); gap < 900*time.Millisecond {
			t.Fatalf("retry %d fired after %v — Retry-After ignored", i, gap)
		}
	}
}

// TestDelete429ExhaustsAttempts — a DELETE that stays throttled gives
// up at deleteMaxAttempts, tallies one error and returns (no hang, no
// infinite retry); the run still exits nil — per-event failures are
// the script's err count, not a fatal exit.
func TestDelete429ExhaustsAttempts(t *testing.T) {
	var mu sync.Mutex
	attempts := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/events", func(w http.ResponseWriter, _ *http.Request) {
		staleList(w, 1)
	})
	mux.HandleFunc("/api/v1/namespaces/", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		attempts++
		mu.Unlock()
		// Retry-After: 0 keeps the exhaustion path fast — the point
		// under test is the attempt cap, not the sleep.
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	var out bytes.Buffer
	if err := Run(context.Background(), Config{
		API: srv.URL, Client: srv.Client(), Workers: 1,
	}, time.Now().Add(time.Minute), &out); err != nil {
		t.Fatalf("exhausted per-event retries must not fail the run: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "deleted=0 errors=1\n") ||
		!strings.Contains(got, "HTTP 429 after 4 attempts") {
		t.Fatalf("exhaustion output wrong:\n%s", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if attempts != deleteMaxAttempts {
		t.Fatalf("attempts=%d want the cap %d", attempts, deleteMaxAttempts)
	}
}

// TestDeleteRetries5xxThenSucceeds — a 5xx mid-burst is transient
// apiserver load: the exponential step (no Retry-After on this 503)
// between attempts, then success.
func TestDeleteRetries5xxThenSucceeds(t *testing.T) {
	var mu sync.Mutex
	var attempts []time.Time
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/events", func(w http.ResponseWriter, _ *http.Request) {
		staleList(w, 1)
	})
	mux.HandleFunc("/api/v1/namespaces/", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		attempts = append(attempts, time.Now())
		n := len(attempts)
		mu.Unlock()
		if n == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	var out bytes.Buffer
	if err := Run(context.Background(), Config{
		API: srv.URL, Client: srv.Client(), Workers: 1,
	}, time.Now().Add(time.Minute), &out); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "deleted=1 errors=0\n") {
		t.Fatalf("retried delete did not land clean:\n%s", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(attempts) != 2 {
		t.Fatalf("attempts=%d want exactly 2", len(attempts))
	}
	// Full-speed retrying would land far under the 500ms step.
	if gap := attempts[1].Sub(attempts[0]); gap < 400*time.Millisecond {
		t.Fatalf("retry fired after %v — backoff ignored", gap)
	}
}

// TestDelete4xxFailsWithoutRetry — a 4xx refusal is a real failure:
// exactly one attempt, one error tally, no backoff sleeps.
func TestDelete4xxFailsWithoutRetry(t *testing.T) {
	var mu sync.Mutex
	attempts := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/events", func(w http.ResponseWriter, _ *http.Request) {
		staleList(w, 1)
	})
	mux.HandleFunc("/api/v1/namespaces/", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		attempts++
		mu.Unlock()
		w.WriteHeader(http.StatusForbidden)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	var out bytes.Buffer
	if err := Run(context.Background(), Config{
		API: srv.URL, Client: srv.Client(), Workers: 1,
	}, time.Now().Add(time.Minute), &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "deleted=0 errors=1\n") ||
		!strings.Contains(got,
			"first error: /api/v1/namespaces/default/events/old-0: HTTP 403") {
		t.Fatalf("4xx output wrong:\n%s", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if attempts != 1 {
		t.Fatalf("attempts=%d want exactly 1 — 4xx must not retry", attempts)
	}
}

// TestRetryDelayPolicy — Retry-After wins when present and is capped;
// the exponential 0.5s→1s→2s steps fill in when the header is absent
// or unparseable.
func TestRetryDelayPolicy(t *testing.T) {
	if got := retryDelay(map[string][]string{"Retry-After": {"120"}}, 0); got != deleteBackoffCap {
		t.Fatalf("Retry-After 120s = %v want the %v cap", got, deleteBackoffCap)
	}
	if got := retryDelay(map[string][]string{"Retry-After": {"7"}}, 3); got != 7*time.Second {
		t.Fatalf("Retry-After 7s = %v want 7s", got)
	}
	for _, tc := range []struct {
		attempt int
		want    time.Duration
	}{
		{0, 500 * time.Millisecond},
		{1, time.Second},
		{2, 2 * time.Second},
	} {
		if got := retryDelay(nil, tc.attempt); got != tc.want {
			t.Fatalf("attempt %d = %v want %v", tc.attempt, got, tc.want)
		}
	}
	if got := retryDelay(map[string][]string{"Retry-After": {"soon"}}, 0); got != 500*time.Millisecond {
		t.Fatalf("unparseable Retry-After = %v want the exponential fallback", got)
	}
}
