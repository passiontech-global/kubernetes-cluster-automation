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
	"path/filepath"
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
			// No resourceVersion pin — rv=0 pages inconsistently;
			// the purge wants clean 500-event batches.
			if q.Get("limit") != "500" || q.Get("resourceVersion") != "" {
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
			// The client's cancellation usually aborts the DELETE
			// client-side — but the response headers can also win
			// that race (the transport's ctx watch and the response
			// read race; under load the 200 used to land first and
			// the tally read deleted=2 errors=0). An error status
			// makes the racing branch an error too, so the tally
			// reads deleted=1 errors=1 either way.
			w.WriteHeader(http.StatusInternalServerError)
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

// applyDefaults fills every knob — a bare Config{} IS the script's
// production config (CA resolution included).
func TestApplyDefaults(t *testing.T) {
	cfg := Config{}
	cfg.applyDefaults()
	if cfg.API != defaultAPI {
		t.Fatalf("API=%q want %q", cfg.API, defaultAPI)
	}
	if cfg.CAFile != DefaultCA() || cfg.CertFile != defaultCertFile ||
		cfg.KeyFile != defaultKeyFile {
		t.Fatalf("pki defaults = %q %q %q", cfg.CAFile, cfg.CertFile, cfg.KeyFile)
	}
	if cfg.Workers != defaultWorkers || cfg.Timeout != defaultTimeout ||
		cfg.MaxDeletes != defaultMaxDeletes {
		t.Fatalf("knob defaults = %d %v %d", cfg.Workers, cfg.Timeout, cfg.MaxDeletes)
	}
}

// A TLS client that cannot be built (unreadable CA) fails Run before
// any LIST is attempted — fatal, not a tally.
func TestRunClientSetupFailure(t *testing.T) {
	var out bytes.Buffer
	err := Run(context.Background(), Config{
		API:      "https://127.0.0.1:1",
		CAFile:   filepath.Join(t.TempDir(), "no-ca.crt"),
		CertFile: "x", KeyFile: "y",
	}, time.Now(), &out)
	if err == nil || !strings.Contains(err.Error(), "read CA") {
		t.Fatalf("err=%v want the read-CA failure", err)
	}
}

// A failed LIST page is fatal — the purge never starts deleting.
func TestRunListHTTPFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
	defer srv.Close()
	var out bytes.Buffer
	err := Run(context.Background(), Config{
		API: srv.URL, Client: srv.Client(),
	}, time.Now(), &out)
	if err == nil || !strings.Contains(err.Error(), "list events: HTTP 500") {
		t.Fatalf("err=%v want the list HTTP failure", err)
	}
}

// A 200 page that is not an EventList is fatal too — a truncated or
// rewritten response must not drive deletes.
func TestRunListBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("not json"))
		}))
	defer srv.Close()
	var out bytes.Buffer
	err := Run(context.Background(), Config{
		API: srv.URL, Client: srv.Client(),
	}, time.Now(), &out)
	if err == nil || !strings.Contains(err.Error(), "list events") {
		t.Fatalf("err=%v want the JSON failure", err)
	}
}

// An unbuildable request URL surfaces through listStale — doReq's
// NewRequest failure branch.
func TestListStaleBadURL(t *testing.T) {
	_, err := listStale(context.Background(), http.DefaultClient,
		"http://bad url", time.Now())
	if err == nil || !strings.Contains(err.Error(), "list events") {
		t.Fatalf("err=%v want the request-build failure", err)
	}
}

// failBody is a response body that fails every Read — doReq's
// read-failure branch (distinct from the oversize-cap failure).
type failBody struct{}

func (failBody) Read([]byte) (int, error) { return 0, errors.New("read boom") }
func (failBody) Close() error             { return nil }

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestListStaleBodyReadError(t *testing.T) {
	client := &http.Client{Transport: rtFunc(
		func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       failBody{},
				Request:    r,
			}, nil
		})}
	_, err := listStale(context.Background(), client, "http://fake", time.Now())
	if err == nil || !strings.Contains(err.Error(), "list events") {
		t.Fatalf("err=%v want the body-read failure", err)
	}
}

// A ctx dying mid-backoff aborts the retry instead of burning the
// budget — the detail names the abort, not a give-up.
func TestDeleteAbortsRetryOnCancelledCtx(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	saw := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			close(saw)
			w.WriteHeader(http.StatusTooManyRequests)
		}))
	defer srv.Close()
	// Cancel shortly after the 429 is served — the response round
	// trip finishes in ~ms while the backoff sleeps 500ms, so the
	// ctx dies inside sleepCtx: the aborted-retry branch, not the
	// transport-error branch a pre-cancelled request would hit.
	go func() { <-saw; time.Sleep(100 * time.Millisecond); cancel() }()
	ok, detail := deleteOne(ctx, srv.Client(), srv.URL, "/x")
	if ok {
		t.Fatal("cancelled retry reported ok")
	}
	if !strings.Contains(detail, "aborted retrying HTTP 429") {
		t.Fatalf("detail=%q want aborted-retrying", detail)
	}
}

// retryDelay clamps everything at the cap: a huge server Retry-After
// AND a shift-overflowing attempt count both land on 30s.
func TestRetryDelayCapClamp(t *testing.T) {
	hdr := http.Header{"Retry-After": []string{"999"}}
	if got := retryDelay(hdr, 0); got != deleteBackoffCap {
		t.Fatalf("Retry-After 999 = %v want %v", got, deleteBackoffCap)
	}
	if got := retryDelay(nil, 62); got != deleteBackoffCap {
		t.Fatalf("overflow attempt = %v want %v", got, deleteBackoffCap)
	}
}

// sleepCtx: false when ctx dies first, true when the delay elapses.
func TestSleepCtx(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if sleepCtx(ctx, time.Hour) {
		t.Fatal("sleepCtx on a dead ctx returned true")
	}
	if !sleepCtx(context.Background(), 0) {
		t.Fatal("elapsed sleep returned false")
	}
}

// deleteAll's feed loop stops sending on ctx.Done — with no workers
// draining jobs the select can only take the cancel branch.
func TestDeleteAllStopsFeedingOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ok, errs, firstErr := deleteAll(ctx, http.DefaultClient,
		"http://fake", []string{"/a", "/b"}, 0)
	if ok != 0 || errs != 0 || firstErr != "" {
		t.Fatalf("deleteAll = %d,%d,%q want 0,0,\"\"", ok, errs, firstErr)
	}
}
