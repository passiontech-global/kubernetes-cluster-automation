package httpx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// New must bind synchronously: Addr answers (even for ":0") and a
// request round-trips before and after a graceful Shutdown, whose
// serve channel folds http.ErrServerClosed into nil.
func TestBindsAndServes(t *testing.T) {
	var hits atomic.Int64
	srv, err := New("127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}), Opts{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if srv.Addr() == "" || !strings.Contains(srv.Addr(), ":") {
		t.Fatalf("Addr()=%q, want a bound host:port", srv.Addr())
	}

	served := srv.Serve()
	resp, err := http.Get("http://" + srv.Addr() + "/probe")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := <-served; err != nil {
		t.Fatalf("serve after graceful shutdown = %v, want nil", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits=%d, want 1", hits.Load())
	}
}

// Shutdown must let in-flight requests finish instead of cutting them:
// the client started before Shutdown still gets its full response, and
// only then does the serve loop end.
func TestShutdownDrainsInFlightRequest(t *testing.T) {
	started := make(chan struct{})
	srv, err := New("127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		time.Sleep(150 * time.Millisecond) // Shutdown lands inside this window
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("drained"))
	}), Opts{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	served := srv.Serve()

	type result struct {
		status int
		body   string
		err    error
	}
	resCh := make(chan result, 1)
	go func() {
		cl := &http.Client{Timeout: 5 * time.Second}
		resp, err := cl.Get("http://" + srv.Addr() + "/slow")
		if err != nil {
			resCh <- result{err: err}
			return
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		resCh <- result{status: resp.StatusCode, body: string(body)}
	}()

	<-started
	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown during in-flight request: %v", err)
	}
	res := <-resCh
	if res.err != nil {
		t.Fatalf("in-flight request failed during drain: %v", res.err)
	}
	if res.status != http.StatusOK || res.body != "drained" {
		t.Fatalf("in-flight request got status=%d body=%q, want 200/drained", res.status, res.body)
	}
	if err := <-served; err != nil {
		t.Fatalf("serve = %v, want nil", err)
	}
}

// A ctx without a deadline gets the server's shutdown budget: with a
// handler parked past the budget, Shutdown must return
// context.DeadlineExceeded after roughly the budget, not hang forever.
func TestShutdownBudgetRespected(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	srv, err := New("127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release // parked far beyond the budget
	}), Opts{ShutdownBudget: 100 * time.Millisecond})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv.Serve()

	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		cl := &http.Client{Timeout: 5 * time.Second}
		resp, _ := cl.Get("http://" + srv.Addr() + "/stuck")
		if resp != nil {
			resp.Body.Close()
		}
	}()
	<-started

	start := time.Now()
	err = srv.Shutdown(context.Background())
	elapsed := time.Since(start)
	close(release) // unstick the handler so the test can end
	<-clientDone

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown err=%v, want context.DeadlineExceeded", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Shutdown took %v; 100ms budget not respected", elapsed)
	}
}

// Timeout wraps a slow route so it answers 503 with the given message
// once the route budget expires, instead of holding the connection.
func TestTimeoutWrapsRoute(t *testing.T) {
	handler := Timeout(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(200 * time.Millisecond) // far past the route budget
		}),
		20*time.Millisecond, "probe timed out",
	)
	srv, err := New("127.0.0.1:0", handler, Opts{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	served := srv.Serve()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
		<-served
	}()

	resp, err := http.Get(fmt.Sprintf("http://%s/slow", srv.Addr()))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", resp.StatusCode)
	}
	if string(body) != "probe timed out" {
		t.Fatalf("body=%q, want probe timed out", body)
	}
}
