package httpx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
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

// A bound-but-never-Served Server still owns a socket: Shutdown must
// close the listener itself (http.Server.Shutdown cannot see a
// listener it was never handed), Addr must go empty, and a later
// Serve must resolve nil rather than hang or panic. Repeated
// teardown must be safe.
func TestShutdownBeforeServeClosesListener(t *testing.T) {
	srv, err := New("127.0.0.1:0", http.NotFoundHandler(), Opts{})
	if err != nil {
		t.Fatal(err)
	}
	addr := srv.Addr()
	if addr == "" {
		t.Fatal("Addr empty before Serve")
	}

	// Shutdown BEFORE the first Serve — the bound listener must be
	// released by teardown itself, and the later Serve must resolve
	// nil on the already-closed server rather than accepting.
	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if got := srv.Addr(); got != "" {
		t.Fatalf("Addr after Shutdown = %q, want empty", got)
	}
	done := srv.Serve()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve result after pre-Serve Shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serve channel never resolved")
	}
	// The port must actually be released.
	if conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatal("listener still accepting after Shutdown")
	}

	// Repeated teardown is a no-op, and Serve-after-teardown resolves
	// nil instead of accepting on the dead listener.
	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("second Shutdown: %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("Close after Shutdown: %v", err)
	}
	done2 := srv.Serve()
	select {
	case err := <-done2:
		if err != nil {
			t.Fatalf("Serve after teardown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("post-teardown Serve hung")
	}
}

// Close must release the socket immediately — no drain — and be
// safe before Serve, during serving, and repeated.
func TestCloseImmediate(t *testing.T) {
	srv, err := New("127.0.0.1:0", http.NotFoundHandler(), Opts{})
	if err != nil {
		t.Fatal(err)
	}
	addr := srv.Addr()
	done := srv.Serve()

	start := time.Now()
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Close blocked for %v", elapsed)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serve channel never resolved after Close")
	}
	if conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatal("listener still accepting after Close")
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// Opts.IdleTimeout must land on the http.Server — an unset value
// would inherit ReadHeaderTimeout (10s) via net/http's derivation
// and sever keep-alive connections every scrape interval.
func TestIdleTimeoutApplied(t *testing.T) {
	srv, err := New("127.0.0.1:0", http.NotFoundHandler(), Opts{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()
	if srv.srv.IdleTimeout != DefaultIdleTimeout {
		t.Fatalf("IdleTimeout = %v, want %v", srv.srv.IdleTimeout, DefaultIdleTimeout)
	}
	custom, err := New("127.0.0.1:0", http.NotFoundHandler(), Opts{IdleTimeout: 7 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = custom.Close() }()
	if custom.srv.IdleTimeout != 7*time.Second {
		t.Fatalf("custom IdleTimeout = %v", custom.srv.IdleTimeout)
	}
}

func TestOptsTimeoutsAndPooledTransport(t *testing.T) {
	srv, err := New("127.0.0.1:0", http.NotFoundHandler(), Opts{
		ReadTimeout:    3 * time.Second,
		WriteTimeout:   4 * time.Second,
		MaxHeaderBytes: 64 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()
	if srv.srv.ReadTimeout != 3*time.Second || srv.srv.WriteTimeout != 4*time.Second || srv.srv.MaxHeaderBytes != 64<<10 {
		t.Fatalf("server opts mismatch: read=%v write=%v maxhdr=%d", srv.srv.ReadTimeout, srv.srv.WriteTimeout, srv.srv.MaxHeaderBytes)
	}

	tr := PooledTransport(16, nil)
	if tr.MaxIdleConnsPerHost != 16 || tr.MaxIdleConns != 100 {
		t.Fatalf("PooledTransport idle counts: perHost=%d total=%d", tr.MaxIdleConnsPerHost, tr.MaxIdleConns)
	}
	trDefault := PooledTransport(0, nil)
	if trDefault.MaxIdleConnsPerHost != 0 {
		t.Fatalf("PooledTransport(0) perHost=%d, want 0", trDefault.MaxIdleConnsPerHost)
	}
}

// Close racing Serve must resolve the serve channel cleanly —
// net/http's "use of closed network connection" is teardown, not a
// serve failure, and the closed flag must make a LATER Serve call
// resolve nil instead of accepting on the dead listener. Run under
// -race: the flag lives under s.mu.
func TestCloseRacesServe(t *testing.T) {
	for i := 0; i < 20; i++ {
		srv, err := New("127.0.0.1:0", http.NotFoundHandler(), Opts{})
		if err != nil {
			t.Fatal(err)
		}
		done := srv.Serve()
		// Hammer teardown from two goroutines while Serve may still
		// be binding/accepting — every interleaving must end with a
		// nil serve result and a released port.
		var wg sync.WaitGroup
		for _, fn := range []func(){
			func() { _ = srv.Close() },
			func() { _ = srv.Shutdown(context.Background()) },
		} {
			wg.Add(1)
			go func(f func()) {
				defer wg.Done()
				f()
			}(fn)
		}
		wg.Wait()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("iter %d: serve result = %v, want nil", i, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("iter %d: serve channel never resolved", i)
		}
	}
}
