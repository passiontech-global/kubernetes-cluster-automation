// concourse_test.go — the shared fake ATC and the getJSON transport
// tests. atcStub fakes the index endpoints and records check-webhook
// calls plus per-path hit counts; slowATC parks the pipelines listing
// for the singleflight scenarios; waitInFlight waits on a handler's
// entered signal. The scenario suites live in auth_test.go,
// index_test.go and match_test.go.
package concourse

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// atcStub fakes the index endpoints and records check-webhook calls
// plus per-path hit counts. All mutable state is mutex-guarded —
// httptest handlers run on server goroutines.
type atcStub struct {
	srv    *httptest.Server
	mu     sync.Mutex
	checks []string
	hits   map[string]int    // path -> request count
	routes map[string]string // path -> JSON body
	fails  map[string]int    // path -> status to force
}

func newATCStub(t *testing.T, routes map[string]string) *atcStub {
	a := &atcStub{
		routes: routes,
		fails:  map[string]int{},
		hits:   map[string]int{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.hits[r.URL.Path]++
		status, fail := a.fails[r.URL.Path]
		body, routed := a.routes[r.URL.Path]
		isCheck := strings.HasSuffix(r.URL.Path, "/check/webhook")
		if isCheck {
			a.checks = append(a.checks, r.URL.String())
		}
		a.mu.Unlock()

		switch {
		case fail:
			w.WriteHeader(status)
		case routed:
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, body)
		case isCheck:
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	a.srv = httptest.NewServer(mux)
	t.Cleanup(a.srv.Close)
	return a
}

func (a *atcStub) hitCount(path string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.hits[path]
}

func (a *atcStub) checksList() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.checks...)
}

func (a *atcStub) fail(path string, status int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.fails[path] = status
}

func (a *atcStub) unfail(path string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.fails, path)
}

func (a *atcStub) setRoute(path, body string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.routes[path] = body
}

const (
	pipelinesBody = `[{"name":"p1"},{"name":"p2"}]`
	p1Body        = `[
		{"name":"repo-git","type":"git","source":{"uri":"git@github.com:org/repo.git"}},
		{"name":"repo-pr","type":"github-pr","source":{"repository":"org/repo"}},
		{"name":"other","type":"git","source":{"uri":"https://github.com/org/other"}},
		{"name":"norepo","type":"time","source":{"interval":"1h"}}
	]`
	p2Body = `[{"name":"repo-https","type":"git","source":{"uri":"https://github.com/org/repo"}}]`
)

func stubRoutes() map[string]string {
	return map[string]string{
		"/api/v1/teams/main/pipelines":              pipelinesBody,
		"/api/v1/teams/main/pipelines/p1/resources": p1Body,
		"/api/v1/teams/main/pipelines/p2/resources": p2Body,
	}
}

// slowATC serves stubRoutes() except the pipelines listing, which
// blocks until release is closed — simulating an ATC that answers
// slowly enough that, under the old lock-held fetch, every concurrent
// caller would serialize behind it. entered is signaled (capacity 1,
// non-blocking) each time a request crosses the blockFrom hit into
// the parked pipelines handler: blockFrom 2 = only refetches park,
// the warm-up passes; 1 = cold-start park. pipelinesHits counts every
// pipelines-list request the client made.
func slowATC(t *testing.T, release chan struct{},
	blockFrom int) (*httptest.Server, <-chan struct{}, *atomic.Int64) {
	entered := make(chan struct{}, 1)
	var pipelinesHits atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/teams/main/pipelines", func(w http.ResponseWriter, r *http.Request) {
		hits := pipelinesHits.Add(1)
		if hits >= int64(blockFrom) {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-release
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, pipelinesBody)
	})
	for path, body := range stubRoutes() {
		if path == "/api/v1/teams/main/pipelines" {
			continue
		}
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, body)
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, entered, &pipelinesHits
}

// waitInFlight blocks until a request has entered the slow ATC's
// parked pipelines handler — the channel signal that replaced the old
// millisecond poll loop.
func waitInFlight(t *testing.T, entered <-chan struct{}) {
	t.Helper()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("fetch never reached the ATC")
	}
}

func TestGetJSONNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Team: "main"}
	var out []any
	if err := c.getJSON(t.Context(), "/x", &out); err == nil {
		t.Fatal("getJSON(401) want error")
	}
}

func TestGetJSONBodyOverCapFails(t *testing.T) {
	// A 2xx body longer than maxJSONBody (a wedged ATC streaming
	// forever) must fail the decode instead of being buffered whole.
	// The stub writes a small chunk on repeat, so the test itself
	// never holds more than one chunk in memory.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		chunk := []byte(strings.Repeat("a", 64<<10))
		for written := 0; written <= maxJSONBody; written += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return // client stopped reading once the cap was hit
			}
		}
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Team: "main"}
	var out []any
	if err := c.getJSON(t.Context(), "/x", &out); err == nil {
		t.Fatal("getJSON over-cap body want error")
	}
}

func TestGetJSONDecodes2xxBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/sky/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"n":2}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Team: "main"}
	var out struct {
		OK bool `json:"ok"`
		N  int  `json:"n"`
	}
	if err := c.getJSON(t.Context(), "/x", &out); err != nil {
		t.Fatal(err)
	}
	if !out.OK || out.N != 2 {
		t.Fatalf("decoded=%+v want {OK:true N:2}", out)
	}
}

func TestGetJSONDrainsBodyForKeepAliveReuse(t *testing.T) {
	// A 2xx body the decoder does not consume to EOF must be drained
	// before the body closes — leftover bytes make http.Transport drop
	// the keep-alive connection, so every later call re-dials.
	// The payload is written in two flushes: the JSON value first
	// (larger than the decoder's initial buffer, so it must refill),
	// and the trailing newline only after the decode has finished —
	// bytes that only the post-decode drain can pick up.
	//
	// The 50ms hold is pacing, not synchronization: the trailing
	// newline must land strictly BETWEEN the decode consuming the
	// value and the drain reading the rest, and the client exposes no
	// signal at that point — writing it earlier makes the decoder
	// buffer it (the pin goes vacuous), later and the connection is
	// dropped before the drain runs.
	var conns atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/x", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"pad":"` + strings.Repeat("p", 700) + `"}`))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		time.Sleep(50 * time.Millisecond) // let the decode finish the value
		_, _ = w.Write([]byte("\n"))      // trailing bytes past the JSON value
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.Config.ConnState = func(_ net.Conn, cs http.ConnState) {
		if cs == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, Team: "main"}
	for range 3 {
		var out struct {
			Pad string `json:"pad"`
		}
		if err := c.getJSON(t.Context(), "/x", &out); err != nil {
			t.Fatal(err)
		}
		if len(out.Pad) != 700 {
			t.Fatalf("decoded pad=%d bytes want 700", len(out.Pad))
		}
	}
	if got := conns.Load(); got != 1 {
		t.Fatalf("TCP connections=%d want 1 (keep-alive reuse requires the body drained)", got)
	}
}
