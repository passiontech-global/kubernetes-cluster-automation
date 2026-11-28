// concourse_test.go — the shared fake ATC and the getJSON transport
// tests. atcStub fakes the index endpoints and records check-webhook
// calls plus per-path hit counts; slowATC parks the pipelines listing
// for the singleflight scenarios; waitInFlight waits on a handler's
// entered signal. The scenario suites live in auth_test.go,
// index_test.go and match_test.go.
package concourse

import (
	"errors"
	"fmt"
	"io"
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
	p1Body        = `{"config":{"resources":[
		{"name":"repo-git","type":"git","source":{"uri":"git@github.com:org/repo.git"}},
		{"name":"repo-pr","type":"github-pr","source":{"repository":"org/repo"}},
		{"name":"other","type":"git","source":{"uri":"https://github.com/org/other"}},
		{"name":"norepo","type":"time","source":{"interval":"1h"}}
	]}}`
	p2Body = `{"config":{"resources":[{"name":"repo-https","type":"git","source":{"uri":"https://github.com/org/repo"}}]}}`
)

func stubRoutes() map[string]string {
	return map[string]string{
		"/api/v1/teams/main/pipelines":           pipelinesBody,
		"/api/v1/teams/main/pipelines/p1/config": p1Body,
		"/api/v1/teams/main/pipelines/p2/config": p2Body,
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

type closeTrackingBody struct {
	rc            io.ReadCloser
	mu            sync.Mutex
	bytesRead     int
	sawEOF        bool
	closed        bool
	bytesAtClose  int
	sawEOFAtClose bool
}

func (b *closeTrackingBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	b.mu.Lock()
	b.bytesRead += n
	if errors.Is(err, io.EOF) {
		b.sawEOF = true
	}
	b.mu.Unlock()
	return n, err
}

func (b *closeTrackingBody) Close() error {
	b.mu.Lock()
	if !b.closed {
		b.closed = true
		b.bytesAtClose = b.bytesRead
		b.sawEOFAtClose = b.sawEOF
	}
	b.mu.Unlock()
	return b.rc.Close()
}

type drainTrackingTransport struct {
	base http.RoundTripper
	mu   sync.Mutex
	req1 *closeTrackingBody
}

func (t *drainTrackingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if req.URL.Path == "/x" {
		t.mu.Lock()
		if t.req1 == nil {
			tracked := &closeTrackingBody{rc: resp.Body}
			t.req1 = tracked
			resp.Body = tracked
		}
		t.mu.Unlock()
	}
	return resp, nil
}

func TestGetJSONDrainsBodyForKeepAliveReuse(t *testing.T) {
	// A 2xx body the decoder aborts early on (trailing bytes past the
	// first JSON value) must be drained synchronously before Close:
	// in Go 1.27, http.Transport drains <=256 KiB bodies asynchronously
	// in maybeDrainBody after Close() (maxPostCloseReadBytes = 256<<10),
	// which masks missing drains most of the time when only connection
	// count is checked. Wrapping Request 1's resp.Body proves
	// concourse.go's bounded post-decode drain consumes the full 32 KiB
	// tail to EOF BEFORE Close() is invoked, while also verifying both
	// requests share 1 TCP connection.
	payload1 := `{"ok":true}{"trailing":"` + strings.Repeat("x", 32<<10) + `"}`
	var conns atomic.Int64
	var reqNum atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/x", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if reqNum.Add(1) == 1 {
			_, _ = w.Write([]byte(payload1))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.Config.ConnState = func(_ net.Conn, cs http.ConnState) {
		if cs == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()

	baseTR := &http.Transport{}
	defer baseTR.CloseIdleConnections()
	rt := &drainTrackingTransport{base: baseTR}
	c := &Client{
		BaseURL: srv.URL,
		Team:    "main",
		HTTP:    &http.Client{Transport: rt},
	}
	var out struct {
		OK bool `json:"ok"`
	}
	if err := c.getJSON(t.Context(), "/x", &out); err == nil {
		t.Fatal("request 1 with trailing JSON document want decode error")
	}

	rt.mu.Lock()
	req1Body := rt.req1
	rt.mu.Unlock()
	if req1Body == nil {
		t.Fatal("request 1 body was not captured by RoundTripper")
	}
	req1Body.mu.Lock()
	closed := req1Body.closed
	bytesAtClose := req1Body.bytesAtClose
	sawEOFAtClose := req1Body.sawEOFAtClose
	req1Body.mu.Unlock()
	if !closed {
		t.Fatal("request 1 body was not closed")
	}
	if !sawEOFAtClose || bytesAtClose != len(payload1) {
		t.Fatalf("at Close(): sawEOF=%v bytesRead=%d want sawEOF=true bytesRead=%d (body not synchronously drained before Close)",
			sawEOFAtClose, bytesAtClose, len(payload1))
	}

	out.OK = false
	if err := c.getJSON(t.Context(), "/x", &out); err != nil {
		t.Fatalf("request 2 failed: %v", err)
	}
	if !out.OK {
		t.Fatal("request 2 decoded OK=false want true")
	}
	if got := conns.Load(); got != 1 {
		t.Fatalf("TCP connections=%d want 1 (keep-alive reuse requires the body drained)", got)
	}
}

func TestGetJSONToleratesInvalidUTF8AndDuplicateKeys(t *testing.T) {
	t.Parallel()
	body := append([]byte(`[{"name":"p1","name":"p2","extra":"bad`), 0xff)
	body = append(body, []byte(`","surrogate":"\uD800"}]`)...)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/sky/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, Team: "main"}
	var out []struct {
		Name string `json:"name"`
	}
	if err := c.getJSON(t.Context(), "/api/v1/teams/main/pipelines", &out); err != nil {
		t.Fatalf("getJSON failed on invalid UTF-8 / duplicate keys: %v", err)
	}
	if len(out) != 1 || out[0].Name != "p2" {
		t.Fatalf("decoded=%+v want [{Name:p2}]", out)
	}
}

func TestSafeBaseURL(t *testing.T) {
	cases := []struct {
		name string
		base string
		want string
	}{
		{"plain", "https://ci.example.com", "https://ci.example.com"},
		{"strips_userinfo", "https://user:secret@ci.example.com/path", "https://ci.example.com/path"},
		{"invalid_url", "://bad-url", "://bad-url"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{BaseURL: tc.base}
			if got := c.SafeBaseURL(); got != tc.want {
				t.Fatalf("SafeBaseURL() = %q, want %q", got, tc.want)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSafeBaseURLStripsUserinfoInRequests(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sky/issuer/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":1800}`))
		case "/api/v1/teams/main/pipelines":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[]`))
		case "/api/v1/teams/main/pipelines/p1/resources/r1/check/webhook":
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	baseWithUserinfo := strings.Replace(srv.URL, "http://", "http://secretuser:secretpass@", 1)
	var mu sync.Mutex
	var seenURLs []string
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.User != nil {
			t.Errorf("request %s carried URL userinfo %v", r.URL.Path, r.URL.User)
		}
		raw := r.URL.String()
		if strings.Contains(raw, "secretuser") || strings.Contains(raw, "secretpass") {
			t.Errorf("request URL leaked userinfo: %q", raw)
		}
		mu.Lock()
		seenURLs = append(seenURLs, raw)
		mu.Unlock()
		return srv.Client().Transport.RoundTrip(r)
	})

	c := &Client{
		BaseURL:      baseWithUserinfo + "/",
		Team:         "main",
		User:         "u",
		Password:     "p",
		WebhookToken: "whtok",
		HTTP:         &http.Client{Transport: rt},
	}

	var out []any
	if err := c.getJSON(t.Context(), "/api/v1/teams/main/pipelines", &out); err != nil {
		t.Fatalf("getJSON: %v", err)
	}
	if a := c.ensureAuth(); a.baseURL != srv.URL || a.safeBaseURL != srv.URL {
		t.Fatalf("ensureAuth URLs = (%q, %q), want (%q, %q)", a.baseURL, a.safeBaseURL, srv.URL, srv.URL)
	}
	code, err := c.CheckWebhook(t.Context(), Resource{Pipeline: "p1", Name: "r1"})
	if err != nil || code != http.StatusCreated {
		t.Fatalf("CheckWebhook = (%d, %v), want (201, nil)", code, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seenURLs) != 3 {
		t.Fatalf("saw %d requests (%v), want 3 (token, getJSON, CheckWebhook)", len(seenURLs), seenURLs)
	}
}
