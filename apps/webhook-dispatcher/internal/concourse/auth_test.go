package concourse

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mintAuth builds a bare atcAuth pointed at srv — no Client needed:
// mint only touches baseURL, the client transport and the form body.
func mintAuth(srv *httptest.Server) *atcAuth {
	return &atcAuth{
		client:  srv.Client(),
		baseURL: strings.TrimSuffix(srv.URL, "/"),
		user:    "u",
		pass:    "p",
		form:    "grant_type=password",
	}
}

func tokenBody(expiresIn string) string {
	return fmt.Sprintf(`{"access_token":"tok","token_type":"Bearer","expires_in":%s}`, expiresIn)
}

func TestMintExpiresInClamp(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		body    string
		wantMin time.Duration // expiry - now must be within [wantMin, wantMax]
		wantMax time.Duration
	}{
		{
			name:    "normal value honored",
			body:    tokenBody("1800"),
			wantMin: 29 * time.Minute,
			wantMax: 31 * time.Minute,
		},
		{
			// time.Duration(math.MaxInt64) * time.Second overflows
			// int64 and would wrap the expiry into the past — the
			// clamp must keep it within tokenMaxTTL.
			name:    "huge expires_in clamped to 24h, no overflow",
			body:    tokenBody(fmt.Sprint(math.MaxInt64)),
			wantMin: tokenMaxTTL - time.Minute,
			wantMax: tokenMaxTTL,
		},
		{
			name:    "just over the cap clamped to 24h",
			body:    tokenBody(fmt.Sprint(int64(30 * 24 * 3600))),
			wantMin: tokenMaxTTL - time.Minute,
			wantMax: tokenMaxTTL,
		},
		{
			name:    "zero falls back to default TTL",
			body:    tokenBody("0"),
			wantMin: tokenDefaultTTL - time.Minute,
			wantMax: tokenDefaultTTL,
		},
		{
			name:    "negative falls back to default TTL",
			body:    tokenBody("-5"),
			wantMin: tokenDefaultTTL - time.Minute,
			wantMax: tokenDefaultTTL,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			before := time.Now()
			_, expires, basic, err := mintAuth(srv).mint(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if basic {
				t.Fatal("mint latched basic mode, want bearer")
			}
			ttl := expires.Sub(before)
			if ttl < tc.wantMin || ttl > tc.wantMax+time.Minute {
				t.Fatalf("ttl=%v want [%v, %v]", ttl, tc.wantMin, tc.wantMax+time.Minute)
			}
		})
	}
}

func TestSameOriginRedirectPolicy(t *testing.T) {
	t.Parallel()
	policy := SameOriginRedirectPolicy("http://atc.internal:8080")

	t.Run("same-origin redirect allowed", func(t *testing.T) {
		via := []*http.Request{httptest.NewRequest(http.MethodPost, "http://atc.internal:8080/api/v1/x", nil)}
		req := httptest.NewRequest(http.MethodPost, "http://atc.internal:8080/api/v1/rewritten", nil)
		if err := policy(req, via); err != nil {
			t.Fatalf("same-origin redirect rejected: %v", err)
		}
	})
	t.Run("cross-origin redirect blocked", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://evil.example/path", nil)
		via := []*http.Request{httptest.NewRequest(http.MethodPost, "http://atc.internal:8080/api/v1/x", nil)}
		if err := policy(req, via); err == nil {
			t.Fatal("cross-origin redirect allowed — webhook_token would leak")
		}
	})
	t.Run("scheme change blocked", func(t *testing.T) {
		via := []*http.Request{httptest.NewRequest(http.MethodPost, "http://atc.internal:8080/x", nil)}
		req := httptest.NewRequest(http.MethodPost, "https://atc.internal:8080/x", nil)
		if err := policy(req, via); err == nil {
			t.Fatal("scheme-changing redirect allowed")
		}
	})
	t.Run("credential-free error", func(t *testing.T) {
		// The refusal message must not embed the full request URL —
		// only the redirect target's host.
		req := httptest.NewRequest(http.MethodPost,
			"http://evil.example/p?webhook_token=secret", nil)
		via := []*http.Request{httptest.NewRequest(http.MethodPost,
			"http://atc.internal:8080/api/v1/x?webhook_token=secret", nil)}
		err := policy(req, via)
		if err == nil {
			t.Fatal("cross-origin redirect allowed")
		}
		if msg := err.Error(); strings.Contains(msg, "secret") {
			t.Fatalf("redirect error leaks the token: %v", msg)
		}
	})
}

// TestCheckWebhookCrossOriginRedirectBlocked drives the policy end to
// end: the ATC answers the check-webhook POST with a redirect to
// another host; the client must refuse instead of replaying
// ?webhook_token= there.
func TestCheckWebhookCrossOriginRedirectBlocked(t *testing.T) {
	t.Parallel()
	atc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("webhook_token") == "" {
			http.Error(w, "missing token", http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, "http://evil.example/captured?"+r.URL.RawQuery,
			http.StatusFound)
	}))
	defer atc.Close()
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("cross-origin redirect followed — webhook_token=%q leaked", r.URL.Query().Get("webhook_token"))
		w.WriteHeader(http.StatusOK)
	}))
	defer evil.Close()

	c := &Client{
		BaseURL:      atc.URL,
		Team:         "main",
		WebhookToken: "secret",
		HTTP: &http.Client{
			CheckRedirect: SameOriginRedirectPolicy(atc.URL),
		},
	}
	code, err := c.CheckWebhook(t.Context(), Resource{Pipeline: "p", Name: "r"})
	if code != 0 || err == nil {
		t.Fatalf("CheckWebhook=(%d, %v), want (0, cross-origin error)", code, err)
	}
	if strings.Contains(fmt.Sprint(err), "secret") {
		t.Fatalf("error leaks the token: %v", err)
	}
}

// TestCheckWebhookSameOriginRedirectFollowed proves the policy keeps
// legitimate same-origin rewrites working.
func TestCheckWebhookSameOriginRedirectFollowed(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/teams/main/pipelines/p/resources/r/check/webhook",
		func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/api/v1/rewritten/check", http.StatusFound)
		})
	mux.HandleFunc("/api/v1/rewritten/check", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &Client{
		BaseURL:      srv.URL,
		Team:         "main",
		WebhookToken: "secret",
		HTTP: &http.Client{
			CheckRedirect: SameOriginRedirectPolicy(srv.URL),
		},
	}
	code, err := c.CheckWebhook(context.Background(), Resource{Pipeline: "p", Name: "r"})
	if err != nil {
		t.Fatal(err)
	}
	if code != http.StatusOK {
		t.Fatalf("status=%d want 200", code)
	}
}

func TestCheckWebhookErrorDoesNotLeakToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) {}))
	srv.Close() // force a transport error on the next request

	c := &Client{
		BaseURL:      srv.URL,
		Team:         "main",
		WebhookToken: "tok-secret-9",
	}
	_, err := c.CheckWebhook(t.Context(), Resource{
		Pipeline: "p1", Name: "r",
	})
	if err == nil {
		t.Fatal("want transport error")
	}
	// The raw *url.Error embeds the full URL — webhook_token and all —
	// which would leak into error logs.
	var ue *url.Error
	if errors.As(err, &ue) {
		t.Fatalf("error still wraps *url.Error (would leak token): %v", ue)
	}
	if strings.Contains(err.Error(), "tok-secret-9") {
		t.Fatalf("error leaks webhook token: %v", err)
	}
}

func TestCheckWebhookPostsToken(t *testing.T) {
	stub := newATCStub(t, stubRoutes())
	c := &Client{
		BaseURL:      stub.srv.URL,
		Team:         "main",
		WebhookToken: "tok-123",
	}
	status, err := c.CheckWebhook(t.Context(), Resource{
		Pipeline: "p1", Name: "repo-git", Type: "git", Repo: "org/repo",
	})
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusCreated {
		t.Fatalf("status=%d want 201", status)
	}
	want := "/api/v1/teams/main/pipelines/p1/resources/repo-git/check/webhook?webhook_token=tok-123"
	if checks := stub.checksList(); len(checks) != 1 || checks[0] != want {
		t.Fatalf("checks=%v want [%s]", checks, want)
	}
}

func TestGetJSONSendsBasicAuth(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/sky/") {
			// No token endpoint on this stub — auth latches basic.
			w.WriteHeader(http.StatusNotFound)
			return
		}
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `[]`)
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, Team: "main", User: "admin", Password: "pw"}
	var out []any
	if err := c.getJSON(t.Context(), "/x", &out); err != nil {
		t.Fatal(err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:pw"))
	if gotAuth != want {
		t.Fatalf("Authorization=%q want %q", gotAuth, want)
	}
}

// TestGetJSONBearerAuth: a web node with a token endpoint gets Bearer
// auth — the token is minted once via /sky/issuer/token with the fly
// client pair and reused; a 401 on the bearer request invalidates
// and re-mints exactly once.
func TestGetJSONBearerAuth(t *testing.T) {
	var mu sync.Mutex
	var authHeaders []string
	var mints int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/sky/issuer/token":
			mints++
			user, pass, _ := r.BasicAuth()
			if user != "fly" || pass != "Zmx5" {
				t.Errorf("token endpoint basic auth = %q/%q want fly/Zmx5", user, pass)
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"access_token":"tok-%d","expires_in":3600}`, mints)
		case "/api/v1/teams/main/pipelines":
			authHeaders = append(authHeaders, r.Header.Get("Authorization"))
			// First bearer call 401s once to exercise the
			// invalidate+remint path.
			if len(authHeaders) == 1 {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			fmt.Fprint(w, `[]`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	c := &Client{BaseURL: srv.URL, Team: "main", User: "u", Password: "p"}
	var out []struct {
		Name string `json:"name"`
	}
	if err := c.getJSON(t.Context(),
		"/api/v1/teams/main/pipelines", &out); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if mints != 2 {
		t.Fatalf("token mints=%d want 2 (initial + post-401 remint)", mints)
	}
	want := []string{"Bearer tok-1", "Bearer tok-2"}
	if len(authHeaders) != 2 {
		t.Fatalf("api auth headers=%v want %v", authHeaders, want)
	}
	for i := range want {
		if authHeaders[i] != want[i] {
			t.Fatalf("api auth[%d]=%q want %q", i, authHeaders[i], want[i])
		}
	}
}

func TestGetJSONDrains401RetryBodyForKeepAliveReuse(t *testing.T) {
	// The 401-retry path closes the response body before re-minting
	// and re-sending. If the 401 body is not drained (bounded) first,
	// the transport drops the keep-alive connection and the retry
	// re-dials — the failure this test pins.
	var conns atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/sky/issuer/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
	})
	attempt := 0
	var attemptMu sync.Mutex
	mux.HandleFunc("/api/v1/teams/main/x", func(w http.ResponseWriter, _ *http.Request) {
		attemptMu.Lock()
		attempt++
		n := attempt
		attemptMu.Unlock()
		if n == 1 {
			// 401 with a body bigger than the transport's read
			// buffer — bytes that only an explicit drain picks up.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(strings.Repeat("x", 8192)))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
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

	c := &Client{BaseURL: srv.URL, Team: "main", User: "u", Password: "p"}
	var out struct {
		OK bool `json:"ok"`
	}
	if err := c.getJSON(t.Context(), "/api/v1/teams/main/x", &out); err != nil {
		t.Fatal(err)
	}
	if !out.OK {
		t.Fatal("retry did not return the 2xx payload")
	}
	if got := conns.Load(); got != 1 {
		t.Fatalf("TCP connections=%d want 1 (the 401 body must be drained before the retry)", got)
	}
}
