package concourse

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
		via := []*http.Request{httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://atc.internal:8080/api/v1/x", nil)}
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://atc.internal:8080/api/v1/rewritten", nil)
		if err := policy(req, via); err != nil {
			t.Fatalf("same-origin redirect rejected: %v", err)
		}
	})
	t.Run("cross-origin redirect blocked", func(t *testing.T) {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://evil.example/path", nil)
		via := []*http.Request{httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://atc.internal:8080/api/v1/x", nil)}
		if err := policy(req, via); err == nil {
			t.Fatal("cross-origin redirect allowed — webhook_token would leak")
		}
	})
	t.Run("scheme change blocked", func(t *testing.T) {
		via := []*http.Request{httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://atc.internal:8080/x", nil)}
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://atc.internal:8080/x", nil)
		if err := policy(req, via); err == nil {
			t.Fatal("scheme-changing redirect allowed")
		}
	})
	t.Run("host case difference allowed", func(t *testing.T) {
		// DNS is case-insensitive — EqualFold must treat
		// ATC.INTERNAL as the same origin or every capitalized
		// redirect target would leak-block legitimate retries.
		via := []*http.Request{httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://atc.internal:8080/x", nil)}
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://ATC.INTERNAL:8080/x", nil)
		if err := policy(req, via); err != nil {
			t.Fatalf("case-different same host rejected: %v", err)
		}
	})
	t.Run("credential-free error", func(t *testing.T) {
		// The refusal message must not embed the full request URL —
		// only the redirect target's host.
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
			"http://evil.example/p?webhook_token=secret", nil)
		via := []*http.Request{httptest.NewRequestWithContext(t.Context(), http.MethodPost,
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
	// The redirect target is a LIVE server (evil.URL), not just a
	// hostname: if the client ever follows it, the handler below
	// fails the test and the credentials land on a real listener.
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("cross-origin redirect followed — webhook_token=%q leaked", r.URL.Query().Get("webhook_token"))
		w.WriteHeader(http.StatusOK)
	}))
	defer evil.Close()
	atc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("webhook_token") == "" {
			http.Error(w, "missing token", http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, evil.URL+"/captured?"+r.URL.RawQuery,
			http.StatusFound)
	}))
	defer atc.Close()

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

// TestAuthOIDCDecodeRemainsStrict verifies that auth.go:272 keeps
// strict encoding/json/v2 defaults (rejecting duplicate keys and
// invalid UTF-8 in OIDC token responses).
func TestAuthOIDCDecodeRemainsStrict(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body []byte
	}{
		{
			name: "duplicate_keys",
			body: []byte(`{"access_token":"tok-1","access_token":"tok-2","expires_in":3600}`),
		},
		{
			name: "invalid_utf8",
			body: append(append([]byte(`{"access_token":"tok-`), 0xff), []byte(`","expires_in":3600}`)...),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/sky/issuer/token" {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write(tc.body)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			defer srv.Close()

			_, _, _, err := mintAuth(srv).mint(t.Context())
			if err == nil {
				t.Fatalf("mint(%s) succeeded, want strict json/v2 decode error", tc.name)
			}
		})
	}
}

// TestBearerModeTreatsToken404And405AsTransient proves that once a
// Client has authenticated with Bearer, a transient 404/405 from both
// token endpoints (e.g. during an ATC rollout) fails that refresh
// without permanently downgrading to authModeBasic.
func TestBearerModeTreatsToken404And405AsTransient(t *testing.T) {
	var logBuf strings.Builder
	var logMu sync.Mutex
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&syncWriter{mu: &logMu, dst: &logBuf}, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	for _, failStatus := range []int{http.StatusNotFound, http.StatusMethodNotAllowed} {
		t.Run(fmt.Sprintf("status_%d", failStatus), func(t *testing.T) {
			var tokenStatus atomic.Int32
			tokenStatus.Store(http.StatusOK)
			var mintSeq atomic.Int32
			var basicSeen atomic.Bool
			var apiPhase atomic.Int32 // 0=ok, 1=401 once

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/sky/issuer/token", "/sky/token":
					st := int(tokenStatus.Load())
					if st != http.StatusOK {
						w.WriteHeader(st)
						return
					}
					n := mintSeq.Add(1)
					w.Header().Set("Content-Type", "application/json")
					_, _ = fmt.Fprintf(w, `{"access_token":"tok-%d","expires_in":3600}`, n)
				case "/api/v1/teams/main/x":
					if strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
						basicSeen.Store(true)
					}
					if apiPhase.CompareAndSwap(1, 0) {
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					if r.Header.Get("Authorization") == "" {
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"ok":true}`))
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer srv.Close()

			clk := newFakeClock()
			c := &Client{
				BaseURL:  srv.URL,
				Team:     "main",
				User:     "u",
				Password: "p",
				now:      clk.Now,
			}

			var out struct {
				OK bool `json:"ok"`
			}
			if err := c.getJSON(t.Context(), "/api/v1/teams/main/x", &out); err != nil {
				t.Fatalf("initial bearer getJSON failed: %v", err)
			}
			if a := c.authPtr.Load(); a == nil || a.mode != authModeBearer {
				t.Fatalf("mode=%v want authModeBearer", a.mode)
			}

			// Simulate token expiry + both /sky/* returning 404/405.
			tokenStatus.Store(int32(failStatus))
			clk.Advance(2 * time.Hour)
			if err := c.getJSON(t.Context(), "/api/v1/teams/main/x", &out); err == nil {
				t.Fatal("expected error when token endpoints 404/405 in bearer mode")
			}
			if basicSeen.Load() {
				t.Fatal("Basic auth was sent after bearer mode downgrade attempt")
			}
			if a := c.authPtr.Load(); a.mode != authModeBearer {
				t.Fatalf("mode downgraded to %v, want authModeBearer preserved", a.mode)
			}

			// Also verify 401 invalidation -> re-mint hitting 404/405 does not downgrade.
			tokenStatus.Store(http.StatusOK)
			if err := c.getJSON(t.Context(), "/api/v1/teams/main/x", &out); err != nil {
				t.Fatalf("recovery bearer getJSON failed: %v", err)
			}
			if mintSeq.Load() < 2 {
				t.Fatalf("mintSeq=%d want >= 2 after recovery", mintSeq.Load())
			}

			tokenStatus.Store(int32(failStatus))
			apiPhase.Store(1)
			if err := c.getJSON(t.Context(), "/api/v1/teams/main/x", &out); err == nil {
				t.Fatal("expected error on 401 re-mint when token endpoints 404/405")
			}
			if a := c.authPtr.Load(); a.mode != authModeBearer {
				t.Fatalf("mode downgraded on 401 remint to %v, want authModeBearer", a.mode)
			}
		})
	}

	logMu.Lock()
	logs := logBuf.String()
	logMu.Unlock()
	if !strings.Contains(logs, "keeping bearer auth") {
		t.Fatalf("expected Warn log keeping bearer auth, got:\n%s", logs)
	}
}

// TestBasicFallbackRecoversToAutoOn401WithBackoff verifies that a Client
// latched into authModeBasic resets to authModeAuto on an API 401,
// rate-limited by basicRecoveryBackoff, and recovers to Bearer when
// token endpoints become available.
func TestBasicFallbackRecoversToAutoOn401WithBackoff(t *testing.T) {
	var logBuf strings.Builder
	var logMu sync.Mutex
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&syncWriter{mu: &logMu, dst: &logBuf}, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	t.Run("recovers_to_bearer_on_first_401", func(t *testing.T) {
		var skyAvailable atomic.Bool
		var apiRequiresBearer atomic.Bool
		var skyHits atomic.Int32
		var authHeaders []string
		var mu sync.Mutex

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/sky/issuer/token":
				skyHits.Add(1)
				if !skyAvailable.Load() {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"recovered-tok","expires_in":3600}`))
			case "/sky/token":
				if !skyAvailable.Load() {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			case "/api/v1/teams/main/x":
				auth := r.Header.Get("Authorization")
				mu.Lock()
				authHeaders = append(authHeaders, auth)
				mu.Unlock()
				if apiRequiresBearer.Load() && !strings.HasPrefix(auth, "Bearer ") {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"ok":true}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()

		clk := newFakeClock()
		c := &Client{BaseURL: srv.URL, Team: "main", User: "u", Password: "p", now: clk.Now}
		var out struct {
			OK bool `json:"ok"`
		}
		// Initial call: /sky/* 404 -> latches Basic and succeeds.
		if err := c.getJSON(t.Context(), "/api/v1/teams/main/x", &out); err != nil {
			t.Fatalf("initial basic getJSON failed: %v", err)
		}
		if a := c.authPtr.Load(); a.mode != authModeBasic {
			t.Fatalf("mode=%v want authModeBasic", a.mode)
		}

		// ATC upgrades: /sky/issuer/token now 200 and API rejects Basic with 401.
		skyAvailable.Store(true)
		apiRequiresBearer.Store(true)
		out.OK = false
		if err := c.getJSON(t.Context(), "/api/v1/teams/main/x", &out); err != nil {
			t.Fatalf("recovery getJSON failed: %v", err)
		}
		if !out.OK {
			t.Fatal("expected OK=true after Basic -> Auto -> Bearer recovery")
		}
		if a := c.authPtr.Load(); a.mode != authModeBearer {
			t.Fatalf("mode=%v want authModeBearer", a.mode)
		}
		mu.Lock()
		lastAuth := authHeaders[len(authHeaders)-1]
		mu.Unlock()
		if lastAuth != "Bearer recovered-tok" {
			t.Fatalf("last Authorization=%q want Bearer recovered-tok", lastAuth)
		}
	})

	t.Run("backoff_suppresses_repeat_probes", func(t *testing.T) {
		var skyAvailable atomic.Bool
		var skyHits atomic.Int32

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/sky/issuer/token":
				skyHits.Add(1)
				if !skyAvailable.Load() {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"tok-after-backoff","expires_in":3600}`))
			case "/sky/token":
				w.WriteHeader(http.StatusNotFound)
			case "/api/v1/teams/main/x":
				if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"ok":true}`))
					return
				}
				w.WriteHeader(http.StatusUnauthorized)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()

		clk := newFakeClock()
		c := &Client{BaseURL: srv.URL, Team: "main", User: "u", Password: "p", now: clk.Now}
		var out struct {
			OK bool `json:"ok"`
		}
		// Call 1: /sky/* 404 -> latches Basic -> API 401 -> recoverBasicOn401()
		// resets to Auto (stamping basicRetryAt = now+1m) -> retry probes /sky/*
		// again (still 404 -> re-latches Basic) -> retry API 401 -> fails.
		if err := c.getJSON(t.Context(), "/api/v1/teams/main/x", &out); err == nil {
			t.Fatal("expected 401 error when /sky/* 404 and API 401")
		}
		hitsAfterCall1 := skyHits.Load()
		if hitsAfterCall1 != 2 {
			t.Fatalf("skyHits after call 1=%d want 2 (initial + recovery probe)", hitsAfterCall1)
		}

		// Call 2 inside backoff window: must NOT probe /sky/* again.
		clk.Advance(basicRecoveryBackoff / 2)
		if err := c.getJSON(t.Context(), "/api/v1/teams/main/x", &out); err == nil {
			t.Fatal("expected 401 error during backoff")
		}
		if got := skyHits.Load(); got != hitsAfterCall1 {
			t.Fatalf("skyHits inside backoff=%d want %d (backoff must suppress probe)", got, hitsAfterCall1)
		}

		// Call 3 after backoff expires: /sky/issuer/token now available -> recovers.
		skyAvailable.Store(true)
		clk.Advance(basicRecoveryBackoff)
		if err := c.getJSON(t.Context(), "/api/v1/teams/main/x", &out); err != nil {
			t.Fatalf("getJSON after backoff failed: %v", err)
		}
		if !out.OK {
			t.Fatal("expected OK=true after backoff recovery")
		}
		if got := skyHits.Load(); got != hitsAfterCall1+1 {
			t.Fatalf("skyHits after backoff=%d want %d", got, hitsAfterCall1+1)
		}
	})

	logMu.Lock()
	logs := logBuf.String()
	logMu.Unlock()
	if !strings.Contains(logs, "resetting to auto to probe token endpoints") {
		t.Fatalf("expected Warn log resetting to auto, got:\n%s", logs)
	}
}

type syncWriter struct {
	mu  *sync.Mutex
	dst *strings.Builder
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.dst.Write(p)
}

func TestAuthMintPanicRecoversAndUnblocksWaiters(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	c := &Client{
		BaseURL:  "http://atc.example",
		User:     "u",
		Password: "p",
		HTTP: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if calls.Add(1) == 1 {
					close(started)
					<-release
					panic("boom-mint")
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": {"application/json"}},
					Body:       io.NopCloser(strings.NewReader(tokenBody("1800"))),
					Request:    r,
				}, nil
			}),
		},
	}

	leaderErr := make(chan error, 1)
	go func() {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://atc.example/x", nil)
		_, err := c.authorize(t.Context(), req)
		leaderErr <- err
	}()
	<-started

	waiterErr := make(chan error, 1)
	go func() {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://atc.example/x", nil)
		_, err := c.authorize(t.Context(), req)
		waiterErr <- err
	}()
	// Give the waiter goroutine a moment to join a.flight before releasing the panic.
	time.Sleep(15 * time.Millisecond)
	close(release)

	for _, tc := range []struct {
		name string
		ch   <-chan error
	}{
		{"leader", leaderErr},
		{"waiter", waiterErr},
	} {
		select {
		case err := <-tc.ch:
			if err == nil || !strings.Contains(err.Error(), "panicked") {
				t.Fatalf("%s err = %v, want panic error", tc.name, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s deadlocked after mint panic", tc.name)
		}
	}

	// Subsequent authorize must clear the flight and mint cleanly.
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://atc.example/x", nil)
	tok, err := c.authorize(t.Context(), req)
	if err != nil {
		t.Fatalf("post-panic authorize err = %v", err)
	}
	if tok != "tok" {
		t.Fatalf("post-panic token = %q, want %q", tok, "tok")
	}
}

func TestMintOversizedBodyRejected(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + strings.Repeat("a", maxTokenBody) + `"}`))
	}))
	defer srv.Close()

	_, _, _, err := mintAuth(srv).mint(t.Context())
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("mint oversized body err = %v, want exceeds error", err)
	}
}
