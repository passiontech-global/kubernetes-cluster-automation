package concourse

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNormalizeRepo(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"git@github.com:org/repo.git", "org/repo"},
		{"git@github.com:org/repo", "org/repo"},
		{"https://github.com/org/repo.git", "org/repo"},
		{"https://github.com/org/repo", "org/repo"},
		{"https://github.com/org/repo/", "org/repo"},
		{"https://github.com/org/repo.git/", "org/repo"},
		{"http://github.com/org/repo", "org/repo"},
		{"ssh://git@github.com/org/repo.git", "org/repo"},
		{"ssh://git@github.com:22/org/repo.git", "org/repo"},
		{"github.com:443/org/repo", "org/repo"},
		// Digits after the scp colon that aren't followed by a slash
		// are part of the repo name, not a port.
		{"git@github.com:22org/repo", "22org/repo"},
		{"git://github.com/org/repo", "org/repo"},
		{"github.com/org/repo", "org/repo"},
		{"org/repo", "org/repo"},
		{"org/repo.git", "org/repo"},
		{"Org/Repo", "org/repo"},
		{"  git@github.com:Org/Repo.git  ", "org/repo"},
		{"", ""},
		{"  ", ""},
		// A lookalike host must not collapse to "org/repo" — the
		// boundary check keeps it from matching a real resource.
		{"https://notgithub.com/org/repo", "https://notgithub.com/org/repo"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := NormalizeRepo(tc.in); got != tc.want {
				t.Fatalf("NormalizeRepo(%q)=%q want %q", tc.in, got, tc.want)
			}
		})
	}
}

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

func TestResourcesBuildsIndex(t *testing.T) {
	stub := newATCStub(t, stubRoutes())
	c := &Client{BaseURL: stub.srv.URL, Team: "main", User: "u", Password: "p"}

	index, err := c.Resources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := map[Resource]bool{
		{Pipeline: "p1", Name: "repo-git", Type: "git", Repo: "org/repo"}:      true,
		{Pipeline: "p1", Name: "repo-pr", Type: "github-pr", Repo: "org/repo"}: true,
		{Pipeline: "p1", Name: "other", Type: "git", Repo: "org/other"}:        true,
		{Pipeline: "p2", Name: "repo-https", Type: "git", Repo: "org/repo"}:    true,
	}
	if len(index) != len(want) {
		t.Fatalf("index=%+v want %d resources", index, len(want))
	}
	for _, r := range index {
		if !want[r] {
			t.Fatalf("unexpected resource in index: %+v", r)
		}
	}
}

func TestResourcesCachesUntilTTL(t *testing.T) {
	stub := newATCStub(t, stubRoutes())
	c := &Client{
		BaseURL:  stub.srv.URL,
		Team:     "main",
		IndexTTL: time.Hour,
	}
	if _, err := c.Resources(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Resources(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The second call within the TTL must not re-list pipelines.
	if got := stub.hitCount("/api/v1/teams/main/pipelines"); got != 1 {
		t.Fatalf("pipeline-list hits=%d want 1 (cache hit)", got)
	}
	// Even with the ATC now broken, the fresh cache wins.
	stub.fail("/api/v1/teams/main/pipelines", 500)
	if _, err := c.Resources(context.Background()); err != nil {
		t.Fatalf("cached Resources err=%v want nil (TTL)", err)
	}
	if got := stub.hitCount("/api/v1/teams/main/pipelines"); got != 1 {
		t.Fatalf("pipeline-list hits=%d want 1", got)
	}
}

func TestResourcesStaleFallback(t *testing.T) {
	stub := newATCStub(t, stubRoutes())
	c := &Client{BaseURL: stub.srv.URL, Team: "main", IndexTTL: time.Nanosecond}

	if _, err := c.Resources(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond) // expire the TTL
	stub.fail("/api/v1/teams/main/pipelines", 500)
	index, err := c.Resources(context.Background())
	if err != nil {
		t.Fatalf("stale fallback err=%v want nil", err)
	}
	if len(index) != 4 {
		t.Fatalf("stale index=%d resources want 4", len(index))
	}
}

func TestRefreshBypassesTTL(t *testing.T) {
	stub := newATCStub(t, stubRoutes())
	c := &Client{BaseURL: stub.srv.URL, Team: "main", IndexTTL: time.Hour}

	index, err := c.Resources(context.Background())
	if err != nil || len(index) != 4 {
		t.Fatalf("index=%v err=%v want 4 resources", index, err)
	}
	// A resource set after the index was cached; the TTL would hide
	// it from Resources for an hour.
	stub.setRoute("/api/v1/teams/main/pipelines/p2/resources",
		`[{"name":"new","type":"git","source":{"uri":"org/new"}}]`)
	// Past the forced-refresh throttle window.
	c.fetchedAt = time.Now().Add(-c.minRefreshInterval())

	fresh, err := c.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range fresh {
		if r.Pipeline == "p2" && r.Name == "new" && r.Repo == "org/new" {
			found = true
		}
	}
	if !found {
		t.Fatalf("fresh index %v missing new resource", fresh)
	}

	// A failed refresh keeps the previous index.
	c.fetchedAt = time.Now().Add(-c.minRefreshInterval())
	stub.fail("/api/v1/teams/main/pipelines", 500)
	if _, err := c.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh(500) want error")
	}
	if cached, _ := c.Resources(context.Background()); len(cached) != len(fresh) {
		t.Fatalf("index after failed refresh=%d want %d", len(cached), len(fresh))
	}
}

func TestRefreshThrottled(t *testing.T) {
	stub := newATCStub(t, stubRoutes())
	c := &Client{BaseURL: stub.srv.URL, Team: "main"}

	// The first Refresh always fetches (index never built).
	if _, err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	// An immediate second Refresh must not hit the ATC again —
	// zero-match deliveries throttle to MinRefreshInterval.
	index, err := c.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := stub.hitCount("/api/v1/teams/main/pipelines"); got != 1 {
		t.Fatalf("pipeline-list hits=%d want 1 (second Refresh throttled)", got)
	}
	if len(index) != 4 {
		t.Fatalf("throttled Refresh index=%d want 4", len(index))
	}
}

func TestEmptyIndexIsCached(t *testing.T) {
	stub := newATCStub(t, map[string]string{
		"/api/v1/teams/main/pipelines":              `[{"name":"p1"}]`,
		"/api/v1/teams/main/pipelines/p1/resources": `[]`,
	})
	c := &Client{BaseURL: stub.srv.URL, Team: "main", IndexTTL: time.Hour}

	index, err := c.Resources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if index == nil || len(index) != 0 {
		t.Fatalf("index=%v want non-nil empty", index)
	}
	// A healthy empty index still counts as fetched: the TTL holds
	// and a later expiry falls back to it instead of erroring.
	if _, err := c.Resources(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := stub.hitCount("/api/v1/teams/main/pipelines"); got != 1 {
		t.Fatalf("pipeline-list hits=%d want 1 (cache hit)", got)
	}
	stub.fail("/api/v1/teams/main/pipelines", 500)
	c.fetchedAt = time.Now().Add(-2 * c.ttl())
	if index, err := c.Resources(context.Background()); err != nil || index == nil {
		t.Fatalf("stale empty index=%v err=%v want non-nil, nil", index, err)
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
	_, err := c.CheckWebhook(context.Background(), Resource{
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
	status, err := c.CheckWebhook(context.Background(), Resource{
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
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `[]`)
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, Team: "main", User: "admin", Password: "pw"}
	var out []any
	if err := c.getJSON(context.Background(), "/x", &out); err != nil {
		t.Fatal(err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:pw"))
	if gotAuth != want {
		t.Fatalf("Authorization=%q want %q", gotAuth, want)
	}
}

func TestGetJSONNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Team: "main"}
	var out []any
	if err := c.getJSON(context.Background(), "/x", &out); err == nil {
		t.Fatal("getJSON(401) want error")
	}
}

func TestSourceRepo(t *testing.T) {
	if got := sourceRepo(map[string]any{"uri": "u", "repository": "r"}); got != "u" {
		t.Fatalf("uri precedence=%q want u", got)
	}
	if got := sourceRepo(map[string]any{"repository": "r"}); got != "r" {
		t.Fatalf("repository=%q want r", got)
	}
	if got := sourceRepo(map[string]any{"uri": 42}); got != "" {
		t.Fatalf("non-string=%q want empty", got)
	}
	if got := sourceRepo(nil); got != "" {
		t.Fatalf("nil=%q want empty", got)
	}
}
