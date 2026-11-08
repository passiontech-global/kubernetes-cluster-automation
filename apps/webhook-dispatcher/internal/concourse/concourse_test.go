package concourse

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
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
		// An all-numeric org after the scp colon is an ORG, not a
		// port — "git@host:path" carries no port syntax.
		{"git@github.com:12345/repo.git", "12345/repo"},
		{"git@github.com:12345/Repo", "12345/repo"},
		// Real ports on URL forms are still dropped.
		{"ssh://git@github.com:2222/org/repo.git", "org/repo"},
		{"https://github.com:8443/org/repo", "org/repo"},
		// Case is normalized everywhere — host match and the .git
		// strip must see the lowercased input.
		{"HTTPS://GitHub.COM/Org/Repo.GIT", "org/repo"},
		{"SSH://Git@GitHub.Com:2222/Org/Repo.Git", "org/repo"},
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
		// Mid-string matches are part of a longer hostname or of a
		// path — never stripped, whatever surrounds them.
		{"https://git.github.com/org/repo", "https://git.github.com/org/repo"},
		{"https://mygithub.com:8443/org/repo", "https://mygithub.com:8443/org/repo"},
		{"https://example.com/github.com/org/repo", "https://example.com/github.com/org/repo"},
		{"org/github.com", "org/github.com"},
		{"github.comorg/repo", "github.comorg/repo"},
		// The host must be followed by "/" or ":" — a different next
		// byte means the match is not the host (spoofed or bare host).
		{"https://github.com.evil.com/org/repo", "https://github.com.evil.com/org/repo"},
		{"git@github.com.evil.com:org/repo", "git@github.com.evil.com:org/repo"},
		{"github.com", "github.com"},
		// ":owner" scp forms strip the host from every legal position.
		{"github.com:owner/repo", "owner/repo"},
		{"ssh://github.com:owner/repo", "owner/repo"},
		{"GIT@GitHub.COM:Owner/Repo.Git", "owner/repo"},
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

func TestResourcesFailedRefreshBacksOff(t *testing.T) {
	stub := newATCStub(t, stubRoutes())
	c := &Client{BaseURL: stub.srv.URL, Team: "main", IndexTTL: time.Hour}

	if _, err := c.Resources(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Expire the cache artificially — the last fetch attempt is as
	// old as the cache itself (it IS the fetch that populated it) —
	// then break the ATC: the first call re-fetches, fails, and
	// serves the stale index.
	c.fetchedAt = time.Now().Add(-2 * c.ttl())
	c.lastAttemptAt = c.fetchedAt
	stub.fail("/api/v1/teams/main/pipelines", 500)
	index, err := c.Resources(context.Background())
	if err != nil || len(index) != 4 {
		t.Fatalf("stale fallback index=%v err=%v want 4, nil", index, err)
	}
	hits := stub.hitCount("/api/v1/teams/main/pipelines")

	// Repeat calls inside the TTL window must NOT re-hit the ATC —
	// without the attempt backoff each one would block on a doomed
	// fetch, serializing webhook traffic behind a dead ATC.
	for i := 0; i < 3; i++ {
		index, err := c.Resources(context.Background())
		if err != nil || len(index) != 4 {
			t.Fatalf("call %d: stale index=%v err=%v want 4, nil", i, index, err)
		}
	}
	if got := stub.hitCount("/api/v1/teams/main/pipelines"); got != hits {
		t.Fatalf("pipeline-list hits=%d want %d (failed fetch must back off)", got, hits)
	}
}

func TestFetchIndexRetainsResourcesForFailedPipeline(t *testing.T) {
	stub := newATCStub(t, stubRoutes())
	c := &Client{BaseURL: stub.srv.URL, Team: "main", IndexTTL: time.Nanosecond}

	if _, err := c.Resources(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond) // expire the TTL

	// p2's resource listing breaks while the pipeline still exists —
	// the refreshed index must carry p2's last-known resources over
	// instead of silently unregistering them (the fetch succeeds as
	// a whole, so a partial result would overwrite the cache).
	stub.fail("/api/v1/teams/main/pipelines/p2/resources", 500)
	index, err := c.Resources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(index) != 4 {
		t.Fatalf("index=%v want 4 resources (p2 retained)", index)
	}
	found := false
	for _, r := range index {
		if r.Pipeline == "p2" && r.Name == "repo-https" && r.Repo == "org/repo" {
			found = true
		}
	}
	if !found {
		t.Fatalf("index=%v missing p2's retained resource", index)
	}
}

func TestFetchIndexDropsPipelineGoneFromList(t *testing.T) {
	stub := newATCStub(t, stubRoutes())
	c := &Client{BaseURL: stub.srv.URL, Team: "main", IndexTTL: time.Nanosecond}

	if _, err := c.Resources(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond) // expire the TTL

	// p2 disappears from the pipeline list entirely — its stale
	// resources must NOT be retained (only a failed listing keeps
	// them; a truly deleted pipeline drops out).
	stub.setRoute("/api/v1/teams/main/pipelines", `[{"name":"p1"}]`)
	index, err := c.Resources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range index {
		if r.Pipeline == "p2" {
			t.Fatalf("index=%v still carries deleted pipeline p2", index)
		}
	}
	if len(index) != 3 {
		t.Fatalf("index=%v want 3 resources", index)
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
	// Past the forced-refresh throttle window — it keys on
	// lastForceRefreshAt, Refresh's own clock.
	c.lastForceRefreshAt = time.Now().Add(-c.minRefreshInterval())

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
	c.lastForceRefreshAt = time.Now().Add(-c.minRefreshInterval())
	stub.fail("/api/v1/teams/main/pipelines", 500)
	if _, err := c.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh(500) want error")
	}
	if cached, _ := c.Resources(context.Background()); len(cached) != len(fresh) {
		t.Fatalf("index after failed refresh=%d want %d", len(cached), len(fresh))
	}
}

func TestRefreshThrottleOwnsItsClock(t *testing.T) {
	// Refresh's throttle keys on lastForceRefreshAt, not lastAttemptAt:
	// a failed Resources refetch that just stamped its own backoff
	// attempt must not suppress a forced refresh — a zero-match
	// delivery needs the network, not the cached index.
	stub := newATCStub(t, stubRoutes())
	c := &Client{BaseURL: stub.srv.URL, Team: "main", IndexTTL: time.Hour}

	if _, err := c.Resources(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Age the cache and break the ATC: the next Resources refetches,
	// fails, stamps lastAttemptAt, and falls back to the stale index.
	c.mu.Lock()
	c.fetchedAt = time.Now().Add(-2 * c.ttl())
	c.mu.Unlock()
	stub.fail("/api/v1/teams/main/pipelines", 500)
	if _, err := c.Resources(context.Background()); err != nil {
		t.Fatalf("stale fallback err=%v want nil", err)
	}

	// lastForceRefreshAt is still zero — long past any throttle
	// window — so Refresh must attempt its own fetch and surface the
	// ATC failure instead of silently serving the cached index.
	if _, err := c.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh err=nil want error (throttled by Resources' attempt stamp)")
	}
}

func TestResourcesBackoffOwnsItsClock(t *testing.T) {
	// Symmetric: Resources' backoff keys on lastAttemptAt — a forced
	// Refresh stamping lastForceRefreshAt must not double as
	// Resources' backoff, or a recovering ATC would stay hidden behind
	// Refresh's stamp for a whole extra TTL window.
	stub := newATCStub(t, stubRoutes())
	c := &Client{BaseURL: stub.srv.URL, Team: "main"}

	// Warm through Refresh: lastForceRefreshAt is fresh, lastAttemptAt
	// stays zero.
	if _, err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Age the cache and break the ATC; Resources must attempt its own
	// (doomed) fetch rather than treat Refresh's stamp as its backoff.
	c.mu.Lock()
	c.fetchedAt = time.Now().Add(-2 * c.ttl())
	c.mu.Unlock()
	stub.fail("/api/v1/teams/main/pipelines", 500)
	hits := stub.hitCount("/api/v1/teams/main/pipelines")
	index, err := c.Resources(context.Background())
	if err != nil || len(index) != 4 {
		t.Fatalf("stale fallback index=%v err=%v want 4, nil", index, err)
	}
	if got := stub.hitCount("/api/v1/teams/main/pipelines"); got != hits+1 {
		t.Fatalf("pipeline-list hits=%d want %d (Resources must attempt its own fetch)",
			got, hits+1)
	}
}

func TestFetchIndexColdStartListingFailureErrors(t *testing.T) {
	// Cold start: the pipeline list succeeds but a per-pipeline
	// resource listing fails with nothing in the previous index to
	// carry over. The fetch must FAIL — caching the partial result
	// would stamp fetchedAt and answer 202/resources_matched:0 for
	// the TTL window, silently dropping build triggers.
	stub := newATCStub(t, stubRoutes())
	stub.fail("/api/v1/teams/main/pipelines/p1/resources", 500)
	c := &Client{BaseURL: stub.srv.URL, Team: "main", IndexTTL: time.Hour}

	if _, err := c.Resources(context.Background()); err == nil {
		t.Fatal("Resources want error — the index is incomplete")
	}
	if c.index != nil {
		t.Fatalf("c.index=%v want nil (incomplete index must not cache)", c.index)
	}
	// With the ATC recovered the next call retries (there is no
	// stale index to back off behind) and builds the real index.
	stub.unfail("/api/v1/teams/main/pipelines/p1/resources")
	index, err := c.Resources(context.Background())
	if err != nil {
		t.Fatalf("retry after recovery: err=%v want nil", err)
	}
	if len(index) != 4 {
		t.Fatalf("index=%d resources want 4", len(index))
	}
}

func TestFetchIndexNewPipelineListingFailureServesStale(t *testing.T) {
	// Warm cache: a pipeline that appeared since the last fetch has
	// no last-known resources, so its failed listing makes the whole
	// fetch fail — Resources then falls back to the stale index
	// rather than caching an incomplete view.
	stub := newATCStub(t, stubRoutes())
	c := &Client{BaseURL: stub.srv.URL, Team: "main", IndexTTL: time.Nanosecond}
	if _, err := c.Resources(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond) // expire the TTL

	// p3 is brand new (no prev data) and its listing 404s.
	stub.setRoute("/api/v1/teams/main/pipelines",
		`[{"name":"p1"},{"name":"p2"},{"name":"p3"}]`)
	index, err := c.Resources(context.Background())
	if err != nil {
		t.Fatalf("stale fallback err=%v want nil", err)
	}
	if len(index) != 4 {
		t.Fatalf("stale index=%d resources want 4", len(index))
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

func TestRefreshFailedAttemptBacksOff(t *testing.T) {
	stub := newATCStub(t, stubRoutes())
	c := &Client{BaseURL: stub.srv.URL, Team: "main"}

	// Warm the index, then age the last forced-refresh attempt out of
	// the throttle window and break the ATC: the next Refresh hits the
	// network, fails, and stamps lastForceRefreshAt.
	if _, err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.lastForceRefreshAt = time.Now().Add(-c.minRefreshInterval())
	stub.fail("/api/v1/teams/main/pipelines", 500)
	if _, err := c.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh(500) want error")
	}
	hits := stub.hitCount("/api/v1/teams/main/pipelines")

	// Refreshes inside the throttle window must serve the cached
	// index without another doomed network call — fetchedAt only
	// moves on success, so without the lastForceRefreshAt throttle
	// every zero-match webhook would fire a doomed fetch at the dead
	// ATC and stall behind the HTTP timeout.
	for i := 0; i < 3; i++ {
		index, err := c.Refresh(context.Background())
		if err != nil || len(index) != 4 {
			t.Fatalf("call %d: index=%v err=%v want 4, nil", i, index, err)
		}
	}
	if got := stub.hitCount("/api/v1/teams/main/pipelines"); got != hits {
		t.Fatalf("pipeline-list hits=%d want %d (failed Refresh must back off)", got, hits)
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
	if err := c.getJSON(context.Background(), "/x", &out); err == nil {
		t.Fatal("getJSON over-cap body want error")
	}
}

func TestGetJSONDecodes2xxBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"n":2}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Team: "main"}
	var out struct {
		OK bool `json:"ok"`
		N  int  `json:"n"`
	}
	if err := c.getJSON(context.Background(), "/x", &out); err != nil {
		t.Fatal(err)
	}
	if !out.OK || out.N != 2 {
		t.Fatalf("decoded=%+v want {OK:true N:2}", out)
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

// slowATC serves stubRoutes() except the pipelines listing, which
// blocks until release is closed — simulating an ATC that answers
// slowly enough that, under the old lock-held fetch, every concurrent
// caller would serialize behind it. inFlight counts requests currently inside the blocked pipelines
// handler; blockFrom is the pipelines hit number the block starts at
// (2 = only refetches block, the warm-up passes; 1 = cold-start block).
// pipelinesHits counts every pipelines-list request the client made.
func slowATC(t *testing.T, release chan struct{},
	blockFrom int) (*httptest.Server, *atomic.Int64, *atomic.Int64) {
	var inFlight atomic.Int64
	var pipelinesHits atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/teams/main/pipelines", func(w http.ResponseWriter, r *http.Request) {
		hits := pipelinesHits.Add(1)
		if hits >= int64(blockFrom) {
			inFlight.Add(1)
			defer inFlight.Add(-1)
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
	return srv, &inFlight, &pipelinesHits
}

func TestResourcesConcurrentCallerServedStaleMidFetch(t *testing.T) {
	release := make(chan struct{})
	// Closed exactly once, on every exit path: t.Fatal must not leave
	// the slow ATC handler blocking t.Cleanup(srv.Close).
	closeRelease := sync.OnceFunc(func() { close(release) })
	defer closeRelease()
	srv, inFlight, _ := slowATC(t, release, 2)
	c := &Client{BaseURL: srv.URL, Team: "main", IndexTTL: time.Hour}

	// Warm index, then age the stamps so the next Resources must
	// refetch (TTL expired) but the fetch itself blocks at the ATC.
	if _, err := c.Resources(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.fetchedAt = time.Now().Add(-2 * c.ttl())
	c.lastAttemptAt = c.fetchedAt
	c.mu.Unlock()

	// Start the slow refetch in the background.
	bgRes := make(chan error, 1)
	go func() {
		_, err := c.Resources(context.Background())
		bgRes <- err
	}()
	waitInFlight(t, inFlight)

	// A concurrent caller must be served the stale index immediately —
	// it must not block behind the in-flight fetch.
	concIdx := make(chan int, 1)
	concErr := make(chan error, 1)
	go func() {
		index, err := c.Resources(context.Background())
		concIdx <- len(index)
		concErr <- err
	}()
	select {
	case n := <-concIdx:
		if err := <-concErr; err != nil || n != 4 {
			t.Fatalf("concurrent Resources index=%d err=%v want 4, nil", n, err)
		}
	case <-time.After(time.Second):
		t.Fatal("concurrent Resources blocked behind in-flight fetch")
	}

	closeRelease() // unblock the background fetch before waiting on it
	if err := <-bgRes; err != nil {
		t.Fatalf("background Resources err=%v want nil", err)
	}
	c.mu.Lock()
	got := len(c.index)
	c.mu.Unlock()
	if got != 4 {
		t.Fatalf("published index=%d resources want 4", got)
	}
}

func TestResourcesColdStartCallersShareOneFetch(t *testing.T) {
	// Cold start: every concurrent Resources caller must share the
	// single in-flight fetch — no caller may stampede the ATC with a
	// duplicate full-index fetch, and none may error out while the
	// answer is one shared fetch away.
	release := make(chan struct{})
	// Closed exactly once, on every exit path: an early t.Fatal must
	// not leave the slow ATC handler blocking t.Cleanup(srv.Close).
	closeRelease := sync.OnceFunc(func() { close(release) })
	defer closeRelease()
	srv, inFlight, pipelinesHits := slowATC(t, release, 1)
	c := &Client{BaseURL: srv.URL, Team: "main"}

	const callers = 8
	errs := make(chan error, callers)
	sizes := make(chan int, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			index, err := c.Resources(context.Background())
			errs <- err
			sizes <- len(index)
		}()
	}
	waitInFlight(t, inFlight)
	// All callers are parked on (or heading into) the one in-flight
	// fetch; give the stampede window a beat before releasing it.
	time.Sleep(20 * time.Millisecond)
	closeRelease()
	wg.Wait()
	close(errs)
	close(sizes)
	for err := range errs {
		if err != nil {
			t.Fatalf("cold-start Resources err=%v want nil (shared fetch)", err)
		}
	}
	for size := range sizes {
		if size != 4 {
			t.Fatalf("cold-start Resources index=%d resources want 4", size)
		}
	}
	if got := pipelinesHits.Load(); got != 1 {
		t.Fatalf("pipelines-list hits=%d want 1 (cold start must not stampede)", got)
	}
	// The published cache now serves later callers.
	if _, err := c.Resources(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := pipelinesHits.Load(); got != 1 {
		t.Fatalf("pipelines-list hits=%d want 1 (cache hit)", got)
	}
}

func TestResourcesColdStartWaitRespectsContext(t *testing.T) {
	// A cold-start caller waiting on the in-flight fetch must bail out
	// when its own context dies, not hang behind a wedged ATC.
	release := make(chan struct{})
	defer close(release)
	srv, inFlight, _ := slowATC(t, release, 1)
	c := &Client{BaseURL: srv.URL, Team: "main"}

	go func() { _, _ = c.Resources(context.Background()) }()
	waitInFlight(t, inFlight)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Resources(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cold-start wait err=%v want context.Canceled", err)
	}
}

func TestRefreshConcurrentCallerThrottledMidFetch(t *testing.T) {
	release := make(chan struct{})
	defer close(release) // never leave the slow ATC blocking cleanup
	srv, inFlight, _ := slowATC(t, release, 1)
	c := &Client{BaseURL: srv.URL, Team: "main"}

	go func() {
		_, _ = c.Refresh(context.Background())
	}()
	waitInFlight(t, inFlight)

	// Throttled by the in-flight attempt stamp — returns immediately
	// without its own fetch.
	concErr := make(chan error, 1)
	go func() {
		_, err := c.Refresh(context.Background())
		concErr <- err
	}()
	select {
	case err := <-concErr:
		if err != nil {
			t.Fatalf("throttled Refresh err=%v want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Refresh blocked behind in-flight fetch (throttle missed)")
	}

}

// waitInFlight blocks until a request is inside the slow ATC handler.
func waitInFlight(t *testing.T, inFlight *atomic.Int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for inFlight.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if inFlight.Load() == 0 {
		t.Fatal("fetch never reached the ATC")
	}
}

func TestFetchIndexUsesCallerSnapshotForCarryover(t *testing.T) {
	// fetchIndex must carry over failed pipelines' resources from the
	// snapshot passed in, not from live client state — it now runs
	// outside the mutex.
	stub := newATCStub(t, stubRoutes())
	c := &Client{BaseURL: stub.srv.URL, Team: "main"}
	if _, err := c.Resources(context.Background()); err != nil {
		t.Fatal(err)
	}
	stub.fail("/api/v1/teams/main/pipelines/p1/resources", 500)
	c.mu.Lock()
	snap := append([]Resource(nil), c.index...)
	c.mu.Unlock()
	index, err := c.fetchIndex(context.Background(), snap)
	if err != nil {
		t.Fatalf("fetchIndex err=%v want nil (carryover)", err)
	}
	if len(index) != 4 {
		t.Fatalf("index=%d resources want 4 (p1 carried over)", len(index))
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
		if err := c.getJSON(context.Background(), "/x", &out); err != nil {
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
