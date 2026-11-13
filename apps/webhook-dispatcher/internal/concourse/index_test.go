// index_test.go — the TTL/singleflight cache: index build and carry-
// over, TTL and backoff windows, cold-start waiters, forced refreshes
// and the freshness gauges, driven against fake ATC stubs. The clock
// seam (Client.now + fakeClock below) lets the TTL/backoff tests
// advance time deterministically instead of sleeping across real
// windows.
package concourse

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// fakeClock is the de-slept TTL tests' clock: tests Advance it past
// TTL/backoff windows instead of sleeping across them. It starts at
// the real wall clock so values derived from it (the freshness
// gauge's unix timestamp) stay in sane ranges.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{now: time.Now()} }

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// Advance moves the clock forward: every window measured against
// Client.now ages by d at once.
func (f *fakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

func TestResourcesBuildsIndex(t *testing.T) {
	stub := newATCStub(t, stubRoutes())
	c := &Client{BaseURL: stub.srv.URL, Team: "main", User: "u", Password: "p"}

	index, err := c.Resources(t.Context())
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
	if _, err := c.Resources(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Resources(t.Context()); err != nil {
		t.Fatal(err)
	}
	// The second call within the TTL must not re-list pipelines.
	if got := stub.hitCount("/api/v1/teams/main/pipelines"); got != 1 {
		t.Fatalf("pipeline-list hits=%d want 1 (cache hit)", got)
	}
	// Even with the ATC now broken, the fresh cache wins.
	stub.fail("/api/v1/teams/main/pipelines", 500)
	if _, err := c.Resources(t.Context()); err != nil {
		t.Fatalf("cached Resources err=%v want nil (TTL)", err)
	}
	if got := stub.hitCount("/api/v1/teams/main/pipelines"); got != 1 {
		t.Fatalf("pipeline-list hits=%d want 1", got)
	}
}

func TestResourcesStaleFallback(t *testing.T) {
	stub := newATCStub(t, stubRoutes())
	clk := newFakeClock()
	c := &Client{BaseURL: stub.srv.URL, Team: "main", IndexTTL: time.Hour, now: clk.Now}

	if _, err := c.Resources(t.Context()); err != nil {
		t.Fatal(err)
	}
	clk.Advance(time.Hour) // expire the TTL
	stub.fail("/api/v1/teams/main/pipelines", 500)
	index, err := c.Resources(t.Context())
	if err != nil {
		t.Fatalf("stale fallback err=%v want nil", err)
	}
	if len(index) != 4 {
		t.Fatalf("stale index=%d resources want 4", len(index))
	}
}

func TestResourcesFailedRefreshBacksOff(t *testing.T) {
	stub := newATCStub(t, stubRoutes())
	clk := newFakeClock()
	c := &Client{BaseURL: stub.srv.URL, Team: "main", IndexTTL: time.Hour, now: clk.Now}

	if _, err := c.Resources(t.Context()); err != nil {
		t.Fatal(err)
	}
	// Expire the cache artificially — the last fetch attempt is as
	// old as the cache itself (it IS the fetch that populated it) —
	// then break the ATC: the first call re-fetches, fails, and
	// serves the stale index.
	clk.Advance(2 * c.ttl())
	stub.fail("/api/v1/teams/main/pipelines", 500)
	index, err := c.Resources(t.Context())
	if err != nil || len(index) != 4 {
		t.Fatalf("stale fallback index=%v err=%v want 4, nil", index, err)
	}
	hits := stub.hitCount("/api/v1/teams/main/pipelines")

	// Repeat calls inside the TTL window must NOT re-hit the ATC —
	// without the attempt backoff each one would block on a doomed
	// fetch, serializing webhook traffic behind a dead ATC.
	for i := range 3 {
		index, err := c.Resources(t.Context())
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
	clk := newFakeClock()
	c := &Client{BaseURL: stub.srv.URL, Team: "main", IndexTTL: time.Hour, now: clk.Now}

	if _, err := c.Resources(t.Context()); err != nil {
		t.Fatal(err)
	}
	clk.Advance(c.ttl()) // expire the TTL

	// p2's resource listing breaks while the pipeline still exists —
	// the refreshed index must carry p2's last-known resources over
	// instead of silently unregistering them (the fetch succeeds as
	// a whole, so a partial result would overwrite the cache).
	stub.fail("/api/v1/teams/main/pipelines/p2/resources", 500)
	index, err := c.Resources(t.Context())
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
	clk := newFakeClock()
	c := &Client{BaseURL: stub.srv.URL, Team: "main", IndexTTL: time.Hour, now: clk.Now}

	if _, err := c.Resources(t.Context()); err != nil {
		t.Fatal(err)
	}
	clk.Advance(c.ttl()) // expire the TTL

	// p2 disappears from the pipeline list entirely — its stale
	// resources must NOT be retained (only a failed listing keeps
	// them; a truly deleted pipeline drops out).
	stub.setRoute("/api/v1/teams/main/pipelines", `[{"name":"p1"}]`)
	index, err := c.Resources(t.Context())
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
	clk := newFakeClock()
	c := &Client{BaseURL: stub.srv.URL, Team: "main", IndexTTL: time.Hour, now: clk.Now}

	index, err := c.Resources(t.Context())
	if err != nil || len(index) != 4 {
		t.Fatalf("index=%v err=%v want 4 resources", index, err)
	}
	// A resource set after the index was cached; the TTL would hide
	// it from Resources for an hour.
	stub.setRoute("/api/v1/teams/main/pipelines/p2/resources",
		`[{"name":"new","type":"git","source":{"uri":"org/new"}}]`)
	// Past BOTH throttle windows — lastForceRefreshAt (Refresh's own
	// clock) and fetchedAt (a successful fetch moments ago already
	// IS the fresh index Refresh exists to produce).
	clk.Advance(c.minRefreshInterval())

	fresh, err := c.Refresh(t.Context())
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
	clk.Advance(c.minRefreshInterval())
	stub.fail("/api/v1/teams/main/pipelines", 500)
	if _, err := c.Refresh(t.Context()); err == nil {
		t.Fatal("Refresh(500) want error")
	}
	if cached, _ := c.Resources(t.Context()); len(cached) != len(fresh) {
		t.Fatalf("index after failed refresh=%d want %d", len(cached), len(fresh))
	}
}

func TestRefreshThrottleOwnsItsClock(t *testing.T) {
	// Refresh's throttle keys on lastForceRefreshAt, not lastAttemptAt:
	// a failed Resources refetch that just stamped its own backoff
	// attempt must not suppress a forced refresh — a zero-match
	// delivery needs the network, not the cached index.
	stub := newATCStub(t, stubRoutes())
	clk := newFakeClock()
	c := &Client{BaseURL: stub.srv.URL, Team: "main", IndexTTL: time.Hour, now: clk.Now}

	if _, err := c.Resources(t.Context()); err != nil {
		t.Fatal(err)
	}
	// Age the cache and break the ATC: the next Resources refetches,
	// fails, stamps lastAttemptAt, and falls back to the stale index.
	clk.Advance(2 * c.ttl())
	stub.fail("/api/v1/teams/main/pipelines", 500)
	if _, err := c.Resources(t.Context()); err != nil {
		t.Fatalf("stale fallback err=%v want nil", err)
	}

	// lastForceRefreshAt is still zero — long past any throttle
	// window — so Refresh must attempt its own fetch and surface the
	// ATC failure instead of silently serving the cached index.
	if _, err := c.Refresh(t.Context()); err == nil {
		t.Fatal("Refresh err=nil want error (throttled by Resources' attempt stamp)")
	}
}

func TestResourcesBackoffOwnsItsClock(t *testing.T) {
	// Symmetric: Resources' backoff keys on lastAttemptAt — a forced
	// Refresh stamping lastForceRefreshAt must not double as
	// Resources' backoff, or a recovering ATC would stay hidden behind
	// Refresh's stamp for a whole extra TTL window.
	stub := newATCStub(t, stubRoutes())
	clk := newFakeClock()
	c := &Client{BaseURL: stub.srv.URL, Team: "main", now: clk.Now}

	// Warm through Refresh: lastForceRefreshAt is fresh, lastAttemptAt
	// stays zero.
	if _, err := c.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	// Age the cache and break the ATC; Resources must attempt its own
	// (doomed) fetch rather than treat Refresh's stamp as its backoff.
	clk.Advance(2 * c.ttl())
	stub.fail("/api/v1/teams/main/pipelines", 500)
	hits := stub.hitCount("/api/v1/teams/main/pipelines")
	index, err := c.Resources(t.Context())
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

	if _, err := c.Resources(t.Context()); err == nil {
		t.Fatal("Resources want error — the index is incomplete")
	}
	c.mu.RLock()
	cached := c.index
	c.mu.RUnlock()
	if cached != nil {
		t.Fatalf("c.index=%v want nil (incomplete index must not cache)", cached)
	}
	// Cold-start negative cache: an immediate retry — even with the
	// ATC recovered — shares the just-failed fetch's error inside
	// NegCacheTTL instead of stampeding a fresh rebuild (the
	// concurrent-first-delivery retry storm this cache exists for).
	stub.unfail("/api/v1/teams/main/pipelines/p1/resources")
	if _, err := c.Resources(t.Context()); err == nil {
		t.Fatal("retry inside NegCacheTTL want shared error, got nil")
	}
	// Past the window the next call retries for real and builds the
	// index — there is no stale index to back off behind.
	c.mu.Lock()
	c.lastErrAt = time.Now().Add(-time.Hour)
	c.mu.Unlock()
	index, err := c.Resources(t.Context())
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
	clk := newFakeClock()
	c := &Client{BaseURL: stub.srv.URL, Team: "main", IndexTTL: time.Hour, now: clk.Now}
	if _, err := c.Resources(t.Context()); err != nil {
		t.Fatal(err)
	}
	clk.Advance(c.ttl()) // expire the TTL

	// p3 is brand new (no prev data) and its listing 404s.
	stub.setRoute("/api/v1/teams/main/pipelines",
		`[{"name":"p1"},{"name":"p2"},{"name":"p3"}]`)
	index, err := c.Resources(t.Context())
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
	if _, err := c.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	// An immediate second Refresh must not hit the ATC again —
	// zero-match deliveries throttle to MinRefreshInterval.
	index, err := c.Refresh(t.Context())
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
	clk := newFakeClock()
	c := &Client{BaseURL: stub.srv.URL, Team: "main", now: clk.Now}

	// Warm the index, then age the last forced-refresh attempt AND the
	// fetch timestamp out of their throttle windows and break the ATC:
	// the next Refresh hits the network, fails, and stamps
	// lastForceRefreshAt.
	if _, err := c.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	clk.Advance(c.minRefreshInterval())
	stub.fail("/api/v1/teams/main/pipelines", 500)
	if _, err := c.Refresh(t.Context()); err == nil {
		t.Fatal("Refresh(500) want error")
	}
	hits := stub.hitCount("/api/v1/teams/main/pipelines")

	// Refreshes inside the throttle window must serve the cached
	// index without another doomed network call — fetchedAt only
	// moves on success, so without the lastForceRefreshAt throttle
	// every zero-match webhook would fire a doomed fetch at the dead
	// ATC and stall behind the HTTP timeout.
	for i := range 3 {
		index, err := c.Refresh(t.Context())
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

	index, err := c.Resources(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if index == nil || len(index) != 0 {
		t.Fatalf("index=%v want non-nil empty", index)
	}
	// A healthy empty index still counts as fetched: the TTL holds
	// and a later expiry falls back to it instead of erroring.
	if _, err := c.Resources(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := stub.hitCount("/api/v1/teams/main/pipelines"); got != 1 {
		t.Fatalf("pipeline-list hits=%d want 1 (cache hit)", got)
	}
	stub.fail("/api/v1/teams/main/pipelines", 500)
	c.mu.Lock()
	c.fetchedAt = time.Now().Add(-2 * c.ttl())
	c.mu.Unlock()
	if index, err := c.Resources(t.Context()); err != nil || index == nil {
		t.Fatalf("stale empty index=%v err=%v want non-nil, nil", index, err)
	}
}

func TestResourcesConcurrentCallerServedStaleMidFetch(t *testing.T) {
	release := make(chan struct{})
	// Closed exactly once, on every exit path: t.Fatal must not leave
	// the slow ATC handler blocking t.Cleanup(srv.Close).
	closeRelease := sync.OnceFunc(func() { close(release) })
	defer closeRelease()
	srv, entered, _ := slowATC(t, release, 2)
	c := &Client{BaseURL: srv.URL, Team: "main", IndexTTL: time.Hour}

	// Warm index, then age the stamps so the next Resources must
	// refetch (TTL expired) but the fetch itself blocks at the ATC.
	if _, err := c.Resources(t.Context()); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.fetchedAt = time.Now().Add(-2 * c.ttl())
	c.lastAttemptAt = c.fetchedAt
	c.mu.Unlock()

	// Start the slow refetch in the background.
	bgRes := make(chan error, 1)
	go func() {
		_, err := c.Resources(t.Context())
		bgRes <- err
	}()
	waitInFlight(t, entered)

	// A concurrent caller must be served the stale index immediately —
	// it must not block behind the in-flight fetch.
	concIdx := make(chan int, 1)
	concErr := make(chan error, 1)
	go func() {
		index, err := c.Resources(t.Context())
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
	srv, entered, pipelinesHits := slowATC(t, release, 1)
	c := &Client{BaseURL: srv.URL, Team: "main"}

	const callers = 8
	errs := make(chan error, callers)
	sizes := make(chan int, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() {
			index, err := c.Resources(t.Context())
			errs <- err
			sizes <- len(index)
		})
	}
	waitInFlight(t, entered)
	// The pipelines handler stays parked until closeRelease, so no
	// caller can miss the flight: whoever arrives before the fetch
	// settles joins it, whoever arrives after is served the published
	// index — either way no duplicate fetch can reach the ATC.
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
	if _, err := c.Resources(t.Context()); err != nil {
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
	srv, entered, _ := slowATC(t, release, 1)
	c := &Client{BaseURL: srv.URL, Team: "main"}

	go func() { _, _ = c.Resources(t.Context()) }()
	waitInFlight(t, entered)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Resources(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cold-start wait err=%v want context.Canceled", err)
	}
}

func TestRefreshConcurrentCallerJoinsInFlightFetch(t *testing.T) {
	release := make(chan struct{})
	closeRelease := sync.OnceFunc(func() { close(release) })
	defer closeRelease()
	srv, entered, pipelinesHits := slowATC(t, release, 1)
	c := &Client{BaseURL: srv.URL, Team: "main"}

	first := make(chan error, 1)
	go func() {
		_, err := c.Refresh(t.Context())
		first <- err
	}()
	waitInFlight(t, entered)

	// A second Refresh while the first is in flight JOINS it — single
	// flight: it must not return early with a stale/empty index, must
	// not fire a duplicate ATC fetch, and only settles once the
	// in-flight fetch does. The joined caller reports its index length,
	// so an early return on a cold start (empty index) fails the check
	// below deterministically — no timing window needed to catch it.
	secondIdx := make(chan int, 1)
	secondErr := make(chan error, 1)
	go func() {
		index, err := c.Refresh(t.Context())
		secondIdx <- len(index)
		secondErr <- err
	}()

	closeRelease()
	if err := <-first; err != nil {
		t.Fatalf("first Refresh err=%v", err)
	}
	if got := <-secondIdx; got != 4 {
		t.Fatalf("joined Refresh index=%d want 4 — it must wait for the in-flight fetch, not return early empty", got)
	}
	if err := <-secondErr; err != nil {
		t.Fatalf("joined Refresh err=%v want nil", err)
	}
	if got := pipelinesHits.Load(); got != 1 {
		t.Fatalf("pipelines fetches=%d want 1 (singleflight)", got)
	}
}

func TestRefreshManyConcurrentCallersSingleFetch(t *testing.T) {
	release := make(chan struct{})
	closeRelease := sync.OnceFunc(func() { close(release) })
	defer closeRelease()
	srv, entered, pipelinesHits := slowATC(t, release, 1)
	c := &Client{BaseURL: srv.URL, Team: "main"}

	const callers = 4
	errs := make(chan error, callers)
	for range callers {
		go func() {
			_, err := c.Refresh(t.Context())
			errs <- err
		}()
	}
	waitInFlight(t, entered)
	closeRelease()
	for range callers {
		if err := <-errs; err != nil {
			t.Fatalf("Refresh err=%v want nil", err)
		}
	}
	if got := pipelinesHits.Load(); got != 1 {
		t.Fatalf("pipelines fetches=%d want 1 (singleflight)", got)
	}
}

func TestFetchIndexPipeline404DropsGhosts(t *testing.T) {
	stub := newATCStub(t, stubRoutes())
	clk := newFakeClock()
	c := &Client{BaseURL: stub.srv.URL, Team: "main", now: clk.Now}
	// Seed the index so prevByPipeline carries p2's last-known
	// resources into the next fetch.
	if _, err := c.Resources(t.Context()); err != nil {
		t.Fatal(err)
	}
	// p2 is deleted between the pipeline listing and its resource
	// fetch: the listing still returns it, but its resources endpoint
	// 404s. The refreshed index must drop p2's ghost resources
	// entirely — not carry them over, and not fail the fetch.
	stub.fail("/api/v1/teams/main/pipelines/p2/resources", http.StatusNotFound)
	// Age fetchedAt past the forced-refresh throttle — a fetch that
	// just succeeded would otherwise satisfy Refresh without a
	// network call.
	clk.Advance(c.minRefreshInterval())
	index, err := c.Refresh(t.Context())
	if err != nil {
		t.Fatalf("Refresh err=%v want nil (404 is not a fetch failure)", err)
	}
	for _, r := range index {
		if r.Pipeline == "p2" {
			t.Fatalf("index keeps ghost resource %+v from deleted pipeline", r)
		}
	}
	if len(index) != 3 {
		t.Fatalf("index=%d resources want 3 (p1 only)", len(index))
	}
}

func TestFetchIndexUsesCallerSnapshotForCarryover(t *testing.T) {
	// fetchIndex must carry over failed pipelines' resources from the
	// snapshot passed in, not from live client state — it now runs
	// outside the mutex.
	stub := newATCStub(t, stubRoutes())
	c := &Client{BaseURL: stub.srv.URL, Team: "main"}
	if _, err := c.Resources(t.Context()); err != nil {
		t.Fatal(err)
	}
	stub.fail("/api/v1/teams/main/pipelines/p1/resources", 500)
	c.mu.Lock()
	snap := append([]Resource(nil), c.index...)
	c.mu.Unlock()
	index, err := c.fetchIndex(t.Context(), snap)
	if err != nil {
		t.Fatalf("fetchIndex err=%v want nil (carryover)", err)
	}
	if len(index) != 4 {
		t.Fatalf("index=%d resources want 4 (p1 carried over)", len(index))
	}
}

func TestIndexFreshnessMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	RegisterMetrics(reg)
	stub := newATCStub(t, stubRoutes())
	c := &Client{BaseURL: stub.srv.URL, Team: "main", User: "u", Password: "p"}

	errBefore := testutil.ToFloat64(indexFetchErrorsTotal)

	// A successful fetch emits the freshness gauge at ~now.
	if _, err := c.Resources(t.Context()); err != nil {
		t.Fatal(err)
	}
	ts := testutil.ToFloat64(indexLastRefreshSeconds)
	if age := time.Since(time.Unix(int64(ts), 0)); age < 0 || age > 5*time.Second {
		t.Fatalf("refresh timestamp age=%v want ~now", age)
	}

	// A failed fetch whose stale index is served still counts the
	// error — deliveries keep flowing while it climbs.
	c.mu.Lock()
	c.fetchedAt = time.Now().Add(-2 * c.ttl())
	c.lastAttemptAt = c.fetchedAt
	c.mu.Unlock()
	stub.fail("/api/v1/teams/main/pipelines", 500)
	if _, err := c.Resources(t.Context()); err != nil {
		t.Fatalf("stale fallback err=%v want nil", err)
	}
	if got := testutil.ToFloat64(indexFetchErrorsTotal); got != errBefore+1 {
		t.Fatalf("fetch errors=%v want %v", got, errBefore+1)
	}

	// A failed forced Refresh counts too.
	stub.unfail("/api/v1/teams/main/pipelines")
	c.mu.Lock()
	c.lastForceRefreshAt = time.Now().Add(-c.minRefreshInterval())
	c.fetchedAt = time.Now().Add(-2 * c.ttl())
	c.mu.Unlock()
	stub.fail("/api/v1/teams/main/pipelines", 503)
	if _, err := c.Refresh(t.Context()); err == nil {
		t.Fatal("Refresh(503) want error")
	}
	if got := testutil.ToFloat64(indexFetchErrorsTotal); got != errBefore+2 {
		t.Fatalf("fetch errors=%v want %v", got, errBefore+2)
	}

	// Recovery: the gauge moves again, the error counter holds.
	stub.unfail("/api/v1/teams/main/pipelines")
	c.mu.Lock()
	c.lastForceRefreshAt = time.Now().Add(-c.minRefreshInterval())
	c.fetchedAt = time.Now().Add(-2 * c.ttl())
	c.lastAttemptAt = c.fetchedAt
	c.mu.Unlock()
	if _, err := c.Resources(t.Context()); err != nil {
		t.Fatal(err)
	}
	if age := time.Since(time.Unix(int64(
		testutil.ToFloat64(indexLastRefreshSeconds)), 0)); age < 0 || age > 5*time.Second {
		t.Fatalf("post-recovery refresh timestamp age=%v want ~now", age)
	}
	if got := testutil.ToFloat64(indexFetchErrorsTotal); got != errBefore+2 {
		t.Fatalf("fetch errors=%v want %v (recovery must not count)", got, errBefore+2)
	}
}

// A caller-cancelled context (request shutdown, handler deadline)
// must not be recorded as an ATC failure: no negative-cache write
// (which would hand the caller's own unwind to every later cold-start
// caller) and no indexFetchErrorsTotal increment. The next caller
// with a live context fetches normally.
func TestResourcesCallerCancelNotAnATCFailure(t *testing.T) {
	// The gate parks every ATC request until the test opens it — the
	// deterministic stand-in for a sleeping handler: the fetch under
	// test must outlive its caller's patience, and later phases must
	// not race a still-parked fetch.
	var gate atomic.Value // chan struct{}; nil-able
	park := func() { gate.Store(make(chan struct{})) }
	unpark := func() {
		if g, ok := gate.Load().(chan struct{}); ok {
			close(g)
			gate.Store(chan struct{}(nil))
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/sky/") {
			// No token endpoint — auth latches basic so the fetch
			// under test exercises the API paths below.
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if g, ok := gate.Load().(chan struct{}); ok && g != nil {
			<-g
		}
		body := pipelinesBody
		if strings.HasSuffix(r.URL.Path, "/pipelines/p1/resources") {
			body = p1Body
		} else if strings.HasSuffix(r.URL.Path, "/pipelines/p2/resources") {
			body = p2Body
		}
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	c := &Client{BaseURL: srv.URL, Team: "main"}

	errBefore := testutil.ToFloat64(indexFetchErrorsTotal)
	park()
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	defer cancel()
	if _, err := c.Resources(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Resources err=%v want context.Canceled", err)
	}
	c.mu.Lock()
	lastErr := c.lastErr
	c.mu.Unlock()
	if lastErr != nil {
		t.Fatalf("cancelled fetch wrote lastErr=%v — caller unwind must not negative-cache", lastErr)
	}
	if got := testutil.ToFloat64(indexFetchErrorsTotal); got != errBefore {
		t.Fatalf("fetch errors=%v want %v (cancellation must not count)", got, errBefore)
	}
	// And the next caller with a live context fetches normally — the
	// cancellation left no negative cache or doomed backoff behind.
	// Opening the gate lets the still-detached first fetch settle and
	// publish, so this caller is answered by the cache.
	unpark()
	index, err := c.Resources(t.Context())
	if err != nil {
		t.Fatalf("post-cancel Resources err=%v want nil", err)
	}
	if len(index) != 4 {
		t.Fatalf("index=%d resources want 4", len(index))
	}
	// Refresh applies the same rule: no counter, no lastErr. Rewind
	// the throttle clocks so the cancelled Refresh really fetches,
	// and park the ATC again so its fetch outlives the caller.
	c.mu.Lock()
	c.fetchedAt = time.Time{}
	c.lastForceRefreshAt = time.Time{}
	c.mu.Unlock()
	park()
	ctx2, cancel2 := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel2)
	defer cancel2()
	if _, err := c.Refresh(ctx2); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Refresh err=%v want context.Canceled", err)
	}
	c.mu.Lock()
	lastErr = c.lastErr
	c.mu.Unlock()
	if lastErr != nil {
		t.Fatalf("cancelled Refresh wrote lastErr=%v", lastErr)
	}
	if got := testutil.ToFloat64(indexFetchErrorsTotal); got != errBefore {
		t.Fatalf("fetch errors after cancelled Refresh=%v want %v", got, errBefore)
	}
	// The cancelled Refresh's fetch is DETACHED — it outlives the
	// caller on purpose. Drain it before the test ends: a joined
	// Refresh waits on the flight's done, so the stub server stays
	// up until the fetch settles instead of the fetch failing
	// against the closed listener and leaking an
	// indexFetchErrorsTotal increment into the next test.
	unpark()
	if _, err := c.Refresh(t.Context()); err != nil {
		t.Fatalf("drain Refresh err=%v want nil", err)
	}
}

// Cold-start waiters surface the flight's error: the first caller
// starts the only fetch, a second caller arriving mid-flight waits on
// done and re-loops into the negative cache — it must come back with
// the SAME failure instead of stamping a duplicate attempt at the
// ATC.
func TestColdStartWaiterSurfacesFlightError(t *testing.T) {
	var hits atomic.Int64
	// release holds the (single) ATC request open until both callers
	// are in play; entered signals a request reached the handler —
	// the deterministic flight-installed marker.
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/sky/") {
			// No token endpoint — auth latches basic; only API
			// fetches count as pipeline-list hits below.
			w.WriteHeader(http.StatusNotFound)
			return
		}
		hits.Add(1)
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release // hold the flight open for the joiner
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	c := &Client{BaseURL: srv.URL, Team: "main", NegCacheTTL: 5 * time.Second}

	errBefore := testutil.ToFloat64(indexFetchErrorsTotal)
	errs := make(chan error, 2)
	go func() {
		_, err := c.Resources(t.Context())
		errs <- err
	}()
	waitInFlight(t, entered) // flight installed, starter parked at the ATC
	go func() {
		_, err := c.Resources(t.Context())
		errs <- err
	}()
	close(release)
	e1, e2 := <-errs, <-errs
	if e1 == nil || e2 == nil {
		t.Fatalf("cold-start errors %v/%v want both failed", e1, e2)
	}
	if e1.Error() != e2.Error() {
		t.Fatalf("waiter err %v != flight err %v — flight failure must surface", e2, e1)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("pipeline-list hits=%d want 1 (waiter must join the flight)", got)
	}
	if got := testutil.ToFloat64(indexFetchErrorsTotal); got != errBefore+1 {
		t.Fatalf("fetch errors=%v want %v (one fetch, two callers)", got, errBefore+1)
	}
}

// TestFetchIndexInstancedPipeline: an instanced pipeline's
// /resources listing must carry the vars.<key>= fragment, the
// Resource must retain it, and the check webhook must re-append it —
// without it the ATC cannot resolve which instance to check.
func TestFetchIndexInstancedPipeline(t *testing.T) {
	var mu sync.Mutex
	var resQueries []string
	var checkQueries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Path == "/api/v1/teams/main/pipelines":
			fmt.Fprint(w, `[{"name":"p1","instance_vars":{"release":{"line":"1.2"},"channel":"stable"}}]`)
		case r.URL.Path == "/api/v1/teams/main/pipelines/p1/resources":
			resQueries = append(resQueries, r.URL.RawQuery)
			fmt.Fprint(w, `[{"name":"repo-git","type":"git","source":{"uri":"git@github.com:org/repo.git"}}]`)
		case strings.HasSuffix(r.URL.Path, "/check/webhook"):
			checkQueries = append(checkQueries, r.URL.RawQuery)
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	c := &Client{BaseURL: srv.URL, Team: "main", User: "u", Password: "p",
		WebhookToken: "tok"}
	index, err := c.Resources(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(index) != 1 {
		t.Fatalf("index=%v want 1 resource", index)
	}
	wantQuery := "vars.channel=%22stable%22&vars.release.line=%221.2%22"
	mu.Lock()
	gotQueries := append([]string(nil), resQueries...)
	mu.Unlock()
	if len(gotQueries) != 1 || gotQueries[0] != wantQuery {
		t.Fatalf("resources queries=%v want [%q]", gotQueries, wantQuery)
	}
	if index[0].InstanceVarsQuery != wantQuery {
		t.Fatalf("InstanceVarsQuery=%q want %q", index[0].InstanceVarsQuery, wantQuery)
	}

	code, err := c.CheckWebhook(t.Context(), index[0])
	if err != nil || code != http.StatusCreated {
		t.Fatalf("CheckWebhook=(%d,%v) want 201", code, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(checkQueries) != 1 {
		t.Fatalf("check webhook calls=%v want 1", checkQueries)
	}
	// webhook_token first, then the vars fragment — the ATC needs
	// both to resolve the instanced pipeline's check.
	if !strings.Contains(checkQueries[0], "webhook_token=tok") ||
		!strings.Contains(checkQueries[0], wantQuery) {
		t.Fatalf("check webhook query=%q want token + vars fragment %q",
			checkQueries[0], wantQuery)
	}
}

// TestFetchIndexSkipsArchived: archived pipelines are dropped before
// their /resources is ever listed — their entries are dead weight
// and their listings can 404/hang.
func TestFetchIndexSkipsArchived(t *testing.T) {
	var mu sync.Mutex
	var listed []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Path == "/api/v1/teams/main/pipelines":
			fmt.Fprint(w, `[{"name":"live"},{"name":"dead","archived":true}]`)
		case strings.HasPrefix(r.URL.Path, "/api/v1/teams/main/pipelines/"):
			listed = append(listed, r.URL.Path)
			fmt.Fprint(w, `[{"name":"repo-git","type":"git","source":{"uri":"git@github.com:org/repo.git"}}]`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	c := &Client{BaseURL: srv.URL, Team: "main", User: "u", Password: "p"}
	index, err := c.Resources(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(index) != 1 || index[0].Pipeline != "live" {
		t.Fatalf("index=%v want only live pipeline's resource", index)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, p := range listed {
		if strings.Contains(p, "dead") {
			t.Fatalf("archived pipeline was listed: %v", listed)
		}
	}
}

// BenchmarkEnsureIndexFreshPath measures the per-delivery fast path:
// EnsureIndex against a TTL-fresh published index — one RLock, the
// freshness check and the error-only return, with no fetch and no
// index slice cloned out.
func BenchmarkEnsureIndexFreshPath(b *testing.B) {
	index := benchmarkIndex()
	c := benchmarkClient(index)
	c.fetchedAt = time.Now()
	b.ReportAllocs()
	for b.Loop() {
		if err := c.EnsureIndex(b.Context()); err != nil {
			b.Fatal(err)
		}
	}
}
