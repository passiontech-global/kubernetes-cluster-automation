// Package concourse implements the small slice of the Concourse ATC
// API the dispatcher needs: listing pipelines and their resources to
// build a repo -> resource index, and POSTing resource check webhooks.
package concourse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// Resource is one Concourse resource pinned to a GitHub repo. Repo is
// the normalized "org/repo" form produced by NormalizeRepo.
type Resource struct {
	Pipeline string
	Name     string
	Type     string
	Repo     string
	// InstanceVarsQuery is the pipeline's instance_vars rendered as
	// the ATC dot-notation query fragment ("vars.k=<json>&…", "" for
	// non-instanced pipelines). Instanced pipelines only resolve
	// their resources/checks under ?vars.<key>=, so the fragment
	// rides every Resource and is appended to both the /resources
	// listing and the check-webhook POST.
	InstanceVarsQuery string
}

// Client talks to a single Concourse ATC team.
type Client struct {
	BaseURL      string // e.g. http://concourse-web:8080
	Team         string
	User         string // basic auth, parsed from LOCAL_USERS
	Password     string
	WebhookToken string // CI_WEBHOOK_TOKEN, sent as webhook_token=…

	// HTTP is the client used for ATC calls; nil -> http.DefaultClient.
	HTTP *http.Client

	// IndexTTL bounds how long the resource index is served from
	// cache before a refresh; zero -> 1 minute.
	IndexTTL time.Duration

	// MinRefreshInterval bounds forced Refresh calls — zero-match
	// deliveries for repos with no pipeline would otherwise refetch
	// the whole index on every push. Zero -> 30 seconds.
	MinRefreshInterval time.Duration

	// NegCacheTTL is the cold-start negative-cache window: when a
	// fetch fails with NO index to serve, Resources callers used to
	// each stamp a fresh attempt and start their own fetch — N
	// concurrent first deliveries serialized N doomed index
	// rebuilds at a flapping ATC. The shared error is returned
	// instead for this window. Zero -> 3 seconds.
	NegCacheTTL time.Duration

	mu sync.Mutex

	// index is the last successfully fetched index; lookup is its
	// (type, repo) -> resources map, built once per fetch publish so
	// the per-delivery match is a map hit (Client.Match) instead of a
	// linear scan of every resource in the team. Both are replaced
	// wholesale on publish — never mutated in place — so serving a
	// snapshot is race-free and Match returns value copies.
	index     []Resource
	lookup    map[indexKey][]Resource
	fetchedAt time.Time
	// lastAttemptAt stamps the start of the most recent fetch attempt
	// made by Resources — success or failure — so a failed fetch backs
	// off instead of letting every caller block on a fresh fetch
	// against a dead ATC, and callers arriving mid-fetch are served
	// the current index rather than queueing a second fetch. It
	// belongs to Resources alone: Refresh throttles on its own
	// lastForceRefreshAt clock, so one entry point's attempt stamp
	// never masks the other's.
	lastAttemptAt time.Time
	// lastForceRefreshAt stamps the most recent forced Refresh
	// attempt, throttling Refresh to MinRefreshInterval. It is kept
	// separate from lastAttemptAt: a zero-match delivery's forced
	// refresh must not be suppressed by an unrelated Resources cache
	// miss that just stamped its own attempt, and a Refresh attempt
	// must never double as Resources' backoff stamp.
	lastForceRefreshAt time.Time
	// flight is the in-flight index fetch, if any. Starting a fetch
	// installs a fresh flight under the lock and closes its done
	// channel — only when that fetch itself settles — so concurrent
	// starters never clear each other's in-flight marker. Cold-start
	// callers (no index to serve) capture the channel and wait on it,
	// sharing the in-flight fetch's result instead of stampeding the
	// ATC with duplicate full-index fetches.
	flight *fetchFlight
	// lastErr/lastErrAt are the cold-start negative cache — see
	// NegCacheTTL. Written under c.mu on any fetch failure EXCEPT a
	// caller-cancelled context (not an ATC failure), cleared on
	// success; consulted only while c.index == nil.
	lastErr   error
	lastErrAt time.Time

	// auth is the lazily-built dual-mode credential state (bearer
	// token with basic fallback — see auth.go). Built under c.mu on
	// first authorize so zero-value Clients work unchanged.
	auth *atcAuth
}

// fetchFlight tracks one in-flight index fetch. done is closed by the
// fetch that installed the flight, exactly once, when that fetch
// settles — waiters that captured the channel are woken no matter how
// many later fetches replace the flight pointer in the meantime. err
// is the settled fetch's failure, written before done closes: a
// Refresh waiter that joined the flight reads it to tell "the fetch
// I waited on failed" apart from "a throttle window is serving the
// cached index" — without it the waiter loops into the throttle
// branch and returns stale+nil, hiding the failure the caller asked
// a forced refresh to surface.
type fetchFlight struct {
	done chan struct{}
	err  error
}

// statusError carries the HTTP status of a failed ATC call so callers
// can distinguish 404 (the object is gone — e.g. a pipeline deleted
// between the listing and its resource fetch) from transient failures
// that must keep last-known data.
type statusError struct {
	status int
	path   string
}

func (e *statusError) Error() string {
	return fmt.Sprintf("GET %s: unexpected status %d", e.path, e.status)
}

// indexKey keys the lookup map: one entry per (resource type, repo)
// pair. A delivery's match is then a handful of map hits instead of a
// linear scan of every resource in the team on every webhook.
type indexKey struct {
	typ  string
	repo string
}

// newLookup builds the (type, repo) -> resources map for a freshly
// fetched index. Called once per publish, not once per delivery.
func newLookup(index []Resource) map[indexKey][]Resource {
	lookup := make(map[indexKey][]Resource, len(index))
	for _, r := range index {
		k := indexKey{r.Type, r.Repo}
		lookup[k] = append(lookup[k], r)
	}
	return lookup
}

// Match returns the current index's resources of wantType whose repo
// is one of repos — the O(1) lookup the handler's per-delivery match
// runs on, over the map newLookup built at the last fetch publish.
// Returned Resource values are copies: callers cannot reach the
// client's snapshot. Repos are visited in sorted order so the result
// order is deterministic (equal inputs, equal output — helps logs and
// tests; the fan-out itself is order-insensitive).
func (c *Client) Match(wantType string, repos map[string]struct{}) []Resource {
	c.mu.Lock()
	defer c.mu.Unlock()
	var matched []Resource
	for _, repo := range slices.Sorted(maps.Keys(repos)) {
		matched = append(matched, c.lookup[indexKey{wantType, repo}]...)
	}
	return matched
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func (c *Client) ttl() time.Duration {
	if c.IndexTTL > 0 {
		return c.IndexTTL
	}
	return time.Minute
}

func (c *Client) minRefreshInterval() time.Duration {
	if c.MinRefreshInterval > 0 {
		return c.MinRefreshInterval
	}
	return 30 * time.Second
}

func (c *Client) negCacheTTL() time.Duration {
	if c.NegCacheTTL > 0 {
		return c.NegCacheTTL
	}
	return 3 * time.Second
}

// Resources returns the repo -> resource index, served from a ~60s
// cache and refreshed on a miss (absent or expired). A failed refresh
// falls back to the stale index when one exists, and further calls
// inside the TTL window keep serving it — lastAttemptAt backs the
// fetch off so an ATC outage doesn't serialize every webhook request
// behind the HTTP timeout.
//
// The mutex is never held across the network fetch: the decision and
// the lastAttemptAt stamp happen under the lock, the fetch runs
// unlocked, and only a successful publish re-takes it. Callers that
// arrive while a fetch is in flight are served the current index
// immediately when there is one (stale is fine — the in-flight fetch
// will replace it). On a cold start there is nothing to serve, so the
// caller instead waits on the in-flight fetch and shares its result:
// concurrent first deliveries must not stampede the ATC with
// duplicate full-index fetches. The wait is bounded by the caller's
// context, so a wedged ATC still can't hang the handler forever.
// fetchFlightBudget bounds the DETACHED fetch context — deliberately
// longer than the handler's synchronous wait budget (7s) so a caller
// timing out never kills the shared fetch every other caller joined.
const fetchFlightBudget = 30 * time.Second

// runFetch executes one index fetch on a caller-detached context and
// publishes the outcome: success replaces the index/lookup wholesale,
// failure records the cold-start negative cache and wakes joiners
// via flight.err. It owns the flight's whole lifecycle — install,
// clear, done-close — so EVERY caller (starter included) is just a
// waiter on done; no caller blocks inside fetchIndex itself.
func (c *Client) runFetch(callerCtx context.Context, flight *fetchFlight, prev []Resource) {
	// WithoutCancel strips the caller's deadline AND cancellation:
	// the fetch is shared work — a 7s wait-budget expiring on one
	// delivery must not abort the fetch other deliveries joined.
	fetchCtx, cancel := context.WithTimeout(
		context.WithoutCancel(callerCtx), fetchFlightBudget)
	defer cancel()
	index, err := c.fetchIndex(fetchCtx, prev)

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.flight == flight {
		c.flight = nil
	}
	if err != nil {
		flight.err = err // before close(done) — joiners read it
		// Negative-cache the failure (NegCacheTTL) — waiters waking
		// on done re-loop into this check and share the error
		// rather than serializing fetches.
		c.lastErr, c.lastErrAt = err, time.Now()
		indexFetchErrorsTotal.Inc()
		if c.index != nil {
			logger().Warn("resource index refresh failed — serving stale",
				"concourse_url", c.BaseURL, "team", c.Team,
				"error", err)
		}
	} else {
		// The client keeps its OWN copy of the fetched index — the
		// caller's slice must not alias the cache, or a caller
		// mutating its return value would corrupt what every later
		// delivery matches against. Serve paths below clone out too.
		c.index = slices.Clone(index)
		c.fetchedAt = time.Now()
		c.lookup = newLookup(c.index)
		c.lastErr = nil
		// Freshness signal: this gauge moves only here and in
		// Refresh's success path — a stalled value is the
		// stale-index alarm.
		indexLastRefreshSeconds.Set(float64(c.fetchedAt.Unix()))
	}
	close(flight.done)
}

// Resources returns the repo -> resource index, served from a ~60s
// cache and refreshed on a miss (absent or expired). A failed refresh
// falls back to the stale index when one exists, and further calls
// inside the TTL window keep serving it — lastAttemptAt backs the
// fetch off so an ATC outage doesn't serialize every webhook request
// behind the HTTP timeout.
//
// The mutex is never held across the network fetch: callers only ever
// WAIT on a fetchFlight's done channel — the fetch itself runs
// detached on fetchFlightBudget inside runFetch, so a caller's wait
// budget expiring (the handler's 7s synchronous window vs GitHub's
// ~10s webhook timeout) returns the stale index — or ctx.Err() on a
// cold start with nothing to serve — while the fetch keeps running
// for whoever joined it.
func (c *Client) Resources(ctx context.Context) ([]Resource, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for {
		c.mu.Lock()
		if c.index != nil && time.Since(c.fetchedAt) < c.ttl() {
			index := slices.Clone(c.index)
			c.mu.Unlock()
			return index, nil
		}
		// A fetch is already in flight — never start a second one on
		// top of it. With an index to serve, even a stale one, this
		// caller is answered immediately (stale-while-revalidate:
		// the in-flight fetch will replace it momentarily); only a
		// cold start has nothing to serve and must wait on done,
		// sharing the fetch's result instead of stampeding the ATC.
		if c.flight != nil {
			f := c.flight
			index := c.index
			c.mu.Unlock()
			if index != nil {
				return slices.Clone(index), nil
			}
			select {
			case <-f.done:
				// The flight settled. Serve whatever it left
				// behind directly rather than re-running the
				// TTL checks above: a SUCCESS publishes a fresh
				// index, a FAILURE leaves the index nil — both
				// are the answer this call exists to produce,
				// and re-deciding would spin a fresh fetch per
				// wake whenever the fetch outlasts the TTL.
				c.mu.Lock()
				index = c.index
				c.mu.Unlock()
				if index != nil {
					return slices.Clone(index), nil
				}
				// Cold start, fetch failed — loop into the
				// negative-cache check, which hands back the
				// flight's shared error within NegCacheTTL
				// instead of serializing doomed rebuilds.
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		// The last attempt failed inside the same TTL window — serve
		// the stale index without re-fetching. Without this backoff
		// every request re-takes the mutex and blocks on a doomed
		// fetch. Reached only when NO fetch is in flight: a running
		// one was joined above.
		if c.index != nil && time.Since(c.lastAttemptAt) < c.ttl() {
			index := slices.Clone(c.index)
			c.mu.Unlock()
			return index, nil
		}
		// Cold-start negative cache: the last fetch failed with
		// nothing to serve — hand back the SHARED error instead of
		// letting this caller stamp a fresh attempt and start the
		// next doomed rebuild. Gated on index==nil: with a stale
		// index to serve the backoff check above already owns the
		// retry decision.
		if c.index == nil && c.lastErr != nil &&
			time.Since(c.lastErrAt) < c.negCacheTTL() {
			err := c.lastErr
			c.mu.Unlock()
			return nil, err
		}
		// No fetch running: stamp the attempt (concurrent callers
		// hitting the checks above must see a fresh lastAttemptAt
		// and be served the existing index / join this flight
		// instead of starting their own) and install the flight.
		// The fetch itself is detached — see runFetch.
		c.lastAttemptAt = time.Now()
		flight := &fetchFlight{done: make(chan struct{})}
		c.flight = flight
		prev := slices.Clone(c.index)
		c.mu.Unlock()
		go c.runFetch(ctx, flight, prev)
		// The starter waits on ITS OWN flight rather than looping:
		// joiners with a stale index are answered instantly above,
		// but this caller asked for the refresh — it gets the
		// fetch's outcome (fresh index, stale on failure, the
		// shared error on a cold start).
		select {
		case <-flight.done:
			c.mu.Lock()
			index := c.index
			c.mu.Unlock()
			if index != nil {
				return slices.Clone(index), nil
			}
			if flight.err != nil {
				return nil, flight.err
			}
			continue // unreachable — re-decide defensively
		case <-ctx.Done():
			// Same rule as the join wait: cancellation reports
			// itself; only a wait-budget DEADLINE falls back to
			// the stale index (a cold start still errors).
			if errors.Is(ctx.Err(), context.Canceled) {
				return nil, ctx.Err()
			}
			c.mu.Lock()
			stale := c.index
			c.mu.Unlock()
			if stale != nil {
				return slices.Clone(stale), nil
			}
			return nil, ctx.Err()
		}
	}
}

// Refresh forces an index refetch, bypassing the TTL — used when a
// delivery matched nothing, covering a pipeline set since the last
// fetch. Calls are throttled to MinRefreshInterval on the
// Refresh-owned lastForceRefreshAt clock: repos without a pipeline
// zero-match every delivery, so an unthrottled refresh would turn
// org-webhook volume into constant index rebuilds. The clock is
// deliberately separate from Resources' lastAttemptAt — a forced
// refresh must not be suppressed by an unrelated cache miss that just
// stamped its own attempt, and a failed forced refresh must not
// silently extend Resources' backoff window. A failed refresh keeps
// the previous index.
//
// The fetch runs outside the mutex, same snapshot pattern as
// Resources; it installs its own flight, so cold-start Resources
// callers arriving mid-refresh share this fetch's result instead of
// starting a duplicate one.
//
// A fetch already in flight is JOINED, not duplicated: the waiter
// blocks on the flight's done channel and re-runs the cache checks —
// it neither overwrites c.flight, nor is rejected by
// MinRefreshInterval, nor fires a second index rebuild at the ATC.
// Only when no fetch is running does the throttle apply.
func (c *Client) Refresh(ctx context.Context) ([]Resource, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for {
		c.mu.Lock()
		if f := c.flight; f != nil {
			c.mu.Unlock()
			select {
			case <-f.done:
				if f.err != nil {
					// The fetch we joined failed — report it
					// rather than looping into the throttle
					// branch, which would serve the stale index
					// with a nil error and hide the failure (and
					// skip the forced retry this call exists for).
					return nil, f.err
				}
				// The joined fetch settled cleanly — loop back
				// and serve whatever it published.
				continue
			case <-ctx.Done():
				// Same rule as Resources: cancellation reports
				// itself; only a wait-budget DEADLINE falls back
				// to the stale index (cold start still errors).
				if errors.Is(ctx.Err(), context.Canceled) {
					return nil, ctx.Err()
				}
				c.mu.Lock()
				stale := c.index
				c.mu.Unlock()
				if stale != nil {
					return slices.Clone(stale), nil
				}
				return nil, ctx.Err()
			}
		}
		// Cold-start negative cache — same shared lastErr window
		// Resources consults, so a failed fetch can't be re-armed
		// in a tight retry loop by alternating entry points.
		if c.index == nil && c.lastErr != nil &&
			time.Since(c.lastErrAt) < c.negCacheTTL() {
			err := c.lastErr
			c.mu.Unlock()
			return nil, err
		}
		// The throttle watches lastForceRefreshAt AND fetchedAt: a
		// successful fetch — Resources' opportunistic refresh or a
		// prior forced Refresh — published moments ago already IS
		// the fresh index this call exists to produce; rebuilding it
		// again inside MinRefreshInterval is duplicate ATC load (the
		// zero-match retry calls Refresh right after Resources just
		// fetched, and a Refresh that joined an in-flight fetch must
		// not fire a second rebuild on wake). fetchedAt can't see
		// failed attempts — lastForceRefreshAt covers those.
		// The throttle only applies when there IS an index to serve:
		// on a cold start (index == nil) a second Refresh inside the
		// window would otherwise clone the nil index and return
		// (nil, nil) — a silent empty success instead of the fetch
		// error the caller asked a forced refresh to surface.
		if c.index != nil &&
			(time.Since(c.fetchedAt) < c.minRefreshInterval() ||
				time.Since(c.lastForceRefreshAt) < c.minRefreshInterval()) {
			index := slices.Clone(c.index)
			c.mu.Unlock()
			return index, nil
		}
		// Stamp before spawning so concurrent Refresh callers take
		// the throttle branch (or join this flight) instead of
		// queueing a second fetch behind this one; a failure keeps
		// that stamp so the next forced refresh inside the throttle
		// window still serves the cached index instead of
		// immediately re-fetching a just-failed ATC. The fetch runs
		// detached — see runFetch — so this stamp can never be
		// "restored" by a caller unwind: a started fetch really did
		// happen.
		c.lastForceRefreshAt = time.Now()
		flight := &fetchFlight{done: make(chan struct{})}
		c.flight = flight
		prev := slices.Clone(c.index)
		c.mu.Unlock()
		go c.runFetch(ctx, flight, prev)
		// Wait on OUR OWN flight directly — same shape as
		// Resources' starter path. Looping back to the top would
		// re-decide through the throttle: lastForceRefreshAt was
		// stamped milliseconds ago, so a fetch that already
		// settled (or one whose c.flight pointer was cleared
		// before we re-locked) could fall into the throttle
		// branch and answer the OLD index with a nil error —
		// hiding the fetch outcome this call exists to surface.
		select {
		case <-flight.done:
			// Same ordering as the join wait above: a failed
			// fetch reports its error — serving the stale index
			// with a nil error would hide the failure this
			// forced refresh exists to surface.
			if flight.err != nil {
				return nil, flight.err
			}
			c.mu.Lock()
			index := c.index
			c.mu.Unlock()
			if index != nil {
				return slices.Clone(index), nil
			}
			continue // unreachable — re-decide defensively
		case <-ctx.Done():
			// Same rule as Resources/the join wait: cancellation
			// reports itself; only a wait-budget DEADLINE falls
			// back to the stale index (cold start still errors).
			if errors.Is(ctx.Err(), context.Canceled) {
				return nil, ctx.Err()
			}
			c.mu.Lock()
			stale := c.index
			c.mu.Unlock()
			if stale != nil {
				return slices.Clone(stale), nil
			}
			return nil, ctx.Err()
		}
	}
}

// fetchIndexWorkers bounds how many pipeline resource listings run
// concurrently — a large team shouldn't fan one GET per pipeline at
// the ATC all at once, but a serial listing is what made index
// rebuilds slow enough to matter.
const fetchIndexWorkers = 8

// fetchIndex lists the team's pipelines, then each pipeline's
// resources, keeping only resources whose source points at a repo.
// prev is the caller's snapshot of the current index, taken under
// c.mu before the fetch started. The per-pipeline listings run in
// parallel (bounded by fetchIndexWorkers); results stay in pipeline
// order so the index is deterministic.
func (c *Client) fetchIndex(ctx context.Context,
	prev []Resource) ([]Resource, error) {
	start := time.Now()
	var pipelines []struct {
		Name         string         `json:"name"`
		Archived     bool           `json:"archived"`
		InstanceVars map[string]any `json:"instance_vars"`
	}
	if err := c.getJSON(ctx, c.apiPath("pipelines"), &pipelines); err != nil {
		return nil, err
	}
	// Archived pipelines are gone for check purposes — listing their
	// resources would index dead entries (and their /resources calls
	// can 404 or hang on the archived flag). Drop them up front.
	live := pipelines[:0]
	for _, p := range pipelines {
		if !p.Archived {
			live = append(live, p)
		}
	}
	pipelines = live

	// Snapshot the previous index per (pipeline, varsQuery): a
	// transient per-pipeline listing failure below must carry its
	// last-known resources into the new index rather than silently
	// unregistering them — err stays nil, so a partial result would
	// otherwise overwrite c.index with a silently smaller view. The
	// varsQuery half of the key matters: a set_pipeline step can
	// re-instance a pipeline under DIFFERENT vars while keeping the
	// name — carrying the old instance's resources over would index
	// entries the new instance does not have. (Copied from c.index
	// under c.mu by the caller before this fetch started, so no
	// lock is needed here.)
	prevByPipeline := make(map[string][]Resource)
	for _, r := range prev {
		key := r.Pipeline + "\x00" + r.InstanceVarsQuery
		prevByPipeline[key] = append(prevByPipeline[key], r)
	}

	results := make([][]Resource, len(pipelines))
	// varsQuery[i] is the pipeline's instance_vars rendered as the
	// ATC dot-notation query fragment — instanced pipelines only
	// resolve /resources and check webhooks under ?vars.<key>=, so
	// the same fragment rides every Resource and both call sites.
	// Empty for non-instanced pipelines.
	varsQuery := make([]string, len(pipelines))
	for i, p := range pipelines {
		varsQuery[i] = instanceVarsQuery(p.InstanceVars)
	}
	// lost[i] records a pipeline whose listing failed with nothing in
	// the previous index to carry over — the refreshed index would be
	// silently missing its resources, so the fetch must fail instead
	// of caching an incomplete view (see below). failed[i] records
	// ANY listing failure (404-deleted pipelines excluded — they are
	// gone, not unreadable): when every listing fails the "refresh"
	// learned nothing, and returning the carried-over prev data as a
	// success would stamp fetchedAt and freeze the stale index for
	// the whole TTL.
	lost := make([]string, len(pipelines))
	failed := make([]bool, len(pipelines))
	sem := make(chan struct{}, fetchIndexWorkers)
	var wg sync.WaitGroup
	for i, p := range pipelines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			var resources []struct {
				Name   string `json:"name"`
				Type   string `json:"type"`
				Source source `json:"source"`
			}
			path := "pipelines/" + url.PathEscape(p.Name) + "/resources"
			if varsQuery[i] != "" {
				path += "?" + varsQuery[i]
			}
			if err := c.getJSON(ctx, c.apiPath(path), &resources); err != nil {
				var se *statusError
				if errors.As(err, &se) && se.status == http.StatusNotFound {
					// The pipeline was deleted between the pipeline
					// listing and this fetch — it has no resources.
					// Carrying prevByPipeline entries over would keep
					// ghost resources of a dead pipeline in the index.
					return
				}
				// One unreadable pipeline must not lose the whole
				// index — and must not lose its own resources either:
				// retain the previous index's entries for it (the
				// pipeline still exists — only its listing failed).
				// Pipelines truly gone drop out via the pipeline list
				// itself, not through this path. The carry-over key
				// includes the vars fragment — resources of a
				// re-instanced pipeline under different vars must
				// not leak into the new instance's index.
				carryKey := p.Name + "\x00" + varsQuery[i]
				results[i] = append(results[i], prevByPipeline[carryKey]...)
				failed[i] = true
				if len(prevByPipeline[carryKey]) == 0 {
					// Nothing to carry over — the new index would
					// silently lack this pipeline's resources.
					lost[i] = p.Name
				}
				logger().Warn("pipeline resource listing failed — keeping last-known resources",
					"concourse_url", c.BaseURL, "team", c.Team,
					"pipeline", p.Name, "error", err)
				return
			}
			for _, r := range resources {
				repo := NormalizeRepo(sourceRepo(r.Source))
				if repo == "" {
					continue
				}
				results[i] = append(results[i], Resource{
					Pipeline:          p.Name,
					Name:              r.Name,
					Type:              r.Type,
					Repo:              repo,
					InstanceVarsQuery: varsQuery[i],
				})
			}
		}()
	}
	wg.Wait()

	// A pipeline whose listing failed with no last-known resources to
	// carry means the index is incomplete: caching it would stamp
	// fetchedAt and answer 202/nothing-matched for the TTL window,
	// dropping build triggers. Fail the fetch instead — the callers
	// then serve the stale index (or 502 on a cold start) and retry.
	var missing []string
	for _, name := range lost {
		if name != "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf(
			"resource listings failed with no prior data: %s",
			strings.Join(missing, ","))
	}

	// Every pipeline listing failed: the fetch produced nothing but
	// carried-over prev entries. Returning them as a success would
	// stamp fetchedAt (and satisfy Refresh's freshness throttle) on
	// data that never refreshed — the stale index would be served as
	// "fresh" for the whole TTL. Fail so the callers take the error
	// path: serve stale through lastAttemptAt backoff and retry.
	if len(pipelines) > 0 {
		allFailed := true
		for _, f := range failed {
			if !f {
				allFailed = false
				break
			}
		}
		if allFailed {
			return nil, fmt.Errorf(
				"all %d pipeline resource listings failed", len(pipelines))
		}
	}

	var index []Resource
	for _, rs := range results {
		index = append(index, rs...)
	}
	if index == nil {
		// Keep it non-nil: a healthy empty index must still count as
		// "fetched" for the TTL check and the stale fallback.
		index = []Resource{}
	}
	logger().Info("resource index refreshed",
		"concourse_url", c.BaseURL, "team", c.Team,
		"pipelines", len(pipelines), "resources", len(index),
		"duration", time.Since(start).Round(time.Millisecond))
	return index, nil
}

// CheckWebhook POSTs the resource's check webhook. The webhook_token
// query param is the credential, so no basic auth is sent. It returns
// the ATC status code so the caller can classify warn vs error;
// transport errors return 0.
func (c *Client) CheckWebhook(ctx context.Context, r Resource) (int, error) {
	u := strings.TrimSuffix(c.BaseURL, "/") + c.apiPath(
		"pipelines/"+url.PathEscape(r.Pipeline)+
			"/resources/"+url.PathEscape(r.Name)+"/check/webhook") +
		"?webhook_token=" + url.QueryEscape(c.WebhookToken)
	if r.InstanceVarsQuery != "" {
		// Instanced pipelines check under their instance vars —
		// without ?vars.<key>= the ATC can't resolve which instance
		// to check (and may 404 the resource outright).
		u += "&" + r.InstanceVarsQuery
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		// url.Parse failures surface as *url.Error embedding the raw
		// URL — webhook_token included. Unwrap like the Do path.
		var ue *url.Error
		if errors.As(err, &ue) {
			return 0, ue.Err
		}
		return 0, err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		// Do wraps transport failures in *url.Error, which embeds the
		// full request URL — webhook_token included — and would leak
		// the token into error logs. Return only the wrapped error.
		var ue *url.Error
		if errors.As(err, &ue) {
			return 0, ue.Err
		}
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	// Drain (bounded) so the keep-alive connection can be reused.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, nil
}

// apiPath prefixes p with the team-scoped API root.
// instanceVarsQuery renders a pipeline's instance_vars as the ATC
// dot-notation query fragment, mirroring Concourse's own encoder
// (atc/pipeline.go QueryParams over vars.StaticVariables.Flatten):
// nested maps are FLATTENED into dot-joined leaf paths — the ATC
// parses vars.a.b back into {"a":{"b":...}}, so a nested instance_vars
// must never be sent as one JSON blob — and every path segment that
// contains a dot (or any of ",.:/ ") is %q-quoted so a literal
// "release.line" key stays one segment instead of reading as nesting.
// One vars.<key>=<json-val> param per leaf, keys sorted by rendered
// ref so two fetches of the same vars produce byte-identical
// fragments (cache-friendly, diff-friendly logs). "" for
// non-instanced pipelines; empty maps flatten to zero pairs (the var
// vanishes, matching Flatten); a leaf whose value fails to marshal
// is skipped rather than failing the whole listing.
func instanceVarsQuery(vars map[string]any) string {
	if len(vars) == 0 {
		return ""
	}
	pairs := flattenInstanceVars(vars)
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].ref < pairs[j].ref })
	var b strings.Builder
	for _, p := range pairs {
		v, err := json.Marshal(p.value)
		if err != nil {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('&')
		}
		b.WriteString(url.QueryEscape("vars." + p.ref))
		b.WriteByte('=')
		b.WriteString(url.QueryEscape(string(v)))
	}
	return b.String()
}

// instanceVarPair is one flattened leaf: the dot-notation ref the
// ATC parses (segments already quoting-applied) plus its JSON value.
type instanceVarPair struct {
	ref   string
	value any
}

// flattenInstanceVars walks the instance_vars tree the way
// vars.StaticVariables.Flatten does: only map[string]any nodes
// recurse — every other value (including lists and nil) is a leaf.
// An empty map contributes zero pairs.
func flattenInstanceVars(vars map[string]any) []instanceVarPair {
	var pairs []instanceVarPair
	for k, v := range vars {
		pairs = append(pairs, flattenInstanceVar(k, nil, v)...)
	}
	return pairs
}

func flattenInstanceVar(path string, fields []string, value any) []instanceVarPair {
	if m, ok := value.(map[string]any); ok {
		var out []instanceVarPair
		for k, v := range m {
			out = append(out, flattenInstanceVar(path, append(fields, k), v)...)
		}
		return out
	}
	var b strings.Builder
	b.WriteString(instanceVarSegment(path))
	for _, f := range fields {
		b.WriteByte('.')
		b.WriteString(instanceVarSegment(f))
	}
	return []instanceVarPair{{ref: b.String(), value: value}}
}

// instanceVarSegment quotes a path segment exactly like Concourse's
// refSegmentString: segments containing a separator char (",.:/ ")
// are wrapped in Go quoting so the ATC's dot-notation parser keeps
// them as ONE field.
func instanceVarSegment(seg string) string {
	if strings.ContainsAny(seg, ",.:/ ") {
		return fmt.Sprintf("%q", seg)
	}
	return seg
}

func (c *Client) apiPath(p string) string {
	return "/api/v1/teams/" + url.PathEscape(c.Team) + "/" + p
}

// maxJSONBody bounds how much of a 2xx ATC response getJSON will
// decode — matched to the handler's 8 MiB inbound webhook body cap
// (handler.maxBodyBytes). Real index/listing payloads are far
// smaller, so a longer body means a wedged or hostile peer and the
// decode must fail instead of buffering the stream whole.
const maxJSONBody = 8 << 20 // 8 MiB

func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	// Up to two attempts: a 401 on a bearer-token request invalidates
	// the cached token and re-mints exactly once (auth.go) — a
	// revoked/expired-early token self-heals instead of failing the
	// whole index fetch. Basic-mode requests never retry: their 401
	// is a credential problem, not a stale token.
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			strings.TrimSuffix(c.BaseURL, "/")+path, nil)
		if err != nil {
			return err
		}
		usedToken, err := c.authorize(ctx, req)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		resp, err := c.httpClient().Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode == http.StatusUnauthorized && usedToken != "" && attempt == 0 {
			_ = resp.Body.Close()
			// Invalidate only the token THIS request carried — a
			// fresher token another worker already minted survives.
			c.invalidateToken(usedToken)
			continue
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode/100 != 2 {
			// Drain (bounded) so the keep-alive connection can be reused.
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			return &statusError{status: resp.StatusCode, path: path}
		}
		// Bound the decode: without LimitReader a 2xx body longer than
		// maxJSONBody (an ATC streaming forever) would be buffered whole.
		err = json.NewDecoder(io.LimitReader(resp.Body, maxJSONBody)).Decode(out)
		// Drain whatever the decoder left before the body closes: a decode
		// that finished before EOF (trailing newline, whitespace, extra
		// documents) or one that failed at the maxJSONBody cap would
		// otherwise strand the keep-alive connection, forcing every later
		// call to re-dial. Bounded like the error path — an endless
		// hostile stream is abandoned, not drained forever.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return err
	}
}

// source is the slice of a resource's source config the index needs:
// git-type resources carry the repo in "uri", github-pr resources in
// "repository". A struct rather than map[string]any: the decode keeps
// encoding/json's tolerance for every other key a resource type
// carries (interval, check_every, ...) and skips the per-resource map
// allocation — a whole-team index decode used to build a map per
// resource only to fish out one string.
type source struct {
	URI        string `json:"uri"`
	Repository string `json:"repository"`
}

// sourceRepo pulls the repo identity out of a resource's source;
// "uri" wins when both keys are present (a github-pr resource with a
// git uri checks out via the uri), the same precedence the map-based
// decode had.
func sourceRepo(s source) string {
	if s.URI != "" {
		return s.URI
	}
	return s.Repository
}

// NormalizeRepo reduces a GitHub repo identifier — scp-like SSH
// (git@github.com:org/repo.git), ssh:// or HTTPS URL
// (ssh://git@github.com[:port]/org/repo[.git],
// https://github.com[:port]/org/repo[.git]) or bare "org/repo" — to
// the lowercase "org/repo" form used for equality matching.
//
// The "github.com" prefix is stripped only where github.com can
// actually be the host: at the start of the string, or immediately
// after "://" (scheme separator) or "@" (scp user marker), AND only
// when "/" or ":" follows (path or scp separator). Anywhere else —
// "git.github.com", "notgithub.com", "github.com.evil.com", a mention
// inside a path — the match is part of a longer hostname or of the
// path, and the input must NOT collapse to "org/repo" or it would
// match resources it has no business matching.
func NormalizeRepo(s string) string {
	// Lowercase and strip the trailing ".git" up front: the host
	// match and the suffix strip are both case-sensitive, and an
	// upper-cased "GitHub.COM"/"Repo.GIT" must still normalize.
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, "/")
	s = strings.TrimSuffix(s, ".git")
	i := strings.Index(s, "github.com")
	if i < 0 {
		return s
	}
	// Host boundary: start of string, or right after the scheme
	// separator or a user marker — and the host must be followed by
	// the path separator ("/") or the scp separator (":"). A match
	// failing either test is mid-string and stays untouched.
	atHost := i == 0 ||
		strings.HasSuffix(s[:i], "://") || strings.HasSuffix(s[:i], "@")
	rest := s[i+len("github.com"):]
	if !atHost || rest == "" || (rest[0] != '/' && rest[0] != ':') {
		return s
	}
	if rest[0] == ':' {
		rest = rest[1:]
		// What the colon means depends on the syntax around the
		// host:
		//   scheme://[user@]host:port/path — a :<digits>/ segment
		//     is a TCP port to drop;
		//   host:port/path with no user part — likewise a port;
		//   user@host:path (scp-like, "git@github.com:…") — the
		//     colon IS the path separator, so an all-numeric
		//     first segment is an org, not a port.
		// Scp-like = a user@ part ahead of the host with no "//"
		// authority marker before it.
		prefix := s[:i]
		scpLike := strings.ContainsRune(prefix, '@') &&
			!strings.Contains(prefix, "//")
		if !scpLike {
			j := 0
			for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
				j++
			}
			if j > 0 && j < len(rest) && rest[j] == '/' {
				rest = rest[j:]
			}
		}
	}
	return strings.TrimLeft(rest, "/")
}
