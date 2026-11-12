// index.go — the resource-index cache: TTL reads (Resources /
// EnsureIndex), forced refreshes (Refresh / RefreshIndex) and the
// singleflight fetch plumbing (fetchFlight, runFetch,
// waitRefreshFlight) every entry point shares.
//
// The mutex is never held across the network fetch: the decision and
// the attempt stamps happen under the lock, the fetch runs unlocked
// on a caller-detached context inside runFetch, and only a
// successful publish re-takes it. Callers that arrive while a fetch
// is in flight are served the current index immediately when there
// is one (stale is fine — the in-flight fetch will replace it); only
// a cold start has nothing to serve and must wait on the flight's
// done channel, sharing the fetch's result instead of stampeding the
// ATC with duplicate full-index fetches.
package concourse

import (
	"context"
	"errors"
	"slices"
	"time"
)

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
				"concourse_url", c.safeBaseURL(), "team", c.Team,
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

// serveIndex clones idx for a clone=true caller and returns nil for
// the error-only entry points (EnsureIndex / RefreshIndex) — the
// handler Matches against the published lookup right after, so
// copying the whole index slice per webhook delivery was pure waste.
func serveIndex(idx []Resource, clone bool) []Resource {
	if !clone {
		return nil
	}
	return slices.Clone(idx)
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
	return c.resources(ctx, true)
}

// EnsureIndex runs the same TTL/singleflight/backoff decision as
// Resources but returns only the error — for callers (the handler)
// that go straight to Match against the published lookup and never
// needed the index slice cloned out per delivery.
func (c *Client) EnsureIndex(ctx context.Context) error {
	_, err := c.resources(ctx, false)
	return err
}

func (c *Client) resources(ctx context.Context, clone bool) ([]Resource, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for {
		c.mu.Lock()
		if c.index != nil && time.Since(c.fetchedAt) < c.ttl() {
			index := c.index
			c.mu.Unlock()
			return serveIndex(index, clone), nil
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
				return serveIndex(index, clone), nil
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
					return serveIndex(index, clone), nil
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
			index := c.index
			c.mu.Unlock()
			return serveIndex(index, clone), nil
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
				return serveIndex(index, clone), nil
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
			return c.staleOrErr(ctx, clone)
		}
	}
}

// staleOrErr serves the current index for a caller whose wait budget
// expired — the deadline-fallback half of every wait site. A cold
// start (nothing published yet) reports ctx.Err() instead.
func (c *Client) staleOrErr(ctx context.Context, clone bool) ([]Resource, error) {
	c.mu.Lock()
	index := c.index
	c.mu.Unlock()
	if index != nil {
		return serveIndex(index, clone), nil
	}
	return nil, ctx.Err()
}

// waitRefreshFlight blocks until the flight settles or ctx ends and
// classifies the outcome for BOTH Refresh wait sites (a joined
// in-flight fetch and the starter's own fetch):
//
//   - joined=true, err=nil — the fetch succeeded; the caller loops
//     back and serves whatever it published (or, for the starter,
//     reads the fresh index directly).
//   - joined=false, err!=nil — return err: the flight's own failure,
//     or ctx.Err() on cancellation. A failed fetch must surface —
//     serving the stale index with a nil error would hide the
//     failure a forced refresh exists to report.
//   - joined=false, err=nil — the wait budget (not a cancellation)
//     expired; the caller falls back to the stale index via
//     staleOrErr.
//
// Going through one helper keeps the join path and the starter path
// from drifting: the old bug was the starter looping back to the top
// of Refresh after its own fetch settled, where the just-stamped
// lastForceRefreshAt throttle answered the OLD index with a nil
// error — hiding the fetch outcome this call exists to surface.
func (c *Client) waitRefreshFlight(ctx context.Context, f *fetchFlight) (joined bool, err error) {
	select {
	case <-f.done:
		if f.err != nil {
			return false, f.err
		}
		return true, nil
	case <-ctx.Done():
		// Same rule as Resources: cancellation reports itself; only
		// a wait-budget DEADLINE falls back to the stale index
		// (cold start still errors).
		if errors.Is(ctx.Err(), context.Canceled) {
			return false, ctx.Err()
		}
		return false, nil
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
// blocks on the flight's done channel via waitRefreshFlight and
// re-runs the cache checks — it neither overwrites c.flight, nor is
// rejected by MinRefreshInterval, nor fires a second index rebuild at
// the ATC. Only when no fetch is running does the throttle apply.
func (c *Client) Refresh(ctx context.Context) ([]Resource, error) {
	return c.refresh(ctx, true)
}

// RefreshIndex is the error-only view of Refresh — the handler's
// zero-match retry only needs to know whether the forced fetch
// failed; the index slice itself is read through Match.
func (c *Client) RefreshIndex(ctx context.Context) error {
	_, err := c.refresh(ctx, false)
	return err
}

func (c *Client) refresh(ctx context.Context, clone bool) ([]Resource, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for {
		c.mu.Lock()
		if f := c.flight; f != nil {
			c.mu.Unlock()
			joined, err := c.waitRefreshFlight(ctx, f)
			if err != nil {
				// The fetch we joined failed — report it rather
				// than looping into the throttle branch, which
				// would serve the stale index with a nil error
				// and hide the failure (and skip the forced
				// retry this call exists for).
				return nil, err
			}
			if !joined {
				// Wait-budget deadline — serve the stale index.
				return c.staleOrErr(ctx, clone)
			}
			// The joined fetch settled cleanly — loop back and
			// serve whatever it published.
			continue
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
			index := c.index
			c.mu.Unlock()
			return serveIndex(index, clone), nil
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
		// Wait on OUR OWN flight directly via the same helper the
		// join path uses — never loop back to the top: the throttle
		// was stamped milliseconds ago, so re-deciding could answer
		// the OLD index with a nil error and hide the fetch outcome
		// this call exists to surface.
		joined, err := c.waitRefreshFlight(ctx, flight)
		if err != nil {
			// Same ordering as the join wait above: a failed
			// fetch reports its error — serving the stale index
			// with a nil error would hide the failure this
			// forced refresh exists to surface.
			return nil, err
		}
		if !joined {
			return c.staleOrErr(ctx, clone)
		}
		// Our fetch published a fresh index — serve it directly
		// rather than re-deciding through the throttle.
		c.mu.Lock()
		index := c.index
		c.mu.Unlock()
		if index != nil {
			return serveIndex(index, clone), nil
		}
		continue // unreachable — re-decide defensively
	}
}
