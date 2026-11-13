// dispatch.go owns the post-verification half of a delivery: the
// synchronous index ensure, repo match (with the zero-match forced
// refresh retry), and the detached, bounded check-webhook fan-out.
// See handler.go for the request-admission and payload front half.
package handler

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/webhook-dispatcher/internal/concourse"
)

// fanoutStart registers a delivery's would-be fan-out with the
// WaitGroup — MUST run before the index fetch (see Wait for the race
// this closes). fanoutDone releases it; every exit path that started
// a registration Dones exactly once.
func (h *Handler) fanoutStart() {
	h.wg.Add(1)
	h.inFlight.Add(1)
}

func (h *Handler) fanoutDone() {
	// Counted down BEFORE wg.Done: a Wait that observes the WaitGroup
	// drain must never read a stale inFlight count.
	h.inFlight.Add(-1)
	h.wg.Done()
}

// Wait blocks until every in-flight background fan-out has finished,
// or ctx's budget expires — the graceful-shutdown path calls it once
// the HTTP server has drained so the last check POSTs land before the
// process exits (the fan-outs run on detached contexts and otherwise
// outlive the listener). The budget is what makes the shutdown
// contract honest: Shutdown(10s) + Wait ≤ ~25s, under the pod's 30s
// SIGKILL grace. On expiry it logs how many fan-outs were abandoned
// (their own fanoutBudget or the process kill ends them — they are
// never left waiting forever) and returns that count; a clean drain
// returns 0.
func (h *Handler) Wait(ctx context.Context) int {
	// Flip draining FIRST: requests still inside ServeHTTP finish
	// normally, but anything reaching admit() from here on is
	// rejected 503 — Wait's WaitGroup observation can't be raced by
	// a request that slipped its Add in after the check.
	h.drainMu.Lock()
	h.draining = true
	h.drainMu.Unlock()
	done := make(chan struct{})
	go func() {
		h.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return 0
	case <-ctx.Done():
		dropped := h.inFlight.Load()
		logger().Warn("fan-out drain budget expired — in-flight check POSTs abandoned",
			"in_flight_fanouts", dropped)
		return int(dropped)
	}
}

// accept runs the post-verification half of a delivery: repo
// normalization, the detached-budget index ensure, the O(1) match
// (plus the zero-match forced refresh retry) and the 202 response —
// spawning the detached fan-out when anything matched.
func (h *Handler) accept(w http.ResponseWriter, r *http.Request,
	delivery, event, eventMetric, wantType string, p payload) {
	// The event's repo identities — resources reference the same repo
	// via ssh or https indifferently, so every URL form the payload
	// carries is a match candidate.
	repos := map[string]struct{}{}
	for _, u := range []string{
		p.Repository.FullName, p.Repository.SSHURL,
		p.Repository.CloneURL, p.Repository.HTMLURL,
	} {
		if n := concourse.NormalizeRepo(u); n != "" {
			repos[n] = struct{}{}
		}
	}

	// The index fetch is the only ATC call still in the request path.
	// It runs detached from the request lifetime: a client disconnect
	// mid-fetch must not poison the shared cache the fetch populates.
	// The wait budget (indexWaitBudget, 7s) stays under GitHub's ~10s
	// webhook timeout; the client's fetchFlight runs the fetch itself
	// on a longer detached budget, so this ctx expiring serves the
	// stale index — it never aborts the shared fetch.
	ctx, cancel := context.WithTimeout(
		context.WithoutCancel(r.Context()), indexWaitBudget)
	defer cancel()

	// Register with the WaitGroup BEFORE the index fetch: the fan-out
	// may or may not spawn (the match set can be empty, the fetch can
	// fail), but a concurrent Wait must already see this delivery
	// counted. Otherwise the graceful-shutdown path could race:
	// wh.Wait() observing an empty WaitGroup in the window between the
	// fetch and wg.Add(1) would return while this delivery's fan-out
	// was still starting, and the process could exit with check POSTs
	// unlanded. Every exit below either spawns the goroutine (which
	// Dones) or Dones explicitly.
	h.fanoutStart()
	// The index slice itself is not needed — Match consults the
	// backend's published (type, repo) lookup — but the fetch must
	// run: it owns the TTL/singleflight decision that populates the
	// lookup this match reads.
	if err := h.backend.EnsureIndex(ctx); err != nil {
		h.fanoutDone() // fetch failed — no fan-out will start
		// With no index (and no stale copy) nothing can be checked —
		// a 502 lets GitHub redeliver once the ATC is back instead of
		// silently dropping the delivery.
		deliveriesTotal.WithLabelValues(eventMetric, "index_unavailable").Inc()
		logger().Error("resource index unavailable",
			"remote_addr", r.RemoteAddr,
			"delivery", delivery, "event", event, "error", err,
			"status", http.StatusBadGateway)
		http.Error(w, "resource index unavailable", http.StatusBadGateway)
		return
	}

	matched := h.backend.Match(wantType, repos)
	if len(matched) == 0 && ctx.Err() == nil {
		// A pipeline set since the last index fetch may not be in the
		// cache — force one refresh and retry the match once. No loop:
		// a second miss is a genuine "nothing to check". Skipped
		// outright once the wait budget is spent — a Refresh on a dead
		// ctx can only fail, and its error path would mask the real
		// outcome (deadline → stale-index fallback below).
		if err := h.backend.RefreshIndex(ctx); err != nil {
			logger().Warn("index refresh on zero match failed — keeping prior result",
				"remote_addr", r.RemoteAddr,
				"delivery", delivery, "event", event, "error", err)
		} else {
			matched = h.backend.Match(wantType, repos)
		}
	}

	// Signature verified, resources matched — the delivery is accepted.
	// The check POSTs fan out on a detached context so the 202 goes
	// back immediately and GitHub's ~10s webhook timeout can't fire
	// (a single resource failure never fails the delivery anyway —
	// redelivery would re-trigger every resource, not just the one).
	deliveriesTotal.WithLabelValues(eventMetric, "dispatched").Inc()
	if len(matched) > 0 {
		go func() {
			defer h.fanoutDone()
			h.dispatch(matched, delivery, event, p.Repository.FullName)
		}()
	} else {
		h.fanoutDone() // nothing matched — no fan-out to wait for
	}

	logger().Info("webhook delivery accepted",
		"remote_addr", r.RemoteAddr,
		"delivery", delivery, "event", event,
		"repo", p.Repository.FullName,
		"resources_matched", len(matched))
	writeJSON(w, http.StatusAccepted, summary{ResourcesMatched: len(matched)})
}

// dispatch POSTs every matched resource's check webhook on a detached
// context — the request is already answered. The whole fan-out runs
// on a fixed budget (h.budget, fanoutBudget in production): the
// Handler-wide worker semaphore bounds concurrency so a large match
// set (or several deliveries at once) can't stampede the ATC, and a
// target queued behind a full semaphore has no per-target timeout
// yet — that starts only once a slot is taken — so the budget is its
// escape hatch. Each admitted target then gets its own 15s timeout
// so one wedged pipeline can't stall the rest of the fan-out.
//
// The overwhelmingly common case is a single matched resource: the
// direct path skips the jobs channel and worker goroutine entirely —
// same semaphore, same per-target timeout, same metrics.
//
// The worker pool is per-dispatch, not process-lifetime: each pool
// self-terminates when its jobs channel drains, so shutdown needs no
// worker-lifetime bookkeeping — the TOTAL drain is bounded instead by
// Wait's budget (WaitBudget), which is the property the shutdown
// contract actually requires.
func (h *Handler) dispatch(resources []concourse.Resource,
	delivery, event, repo string) {
	start := time.Now()
	// Detached by construction (dispatch runs on its own goroutine
	// outliving the request), but still bounded: nothing here may
	// wait on the ATC without an exit path.
	ctx, cancel := context.WithTimeout(context.Background(), h.budget)
	defer cancel()

	if len(resources) == 1 {
		// Single match: no jobs channel, no workers — just the
		// semaphore slot and the per-target timeout.
		checked := h.checkOne(ctx, resources[0], delivery)
		h.finishDispatch(start, delivery, event, repo,
			int64(len(resources)), checked)
		return
	}

	// Fixed worker pool instead of one goroutine per resource: a
	// pathological match set must not spawn hundreds of goroutines
	// all parked on the semaphore. Workers pull from a channel; the
	// Handler-wide semaphore (h.sem) still bounds concurrent POSTs
	// across ALL in-flight fan-outs.
	workers := fanoutWorkers
	if len(resources) < workers {
		workers = len(resources)
	}
	jobs := make(chan concourse.Resource)
	var wg sync.WaitGroup
	var checked atomic.Int64
	for range workers {
		wg.Go(func() {
			for res := range jobs {
				checked.Add(h.checkOne(ctx, res, delivery))
			}
		})
	}
	for _, res := range resources {
		jobs <- res
	}
	close(jobs)
	wg.Wait()
	fanoutDuration.Observe(time.Since(start).Seconds())
	logger().Info("webhook fan-out complete",
		"delivery", delivery, "event", event, "repo", repo,
		"resources_matched", len(resources),
		"resources_checked", checked.Load(),
		"duration", time.Since(start).Round(time.Millisecond))
}

// checkOne runs one resource's check webhook through the semaphore
// and per-target timeout, records its fanoutTotal result and returns
// 1 when the POST landed a 2xx (0 otherwise) so callers can count
// "checked" resources without a second channel.
func (h *Handler) checkOne(ctx context.Context, res concourse.Resource,
	delivery string) int64 {
	select {
	case h.sem <- struct{}{}:
	case <-ctx.Done():
		// Budget spent queued — skip the POST and let the target go.
		fanoutTotal.WithLabelValues("budget").Inc()
		logger().Warn("check webhook skipped: fan-out budget expired while queued",
			"pipeline", res.Pipeline, "resource", res.Name,
			"repo", res.Repo, "delivery", delivery)
		return 0
	}
	defer func() { <-h.sem }()
	tctx, cancel := context.WithTimeout(ctx, fanoutTimeout)
	defer cancel()
	status, err := h.backend.CheckWebhook(tctx, res)
	switch {
	case err != nil:
		fanoutTotal.WithLabelValues("error").Inc()
		logger().Error("check webhook request failed",
			"pipeline", res.Pipeline, "resource", res.Name,
			"repo", res.Repo, "delivery", delivery, "error", err)
	case status/100 == 2:
		fanoutTotal.WithLabelValues("ok").Inc()
		logger().Info("check webhook dispatched",
			"pipeline", res.Pipeline, "resource", res.Name,
			"repo", res.Repo, "delivery", delivery, "status", status)
		return 1
	case status == http.StatusUnauthorized || status == http.StatusNotFound:
		fanoutTotal.WithLabelValues("rejected").Inc()
		logger().Warn("check webhook rejected",
			"pipeline", res.Pipeline, "resource", res.Name,
			"repo", res.Repo, "delivery", delivery, "status", status)
	default:
		fanoutTotal.WithLabelValues("error").Inc()
		logger().Error("check webhook unexpected status",
			"pipeline", res.Pipeline, "resource", res.Name,
			"repo", res.Repo, "delivery", delivery, "status", status)
	}
	return 0
}

// finishDispatch closes out the direct single-resource path — the
// multi-resource path inlines the same metric+log at its tail.
func (h *Handler) finishDispatch(start time.Time,
	delivery, event, repo string, matched, checked int64) {
	fanoutDuration.Observe(time.Since(start).Seconds())
	logger().Info("webhook fan-out complete",
		"delivery", delivery, "event", event, "repo", repo,
		"resources_matched", matched,
		"resources_checked", checked,
		"duration", time.Since(start).Round(time.Millisecond))
}
