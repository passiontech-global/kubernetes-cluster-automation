// Package handler serves POST /webhook: it verifies the GitHub HMAC
// signature, resolves the delivery's repo against the Concourse
// resource index, and fans out check webhooks to matching resources.
//
// Fan-out is asynchronous: once the delivery is verified and matched,
// the handler answers 202 and dispatches the resource checks on a
// detached context (worker semaphore, per-target timeout) — the
// response never waits on the ATC, so it cannot hit GitHub's ~10s
// webhook timeout.
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/webhook-dispatcher/internal/concourse"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/webhook-dispatcher/internal/verify"
)

// maxBodyBytes caps the webhook payload — GitHub deliveries are far
// below this; the bound keeps a hostile peer from forcing a large
// allocation before the HMAC check rejects it.
const maxBodyBytes = 8 << 20 // 8 MiB

const (
	// fanoutWorkers bounds concurrent check-webhook POSTs inside one
	// delivery — a large match set must not stampede the ATC.
	fanoutWorkers = 16
	// fanoutTimeout caps each check-webhook POST so one wedged
	// pipeline can't stall the rest of the fan-out.
	fanoutTimeout = 15 * time.Second
	// fanoutBudget bounds one whole dispatch — the semaphore queue
	// included. A target's 15s timeout starts only after it takes a
	// slot, so a target queued behind a full semaphore (16 slots held
	// by slow POSTs) would otherwise wait forever.
	fanoutBudget = 30 * time.Second
	// WaitBudget bounds the shutdown drain (Handler.Wait): with main's
	// 10s HTTP Shutdown in front, the total stays ~25s — under the
	// pod's 30s SIGKILL grace period, so the process still exits on
	// its own terms (dropped fan-outs are logged, see Wait). Exported
	// so main builds its wait context from the same constant it
	// documents.
	WaitBudget = 15 * time.Second
)

// Backend is the slice of the Concourse client the handler needs —
// an interface so tests can substitute a fake ATC.
type Backend interface {
	Resources(ctx context.Context) ([]concourse.Resource, error)
	// Refresh bypasses the index cache TTL and returns a freshly
	// fetched index; the previous index stays authoritative on error.
	Refresh(ctx context.Context) ([]concourse.Resource, error)
	// Match returns the current index's fan-out targets: resources of
	// wantType whose repo is one of repos. The concourse.Client
	// answers from the (type, repo) map built once per fetch publish;
	// fakes answer from their own slice — the lookup must be
	// equivalent either way.
	Match(wantType string, repos map[string]struct{}) []concourse.Resource
	CheckWebhook(ctx context.Context, r concourse.Resource) (int, error)
}

// resourceTypeForEvent maps GitHub events to the Concourse resource
// type they fan out to: pushes, releases and tag creations check git
// resources, pull_request deliveries check github-pr resources.
// release and create are refined by payload fields below — only a
// published release and a tag (not branch) create matter.
var resourceTypeForEvent = map[string]string{
	"push":         "git",
	"pull_request": "github-pr",
	"release":      "git",
	"create":       "git",
}

// payload is the slice of a GitHub webhook body the dispatcher reads.
type payload struct {
	Action     string `json:"action"`
	RefType    string `json:"ref_type"`
	Deleted    bool   `json:"deleted"`
	After      string `json:"after"`
	Repository struct {
		FullName string `json:"full_name"`
		SSHURL   string `json:"ssh_url"`
		CloneURL string `json:"clone_url"`
		HTMLURL  string `json:"html_url"`
	} `json:"repository"`
}

// actionablePRActions are the pull_request actions that can change
// what a github-pr resource checks out. Every other action (labeled,
// closed, edited, assigned, ...) is acknowledged without touching the
// index — they would only burn a forced-refresh slot against
// MinRefreshInterval.
var actionablePRActions = map[string]bool{
	"opened":           true,
	"synchronize":      true,
	"reopened":         true,
	"ready_for_review": true,
	"unlocked":         true,
}

// summary is the JSON response body for accepted deliveries: how many
// resources matched and will be checked asynchronously.
type summary struct {
	ResourcesMatched int `json:"resources_matched"`
}

// Handler verifies and dispatches webhook deliveries.
type Handler struct {
	secret  string
	backend Backend
	// sem bounds concurrent check-webhook POSTs across ALL in-flight
	// fan-outs — allocated once here, not per dispatch: a per-request
	// semaphore would still let N concurrent deliveries fire
	// fanoutWorkers*N parallel requests at the ATC.
	sem chan struct{}
	// wg tracks in-flight background fan-outs so tests and the
	// graceful-shutdown path (Wait) can wait for the last check to
	// land.
	wg sync.WaitGroup
	// inFlight mirrors wg's outstanding count — a WaitGroup has no
	// "how many are still running" read, and Wait's budget-expiry
	// path reports the abandoned count from here. Mutated only via
	// fanoutStart/fanoutDone so the two counters can't drift.
	inFlight atomic.Int64
	// budget bounds one dispatch — the semaphore queue included
	// (fanoutBudget in production; tests shorten it so the budget
	// path stays deterministic).
	budget time.Duration
}

// New returns a Handler verifying signatures against secret and
// fanning out through b.
func New(secret string, b Backend) *Handler {
	return &Handler{
		secret:  secret,
		backend: b,
		sem:     make(chan struct{}, fanoutWorkers),
		budget:  fanoutBudget,
	}
}

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

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Header values are attacker-controlled until the HMAC check
	// passes, and Go only rejects control characters in them — a
	// hostile peer can still forge/flood plausible-looking log fields.
	// The delivery GUID is length-capped and filtered to a safe
	// alphabet (GitHub's UUIDs are hex+hyphen) before any logging;
	// the signature header is never logged at all. Event values go
	// through the fixed metric label set pre-verification (below).
	delivery := logSafe(r.Header.Get("X-GitHub-Delivery"))
	event := r.Header.Get("X-GitHub-Event")
	sig := r.Header.Get("X-Hub-Signature-256")
	// The event header is unauthenticated until the HMAC check passes
	// — normalize it onto the fixed metric label set so a flood of
	// random values can't grow deliveriesTotal's series without bound.
	// Logs written BEFORE verification carry the same normalized value:
	// raw header values must not be echoed into the log stream ahead of
	// the signature check. Post-verification logs (a peer that just
	// proved it holds the secret) keep the raw event for diagnostics.
	eventMetric := metricEventLabel(event)

	logger().Info("webhook delivery received",
		"remote_addr", r.RemoteAddr, "path", r.URL.Path,
		"delivery", delivery, "event", eventMetric)

	// Reject missing/malformed signatures before touching the body:
	// port scanners and unauthenticated probes must not force a body
	// buffer allocation. The HMAC check below still runs on the full
	// body for well-formed headers.
	if !verify.HasValidSignatureFormat(h.secret, sig) {
		deliveriesTotal.WithLabelValues(eventMetric, "unauthorized").Inc()
		logger().Warn("webhook rejected: malformed signature",
			"remote_addr", r.RemoteAddr,
			"delivery", delivery, "event", eventMetric,
			"status", http.StatusUnauthorized)
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		// "Body over maxBodyBytes" (the sender's fault -> 413) and a
		// transport failure like a client disconnect (-> 400) both
		// surface as a ReadAll error — split them on MaxBytesError.
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			deliveriesTotal.WithLabelValues(eventMetric, "payload_too_large").Inc()
			logger().Warn("webhook rejected: body exceeds size limit",
				"remote_addr", r.RemoteAddr,
				"delivery", delivery, "event", eventMetric, "error", err,
				"status", http.StatusRequestEntityTooLarge)
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		} else {
			deliveriesTotal.WithLabelValues(eventMetric, "bad_request").Inc()
			logger().Warn("webhook rejected: body read failed",
				"remote_addr", r.RemoteAddr,
				"delivery", delivery, "event", eventMetric, "error", err,
				"status", http.StatusBadRequest)
			http.Error(w, "bad request", http.StatusBadRequest)
		}
		return
	}
	if !verify.Signature(h.secret, body, sig) {
		deliveriesTotal.WithLabelValues(eventMetric, "unauthorized").Inc()
		logger().Warn("webhook rejected: signature mismatch",
			"remote_addr", r.RemoteAddr,
			"delivery", delivery, "event", eventMetric,
			"status", http.StatusUnauthorized)
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	wantType, ok := resourceTypeForEvent[event]
	if !ok {
		deliveriesTotal.WithLabelValues(eventMetric, "ignored").Inc()
		logger().Info("webhook delivery ignored: unhandled event",
			"remote_addr", r.RemoteAddr,
			"delivery", delivery, "event", event)
		writeJSON(w, http.StatusAccepted, summary{})
		return
	}

	var p payload
	if err := json.Unmarshal(body, &p); err != nil {
		deliveriesTotal.WithLabelValues(eventMetric, "bad_request").Inc()
		logger().Warn("webhook rejected: malformed JSON payload",
			"remote_addr", r.RemoteAddr,
			"delivery", delivery, "event", event, "error", err,
			"status", http.StatusBadRequest)
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}
	if p.Repository.FullName == "" {
		deliveriesTotal.WithLabelValues(eventMetric, "bad_request").Inc()
		logger().Warn("webhook rejected: missing repository.full_name",
			"remote_addr", r.RemoteAddr,
			"delivery", delivery, "event", event,
			"status", http.StatusBadRequest)
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}

	// release fires for many actions — only publishing one means a
	// new tag for git resources to see; create fires for branches and
	// tags alike, and only a tag warrants a check.
	switch {
	case event == "release" && p.Action != "published" && p.Action != "released":
		fallthrough
	case event == "create" && p.RefType != "tag":
		deliveriesTotal.WithLabelValues(eventMetric, "ignored").Inc()
		logger().Info("webhook delivery ignored: no-op for resource checks",
			"remote_addr", r.RemoteAddr,
			"delivery", delivery, "event", event,
			"action", p.Action, "ref_type", p.RefType)
		writeJSON(w, http.StatusAccepted, summary{})
		return
	}

	// Filter deliveries that can never match a resource check BEFORE
	// the index lookup: a non-actionable pull_request action or a
	// branch deletion would otherwise burn a forced Refresh slot
	// (MinRefreshInterval-throttled, so every skipped delivery delays
	// a real one behind it). payload.Action == "" keeps synthetic
	// test payloads (repository-only bodies) on the matching path.
	if event == "pull_request" && p.Action != "" && !actionablePRActions[p.Action] {
		deliveriesTotal.WithLabelValues(eventMetric, "ignored").Inc()
		logger().Info("webhook delivery ignored: non-actionable pull_request action",
			"remote_addr", r.RemoteAddr,
			"delivery", delivery, "event", event, "action", p.Action)
		writeSkipped(w, "action")
		return
	}
	// A deleted branch (or the all-zero "after" sha GitHub sends for
	// deletions) has no commit for git resources to check.
	if event == "push" &&
		(p.Deleted || p.After == "0000000000000000000000000000000000000000") {
		deliveriesTotal.WithLabelValues(eventMetric, "ignored").Inc()
		logger().Info("webhook delivery ignored: branch deletion",
			"remote_addr", r.RemoteAddr,
			"delivery", delivery, "event", event,
			"deleted", p.Deleted, "after", p.After)
		writeSkipped(w, "deleted")
		return
	}

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
	// A 30s budget keeps a wedged ATC from hanging the handler forever.
	ctx, cancel := context.WithTimeout(
		context.WithoutCancel(r.Context()), 30*time.Second)
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
	if _, err := h.backend.Resources(ctx); err != nil {
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
	if len(matched) == 0 {
		// A pipeline set since the last index fetch may not be in the
		// cache — force one refresh and retry the match once. No loop:
		// a second miss is a genuine "nothing to check".
		if _, err := h.backend.Refresh(ctx); err != nil {
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
// on a fixed budget (fanoutBudget, same 30s the request-path index
// fetch gets): the Handler-wide worker semaphore bounds concurrency
// so a large match set (or several deliveries at once) can't stampede
// the ATC, and a target queued behind a full semaphore has no
// per-target timeout yet — that starts only once a slot is taken —
// so the budget is its escape hatch. Each admitted target then gets
// its own 15s timeout so one wedged pipeline can't stall the rest of
// the fan-out.
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
		wg.Add(1)
		go func() {
			defer wg.Done()
			for res := range jobs {
				select {
				case h.sem <- struct{}{}:
				case <-ctx.Done():
					// Budget spent queued — skip the POST and let
					// the target go.
					fanoutTotal.WithLabelValues("budget").Inc()
					logger().Warn("check webhook skipped: fan-out budget expired while queued",
						"pipeline", res.Pipeline, "resource", res.Name,
						"repo", res.Repo, "delivery", delivery)
					continue
				}
				func() {
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
						checked.Add(1)
						logger().Info("check webhook dispatched",
							"pipeline", res.Pipeline, "resource", res.Name,
							"repo", res.Repo, "delivery", delivery, "status", status)
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
				}()
			}
		}()
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

// logSafe bounds an unauthenticated header value for logging: GitHub
// delivery GUIDs are 36-char hex+hyphen UUIDs, so anything outside the
// safe alphabet is dropped and anything longer than a UUID is
// truncated — a hostile peer cannot echo arbitrary (or long, or
// control-laden) bytes into the log stream before the HMAC check
// rejects them. Legit IDs survive intact for correlation.
func logSafe(s string) string {
	const maxLen = 64
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
			r == '-', r == '.', r == '_':
			return r
		default:
			// Invalid UTF-8 decodes to RuneError and lands here too.
			return -1
		}
	}, s)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeSkipped acknowledges an authenticated delivery that was
// filtered before the index lookup — 200 (not 202) with the skip
// reason so operators can tell "matched nothing" from "never
// checked".
func writeSkipped(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"matched": 0,
		"skipped": reason,
	})
}
