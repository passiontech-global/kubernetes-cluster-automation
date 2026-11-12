// Package handler serves POST /webhook: it verifies the GitHub HMAC
// signature, resolves the delivery's repo against the Concourse
// resource index, and fans out check webhooks to matching resources.
//
// Fan-out is asynchronous: once the delivery is verified and matched,
// the handler answers 202 and dispatches the resource checks on a
// detached context (worker semaphore, per-target timeout) — the
// response never waits on the ATC, so it cannot hit GitHub's ~10s
// webhook timeout.
//
// This file owns request admission and the ServeHTTP front half —
// headers, signature verification, payload parsing and the
// pre-index filters. The post-verification half (index ensure, repo
// match, the zero-match refresh retry and the detached fan-out) lives
// in dispatch.go.
package handler

import (
	"bytes"
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
	// indexWaitBudget bounds the synchronous index fetch on the
	// request path — deliberately under GitHub's ~10s webhook
	// timeout so the handler always answers in time. The fetch
	// itself runs detached on the client's 30s flight budget; a
	// timeout here serves the stale index instead of 502ing.
	indexWaitBudget = 7 * time.Second
	// maxInflightRequests caps concurrent post-signature requests —
	// each one holds a body buffer (up to 8 MiB) plus goroutine
	// stack, so an unbounded flood is a memory/CPU exhaustion
	// vector. Over the cap the delivery gets an immediate 503
	// (GitHub retries) instead of queueing thousands of goroutines.
	maxInflightRequests = 128
)

// bodyPool recycles the request-body buffers of the four handled
// event types — each delivery can hold up to maxBodyBytes, and
// webhook volume is far higher than GC would reclaim them at. Buffers
// are Reset before Put so a pooled 8 MiB slab never leaks stale body
// bytes into the next delivery.
var bodyPool = sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

// Backend is the slice of the Concourse client the handler needs —
// an interface so tests can substitute a fake ATC. The index entry
// points are error-only: the handler goes straight to Match against
// the client's published lookup, so it never needed the index slice
// cloned out per delivery.
type Backend interface {
	// EnsureIndex runs the TTL/singleflight/backoff decision — the
	// index is populated (or a stale one kept) by the time it
	// returns nil.
	EnsureIndex(ctx context.Context) error
	// RefreshIndex forces an index refetch past the TTL — the
	// zero-match retry. Its error is warn-only for the handler.
	RefreshIndex(ctx context.Context) error
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
	// inFlight mirrors the outstanding FAN-OUT count only —
	// fanoutStart/fanoutDone are the sole mutators, so Wait's
	// budget-expiry report ("in_flight_fanouts") counts exactly the
	// detached check POSTs it abandoned, never requests still inside
	// ServeHTTP (those are covered by wg but aren't fan-outs).
	inFlight atomic.Int64
	// budget bounds one dispatch — the semaphore queue included
	// (fanoutBudget in production; tests shorten it so the budget
	// path stays deterministic).
	budget time.Duration
	// reqSem bounds concurrent admitted requests (maxInflightRequests).
	reqSem chan struct{}
	// drainMu guards draining + the request-scope wg.Add: Wait sets
	// draining under this lock, and admit() takes the same lock to
	// register — so once draining flips, no new request can slip a
	// wg.Add past Wait's observation of an empty WaitGroup.
	drainMu  sync.Mutex
	draining bool
}

// New returns a Handler verifying signatures against secret and
// fanning out through b.
func New(secret string, b Backend) *Handler {
	return &Handler{
		secret:  secret,
		backend: b,
		sem:     make(chan struct{}, fanoutWorkers),
		budget:  fanoutBudget,
		reqSem:  make(chan struct{}, maxInflightRequests),
	}
}

// admit registers an authenticated request for the shutdown drain
// and takes an in-flight slot — MUST run before the body read so a
// slow-loris flood can't pile up unbounded goroutines+buffers, and
// so Wait covers every request that passed the signature gate (the
// fan-out's own fanoutStart only fires much later, after the index
// fetch). ok=false means the caller answers 503; draining reports
// WHICH refusal (shutdown vs capacity) for the metric label — it is
// read under drainMu so it can't race Wait's flip.
func (h *Handler) admit() (ok, draining bool) {
	select {
	case h.reqSem <- struct{}{}:
	default:
		return false, false
	}
	h.drainMu.Lock()
	defer h.drainMu.Unlock()
	if h.draining {
		<-h.reqSem
		return false, true
	}
	h.wg.Add(1)
	return true, false
}

// release pairs admit — called once per admitted request via defer.
func (h *Handler) release() {
	h.wg.Done()
	<-h.reqSem
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

	// Admission gate: bounded concurrency + shutdown drain, taken
	// BEFORE the body read — the signature format check above is
	// cheap, but the body buffer (8 MiB cap) and HMAC are not, and
	// an unbounded flood of well-formed-signature probes would
	// otherwise stack goroutines without limit.
	if ok, draining := h.admit(); !ok {
		status := "overloaded"
		if draining {
			status = "draining"
		}
		code := http.StatusServiceUnavailable
		deliveriesTotal.WithLabelValues(eventMetric, status).Inc()
		logger().Warn("webhook rejected: admission refused",
			"remote_addr", r.RemoteAddr,
			"delivery", delivery, "event", eventMetric,
			"status", code)
		http.Error(w, "service unavailable", code)
		return
	}
	defer h.release()

	wantType, handledEvent := resourceTypeForEvent[event]
	if !handledEvent {
		// Events outside the four handled types are acknowledged on
		// the signature alone — the payload is never parsed, so
		// stream it through the HMAC instead of buffering up to
		// 8 MiB for a delivery that only earns a 202. The response
		// ordering is identical to the buffered path: the
		// MaxBytesReader still produces 413/400 before the 401
		// verdict, and the metric outcomes are the same.
		matched, err := verify.SignatureReader(h.secret,
			http.MaxBytesReader(w, r.Body, maxBodyBytes), sig)
		if err != nil {
			h.failBodyRead(w, r, delivery, event, eventMetric, err)
			return
		}
		if !matched {
			h.rejectSignature(w, r, delivery, eventMetric)
			return
		}
		deliveriesTotal.WithLabelValues(eventMetric, "ignored").Inc()
		logger().Info("webhook delivery ignored: unhandled event",
			"remote_addr", r.RemoteAddr,
			"delivery", delivery, "event", event)
		writeJSON(w, http.StatusAccepted, summary{})
		return
	}

	// The four handled events DO parse the payload — borrow a
	// MaxBytesReader-bounded buffer from the pool instead of
	// io.ReadAll's fresh allocation per delivery.
	buf := bodyPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer func() {
		buf.Reset()
		bodyPool.Put(buf)
	}()
	if _, err := io.Copy(buf, http.MaxBytesReader(w, r.Body, maxBodyBytes)); err != nil {
		h.failBodyRead(w, r, delivery, event, eventMetric, err)
		return
	}
	if !verify.Signature(h.secret, buf.Bytes(), sig) {
		h.rejectSignature(w, r, delivery, eventMetric)
		return
	}

	var p payload
	if err := json.Unmarshal(buf.Bytes(), &p); err != nil {
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

	// Signature verified, payload parsed and actionable — hand the
	// delivery to the index/match/fan-out half (dispatch.go).
	h.accept(w, r, delivery, event, eventMetric, wantType, p)
}

// failBodyRead maps a body-read failure onto the delivery metric and
// the HTTP status — shared by the buffered and streaming verify
// paths so their 413/400 ordering can never drift apart. "Body over
// maxBodyBytes" (the sender's fault -> 413) and a transport failure
// like a client disconnect (-> 400) both surface as a read error —
// split them on MaxBytesError.
func (h *Handler) failBodyRead(w http.ResponseWriter, r *http.Request,
	delivery, event, eventMetric string, err error) {
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
}

// rejectSignature is the shared 401 for a well-formed signature that
// does not verify — buffered and streaming paths alike.
func (h *Handler) rejectSignature(w http.ResponseWriter, r *http.Request,
	delivery, eventMetric string) {
	deliveriesTotal.WithLabelValues(eventMetric, "unauthorized").Inc()
	logger().Warn("webhook rejected: signature mismatch",
		"remote_addr", r.RemoteAddr,
		"delivery", delivery, "event", eventMetric,
		"status", http.StatusUnauthorized)
	http.Error(w, "invalid signature", http.StatusUnauthorized)
}

// logSafe bounds an unauthenticated header value for logging: GitHub
// delivery GUIDs are 36-char hex+hyphen UUIDs, so anything outside the
// safe alphabet is dropped and anything longer than a UUID is
// truncated — a hostile peer cannot echo arbitrary (or long, or
// control-laden) bytes into the log stream before the HMAC check
// rejects them. Legit IDs survive intact for correlation.
func logSafe(s string) string {
	const maxLen = 64
	n := len(s)
	if n > maxLen {
		n = maxLen
	}
	// Fast path — the overwhelmingly common case: every byte already
	// sits in the safe ASCII alphabet, so the string can be returned
	// (truncated) with zero allocation instead of strings.Map's rune
	// walk building a fresh string.
	i := 0
	for ; i < n; i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' ||
			c >= 'A' && c <= 'Z' || c == '-' || c == '.' || c == '_') {
			break
		}
	}
	if i == n {
		return s[:n]
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
	}, s[:n])
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
