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
// in dispatch.go; the shared response/log-safety helpers live in
// respond.go.
package handler

import (
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"net/http"
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
	// maxPreAuthRequests and maxPreAuthBytes bound concurrent
	// pre-verification buffered reads on handled events so an
	// unauthenticated flood of valid-format bogus signatures cannot
	// bypass reqSem and OOM the process, while keeping reqSem isolated
	// for verified deliveries.
	maxPreAuthRequests = 256
	maxPreAuthBytes    = 32 << 20 // 32 MiB
)

var errPreAuthBudget = errors.New("pre-auth body byte budget exceeded")

// bodyPool recycles the request-body buffers of the four handled
// event types — each delivery can hold up to maxBodyBytes, and
// webhook volume is far higher than GC would reclaim them at. Buffers
// are sliced to [:0] before Put so a pooled slab never leaks stale
// body bytes into the next delivery. New preallocates 16 KiB — the
// typical delivery size — so steady-state traffic stops growing
// pooled buffers; on Put, buffers over 64 KiB are dropped to GC
// instead of being recycled, so one huge delivery cannot pin an
// 8 MiB-class slab in the pool for the process lifetime.
var bodyPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 16<<10)
		return &b
	},
}

// cappedBodyWriter appends read chunks into buf without doubling
// capacity past max (maxBodyBytes), preventing 8 MiB -> 16 MiB buffer
// amplification, and charges capacity growth against reserve when set.
type cappedBodyWriter struct {
	buf      []byte
	max      int
	reserved int64
	reserve  func(int64) bool
}

func (w *cappedBodyWriter) Write(p []byte) (int, error) {
	need := len(w.buf) + len(p)
	if need > cap(w.buf) {
		newCap := max(cap(w.buf)*2, need)
		if w.max > 0 && newCap > w.max {
			newCap = max(w.max, need)
		}
		if w.reserve != nil {
			delta := int64(newCap) - w.reserved
			if delta > 0 {
				if !w.reserve(delta) {
					return 0, errPreAuthBudget
				}
				w.reserved += delta
			}
		}
		grown := make([]byte, len(w.buf), newCap)
		copy(grown, w.buf)
		w.buf = grown
	}
	w.buf = append(w.buf, p...)
	return len(p), nil
}

// maxPooledBodyCap is the largest buffer bodyPool recycles: a delivery
// that forced the buffer past this size hands its slab back to GC.
const maxPooledBodyCap = 64 << 10

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
	Match(wantType string, repos []string) []concourse.Resource
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
	// preAuthSem and preAuthBytes bound concurrent pre-auth buffered
	// reads on handled events before reqSem admission.
	preAuthSem      chan struct{}
	preAuthBytes    atomic.Int64
	preAuthMaxBytes int64
	// drainMu guards draining + the request-scope wg.Add: Wait sets
	// draining under this lock, and admit() takes the same lock to
	// register — so once draining flips, no new request can slip a
	// wg.Add past Wait's observation of an empty WaitGroup.
	drainMu  sync.Mutex
	draining bool
	// onBodyPut, when non-nil (test seam), overrides bodyPool.Put in
	// releaseBuf so tests can deterministically observe buffer returns
	// under -race (where sync.Pool.Put drops ~25% of pooled items).
	onBodyPut func(*[]byte)
}

// New returns a Handler verifying signatures against secret and
// fanning out through b.
func New(secret string, b Backend) *Handler {
	return &Handler{
		secret:          secret,
		backend:         b,
		sem:             make(chan struct{}, fanoutWorkers),
		budget:          fanoutBudget,
		reqSem:          make(chan struct{}, maxInflightRequests),
		preAuthSem:      make(chan struct{}, maxPreAuthRequests),
		preAuthMaxBytes: maxPreAuthBytes,
	}
}

func (h *Handler) tryReservePreAuthBytes(n int64) bool {
	if n <= 0 {
		return true
	}
	for {
		cur := h.preAuthBytes.Load()
		if cur+n > h.preAuthMaxBytes {
			return false
		}
		if h.preAuthBytes.CompareAndSwap(cur, cur+n) {
			return true
		}
	}
}

// isDraining reports whether Wait has initiated shutdown drain so
// ServeHTTP can fail fast with 503 before buffering/hashing a body.
func (h *Handler) isDraining() bool {
	h.drainMu.Lock()
	d := h.draining
	h.drainMu.Unlock()
	return d
}

// refuseAdmission answers 503 for either drain or semaphore saturation.
func (h *Handler) refuseAdmission(w http.ResponseWriter, r *http.Request,
	delivery, eventMetric string, draining bool) {
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
}

// admit registers an HMAC-verified request for the shutdown drain
// and takes an in-flight slot — run AFTER HMAC verification so
// unauthenticated slow-loris requests cannot hold reqSem slots for
// ReadTimeout (10s), while drainMu still ensures Wait cannot observe
// an empty WaitGroup ahead of an in-flight admission. ok=false means
// the caller answers 503; draining reports WHICH refusal (shutdown vs
// capacity) for the metric label.
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

	// Reject declared-oversized payloads immediately after signature
	// format validation (preserving 401 for unsigned probes) and before
	// touching bodyPool, reqSem, or reading r.Body.
	if r.ContentLength > maxBodyBytes {
		h.failBodyRead(w, r, delivery, event, eventMetric,
			&http.MaxBytesError{Limit: maxBodyBytes})
		return
	}

	// Fast-reject draining servers before reading/hashing the body.
	if h.isDraining() {
		h.refuseAdmission(w, r, delivery, eventMetric, true)
		return
	}

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
		if ok, draining := h.admit(); !ok {
			h.refuseAdmission(w, r, delivery, eventMetric, draining)
			return
		}
		defer h.release()
		deliveriesTotal.WithLabelValues(eventMetric, "ignored").Inc()
		logger().Info("webhook delivery ignored: unhandled event",
			"remote_addr", r.RemoteAddr,
			"delivery", delivery, "event", event)
		writeJSON(w, http.StatusAccepted, summary{})
		return
	}

	// The four handled events DO parse the payload — bound pre-auth
	// concurrency and aggregate buffered bytes before borrowing from
	// bodyPool and streaming through SignatureTee so an unauthenticated
	// flood cannot OOM the process, while keeping reqSem isolated.
	select {
	case h.preAuthSem <- struct{}{}:
	default:
		h.refuseAdmission(w, r, delivery, eventMetric, false)
		return
	}

	bp := bodyPool.Get().(*[]byte)
	cw := cappedBodyWriter{buf: (*bp)[:0], max: maxBodyBytes}
	releaseBuf := func() {
		if bp == nil {
			return
		}
		if cap(cw.buf) <= maxPooledBodyCap {
			*bp = cw.buf[:0]
			if h.onBodyPut != nil {
				h.onBodyPut(bp)
			} else {
				bodyPool.Put(bp)
			}
		}
		cw.buf = nil
		bp = nil
	}
	defer releaseBuf()

	initCap := int64(cap(cw.buf))
	if !h.tryReservePreAuthBytes(initCap) {
		<-h.preAuthSem
		h.refuseAdmission(w, r, delivery, eventMetric, false)
		return
	}
	cw.reserved = initCap
	cw.reserve = h.tryReservePreAuthBytes
	preAuthHeld := true
	releasePreAuth := func() {
		if !preAuthHeld {
			return
		}
		preAuthHeld = false
		if cw.reserved > 0 {
			h.preAuthBytes.Add(-cw.reserved)
			cw.reserved = 0
		}
		<-h.preAuthSem
	}
	defer releasePreAuth()

	matched, err := verify.SignatureTee(h.secret,
		http.MaxBytesReader(w, r.Body, maxBodyBytes), &cw, sig)
	if err != nil {
		if errors.Is(err, errPreAuthBudget) {
			h.refuseAdmission(w, r, delivery, eventMetric, false)
			return
		}
		h.failBodyRead(w, r, delivery, event, eventMetric, err)
		return
	}
	if !matched {
		h.rejectSignature(w, r, delivery, eventMetric)
		return
	}

	// Admission gate after HMAC verification so unauthenticated slow
	// readers cannot exhaust reqSem across ReadTimeout.
	if ok, draining := h.admit(); !ok {
		h.refuseAdmission(w, r, delivery, eventMetric, draining)
		return
	}
	defer h.release()

	var p payload
	err = json.Unmarshal(cw.buf, &p,
		jsontext.AllowInvalidUTF8(true),
		jsontext.AllowDuplicateNames(true),
	)
	// Return the pooled buffer and release pre-auth budget immediately
	// once JSON decode finishes so neither is held across h.accept()'s
	// 7s index wait.
	releaseBuf()
	releasePreAuth()
	if err != nil {
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
