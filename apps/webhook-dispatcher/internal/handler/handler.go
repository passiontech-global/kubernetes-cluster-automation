// Package handler serves POST /webhook: it verifies the GitHub HMAC
// signature, resolves the delivery's repo against the Concourse
// resource index, and fans out check webhooks to matching resources.
package handler

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/webhook-dispatcher/internal/concourse"
	"github.com/passiontech-global/kubernetes-node-automation/apps/webhook-dispatcher/internal/verify"
)

// maxBodyBytes caps the webhook payload — GitHub deliveries are far
// below this; the bound keeps a hostile peer from forcing a large
// allocation before the HMAC check rejects it.
const maxBodyBytes = 8 << 20 // 8 MiB

// Backend is the slice of the Concourse client the handler needs —
// an interface so tests can substitute a fake ATC.
type Backend interface {
	Resources(ctx context.Context) ([]concourse.Resource, error)
	// Refresh bypasses the index cache TTL and returns a freshly
	// fetched index; the previous index stays authoritative on error.
	Refresh(ctx context.Context) ([]concourse.Resource, error)
	CheckWebhook(ctx context.Context, r concourse.Resource) (int, error)
}

// resourceTypeForEvent maps GitHub events to the Concourse resource
// type they fan out to: pushes check git resources, pull_request
// deliveries check github-pr resources.
var resourceTypeForEvent = map[string]string{
	"push":         "git",
	"pull_request": "github-pr",
}

// payload is the slice of a GitHub webhook body the dispatcher reads.
type payload struct {
	Repository struct {
		FullName string `json:"full_name"`
		SSHURL   string `json:"ssh_url"`
		CloneURL string `json:"clone_url"`
		HTMLURL  string `json:"html_url"`
	} `json:"repository"`
}

// summary is the JSON response body for accepted deliveries.
type summary struct {
	ResourcesChecked int `json:"resources_checked"`
}

// Handler verifies and dispatches webhook deliveries.
type Handler struct {
	secret  string
	backend Backend
}

// New returns a Handler verifying signatures against secret and
// fanning out through b.
func New(secret string, b Backend) *Handler {
	return &Handler{secret: secret, backend: b}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	delivery := r.Header.Get("X-GitHub-Delivery")
	event := r.Header.Get("X-GitHub-Event")
	sig := r.Header.Get("X-Hub-Signature-256")

	logger().Info("webhook delivery received",
		"remote_addr", r.RemoteAddr, "path", r.URL.Path,
		"delivery", delivery, "event", event)

	// Reject missing/malformed signatures before touching the body:
	// port scanners and unauthenticated probes must not force a body
	// buffer allocation. The HMAC check below still runs on the full
	// body for well-formed headers.
	if !verify.HasValidSignatureFormat(h.secret, sig) {
		logger().Warn("webhook rejected: malformed signature",
			"remote_addr", r.RemoteAddr,
			"delivery", delivery, "event", event,
			"status", http.StatusUnauthorized)
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		logger().Warn("webhook rejected: body read failed",
			"remote_addr", r.RemoteAddr,
			"delivery", delivery, "event", event, "error", err,
			"status", http.StatusRequestEntityTooLarge)
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	if !verify.Signature(h.secret, body, sig) {
		logger().Warn("webhook rejected: signature mismatch",
			"remote_addr", r.RemoteAddr,
			"delivery", delivery, "event", event,
			"status", http.StatusUnauthorized)
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	wantType, ok := resourceTypeForEvent[event]
	if !ok {
		logger().Info("webhook delivery ignored: unhandled event",
			"remote_addr", r.RemoteAddr,
			"delivery", delivery, "event", event)
		writeJSON(w, http.StatusAccepted, summary{})
		return
	}

	var p payload
	if err := json.Unmarshal(body, &p); err != nil {
		logger().Warn("webhook rejected: malformed JSON payload",
			"remote_addr", r.RemoteAddr,
			"delivery", delivery, "event", event, "error", err,
			"status", http.StatusBadRequest)
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}
	if p.Repository.FullName == "" {
		logger().Warn("webhook rejected: missing repository.full_name",
			"remote_addr", r.RemoteAddr,
			"delivery", delivery, "event", event,
			"status", http.StatusBadRequest)
		http.Error(w, "bad payload", http.StatusBadRequest)
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

	// Fan-out work runs detached from the request lifetime: GitHub
	// abandons the connection after ~10s, which must not cancel the
	// remaining check POSTs. A 30s budget keeps a wedged ATC from
	// hanging the handler forever.
	ctx, cancel := context.WithTimeout(
		context.WithoutCancel(r.Context()), 30*time.Second)
	defer cancel()

	resources, err := h.backend.Resources(ctx)
	if err != nil {
		// With no index (and no stale copy) nothing can be checked —
		// a 502 lets GitHub redeliver once the ATC is back instead of
		// silently dropping the delivery.
		logger().Error("resource index unavailable",
			"remote_addr", r.RemoteAddr,
			"delivery", delivery, "event", event, "error", err,
			"status", http.StatusBadGateway)
		http.Error(w, "resource index unavailable", http.StatusBadGateway)
		return
	}

	matched := matchResources(resources, wantType, repos)
	if len(matched) == 0 {
		// A pipeline set since the last index fetch may not be in the
		// cache — force one refresh and retry the match once. No loop:
		// a second miss is a genuine "nothing to check".
		fresh, err := h.backend.Refresh(ctx)
		if err != nil {
			logger().Warn("index refresh on zero match failed — keeping prior result",
				"remote_addr", r.RemoteAddr,
				"delivery", delivery, "event", event, "error", err)
		} else {
			matched = matchResources(fresh, wantType, repos)
		}
	}

	checked := 0
	for _, res := range matched {
		status, err := h.backend.CheckWebhook(ctx, res)
		switch {
		case err != nil:
			logger().Error("check webhook request failed",
				"pipeline", res.Pipeline, "resource", res.Name,
				"repo", res.Repo, "delivery", delivery, "error", err)
		case status/100 == 2:
			checked++
			logger().Info("check webhook dispatched",
				"pipeline", res.Pipeline, "resource", res.Name,
				"repo", res.Repo, "delivery", delivery, "status", status)
		case status == http.StatusUnauthorized || status == http.StatusNotFound:
			logger().Warn("check webhook rejected",
				"pipeline", res.Pipeline, "resource", res.Name,
				"repo", res.Repo, "delivery", delivery, "status", status)
		default:
			logger().Error("check webhook unexpected status",
				"pipeline", res.Pipeline, "resource", res.Name,
				"repo", res.Repo, "delivery", delivery, "status", status)
		}
	}

	logger().Info("webhook delivery dispatched",
		"remote_addr", r.RemoteAddr,
		"delivery", delivery, "event", event,
		"repo", p.Repository.FullName,
		"resources_matched", len(matched), "resources_checked", checked)
	writeJSON(w, http.StatusOK, summary{ResourcesChecked: checked})
}

// matchResources returns the fan-out targets: resources of the
// event's type whose normalized repo is one of the delivery's repo
// identities.
func matchResources(resources []concourse.Resource, wantType string,
	repos map[string]struct{}) []concourse.Resource {
	var matched []concourse.Resource
	for _, res := range resources {
		if res.Type != wantType {
			continue
		}
		if _, ok := repos[res.Repo]; !ok {
			continue
		}
		matched = append(matched, res)
	}
	return matched
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
