package handler

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-node-automation/apps/webhook-dispatcher/internal/concourse"
)

const testSecret = "hook-secret"

func signedRequest(t *testing.T, event, body string) *http.Request {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write([]byte(body))
	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(body))
	req.Header.Set("X-GitHub-Event", event)
	req.Header.Set("X-GitHub-Delivery", "delivery-1")
	req.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	return req
}

// fakeBackend returns a fixed index, a separately configured index on
// Refresh, and records CheckWebhook calls.
type fakeBackend struct {
	resources  []concourse.Resource
	indexErr   error
	refreshRes []concourse.Resource
	refreshErr error
	refreshed  int
	status     int
	checkErr   error
	checks     []concourse.Resource
}

func (f *fakeBackend) Resources(_ context.Context) ([]concourse.Resource, error) {
	return f.resources, f.indexErr
}

func (f *fakeBackend) Refresh(_ context.Context) ([]concourse.Resource, error) {
	f.refreshed++
	return f.refreshRes, f.refreshErr
}

func (f *fakeBackend) CheckWebhook(_ context.Context, r concourse.Resource) (int, error) {
	f.checks = append(f.checks, r)
	if f.checkErr != nil {
		return 0, f.checkErr
	}
	return f.status, nil
}

var pushBody = `{"repository":{
	"full_name":"org/repo",
	"ssh_url":"git@github.com:org/repo.git",
	"clone_url":"https://github.com/org/repo.git",
	"html_url":"https://github.com/org/repo"
}}`

func testIndex() []concourse.Resource {
	return []concourse.Resource{
		{Pipeline: "p1", Name: "repo-git", Type: "git", Repo: "org/repo"},
		{Pipeline: "p1", Name: "repo-pr", Type: "github-pr", Repo: "org/repo"},
		{Pipeline: "p2", Name: "repo-https", Type: "git", Repo: "org/repo"},
		{Pipeline: "p1", Name: "other", Type: "git", Repo: "org/other"},
	}
}

func decodeSummary(t *testing.T, rec *httptest.ResponseRecorder) summary {
	t.Helper()
	var s summary
	if err := json.Unmarshal(rec.Body.Bytes(), &s); err != nil {
		t.Fatalf("response body not JSON: %q", rec.Body.String())
	}
	return s
}

func TestBadSignatureRejected(t *testing.T) {
	h := New(testSecret, &fakeBackend{})
	for _, tc := range []struct {
		name, sig string
	}{
		{"missing", ""},
		{"wrong secret", func() string {
			mac := hmac.New(sha256.New, []byte("nope"))
			mac.Write([]byte(pushBody))
			return "sha256=" + hex.EncodeToString(mac.Sum(nil))
		}()},
		{"garbage", "sha256=zzzz"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := signedRequest(t, "push", pushBody)
			req.Header.Set("X-Hub-Signature-256", tc.sig)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d want 401", rec.Code)
			}
		})
	}
}

func TestUnhandledEventAccepted(t *testing.T) {
	h := New(testSecret, &fakeBackend{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(t, "ping", pushBody))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d want 202", rec.Code)
	}
	if s := decodeSummary(t, rec); s.ResourcesChecked != 0 {
		t.Fatalf("resources_checked=%d want 0", s.ResourcesChecked)
	}
}

func TestPushChecksGitResourcesOnly(t *testing.T) {
	b := &fakeBackend{resources: testIndex(), status: http.StatusCreated}
	h := New(testSecret, b)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(t, "push", pushBody))

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", rec.Code)
	}
	if s := decodeSummary(t, rec); s.ResourcesChecked != 2 {
		t.Fatalf("resources_checked=%d want 2", s.ResourcesChecked)
	}
	for _, r := range b.checks {
		if r.Type != "git" || r.Repo != "org/repo" {
			t.Fatalf("unexpected check fan-out: %+v", r)
		}
	}
	if len(b.checks) != 2 {
		t.Fatalf("checks=%d want 2", len(b.checks))
	}
	if b.refreshed != 0 {
		t.Fatalf("refreshed=%d want 0 (match found without retry)", b.refreshed)
	}
}

func TestZeroMatchRetriesAfterRefresh(t *testing.T) {
	// The cached index knows nothing about the repo (newly set
	// pipeline); the forced refresh picks it up and the delivery
	// still fans out.
	b := &fakeBackend{
		refreshRes: testIndex(),
		status:     http.StatusCreated,
	}
	h := New(testSecret, b)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(t, "push", pushBody))

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", rec.Code)
	}
	if b.refreshed != 1 {
		t.Fatalf("refreshed=%d want 1", b.refreshed)
	}
	if s := decodeSummary(t, rec); s.ResourcesChecked != 2 {
		t.Fatalf("resources_checked=%d want 2", s.ResourcesChecked)
	}
	if len(b.checks) != 2 {
		t.Fatalf("checks=%d want 2", len(b.checks))
	}
}

func TestZeroMatchStaysZeroWhenRefreshEmpty(t *testing.T) {
	// A repo genuinely unknown to Concourse: refresh once, still no
	// match, answer 200 with nothing checked — no loop.
	b := &fakeBackend{status: http.StatusOK}
	h := New(testSecret, b)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(t, "push", pushBody))

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", rec.Code)
	}
	if b.refreshed != 1 {
		t.Fatalf("refreshed=%d want exactly 1 (no loop)", b.refreshed)
	}
	if s := decodeSummary(t, rec); s.ResourcesChecked != 0 {
		t.Fatalf("resources_checked=%d want 0", s.ResourcesChecked)
	}
	if len(b.checks) != 0 {
		t.Fatalf("checks=%d want 0", len(b.checks))
	}
}

func TestZeroMatchRefreshFailureKeepsResult(t *testing.T) {
	// ATC down during the retry — the delivery still succeeds with
	// the prior (empty) match result.
	b := &fakeBackend{refreshErr: fmt.Errorf("atc down"), status: http.StatusOK}
	h := New(testSecret, b)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(t, "push", pushBody))

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", rec.Code)
	}
	if s := decodeSummary(t, rec); s.ResourcesChecked != 0 {
		t.Fatalf("resources_checked=%d want 0", s.ResourcesChecked)
	}
}

func TestPullRequestChecksPRResourcesOnly(t *testing.T) {
	b := &fakeBackend{resources: testIndex(), status: http.StatusOK}
	h := New(testSecret, b)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(t, "pull_request", pushBody))

	if s := decodeSummary(t, rec); s.ResourcesChecked != 1 {
		t.Fatalf("resources_checked=%d want 1", s.ResourcesChecked)
	}
	if len(b.checks) != 1 || b.checks[0].Type != "github-pr" {
		t.Fatalf("checks=%+v want one github-pr check", b.checks)
	}
}

func TestMatchViaAlternateRepoURL(t *testing.T) {
	// full_name absent is a 400, but any single URL form suffices for
	// matching — drive the match via clone_url only.
	b := &fakeBackend{resources: testIndex(), status: http.StatusOK}
	h := New(testSecret, b)
	body := `{"repository":{
		"full_name":"org/repo",
		"clone_url":"https://github.com/org/repo"
	}}`
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(t, "push", body))
	if s := decodeSummary(t, rec); s.ResourcesChecked != 2 {
		t.Fatalf("resources_checked=%d want 2", s.ResourcesChecked)
	}
}

func TestCheckFailuresNeverFailDelivery(t *testing.T) {
	// 404 + 5xx must all be swallowed — the summary only counts 2xx
	// checks and the delivery still succeeds.
	h := New(testSecret, &sequencingBackend{
		statuses: []int{http.StatusOK, http.StatusNotFound, http.StatusInternalServerError},
		resources: []concourse.Resource{
			{Pipeline: "p1", Name: "a", Type: "git", Repo: "org/repo"},
			{Pipeline: "p1", Name: "b", Type: "git", Repo: "org/repo"},
			{Pipeline: "p1", Name: "c", Type: "git", Repo: "org/repo"},
		},
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(t, "push", pushBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", rec.Code)
	}
	if s := decodeSummary(t, rec); s.ResourcesChecked != 1 {
		t.Fatalf("resources_checked=%d want 1 (only the 2xx)", s.ResourcesChecked)
	}
}

// sequencingBackend returns a different status per CheckWebhook call.
type sequencingBackend struct {
	resources []concourse.Resource
	statuses  []int
	n         int
}

func (s *sequencingBackend) Resources(_ context.Context) ([]concourse.Resource, error) {
	return s.resources, nil
}

func (s *sequencingBackend) Refresh(_ context.Context) ([]concourse.Resource, error) {
	return s.resources, nil
}

func (s *sequencingBackend) CheckWebhook(_ context.Context, _ concourse.Resource) (int, error) {
	st := s.statuses[s.n%len(s.statuses)]
	s.n++
	return st, nil
}

func TestIndexUnavailableReturns502(t *testing.T) {
	h := New(testSecret, &fakeBackend{indexErr: fmt.Errorf("atc down")})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(t, "push", pushBody))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status=%d want 502", rec.Code)
	}
}

func TestBadPayloadRejected(t *testing.T) {
	h := New(testSecret, &fakeBackend{})
	for _, body := range []string{
		`not json`,
		`{"repository":{}}`,
		`{"repository":{"ssh_url":"git@github.com:o/r.git"}}`,
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, signedRequest(t, "push", body))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body=%q status=%d want 400", body, rec.Code)
		}
	}
}
