package handler

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/webhook-dispatcher/internal/concourse"
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

// fakeBackend is the shared test Backend: a fixed index, a
// separately configured index on RefreshIndex, and recorded
// CheckWebhook calls. The ensureFn/checkFn hooks let a test replace
// one behavior (a gated index fetch, a blocking or sequenced check
// POST) without a new backend type — every handler test drives the
// same fake. Mutable state is mutex-guarded — the fan-out runs on
// background goroutines.
type fakeBackend struct {
	resources  []concourse.Resource
	indexErr   error
	refreshRes []concourse.Resource
	refreshErr error
	status     int
	checkErr   error

	// ensureFn, when set, replaces the default EnsureIndex body
	// AFTER cur is published — e.g. a test that parks the request
	// inside the index fetch. checkFn likewise replaces the default
	// CheckWebhook response once the call is recorded.
	ensureFn func(context.Context) error
	checkFn  func(context.Context, concourse.Resource) (int, error)

	mu        sync.Mutex
	refreshed int
	checks    []concourse.Resource
	// cur mirrors what the real client's Match reads: the index the
	// last fetch (EnsureIndex or RefreshIndex) published.
	cur []concourse.Resource
}

func (f *fakeBackend) EnsureIndex(ctx context.Context) error {
	f.mu.Lock()
	f.cur = f.resources
	f.mu.Unlock()
	if f.ensureFn != nil {
		return f.ensureFn(ctx)
	}
	return f.indexErr
}

func (f *fakeBackend) RefreshIndex(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refreshed++
	f.cur = f.refreshRes
	return f.refreshErr
}

func (f *fakeBackend) Match(wantType string, repos map[string]struct{}) []concourse.Resource {
	f.mu.Lock()
	defer f.mu.Unlock()
	return linearMatch(f.cur, wantType, repos)
}

func (f *fakeBackend) CheckWebhook(ctx context.Context, r concourse.Resource) (int, error) {
	f.mu.Lock()
	f.checks = append(f.checks, r)
	f.mu.Unlock()
	if f.checkFn != nil {
		return f.checkFn(ctx, r)
	}
	if f.checkErr != nil {
		return 0, f.checkErr
	}
	return f.status, nil
}

func (f *fakeBackend) checkList() []concourse.Resource {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]concourse.Resource(nil), f.checks...)
}

func (f *fakeBackend) refreshCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.refreshed
}

// checkStats is the shared CheckWebhook hook state for fan-out
// tests: peak concurrency, call count and an optional per-call delay
// — what throttledBackend used to be, now a checkFn closure body.
type checkStats struct {
	mu       sync.Mutex
	inflight int
	max      int
	n        int
	delay    time.Duration
}

// run sleeps delay (or until ctx ends), tracking inflight/max/n, and
// returns status — the common checkFn body.
func (s *checkStats) run(ctx context.Context, status int) (int, error) {
	s.mu.Lock()
	s.inflight++
	if s.inflight > s.max {
		s.max = s.inflight
	}
	s.n++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.inflight--
		s.mu.Unlock()
	}()
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	return status, nil
}

func (s *checkStats) maxInflight() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.max
}

func (s *checkStats) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n
}

// linearMatch is the reference matcher the test backends answer Match
// with — a plain scan. The real concourse.Client answers from its
// (type, repo) lookup map; the two must stay equivalent (the O(1)
// index test in the concourse package pins that directly).
func linearMatch(resources []concourse.Resource, wantType string,
	repos map[string]struct{}) []concourse.Resource {
	var out []concourse.Resource
	for _, r := range resources {
		if r.Type != wantType {
			continue
		}
		if _, ok := repos[r.Repo]; !ok {
			continue
		}
		out = append(out, r)
	}
	return out
}

var pushBody = `{"repository":{
	"full_name":"org/repo",
	"ssh_url":"git@github.com:org/repo.git",
	"clone_url":"https://github.com/org/repo.git",
	"html_url":"https://github.com/org/repo"
}}`

// releaseBody is a release "published" delivery — the only release
// action that can mean a new tag for git resources.
var releaseBody = `{"action":"published","repository":{
	"full_name":"org/repo",
	"html_url":"https://github.com/org/repo"
}}`

var createTagBody = `{"ref_type":"tag","ref":"v1.2.3","repository":{
	"full_name":"org/repo",
	"html_url":"https://github.com/org/repo"
}}`

var createBranchBody = `{"ref_type":"branch","ref":"feature","repository":{
	"full_name":"org/repo",
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

// errReader fails if anything tries to read it and records the
// attempt — proof the handler rejected without touching the body.
type errReader struct{ reads int }

func (r *errReader) Read([]byte) (int, error) {
	r.reads++
	return 0, errors.New("body must not be read")
}

func TestMalformedSignatureRejectsBeforeBodyRead(t *testing.T) {
	// Missing or malformed signature headers are refused before the
	// body is read — a port scanner or unauthenticated probe must not
	// be able to force a body buffer allocation.
	h := New(testSecret, &fakeBackend{})
	for _, tc := range []struct {
		name, sig string
	}{
		{"missing", ""},
		{"wrong scheme", "sha1=" + strings.Repeat("0", 40)},
		{"short hex", "sha256=abcd"},
		{"non-hex", "sha256=" + strings.Repeat("z", 64)},
		{"too long", "sha256=" + strings.Repeat("a", 65)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &errReader{}
			req := httptest.NewRequest(http.MethodPost, "/webhook", body)
			req.Header.Set("X-GitHub-Event", "push")
			req.Header.Set("X-Hub-Signature-256", tc.sig)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d want 401", rec.Code)
			}
			if body.reads != 0 {
				t.Fatalf("body read %d times; want 0", body.reads)
			}
		})
	}
}

func TestOversizedBodyWithoutSignatureRejected(t *testing.T) {
	// A payload over maxBodyBytes with no signature is still a fast
	// 401, not a 413: the format check fires before MaxBytesReader.
	h := New(testSecret, &fakeBackend{})
	req := httptest.NewRequest(http.MethodPost, "/webhook",
		strings.NewReader(strings.Repeat("x", maxBodyBytes+1)))
	req.Header.Set("X-GitHub-Event", "push")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", rec.Code)
	}
}

func TestEmptySecretRejectsBeforeBodyRead(t *testing.T) {
	// With no secret configured nothing can verify — even a
	// well-formed header dies before the body read.
	h := New("", &fakeBackend{})
	body := &errReader{}
	req := httptest.NewRequest(http.MethodPost, "/webhook", body)
	req.Header.Set("X-Hub-Signature-256", "sha256="+strings.Repeat("0", 64))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", rec.Code)
	}
	if body.reads != 0 {
		t.Fatalf("body read %d times; want 0", body.reads)
	}
}

func TestUnhandledEventAccepted(t *testing.T) {
	h := New(testSecret, &fakeBackend{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(t, "ping", pushBody))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d want 202", rec.Code)
	}
	if s := decodeSummary(t, rec); s.ResourcesMatched != 0 {
		t.Fatalf("resources_matched=%d want 0", s.ResourcesMatched)
	}
}

func TestPushChecksGitResourcesOnly(t *testing.T) {
	b := &fakeBackend{resources: testIndex(), status: http.StatusCreated}
	h := New(testSecret, b)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(t, "push", pushBody))

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d want 202", rec.Code)
	}
	if s := decodeSummary(t, rec); s.ResourcesMatched != 2 {
		t.Fatalf("resources_matched=%d want 2", s.ResourcesMatched)
	}
	h.wg.Wait()
	checks := b.checkList()
	for _, r := range checks {
		if r.Type != "git" || r.Repo != "org/repo" {
			t.Fatalf("unexpected check fan-out: %+v", r)
		}
	}
	if len(checks) != 2 {
		t.Fatalf("checks=%d want 2", len(checks))
	}
	if b.refreshCount() != 0 {
		t.Fatalf("refreshed=%d want 0 (match found without retry)", b.refreshCount())
	}
}

func TestReleasePublishedChecksGitResources(t *testing.T) {
	b := &fakeBackend{resources: testIndex(), status: http.StatusCreated}
	h := New(testSecret, b)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(t, "release", releaseBody))

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d want 202", rec.Code)
	}
	if s := decodeSummary(t, rec); s.ResourcesMatched != 2 {
		t.Fatalf("resources_matched=%d want 2", s.ResourcesMatched)
	}
	h.wg.Wait()
	if checks := b.checkList(); len(checks) != 2 {
		t.Fatalf("checks=%d want 2", len(checks))
	}
}

func TestReleaseNonPublishActionIgnored(t *testing.T) {
	// edited/deleted/prereleased release deliveries carry no new tag.
	b := &fakeBackend{resources: testIndex(), status: http.StatusOK}
	h := New(testSecret, b)
	for _, action := range []string{"edited", "deleted", "created"} {
		body := strings.Replace(releaseBody, "published", action, 1)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, signedRequest(t, "release", body))
		if rec.Code != http.StatusAccepted {
			t.Fatalf("action=%s status=%d want 202", action, rec.Code)
		}
		if s := decodeSummary(t, rec); s.ResourcesMatched != 0 {
			t.Fatalf("action=%s resources_matched=%d want 0", action, s.ResourcesMatched)
		}
	}
	h.wg.Wait()
	if checks := b.checkList(); len(checks) != 0 {
		t.Fatalf("checks=%d want 0", len(checks))
	}
}

func TestCreateTagChecksGitResources(t *testing.T) {
	b := &fakeBackend{resources: testIndex(), status: http.StatusCreated}
	h := New(testSecret, b)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(t, "create", createTagBody))

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d want 202", rec.Code)
	}
	if s := decodeSummary(t, rec); s.ResourcesMatched != 2 {
		t.Fatalf("resources_matched=%d want 2", s.ResourcesMatched)
	}
	h.wg.Wait()
	checks := b.checkList()
	if len(checks) != 2 {
		t.Fatalf("checks=%d want 2", len(checks))
	}
	for _, r := range checks {
		if r.Type != "git" {
			t.Fatalf("unexpected check fan-out: %+v", r)
		}
	}
}

func TestCreateBranchIgnored(t *testing.T) {
	b := &fakeBackend{resources: testIndex(), status: http.StatusOK}
	h := New(testSecret, b)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(t, "create", createBranchBody))

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d want 202", rec.Code)
	}
	if s := decodeSummary(t, rec); s.ResourcesMatched != 0 {
		t.Fatalf("resources_matched=%d want 0", s.ResourcesMatched)
	}
	h.wg.Wait()
	if checks := b.checkList(); len(checks) != 0 {
		t.Fatalf("checks=%d want 0", len(checks))
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

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d want 202", rec.Code)
	}
	if b.refreshCount() != 1 {
		t.Fatalf("refreshed=%d want 1", b.refreshCount())
	}
	if s := decodeSummary(t, rec); s.ResourcesMatched != 2 {
		t.Fatalf("resources_matched=%d want 2", s.ResourcesMatched)
	}
	h.wg.Wait()
	if checks := b.checkList(); len(checks) != 2 {
		t.Fatalf("checks=%d want 2", len(checks))
	}
}

func TestZeroMatchStaysZeroWhenRefreshEmpty(t *testing.T) {
	// A repo genuinely unknown to Concourse: refresh once, still no
	// match, answer 202 with nothing to check — no loop.
	b := &fakeBackend{status: http.StatusOK}
	h := New(testSecret, b)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(t, "push", pushBody))

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d want 202", rec.Code)
	}
	if b.refreshCount() != 1 {
		t.Fatalf("refreshed=%d want exactly 1 (no loop)", b.refreshCount())
	}
	if s := decodeSummary(t, rec); s.ResourcesMatched != 0 {
		t.Fatalf("resources_matched=%d want 0", s.ResourcesMatched)
	}
	h.wg.Wait()
	if checks := b.checkList(); len(checks) != 0 {
		t.Fatalf("checks=%d want 0", len(checks))
	}
}

func TestZeroMatchRefreshFailureKeepsResult(t *testing.T) {
	// ATC down during the retry — the delivery still succeeds with
	// the prior (empty) match result.
	b := &fakeBackend{refreshErr: errors.New("atc down"), status: http.StatusOK}
	h := New(testSecret, b)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(t, "push", pushBody))

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d want 202", rec.Code)
	}
	if s := decodeSummary(t, rec); s.ResourcesMatched != 0 {
		t.Fatalf("resources_matched=%d want 0", s.ResourcesMatched)
	}
}

func TestPullRequestChecksPRResourcesOnly(t *testing.T) {
	b := &fakeBackend{resources: testIndex(), status: http.StatusOK}
	h := New(testSecret, b)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(t, "pull_request", pushBody))

	if s := decodeSummary(t, rec); s.ResourcesMatched != 1 {
		t.Fatalf("resources_matched=%d want 1", s.ResourcesMatched)
	}
	h.wg.Wait()
	checks := b.checkList()
	if len(checks) != 1 || checks[0].Type != "github-pr" {
		t.Fatalf("checks=%+v want one github-pr check", checks)
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
	if s := decodeSummary(t, rec); s.ResourcesMatched != 2 {
		t.Fatalf("resources_matched=%d want 2", s.ResourcesMatched)
	}
}

func TestCheckFailuresNeverFailDelivery(t *testing.T) {
	// 404 + 5xx must all be swallowed — the delivery is still
	// accepted and every target gets its check attempt. The checkFn
	// hook sequences the statuses the old sequencingBackend returned.
	statuses := []int{http.StatusOK, http.StatusNotFound, http.StatusInternalServerError}
	var seqMu sync.Mutex
	seq := 0
	b := &fakeBackend{
		resources: []concourse.Resource{
			{Pipeline: "p1", Name: "a", Type: "git", Repo: "org/repo"},
			{Pipeline: "p1", Name: "b", Type: "git", Repo: "org/repo"},
			{Pipeline: "p1", Name: "c", Type: "git", Repo: "org/repo"},
		},
		checkFn: func(_ context.Context, _ concourse.Resource) (int, error) {
			seqMu.Lock()
			defer seqMu.Unlock()
			st := statuses[seq%len(statuses)]
			seq++
			return st, nil
		},
	}
	h := New(testSecret, b)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(t, "push", pushBody))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d want 202", rec.Code)
	}
	if s := decodeSummary(t, rec); s.ResourcesMatched != 3 {
		t.Fatalf("resources_matched=%d want 3", s.ResourcesMatched)
	}
	h.wg.Wait()
	if got := len(b.checkList()); got != 3 {
		t.Fatalf("check calls=%d want 3", got)
	}
}

func TestIndexUnavailableReturns502(t *testing.T) {
	h := New(testSecret, &fakeBackend{indexErr: errors.New("atc down")})
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

func TestFanoutBoundsConcurrency(t *testing.T) {
	// More targets than fanoutWorkers: in-flight CheckWebhook calls
	// must never exceed the semaphore — a large match set can't
	// stampede the ATC.
	stats := &checkStats{delay: 5 * time.Millisecond}
	b := &fakeBackend{
		checkFn: func(ctx context.Context, _ concourse.Resource) (int, error) {
			return stats.run(ctx, http.StatusCreated)
		},
	}
	var resources []concourse.Resource
	for i := 0; i < fanoutWorkers*4; i++ {
		resources = append(resources, concourse.Resource{
			Pipeline: "p1", Name: fmt.Sprintf("r%d", i),
			Type: "git", Repo: "org/repo",
		})
	}
	b.resources = resources
	h := New(testSecret, b)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(t, "push", pushBody))

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d want 202", rec.Code)
	}
	h.wg.Wait()
	if got := stats.maxInflight(); got > fanoutWorkers {
		t.Fatalf("max in-flight checks=%d want <= %d", got, fanoutWorkers)
	}
	if got := stats.maxInflight(); got < 2 {
		t.Fatalf("max in-flight checks=%d want > 1 (fan-out must be parallel)", got)
	}
	if got := stats.calls(); got != len(resources) {
		t.Fatalf("check calls=%d want %d", got, len(resources))
	}
}

func TestFanoutSemaphoreSharedAcrossDeliveries(t *testing.T) {
	// The fan-out semaphore belongs to the Handler, not to one
	// dispatch — several deliveries fanning out at once must keep
	// TOTAL in-flight checks <= fanoutWorkers. A per-dispatch
	// semaphore would let each run fanoutWorkers in parallel.
	stats := &checkStats{delay: 10 * time.Millisecond}
	b := &fakeBackend{
		checkFn: func(ctx context.Context, _ concourse.Resource) (int, error) {
			return stats.run(ctx, http.StatusCreated)
		},
	}
	h := New(testSecret, b)
	var resources []concourse.Resource
	for i := 0; i < fanoutWorkers; i++ {
		resources = append(resources, concourse.Resource{
			Pipeline: "p1", Name: fmt.Sprintf("r%d", i),
			Type: "git", Repo: "org/repo",
		})
	}
	b.resources = resources
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.dispatch(resources, "d", "push", "org/repo")
		}()
	}
	wg.Wait()
	if got := stats.maxInflight(); got > fanoutWorkers {
		t.Fatalf("max in-flight checks=%d want <= %d (semaphore must be shared across fan-outs)",
			got, fanoutWorkers)
	}
	if got := stats.calls(); got != 3*len(resources) {
		t.Fatalf("check calls=%d want %d", got, 3*len(resources))
	}
}

func TestMetricsRecorded(t *testing.T) {
	dispatchedBefore := testutil.ToFloat64(
		deliveriesTotal.WithLabelValues("push", "dispatched"))
	unauthorizedBefore := testutil.ToFloat64(
		deliveriesTotal.WithLabelValues("push", "unauthorized"))
	okBefore := testutil.ToFloat64(fanoutTotal.WithLabelValues("ok"))

	b := &fakeBackend{resources: testIndex(), status: http.StatusCreated}
	h := New(testSecret, b)

	// A rejected delivery and a dispatched one.
	req := signedRequest(t, "push", pushBody)
	req.Header.Set("X-Hub-Signature-256", "sha256="+strings.Repeat("0", 64))
	h.ServeHTTP(httptest.NewRecorder(), req)
	h.ServeHTTP(httptest.NewRecorder(), signedRequest(t, "push", pushBody))
	h.wg.Wait()

	if got := testutil.ToFloat64(
		deliveriesTotal.WithLabelValues("push", "unauthorized")); got != unauthorizedBefore+1 {
		t.Fatalf("unauthorized deliveries=%v want %v", got, unauthorizedBefore+1)
	}
	if got := testutil.ToFloat64(
		deliveriesTotal.WithLabelValues("push", "dispatched")); got != dispatchedBefore+1 {
		t.Fatalf("dispatched deliveries=%v want %v", got, dispatchedBefore+1)
	}
	// The index holds two git resources for org/repo.
	if got := testutil.ToFloat64(
		fanoutTotal.WithLabelValues("ok")); got != okBefore+2 {
		t.Fatalf("ok fanout=%v want %v", got, okBefore+2)
	}
}

func TestMetricEventLabel(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"push", "push"},
		{"pull_request", "pull_request"},
		{"release", "release"},
		{"create", "create"},
		{"", "none"},
		{"ping", "other"},
		{"check_run", "other"},
		{"PUSH", "other"}, // case is part of the event identity
		{"push\x00forged", "other"},
	} {
		if got := metricEventLabel(tc.in); got != tc.want {
			t.Fatalf("metricEventLabel(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}

func TestEventHeaderCannotCreateMetricSeries(t *testing.T) {
	// An unauthenticated probe carrying an arbitrary X-GitHub-Event
	// must land on the bounded "other" label — before normalization,
	// every random value grew a new deliveriesTotal series
	// (metrics-cardinality DoS).
	otherBefore := testutil.ToFloat64(
		deliveriesTotal.WithLabelValues("other", "unauthorized"))
	noneBefore := testutil.ToFloat64(
		deliveriesTotal.WithLabelValues("none", "unauthorized"))
	forged := "forged-event-" + t.Name()

	h := New(testSecret, &fakeBackend{})
	for _, event := range []string{forged, ""} {
		req := signedRequest(t, event, pushBody)
		req.Header.Set("X-Hub-Signature-256", "sha256="+strings.Repeat("0", 64))
		h.ServeHTTP(httptest.NewRecorder(), req)
	}

	if got := testutil.ToFloat64(
		deliveriesTotal.WithLabelValues("other", "unauthorized")); got != otherBefore+1 {
		t.Fatalf("other/unauthorized=%v want %v", got, otherBefore+1)
	}
	if got := testutil.ToFloat64(
		deliveriesTotal.WithLabelValues("none", "unauthorized")); got != noneBefore+1 {
		t.Fatalf("none/unauthorized=%v want %v", got, noneBefore+1)
	}
	// The forged value must never have become a label — a counter
	// under it exists only if normalization failed.
	if got := testutil.ToFloat64(
		deliveriesTotal.WithLabelValues(forged, "unauthorized")); got != 0 {
		t.Fatalf("forged event label series=%v want 0", got)
	}
}

func TestWaitDrainsInFlightFanout(t *testing.T) {
	// Wait must block until every detached check goroutine finishes —
	// the shutdown path in main depends on it.
	stats := &checkStats{delay: 20 * time.Millisecond}
	b := &fakeBackend{
		resources: []concourse.Resource{
			{Pipeline: "p1", Name: "a", Type: "git", Repo: "org/repo"},
			{Pipeline: "p1", Name: "b", Type: "git", Repo: "org/repo"},
		},
		checkFn: func(ctx context.Context, _ concourse.Resource) (int, error) {
			return stats.run(ctx, http.StatusCreated)
		},
	}
	h := New(testSecret, b)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(t, "push", pushBody))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d want 202", rec.Code)
	}
	h.Wait(context.Background()) // exported drain path — same as main's shutdown
	if got := stats.calls(); got != 2 {
		t.Fatalf("check calls=%d want 2 after Wait", got)
	}
}

func TestWaitCannotRaceFanoutRegistration(t *testing.T) {
	// wg.Add must run BEFORE the index fetch: otherwise a Wait()
	// entering while a delivery sits inside EnsureIndex sees an empty
	// WaitGroup, returns immediately — and the fan-out started
	// afterwards runs unwaited, so shutdown could exit the process
	// while check POSTs are still in flight. The race window is
	// exercised directly: Wait is started while the request is parked
	// inside the fetch, every iteration, under -race. The ensureFn
	// hook parks EnsureIndex the way gateBackend's Resources did.
	for i := range 50 {
		inResources := make(chan struct{}, 1)
		release := make(chan struct{})
		b := &fakeBackend{
			resources: testIndex(),
			status:    http.StatusCreated,
			ensureFn: func(context.Context) error {
				inResources <- struct{}{}
				<-release
				return nil
			},
		}
		h := New(testSecret, b)
		reqDone := make(chan struct{})
		go func() {
			defer close(reqDone)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, signedRequest(t, "push", pushBody))
			if rec.Code != http.StatusAccepted {
				t.Errorf("iteration %d: status=%d want 202", i, rec.Code)
			}
		}()
		<-inResources // request parked inside the index fetch

		waitDone := make(chan struct{})
		go func() {
			h.Wait(context.Background())
			close(waitDone)
		}()
		// The fan-out is already registered (Add ran before the
		// fetch), so Wait must still be blocked here. Give a racy
		// Wait every scheduling chance to (wrongly) observe an empty
		// WaitGroup before releasing the fetch.
		time.Sleep(2 * time.Millisecond)
		select {
		case <-waitDone:
			t.Fatalf("iteration %d: Wait returned before the fan-out completed", i)
		default:
		}

		close(release)
		<-reqDone
		<-waitDone // must finish once the fan-out lands
		if got := len(b.checkList()); got != 2 {
			t.Fatalf("iteration %d: check calls=%d want 2", i, got)
		}
	}
}

// TestFanoutBudgetReleasesQueuedTargets: the semaphore must never be
// a dead end. Every slot is held while a delivery fans out, so all
// matched targets queue with no way in; the dispatch budget (shortened
// here) has to let them give up, release the detached goroutine for
// Wait/shutdown, and never fire the POSTs they never got a slot for.
func TestFanoutBudgetReleasesQueuedTargets(t *testing.T) {
	b := &fakeBackend{resources: testIndex(), status: http.StatusCreated}
	h := New(testSecret, b)
	h.budget = 50 * time.Millisecond

	// Hold every slot for the whole delivery — nothing can acquire one.
	for range fanoutWorkers {
		h.sem <- struct{}{}
	}
	defer func() {
		for range fanoutWorkers {
			<-h.sem
		}
	}()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(t, "push", pushBody))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d want 202 (the response must not wait on the fan-out)", rec.Code)
	}
	if s := decodeSummary(t, rec); s.ResourcesMatched != 2 {
		t.Fatalf("resources_matched=%d want 2 (push matches the 2 git resources)", s.ResourcesMatched)
	}

	done := make(chan struct{})
	go func() {
		h.Wait(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not return — queued targets have no escape from the semaphore")
	}
	if got := len(b.checkList()); got != 0 {
		t.Fatalf("check calls=%d want 0 (budget-expired targets must not POST)", got)
	}
}

// TestWaitBudgetExpiresWithInFlightFanout: the shutdown contract —
// Wait must RETURN when its budget expires even with a fan-out stuck
// mid-flight, so Shutdown(10s)+Wait(15s) beats the pod's 30s SIGKILL.
// The abandoned fan-out is counted and logged (dropped return value);
// once the stuck POSTs finish, an unconstrained drain sees 0 left.
// The checkFn hook parks every CheckWebhook on release — the old
// blockingBackend's behavior.
func TestWaitBudgetExpiresWithInFlightFanout(t *testing.T) {
	release := make(chan struct{})
	b := &fakeBackend{
		checkFn: func(context.Context, concourse.Resource) (int, error) {
			<-release
			return http.StatusCreated, nil
		},
	}
	for i := range 2 {
		b.resources = append(b.resources, concourse.Resource{
			Pipeline: "p1", Name: fmt.Sprintf("r%d", i),
			Type: "git", Repo: "org/repo",
		})
	}
	h := New(testSecret, b)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(t, "push", pushBody))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d want 202", rec.Code)
	}

	// Both check POSTs are parked inside the backend — the delivery's
	// fan-out is genuinely in flight and cannot finish.
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	dropped := h.Wait(ctx)
	cancel()
	if elapsed := time.Since(start); elapsed >= 5*time.Second {
		t.Fatalf("Wait returned after %v — the budget was not honored", elapsed)
	}
	if dropped != 1 {
		t.Fatalf("dropped=%d want 1 (the delivery's in-flight fan-out)", dropped)
	}

	close(release) // the parked POSTs land
	if got := h.Wait(context.Background()); got != 0 {
		t.Fatalf("dropped=%d want 0 once the stuck checks finish", got)
	}
}

// TestPreVerificationLogsHideRawHeaderValues: header values are
// attacker-controlled until the HMAC check passes — pre-verification
// logs must not echo them verbatim. The delivery GUID is filtered to
// a safe alphabet (quotes, semicolons, control bytes dropped) and the
// event collapses onto the fixed metric label set.
func TestPreVerificationLogsHideRawHeaderValues(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	h := New(testSecret, &fakeBackend{})
	req := signedRequest(t, "push", pushBody)
	req.Header.Set("X-GitHub-Delivery",
		`evil"value;flood`+"\x01"+`-tail-1234`)
	req.Header.Set("X-GitHub-Event", "push\x00forged")
	// Invalid signature — every log line this delivery produces is
	// written before verification.
	req.Header.Set("X-Hub-Signature-256", "sha256="+strings.Repeat("0", 64))
	h.ServeHTTP(httptest.NewRecorder(), req)

	logs := buf.String()
	for _, raw := range []string{`evil"value`, "flood\x01", "push\x00forged"} {
		if strings.Contains(logs, raw) {
			t.Fatalf("raw header value %q leaked into logs:\n%s", raw, logs)
		}
	}
	// The event is the fixed label value, not the raw header.
	if !strings.Contains(logs, "event=other") {
		t.Fatalf("pre-verification event not normalized to the fixed label set:\n%s", logs)
	}
	// The harmless remainder of the delivery GUID survives for
	// correlation.
	if !strings.Contains(logs, "delivery=evilvalueflood-tail-1234") {
		t.Fatalf("sanitized delivery id missing from logs:\n%s", logs)
	}
}

// Non-actionable pull_request actions and branch deletions are
// acknowledged before the index lookup — they must not consume a
// Refresh slot or an index fetch.
func TestSkippedDeliveriesBypassIndex(t *testing.T) {
	b := &fakeBackend{resources: testIndex(), status: http.StatusOK}
	h := New(testSecret, b)

	prSkipped := `{"action":"labeled","repository":{"full_name":"org/repo"}}`
	for _, action := range []string{"closed", "labeled", "edited", "assigned"} {
		body := strings.Replace(prSkipped, "labeled", action, 1)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, signedRequest(t, "pull_request", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("action=%s status=%d want 200", action, rec.Code)
		}
		var s map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &s); err != nil {
			t.Fatal(err)
		}
		if s["skipped"] != "action" {
			t.Fatalf("action=%s body=%v want skipped=action", action, s)
		}
	}
	// Actionable actions still reach the index path (202).
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(t, "pull_request",
		`{"action":"synchronize","repository":{"full_name":"org/repo"}}`))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("synchronize status=%d want 202", rec.Code)
	}

	for _, body := range []string{
		`{"deleted":true,"repository":{"full_name":"org/repo"}}`,
		`{"after":"0000000000000000000000000000000000000000","repository":{"full_name":"org/repo"}}`,
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, signedRequest(t, "push", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("push body=%s status=%d want 200", body, rec.Code)
		}
	}
	if n := b.refreshCount(); n != 0 {
		t.Fatalf("Refresh calls=%d want 0 (all deliveries skipped or matched)", n)
	}
}

// TestAdmissionRefusalsReturn503 covers both admit() refusals: the
// shutdown drain flag and a full request semaphore each answer 503 —
// GitHub must see a retryable refusal, never a hang or a 202 that
// silently drops the delivery.
func TestAdmissionRefusalsReturn503(t *testing.T) {
	t.Run("draining", func(t *testing.T) {
		h := New(testSecret, &fakeBackend{})
		h.drainMu.Lock()
		h.draining = true
		h.drainMu.Unlock()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, signedRequest(t, "push", pushBody))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status=%d want 503", rec.Code)
		}
	})
	t.Run("overloaded", func(t *testing.T) {
		h := New(testSecret, &fakeBackend{})
		// Saturate the admission semaphore — every slot held means
		// the next authenticated delivery is refused, not queued.
		for i := 0; i < maxInflightRequests; i++ {
			h.reqSem <- struct{}{}
		}
		defer func() {
			for i := 0; i < maxInflightRequests; i++ {
				<-h.reqSem
			}
		}()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, signedRequest(t, "push", pushBody))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status=%d want 503", rec.Code)
		}
	})
}
