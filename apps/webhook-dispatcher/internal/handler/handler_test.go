package handler

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

// fakeBackend returns a fixed index, a separately configured index on
// Refresh, and records CheckWebhook calls. Mutable state is
// mutex-guarded — the fan-out runs on background goroutines.
type fakeBackend struct {
	resources  []concourse.Resource
	indexErr   error
	refreshRes []concourse.Resource
	refreshErr error
	status     int
	checkErr   error

	mu        sync.Mutex
	refreshed int
	checks    []concourse.Resource
}

func (f *fakeBackend) Resources(_ context.Context) ([]concourse.Resource, error) {
	return f.resources, f.indexErr
}

func (f *fakeBackend) Refresh(_ context.Context) ([]concourse.Resource, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refreshed++
	return f.refreshRes, f.refreshErr
}

func (f *fakeBackend) CheckWebhook(_ context.Context, r concourse.Resource) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checks = append(f.checks, r)
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
	// accepted and every target gets its check attempt.
	b := &sequencingBackend{
		statuses: []int{http.StatusOK, http.StatusNotFound, http.StatusInternalServerError},
		resources: []concourse.Resource{
			{Pipeline: "p1", Name: "a", Type: "git", Repo: "org/repo"},
			{Pipeline: "p1", Name: "b", Type: "git", Repo: "org/repo"},
			{Pipeline: "p1", Name: "c", Type: "git", Repo: "org/repo"},
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
	if got := b.calls(); got != 3 {
		t.Fatalf("check calls=%d want 3", got)
	}
}

// sequencingBackend returns a different status per CheckWebhook call.
type sequencingBackend struct {
	resources []concourse.Resource
	statuses  []int
	mu        sync.Mutex
	n         int
}

func (s *sequencingBackend) Resources(_ context.Context) ([]concourse.Resource, error) {
	return s.resources, nil
}

func (s *sequencingBackend) Refresh(_ context.Context) ([]concourse.Resource, error) {
	return s.resources, nil
}

func (s *sequencingBackend) CheckWebhook(_ context.Context, _ concourse.Resource) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.statuses[s.n%len(s.statuses)]
	s.n++
	return st, nil
}

func (s *sequencingBackend) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n
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
	b := &throttledBackend{delay: 5 * time.Millisecond}
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
	if got := b.maxInflight(); got > fanoutWorkers {
		t.Fatalf("max in-flight checks=%d want <= %d", got, fanoutWorkers)
	}
	if got := b.maxInflight(); got < 2 {
		t.Fatalf("max in-flight checks=%d want > 1 (fan-out must be parallel)", got)
	}
	if got := b.calls(); got != len(resources) {
		t.Fatalf("check calls=%d want %d", got, len(resources))
	}
}

func TestFanoutSemaphoreSharedAcrossDeliveries(t *testing.T) {
	// The fan-out semaphore belongs to the Handler, not to one
	// dispatch — several deliveries fanning out at once must keep
	// TOTAL in-flight checks <= fanoutWorkers. A per-dispatch
	// semaphore would let each run fanoutWorkers in parallel.
	b := &throttledBackend{delay: 10 * time.Millisecond}
	h := New(testSecret, b)
	var resources []concourse.Resource
	for i := 0; i < fanoutWorkers; i++ {
		resources = append(resources, concourse.Resource{
			Pipeline: "p1", Name: fmt.Sprintf("r%d", i),
			Type: "git", Repo: "org/repo",
		})
	}
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.dispatch(resources, "d", "push", "org/repo")
		}()
	}
	wg.Wait()
	if got := b.maxInflight(); got > fanoutWorkers {
		t.Fatalf("max in-flight checks=%d want <= %d (semaphore must be shared across fan-outs)",
			got, fanoutWorkers)
	}
	if got := b.calls(); got != 3*len(resources) {
		t.Fatalf("check calls=%d want %d", got, 3*len(resources))
	}
}

// throttledBackend sleeps per check and tracks peak concurrency.
type throttledBackend struct {
	resources []concourse.Resource
	delay     time.Duration
	mu        sync.Mutex
	inflight  int
	max       int
	n         int
}

func (b *throttledBackend) Resources(_ context.Context) ([]concourse.Resource, error) {
	return b.resources, nil
}

func (b *throttledBackend) Refresh(_ context.Context) ([]concourse.Resource, error) {
	return b.resources, nil
}

func (b *throttledBackend) CheckWebhook(ctx context.Context, _ concourse.Resource) (int, error) {
	b.mu.Lock()
	b.inflight++
	if b.inflight > b.max {
		b.max = b.inflight
	}
	b.n++
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		b.inflight--
		b.mu.Unlock()
	}()
	select {
	case <-time.After(b.delay):
		return http.StatusCreated, nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (b *throttledBackend) maxInflight() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.max
}

func (b *throttledBackend) calls() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.n
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
	b := &throttledBackend{delay: 20 * time.Millisecond, resources: []concourse.Resource{
		{Pipeline: "p1", Name: "a", Type: "git", Repo: "org/repo"},
		{Pipeline: "p1", Name: "b", Type: "git", Repo: "org/repo"},
	}}
	h := New(testSecret, b)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(t, "push", pushBody))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d want 202", rec.Code)
	}
	h.Wait() // exported drain path — same as main's shutdown
	if got := b.calls(); got != 2 {
		t.Fatalf("check calls=%d want 2 after Wait", got)
	}
}
