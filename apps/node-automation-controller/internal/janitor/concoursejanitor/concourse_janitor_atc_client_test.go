package concoursejanitor

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// local-users parsing: first line, split on FIRST colon, CRLF trimmed.
// Every malformed shape fails closed → flyOK=false (delete-only mode).
func TestConcourseJanitorATCCredentials(t *testing.T) {
	for _, tc := range []struct {
		name     string
		data     map[string][]byte
		wantUser string
		wantPass string
		wantErr  bool
	}{
		{"normal", map[string][]byte{cjSecretKey: []byte("admin:s3cr3t\nbackup:x\n")}, "admin", "s3cr3t", false},
		{"crlf", map[string][]byte{cjSecretKey: []byte("admin:s3cr3t\r\nbackup:x\r\n")}, "admin", "s3cr3t", false},
		{"colon in pass", map[string][]byte{cjSecretKey: []byte("admin:p:a:s:s\n")}, "admin", "p:a:s:s", false},
		{"missing key", map[string][]byte{"other": []byte("x")}, "", "", true},
		{"no colon", map[string][]byte{cjSecretKey: []byte("justauser\n")}, "", "", true},
		{"empty user", map[string][]byte{cjSecretKey: []byte(":pw\n")}, "", "", true},
		{"empty pass ok", map[string][]byte{cjSecretKey: []byte("admin:\n")}, "admin", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewSimpleClientset(&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: cjNamespace, Name: cjSecretName},
				Data:       tc.data,
			})
			j := &concourseWorkdirJanitor{queue: "concourse-workdir-janitor", cs: cs, cfg: cjConfig{reqTimeout: 10 * time.Second}}
			u, p, err := j.atcCredentials(ctx)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q:%q", u, p)
				}
				return
			}
			if err != nil || u != tc.wantUser || p != tc.wantPass {
				t.Fatalf("got %q:%q err=%v, want %q:%q", u, p, err, tc.wantUser, tc.wantPass)
			}
		})
	}
	// Missing secret object entirely → error → flyOK=false.
	cs := fake.NewSimpleClientset()
	j := &concourseWorkdirJanitor{queue: "concourse-workdir-janitor", cs: cs, cfg: cjConfig{reqTimeout: 10 * time.Second}}
	if _, _, err := j.atcCredentials(ctx); err == nil {
		t.Fatal("expected error for missing secret")
	}
}

// ---------------------------------------------------------------------------
// ATC client tests (httptest)
// ---------------------------------------------------------------------------

// atcRecorder is a httptest handler capturing "METHOD path auth" per
// request plus the token POST form, and serving programmable replies.
type atcRecorder struct {
	requests  []string
	tokenForm map[string]string
	tokenCode int
	tokenBody string
	workers   string
	putCode   int
}

func (r *atcRecorder) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.requests = append(r.requests,
			fmt.Sprintf("%s %s auth=%q", req.Method, req.URL.Path, req.Header.Get("Authorization")))
		switch req.URL.Path {
		case "/sky/issuer/token":
			_ = req.ParseForm()
			r.tokenForm = map[string]string{}
			for k := range req.PostForm {
				r.tokenForm[k] = req.PostForm.Get(k)
			}
			w.WriteHeader(r.tokenCode)
			_, _ = w.Write([]byte(r.tokenBody))
		case "/api/v1/workers":
			_, _ = w.Write([]byte(r.workers))
		default:
			code := r.putCode
			if code == 0 {
				code = http.StatusOK
			}
			w.WriteHeader(code)
		}
	})
}

// OAuth2 password grant (Concourse ≥3.15, deployed 8.3.2): POST
// /sky/issuer/token with Basic client creds fly:Zmx5, then Bearer on
// every subsequent call. Asserts method+path+Authorization for
// token/workers/land/prune — worker routes are NOT team-scoped.
func TestATCClientOAuthShape(t *testing.T) {
	rec := &atcRecorder{
		tokenCode: http.StatusOK,
		tokenBody: `{"access_token":"tok-oauth","token_type":"Bearer"}`,
		workers:   `[{"name":"w1","state":"running"},{"name":"w2","state":"landed"}]`,
	}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()
	c := newATCClient(srv.URL, srv.Client())

	if err := c.login(ctx, "admin", "pw"); err != nil {
		t.Fatalf("login: %v", err)
	}
	if rec.tokenForm["grant_type"] != "password" ||
		rec.tokenForm["username"] != "admin" ||
		rec.tokenForm["password"] != "pw" ||
		!strings.Contains(rec.tokenForm["scope"], "federated:id") {
		t.Fatalf("bad token form: %v", rec.tokenForm)
	}
	st, err := c.workerState(ctx, "w2")
	if err != nil || st != "landed" {
		t.Fatalf("workerState = %q, %v; want landed", st, err)
	}
	if st, err := c.workerState(ctx, "gone"); err != nil || st != "" {
		t.Fatalf("unknown worker = %q, %v; want \"\"", st, err)
	}
	if err := c.landWorker(ctx, "w2"); err != nil {
		t.Fatalf("landWorker: %v", err)
	}
	if err := c.pruneWorker(ctx, "w2"); err != nil {
		t.Fatalf("pruneWorker: %v", err)
	}
	// base64("fly:Zmx5") = Zmx5OlpteDU= — the token request carries
	// fly's public client creds, everything after carries the bearer.
	want := []string{
		`POST /sky/issuer/token auth="Basic Zmx5OlpteDU="`,
		`GET /api/v1/workers auth="Bearer tok-oauth"`,
		`GET /api/v1/workers auth="Bearer tok-oauth"`,
		`PUT /api/v1/workers/w2/land auth="Bearer tok-oauth"`,
		`PUT /api/v1/workers/w2/prune auth="Bearer tok-oauth"`,
	}
	if fmt.Sprint(rec.requests) != fmt.Sprint(want) {
		t.Fatalf("requests:\n%v\nwant:\n%v", rec.requests, want)
	}
}

// Non-2xx on the token endpoint fails login — caller degrades to
// flyOK=false (no Basic-auth fallback exists on Concourse 8.x).
func TestATCClientLoginError(t *testing.T) {
	rec := &atcRecorder{
		tokenCode: http.StatusUnauthorized,
		tokenBody: `{"error":"invalid_grant"}`,
	}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()
	c := newATCClient(srv.URL, srv.Client())
	if err := c.login(ctx, "u", "bad"); err == nil ||
		!strings.Contains(err.Error(), "401") {
		t.Fatalf("expected 401 login error, got %v", err)
	}
}

// Non-2xx on land/prune is an error carrying the status.
func TestATCClientNon2xx(t *testing.T) {
	rec := &atcRecorder{
		tokenCode: http.StatusOK,
		tokenBody: `{"access_token":"t","token_type":"Bearer"}`,
		putCode:   http.StatusInternalServerError,
	}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()
	c := newATCClient(srv.URL, srv.Client())
	if err := c.login(ctx, "u", "p"); err != nil {
		t.Fatal(err)
	}
	if err := c.landWorker(ctx, "w"); err == nil ||
		!strings.Contains(err.Error(), "500") {
		t.Fatalf("expected status error on land, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Mid-run 401 → one re-login → one retry (token expiry survival)
// ---------------------------------------------------------------------------

// cjExpiryServer plays a Dex token endpoint minting tok-1, tok-2, ...
// and a workers endpoint that 401s the FIRST bearer token only — the
// "login at run start, token expires an hour in" shape of a 190m run.
type cjExpiryServer struct {
	tokenPOSTs  int
	workerCalls []string // Authorization header per workers call
	workersCode int      // 0 → 401 tok-1 only; 401 → always 401
	tokenCode   int      // 0 → always 200; else the code from the 2nd token POST on
}

func (s *cjExpiryServer) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/sky/issuer/token":
			s.tokenPOSTs++
			if s.tokenCode != 0 && s.tokenPOSTs > 1 {
				w.WriteHeader(s.tokenCode)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"access_token":"tok-%d","token_type":"Bearer"}`, s.tokenPOSTs)
		case "/api/v1/workers":
			auth := req.Header.Get("Authorization")
			s.workerCalls = append(s.workerCalls, auth)
			if s.workersCode == http.StatusUnauthorized {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if auth == "Bearer tok-1" {
				w.WriteHeader(http.StatusUnauthorized) // token expired mid-run
				return
			}
			_, _ = w.Write([]byte(`[{"name":"w1","state":"landed"}]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

// A mid-run 401 re-logins with the stored credentials and retries the
// request exactly once — the drain verdict then reads the real worker
// state instead of misreading the auth failure as a land failure and
// deleting the pod undrained.
func TestATCClient401ReLoginsOnceAndRetries(t *testing.T) {
	s := &cjExpiryServer{}
	srv := httptest.NewServer(s.handler())
	defer srv.Close()
	c := newATCClient(srv.URL, srv.Client())
	if err := c.login(ctx, "admin", "pw"); err != nil {
		t.Fatal(err)
	}
	st, err := c.workerState(ctx, "w1")
	if err != nil || st != "landed" {
		t.Fatalf("workerState after re-login = %q, %v; want landed", st, err)
	}
	// One re-login — no loop.
	if s.tokenPOSTs != 2 {
		t.Fatalf("token POSTs = %d, want 2 (initial login + one re-login)", s.tokenPOSTs)
	}
	// The retry carried the FRESH token.
	if len(s.workerCalls) != 2 ||
		s.workerCalls[0] != "Bearer tok-1" || s.workerCalls[1] != "Bearer tok-2" {
		t.Fatalf("workers calls = %v, want [tok-1 401, tok-2 200]", s.workerCalls)
	}
	// The fresh token keeps working — no further re-login.
	if _, err := c.workerState(ctx, "gone"); err != nil {
		t.Fatal(err)
	}
	if s.tokenPOSTs != 2 {
		t.Fatalf("token POSTs after follow-up = %d, want 2", s.tokenPOSTs)
	}
}

// A 401 that SURVIVES the re-login is the error it is — one retry,
// then out (no loop).
func TestATCClientSecond401ErrorsWithoutLoop(t *testing.T) {
	s := &cjExpiryServer{workersCode: http.StatusUnauthorized}
	srv := httptest.NewServer(s.handler())
	defer srv.Close()
	c := newATCClient(srv.URL, srv.Client())
	if err := c.login(ctx, "u", "p"); err != nil {
		t.Fatal(err)
	}
	_, err := c.workerState(ctx, "w1")
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected 401 error after the retried request, got %v", err)
	}
	if s.tokenPOSTs != 2 || len(s.workerCalls) != 2 {
		t.Fatalf("token POSTs = %d, worker calls = %d; want 2/2 (exactly one retry)",
			s.tokenPOSTs, len(s.workerCalls))
	}
}

// A failed re-login surfaces as an error carrying the re-login
// context — same fail shape as before the fix.
func TestATCClientReLoginFailureErrors(t *testing.T) {
	s := &cjExpiryServer{tokenCode: http.StatusInternalServerError}
	srv := httptest.NewServer(s.handler())
	defer srv.Close()
	c := newATCClient(srv.URL, srv.Client())
	if err := c.login(ctx, "u", "p"); err != nil {
		t.Fatal(err)
	}
	_, err := c.workerState(ctx, "w1")
	if err == nil || !strings.Contains(err.Error(), "re-login") {
		t.Fatalf("expected re-login failure error, got %v", err)
	}
	if s.tokenPOSTs != 2 || len(s.workerCalls) != 1 {
		t.Fatalf("token POSTs = %d, worker calls = %d; want 2/1 (no retry after failed re-login)",
			s.tokenPOSTs, len(s.workerCalls))
	}
}
