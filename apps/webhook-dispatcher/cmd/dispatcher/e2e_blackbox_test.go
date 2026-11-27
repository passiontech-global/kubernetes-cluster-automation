package main_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const (
	e2eSecret       = "e2e-webhook-secret-value"
	e2eWebhookToken = "e2e-ci-webhook-token"
	e2eLocalUsers   = "ci-user:ci-pass-123"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func waitForLogContains(t *testing.T, logs *syncBuffer, substr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(logs.String(), substr) {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	if !strings.Contains(logs.String(), substr) {
		t.Fatalf("timed out waiting %s for %q in logs, got:\n%s", timeout, substr, logs.String())
	}
}

func reserveLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func signPayload(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func buildDispatcherBinary(t *testing.T) string {
	t.Helper()
	binPath := filepath.Join(t.TempDir(), "webhook-dispatcher")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "build", "-o", binPath, ".")
	cmd.Dir = "."
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build dispatcher binary failed: %v\n%s", err, string(out))
	}
	return binPath
}

func cleanChildEnv(extra map[string]string) []string {
	var env []string
	for _, kv := range os.Environ() {
		k, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		switch k {
		case "GITHUB_WEBHOOK_SECRET", "CI_WEBHOOK_TOKEN", "LOCAL_USERS",
			"CONCOURSE_URL", "CONCOURSE_TEAM", "LISTEN_ADDR", "METRICS_ADDR":
			continue
		}
		env = append(env, kv)
	}
	for k, v := range extra {
		env = append(env, k+"="+v)
	}
	return env
}

type runningDispatcher struct {
	cmd         *exec.Cmd
	listenAddr  string
	metricsAddr string
	logs        *syncBuffer
	doneCh      chan struct{}
	waitErr     error
	stopOnce    sync.Once
}

func startDispatcher(t *testing.T, bin string, concourseURL string) *runningDispatcher {
	t.Helper()
	listenAddr := reserveLoopbackAddr(t)
	metricsAddr := reserveLoopbackAddr(t)
	logs := &syncBuffer{}

	cmd := exec.Command(bin)
	cmd.Env = cleanChildEnv(map[string]string{
		"GITHUB_WEBHOOK_SECRET": e2eSecret,
		"CI_WEBHOOK_TOKEN":      e2eWebhookToken,
		"LOCAL_USERS":           e2eLocalUsers,
		"CONCOURSE_URL":         concourseURL,
		"CONCOURSE_TEAM":        "main",
		"LISTEN_ADDR":           listenAddr,
		"METRICS_ADDR":          metricsAddr,
	})
	cmd.Stdout = logs
	cmd.Stderr = logs

	if err := cmd.Start(); err != nil {
		t.Fatalf("start dispatcher: %v", err)
	}

	doneCh := make(chan struct{})
	rd := &runningDispatcher{
		cmd:         cmd,
		listenAddr:  listenAddr,
		metricsAddr: metricsAddr,
		logs:        logs,
		doneCh:      doneCh,
	}
	go func() {
		rd.waitErr = cmd.Wait()
		close(doneCh)
	}()

	t.Cleanup(func() {
		rd.stopOnce.Do(func() {
			select {
			case <-rd.doneCh:
				return
			default:
			}
			_ = cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-rd.doneCh:
			case <-time.After(5 * time.Second):
				_ = cmd.Process.Kill()
				<-rd.doneCh
			}
		})
	})

	// Poll /readyz until 200 ok.
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-rd.doneCh:
			t.Fatalf("dispatcher exited prematurely (%v), logs:\n%s", rd.waitErr, logs.String())
		default:
		}
		resp, err := client.Get("http://" + listenAddr + "/readyz")
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK && string(body) == "ok" {
				return rd
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("dispatcher /readyz did not become ready within 5s, logs:\n%s", logs.String())
	return nil
}

func (rd *runningDispatcher) postWebhook(t *testing.T, event, delivery, sig string, body []byte) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://"+rd.listenAddr+"/webhook", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new webhook request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if event != "" {
		req.Header.Set("X-GitHub-Event", event)
	}
	if delivery != "" {
		req.Header.Set("X-GitHub-Delivery", delivery)
	}
	if sig != "" {
		req.Header.Set("X-Hub-Signature-256", sig)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /webhook failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(respBody)
}

type webhookCall struct {
	Path    string
	Query   string
	Token   string
	VarsEnv string
	AuthHdr string
}

type mockATC struct {
	server *httptest.Server
	mu     sync.Mutex
	calls  []webhookCall

	tokenHandler     func(w http.ResponseWriter, r *http.Request, path string)
	pipelinesHandler func(w http.ResponseWriter, r *http.Request)
	configHandler    func(w http.ResponseWriter, r *http.Request, pipeline string)
	checkHandler     func(w http.ResponseWriter, r *http.Request)
}

func newMockATC(t *testing.T) *mockATC {
	t.Helper()
	m := &mockATC{}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && (r.URL.Path == "/sky/issuer/token" || r.URL.Path == "/sky/token"):
			m.mu.Lock()
			h := m.tokenHandler
			m.mu.Unlock()
			if h != nil {
				h(w, r, r.URL.Path)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"default-tok","expires_in":3600}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/teams/main/pipelines":
			m.mu.Lock()
			h := m.pipelinesHandler
			m.mu.Unlock()
			if h != nil {
				h(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[]`))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/teams/main/pipelines/") && strings.HasSuffix(r.URL.Path, "/config"):
			trimmed := strings.TrimPrefix(r.URL.Path, "/api/v1/teams/main/pipelines/")
			pipeline := strings.TrimSuffix(trimmed, "/config")
			m.mu.Lock()
			h := m.configHandler
			m.mu.Unlock()
			if h != nil {
				h(w, r, pipeline)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"config":{"resources":[]}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/check/webhook"):
			m.mu.Lock()
			m.calls = append(m.calls, webhookCall{
				Path:    r.URL.Path,
				Query:   r.URL.RawQuery,
				Token:   r.URL.Query().Get("webhook_token"),
				VarsEnv: r.URL.Query().Get("vars.env"),
				AuthHdr: r.Header.Get("Authorization"),
			})
			h := m.checkHandler
			m.mu.Unlock()
			if h != nil {
				h(w, r)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockATC) webhookCalls() []webhookCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]webhookCall, len(m.calls))
	copy(out, m.calls)
	return out
}

func (m *mockATC) waitForWebhookCalls(t *testing.T, want int, timeout time.Duration) []webhookCall {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		got := m.webhookCalls()
		if len(got) >= want {
			return got
		}
		time.Sleep(20 * time.Millisecond)
	}
	got := m.webhookCalls()
	t.Fatalf("timed out waiting for %d check/webhook calls; got %d (%+v)", want, len(got), got)
	return nil
}

func TestE2EDispatcher(t *testing.T) {
	bin := buildDispatcherBinary(t)

	t.Run("Tier1_VersionFlag", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, "-version")
		cmd.Env = cleanChildEnv(nil)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("-version exited with error: %v\n%s", err, string(out))
		}
		if !strings.HasPrefix(string(out), "webhook-dispatcher ") {
			t.Fatalf("-version output = %q, want prefix %q", string(out), "webhook-dispatcher ")
		}
	})

	t.Run("Tier1_BootValidationMissingEnvAndMalformedLocalUsers", func(t *testing.T) {
		cases := []struct {
			name string
			env  map[string]string
		}{
			{"missing_secret", map[string]string{"CI_WEBHOOK_TOKEN": e2eWebhookToken, "LOCAL_USERS": e2eLocalUsers}},
			{"missing_token", map[string]string{"GITHUB_WEBHOOK_SECRET": e2eSecret, "LOCAL_USERS": e2eLocalUsers}},
			{"missing_local_users", map[string]string{"GITHUB_WEBHOOK_SECRET": e2eSecret, "CI_WEBHOOK_TOKEN": e2eWebhookToken}},
			{"malformed_no_colon", map[string]string{"GITHUB_WEBHOOK_SECRET": e2eSecret, "CI_WEBHOOK_TOKEN": e2eWebhookToken, "LOCAL_USERS": "adminonly"}},
			{"malformed_empty_user", map[string]string{"GITHUB_WEBHOOK_SECRET": e2eSecret, "CI_WEBHOOK_TOKEN": e2eWebhookToken, "LOCAL_USERS": ":secret"}},
			{"malformed_empty_pass", map[string]string{"GITHUB_WEBHOOK_SECRET": e2eSecret, "CI_WEBHOOK_TOKEN": e2eWebhookToken, "LOCAL_USERS": "admin:"}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, bin)
				cmd.Env = cleanChildEnv(tc.env)
				out, err := cmd.CombinedOutput()
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
					t.Fatalf("%s: expected exit code 1, got err=%v out=%s", tc.name, err, string(out))
				}
			})
		}
	})

	t.Run("Tier1_ListenersHealthMetricsPprofIsolation", func(t *testing.T) {
		atc := newMockATC(t)
		atc.pipelinesHandler = func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`[{"name":"app-ci","archived":false}]`))
		}
		atc.configHandler = func(w http.ResponseWriter, _ *http.Request, _ string) {
			_, _ = w.Write([]byte(`{"config":{"resources":[{"name":"repo-git","type":"git","source":{"uri":"https://github.com/org/demo.git"}}]}}`))
		}
		rd := startDispatcher(t, bin, atc.server.URL)

		client := &http.Client{Timeout: 3 * time.Second}
		for _, route := range []string{"/healthz", "/readyz"} {
			resp, err := client.Get("http://" + rd.listenAddr + route)
			if err != nil {
				t.Fatalf("GET %s failed: %v", route, err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK || string(body) != "ok" {
				t.Fatalf("GET %s = (%d, %q), want (200, \"ok\")", route, resp.StatusCode, string(body))
			}
		}

		// Trigger one delivery so CounterVec/HistogramVec metrics materialize.
		payload := []byte(`{"repository":{"full_name":"org/demo"}}`)
		code, _ := rd.postWebhook(t, "push", "del-metrics-1", signPayload(e2eSecret, payload), payload)
		if code != http.StatusAccepted {
			t.Fatalf("push status = %d, want 202", code)
		}
		atc.waitForWebhookCalls(t, 1, 3*time.Second)

		// Verify /metrics and /debug/pprof/ on METRICS_ADDR.
		// Poll /metrics until fanout completes and updates fanout_total/fanout_duration_seconds:
		// mock ATC records the request before CheckWebhook returns to handler/dispatch.go.
		wantMetrics := []string{
			"webhook_dispatcher_deliveries_total",
			"webhook_dispatcher_fanout_total",
			"webhook_dispatcher_fanout_duration_seconds",
			"webhook_dispatcher_concourse_index_last_refresh_timestamp_seconds",
			"webhook_dispatcher_concourse_index_fetch_errors_total",
		}
		metricsDeadline := time.Now().Add(5 * time.Second)
		var lastMetricsErr error
		for {
			var missing string
			resp, err := client.Get("http://" + rd.metricsAddr + "/metrics")
			if err != nil {
				lastMetricsErr = fmt.Errorf("GET /metrics failed: %v", err)
			} else {
				metricsBody, readErr := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if readErr != nil {
					lastMetricsErr = fmt.Errorf("read /metrics body: %v", readErr)
				} else if resp.StatusCode != http.StatusOK {
					lastMetricsErr = fmt.Errorf("GET /metrics status = %d, want 200", resp.StatusCode)
				} else {
					bodyStr := string(metricsBody)
					for _, metricName := range wantMetrics {
						if !strings.Contains(bodyStr, metricName) {
							missing = metricName
							break
						}
					}
					if missing == "" {
						break
					}
					lastMetricsErr = fmt.Errorf("/metrics missing %q", missing)
				}
			}
			if time.Now().After(metricsDeadline) {
				t.Fatalf("timed out waiting for /metrics series: %v", lastMetricsErr)
			}
			time.Sleep(25 * time.Millisecond)
		}

		pprofResp, err := client.Get("http://" + rd.metricsAddr + "/debug/pprof/")
		if err != nil {
			t.Fatalf("GET metrics /debug/pprof/ failed: %v", err)
		}
		_, _ = io.Copy(io.Discard, pprofResp.Body)
		_ = pprofResp.Body.Close()
		if pprofResp.StatusCode != http.StatusOK {
			t.Fatalf("GET metrics /debug/pprof/ = %d, want 200", pprofResp.StatusCode)
		}

		// Verify isolation: /debug/pprof/ and /metrics MUST return 404 on LISTEN_ADDR,
		// and /healthz, /readyz, POST /webhook MUST return 404 on METRICS_ADDR.
		for _, isolated := range []string{"/debug/pprof/", "/metrics"} {
			isoResp, err := client.Get("http://" + rd.listenAddr + isolated)
			if err != nil {
				t.Fatalf("GET public %s failed: %v", isolated, err)
			}
			_, _ = io.Copy(io.Discard, isoResp.Body)
			_ = isoResp.Body.Close()
			if isoResp.StatusCode != http.StatusNotFound {
				t.Fatalf("public listener %s status = %d, want 404", isolated, isoResp.StatusCode)
			}
		}
		for _, route := range []string{"/healthz", "/readyz"} {
			isoResp, err := client.Get("http://" + rd.metricsAddr + route)
			if err != nil {
				t.Fatalf("GET metrics %s failed: %v", route, err)
			}
			_, _ = io.Copy(io.Discard, isoResp.Body)
			_ = isoResp.Body.Close()
			if isoResp.StatusCode != http.StatusNotFound {
				t.Fatalf("metrics listener %s status = %d, want 404", route, isoResp.StatusCode)
			}
		}
		whReq, err := http.NewRequest(http.MethodPost, "http://"+rd.metricsAddr+"/webhook", bytes.NewReader(payload))
		if err != nil {
			t.Fatalf("new metrics /webhook request: %v", err)
		}
		whResp, err := client.Do(whReq)
		if err != nil {
			t.Fatalf("POST metrics /webhook failed: %v", err)
		}
		_, _ = io.Copy(io.Discard, whResp.Body)
		_ = whResp.Body.Close()
		if whResp.StatusCode != http.StatusNotFound {
			t.Fatalf("metrics listener POST /webhook status = %d, want 404", whResp.StatusCode)
		}
		client.CloseIdleConnections()
	})

	t.Run("Tier1_WebhookEventsAndInstancedVars", func(t *testing.T) {
		atc := newMockATC(t)
		atc.pipelinesHandler = func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`[
				{"name":"main-pipe","archived":false},
				{"name":"inst-pipe","archived":false,"instance_vars":{"env":"prod"}},
				{"name":"old-pipe","archived":true}
			]`))
		}
		atc.configHandler = func(w http.ResponseWriter, r *http.Request, pipeline string) {
			switch pipeline {
			case "main-pipe":
				_, _ = w.Write([]byte(`{"config":{"resources":[
					{"name":"src-git","type":"git","source":{"uri":"git@github.com:org/service.git"}},
					{"name":"pr-check","type":"github-pr","source":{"repository":"org/service"}}
				]}}`))
			case "inst-pipe":
				if r.URL.Query().Get("vars.env") != `"prod"` {
					http.Error(w, "missing instance vars", http.StatusBadRequest)
					return
				}
				_, _ = w.Write([]byte(`{"config":{"resources":[
					{"name":"inst-git","type":"git","source":{"uri":"https://github.com/org/service.git"}}
				]}}`))
			case "old-pipe":
				http.Error(w, "archived pipeline must not be queried", http.StatusInternalServerError)
			}
		}
		rd := startDispatcher(t, bin, atc.server.URL)

		// 1. push -> matches both main-pipe/src-git and inst-pipe/inst-git (2 resources).
		pushBody := []byte(`{"after":"abc123","repository":{"full_name":"org/service"}}`)
		code, resp := rd.postWebhook(t, "push", "d-push", signPayload(e2eSecret, pushBody), pushBody)
		if code != http.StatusAccepted || !strings.Contains(resp, `"resources_matched":2`) {
			t.Fatalf("push = (%d, %s), want (202, resources_matched:2)", code, resp)
		}
		calls := atc.waitForWebhookCalls(t, 2, 3*time.Second)
		var sawInstanced bool
		for _, c := range calls {
			if c.Token != e2eWebhookToken {
				t.Fatalf("check/webhook token = %q, want %q", c.Token, e2eWebhookToken)
			}
			if c.AuthHdr != "" {
				t.Fatalf("check/webhook must not forward Basic/Bearer header, got %q", c.AuthHdr)
			}
			if strings.Contains(c.Path, "/inst-pipe/") && c.VarsEnv == `"prod"` {
				sawInstanced = true
			}
		}
		if !sawInstanced {
			t.Fatalf("expected instanced pipeline check/webhook with vars.env=\"prod\", got %+v", calls)
		}

		// 2. pull_request (opened) -> matches github-pr (1 resource).
		prBody := []byte(`{"action":"opened","repository":{"full_name":"org/service"}}`)
		code, resp = rd.postWebhook(t, "pull_request", "d-pr", signPayload(e2eSecret, prBody), prBody)
		if code != http.StatusAccepted || !strings.Contains(resp, `"resources_matched":1`) {
			t.Fatalf("pull_request = (%d, %s), want (202, resources_matched:1)", code, resp)
		}
		prCalls := atc.waitForWebhookCalls(t, 3, 3*time.Second)
		const wantPRPath = "/api/v1/teams/main/pipelines/main-pipe/resources/pr-check/check/webhook"
		if prCalls[2].Path != wantPRPath {
			t.Fatalf("pull_request check/webhook Path = %q, want %q", prCalls[2].Path, wantPRPath)
		}

		// 3. release (published) -> matches git (2); release (created) -> ignored (0).
		relPub := []byte(`{"action":"published","repository":{"full_name":"org/service"}}`)
		code, resp = rd.postWebhook(t, "release", "d-rel1", signPayload(e2eSecret, relPub), relPub)
		if code != http.StatusAccepted || !strings.Contains(resp, `"resources_matched":2`) {
			t.Fatalf("release published = (%d, %s)", code, resp)
		}
		atc.waitForWebhookCalls(t, 5, 3*time.Second)

		relCreated := []byte(`{"action":"created","repository":{"full_name":"org/service"}}`)
		code, resp = rd.postWebhook(t, "release", "d-rel2", signPayload(e2eSecret, relCreated), relCreated)
		if code != http.StatusAccepted || !strings.Contains(resp, `"resources_matched":0`) {
			t.Fatalf("release created = (%d, %s)", code, resp)
		}

		// 4. create (tag) -> matches git (2); create (branch) -> ignored (0).
		tagBody := []byte(`{"ref_type":"tag","repository":{"full_name":"org/service"}}`)
		code, resp = rd.postWebhook(t, "create", "d-tag", signPayload(e2eSecret, tagBody), tagBody)
		if code != http.StatusAccepted || !strings.Contains(resp, `"resources_matched":2`) {
			t.Fatalf("create tag = (%d, %s)", code, resp)
		}
		atc.waitForWebhookCalls(t, 7, 3*time.Second)

		branchBody := []byte(`{"ref_type":"branch","repository":{"full_name":"org/service"}}`)
		code, resp = rd.postWebhook(t, "create", "d-branch", signPayload(e2eSecret, branchBody), branchBody)
		if code != http.StatusAccepted || !strings.Contains(resp, `"resources_matched":0`) {
			t.Fatalf("create branch = (%d, %s)", code, resp)
		}

		// 5. unhandled event -> 202 resources_matched:0.
		issueBody := []byte(`{"action":"opened","repository":{"full_name":"org/service"}}`)
		code, resp = rd.postWebhook(t, "issues", "d-issues", signPayload(e2eSecret, issueBody), issueBody)
		if code != http.StatusAccepted || !strings.Contains(resp, `"resources_matched":0`) {
			t.Fatalf("unhandled issues = (%d, %s)", code, resp)
		}
	})

	t.Run("Tier2_F9_BearerAuth404_405NonDowngradeAnd401Recovery", func(t *testing.T) {
		t.Run("bearer_401_re_mint_recovery", func(t *testing.T) {
			atc := newMockATC(t)
			var tokenSeq atomic.Int32
			atc.tokenHandler = func(w http.ResponseWriter, _ *http.Request, path string) {
				if path != "/sky/issuer/token" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				n := tokenSeq.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"access_token":"tok-%d","expires_in":3600}`, n)
			}
			atc.pipelinesHandler = func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
					http.Error(w, "bearer required", http.StatusUnauthorized)
					return
				}
				_, _ = w.Write([]byte(`[{"name":"p1","archived":false}]`))
			}
			atc.configHandler = func(w http.ResponseWriter, r *http.Request, _ string) {
				// Revoke tok-1 on /config so getJSON triggers 401 -> invalidate -> re-mint tok-2.
				if r.Header.Get("Authorization") != "Bearer tok-2" {
					http.Error(w, "token revoked", http.StatusUnauthorized)
					return
				}
				_, _ = w.Write([]byte(`{"config":{"resources":[{"name":"r1","type":"git","source":{"uri":"https://github.com/org/recover.git"}}]}}`))
			}
			rd := startDispatcher(t, bin, atc.server.URL)

			body := []byte(`{"repository":{"full_name":"org/recover"}}`)
			code, resp := rd.postWebhook(t, "push", "d-f9-401", signPayload(e2eSecret, body), body)
			if code != http.StatusAccepted || !strings.Contains(resp, `"resources_matched":1`) {
				t.Fatalf("Bearer 401 re-mint recovery failed: (%d, %s), logs:\n%s", code, resp, rd.logs.String())
			}
			atc.waitForWebhookCalls(t, 1, 3*time.Second)
		})

		t.Run("bearer_404_405_no_permanent_basic_latch", func(t *testing.T) {
			atc := newMockATC(t)
			var phase atomic.Int32 // 0: issue tok-1; 1: token endpoints 404/405; 2: token endpoint restored issuing tok-2
			var sawBasicOnAPI atomic.Bool
			var tokenCalls atomic.Int32

			atc.tokenHandler = func(w http.ResponseWriter, _ *http.Request, path string) {
				tokenCalls.Add(1)
				switch phase.Load() {
				case 0:
					if path == "/sky/issuer/token" {
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write([]byte(`{"access_token":"tok-1","expires_in":3600}`))
						return
					}
					w.WriteHeader(http.StatusNotFound)
				case 1:
					// Transient 404 on /sky/issuer/token and 405 on /sky/token during re-mint.
					if path == "/sky/issuer/token" {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					w.WriteHeader(http.StatusMethodNotAllowed)
				case 2:
					if path == "/sky/issuer/token" {
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write([]byte(`{"access_token":"tok-2","expires_in":3600}`))
						return
					}
					w.WriteHeader(http.StatusNotFound)
				}
			}
			atc.pipelinesHandler = func(w http.ResponseWriter, r *http.Request) {
				auth := r.Header.Get("Authorization")
				if strings.HasPrefix(auth, "Basic ") {
					sawBasicOnAPI.Store(true)
					http.Error(w, "basic disabled on bearer ATC", http.StatusUnauthorized)
					return
				}
				if auth != "Bearer tok-1" && auth != "Bearer tok-2" {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
				_, _ = w.Write([]byte(`[{"name":"p1","archived":false}]`))
			}
			atc.configHandler = func(w http.ResponseWriter, r *http.Request, _ string) {
				auth := r.Header.Get("Authorization")
				if strings.HasPrefix(auth, "Basic ") {
					sawBasicOnAPI.Store(true)
					http.Error(w, "basic disabled on bearer ATC", http.StatusUnauthorized)
					return
				}
				if auth == "Bearer tok-1" {
					// Flip token endpoints to 404/405 right as we revoke tok-1!
					phase.Store(1)
					http.Error(w, "tok-1 revoked", http.StatusUnauthorized)
					return
				}
				if auth != "Bearer tok-2" {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
				_, _ = w.Write([]byte(`{"config":{"resources":[{"name":"r1","type":"git","source":{"uri":"https://github.com/org/bearer.git"}}]}}`))
			}

			rd := startDispatcher(t, bin, atc.server.URL)

			// Delivery 1: obtains tok-1, then hits 401 on /config while token endpoints 404/405.
			body := []byte(`{"repository":{"full_name":"org/bearer"}}`)
			code1, resp1 := rd.postWebhook(t, "push", "d-f9-1", signPayload(e2eSecret, body), body)
			if code1 != http.StatusBadGateway {
				t.Fatalf("Delivery 1 expected 502 while token endpoints 404/405, got (%d, %s)", code1, resp1)
			}
			if sawBasicOnAPI.Load() {
				t.Fatalf("dispatcher downgraded from authModeBearer to Basic Auth on 404/405 during Delivery 1")
			}

			// Restore token endpoint and wait past NegCacheTTL (3s) so cold-start index fetch runs again.
			phase.Store(2)
			time.Sleep(3200 * time.Millisecond)

			code2, resp2 := rd.postWebhook(t, "push", "d-f9-2", signPayload(e2eSecret, body), body)
			if code2 != http.StatusAccepted || !strings.Contains(resp2, `"resources_matched":1`) {
				t.Fatalf("Delivery 2 after token endpoint recovery failed: (%d, %s), sawBasic=%v, tokenCalls=%d, logs:\n%s",
					code2, resp2, sawBasicOnAPI.Load(), tokenCalls.Load(), rd.logs.String())
			}
			if sawBasicOnAPI.Load() {
				t.Fatalf("dispatcher permanently latched Basic Auth after 404/405 in authModeBearer")
			}
			atc.waitForWebhookCalls(t, 1, 3*time.Second)
		})

		t.Run("basic_401_recovery_to_bearer", func(t *testing.T) {
			atc := newMockATC(t)
			var tokenRestored atomic.Bool
			var sawBasicOnPipelines atomic.Bool
			var sawBearerOnResources atomic.Bool

			atc.tokenHandler = func(w http.ResponseWriter, _ *http.Request, path string) {
				if !tokenRestored.Load() {
					// Initial probe during /pipelines sees 404 on both endpoints -> latches Basic Auth.
					w.WriteHeader(http.StatusNotFound)
					return
				}
				if path != "/sky/issuer/token" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"tok-after-401","expires_in":3600}`))
			}
			atc.pipelinesHandler = func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
					http.Error(w, "expected basic auth after token 404", http.StatusUnauthorized)
					return
				}
				sawBasicOnPipelines.Store(true)
				_, _ = w.Write([]byte(`[{"name":"p1","archived":false}]`))
			}
			atc.configHandler = func(w http.ResponseWriter, r *http.Request, _ string) {
				auth := r.Header.Get("Authorization")
				if strings.HasPrefix(auth, "Basic ") {
					// ATC upgraded to require OIDC Bearer token while Basic was latched.
					tokenRestored.Store(true)
					http.Error(w, "basic rejected; bearer required", http.StatusUnauthorized)
					return
				}
				if auth != "Bearer tok-after-401" {
					http.Error(w, "unexpected auth header", http.StatusUnauthorized)
					return
				}
				sawBearerOnResources.Store(true)
				_, _ = w.Write([]byte(`{"config":{"resources":[{"name":"r1","type":"git","source":{"uri":"https://github.com/org/basic-recover.git"}}]}}`))
			}

			rd := startDispatcher(t, bin, atc.server.URL)

			body := []byte(`{"repository":{"full_name":"org/basic-recover"}}`)
			code, resp := rd.postWebhook(t, "push", "d-f9-basic-401", signPayload(e2eSecret, body), body)
			if code != http.StatusAccepted || !strings.Contains(resp, `"resources_matched":1`) {
				t.Fatalf("Basic 401 recovery failed: (%d, %s), logs:\n%s", code, resp, rd.logs.String())
			}
			if !sawBasicOnPipelines.Load() || !sawBearerOnResources.Load() {
				t.Fatalf("expected Basic->401->Bearer transition, sawBasic=%v sawBearer=%v",
					sawBasicOnPipelines.Load(), sawBearerOnResources.Load())
			}
			atc.waitForWebhookCalls(t, 1, 3*time.Second)
			waitForLogContains(t, rd.logs, "concourse API returned 401 in basic-auth mode", 2*time.Second)
		})

		t.Run("strict_token_jsonv2_rejects_duplicate_keys", func(t *testing.T) {
			atc := newMockATC(t)
			atc.tokenHandler = func(w http.ResponseWriter, _ *http.Request, path string) {
				if path != "/sky/issuer/token" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"t1","access_token":"t2","expires_in":3600}`))
			}
			rd := startDispatcher(t, bin, atc.server.URL)
			body := []byte(`{"repository":{"full_name":"org/strict-tok"}}`)
			code, resp := rd.postWebhook(t, "push", "d-strict-tok", signPayload(e2eSecret, body), body)
			if code != http.StatusBadGateway {
				t.Fatalf("duplicate keys in OIDC token response expected 502, got (%d, %s)", code, resp)
			}
			waitForLogContains(t, rd.logs, "duplicate", 2*time.Second)
		})
	})

	t.Run("Tier2_F13_NonStringSourceURIAuthorityBypassAndJSONv2", func(t *testing.T) {
		atc := newMockATC(t)
		atc.pipelinesHandler = func(w http.ResponseWriter, _ *http.Request) {
			// Include duplicate keys + lone UTF-16 surrogate + raw invalid UTF-8 from ATC.
			_, _ = w.Write([]byte(`[{"name":"p-stale","name":"p1","archived":false,"note":"bad \uD83D ` + "\xff" + `"}]`))
		}
		atc.configHandler = func(w http.ResponseWriter, _ *http.Request, _ string) {
			_, _ = w.Write([]byte(`{"config":{"resources":[
				{"name":"obj-uri","type":"git","source":{"uri":{"url":"https://github.com/org/ignored.git"}}},
				{"name":"arr-uri","type":"git","source":{"uri":["https://github.com/org/ignored2.git"]}},
				{"name":"num-uri","type":"git","source":{"uri":42}},
				{"name":"evil-query","type":"git","source":{"uri":"https://evil.com?x=@github.com/org/victim.git"}},
				{"name":"evil-frag","type":"git","source":{"uri":"https://evil.com#x@github.com/org/victim2.git"}},
				{"name":"legit-old","name":"legit","type":"git","source":{"note":"` + "\xff" + `\uD83D","uri":"https://github.com/org/wrong.git","uri":"https://github.com/org/legit.git"}}
			]}}`))
		}
		rd := startDispatcher(t, bin, atc.server.URL)

		// 1. Non-string source.uri and dirty ATC JSON must not break team index for legit resource.
		legitBody := []byte(`{"repository":{"full_name":"org/legit"}}`)
		code, resp := rd.postWebhook(t, "push", "d-legit", signPayload(e2eSecret, legitBody), legitBody)
		if code != http.StatusAccepted || !strings.Contains(resp, `"resources_matched":1`) {
			t.Fatalf("legit webhook failed (non-string source.uri / dirty ATC JSON broke index): (%d, %s)", code, resp)
		}
		atc.waitForWebhookCalls(t, 1, 3*time.Second)

		// 2. NormalizeRepo ? and # authority bypass rejection.
		for _, victim := range []string{"org/victim", "org/victim2"} {
			vBody := []byte(fmt.Sprintf(`{"repository":{"full_name":%q}}`, victim))
			code, resp := rd.postWebhook(t, "push", "d-bypass", signPayload(e2eSecret, vBody), vBody)
			if code != http.StatusAccepted || !strings.Contains(resp, `"resources_matched":0`) {
				t.Fatalf("authority bypass matched %q: (%d, %s)", victim, code, resp)
			}
		}

		// 3. Lone UTF-16 surrogate (\uD83D) + duplicate keys in webhook JSON -> 202 & fan-out.
		dirtyJSON := []byte(`{"after":"123","head_commit":{"message":"broken \uD83D surrogate"},"repository":{"full_name":"org/wrong","full_name":"org/legit"}}`)
		code, resp = rd.postWebhook(t, "push", "d-dirty-json", signPayload(e2eSecret, dirtyJSON), dirtyJSON)
		if code != http.StatusAccepted || !strings.Contains(resp, `"resources_matched":1`) {
			t.Fatalf("lone UTF-16 surrogate / duplicate key JSON rejected: (%d, %s)", code, resp)
		}
		atc.waitForWebhookCalls(t, 2, 3*time.Second)

		// 4. Malformed JSON & missing repository.full_name -> 400 Bad Request.
		badJSON := []byte(`{"repository":`)
		code, _ = rd.postWebhook(t, "push", "d-bad-json", signPayload(e2eSecret, badJSON), badJSON)
		if code != http.StatusBadRequest {
			t.Fatalf("malformed JSON status = %d, want 400", code)
		}
		missingRepo := []byte(`{"after":"123"}`)
		code, _ = rd.postWebhook(t, "push", "d-no-repo", signPayload(e2eSecret, missingRepo), missingRepo)
		if code != http.StatusBadRequest {
			t.Fatalf("missing repository.full_name status = %d, want 400", code)
		}

		// 5. Bad / missing HMAC -> 401.
		code, _ = rd.postWebhook(t, "push", "d-no-sig", "", legitBody)
		if code != http.StatusUnauthorized {
			t.Fatalf("missing HMAC status = %d, want 401", code)
		}
		code, _ = rd.postWebhook(t, "push", "d-bad-sig", "sha256="+strings.Repeat("0", 64), legitBody)
		if code != http.StatusUnauthorized {
			t.Fatalf("wrong HMAC status = %d, want 401", code)
		}

		// 6. >8 MiB body -> 413.
		oversized := bytes.Repeat([]byte("a"), (8<<20)+1024)
		code, _ = rd.postWebhook(t, "push", "d-big", signPayload(e2eSecret, oversized), oversized)
		if code != http.StatusRequestEntityTooLarge {
			t.Fatalf(">8 MiB body status = %d, want 413", code)
		}

		// 7. Non-actionable PR & deleted branch -> 200 skipped.
		prLabeled := []byte(`{"action":"labeled","repository":{"full_name":"org/legit"}}`)
		code, resp = rd.postWebhook(t, "pull_request", "d-pr-skip", signPayload(e2eSecret, prLabeled), prLabeled)
		if code != http.StatusOK || !strings.Contains(resp, `"skipped":"action"`) {
			t.Fatalf("non-actionable PR = (%d, %s), want 200 skipped:action", code, resp)
		}

		branchDeleted := []byte(`{"deleted":true,"after":"0000000000000000000000000000000000000000","repository":{"full_name":"org/legit"}}`)
		code, resp = rd.postWebhook(t, "push", "d-del-skip", signPayload(e2eSecret, branchDeleted), branchDeleted)
		if code != http.StatusOK || !strings.Contains(resp, `"skipped":"deleted"`) {
			t.Fatalf("deleted branch push = (%d, %s), want 200 skipped:deleted", code, resp)
		}
	})

	t.Run("Tier4_ConcurrentBurstAndGracefulDrain", func(t *testing.T) {
		atc := newMockATC(t)
		atc.pipelinesHandler = func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`[{"name":"burst-pipe","archived":false}]`))
		}
		atc.configHandler = func(w http.ResponseWriter, _ *http.Request, _ string) {
			_, _ = w.Write([]byte(`{"config":{"resources":[{"name":"burst-git","type":"git","source":{"uri":"https://github.com/org/burst.git"}}]}}`))
		}
		var checkStarted atomic.Int32
		releaseCheck := make(chan struct{})
		var releaseOnce sync.Once
		unblockCheck := func() {
			releaseOnce.Do(func() { close(releaseCheck) })
		}
		t.Cleanup(unblockCheck)
		atc.checkHandler = func(w http.ResponseWriter, _ *http.Request) {
			checkStarted.Add(1)
			<-releaseCheck
			w.WriteHeader(http.StatusOK)
		}
		rd := startDispatcher(t, bin, atc.server.URL)

		// Send a 24-goroutine concurrent burst on a cold index.
		body := []byte(`{"repository":{"full_name":"org/burst"}}`)
		sig := signPayload(e2eSecret, body)

		const burst = 24
		var wg sync.WaitGroup
		errs := make(chan error, burst)
		for i := range burst {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				req, err := http.NewRequest(http.MethodPost, "http://"+rd.listenAddr+"/webhook", bytes.NewReader(body))
				if err != nil {
					errs <- err
					return
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-GitHub-Event", "push")
				req.Header.Set("X-GitHub-Delivery", fmt.Sprintf("burst-%d", idx))
				req.Header.Set("X-Hub-Signature-256", sig)
				client := &http.Client{Timeout: 5 * time.Second}
				resp, err := client.Do(req)
				if err != nil {
					errs <- err
					return
				}
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusAccepted {
					errs <- fmt.Errorf("unexpected burst status %d, want 202", resp.StatusCode)
				}
			}(i)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatalf("concurrent burst error: %v", err)
		}

		// Wait until at least one check POST is blocked inside checkHandler, then send SIGTERM.
		deadline := time.Now().Add(3 * time.Second)
		for checkStarted.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(15 * time.Millisecond)
		}
		if checkStarted.Load() == 0 {
			unblockCheck()
			t.Fatal("expected in-flight check/webhook calls during burst")
		}

		// Send SIGTERM and wait for shutdown to begin (/readyz leaves 200 -> 503 or listener closes),
		// then verify across 250ms that the process stays alive draining in-flight fan-outs before unblockCheck().
		if err := rd.cmd.Process.Signal(syscall.SIGTERM); err != nil {
			unblockCheck()
			t.Fatalf("send SIGTERM: %v", err)
		}

		readyzClient := &http.Client{Timeout: time.Second}
		shutdownSeen := false
		sigDeadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(sigDeadline) {
			select {
			case <-rd.doneCh:
				unblockCheck()
				t.Fatalf("dispatcher exited prematurely (%v) while check/webhook was still blocked", rd.waitErr)
			default:
			}
			resp, err := readyzClient.Get("http://" + rd.listenAddr + "/readyz")
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusServiceUnavailable {
					shutdownSeen = true
					break
				}
				if resp.StatusCode != http.StatusOK {
					unblockCheck()
					t.Fatalf("/readyz during shutdown transition = %d, want 200 or 503", resp.StatusCode)
				}
			} else if errors.Is(err, syscall.ECONNREFUSED) {
				shutdownSeen = true
				break
			} else {
				unblockCheck()
				t.Fatalf("/readyz during shutdown returned unexpected error: %v", err)
			}
			time.Sleep(15 * time.Millisecond)
		}
		if !shutdownSeen {
			unblockCheck()
			t.Fatal("/readyz stayed 200 for 2s after SIGTERM")
		}

		// Hold check/webhook blocked for 250ms and assert the child process has NOT exited prematurely
		// and /readyz never returns 200 again.
		for range 5 {
			select {
			case <-rd.doneCh:
				unblockCheck()
				t.Fatalf("dispatcher exited prematurely (%v) while check/webhook was still blocked", rd.waitErr)
			default:
			}
			resp, err := readyzClient.Get("http://" + rd.listenAddr + "/readyz")
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusServiceUnavailable {
					unblockCheck()
					t.Fatalf("/readyz after shutdown started = %d, want 503", resp.StatusCode)
				}
			} else if !errors.Is(err, syscall.ECONNREFUSED) {
				unblockCheck()
				t.Fatalf("/readyz after shutdown started returned unexpected error: %v", err)
			}
			time.Sleep(50 * time.Millisecond)
		}

		// Final non-blocking check right before unblocking checkHandler.
		select {
		case <-rd.doneCh:
			unblockCheck()
			t.Fatalf("dispatcher exited prematurely (%v) before unblockCheck()", rd.waitErr)
		default:
		}

		unblockCheck()
		select {
		case <-rd.doneCh:
			if rd.waitErr != nil {
				t.Fatalf("dispatcher exited with non-zero status on SIGTERM drain: %v\nlogs:\n%s", rd.waitErr, rd.logs.String())
			}
		case <-time.After(10 * time.Second):
			t.Fatal("dispatcher did not exit cleanly within 10s after SIGTERM")
		}
		if calls := atc.webhookCalls(); len(calls) != burst {
			t.Fatalf("expected all %d check/webhook fan-outs to complete during SIGTERM drain, got %d", burst, len(calls))
		}
	})
}
