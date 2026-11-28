package main_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type reqZeroReader struct{}

func (reqZeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func reqRepoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	// wd is apps/webhook-dispatcher/cmd/dispatcher
	root := filepath.Clean(filepath.Join(wd, "..", "..", "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.work")); err != nil {
		t.Fatalf("unexpected repo root %q: %v", root, err)
	}
	return root
}

func reqModuleRoot(t *testing.T) string {
	t.Helper()
	return filepath.Join(reqRepoRoot(t), "apps", "webhook-dispatcher")
}

func reqRunCmd(t *testing.T, dir string, env []string, name string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	if env != nil {
		cmd.Env = env
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func reqNewHTTPClient(t *testing.T, timeout time.Duration) *http.Client {
	t.Helper()
	tr := &http.Transport{MaxIdleConnsPerHost: 32}
	c := &http.Client{Timeout: timeout, Transport: tr}
	t.Cleanup(tr.CloseIdleConnections)
	return c
}

func reqStartDispatcher(t *testing.T, bin, concourseURL string) *runningDispatcher {
	t.Helper()
	return reqStartDispatcherEnv(t, bin, map[string]string{
		"CONCOURSE_URL": concourseURL,
	})
}

func reqShouldRetryBindCollision(logs string, autoListen, autoMetrics bool) bool {
	if !strings.Contains(logs, "bind: address already in use") {
		return false
	}
	return (autoListen && strings.Contains(logs, "binding public listener")) ||
		(autoMetrics && strings.Contains(logs, "binding metrics listener"))
}

func reqStartDispatcherEnv(t *testing.T, bin string, envOverrides map[string]string) *runningDispatcher {
	t.Helper()
	pinnedListen := envOverrides["LISTEN_ADDR"]
	pinnedMetrics := envOverrides["METRICS_ADDR"]
	autoListen := pinnedListen == ""
	autoMetrics := pinnedMetrics == ""

	const maxBindAttempts = 5
	for attempt := range maxBindAttempts {
		listenAddr := pinnedListen
		if autoListen {
			listenAddr = reserveLoopbackAddr(t)
		}
		metricsAddr := pinnedMetrics
		if autoMetrics {
			metricsAddr = reserveLoopbackAddr(t)
		}
		envMap := map[string]string{
			"GITHUB_WEBHOOK_SECRET": e2eSecret,
			"CI_WEBHOOK_TOKEN":      e2eWebhookToken,
			"LOCAL_USERS":           e2eLocalUsers,
			"CONCOURSE_URL":         "http://127.0.0.1:1",
			"CONCOURSE_TEAM":        "main",
			"LISTEN_ADDR":           listenAddr,
			"METRICS_ADDR":          metricsAddr,
		}
		for k, v := range envOverrides {
			if v == "" {
				delete(envMap, k)
			} else {
				envMap[k] = v
			}
		}

		logs := &syncBuffer{}
		cmdCtx, cancelCmd := context.WithCancel(context.Background())
		cmd := exec.CommandContext(cmdCtx, bin)
		cmd.Env = cleanChildEnv(envMap)
		cmd.Stdout = logs
		cmd.Stderr = logs
		if err := cmd.Start(); err != nil {
			cancelCmd()
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

		client := &http.Client{
			Timeout:   time.Second,
			Transport: &http.Transport{DisableKeepAlives: true},
		}
		deadline := time.Now().Add(5 * time.Second)
		retryBind := false
		for time.Now().Before(deadline) {
			select {
			case <-rd.doneCh:
				logStr := logs.String()
				if attempt+1 < maxBindAttempts && reqShouldRetryBindCollision(logStr, autoListen, autoMetrics) {
					retryBind = true
				} else {
					cancelCmd()
					t.Fatalf("dispatcher exited prematurely (%v), logs:\n%s", rd.waitErr, logStr)
				}
			default:
			}
			if retryBind {
				break
			}
			resp, err := doGet(t.Context(), client, "http://"+listenAddr+"/readyz")
			if err == nil {
				body, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusOK && string(body) == "ok" {
					client.CloseIdleConnections()
					t.Cleanup(cancelCmd)
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
					// Ensure rd.postWebhook keep-alive connections in http.DefaultTransport close BEFORE SIGTERM.
					t.Cleanup(http.DefaultClient.CloseIdleConnections)
					return rd
				}
			}
			time.Sleep(25 * time.Millisecond)
		}
		client.CloseIdleConnections()
		if retryBind {
			cancelCmd()
			continue
		}
		cancelCmd()
		_ = cmd.Process.Kill()
		<-rd.doneCh
		t.Fatalf("dispatcher /readyz did not become ready within 5s, logs:\n%s", logs.String())
	}
	return nil
}

type reqTeamATC struct {
	server *httptest.Server
	mu     sync.Mutex
	calls  []webhookCall

	tokenHandler     func(w http.ResponseWriter, r *http.Request, path string)
	pipelinesHandler func(w http.ResponseWriter, r *http.Request)
	configHandler    func(w http.ResponseWriter, r *http.Request, pipeline string)
	checkHandler     func(w http.ResponseWriter, r *http.Request)
}

func reqNewTeamMockATC(t *testing.T, escapedTeam string) *reqTeamATC {
	t.Helper()
	m := &reqTeamATC{}
	teamPrefix := "/api/v1/teams/" + escapedTeam
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		escPath := r.URL.EscapedPath()
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
		case r.Method == http.MethodGet && escPath == teamPrefix+"/pipelines":
			m.mu.Lock()
			h := m.pipelinesHandler
			m.mu.Unlock()
			if h != nil {
				h(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[]`))
		case r.Method == http.MethodGet && strings.HasPrefix(escPath, teamPrefix+"/pipelines/") && strings.HasSuffix(escPath, "/config"):
			trimmed := strings.TrimPrefix(escPath, teamPrefix+"/pipelines/")
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
		case r.Method == http.MethodPost && strings.HasPrefix(escPath, teamPrefix+"/pipelines/") && strings.HasSuffix(escPath, "/check/webhook"):
			m.mu.Lock()
			m.calls = append(m.calls, webhookCall{
				Path:    escPath,
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

func (m *reqTeamATC) webhookCalls() []webhookCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]webhookCall, len(m.calls))
	copy(out, m.calls)
	return out
}

func (m *reqTeamATC) waitForWebhookCalls(t *testing.T, want int, timeout time.Duration) []webhookCall {
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

func reqWaitForLogCount(t *testing.T, buf *syncBuffer, substr string, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Count(buf.String(), substr) >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d occurrences of %q in logs (got %d):\n%s",
		want, substr, strings.Count(buf.String(), substr), buf.String())
}

func reqScrapeMetrics(t *testing.T, metricsAddr string) string {
	t.Helper()
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{}}
	defer client.CloseIdleConnections()
	resp, err := doGet(t.Context(), client, "http://"+metricsAddr+"/metrics")
	if err != nil {
		t.Fatalf("GET /metrics failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /metrics failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics = %d, want 200", resp.StatusCode)
	}
	return string(body)
}

func reqWriteSlowLorisConn(ctx context.Context, listenAddr, delivery string, writeBytes, declaredLen int, chunked bool) (net.Conn, error) {
	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	bogusSig := "sha256=" + strings.Repeat("0", 64)
	var hdr strings.Builder
	hdr.WriteString("POST /webhook HTTP/1.1\r\n")
	hdr.WriteString("Host: " + listenAddr + "\r\n")
	hdr.WriteString("Connection: close\r\n")
	hdr.WriteString("Content-Type: application/json\r\n")
	hdr.WriteString("X-GitHub-Event: push\r\n")
	hdr.WriteString("X-GitHub-Delivery: " + delivery + "\r\n")
	hdr.WriteString("X-Hub-Signature-256: " + bogusSig + "\r\n")
	if chunked {
		hdr.WriteString("Transfer-Encoding: chunked\r\n\r\n")
	} else {
		fmt.Fprintf(&hdr, "Content-Length: %d\r\n\r\n", declaredLen)
	}
	if _, err := io.WriteString(conn, hdr.String()); err != nil {
		return conn, err
	}
	if writeBytes > 0 {
		payload := bytes.Repeat([]byte("a"), writeBytes)
		payload[0] = '{'
		if chunked {
			if _, err := fmt.Fprintf(conn, "%x\r\n", writeBytes); err != nil {
				return conn, err
			}
			if _, err := conn.Write(payload); err != nil {
				return conn, err
			}
			if _, err := io.WriteString(conn, "\r\n"); err != nil {
				return conn, err
			}
		} else if _, err := conn.Write(payload); err != nil {
			return conn, err
		}
	}
	return conn, nil
}

func reqConnEvicted(c net.Conn) bool {
	if c == nil {
		return true
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Millisecond))
	var buf [1]byte
	n, err := c.Read(buf[:])
	_ = c.SetReadDeadline(time.Time{})
	if n > 0 {
		// Server already wrote an HTTP response (e.g. 503 Service Unavailable).
		return true
	}
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return false
		}
		return true
	}
	return false
}

// reqOpenSlowLorisFlood opens slow-loris connections AFTER the dispatcher is started so LIFO
// t.Cleanup closes client sockets BEFORE startDispatcher's SIGTERM cleanup runs.
func reqOpenSlowLorisFlood(t *testing.T, listenAddr string, largeCount, largeWriteBytes, declaredLen, tailCount int, chunked bool) func() {
	t.Helper()
	total := largeCount + tailCount
	var mu sync.Mutex
	conns := make([]net.Conn, total)
	var extraConns []net.Conn
	var closeOnce sync.Once
	closeAll := func() {
		closeOnce.Do(func() {
			mu.Lock()
			list := make([]net.Conn, 0, len(conns)+len(extraConns))
			list = append(list, conns...)
			list = append(list, extraConns...)
			conns = nil
			extraConns = nil
			mu.Unlock()
			for _, c := range list {
				if c != nil {
					_ = c.Close()
				}
			}
		})
	}
	t.Cleanup(closeAll)

	var openErrCount atomic.Int32
	if largeCount > 0 {
		var wg sync.WaitGroup
		for i := range largeCount {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				c, err := reqWriteSlowLorisConn(t.Context(), listenAddr, fmt.Sprintf("slow-big-%d", idx), largeWriteBytes, declaredLen, chunked)
				if err != nil {
					openErrCount.Add(1)
					if c != nil {
						_ = c.Close()
					}
					return
				}
				mu.Lock()
				if conns != nil {
					conns[idx] = c
					c = nil
				}
				mu.Unlock()
				if c != nil {
					_ = c.Close()
				}
			}(i)
		}
		wg.Wait()
	}
	if tailCount > 0 {
		const maxTailDialWorkers = 32
		const maxTailDialAttempts = 3
		workCh := make(chan int, tailCount)
		for i := range tailCount {
			workCh <- i
		}
		close(workCh)

		workers := min(tailCount, maxTailDialWorkers)
		var wg sync.WaitGroup
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for idx := range workCh {
					var c net.Conn
					var err error
					for attempt := range maxTailDialAttempts {
						c, err = reqWriteSlowLorisConn(t.Context(), listenAddr, fmt.Sprintf("slow-tail-%d", idx), 1, declaredLen, chunked)
						if err == nil {
							break
						}
						if c != nil {
							_ = c.Close()
							c = nil
						}
						if attempt+1 < maxTailDialAttempts {
							time.Sleep(15 * time.Millisecond)
						}
					}
					if err != nil {
						openErrCount.Add(1)
						if c != nil {
							_ = c.Close()
						}
						continue
					}
					mu.Lock()
					if conns != nil {
						conns[largeCount+idx] = c
						c = nil
					}
					mu.Unlock()
					if c != nil {
						_ = c.Close()
					}
				}
			}()
		}
		wg.Wait()
		if int(openErrCount.Load()) >= tailCount {
			t.Fatalf("all %d tail slow-loris connections failed to open", tailCount)
		}
	}

	// Let initial byte-cap connections drain kernel TCP buffers and finish 1 MiB -> 2 MiB growth
	// before sat-poll reserves initCap (16 KiB) against preAuthBytes.
	if tailCount == 0 && largeCount > 0 {
		time.Sleep(250 * time.Millisecond)
	}

	// Poll with a non-blocking complete bogus-sig request until pre-auth cap saturates (503).
	// While unsaturated it returns 401 immediately and releases its budget; once saturated it returns 503.
	client := &http.Client{
		Timeout:   time.Second,
		Transport: &http.Transport{DisableKeepAlives: true},
	}
	defer client.CloseIdleConnections()
	bogusSig := "sha256=" + strings.Repeat("0", 64)
	pollOnce := func() (int, error) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+listenAddr+"/webhook", strings.NewReader(`{}`))
		if err != nil {
			return 0, err
		}
		req.Close = true
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-GitHub-Event", "push")
		req.Header.Set("X-GitHub-Delivery", "sat-poll")
		req.Header.Set("X-Hub-Signature-256", bogusSig)
		resp, derr := client.Do(req)
		if derr != nil {
			return 0, derr
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, nil
	}

	pollStart := time.Now()
	deadline := pollStart.Add(8 * time.Second)
	const minTopUpSize = 1
	topUpSize := min(largeWriteBytes, 1<<20)
	if topUpSize < minTopUpSize {
		topUpSize = minTopUpSize
	}
	stepDownTopUp := func(sz int) int {
		if sz > 16<<10 {
			return sz / 2
		}
		return minTopUpSize
	}
	consecutive503 := 0
	succeededAtSize := 0
	var lastPollStatus int
	var lastPollErr error
	var lastAliveLarge, lastAliveTail, lastExtraCount, evictedTotal int
	largeCursor := 0
	extraCursor := 0
	rounds := 0
	for round := 0; time.Now().Before(deadline); round++ {
		rounds = round + 1
		all503 := true
		if consecutive503 == 0 {
			st, derr := pollOnce()
			lastPollStatus, lastPollErr = st, derr
			if derr != nil || st != http.StatusServiceUnavailable {
				all503 = false
			}
		} else {
			// Fire concurrent confirming polls to avoid repeatedly hitting a single 64 KiB bodyPool slab.
			const confirmPolls = 3
			var pwg sync.WaitGroup
			statuses := make([]int, confirmPolls)
			errs := make([]error, confirmPolls)
			for j := range confirmPolls {
				pwg.Add(1)
				go func(idx int) {
					defer pwg.Done()
					statuses[idx], errs[idx] = pollOnce()
				}(j)
			}
			pwg.Wait()
			for j := range confirmPolls {
				lastPollStatus, lastPollErr = statuses[j], errs[j]
				if errs[j] != nil || statuses[j] != http.StatusServiceUnavailable {
					all503 = false
					break
				}
			}
		}
		if all503 {
			consecutive503++
			if consecutive503 >= 2 && (tailCount > 0 || largeCount == 0 || topUpSize == minTopUpSize) {
				return closeAll
			}
			if tailCount == 0 && largeCount > 0 && topUpSize > minTopUpSize {
				topUpSize = minTopUpSize
				succeededAtSize = 0
			}
		} else {
			consecutive503 = 0
		}

		if tailCount == 0 && largeCount > 0 {
			// Prune evicted connections (503 / EOF) with a bounded per-round probe budget
			// so rounds stay < 50ms even when dozens of slow-loris connections are alive.
			mu.Lock()
			const maxProbesPerRound = 8
			probes := 0
			if round == 0 {
				for i := range largeCount {
					if conns != nil && conns[i] != nil && reqConnEvicted(conns[i]) {
						_ = conns[i].Close()
						conns[i] = nil
						evictedTotal++
					}
				}
			} else if conns != nil && largeCount > 0 {
				for checked := 0; checked < largeCount && probes < maxProbesPerRound/2; checked++ {
					idx := (largeCursor + checked) % largeCount
					if conns[idx] != nil {
						probes++
						if reqConnEvicted(conns[idx]) {
							_ = conns[idx].Close()
							conns[idx] = nil
							evictedTotal++
						}
					}
				}
				largeCursor = (largeCursor + maxProbesPerRound/2) % largeCount
			}
			if len(extraConns) > 0 {
				nExtra := len(extraConns)
				extraBudget := maxProbesPerRound - probes
				for checked := 0; checked < nExtra && checked < extraBudget; checked++ {
					idx := (extraCursor + checked) % nExtra
					ec := extraConns[idx]
					if ec != nil && reqConnEvicted(ec) {
						_ = ec.Close()
						extraConns[idx] = nil
						evictedTotal++
					}
				}
				extraCursor = (extraCursor + extraBudget) % nExtra
				kept := extraConns[:0]
				for _, ec := range extraConns {
					if ec != nil {
						kept = append(kept, ec)
					}
				}
				extraConns = kept
				if len(extraConns) > 0 {
					extraCursor %= len(extraConns)
				} else {
					extraCursor = 0
				}
			}
			aliveLarge := 0
			for i := range largeCount {
				if conns != nil && conns[i] != nil {
					aliveLarge++
				}
			}
			lastAliveLarge = aliveLarge
			lastExtraCount = len(extraConns)
			aliveTotal := aliveLarge + lastExtraCount
			mu.Unlock()

			// If all initial largeCount connections are still open and draining, give them up to
			// 500ms of polling before adding top-up connections; if any was evicted (or >500ms elapsed),
			// top up monotonically with binary backoff down to 1-byte (16 KiB initCap) slow-loris conns.
			if aliveLarge == largeCount && lastExtraCount == 0 && consecutive503 == 0 && time.Since(pollStart) < 500*time.Millisecond {
				time.Sleep(40 * time.Millisecond)
				continue
			}

			if aliveTotal < 220 && topUpSize >= minTopUpSize {
				topUpDeclared := declaredLen
				if !chunked && topUpDeclared <= topUpSize {
					topUpDeclared = 4 << 20
				}
				c, werr := reqWriteSlowLorisConn(t.Context(), listenAddr, fmt.Sprintf("slow-topup-%d", round), topUpSize, topUpDeclared, chunked)
				if werr != nil {
					if c != nil {
						_ = c.Close()
					}
					succeededAtSize = 0
					topUpSize = stepDownTopUp(topUpSize)
					continue
				}
				// Wait briefly for server to ingest topUpSize, then check whether it was evicted with 503.
				time.Sleep(40 * time.Millisecond)
				if reqConnEvicted(c) {
					_ = c.Close()
					evictedTotal++
					succeededAtSize = 0
					topUpSize = stepDownTopUp(topUpSize)
					continue
				}
				mu.Lock()
				if conns != nil {
					extraConns = append(extraConns, c)
					c = nil
				}
				mu.Unlock()
				if c != nil {
					_ = c.Close()
				}
				consecutive503 = 0
				succeededAtSize++
				if succeededAtSize >= 4 && topUpSize >= 16<<10 && topUpSize < min(largeWriteBytes, 512<<10) {
					topUpSize *= 2
					succeededAtSize = 0
				}
				continue
			}
		} else if tailCount > 0 && !all503 {
			// Prune evicted/closed tail sockets and top up back to tailCount whenever saturation has not held.
			type tailProbeTarget struct {
				isExtra bool
				idx     int
				conn    net.Conn
			}
			mu.Lock()
			var targets []tailProbeTarget
			if conns != nil {
				for i := range tailCount {
					if c := conns[largeCount+i]; c != nil {
						targets = append(targets, tailProbeTarget{idx: i, conn: c})
					}
				}
			}
			for i, ec := range extraConns {
				if ec != nil {
					targets = append(targets, tailProbeTarget{isExtra: true, idx: i, conn: ec})
				}
			}
			mu.Unlock()

			if len(targets) > 0 {
				evicted := make([]bool, len(targets))
				probeCh := make(chan int, len(targets))
				for k := range targets {
					probeCh <- k
				}
				close(probeCh)

				const maxTailProbeWorkers = 32
				probeWorkers := min(len(targets), maxTailProbeWorkers)
				var pwg sync.WaitGroup
				for range probeWorkers {
					pwg.Add(1)
					go func() {
						defer pwg.Done()
						for k := range probeCh {
							evicted[k] = reqConnEvicted(targets[k].conn)
						}
					}()
				}
				pwg.Wait()

				mu.Lock()
				for k, tgt := range targets {
					if !evicted[k] {
						continue
					}
					if !tgt.isExtra {
						if conns != nil && conns[largeCount+tgt.idx] == tgt.conn {
							_ = tgt.conn.Close()
							conns[largeCount+tgt.idx] = nil
							evictedTotal++
						}
					} else if extraConns != nil && tgt.idx < len(extraConns) && extraConns[tgt.idx] == tgt.conn {
						_ = tgt.conn.Close()
						extraConns[tgt.idx] = nil
						evictedTotal++
					}
				}
				if len(extraConns) > 0 {
					kept := extraConns[:0]
					for _, ec := range extraConns {
						if ec != nil {
							kept = append(kept, ec)
						}
					}
					extraConns = kept
				}
				mu.Unlock()
			}

			mu.Lock()
			aliveTail := 0
			if conns != nil {
				for i := range tailCount {
					if conns[largeCount+i] != nil {
						aliveTail++
					}
				}
			}
			aliveTail += len(extraConns)
			lastAliveTail = aliveTail
			lastExtraCount = len(extraConns)
			mu.Unlock()

			if needed := tailCount - aliveTail; needed > 0 {
				topUpDeclared := declaredLen
				if !chunked && topUpDeclared <= 1 {
					topUpDeclared = 1024
				}
				batch := min(needed, 32)
				newConns := make([]net.Conn, batch)
				var twg sync.WaitGroup
				for i := range batch {
					twg.Add(1)
					go func(slot int) {
						defer twg.Done()
						c, werr := reqWriteSlowLorisConn(t.Context(), listenAddr, fmt.Sprintf("slow-tail-topup-%d-%d", round, slot), 1, topUpDeclared, chunked)
						if werr != nil {
							if c != nil {
								_ = c.Close()
							}
							return
						}
						newConns[slot] = c
					}(i)
				}
				twg.Wait()

				mu.Lock()
				if conns != nil {
					for _, c := range newConns {
						if c == nil {
							continue
						}
						placed := false
						for i := range tailCount {
							if conns[largeCount+i] == nil {
								conns[largeCount+i] = c
								placed = true
								break
							}
						}
						if !placed {
							extraConns = append(extraConns, c)
						}
					}
					aliveTail = 0
					for i := range tailCount {
						if conns[largeCount+i] != nil {
							aliveTail++
						}
					}
					aliveTail += len(extraConns)
					lastAliveTail = aliveTail
					lastExtraCount = len(extraConns)
					mu.Unlock()
				} else {
					mu.Unlock()
					for _, c := range newConns {
						if c != nil {
							_ = c.Close()
						}
					}
				}
				time.Sleep(25 * time.Millisecond)
				continue
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("slow-loris flood (%d large, %d tail) did not saturate pre-auth cap within 8s (rounds=%d aliveLarge=%d aliveTail=%d extra=%d evicted=%d topUpSize=%d lastStatus=%d lastErr=%v)",
		largeCount, tailCount, rounds, lastAliveLarge, lastAliveTail, lastExtraCount, evictedTotal, topUpSize, lastPollStatus, lastPollErr)
	return closeAll
}

func reqProbeSlowBody503(t *testing.T, listenAddr, event string, chunked bool) (int, string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write([]byte("{"))
		<-ctx.Done()
		_ = pw.Close()
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+listenAddr+"/webhook", pr)
	if err != nil {
		return 0, "", err
	}
	req.Close = true
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", event)
	req.Header.Set("X-GitHub-Delivery", "probe-"+event)
	req.Header.Set("X-Hub-Signature-256", "sha256="+strings.Repeat("0", 64))
	if !chunked {
		req.ContentLength = 512 << 10
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{}}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), nil
}

func reqWaitRecovered202(t *testing.T, rd *runningDispatcher, event, delivery string, body []byte) {
	t.Helper()
	sig := signPayload(e2eSecret, body)
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		code, resp := rd.postWebhook(t, event, delivery, sig, body)
		if code == http.StatusAccepted {
			return
		}
		if code != http.StatusServiceUnavailable {
			t.Fatalf("unexpected recovery status = (%d, %s), want 202 or transient 503", code, resp)
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("dispatcher did not recover from pre-auth flood within 6s")
}

func TestE2ERequirementsDispatcher(t *testing.T) {
	bin := buildDispatcherBinary(t)

	// ---------------- Tier 1: Feature Coverage ----------------
	t.Run("Tier1_F1_SplitListenerIsolation", func(t *testing.T) {
		atc := newMockATC(t)
		rd := reqStartDispatcher(t, bin, atc.server.URL)
		client := reqNewHTTPClient(t, 3*time.Second)

		for _, route := range []string{"/healthz", "/readyz"} {
			resp, err := doGet(t.Context(), client, "http://"+rd.listenAddr+route)
			if err != nil {
				t.Fatalf("GET public %s: %v", route, err)
			}
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK || string(b) != "ok" {
				t.Fatalf("public %s = (%d, %q), want (200, \"ok\")", route, resp.StatusCode, string(b))
			}
		}
		for _, route := range []string{"/metrics", "/debug/pprof/"} {
			resp, err := doGet(t.Context(), client, "http://"+rd.listenAddr+route)
			if err != nil {
				t.Fatalf("GET public %s: %v", route, err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("public %s = %d, want 404", route, resp.StatusCode)
			}
		}
		for _, route := range []string{"/metrics", "/debug/pprof/"} {
			resp, err := doGet(t.Context(), client, "http://"+rd.metricsAddr+route)
			if err != nil {
				t.Fatalf("GET internal %s: %v", route, err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("internal %s = %d, want 200", route, resp.StatusCode)
			}
		}
		for _, route := range []string{"/healthz", "/readyz"} {
			resp, err := doGet(t.Context(), client, "http://"+rd.metricsAddr+route)
			if err != nil {
				t.Fatalf("GET internal %s: %v", route, err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("internal %s = %d, want 404", route, resp.StatusCode)
			}
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+rd.metricsAddr+"/webhook", strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST internal /webhook: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("internal POST /webhook = %d, want 404", resp.StatusCode)
		}
	})

	t.Run("Tier1_F1_PrometheusMetricFamilies", func(t *testing.T) {
		atc := newMockATC(t)
		var failPipes atomic.Bool
		atc.pipelinesHandler = func(w http.ResponseWriter, _ *http.Request) {
			if failPipes.Load() {
				http.Error(w, "boom", http.StatusInternalServerError)
				return
			}
			_, _ = w.Write([]byte(`[{"name":"p1","archived":false}]`))
		}
		atc.configHandler = func(w http.ResponseWriter, _ *http.Request, _ string) {
			_, _ = w.Write([]byte(`{"config":{"resources":[{"name":"r1","type":"git","source":{"uri":"https://github.com/org/m.git"}}]}}`))
		}
		rd := reqStartDispatcher(t, bin, atc.server.URL)

		// 1. Matched push.
		pushBody := []byte(`{"repository":{"full_name":"org/m"}}`)
		code, _ := rd.postWebhook(t, "push", "m-push", signPayload(e2eSecret, pushBody), pushBody)
		if code != http.StatusAccepted {
			t.Fatalf("push = %d, want 202", code)
		}
		atc.waitForWebhookCalls(t, 1, 3*time.Second)
		waitForLogContains(t, rd.logs, "webhook fan-out complete", 3*time.Second)

		// 2. Ignored ping.
		pingBody := []byte(`{"zen":"ok"}`)
		code, _ = rd.postWebhook(t, "ping", "m-ping", signPayload(e2eSecret, pingBody), pingBody)
		if code != http.StatusAccepted {
			t.Fatalf("ping = %d, want 202", code)
		}

		// 3. Cold-start ATC 500 error on separate instance so index_fetch_errors_total > 0.
		failPipes.Store(true)
		rdErr := reqStartDispatcher(t, bin, atc.server.URL)
		code, _ = rdErr.postWebhook(t, "push", "m-err", signPayload(e2eSecret, pushBody), pushBody)
		if code != http.StatusBadGateway {
			t.Fatalf("push with ATC 500 = %d, want 502", code)
		}

		m1 := reqScrapeMetrics(t, rd.metricsAddr)
		for _, fam := range []string{
			"webhook_dispatcher_deliveries_total",
			"webhook_dispatcher_fanout_total",
			"webhook_dispatcher_fanout_duration_seconds",
			"webhook_dispatcher_concourse_index_last_refresh_timestamp_seconds",
			"webhook_dispatcher_concourse_index_fetch_errors_total",
		} {
			if !strings.Contains(m1, fam) {
				t.Fatalf("/metrics missing family %q", fam)
			}
		}
		if !strings.Contains(m1, `webhook_dispatcher_deliveries_total{event="push",status="dispatched"}`) {
			t.Fatalf("/metrics missing dispatched push counter:\n%s", m1)
		}
		if !strings.Contains(m1, `webhook_dispatcher_deliveries_total{event="other",status="ignored"}`) {
			t.Fatalf("/metrics missing ignored other counter:\n%s", m1)
		}
		if !strings.Contains(m1, `webhook_dispatcher_fanout_total{result="ok"}`) {
			t.Fatalf("/metrics missing fanout result=ok:\n%s", m1)
		}

		m2 := reqScrapeMetrics(t, rdErr.metricsAddr)
		if !strings.Contains(m2, `webhook_dispatcher_deliveries_total{event="push",status="index_unavailable"}`) {
			t.Fatalf("/metrics missing index_unavailable counter:\n%s", m2)
		}
	})

	t.Run("Tier1_F1_DepguardModuleBoundaries", func(t *testing.T) {
		modRoot := reqModuleRoot(t)
		env := append(os.Environ(), "GOWORK=off")
		depsOut, err := reqRunCmd(t, modRoot, env, "go", "list", "-deps", "./cmd/...")
		if err != nil {
			t.Fatalf("go list -deps failed: %v\n%s", err, depsOut)
		}
		for _, wantPkg := range []string{
			"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx",
			"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/httpx",
			"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/logx",
		} {
			if !strings.Contains(depsOut, wantPkg) {
				t.Fatalf("expected dependency %q in go list -deps ./cmd/...", wantPkg)
			}
		}
		if strings.Contains(depsOut, "libs/jinja") {
			t.Fatalf("depguard whd-no-jinja violated: found libs/jinja in deps")
		}

		importsOut, err := reqRunCmd(t, modRoot, env, "go", "list", "-f", `{{join .Imports "\n"}}`, "./cmd/dispatcher")
		if err != nil {
			t.Fatalf("go list imports failed: %v\n%s", err, importsOut)
		}
		for _, line := range strings.Split(strings.TrimSpace(importsOut), "\n") {
			if strings.TrimSpace(line) == "net/http/pprof" {
				t.Fatal("cmd/dispatcher directly imports net/http/pprof (must use hostkit/httpx/pprofx)")
			}
		}
	})

	t.Run("Tier1_F1_EnvDocCatalogCompleteness", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(reqModuleRoot(t), "docs", "env.md"))
		if err != nil {
			t.Fatalf("read docs/env.md: %v", err)
		}
		doc := string(raw)
		for _, tok := range []string{
			"GITHUB_WEBHOOK_SECRET",
			"CI_WEBHOOK_TOKEN",
			"LOCAL_USERS",
			"CONCOURSE_URL",
			"CONCOURSE_TEAM",
			"LISTEN_ADDR",
			"METRICS_ADDR",
			"-version",
		} {
			re := regexp.MustCompile(`(?m)(^|[^A-Za-z0-9_-])` + regexp.QuoteMeta(tok) + `([^A-Za-z0-9_-]|$)`)
			if !re.MatchString(doc) {
				t.Fatalf("docs/env.md missing token %q", tok)
			}
		}

		atc := reqNewTeamMockATC(t, "env-team")
		rd := reqStartDispatcherEnv(t, bin, map[string]string{
			"CONCOURSE_URL":  atc.server.URL,
			"CONCOURSE_TEAM": "env-team",
		})
		body := []byte(`{"zen":"ok"}`)
		code, _ := rd.postWebhook(t, "ping", "env-check", signPayload(e2eSecret, body), body)
		if code != http.StatusAccepted {
			t.Fatalf("ping with all optional env vars = %d, want 202", code)
		}
	})

	t.Run("Tier1_F1_SameOriginRedirectAndSecretRedaction", func(t *testing.T) {
		var foreignHits atomic.Int32
		foreignATC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			foreignHits.Add(1)
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(foreignATC.Close)

		atc := newMockATC(t)
		atc.pipelinesHandler = func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`[{"name":"p1","archived":false}]`))
		}
		atc.configHandler = func(w http.ResponseWriter, _ *http.Request, _ string) {
			_, _ = w.Write([]byte(`{"config":{"resources":[{"name":"r1","type":"git","source":{"uri":"https://github.com/org/redir.git"}}]}}`))
		}
		atc.checkHandler = func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, foreignATC.URL+"/steal", http.StatusFound)
		}
		rd := reqStartDispatcher(t, bin, atc.server.URL)

		payload := []byte(`{"repository":{"full_name":"org/redir"}}`)
		code, _ := rd.postWebhook(t, "push", "d-redir", signPayload(e2eSecret, payload), payload)
		if code != http.StatusAccepted {
			t.Fatalf("push = %d, want 202", code)
		}
		atc.waitForWebhookCalls(t, 1, 3*time.Second)
		waitForLogContains(t, rd.logs, "check webhook", 3*time.Second)
		waitForLogContains(t, rd.logs, "webhook fan-out complete", 3*time.Second)
		if foreignHits.Load() != 0 {
			t.Fatalf("cross-origin redirect leaked request to foreignATC (%d hits)", foreignHits.Load())
		}

		logs := rd.logs.String()
		metrics := reqScrapeMetrics(t, rd.metricsAddr)
		for _, secret := range []string{e2eSecret, e2eWebhookToken, "ci-pass-123"} {
			if strings.Contains(logs, secret) || strings.Contains(metrics, secret) {
				t.Fatalf("secret %q leaked in logs or metrics", secret)
			}
		}
	})

	t.Run("Tier1_F5_PreAuthByteCapFloodTriggersFast503", func(t *testing.T) {
		atc := newMockATC(t)
		rd := reqStartDispatcher(t, bin, atc.server.URL)

		// 16 * 2 MiB = 32 MiB exact (maxPreAuthBytes) with zero delta contention.
		reqOpenSlowLorisFlood(t, rd.listenAddr, 16, 2<<20, 4<<20, 0, false)

		code, body, err := reqProbeSlowBody503(t, rd.listenAddr, "push", false)
		if err != nil {
			t.Fatalf("push probe under pre-auth saturation failed: %v", err)
		}
		if code != http.StatusServiceUnavailable {
			t.Fatalf("push probe under pre-auth saturation = (%d, %q), want 503", code, body)
		}
		metrics := reqScrapeMetrics(t, rd.metricsAddr)
		if !strings.Contains(metrics, `webhook_dispatcher_deliveries_total{event="push",status="overloaded"}`) {
			t.Fatalf("expected overloaded push metric after pre-auth saturation:\n%s", metrics)
		}
	})

	t.Run("Tier1_F5_UnhandledStreamingPingUnstarvedDuringFlood", func(t *testing.T) {
		atc := newMockATC(t)
		rd := reqStartDispatcher(t, bin, atc.server.URL)
		reqOpenSlowLorisFlood(t, rd.listenAddr, 16, 2<<20, 4<<20, 0, false)

		pingBody := []byte(`{"zen":"streaming"}`)
		sig := signPayload(e2eSecret, pingBody)
		for i := range 4 {
			code, resp := rd.postWebhook(t, "ping", fmt.Sprintf("ping-%d", i), sig, pingBody)
			if code != http.StatusAccepted || !strings.Contains(resp, `"resources_matched":0`) {
				t.Fatalf("ping %d during slow-loris flood = (%d, %s), want (202, resources_matched:0)", i, code, resp)
			}
		}
	})

	t.Run("Tier1_F5_PreAuthCapRecoversAfterSlowConnsClose", func(t *testing.T) {
		atc := newMockATC(t)
		atc.pipelinesHandler = func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`[{"name":"p1","archived":false}]`))
		}
		atc.configHandler = func(w http.ResponseWriter, _ *http.Request, _ string) {
			_, _ = w.Write([]byte(`{"config":{"resources":[{"name":"r1","type":"git","source":{"uri":"https://github.com/org/rec.git"}}]}}`))
		}
		rd := reqStartDispatcher(t, bin, atc.server.URL)

		closeAll := reqOpenSlowLorisFlood(t, rd.listenAddr, 16, 2<<20, 4<<20, 0, false)
		code, _, err := reqProbeSlowBody503(t, rd.listenAddr, "push", false)
		if err != nil || code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 during flood, got code=%d err=%v", code, err)
		}

		closeAll()
		payload := []byte(`{"repository":{"full_name":"org/rec"}}`)
		reqWaitRecovered202(t, rd, "push", "recover-after-close", payload)
		atc.waitForWebhookCalls(t, 1, 3*time.Second)
		waitForLogContains(t, rd.logs, "webhook fan-out complete", 3*time.Second)
	})

	t.Run("Tier1_F5_AllFourHandledEventsRespectPreAuthCap", func(t *testing.T) {
		atc := newMockATC(t)
		rd := reqStartDispatcher(t, bin, atc.server.URL)
		reqOpenSlowLorisFlood(t, rd.listenAddr, 16, 2<<20, 4<<20, 0, false)

		for _, ev := range []string{"push", "pull_request", "release", "create"} {
			code, body, err := reqProbeSlowBody503(t, rd.listenAddr, ev, false)
			if err != nil {
				t.Fatalf("probe %q failed: %v", ev, err)
			}
			if code != http.StatusServiceUnavailable {
				t.Fatalf("probe %q under pre-auth cap = (%d, %q), want 503", ev, code, body)
			}
		}
	})

	t.Run("Tier1_F5_ValidHandledDeliveriesSucceedUnderNormalLoad", func(t *testing.T) {
		atc := newMockATC(t)
		atc.pipelinesHandler = func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`[{"name":"p1","archived":false}]`))
		}
		atc.configHandler = func(w http.ResponseWriter, _ *http.Request, _ string) {
			_, _ = w.Write([]byte(`{"config":{"resources":[
				{"name":"g1","type":"git","source":{"uri":"https://github.com/org/normal.git"}},
				{"name":"pr1","type":"github-pr","source":{"repository":"org/normal"}}
			]}}`))
		}
		rd := reqStartDispatcher(t, bin, atc.server.URL)

		events := []struct {
			event string
			body  []byte
		}{
			{"push", []byte(`{"repository":{"full_name":"org/normal"}}`)},
			{"pull_request", []byte(`{"action":"opened","repository":{"full_name":"org/normal"}}`)},
			{"release", []byte(`{"action":"published","repository":{"full_name":"org/normal"}}`)},
			{"create", []byte(`{"ref_type":"tag","repository":{"full_name":"org/normal"}}`)},
		}

		client := reqNewHTTPClient(t, 5*time.Second)
		for round := range 2 {
			var wg sync.WaitGroup
			errs := make(chan error, 8)
			for i := range 8 {
				wg.Add(1)
				go func(idx int) {
					defer wg.Done()
					ev := events[idx%len(events)]
					req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+rd.listenAddr+"/webhook", bytes.NewReader(ev.body))
					if err != nil {
						errs <- err
						return
					}
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("X-GitHub-Event", ev.event)
					req.Header.Set("X-GitHub-Delivery", fmt.Sprintf("norm-%d-%d", round, idx))
					req.Header.Set("X-Hub-Signature-256", signPayload(e2eSecret, ev.body))
					resp, err := client.Do(req)
					if err != nil {
						errs <- err
						return
					}
					_, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
					if resp.StatusCode != http.StatusAccepted {
						errs <- fmt.Errorf("round %d idx %d status = %d, want 202", round, idx, resp.StatusCode)
					}
				}(i)
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Fatal(err)
			}
		}
		client.CloseIdleConnections()
		atc.waitForWebhookCalls(t, 16, 3*time.Second)
		reqWaitForLogCount(t, rd.logs, "webhook fan-out complete", 16, 3*time.Second)
	})

	t.Run("Tier1_F20_DockerfileAlpineBuilderAndDistroless", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(reqModuleRoot(t), "Dockerfile"))
		if err != nil {
			t.Fatalf("read Dockerfile: %v", err)
		}
		df := string(raw)
		for _, want := range []string{
			"FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine AS build",
			"ENV GOWORK=off",
			"COPY libs/hostkit/go.*",
			"ARG TARGETOS=linux",
			"ARG TARGETARCH",
			"CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath",
			`-ldflags="-s -w -X main.version=${VERSION}"`,
			"FROM gcr.io/distroless/static:nonroot",
			"USER 65532:65532",
			`ENTRYPOINT ["/webhook-dispatcher"]`,
		} {
			if !strings.Contains(df, want) {
				t.Fatalf("Dockerfile missing required directive %q", want)
			}
		}
		idxManifest := strings.Index(df, "COPY libs/hostkit/go.*")
		idxSrc := strings.Index(df, "COPY libs/hostkit/ /src/libs/hostkit/")
		if idxManifest < 0 || idxSrc < 0 || idxManifest >= idxSrc {
			t.Fatalf("Dockerfile must copy libs/hostkit/go.* before full source (manifest=%d src=%d)", idxManifest, idxSrc)
		}
	})

	t.Run("Tier1_F20_HadolintZeroIssues", func(t *testing.T) {
		out, err := reqRunCmd(t, reqRepoRoot(t), nil, "hadolint", "apps/webhook-dispatcher/Dockerfile")
		if err != nil || strings.TrimSpace(out) != "" {
			t.Fatalf("hadolint failed (err=%v):\n%s", err, out)
		}
	})

	t.Run("Tier1_F20_StaticTrimpathVersionLdflagBuild", func(t *testing.T) {
		modRoot := reqModuleRoot(t)
		staticBin := filepath.Join(t.TempDir(), "webhook-dispatcher-static")
		env := append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0")
		out, err := reqRunCmd(t, modRoot, env, "go", "build", "-trimpath",
			"-ldflags=-s -w -X main.version=v9.9.9-e2e", "-o", staticBin, "./cmd/dispatcher")
		if err != nil {
			t.Fatalf("static go build failed: %v\n%s", err, out)
		}
		vOut, err := reqRunCmd(t, modRoot, cleanChildEnv(nil), staticBin, "-version")
		if err != nil || vOut != "webhook-dispatcher v9.9.9-e2e\n" {
			t.Fatalf("-version = (%q, %v), want (%q, nil)", vOut, err, "webhook-dispatcher v9.9.9-e2e\n")
		}
	})

	t.Run("Tier1_F20_CIWorkflowOptimizedAndDepSync", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(reqRepoRoot(t), ".github", "workflows", "ci.yml"))
		if err != nil {
			t.Fatalf("read ci.yml: %v", err)
		}
		ci := string(raw)

		checksStart := strings.Index(ci, "  checks:\n")
		lintMainStart := strings.Index(ci, "  lint-main:\n")
		if checksStart < 0 || lintMainStart <= checksStart {
			t.Fatalf("unexpected ci.yml job layout (checks=%d, lint-main=%d)", checksStart, lintMainStart)
		}
		checksBlock := ci[checksStart:lintMainStart]
		if strings.Contains(checksBlock, "needs: docker-detect") {
			t.Fatal("ci.yml checks job still depends on docker-detect (F20 requires dropping needs: docker-detect)")
		}
		if strings.Contains(ci, "${{ github.run_id }}") {
			t.Fatal("ci.yml still uses github.run_id in cache keys (F20 requires removing github.run_id cache key churn)")
		}
		if !strings.Contains(ci, "govulncheck") {
			t.Fatal("ci.yml missing govulncheck step (F20)")
		}
		for _, tok := range []string{
			`elif ($p | startswith("libs/hostkit/envx/")) or ($p | startswith("libs/hostkit/httpx/"))`,
			`elif ($p | startswith("libs/hostkit/logx/")) then ["node-host-agent","node-automation-controller","webhook-dispatcher"]`,
			`elif ($p | startswith("libs/jinja/")) then ["node-host-agent"]`,
		} {
			if !strings.Contains(ci, tok) {
				t.Fatalf("ci.yml docker-detect consumers missing expected mapping %q", tok)
			}
		}
	})

	t.Run("Tier1_F20_ReleaseWorkflowAndMoonInputsSync", func(t *testing.T) {
		repoRoot := reqRepoRoot(t)
		relRaw, err := os.ReadFile(filepath.Join(repoRoot, ".github", "workflows", "release-webhook-dispatcher.yml"))
		if err != nil {
			t.Fatalf("read release-webhook-dispatcher.yml: %v", err)
		}
		rel := string(relRaw)
		for _, want := range []string{
			`"apps/webhook-dispatcher/**"`,
			`"libs/hostkit/envx/**"`,
			`"libs/hostkit/httpx/**"`,
			`"libs/hostkit/logx/**"`,
			`"libs/hostkit/go.mod"`,
			`"libs/hostkit/go.sum"`,
		} {
			if !strings.Contains(rel, want) {
				t.Fatalf("release-webhook-dispatcher.yml missing %s", want)
			}
		}

		moonRaw, err := os.ReadFile(filepath.Join(reqModuleRoot(t), "moon.yml"))
		if err != nil {
			t.Fatalf("read moon.yml: %v", err)
		}
		moon := string(moonRaw)
		for _, want := range []string{
			`'docs/env.md'`,
			`'/.github/workflows/ci.yml'`,
			`'/.github/workflows/release-app.yml'`,
			`'/.github/workflows/release-webhook-dispatcher.yml'`,
		} {
			if !strings.Contains(moon, want) {
				t.Fatalf("moon.yml missing input %s", want)
			}
		}
	})

	t.Run("Tier1_F21_VersionFlagNoEnvRequired", func(t *testing.T) {
		out, err := reqRunCmd(t, reqModuleRoot(t), cleanChildEnv(nil), bin, "-version")
		if err != nil {
			t.Fatalf("-version failed: %v\n%s", err, out)
		}
		if !strings.HasPrefix(out, "webhook-dispatcher ") {
			t.Fatalf("-version = %q, want prefix %q", out, "webhook-dispatcher ")
		}
	})

	t.Run("Tier1_F21_CustomConcourseTeamAndURLWiring", func(t *testing.T) {
		atc := reqNewTeamMockATC(t, "platform-ops")
		atc.pipelinesHandler = func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`[{"name":"ops-pipe","archived":false}]`))
		}
		atc.configHandler = func(w http.ResponseWriter, _ *http.Request, _ string) {
			_, _ = w.Write([]byte(`{"config":{"resources":[{"name":"ops-git","type":"git","source":{"uri":"https://github.com/org/ops.git"}}]}}`))
		}
		rd := reqStartDispatcherEnv(t, bin, map[string]string{
			"CONCOURSE_URL":  atc.server.URL,
			"CONCOURSE_TEAM": "platform-ops",
		})

		body := []byte(`{"repository":{"full_name":"org/ops"}}`)
		code, resp := rd.postWebhook(t, "push", "f21-team", signPayload(e2eSecret, body), body)
		if code != http.StatusAccepted || !strings.Contains(resp, `"resources_matched":1`) {
			t.Fatalf("push = (%d, %s), want (202, resources_matched:1)", code, resp)
		}
		calls := atc.waitForWebhookCalls(t, 1, 3*time.Second)
		waitForLogContains(t, rd.logs, "webhook fan-out complete", 3*time.Second)
		if !strings.HasPrefix(calls[0].Path, "/api/v1/teams/platform-ops/") {
			t.Fatalf("ATC call path = %q, want /api/v1/teams/platform-ops/...", calls[0].Path)
		}
	})

	t.Run("Tier1_F21_MultiUserLocalUsersFirstValidAndWarn", func(t *testing.T) {
		atc := newMockATC(t)
		atc.tokenHandler = func(w http.ResponseWriter, _ *http.Request, _ string) {
			w.WriteHeader(http.StatusNotFound)
		}
		var sawAuth atomic.Value
		atc.pipelinesHandler = func(w http.ResponseWriter, r *http.Request) {
			sawAuth.Store(r.Header.Get("Authorization"))
			_, _ = w.Write([]byte(`[]`))
		}
		rd := reqStartDispatcherEnv(t, bin, map[string]string{
			"CONCOURSE_URL": atc.server.URL,
			"LOCAL_USERS":   "first-u:first-p,second-u:second-p",
		})

		body := []byte(`{"repository":{"full_name":"org/none"}}`)
		code, _ := rd.postWebhook(t, "push", "f21-multi", signPayload(e2eSecret, body), body)
		if code != http.StatusAccepted {
			t.Fatalf("push = %d, want 202", code)
		}
		wantHdr := "Basic " + base64.StdEncoding.EncodeToString([]byte("first-u:first-p"))
		if got, _ := sawAuth.Load().(string); got != wantHdr {
			t.Fatalf("ATC Basic Auth = %q, want %q", got, wantHdr)
		}
		waitForLogContains(t, rd.logs, "LOCAL_USERS lists multiple users", 2*time.Second)
	})

	t.Run("Tier1_F21_CommaAndColonInPasswordPreserved", func(t *testing.T) {
		atc := newMockATC(t)
		atc.tokenHandler = func(w http.ResponseWriter, _ *http.Request, _ string) {
			w.WriteHeader(http.StatusNotFound)
		}
		var sawAuth atomic.Value
		atc.pipelinesHandler = func(w http.ResponseWriter, r *http.Request) {
			sawAuth.Store(r.Header.Get("Authorization"))
			_, _ = w.Write([]byte(`[]`))
		}
		rd := reqStartDispatcherEnv(t, bin, map[string]string{
			"CONCOURSE_URL": atc.server.URL,
			"LOCAL_USERS":   "ops:pa:ss,word,backup:other",
		})

		body := []byte(`{"repository":{"full_name":"org/none"}}`)
		code, _ := rd.postWebhook(t, "push", "f21-comma-colon", signPayload(e2eSecret, body), body)
		if code != http.StatusAccepted {
			t.Fatalf("push = %d, want 202", code)
		}
		wantHdr := "Basic " + base64.StdEncoding.EncodeToString([]byte("ops:pa:ss,word"))
		if got, _ := sawAuth.Load().(string); got != wantHdr {
			t.Fatalf("ATC Basic Auth = %q, want %q", got, wantHdr)
		}
	})

	t.Run("Tier1_F21_CustomListenAndMetricsAddrs", func(t *testing.T) {
		atc := newMockATC(t)
		listenAddr := reserveLoopbackAddr(t)
		metricsAddr := reserveLoopbackAddr(t)
		rd := reqStartDispatcherEnv(t, bin, map[string]string{
			"CONCOURSE_URL":  atc.server.URL,
			"CONCOURSE_TEAM": "custom-team",
			"LISTEN_ADDR":    listenAddr,
			"METRICS_ADDR":   metricsAddr,
		})

		client := reqNewHTTPClient(t, 3*time.Second)
		resp, err := doGet(t.Context(), client, "http://"+listenAddr+"/healthz")
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("custom LISTEN_ADDR /healthz failed: resp=%v err=%v", resp, err)
		}
		_ = resp.Body.Close()
		mBody := reqScrapeMetrics(t, metricsAddr)
		if mBody == "" {
			t.Fatal("expected non-empty /metrics on custom METRICS_ADDR")
		}
		logs := rd.logs.String()
		for _, want := range []string{listenAddr, metricsAddr, "custom-team"} {
			if !strings.Contains(logs, want) {
				t.Fatalf("startup logs missing %q:\n%s", want, logs)
			}
		}
	})

	// ---------------- Tier 2: Boundary & Negative Cases ----------------
	t.Run("Tier2_F1_EventHeaderCardinalityCollapse", func(t *testing.T) {
		atc := newMockATC(t)
		rd := reqStartDispatcher(t, bin, atc.server.URL)

		longEvent := strings.Repeat("x", 120)
		for _, ev := range []string{"", "deployment_status", "attacker_unique_12345", longEvent} {
			code, _ := rd.postWebhook(t, ev, "card-check", "", []byte(`{}`))
			if code != http.StatusUnauthorized {
				t.Fatalf("unauthorized %q = %d, want 401", ev, code)
			}
		}
		metrics := reqScrapeMetrics(t, rd.metricsAddr)
		logs := rd.logs.String()
		for _, forbidden := range []string{"deployment_status", "attacker_unique_12345", longEvent} {
			if strings.Contains(metrics, forbidden) || strings.Contains(logs, forbidden) {
				t.Fatalf("unauthenticated event header %q leaked into metrics/logs", forbidden)
			}
		}
		if !strings.Contains(metrics, `webhook_dispatcher_deliveries_total{event="none",status="unauthorized"}`) {
			t.Fatalf("missing event=none metric:\n%s", metrics)
		}
		if !strings.Contains(metrics, `webhook_dispatcher_deliveries_total{event="other",status="unauthorized"}`) {
			t.Fatalf("missing event=other metric:\n%s", metrics)
		}
	})

	t.Run("Tier2_F1_DeliveryGUIDLogSanitization", func(t *testing.T) {
		atc := newMockATC(t)
		rd := reqStartDispatcher(t, bin, atc.server.URL)

		rawDelivery := `bad"id` + strings.Repeat("z", 90)
		code, _ := rd.postWebhook(t, "push", rawDelivery, "sha256=bad", []byte(`{}`))
		if code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", code)
		}
		wantSanitized := "badid" + strings.Repeat("z", 58)
		waitForLogContains(t, rd.logs, wantSanitized, 2*time.Second)
		if strings.Contains(rd.logs.String(), strings.Repeat("z", 65)) {
			t.Fatalf("delivery ID was not truncated to <= 64 chars:\n%s", rd.logs.String())
		}
	})

	t.Run("Tier2_F1_ConcourseURLUserinfoRedactedFromLogs", func(t *testing.T) {
		atc := newMockATC(t)
		atc.pipelinesHandler = func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "upstream 500", http.StatusInternalServerError)
		}
		u := strings.Replace(atc.server.URL, "http://", "http://admin:supersecret@", 1)
		rd := reqStartDispatcherEnv(t, bin, map[string]string{
			"CONCOURSE_URL": u,
		})

		body := []byte(`{"repository":{"full_name":"org/err"}}`)
		code, _ := rd.postWebhook(t, "push", "userinfo-check", signPayload(e2eSecret, body), body)
		if code != http.StatusBadGateway {
			t.Fatalf("push = %d, want 502", code)
		}
		logs := rd.logs.String()
		if strings.Contains(logs, "supersecret") || strings.Contains(logs, "admin:") {
			t.Fatalf("CONCOURSE_URL userinfo leaked in logs:\n%s", logs)
		}
	})

	t.Run("Tier2_F1_WrongHTTPMethodsReturn405", func(t *testing.T) {
		atc := newMockATC(t)
		rd := reqStartDispatcher(t, bin, atc.server.URL)
		client := reqNewHTTPClient(t, 3*time.Second)

		cases := []struct {
			method string
			url    string
		}{
			{http.MethodGet, "http://" + rd.listenAddr + "/webhook"},
			{http.MethodPut, "http://" + rd.listenAddr + "/webhook"},
			{http.MethodPost, "http://" + rd.listenAddr + "/healthz"},
			{http.MethodPost, "http://" + rd.listenAddr + "/readyz"},
			{http.MethodPost, "http://" + rd.metricsAddr + "/metrics"},
		}
		for _, tc := range cases {
			req, err := http.NewRequestWithContext(t.Context(), tc.method, tc.url, nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("%s %s: %v", tc.method, tc.url, err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Fatalf("%s %s = %d, want 405", tc.method, tc.url, resp.StatusCode)
			}
		}
	})

	t.Run("Tier2_F1_EmptySecretEnvVarFailsClosed", func(t *testing.T) {
		out, err := reqRunCmd(t, reqModuleRoot(t), cleanChildEnv(map[string]string{
			"CI_WEBHOOK_TOKEN": e2eWebhookToken,
			"LOCAL_USERS":      e2eLocalUsers,
		}), bin)
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
			t.Fatalf("expected exit code 1, got err=%v out=%s", err, out)
		}
		if !strings.Contains(out, "GITHUB_WEBHOOK_SECRET") {
			t.Fatalf("expected log mentioning GITHUB_WEBHOOK_SECRET, got:\n%s", out)
		}
	})

	t.Run("Tier2_F5_PreAuthConcurrencyCap256SlowLorisTriggers503", func(t *testing.T) {
		atc := newMockATC(t)
		atc.pipelinesHandler = func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`[{"name":"p1","archived":false}]`))
		}
		atc.configHandler = func(w http.ResponseWriter, _ *http.Request, _ string) {
			_, _ = w.Write([]byte(`{"config":{"resources":[{"name":"r1","type":"git","source":{"uri":"https://github.com/org/c256.git"}}]}}`))
		}
		rd := reqStartDispatcher(t, bin, atc.server.URL)

		// 260 1-byte conns (~4 MiB << 32 MiB) specifically saturate maxPreAuthRequests = 256.
		closeAll := reqOpenSlowLorisFlood(t, rd.listenAddr, 0, 1, 1024, 260, false)
		code, body, err := reqProbeSlowBody503(t, rd.listenAddr, "push", false)
		if err != nil {
			t.Fatalf("probe under 256-conn saturation failed: %v", err)
		}
		if code != http.StatusServiceUnavailable {
			t.Fatalf("probe under 256-conn saturation = (%d, %q), want 503", code, body)
		}

		closeAll()
		payload := []byte(`{"repository":{"full_name":"org/c256"}}`)
		reqWaitRecovered202(t, rd, "push", "recover-256", payload)
		atc.waitForWebhookCalls(t, 1, 3*time.Second)
		waitForLogContains(t, rd.logs, "webhook fan-out complete", 3*time.Second)
	})

	t.Run("Tier2_F5_ChunkedSlowLorisCannotBypassPreAuthCap", func(t *testing.T) {
		atc := newMockATC(t)
		rd := reqStartDispatcher(t, bin, atc.server.URL)

		reqOpenSlowLorisFlood(t, rd.listenAddr, 16, 2<<20, 0, 0, true)
		code, body, err := reqProbeSlowBody503(t, rd.listenAddr, "push", true)
		if err != nil {
			t.Fatalf("chunked probe under chunked slow-loris failed: %v", err)
		}
		if code != http.StatusServiceUnavailable {
			t.Fatalf("chunked probe = (%d, %q), want 503", code, body)
		}
	})

	t.Run("Tier2_F5_MalformedSigRejected401BeforePreAuthCap", func(t *testing.T) {
		atc := newMockATC(t)
		rd := reqStartDispatcher(t, bin, atc.server.URL)
		reqOpenSlowLorisFlood(t, rd.listenAddr, 16, 2<<20, 4<<20, 0, false)

		for _, badSig := range []string{"", "sha256=deadbeef"} {
			code, _ := rd.postWebhook(t, "push", "malformed-sig", badSig, []byte(`{}`))
			if code != http.StatusUnauthorized {
				t.Fatalf("malformed sig %q under saturated pre-auth cap = %d, want 401", badSig, code)
			}
		}
	})

	t.Run("Tier2_F5_DeclaredOversizedRejected413BeforePreAuthCap", func(t *testing.T) {
		atc := newMockATC(t)
		rd := reqStartDispatcher(t, bin, atc.server.URL)
		reqOpenSlowLorisFlood(t, rd.listenAddr, 16, 2<<20, 4<<20, 0, false)

		const overLimit = (8 << 20) + 1
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+rd.listenAddr+"/webhook", io.LimitReader(reqZeroReader{}, overLimit))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.ContentLength = overLimit
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-GitHub-Event", "push")
		req.Header.Set("X-GitHub-Delivery", "oversized-under-cap")
		req.Header.Set("X-Hub-Signature-256", "sha256="+strings.Repeat("0", 64))

		client := reqNewHTTPClient(t, 3*time.Second)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST oversized failed: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		client.CloseIdleConnections()
		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("declared >8MiB under pre-auth saturation = %d, want 413", resp.StatusCode)
		}
	})

	t.Run("Tier2_F5_ReqSemSaturationIsolatedFromPreAuthBogusSig", func(t *testing.T) {
		atc := newMockATC(t)
		gate := make(chan struct{})
		var gateOnce sync.Once
		unblock := func() { gateOnce.Do(func() { close(gate) }) }
		t.Cleanup(unblock)

		var inPipelines atomic.Int32
		atc.pipelinesHandler = func(w http.ResponseWriter, _ *http.Request) {
			inPipelines.Add(1)
			<-gate
			_, _ = w.Write([]byte(`[]`))
		}
		rd := reqStartDispatcher(t, bin, atc.server.URL)

		// Saturate reqSem (128 slots) with 128 valid signed push deliveries parked inside EnsureIndex.
		validBody := []byte(`{"repository":{"full_name":"org/sat"}}`)
		validSig := signPayload(e2eSecret, validBody)
		const reqSemCap = 128
		var wg sync.WaitGroup
		transport := &http.Transport{MaxIdleConnsPerHost: 160}
		t.Cleanup(transport.CloseIdleConnections)
		client := &http.Client{Timeout: 6 * time.Second, Transport: transport}

		for i := range reqSemCap {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+rd.listenAddr+"/webhook", bytes.NewReader(validBody))
				if err != nil {
					return
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-GitHub-Event", "push")
				req.Header.Set("X-GitHub-Delivery", fmt.Sprintf("sat-%d", idx))
				req.Header.Set("X-Hub-Signature-256", validSig)
				resp, err := client.Do(req)
				if err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
				}
			}(i)
		}

		// Wait until reqSem is saturated (a valid streaming ping returns 503).
		pingBody := []byte(`{"zen":"sat"}`)
		pingSig := signPayload(e2eSecret, pingBody)
		saturated := false
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			code, _ := rd.postWebhook(t, "ping", "sat-probe", pingSig, pingBody)
			if code == http.StatusServiceUnavailable {
				saturated = true
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if !saturated {
			unblock()
			wg.Wait()
			t.Fatalf("failed to saturate reqSem (inPipelines=%d)", inPipelines.Load())
		}

		// With reqSem 100% full, a valid-format bogus-sig push still gets 401 (not 503).
		bogusSig := "sha256=" + strings.Repeat("0", 64)
		code, _ := rd.postWebhook(t, "push", "bogus-during-reqsem", bogusSig, []byte(`{}`))
		if code != http.StatusUnauthorized {
			unblock()
			wg.Wait()
			t.Fatalf("bogus sig while reqSem saturated = %d, want 401", code)
		}

		unblock()
		wg.Wait()
	})

	t.Run("Tier2_F5_BogusSigFullBodyReleasesPreAuthCapacity", func(t *testing.T) {
		atc := newMockATC(t)
		atc.pipelinesHandler = func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`[{"name":"p1","archived":false}]`))
		}
		atc.configHandler = func(w http.ResponseWriter, _ *http.Request, _ string) {
			_, _ = w.Write([]byte(`{"config":{"resources":[{"name":"r1","type":"git","source":{"uri":"https://github.com/org/leak.git"}}]}}`))
		}
		rd := reqStartDispatcher(t, bin, atc.server.URL)

		bogusSig := "sha256=" + strings.Repeat("0", 64)
		client := reqNewHTTPClient(t, 3*time.Second)
		var wg sync.WaitGroup
		errs := make(chan error, 300)
		for w := range 4 {
			wg.Add(1)
			go func(worker int) {
				defer wg.Done()
				for i := range 75 {
					req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+rd.listenAddr+"/webhook", strings.NewReader(`{}`))
					if err != nil {
						errs <- err
						return
					}
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("X-GitHub-Event", "push")
					req.Header.Set("X-GitHub-Delivery", fmt.Sprintf("bogus-%d-%d", worker, i))
					req.Header.Set("X-Hub-Signature-256", bogusSig)
					resp, err := client.Do(req)
					if err != nil {
						errs <- err
						return
					}
					_, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
					if resp.StatusCode != http.StatusUnauthorized {
						errs <- fmt.Errorf("expected 401, got %d", resp.StatusCode)
						return
					}
				}
			}(w)
		}
		wg.Wait()
		client.CloseIdleConnections()
		close(errs)
		for err := range errs {
			t.Fatal(err)
		}

		payload := []byte(`{"repository":{"full_name":"org/leak"}}`)
		code, resp := rd.postWebhook(t, "push", "after-300-bogus", signPayload(e2eSecret, payload), payload)
		if code != http.StatusAccepted || !strings.Contains(resp, `"resources_matched":1`) {
			t.Fatalf("301st valid push = (%d, %s), want (202, resources_matched:1)", code, resp)
		}
		atc.waitForWebhookCalls(t, 1, 3*time.Second)
		waitForLogContains(t, rd.logs, "webhook fan-out complete", 3*time.Second)
	})

	t.Run("Tier2_F20_TrimpathStrippedBinaryOmitsRepoPath", func(t *testing.T) {
		repoRoot := reqRepoRoot(t)
		modRoot := reqModuleRoot(t)
		staticBin := filepath.Join(t.TempDir(), "webhook-dispatcher-trim")
		env := append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0")
		out, err := reqRunCmd(t, modRoot, env, "go", "build", "-trimpath", "-ldflags=-s -w", "-o", staticBin, "./cmd/dispatcher")
		if err != nil {
			t.Fatalf("build trimpath binary: %v\n%s", err, out)
		}
		binBytes, err := os.ReadFile(staticBin)
		if err != nil {
			t.Fatalf("read static binary: %v", err)
		}
		if bytes.Contains(binBytes, []byte(repoRoot)) {
			t.Fatalf("trimpath binary unexpectedly contains repoRoot %q", repoRoot)
		}

		dfRaw, err := os.ReadFile(filepath.Join(modRoot, "Dockerfile"))
		if err != nil {
			t.Fatalf("read Dockerfile: %v", err)
		}
		df := string(dfRaw)
		if idxGoMod, idxSrc := strings.Index(df, "COPY libs/hostkit/go.*"), strings.Index(df, "COPY libs/hostkit/ /src/libs/hostkit/"); idxGoMod < 0 || idxSrc < 0 || idxGoMod >= idxSrc {
			t.Fatalf("Dockerfile layer order broken: go.*=%d src=%d", idxGoMod, idxSrc)
		}
	})

	t.Run("Tier2_F20_KoYAMLMatchesDockerfileBuildContract", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(reqModuleRoot(t), ".ko.yaml"))
		if err != nil {
			t.Fatalf("read .ko.yaml: %v", err)
		}
		ko := string(raw)
		for _, want := range []string{
			"defaultBaseImage: gcr.io/distroless/static:nonroot",
			"main: ./cmd/dispatcher",
			`"-s"`,
			`"-w"`,
			"-X main.version=",
		} {
			if !strings.Contains(ko, want) {
				t.Fatalf(".ko.yaml missing %q", want)
			}
		}
	})

	t.Run("Tier2_F20_ReleaseWorkflowExclusionsAndConcurrency", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(reqRepoRoot(t), ".github", "workflows", "release-webhook-dispatcher.yml"))
		if err != nil {
			t.Fatalf("read release-webhook-dispatcher.yml: %v", err)
		}
		rel := string(raw)
		for _, want := range []string{
			`'!**/*.md'`,
			"cancel-in-progress: false",
			"contents: write",
			"packages: write",
			"app: webhook-dispatcher",
		} {
			if !strings.Contains(rel, want) {
				t.Fatalf("release-webhook-dispatcher.yml missing %q", want)
			}
		}
	})

	t.Run("Tier2_F20_CIDockerDetectExcludesTestsAndJinja", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(reqRepoRoot(t), ".github", "workflows", "ci.yml"))
		if err != nil {
			t.Fatalf("read ci.yml: %v", err)
		}
		ci := string(raw)
		for _, want := range []string{
			`endswith(".md") or endswith("_test.go")`,
			`elif ($p | startswith("libs/jinja/")) then ["node-host-agent"]`,
			`if . == "node-host-agent" or . == "node-automation-controller" or . == "webhook-dispatcher"`,
		} {
			if !strings.Contains(ci, want) {
				t.Fatalf("ci.yml missing docker-detect invariant %q", want)
			}
		}
	})

	t.Run("Tier2_F20_GOWORKOffModuleIsolationAndGoMod", func(t *testing.T) {
		modRoot := reqModuleRoot(t)
		gomodRaw, err := os.ReadFile(filepath.Join(modRoot, "go.mod"))
		if err != nil {
			t.Fatalf("read go.mod: %v", err)
		}
		gomod := string(gomodRaw)
		if !strings.Contains(gomod, "=> ../../libs/hostkit") {
			t.Fatal("go.mod missing local replace => ../../libs/hostkit")
		}
		if strings.Contains(gomod, "libs/jinja") {
			t.Fatal("go.mod must not reference libs/jinja")
		}
		out, err := reqRunCmd(t, modRoot, append(os.Environ(), "GOWORK=off"), "go", "build", "-o", filepath.Join(t.TempDir(), "whd"), "./cmd/dispatcher")
		if err != nil {
			t.Fatalf("GOWORK=off go build ./cmd/dispatcher failed: %v\n%s", err, out)
		}
	})

	t.Run("Tier2_F21_UnknownCLIFlagExitsNonZero", func(t *testing.T) {
		out, err := reqRunCmd(t, reqModuleRoot(t), cleanChildEnv(nil), bin, "-bogus-flag")
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
			t.Fatalf("unknown flag expected exit code 1, got err=%v out=%s", err, out)
		}
		if !strings.Contains(out, "bogus-flag") {
			t.Fatalf("expected stderr to mention unknown flag, got:\n%s", out)
		}
	})

	t.Run("Tier2_F21_PortCollisionListenAddrAbortsBoot", func(t *testing.T) {
		ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin)
		cmd.Env = cleanChildEnv(map[string]string{
			"GITHUB_WEBHOOK_SECRET": e2eSecret,
			"CI_WEBHOOK_TOKEN":      e2eWebhookToken,
			"LOCAL_USERS":           e2eLocalUsers,
			"LISTEN_ADDR":           ln.Addr().String(),
			"METRICS_ADDR":          reserveLoopbackAddr(t),
		})
		out, err := cmd.CombinedOutput()
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
			t.Fatalf("listen port collision expected exit code 1, got err=%v out=%s", err, string(out))
		}
		if !strings.Contains(string(out), "binding public listener") {
			t.Fatalf("expected 'binding public listener' in output:\n%s", string(out))
		}
	})

	t.Run("Tier2_F21_PortCollisionMetricsAddrAbortsBoot", func(t *testing.T) {
		ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin)
		cmd.Env = cleanChildEnv(map[string]string{
			"GITHUB_WEBHOOK_SECRET": e2eSecret,
			"CI_WEBHOOK_TOKEN":      e2eWebhookToken,
			"LOCAL_USERS":           e2eLocalUsers,
			"LISTEN_ADDR":           reserveLoopbackAddr(t),
			"METRICS_ADDR":          ln.Addr().String(),
		})
		out, err := cmd.CombinedOutput()
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
			t.Fatalf("metrics port collision expected exit code 1, got err=%v out=%s", err, string(out))
		}
		if !strings.Contains(string(out), "binding metrics listener") {
			t.Fatalf("expected 'binding metrics listener' in output:\n%s", string(out))
		}
	})

	t.Run("Tier2_F21_LocalUsersWhitespaceAndMixedValidity", func(t *testing.T) {
		for _, badUsers := range []string{"   ", " , , "} {
			out, err := reqRunCmd(t, reqModuleRoot(t), cleanChildEnv(map[string]string{
				"GITHUB_WEBHOOK_SECRET": e2eSecret,
				"CI_WEBHOOK_TOKEN":      e2eWebhookToken,
				"LOCAL_USERS":           badUsers,
			}), bin)
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
				t.Fatalf("LOCAL_USERS=%q expected exit 1, got err=%v out=%s", badUsers, err, out)
			}
		}

		atc := newMockATC(t)
		atc.tokenHandler = func(w http.ResponseWriter, _ *http.Request, _ string) {
			w.WriteHeader(http.StatusNotFound)
		}
		var sawAuth atomic.Value
		atc.pipelinesHandler = func(w http.ResponseWriter, r *http.Request) {
			sawAuth.Store(r.Header.Get("Authorization"))
			_, _ = w.Write([]byte(`[]`))
		}
		rd := reqStartDispatcherEnv(t, bin, map[string]string{
			"CONCOURSE_URL": atc.server.URL,
			"LOCAL_USERS":   "broken,valid:pw",
		})
		body := []byte(`{"repository":{"full_name":"org/mixed"}}`)
		code, _ := rd.postWebhook(t, "push", "mixed-users", signPayload(e2eSecret, body), body)
		if code != http.StatusAccepted {
			t.Fatalf("push = %d, want 202", code)
		}
		wantHdr := "Basic " + base64.StdEncoding.EncodeToString([]byte("valid:pw"))
		if got, _ := sawAuth.Load().(string); got != wantHdr {
			t.Fatalf("ATC Basic Auth = %q, want %q", got, wantHdr)
		}
		waitForLogContains(t, rd.logs, "LOCAL_USERS lists multiple users", 2*time.Second)
	})

	t.Run("Tier2_F21_TeamWithSlashPathEscapedInATCRequests", func(t *testing.T) {
		atc := reqNewTeamMockATC(t, "team%2Falpha")
		var gotEscapedPath atomic.Value
		atc.pipelinesHandler = func(w http.ResponseWriter, r *http.Request) {
			gotEscapedPath.Store(r.URL.EscapedPath())
			_, _ = w.Write([]byte(`[{"name":"p1","archived":false}]`))
		}
		atc.configHandler = func(w http.ResponseWriter, _ *http.Request, _ string) {
			_, _ = w.Write([]byte(`{"config":{"resources":[{"name":"r1","type":"git","source":{"uri":"https://github.com/org/slash.git"}}]}}`))
		}
		rd := reqStartDispatcherEnv(t, bin, map[string]string{
			"CONCOURSE_URL":  atc.server.URL,
			"CONCOURSE_TEAM": "team/alpha",
		})
		body := []byte(`{"repository":{"full_name":"org/slash"}}`)
		code, resp := rd.postWebhook(t, "push", "slash-team", signPayload(e2eSecret, body), body)
		if code != http.StatusAccepted || !strings.Contains(resp, `"resources_matched":1`) {
			t.Fatalf("push = (%d, %s), want (202, resources_matched:1)", code, resp)
		}
		atc.waitForWebhookCalls(t, 1, 3*time.Second)
		waitForLogContains(t, rd.logs, "webhook fan-out complete", 3*time.Second)
		if got, _ := gotEscapedPath.Load().(string); got != "/api/v1/teams/team%2Falpha/pipelines" {
			t.Fatalf("EscapedPath = %q, want /api/v1/teams/team%%2Falpha/pipelines", got)
		}
	})

	// ---------------- Tier 3: Pairwise Cross-Feature Combinations ----------------
	t.Run("Tier3_F5_x_F1_PreAuthFloodPreservesMetricsCardinalityAndListenerIsolation", func(t *testing.T) {
		atc := newMockATC(t)
		rd := reqStartDispatcher(t, bin, atc.server.URL)
		reqOpenSlowLorisFlood(t, rd.listenAddr, 16, 2<<20, 4<<20, 0, false)

		code, _, err := reqProbeSlowBody503(t, rd.listenAddr, "push", false)
		if err != nil || code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 probe, got code=%d err=%v", code, err)
		}
		code, _ = rd.postWebhook(t, "x-unknown-ev", `d"1/bad$id`, "sha256=bad", []byte(`{}`))
		if code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", code)
		}

		client := reqNewHTTPClient(t, 3*time.Second)
		isoResp, err := doGet(t.Context(), client, "http://"+rd.listenAddr+"/metrics")
		if err != nil {
			t.Fatalf("GET public /metrics: %v", err)
		}
		_, _ = io.Copy(io.Discard, isoResp.Body)
		_ = isoResp.Body.Close()
		if isoResp.StatusCode != http.StatusNotFound {
			t.Fatalf("public /metrics during flood = %d, want 404", isoResp.StatusCode)
		}

		metrics := reqScrapeMetrics(t, rd.metricsAddr)
		if !strings.Contains(metrics, `webhook_dispatcher_deliveries_total{event="push",status="overloaded"}`) {
			t.Fatalf("missing overloaded push metric:\n%s", metrics)
		}
		if !strings.Contains(metrics, `webhook_dispatcher_deliveries_total{event="other",status="unauthorized"}`) {
			t.Fatalf("missing other/unauthorized metric:\n%s", metrics)
		}
		if strings.Contains(metrics, "x-unknown-ev") || strings.Contains(rd.logs.String(), "x-unknown-ev") {
			t.Fatal("raw unknown event leaked into metrics/logs during flood")
		}
		waitForLogContains(t, rd.logs, `"delivery":"d1badid"`, 2*time.Second)
	})

	t.Run("Tier3_F5_x_F21_CustomTeamAndMultiUserUnderPreAuthFlood", func(t *testing.T) {
		atc := reqNewTeamMockATC(t, "sec-team")
		atc.tokenHandler = func(w http.ResponseWriter, _ *http.Request, _ string) {
			w.WriteHeader(http.StatusNotFound)
		}
		var sawAuth atomic.Value
		atc.pipelinesHandler = func(w http.ResponseWriter, r *http.Request) {
			sawAuth.Store(r.Header.Get("Authorization"))
			_, _ = w.Write([]byte(`[{"name":"sec-p","archived":false}]`))
		}
		atc.configHandler = func(w http.ResponseWriter, _ *http.Request, _ string) {
			_, _ = w.Write([]byte(`{"config":{"resources":[{"name":"sec-r","type":"git","source":{"uri":"https://github.com/org/sec.git"}}]}}`))
		}
		rd := reqStartDispatcherEnv(t, bin, map[string]string{
			"CONCOURSE_URL":  atc.server.URL,
			"CONCOURSE_TEAM": "sec-team",
			"LOCAL_USERS":    "primary:pw:1,x,backup:other",
		})

		closeAll := reqOpenSlowLorisFlood(t, rd.listenAddr, 16, 2<<20, 4<<20, 0, false)
		code, _, err := reqProbeSlowBody503(t, rd.listenAddr, "push", false)
		if err != nil || code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 during flood, got code=%d err=%v", code, err)
		}
		pingBody := []byte(`{"zen":"ok"}`)
		code, _ = rd.postWebhook(t, "ping", "t3-ping", signPayload(e2eSecret, pingBody), pingBody)
		if code != http.StatusAccepted {
			t.Fatalf("ping during flood = %d, want 202", code)
		}

		closeAll()
		payload := []byte(`{"repository":{"full_name":"org/sec"}}`)
		reqWaitRecovered202(t, rd, "push", "t3-recover", payload)
		calls := atc.waitForWebhookCalls(t, 1, 3*time.Second)
		waitForLogContains(t, rd.logs, "webhook fan-out complete", 3*time.Second)
		if !strings.HasPrefix(calls[0].Path, "/api/v1/teams/sec-team/") {
			t.Fatalf("call path = %q, want /api/v1/teams/sec-team/...", calls[0].Path)
		}
		wantHdr := "Basic " + base64.StdEncoding.EncodeToString([]byte("primary:pw:1,x"))
		if got, _ := sawAuth.Load().(string); got != wantHdr {
			t.Fatalf("ATC Basic Auth = %q, want %q", got, wantHdr)
		}
	})

	t.Run("Tier3_F21_x_F1_CustomConfigUserinfoRedactionAndMetricContracts", func(t *testing.T) {
		var foreignHits atomic.Int32
		foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			foreignHits.Add(1)
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(foreign.Close)

		atc := reqNewTeamMockATC(t, "ops-ci")
		var failPipes atomic.Bool
		atc.pipelinesHandler = func(w http.ResponseWriter, _ *http.Request) {
			if failPipes.Load() {
				http.Error(w, "fail", http.StatusInternalServerError)
				return
			}
			_, _ = w.Write([]byte(`[{"name":"p1","archived":false}]`))
		}
		atc.configHandler = func(w http.ResponseWriter, _ *http.Request, _ string) {
			_, _ = w.Write([]byte(`{"config":{"resources":[{"name":"r1","type":"git","source":{"uri":"https://github.com/org/ops-ci.git"}}]}}`))
		}
		atc.checkHandler = func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, foreign.URL+"/leak", http.StatusFound)
		}

		u := strings.Replace(atc.server.URL, "http://", "http://u:secretpass@", 1)
		rd := reqStartDispatcherEnv(t, bin, map[string]string{
			"CONCOURSE_URL":  u,
			"CONCOURSE_TEAM": "ops-ci",
		})

		body := []byte(`{"repository":{"full_name":"org/ops-ci"}}`)
		code, _ := rd.postWebhook(t, "push", "t3-f21-f1", signPayload(e2eSecret, body), body)
		if code != http.StatusAccepted {
			t.Fatalf("push = %d, want 202", code)
		}
		atc.waitForWebhookCalls(t, 1, 3*time.Second)
		waitForLogContains(t, rd.logs, "webhook fan-out complete", 3*time.Second)
		if foreignHits.Load() != 0 {
			t.Fatalf("cross-origin redirect leaked %d hits", foreignHits.Load())
		}

		// Also verify metrics families & listener isolation & secret redaction.
		metrics := reqScrapeMetrics(t, rd.metricsAddr)
		for _, fam := range []string{
			"webhook_dispatcher_deliveries_total",
			"webhook_dispatcher_fanout_total",
			"webhook_dispatcher_fanout_duration_seconds",
			"webhook_dispatcher_concourse_index_last_refresh_timestamp_seconds",
			"webhook_dispatcher_concourse_index_fetch_errors_total",
		} {
			if !strings.Contains(metrics, fam) {
				t.Fatalf("/metrics missing %q", fam)
			}
		}
		client := reqNewHTTPClient(t, 3*time.Second)
		resp, err := doGet(t.Context(), client, "http://"+rd.listenAddr+"/metrics")
		if err != nil {
			t.Fatalf("GET public /metrics: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("public /metrics = %d, want 404", resp.StatusCode)
		}
		logs := rd.logs.String()
		for _, secret := range []string{"secretpass", e2eWebhookToken, e2eSecret} {
			if strings.Contains(logs, secret) {
				t.Fatalf("secret %q leaked in logs:\n%s", secret, logs)
			}
		}
	})

	t.Run("Tier3_F20_x_F21_VersionedStaticBuildEndToEndExecution", func(t *testing.T) {
		modRoot := reqModuleRoot(t)
		staticBin := filepath.Join(t.TempDir(), "webhook-dispatcher-t3")
		env := append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0")
		out, err := reqRunCmd(t, modRoot, env, "go", "build", "-trimpath",
			"-ldflags=-s -w -X main.version=v0.99.0-t3", "-o", staticBin, "./cmd/dispatcher")
		if err != nil {
			t.Fatalf("static build failed: %v\n%s", err, out)
		}
		vOut, err := reqRunCmd(t, modRoot, cleanChildEnv(nil), staticBin, "-version")
		if err != nil || vOut != "webhook-dispatcher v0.99.0-t3\n" {
			t.Fatalf("-version = (%q, %v), want (%q, nil)", vOut, err, "webhook-dispatcher v0.99.0-t3\n")
		}

		atc := reqNewTeamMockATC(t, "release-team")
		atc.pipelinesHandler = func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`[{"name":"rel-p","archived":false}]`))
		}
		atc.configHandler = func(w http.ResponseWriter, _ *http.Request, _ string) {
			_, _ = w.Write([]byte(`{"config":{"resources":[{"name":"rel-g","type":"git","source":{"uri":"https://github.com/org/rel.git"}}]}}`))
		}
		rd := reqStartDispatcherEnv(t, staticBin, map[string]string{
			"CONCOURSE_URL":  atc.server.URL,
			"CONCOURSE_TEAM": "release-team",
			"LOCAL_USERS":    "rel-u:rel-pw,extra:pw",
		})
		body := []byte(`{"repository":{"full_name":"org/rel"}}`)
		code, _ := rd.postWebhook(t, "push", "t3-rel", signPayload(e2eSecret, body), body)
		if code != http.StatusAccepted {
			t.Fatalf("push = %d, want 202", code)
		}
		atc.waitForWebhookCalls(t, 1, 3*time.Second)
		waitForLogContains(t, rd.logs, "webhook fan-out complete", 3*time.Second)

		http.DefaultClient.CloseIdleConnections()
		if err := rd.cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatalf("SIGTERM: %v", err)
		}
		select {
		case <-rd.doneCh:
			if rd.waitErr != nil {
				t.Fatalf("expected clean exit 0 on SIGTERM, got %v\nlogs:\n%s", rd.waitErr, rd.logs.String())
			}
		case <-time.After(5 * time.Second):
			t.Fatal("static binary did not exit cleanly within 5s after SIGTERM")
		}
	})

	// ---------------- Tier 4: Scenario 3 (GitHub Org Webhook Storm) ----------------
	t.Run("Tier4_Scenario3_GitHubOrgWebhookStorm", func(t *testing.T) {
		modRoot := reqModuleRoot(t)
		stormBin := filepath.Join(t.TempDir(), "webhook-dispatcher-storm")
		env := append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0")
		out, err := reqRunCmd(t, modRoot, env, "go", "build", "-trimpath",
			"-ldflags=-s -w -X main.version=v4.0.0-storm", "-o", stormBin, "./cmd/dispatcher")
		if err != nil {
			t.Fatalf("build storm binary: %v\n%s", err, out)
		}

		atc := reqNewTeamMockATC(t, "org-ci")
		var tokSeq atomic.Int32
		atc.tokenHandler = func(w http.ResponseWriter, _ *http.Request, path string) {
			if path != "/sky/issuer/token" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			n := tokSeq.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"access_token":"tok-%d","expires_in":3600}`, n)
		}
		atc.pipelinesHandler = func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				http.Error(w, "bearer required", http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`[
				{"name":"svc-main","archived":false},
				{"name":"svc-canary","archived":false,"instance_vars":{"env":"staging"}}
			]`))
		}
		atc.configHandler = func(w http.ResponseWriter, r *http.Request, pipeline string) {
			auth := r.Header.Get("Authorization")
			if auth == "Bearer tok-1" || !strings.HasPrefix(auth, "Bearer ") {
				http.Error(w, "token revoked", http.StatusUnauthorized)
				return
			}
			switch pipeline {
			case "svc-main":
				_, _ = w.Write([]byte(`{"config":{"resources":[
					{"name":"core-git","type":"git","source":{"uri":"https://github.com/org/core.git"}},
					{"name":"core-pr","type":"github-pr","source":{"repository":"org/core"}}
				]}}`))
			case "svc-canary":
				if r.URL.Query().Get("vars.env") != `"staging"` {
					http.Error(w, "missing vars.env", http.StatusBadRequest)
					return
				}
				_, _ = w.Write([]byte(`{"config":{"resources":[
					{"name":"canary-git","type":"git","source":{"uri":"https://github.com/org/core.git"}}
				]}}`))
			default:
				http.NotFound(w, r)
			}
		}

		var checkStarted atomic.Int32
		var gateChecks atomic.Bool
		releaseChecks := make(chan struct{})
		var releaseOnce sync.Once
		unblockChecks := func() { releaseOnce.Do(func() { close(releaseChecks) }) }
		t.Cleanup(unblockChecks)

		atc.checkHandler = func(w http.ResponseWriter, _ *http.Request) {
			if gateChecks.Load() {
				checkStarted.Add(1)
				<-releaseChecks
			}
			w.WriteHeader(http.StatusOK)
		}

		rd := reqStartDispatcherEnv(t, stormBin, map[string]string{
			"CONCOURSE_URL":  atc.server.URL,
			"CONCOURSE_TEAM": "org-ci",
			"LOCAL_USERS":    "storm-u:p:1,ass,extra:2",
		})

		// Phase A: Pre-auth slow-loris flood + streaming ping isolation + listener isolation.
		closeAll := reqOpenSlowLorisFlood(t, rd.listenAddr, 16, 2<<20, 4<<20, 0, false)
		code, _, err := reqProbeSlowBody503(t, rd.listenAddr, "push", false)
		if err != nil || code != http.StatusServiceUnavailable {
			t.Fatalf("Phase A push probe = (%d, %v), want 503", code, err)
		}

		pingBody := []byte(`{"zen":"phase-a"}`)
		pingSig := signPayload(e2eSecret, pingBody)
		pingClient := reqNewHTTPClient(t, 3*time.Second)
		var pingWG sync.WaitGroup
		pingErrs := make(chan error, 8)
		for i := range 8 {
			pingWG.Add(1)
			go func(idx int) {
				defer pingWG.Done()
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+rd.listenAddr+"/webhook", bytes.NewReader(pingBody))
				if err != nil {
					pingErrs <- err
					return
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-GitHub-Event", "ping")
				req.Header.Set("X-GitHub-Delivery", fmt.Sprintf("storm-ping-%d", idx))
				req.Header.Set("X-Hub-Signature-256", pingSig)
				resp, err := pingClient.Do(req)
				if err != nil {
					pingErrs <- err
					return
				}
				b, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusAccepted || !strings.Contains(string(b), `"resources_matched":0`) {
					pingErrs <- fmt.Errorf("ping %d = (%d, %s)", idx, resp.StatusCode, string(b))
				}
			}(i)
		}
		pingWG.Wait()
		pingClient.CloseIdleConnections()
		close(pingErrs)
		for err := range pingErrs {
			t.Fatal(err)
		}

		isoClient := reqNewHTTPClient(t, 3*time.Second)
		for _, chk := range []struct {
			path string
			want int
		}{
			{"/readyz", http.StatusOK},
			{"/metrics", http.StatusNotFound},
		} {
			resp, err := doGet(t.Context(), isoClient, "http://"+rd.listenAddr+chk.path)
			if err != nil {
				t.Fatalf("GET %s: %v", chk.path, err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != chk.want {
				t.Fatalf("public %s = %d, want %d", chk.path, resp.StatusCode, chk.want)
			}
		}
		isoClient.CloseIdleConnections()

		// Phase B: Recovery + concurrent multi-event storm + tok-1 -> tok-2 auth refresh.
		closeAll()
		pushBody := []byte(`{"repository":{"full_name":"org/core"}}`)
		reqWaitRecovered202(t, rd, "push", "storm-recover", pushBody)
		atc.waitForWebhookCalls(t, 2, 3*time.Second)
		reqWaitForLogCount(t, rd.logs, "webhook fan-out complete", 1, 3*time.Second)

		prOpened := []byte(`{"action":"opened","repository":{"full_name":"org/core"}}`)
		relPublished := []byte(`{"action":"published","repository":{"full_name":"org/core"}}`)
		tagCreate := []byte(`{"ref_type":"tag","repository":{"full_name":"org/core"}}`)
		relCreated := []byte(`{"action":"created","repository":{"full_name":"org/core"}}`)
		branchCreate := []byte(`{"ref_type":"branch","repository":{"full_name":"org/core"}}`)
		prLabeled := []byte(`{"action":"labeled","repository":{"full_name":"org/core"}}`)

		type stormReq struct {
			event      string
			body       []byte
			wantCode   int
			wantSubstr string
		}
		var batch []stormReq
		for range 4 {
			batch = append(batch,
				stormReq{"push", pushBody, http.StatusAccepted, `"resources_matched":2`},
				stormReq{"pull_request", prOpened, http.StatusAccepted, `"resources_matched":1`},
				stormReq{"release", relPublished, http.StatusAccepted, `"resources_matched":2`},
				stormReq{"create", tagCreate, http.StatusAccepted, `"resources_matched":2`},
			)
		}
		for range 2 {
			batch = append(batch,
				stormReq{"release", relCreated, http.StatusAccepted, `"resources_matched":0`},
				stormReq{"create", branchCreate, http.StatusAccepted, `"resources_matched":0`},
				stormReq{"pull_request", prLabeled, http.StatusOK, `"skipped":"action"`},
			)
		}

		stormClient := reqNewHTTPClient(t, 5*time.Second)
		var stormWG sync.WaitGroup
		stormErrs := make(chan error, len(batch))
		for i, sr := range batch {
			stormWG.Add(1)
			go func(idx int, item stormReq) {
				defer stormWG.Done()
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+rd.listenAddr+"/webhook", bytes.NewReader(item.body))
				if err != nil {
					stormErrs <- err
					return
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-GitHub-Event", item.event)
				req.Header.Set("X-GitHub-Delivery", fmt.Sprintf("storm-b-%d", idx))
				req.Header.Set("X-Hub-Signature-256", signPayload(e2eSecret, item.body))
				resp, err := stormClient.Do(req)
				if err != nil {
					stormErrs <- err
					return
				}
				b, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != item.wantCode || !strings.Contains(string(b), item.wantSubstr) {
					stormErrs <- fmt.Errorf("item %d (%s) = (%d, %s), want (%d, %s)", idx, item.event, resp.StatusCode, string(b), item.wantCode, item.wantSubstr)
				}
			}(i, sr)
		}
		stormWG.Wait()
		stormClient.CloseIdleConnections()
		close(stormErrs)
		for err := range stormErrs {
			t.Fatal(err)
		}

		// 2 (recovery push) + 28 (batch) = 30 checks across 17 dispatches so far.
		atc.waitForWebhookCalls(t, 30, 5*time.Second)
		reqWaitForLogCount(t, rd.logs, "check webhook", 30, 5*time.Second)
		reqWaitForLogCount(t, rd.logs, "webhook fan-out complete", 17, 5*time.Second)
		if tokSeq.Load() < 2 {
			t.Fatalf("expected tok-2 re-mint after tok-1 revocation, tokSeq=%d", tokSeq.Load())
		}

		// Scrape /metrics BEFORE SIGTERM.
		metrics := reqScrapeMetrics(t, rd.metricsAddr)
		for _, wantMetric := range []string{
			`webhook_dispatcher_deliveries_total{event="push",status="overloaded"}`,
			`webhook_dispatcher_deliveries_total{event="push",status="dispatched"}`,
			`webhook_dispatcher_deliveries_total{event="pull_request",status="ignored"}`,
			`webhook_dispatcher_fanout_total{result="ok"}`,
			`webhook_dispatcher_concourse_index_last_refresh_timestamp_seconds`,
		} {
			if !strings.Contains(metrics, wantMetric) {
				t.Fatalf("Phase B /metrics missing %q:\n%s", wantMetric, metrics)
			}
		}
		for _, line := range strings.Split(metrics, "\n") {
			if strings.HasPrefix(line, "webhook_dispatcher_concourse_index_last_refresh_timestamp_seconds ") {
				valStr := strings.TrimSpace(strings.TrimPrefix(line, "webhook_dispatcher_concourse_index_last_refresh_timestamp_seconds "))
				if valStr == "0" || valStr == "" {
					t.Fatalf("expected last_refresh_timestamp > 0, got %q", line)
				}
			}
		}

		// Phase C: Final in-flight wave + SIGTERM graceful drain.
		gateChecks.Store(true)
		for i := range 4 {
			code, resp := rd.postWebhook(t, "push", fmt.Sprintf("storm-c-%d", i), signPayload(e2eSecret, pushBody), pushBody)
			if code != http.StatusAccepted {
				unblockChecks()
				t.Fatalf("Phase C push %d = (%d, %s), want 202", i, code, resp)
			}
		}
		deadline := time.Now().Add(6 * time.Second)
		for checkStarted.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(15 * time.Millisecond)
		}
		if checkStarted.Load() == 0 {
			unblockChecks()
			t.Fatal("expected Phase C check/webhook call blocked inside checkHandler")
		}

		http.DefaultClient.CloseIdleConnections()
		if err := rd.cmd.Process.Signal(syscall.SIGTERM); err != nil {
			unblockChecks()
			t.Fatalf("SIGTERM: %v", err)
		}

		readyzClient := reqNewHTTPClient(t, 2*time.Second)
		defer readyzClient.CloseIdleConnections()
		shutdownSeen := false
		sigDeadline := time.Now().Add(6 * time.Second)
		for time.Now().Before(sigDeadline) {
			select {
			case <-rd.doneCh:
				unblockChecks()
				t.Fatalf("dispatcher exited prematurely (%v) during Phase C drain", rd.waitErr)
			default:
			}
			resp, err := doGet(t.Context(), readyzClient, "http://"+rd.listenAddr+"/readyz")
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusServiceUnavailable {
					shutdownSeen = true
					break
				}
			} else if errors.Is(err, syscall.ECONNREFUSED) {
				shutdownSeen = true
				break
			}
			time.Sleep(15 * time.Millisecond)
		}
		readyzClient.CloseIdleConnections()
		if !shutdownSeen {
			unblockChecks()
			t.Fatal("/readyz stayed 200 after SIGTERM")
		}

		for range 5 {
			select {
			case <-rd.doneCh:
				unblockChecks()
				t.Fatalf("dispatcher exited prematurely (%v) while checkHandler blocked", rd.waitErr)
			default:
			}
			time.Sleep(50 * time.Millisecond)
		}

		unblockChecks()
		select {
		case <-rd.doneCh:
			if rd.waitErr != nil {
				t.Fatalf("expected clean exit 0 on SIGTERM drain, got %v\nlogs:\n%s", rd.waitErr, rd.logs.String())
			}
		case <-time.After(10 * time.Second):
			t.Fatal("dispatcher did not exit within 10s after unblocking Phase C checks")
		}

		allCalls := atc.webhookCalls()
		if len(allCalls) != 38 {
			t.Fatalf("total check/webhook calls = %d, want 38 (2 recovery + 28 Phase B + 8 Phase C)", len(allCalls))
		}
		for i, c := range allCalls {
			if !strings.HasPrefix(c.Path, "/api/v1/teams/org-ci/") {
				t.Fatalf("call %d path = %q, want /api/v1/teams/org-ci/...", i, c.Path)
			}
			if c.AuthHdr != "" || c.Token != e2eWebhookToken {
				t.Fatalf("call %d auth/token mismatch: auth=%q token=%q", i, c.AuthHdr, c.Token)
			}
		}

		logs := rd.logs.String()
		if !strings.Contains(logs, "LOCAL_USERS lists multiple users") {
			t.Fatalf("expected multi-user LOCAL_USERS warning in logs:\n%s", logs)
		}
		for _, secret := range []string{e2eSecret, e2eWebhookToken, "p:1,ass"} {
			if strings.Contains(logs, secret) {
				t.Fatalf("secret %q leaked into logs", secret)
			}
		}

		// Confirm startup version log contains v4.0.0-storm (F20 x F21).
		var sawVersion bool
		for _, line := range strings.Split(logs, "\n") {
			var obj map[string]any
			if json.Unmarshal([]byte(line), &obj) == nil && obj["version"] == "v4.0.0-storm" {
				sawVersion = true
				break
			}
		}
		if !sawVersion {
			t.Fatalf("expected startup JSON log with version=v4.0.0-storm:\n%s", logs)
		}
	})
}
