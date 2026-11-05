// apiprober_test.go — Prober construction (New/TLS/CA/metrics
// registration), Name/Run, plus the shared fake-HAProxy + apiStub
// fixtures used across the per-domain test files.
package apiprober

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// fakeHAProxy is a fake HAProxy admin unix socket: `show stat` returns
// generated CSV (disabled servers report MAINT, like real HAProxy),
// enable/disable commands are applied to the server table and recorded.
type fakeHAProxy struct {
	sockPath string
	ln       net.Listener
	mu       sync.Mutex
	cmds     []string
	servers  map[string]string
	order    []string
	disabled map[string]bool
	// failReply maps a command to a reply body — the full command
	// string first ("disable server kube_apiserver/hub1" for a
	// per-server failure), then the two-word prefix ("enable server")
	// for a blanket one. A non-empty reply makes the prober treat the
	// command as failed and the server table is left untouched (like
	// a real HAProxy "No such server" rejection).
	failReply map[string]string
}

func newFakeHAProxy(t *testing.T, rows ...[2]string) *fakeHAProxy {
	t.Helper()
	f := &fakeHAProxy{
		sockPath: t.TempDir() + "/haproxy.sock",
		servers:  map[string]string{},
		disabled: map[string]bool{},
	}
	for _, r := range rows {
		f.servers[r[0]] = r[1]
		f.order = append(f.order, r[0])
	}
	ln, err := net.Listen("unix", f.sockPath)
	if err != nil {
		t.Fatal(err)
	}
	f.ln = ln
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.handle(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return f
}

// statCSV renders `show stat` output for the kube_apiserver backend.
func (f *fakeHAProxy) statCSV() string {
	var b strings.Builder
	b.WriteString("# pxname,svname,status,addr\n")
	b.WriteString("api_local,FRONTEND,OPEN,\n")
	for _, name := range f.order {
		status := "UP"
		if f.disabled[name] {
			status = "MAINT"
		}
		fmt.Fprintf(&b, "kube_apiserver,%s,%s,%s\n", name, status, f.servers[name])
	}
	b.WriteString("kube_apiserver,BACKEND,UP,\n")
	return b.String()
}

func (f *fakeHAProxy) handle(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 8192)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	cmd := strings.TrimSpace(string(buf[:n]))
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cmds = append(f.cmds, cmd)
	if strings.HasPrefix(cmd, "show stat") {
		io.WriteString(conn, f.statCSV())
		return
	}
	// "<enable|disable> server kube_apiserver/<name>" — apply like
	// real HAProxy, empty reply = success.
	parts := strings.Fields(cmd)
	if len(parts) >= 2 {
		reply, fail := f.failReply[cmd]
		if !fail {
			reply, fail = f.failReply[parts[0]+" "+parts[1]]
		}
		if fail {
			io.WriteString(conn, reply)
			return
		}
	}
	if len(parts) == 3 {
		srv := strings.TrimPrefix(parts[2], "kube_apiserver/")
		switch parts[0] {
		case "disable":
			f.disabled[srv] = true
		case "enable":
			delete(f.disabled, srv)
		}
	}
}

func (f *fakeHAProxy) commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.cmds...)
}

// apiStub is a fake apiserver serving LIST responses with controllable
// resourceVersions. resourceVersion=0 → cacheRV, anything else →
// liveRV. fail=true makes queries fail (stall simulation).
// cacheStatus/liveStatus force an HTTP status per path (0 = normal);
// wantToken, when set, demands that exact bearer token and 401s
// otherwise (credential verification for the token-reload tests).
type apiStub struct {
	srv         *httptest.Server
	mu          sync.Mutex
	cacheRV     int64
	liveRV      int64
	fail        bool
	cacheStatus int
	liveStatus  int
	wantToken   string
}

func newAPIStub(t *testing.T) *apiStub {
	t.Helper()
	return newAPIStubOn(t, "127.0.0.1:0")
}

// newAPIStubOn is newAPIStub bound to a specific loopback address —
// watchdog file names key on the backend IP, so tests exercising the
// file contract need distinct IPs per stub (127.0.0.0/8 is all
// loopback, e.g. "127.0.0.2:0").
func newAPIStubOn(t *testing.T, listenAddr string) *apiStub {
	t.Helper()
	a := &apiStub{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.wantToken != "" &&
			r.Header.Get("Authorization") != "Bearer "+a.wantToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		rv := a.liveRV
		status := a.liveStatus
		if r.URL.Query().Get("resourceVersion") == "0" {
			rv = a.cacheRV
			status = a.cacheStatus
		}
		if status == 0 && a.fail {
			status = http.StatusServiceUnavailable
		}
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"apiVersion":"v1","kind":"List","metadata":{"resourceVersion":"%d"},"items":[]}`, rv)
	}))
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	srv.Listener = ln
	srv.StartTLS()
	a.srv = srv
	t.Cleanup(a.srv.Close)
	return a
}

func (a *apiStub) addr() string { return strings.TrimPrefix(a.srv.URL, "https://") }

func (a *apiStub) set(cacheRV, liveRV int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cacheRV, a.liveRV = cacheRV, liveRV
}

func (a *apiStub) setFail(fail bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.fail = fail
}

// setStatus forces an HTTP status per probe path — 0 restores the
// normal LIST response (auth still applies when wantToken is set).
func (a *apiStub) setStatus(cache, live int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cacheStatus, a.liveStatus = cache, live
}

// setToken makes the stub require that exact bearer token — "" lifts
// the requirement (the injected-client fixtures send no auth).
func (a *apiStub) setToken(want string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.wantToken = want
}

// fixture wires a Prober against the fake socket + injected HTTP
// client. tcpReachable controls per-addr TCP preflight (absent = ok).
// One httptest client works for every apiStub — httptest TLS servers
// share the same static localhost cert.
func fixture(t *testing.T, ha *fakeHAProxy, mode string,
	tcpReachable map[string]bool) *Prober {
	t.Helper()
	stub := newAPIStub(t)
	p, err := New(Config{
		SocketPath:    ha.sockPath,
		BackendName:   "kube_apiserver",
		Mode:          mode,
		GapMin:        1000,
		FailCycles:    2,
		FrozenCycles:  2,
		RecoverCycles: 3,
		TokenFile:     "",
		HTTPClient:    stub.srv.Client(),
		TCPCheck: func(_ context.Context, addr string) error {
			if ok, found := tcpReachable[addr]; found && !ok {
				return errors.New("connect refused")
			}
			return nil
		},
	}, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func hasCmd(cmds []string, prefix string) bool {
	for _, c := range cmds {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func TestInvalidModeRejected(t *testing.T) {
	_, err := New(Config{Mode: "yolo"}, prometheus.NewRegistry())
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestRunLoopStopsOnCancel(t *testing.T) {
	ha := newFakeHAProxy(t)
	p := fixture(t, ha, ModeDryRun, nil)
	p.cfg.Interval = time.Hour // only the immediate cycle runs
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestName(t *testing.T) {
	p := fixture(t, newFakeHAProxy(t), ModeDryRun, nil)
	if p.Name() != "apiprober" {
		t.Fatalf("Name()=%q want %q", p.Name(), "apiprober")
	}
}

func TestCAPool(t *testing.T) {
	// A real PEM bundle — reuse the httptest server's cert so no
	// fixture bytes are needed.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	pemFile := filepath.Join(t.TempDir(), "ca.pem")
	der := srv.TLS.Certificates[0].Certificate[0]
	if err := os.WriteFile(pemFile,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	pool, err := caPool(pemFile)
	if err != nil || pool == nil {
		t.Fatalf("caPool(valid) = %v, %v want non-nil pool", pool, err)
	}

	if _, err := caPool(filepath.Join(t.TempDir(), "absent.pem")); err == nil {
		t.Fatal("caPool(missing) want error")
	}

	garbage := filepath.Join(t.TempDir(), "garbage.pem")
	if err := os.WriteFile(garbage, []byte("not a pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := caPool(garbage); err == nil ||
		!strings.Contains(err.Error(), "no certificates") {
		t.Fatalf("caPool(garbage) err=%v want 'no certificates'", err)
	}
}

func TestNewTLSClientBranches(t *testing.T) {
	garbage := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(garbage, []byte("not a pem"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Verify-TLS + unreadable CA bundle → New fails fast.
	_, err := New(Config{InsecureTLS: false, CAFile: garbage},
		prometheus.NewRegistry())
	if err == nil || !strings.Contains(err.Error(), "load CA") {
		t.Fatalf("New(verify, bad CA) err=%v want 'load CA'", err)
	}

	// InsecureTLS → the CA file is never consulted.
	p, err := New(Config{InsecureTLS: true, CAFile: garbage},
		prometheus.NewRegistry())
	if err != nil || p == nil {
		t.Fatalf("New(insecure) = %v, %v", p, err)
	}

	// An injected HTTPClient overrides all TLS material entirely.
	p, err = New(Config{
		HTTPClient: newAPIStub(t).srv.Client(),
		CAFile:     garbage, // must be ignored
	}, prometheus.NewRegistry())
	if err != nil || p.client == nil {
		t.Fatalf("New(injected client) = %v, %v", p, err)
	}
}

// pipeDial returns a DialSocket seam answering every command with
// `reply` over a synchronous net.Pipe (mirrors HAProxy: reply then
// close).
func pipeDial(reply string) func(context.Context, string) (net.Conn, error) {
	return func(_ context.Context, _ string) (net.Conn, error) {
		c1, c2 := net.Pipe()
		go func() {
			defer c2.Close()
			buf := make([]byte, 256)
			_, _ = c2.Read(buf) // consume the command — pipe is synchronous
			if reply != "" {
				_, _ = io.WriteString(c2, reply)
			}
		}()
		return c1, nil
	}
}

// captureSlog swaps the default slog logger for a text handler
// writing to the returned buffer — Cycle logs via the package
// logger, so this sees every line. Restored on test cleanup.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func TestRunTicksCycles(t *testing.T) {
	// The ticker branch: Interval small enough to fire within the
	// test deadline — cycles accumulate, then cancel stops Run.
	ha := newFakeHAProxy(t)
	p := fixture(t, ha, ModeDryRun, nil)
	p.cfg.Interval = 20 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()

	deadline := time.After(5 * time.Second)
	for testutil.ToFloat64(p.cycles.WithLabelValues("ok")) < 2 {
		select {
		case <-deadline:
			t.Fatal("ticker cycles never ran")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	cancel()
	select {
	case <-done:
	case <-deadline:
		t.Fatal("Run did not return after cancel")
	}
}

func TestNewTLSVerifyWithValidCA(t *testing.T) {
	// Verify-TLS + a readable CA bundle → RootCAs installed, New
	// succeeds (the remaining branch of the CA-load guard).
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	pemFile := filepath.Join(t.TempDir(), "ca.pem")
	der := srv.TLS.Certificates[0].Certificate[0]
	if err := os.WriteFile(pemFile,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := New(Config{InsecureTLS: false, CAFile: pemFile},
		prometheus.NewRegistry())
	if err != nil || p == nil {
		t.Fatalf("New(verify, valid CA) = %v, %v", p, err)
	}
}

func TestNewRegisterError(t *testing.T) {
	// A conflicting metric name in the registry makes New fail
	// instead of leaving half-registered collectors.
	reg := prometheus.NewRegistry()
	reg.MustRegister(prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_apiprober_backends",
	}))
	_, err := New(Config{HTTPClient: newAPIStub(t).srv.Client()}, reg)
	if err == nil || !strings.Contains(err.Error(), "register apiprober metrics") {
		t.Fatalf("New err=%v want 'register apiprober metrics'", err)
	}
}

func TestNewClonesDefaultTransport(t *testing.T) {
	// The production client must keep DefaultTransport's dialer /
	// keep-alive defaults — a bare &http.Transport{} has
	// IdleConnTimeout=0 (idle TLS conns pin buffers forever) and no
	// dialer. TLSClientConfig must survive the clone's field
	// assignment too.
	p, err := New(Config{InsecureTLS: true, TokenFile: ""},
		prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := p.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("client transport %T want *http.Transport", p.client.Transport)
	}
	if tr.DialContext == nil {
		t.Fatal("DialContext nil — transport not cloned from DefaultTransport")
	}
	if tr.IdleConnTimeout != 90*time.Second {
		t.Fatalf("IdleConnTimeout=%v want 90s", tr.IdleConnTimeout)
	}
	if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("TLSClientConfig lost on the cloned transport")
	}
}

// --- CompanionBackends + StaticBackends (api-backend-guard.sh merge) ---

// fixtureExt is fixture plus extra Config knobs the new paths need.
func fixtureExt(t *testing.T, ha *fakeHAProxy, mode string,
	tcpReachable map[string]bool, mutate func(*Config)) *Prober {
	t.Helper()
	stub := newAPIStub(t)
	cfg := Config{
		SocketPath:    ha.sockPath,
		BackendName:   "kube_apiserver",
		Mode:          mode,
		GapMin:        1000,
		FailCycles:    2,
		FrozenCycles:  2,
		RecoverCycles: 3,
		TokenFile:     "",
		HTTPClient:    stub.srv.Client(),
		TCPCheck: func(_ context.Context, addr string) error {
			if ok, found := tcpReachable[addr]; found && !ok {
				return errors.New("connect refused")
			}
			return nil
		},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	p, err := New(cfg, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	return p
}
