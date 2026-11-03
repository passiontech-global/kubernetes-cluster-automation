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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
type apiStub struct {
	srv     *httptest.Server
	mu      sync.Mutex
	cacheRV int64
	liveRV  int64
	fail    bool
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
		if a.fail {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		rv := a.liveRV
		if r.URL.Query().Get("resourceVersion") == "0" {
			rv = a.cacheRV
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
				return fmt.Errorf("connect refused")
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

func TestDiscoverParsesBackends(t *testing.T) {
	ha := newFakeHAProxy(t,
		[2]string{"hub1", "10.0.0.1:6443"},
		[2]string{"hub2", "10.0.0.2:6443"},
	)
	ha.disabled["hub2"] = true // pre-drained → MAINT in show stat
	p := fixture(t, ha, ModeDryRun, nil)

	backends, err := p.discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(backends) != 2 {
		t.Fatalf("backends=%v want 2", backends)
	}
	if backends[0].Name != "hub1" || backends[0].Addr != "10.0.0.1:6443" || !backends[0].up() {
		t.Fatalf("hub1 parsed wrong: %+v", backends[0])
	}
	if backends[1].up() {
		t.Fatalf("MAINT backend reported up()")
	}
}

func TestFrozenWedgeDisables(t *testing.T) {
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	p := fixture(t, ha, ModeEnforce, nil)

	// hub1: rv_cache frozen at 100 while rv_now advances — wedge.
	// Cycle 1 sets the baseline, cycles 2-3 accumulate frozen.
	bad.set(100, 200)
	good.set(500, 500)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}

	if !hasCmd(ha.commands(), "disable server kube_apiserver/hub1") {
		t.Fatalf("no disable command sent, cmds=%v", ha.commands())
	}
	if got := testutil.ToFloat64(p.enabled.WithLabelValues("hub1")); got != 0 {
		t.Fatalf("enabled{hub1}=%v want 0", got)
	}
	if got := testutil.ToFloat64(p.enabled.WithLabelValues("hub2")); got != 1 {
		t.Fatalf("enabled{hub2}=%v want 1", got)
	}
	if got := testutil.ToFloat64(p.actions.WithLabelValues("hub1", "disable")); got != 1 {
		t.Fatalf("actions disable=%v want 1", got)
	}
}

func TestGapWedgeDisables(t *testing.T) {
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	p := fixture(t, ha, ModeEnforce, nil)

	// gap = 5000 - 1000 = 4000 > GapMin(1000), cache still advancing.
	bad.set(1000, 5000)
	good.set(100, 100)
	p.Cycle(context.Background())
	bad.set(1100, 5200) // still >1000 gap
	good.set(110, 110)
	p.Cycle(context.Background()) // fail #2 → disable

	if !hasCmd(ha.commands(), "disable server kube_apiserver/hub1") {
		t.Fatalf("no disable for gap wedge, cmds=%v", ha.commands())
	}
}

func TestQueryFailDeadDisables(t *testing.T) {
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	p := fixture(t, ha, ModeEnforce, nil)

	bad.setFail(true)
	good.set(50, 50)
	p.Cycle(context.Background())
	p.Cycle(context.Background()) // qfail #2 → DEAD → disable

	if !hasCmd(ha.commands(), "disable server kube_apiserver/hub1") {
		t.Fatalf("no disable for dead backend, cmds=%v", ha.commands())
	}
	if got := testutil.ToFloat64(p.probeFailures.WithLabelValues("hub1", "query")); got < 2 {
		t.Fatalf("query probe failures=%v want >=2", got)
	}
}

func TestFenceKeepsLastUsableBackend(t *testing.T) {
	bad1 := newAPIStub(t)
	bad2 := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad1.addr()},
		[2]string{"hub2", bad2.addr()},
	)
	p := fixture(t, ha, ModeEnforce, nil)

	// Phase 1: hub1 wedges while hub2 is fresh → hub1 drains.
	bad1.set(100, 200)
	bad2.set(50, 50)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}
	if !hasCmd(ha.commands(), "disable server kube_apiserver/hub1") {
		t.Fatalf("hub1 not drained, cmds=%v", ha.commands())
	}

	// Phase 2: hub2 wedges too while hub1 is still wedged+drained —
	// no fresh backend remains → fence keeps hub2 serving.
	bad2.set(300, 400)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}
	if hasCmd(ha.commands(), "disable server kube_apiserver/hub2") {
		t.Fatalf("last usable backend disabled: %v", ha.commands())
	}
	if got := testutil.ToFloat64(p.actions.WithLabelValues("hub2", "fence_skip")); got < 1 {
		t.Fatalf("fence_skip=%v want >=1", got)
	}
}

func TestSimultaneousWedgeDrainsNothing(t *testing.T) {
	// Both backends wedge in the same cycles → fresh=0 → neither is
	// drained (the shell fence semantics: disabling any backend when
	// nothing fresh remains only takes the VIP down with it).
	bad1 := newAPIStub(t)
	bad2 := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad1.addr()},
		[2]string{"hub2", bad2.addr()},
	)
	p := fixture(t, ha, ModeEnforce, nil)

	bad1.set(100, 200)
	bad2.set(300, 400)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}
	if hasCmd(ha.commands(), "disable server") {
		t.Fatalf("backend disabled with no fresh peer: %v", ha.commands())
	}
}

func TestTCPUnreachableSkipped(t *testing.T) {
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	p := fixture(t, ha, ModeEnforce, map[string]bool{bad.addr(): false})
	bad.set(100, 200) // would wedge — but TCP down wins
	good.set(50, 50)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}

	if hasCmd(ha.commands(), "disable server kube_apiserver/hub1") {
		t.Fatalf("unreachable backend got disabled: %v", ha.commands())
	}
	if got := testutil.ToFloat64(p.probeFailures.WithLabelValues("hub1", "tcp")); got != 3 {
		t.Fatalf("tcp probe failures=%v want 3", got)
	}
}

func TestRecoveryReEnables(t *testing.T) {
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	p := fixture(t, ha, ModeEnforce, nil)

	bad.set(100, 200)
	good.set(50, 50)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	} // → drained

	// Backend recovers: cache advancing again + gap small.
	for i := 0; i < 3; i++ { // RecoverCycles
		bad.set(300+int64(i), 300)
		p.Cycle(context.Background())
	}

	if !hasCmd(ha.commands(), "enable server kube_apiserver/hub1") {
		t.Fatalf("no enable after recovery, cmds=%v", ha.commands())
	}
	// The enabled gauge reflects the next cycle's `show stat` status
	// (the cycle that issues enable still sees MAINT).
	bad.set(400, 300)
	p.Cycle(context.Background())
	if got := testutil.ToFloat64(p.enabled.WithLabelValues("hub1")); got != 1 {
		t.Fatalf("enabled{hub1}=%v want 1 after recovery", got)
	}
}

func TestDryRunTakesNoAction(t *testing.T) {
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	p := fixture(t, ha, ModeDryRun, nil)

	bad.set(100, 200)
	good.set(50, 50)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}

	for _, c := range ha.commands() {
		if !strings.HasPrefix(c, "show stat") {
			t.Fatalf("dry-run issued socket action: %v", ha.commands())
		}
	}
	if got := testutil.ToFloat64(p.actions.WithLabelValues("hub1", "dryrun_disable")); got != 1 {
		t.Fatalf("dryrun_disable=%v want 1", got)
	}
}

func TestDiscoverFailCounted(t *testing.T) {
	// Force a parse failure by serving garbage instead of CSV.
	p, err := New(Config{
		SocketPath:  "unused",
		BackendName: "kube_apiserver",
		DialSocket: func(_ context.Context, _ string) (net.Conn, error) {
			c1, c2 := net.Pipe()
			go func() {
				defer c2.Close()
				buf := make([]byte, 256)
				_, _ = c2.Read(buf) // consume "show stat" — pipe is synchronous
				_, _ = io.WriteString(c2, "garbage without header\n")
			}()
			return c1, nil
		},
		HTTPClient: newAPIStub(t).srv.Client(),
		TokenFile:  "",
	}, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	p.Cycle(context.Background())
	if got := testutil.ToFloat64(p.cycles.WithLabelValues("discover_fail")); got != 1 {
		t.Fatalf("discover_fail=%v want 1", got)
	}
}

func TestRVGapMetric(t *testing.T) {
	b := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", b.addr()},
		[2]string{"hub2", "127.0.0.1:1"},
	)
	p := fixture(t, ha, ModeDryRun, map[string]bool{"127.0.0.1:1": false})
	b.set(100, 900)
	p.Cycle(context.Background())
	if got := testutil.ToFloat64(p.rvGap.WithLabelValues("hub1")); got != 800 {
		t.Fatalf("rvGap=%v want 800", got)
	}
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

func TestVIPBackendFollowsDirectControllerState(t *testing.T) {
	ctrl1 := newAPIStub(t)
	ctrl2 := newAPIStub(t)
	// api_datahub_lb is a VIP entry (suffix "_lb") — its address is not a
	// valid HTTP server, verifying it is never directly probed for RV gap.
	ha := newFakeHAProxy(t,
		[2]string{"api_datahub_ctrl", ctrl1.addr()},
		[2]string{"api_datahub_lb", "127.0.0.1:1"},
		[2]string{"api_contabo_ctrl", ctrl2.addr()},
	)
	p := fixture(t, ha, ModeEnforce, nil)

	// Phase 1: ctrl2 wedges while ctrl1 stays fresh → both ctrl2 and
	// api_datahub_lb are disabled.
	ctrl1.set(500, 500)
	ctrl2.set(100, 3000)
	for i := 0; i < 2; i++ {
		p.Cycle(context.Background())
	}
	if !hasCmd(ha.commands(), "disable server kube_apiserver/api_contabo_ctrl") {
		t.Fatalf("expected api_contabo_ctrl disable, cmds=%v", ha.commands())
	}
	if !hasCmd(ha.commands(), "disable server kube_apiserver/api_datahub_lb") {
		t.Fatalf("expected api_datahub_lb disable alongside wedged ctrl, cmds=%v", ha.commands())
	}
	if got := testutil.ToFloat64(p.enabled.WithLabelValues("api_datahub_lb")); got != 0 {
		t.Fatalf("enabled{api_datahub_lb}=%v want 0", got)
	}

	// Phase 2: ctrl2 recovers for RecoverCycles (3) → both ctrl2 and
	// api_datahub_lb are re-enabled.
	ctrl2.set(500, 500)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}
	if !hasCmd(ha.commands(), "enable server kube_apiserver/api_contabo_ctrl") {
		t.Fatalf("expected api_contabo_ctrl enable, cmds=%v", ha.commands())
	}
	if !hasCmd(ha.commands(), "enable server kube_apiserver/api_datahub_lb") {
		t.Fatalf("expected api_datahub_lb enable after ctrl recovery, cmds=%v", ha.commands())
	}
	p.Cycle(context.Background())
	if got := testutil.ToFloat64(p.enabled.WithLabelValues("api_datahub_lb")); got != 1 {
		t.Fatalf("enabled{api_datahub_lb}=%v want 1", got)
	}
}

func countCmd(cmds []string, want string) int {
	n := 0
	for _, c := range cmds {
		if c == want {
			n++
		}
	}
	return n
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

func TestTCPPreflightRealDial(t *testing.T) {
	// No TCPCheck seam → the real TCP dial runs.
	p, err := New(Config{HTTPClient: newAPIStub(t).srv.Client()},
		prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := p.tcpPreflight(context.Background(), addr); err != nil {
		t.Fatalf("tcpPreflight(%s) err=%v want nil", addr, err)
	}
	ln.Close()
	// Nothing listens now — the dial must fail fast (conn refused).
	if err := p.tcpPreflight(context.Background(), addr); err == nil {
		t.Fatalf("tcpPreflight(%s) after close want error", addr)
	}
}

func TestListRV(t *testing.T) {
	var gotAuth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"metadata":{"resourceVersion":"42"}}`)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")

	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("tok-abc\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// HTTPClient==nil exercises the production path: TLS client built
	// from InsecureTLS + per-query bearer token read.
	p, err := New(Config{InsecureTLS: true, TokenFile: tokenFile},
		prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	rv, ok := p.listRV(context.Background(), addr, "/api/v1/nodes?limit=1")
	if !ok || rv != 42 {
		t.Fatalf("listRV = %d, %v want 42, true", rv, ok)
	}
	if gotAuth != "Bearer tok-abc" {
		t.Fatalf("Authorization=%q want %q", gotAuth, "Bearer tok-abc")
	}

	// Unreadable token file → query fails closed. Cycle refreshes
	// p.eff from cfg every round — refresh here to pick the change up.
	p.cfg.TokenFile = filepath.Join(t.TempDir(), "absent")
	p.refreshGuard()
	if rv, ok := p.listRV(context.Background(), addr, "/x"); ok || rv != 0 {
		t.Fatalf("listRV(bad token) = %d, %v want 0, false", rv, ok)
	}
}

func TestListRVFailureModes(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"non-200", http.StatusServiceUnavailable, `{"metadata":{"resourceVersion":"1"}}`},
		{"not-json", http.StatusOK, `this is not json`},
		{"non-numeric-rv", http.StatusOK, `{"metadata":{"resourceVersion":"abc"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer srv.Close()
			p, err := New(Config{InsecureTLS: true, TokenFile: ""},
				prometheus.NewRegistry())
			if err != nil {
				t.Fatal(err)
			}
			rv, ok := p.listRV(context.Background(),
				strings.TrimPrefix(srv.URL, "https://"), "/x")
			if ok || rv != 0 {
				t.Fatalf("listRV = %d, %v want 0, false", rv, ok)
			}
		})
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

func TestHaproxyServerReplyHandling(t *testing.T) {
	// Non-empty reply → error containing the HAProxy error text.
	p, err := New(Config{
		DialSocket: pipeDial("No such server\n"),
		HTTPClient: newAPIStub(t).srv.Client(),
	}, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	err = p.haproxyServer(context.Background(), "disable", "hub1", false)
	if err == nil || !strings.Contains(err.Error(), "No such server") {
		t.Fatalf("haproxyServer err=%v want reply text in error", err)
	}

	// tolerateMissingPrimary downgrades the primary's "No such server"
	// to a no-op — the contract for names known-absent from the
	// primary backend (static-only API_BACKENDS entries).
	p, err = New(Config{
		DialSocket: pipeDial("No such server\n"),
		HTTPClient: newAPIStub(t).srv.Client(),
	}, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.haproxyServer(context.Background(), "disable", "ghost", true); err != nil {
		t.Fatalf("haproxyServer tolerated-missing err=%v want nil", err)
	}
	// Other reply text is still an error even when tolerated.
	p, err = New(Config{
		DialSocket: pipeDial("permission denied\n"),
		HTTPClient: newAPIStub(t).srv.Client(),
	}, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.haproxyServer(context.Background(), "disable", "ghost", true); err == nil {
		t.Fatal("haproxyServer tolerated non-'No such server' reply — want error")
	}

	// Empty reply → success (HAProxy >= 2.x semantics).
	p, err = New(Config{
		DialSocket: pipeDial(""),
		HTTPClient: newAPIStub(t).srv.Client(),
	}, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.haproxyServer(context.Background(), "disable", "hub1", false); err != nil {
		t.Fatalf("haproxyServer empty-reply err=%v want nil", err)
	}
}

func TestBackendHelpers(t *testing.T) {
	cases := []struct {
		b            backend
		up, mnt, vip bool
	}{
		{backend{Name: "hub1", Status: "UP"}, true, false, false},
		{backend{Name: "hub1", Status: "UP 2/3"}, true, false, false},
		{backend{Name: "hub1", Status: "DOWN"}, false, false, false},
		{backend{Name: "hub1", Status: "MAINT"}, false, true, false},
		{backend{Name: "hub1", Status: "MAINT(via)"}, false, true, false},
		{backend{Name: "api_datahub_lb", Status: "UP"}, true, false, true},
		{backend{Name: "api_datahub_lb", Status: "MAINT"}, false, true, true},
	}
	for _, tc := range cases {
		if got := tc.b.up(); got != tc.up {
			t.Errorf("%+v.up()=%v want %v", tc.b, got, tc.up)
		}
		if got := tc.b.maint(); got != tc.mnt {
			t.Errorf("%+v.maint()=%v want %v", tc.b, got, tc.mnt)
		}
		if got := tc.b.vip(); got != tc.vip {
			t.Errorf("%+v.vip()=%v want %v", tc.b, got, tc.vip)
		}
	}
}

func TestReApplyDisableAfterHAProxyRestart(t *testing.T) {
	// HAProxy restart forgets runtime disables — a backend we marked
	// drained that shows UP again in `show stat` must get the disable
	// re-applied, not be treated as newly stale.
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	p := fixture(t, ha, ModeEnforce, nil)

	bad.set(100, 200)
	good.set(50, 50)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}
	if countCmd(ha.commands(), "disable server kube_apiserver/hub1") != 1 {
		t.Fatalf("expected 1 disable, cmds=%v", ha.commands())
	}

	// Simulate the restart: HAProxy reports hub1 UP again while the
	// prober's in-memory drained flag persists.
	ha.mu.Lock()
	ha.disabled["hub1"] = false
	ha.mu.Unlock()
	p.Cycle(context.Background())

	if got := countCmd(ha.commands(), "disable server kube_apiserver/hub1"); got != 2 {
		t.Fatalf("re-applied disable count=%d want 2, cmds=%v", got, ha.commands())
	}
}

func TestEnableFailureKeepsDrained(t *testing.T) {
	// If `enable server` is rejected on the socket, the backend must
	// stay marked drained — clearing the flag would forget the wedge.
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	p := fixture(t, ha, ModeEnforce, nil)

	bad.set(100, 200)
	good.set(50, 50)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}
	if !p.states["hub1"].drained {
		t.Fatal("hub1 not marked drained after wedge")
	}

	ha.mu.Lock()
	ha.failReply = map[string]string{"enable server": "No such server\n"}
	ha.mu.Unlock()
	for i := 0; i < 4; i++ { // >= RecoverCycles
		bad.set(300+int64(i), 300)
		p.Cycle(context.Background())
	}

	if !hasCmd(ha.commands(), "enable server kube_apiserver/hub1") {
		t.Fatalf("enable was never attempted, cmds=%v", ha.commands())
	}
	if !p.states["hub1"].drained {
		t.Fatal("drained flag cleared despite failed enable")
	}
	if got := testutil.ToFloat64(p.actions.WithLabelValues("hub1", "enable")); got != 0 {
		t.Fatalf("actions enable=%v want 0 (all enables failed)", got)
	}
	if got := testutil.ToFloat64(p.enabled.WithLabelValues("hub1")); got != 0 {
		t.Fatalf("enabled{hub1}=%v want 0", got)
	}
}

func TestExternalMaintBackendRecoversToEnable(t *testing.T) {
	// Backend found already MAINT (manual drain or agent restart lost
	// the drained flag): fresh probes still accumulate ok-cycles and
	// re-enable it after RecoverCycles.
	fresh1 := newAPIStub(t)
	fresh2 := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", fresh1.addr()},
		[2]string{"hub2", fresh2.addr()},
	)
	ha.disabled["hub1"] = true // externally drained → MAINT in show stat
	p := fixture(t, ha, ModeEnforce, nil)

	fresh1.set(50, 50)
	fresh2.set(60, 60)
	for i := 0; i < 3; i++ { // RecoverCycles
		p.Cycle(context.Background())
	}

	if !hasCmd(ha.commands(), "enable server kube_apiserver/hub1") {
		t.Fatalf("no enable for MAINT backend, cmds=%v", ha.commands())
	}
	if got := testutil.ToFloat64(p.actions.WithLabelValues("hub1", "enable")); got != 1 {
		t.Fatalf("actions enable=%v want 1", got)
	}
}

func TestVIPKeptWhenNoFreshController(t *testing.T) {
	// sig14b least-bad: a wedged sole controller must NOT drag the VIP
	// down — with fresh==0 the VIP is the only remaining path.
	ctrl := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"api_datahub_ctrl", ctrl.addr()},
		[2]string{"api_datahub_lb", "127.0.0.1:1"},
	)
	p := fixture(t, ha, ModeEnforce, nil)

	ctrl.set(100, 200) // frozen wedge
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}

	if hasCmd(ha.commands(), "disable server kube_apiserver/api_datahub_lb") {
		t.Fatalf("VIP disabled with no fresh controller: %v", ha.commands())
	}
	if got := testutil.ToFloat64(p.enabled.WithLabelValues("api_datahub_lb")); got != 1 {
		t.Fatalf("enabled{api_datahub_lb}=%v want 1 (least-bad)", got)
	}
}

func TestVIPMaintReEnabledWhenControllersHealthy(t *testing.T) {
	// A VIP found in MAINT while all direct controllers are healthy
	// gets re-enabled — same reconcile path as external drains.
	ctrl := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"api_datahub_ctrl", ctrl.addr()},
		[2]string{"api_datahub_lb", "127.0.0.1:1"},
	)
	ha.disabled["api_datahub_lb"] = true
	p := fixture(t, ha, ModeEnforce, nil)

	ctrl.set(50, 50)
	p.Cycle(context.Background())

	if !hasCmd(ha.commands(), "enable server kube_apiserver/api_datahub_lb") {
		t.Fatalf("no enable for healthy VIP, cmds=%v", ha.commands())
	}
}

// errConn is a net.Conn whose Read/Write fail with the configured
// errors — exercises socketCmd's write/read failure paths without a
// real socket.
type errConn struct {
	readErr  error
	writeErr error
}

func (c errConn) Read([]byte) (int, error)         { return 0, c.readErr }
func (c errConn) Write([]byte) (int, error)        { return 0, c.writeErr }
func (c errConn) Close() error                     { return nil }
func (c errConn) LocalAddr() net.Addr              { return nil }
func (c errConn) RemoteAddr() net.Addr             { return nil }
func (c errConn) SetDeadline(time.Time) error      { return nil }
func (c errConn) SetReadDeadline(time.Time) error  { return nil }
func (c errConn) SetWriteDeadline(time.Time) error { return nil }

// rtFunc adapts a func to http.RoundTripper for transport error
// injection.
type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// errBody is a response body that fails on Read.
type errBody struct{}

func (errBody) Read([]byte) (int, error) { return 0, errors.New("body read boom") }
func (errBody) Close() error             { return nil }

func TestSocketCmdFailureModes(t *testing.T) {
	boom := errors.New("socket boom")

	t.Run("dial error", func(t *testing.T) {
		p, err := New(Config{
			DialSocket: func(context.Context, string) (net.Conn, error) {
				return nil, boom
			},
			HTTPClient: newAPIStub(t).srv.Client(),
		}, prometheus.NewRegistry())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.socketCmd(context.Background(), "show stat"); err == nil {
			t.Fatal("socketCmd with failing dial want error")
		}
	})

	t.Run("write error", func(t *testing.T) {
		p, err := New(Config{
			DialSocket: func(context.Context, string) (net.Conn, error) {
				return errConn{writeErr: boom}, nil
			},
			HTTPClient: newAPIStub(t).srv.Client(),
		}, prometheus.NewRegistry())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.socketCmd(context.Background(), "show stat"); err == nil {
			t.Fatal("socketCmd with failing write want error")
		}
	})

	t.Run("read error", func(t *testing.T) {
		p, err := New(Config{
			DialSocket: func(context.Context, string) (net.Conn, error) {
				return errConn{readErr: boom}, nil
			},
			HTTPClient: newAPIStub(t).srv.Client(),
		}, prometheus.NewRegistry())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.socketCmd(context.Background(), "show stat"); err == nil {
			t.Fatal("socketCmd with failing read want error")
		}
	})
}

func TestDiscoverMalformedStat(t *testing.T) {
	mkProber := func(t *testing.T, reply string) *Prober {
		t.Helper()
		p, err := New(Config{
			DialSocket:  pipeDial(reply),
			BackendName: "kube_apiserver",
			HTTPClient:  newAPIStub(t).srv.Client(),
		}, prometheus.NewRegistry())
		if err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("empty reply means no header", func(t *testing.T) {
		_, err := mkProber(t, "").discover(context.Background())
		if err == nil || !strings.Contains(err.Error(), "no CSV header") {
			t.Fatalf("discover err=%v want 'no CSV header'", err)
		}
	})

	t.Run("short row is skipped not fatal", func(t *testing.T) {
		// Row shorter than the header: get() hits the i>=len(fields)
		// guard and returns "" for addr. One bad row logs + skips —
		// it must not fail the whole scan.
		csv := "# pxname,svname,status,addr\nkube_apiserver,hub1\nkube_apiserver,hub2,UP,10.0.0.2:6443\n"
		backends, err := mkProber(t, csv).discover(context.Background())
		if err != nil {
			t.Fatalf("discover err=%v want nil (row skipped)", err)
		}
		if len(backends) != 1 || backends[0].Name != "hub2" {
			t.Fatalf("backends=%v want [hub2]", backends)
		}
	})
}

func TestSocketFlapAcrossCycles(t *testing.T) {
	// The api-local-lb admin socket can be absent at agent start and
	// appear later (socket appears mid-run): discover fails closed and
	// recovers on the next cycle.
	ha := newFakeHAProxy(t, [2]string{"hub1", "127.0.0.1:1"})
	var sockDown atomic.Bool
	sockDown.Store(true)
	p, err := New(Config{
		SocketPath:  ha.sockPath,
		BackendName: "kube_apiserver",
		DialSocket: func(ctx context.Context, path string) (net.Conn, error) {
			if sockDown.Load() {
				return nil, errors.New("admin socket gone")
			}
			d := net.Dialer{Timeout: time.Second}
			return d.DialContext(ctx, "unix", path)
		},
		HTTPClient: newAPIStub(t).srv.Client(),
	}, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}

	p.Cycle(context.Background())
	if got := testutil.ToFloat64(p.cycles.WithLabelValues("discover_fail")); got != 1 {
		t.Fatalf("discover_fail=%v want 1 while socket absent", got)
	}
	if got := testutil.ToFloat64(p.backendCount); got != 0 {
		t.Fatalf("backendCount=%v want 0", got)
	}

	// api-local-lb installed mid-run → the next cycle discovers it.
	sockDown.Store(false)
	p.Cycle(context.Background())
	if got := testutil.ToFloat64(p.cycles.WithLabelValues("ok")); got != 1 {
		t.Fatalf("cycles ok=%v want 1 after socket appeared", got)
	}
	if got := testutil.ToFloat64(p.backendCount); got != 1 {
		t.Fatalf("backendCount=%v want 1", got)
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

func TestMissingSocketGatesDiscovery(t *testing.T) {
	// api-local-lb is worker-only — on controllers the admin
	// socket legitimately never exists. A missing socket is a
	// gated cycle: no error, cycles{no_socket}, and the absence is
	// logged ONCE per state-change, not once per cycle.
	buf := captureSlog(t)
	p, err := New(Config{
		SocketPath:  filepath.Join(t.TempDir(), "absent.sock"),
		BackendName: "kube_apiserver",
		HTTPClient:  newAPIStub(t).srv.Client(),
	}, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}
	if got := testutil.ToFloat64(p.cycles.WithLabelValues("no_socket")); got != 3 {
		t.Fatalf("no_socket=%v want 3", got)
	}
	if got := testutil.ToFloat64(p.cycles.WithLabelValues("discover_fail")); got != 0 {
		t.Fatalf("discover_fail=%v want 0 — a missing socket is gated, not an error", got)
	}
	logs := buf.String()
	if strings.Contains(logs, "level=ERROR") {
		t.Fatalf("missing socket logged ERROR lines:\n%s", logs)
	}
	if n := strings.Count(logs, "socket absent"); n != 1 {
		t.Fatalf("socket-absent info lines=%d want 1 (log-once latch):\n%s", n, logs)
	}
}

func TestSocketGateRecoversWhenSocketAppears(t *testing.T) {
	// The flip side of the gate: api-local-lb installed (or the
	// host re-roled to worker) mid-run — the socket appears, one
	// informational line marks the transition back, and discovery
	// resumes on the same cycle.
	buf := captureSlog(t)
	stub := newAPIStub(t)
	sockPath := filepath.Join(t.TempDir(), "haproxy.sock")
	p, err := New(Config{
		SocketPath:  sockPath,
		BackendName: "kube_apiserver",
		HTTPClient:  stub.srv.Client(),
		TCPCheck:    func(context.Context, string) error { return nil },
	}, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}

	p.Cycle(context.Background()) // absent → gated
	if got := testutil.ToFloat64(p.cycles.WithLabelValues("no_socket")); got != 1 {
		t.Fatalf("no_socket=%v want 1", got)
	}

	// The socket appears: a real listener at the configured path
	// serving `show stat` (same fake, bound manually — the helper
	// picks its own tempdir path).
	f := &fakeHAProxy{
		servers:  map[string]string{"hub1": stub.addr()},
		order:    []string{"hub1"},
		disabled: map[string]bool{},
	}
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.handle(conn)
		}
	}()

	p.Cycle(context.Background())
	if got := testutil.ToFloat64(p.cycles.WithLabelValues("ok")); got != 1 {
		t.Fatalf("cycles ok=%v want 1 after socket appeared", got)
	}
	if got := testutil.ToFloat64(p.backendCount); got != 1 {
		t.Fatalf("backendCount=%v want 1", got)
	}
	logs := buf.String()
	if strings.Contains(logs, "level=ERROR") {
		t.Fatalf("socket appear cycle logged ERROR:\n%s", logs)
	}
	if n := strings.Count(logs, "socket absent"); n != 1 {
		t.Fatalf("socket-absent info lines=%d want 1:\n%s", n, logs)
	}
	if n := strings.Count(logs, "socket present"); n != 1 {
		t.Fatalf("socket-present info lines=%d want 1:\n%s", n, logs)
	}
}

func TestBrokenSocketStillErrors(t *testing.T) {
	// The gate is socket-EXISTENCE, not "path fails": a path that
	// exists but is not a socket (or is refused/unreadable) is a
	// real discovery failure — the dial errors, discover_fail
	// counts and the ERROR line stays.
	buf := captureSlog(t)
	sockPath := filepath.Join(t.TempDir(), "not-a-socket")
	if err := os.WriteFile(sockPath, []byte("regular file"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := New(Config{
		SocketPath:  sockPath,
		BackendName: "kube_apiserver",
		HTTPClient:  newAPIStub(t).srv.Client(),
	}, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	p.Cycle(context.Background())
	if got := testutil.ToFloat64(p.cycles.WithLabelValues("discover_fail")); got != 1 {
		t.Fatalf("discover_fail=%v want 1 — existing-but-broken socket is a real error", got)
	}
	if got := testutil.ToFloat64(p.cycles.WithLabelValues("no_socket")); got != 0 {
		t.Fatalf("no_socket=%v want 0", got)
	}
	if logs := buf.String(); !strings.Contains(logs, "level=ERROR") {
		t.Fatalf("broken socket produced no ERROR line:\n%s", logs)
	}
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

func TestCycleReturnsOnCancelledCtx(t *testing.T) {
	// Discover succeeds, then the backend loop bails on ctx.Err() —
	// the per-backend check, not a discover failure. The pipeDial
	// seam ignores ctx so `show stat` still answers.
	ha := newFakeHAProxy(t, [2]string{"hub1", "127.0.0.1:1"})
	p := fixture(t, ha, ModeDryRun, nil)
	p.cfg.DialSocket = pipeDial(ha.statCSV())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.Cycle(ctx)

	if got := testutil.ToFloat64(p.cycles.WithLabelValues("ok")); got != 1 {
		t.Fatalf("cycles ok=%v want 1 (discover completed)", got)
	}
}

func TestHaproxyServerSocketError(t *testing.T) {
	// A dial failure inside socketCmd propagates out of haproxyServer.
	p, err := New(Config{
		DialSocket: func(context.Context, string) (net.Conn, error) {
			return nil, errors.New("socket gone")
		},
		HTTPClient: newAPIStub(t).srv.Client(),
	}, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.haproxyServer(context.Background(), "disable", "hub1", false); err == nil {
		t.Fatal("haproxyServer with dead socket want error")
	}
}

func TestListRVTransportErrors(t *testing.T) {
	boom := errors.New("transport boom")

	t.Run("bad url", func(t *testing.T) {
		p, err := New(Config{
			HTTPClient: newAPIStub(t).srv.Client(),
		}, prometheus.NewRegistry())
		if err != nil {
			t.Fatal(err)
		}
		// A space in the host makes http.NewRequest fail before any
		// dial — covers the request-build error return.
		if rv, ok := p.listRV(context.Background(), "bad addr", "/x"); ok || rv != 0 {
			t.Fatalf("listRV(bad url) = %d, %v want 0, false", rv, ok)
		}
	})

	t.Run("roundtrip error", func(t *testing.T) {
		p, err := New(Config{
			HTTPClient: &http.Client{Transport: rtFunc(
				func(*http.Request) (*http.Response, error) { return nil, boom })},
		}, prometheus.NewRegistry())
		if err != nil {
			t.Fatal(err)
		}
		if rv, ok := p.listRV(context.Background(), "127.0.0.1:6443", "/x"); ok || rv != 0 {
			t.Fatalf("listRV(transport err) = %d, %v want 0, false", rv, ok)
		}
	})

	t.Run("body read error", func(t *testing.T) {
		p, err := New(Config{
			HTTPClient: &http.Client{Transport: rtFunc(
				func(*http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       errBody{},
					}, nil
				})},
		}, prometheus.NewRegistry())
		if err != nil {
			t.Fatal(err)
		}
		if rv, ok := p.listRV(context.Background(), "127.0.0.1:6443", "/x"); ok || rv != 0 {
			t.Fatalf("listRV(body err) = %d, %v want 0, false", rv, ok)
		}
	})
}

func TestListRVParseAndTimeout(t *testing.T) {
	// Inject each server client so the token-file branch is skipped —
	// the failures under test happen after the response arrives.
	mkProber := func(t *testing.T, body string) (*Prober, string) {
		t.Helper()
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			io.WriteString(w, body)
		}))
		t.Cleanup(srv.Close)
		p, err := New(Config{HTTPClient: srv.Client()}, prometheus.NewRegistry())
		if err != nil {
			t.Fatal(err)
		}
		return p, strings.TrimPrefix(srv.URL, "https://")
	}

	t.Run("unparseable json", func(t *testing.T) {
		p, addr := mkProber(t, `this is not json`)
		if rv, ok := p.listRV(context.Background(), addr, "/x"); ok || rv != 0 {
			t.Fatalf("listRV(not json) = %d, %v want 0, false", rv, ok)
		}
	})

	t.Run("non numeric rv", func(t *testing.T) {
		p, addr := mkProber(t, `{"metadata":{"resourceVersion":"abc"}}`)
		if rv, ok := p.listRV(context.Background(), addr, "/x"); ok || rv != 0 {
			t.Fatalf("listRV(non-numeric rv) = %d, %v want 0, false", rv, ok)
		}
	})

	t.Run("non-200 with injected client", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer srv.Close()
		p, err := New(Config{HTTPClient: srv.Client()}, prometheus.NewRegistry())
		if err != nil {
			t.Fatal(err)
		}
		if rv, ok := p.listRV(context.Background(),
			strings.TrimPrefix(srv.URL, "https://"), "/x"); ok || rv != 0 {
			t.Fatalf("listRV(503) = %d, %v want 0, false", rv, ok)
		}
	})

	t.Run("query timeout", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-r.Context().Done() // hang until the client gives up
		}))
		defer srv.Close()
		p, err := New(Config{HTTPClient: srv.Client()}, prometheus.NewRegistry())
		if err != nil {
			t.Fatal(err)
		}
		p.cfg.QueryTimeout = 30 * time.Millisecond
		if rv, ok := p.listRV(context.Background(),
			strings.TrimPrefix(srv.URL, "https://"), "/x"); ok || rv != 0 {
			t.Fatalf("listRV(timeout) = %d, %v want 0, false", rv, ok)
		}
	})
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

func TestDryRunEnableOnRecovery(t *testing.T) {
	// Dry-run recovery: a MAINT backend with RecoverCycles fresh
	// probes logs "would enable" without touching the socket.
	fresh1 := newAPIStub(t)
	fresh2 := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", fresh1.addr()},
		[2]string{"hub2", fresh2.addr()},
	)
	ha.disabled["hub1"] = true // externally drained
	p := fixture(t, ha, ModeDryRun, nil)

	fresh1.set(50, 50)
	fresh2.set(60, 60)
	for i := 0; i < 3; i++ { // RecoverCycles
		p.Cycle(context.Background())
	}

	if got := testutil.ToFloat64(p.actions.WithLabelValues("hub1", "dryrun_enable")); got < 1 {
		t.Fatalf("dryrun_enable=%v want >=1", got)
	}
	for _, c := range ha.commands() {
		if !strings.HasPrefix(c, "show stat") {
			t.Fatalf("dry-run issued socket action: %v", ha.commands())
		}
	}
}

func TestEnableAfterHAProxyRestartCountsFresh(t *testing.T) {
	// Backend we drained shows UP again (HAProxy restart forgot the
	// disable) AND its probes recover: the successful enable path
	// counts the backend fresh again.
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	p := fixture(t, ha, ModeEnforce, nil)

	bad.set(100, 200)
	good.set(50, 50)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}
	if !p.states["hub1"].drained {
		t.Fatal("hub1 not drained after wedge")
	}

	// HAProxy restart forgets the runtime disable → hub1 reports UP
	// again; its probes recover at the same time.
	ha.mu.Lock()
	ha.disabled["hub1"] = false
	ha.mu.Unlock()
	for i := 0; i < 3; i++ {
		bad.set(300+int64(i), 300)
		p.Cycle(context.Background())
	}

	if got := testutil.ToFloat64(p.actions.WithLabelValues("hub1", "enable")); got != 1 {
		t.Fatalf("actions enable=%v want 1", got)
	}
	if p.states["hub1"].drained {
		t.Fatal("drained flag still set after successful enable")
	}
}

func TestDrainDisableFailureLeavesUndrained(t *testing.T) {
	// A wedged backend whose `disable server` is rejected stays
	// un-drained — the guard must not record an action that never
	// happened.
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	ha.failReply = map[string]string{"disable server": "socket read only\n"}
	p := fixture(t, ha, ModeEnforce, nil)

	bad.set(100, 200)
	good.set(50, 50)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}

	if !hasCmd(ha.commands(), "disable server kube_apiserver/hub1") {
		t.Fatalf("disable never attempted, cmds=%v", ha.commands())
	}
	if p.states["hub1"].drained {
		t.Fatal("drained flag set despite failed disable")
	}
	if got := testutil.ToFloat64(p.actions.WithLabelValues("hub1", "disable")); got != 0 {
		t.Fatalf("actions disable=%v want 0 (all disables failed)", got)
	}
}

func TestReApplyDisableFailure(t *testing.T) {
	// Drained backend shows UP again after a HAProxy restart while
	// still wedged → re-apply is attempted; when the socket rejects
	// it, the error branch is taken and drained stays set.
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	p := fixture(t, ha, ModeEnforce, nil)

	bad.set(100, 200)
	good.set(50, 50)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}
	if countCmd(ha.commands(), "disable server kube_apiserver/hub1") != 1 {
		t.Fatalf("expected 1 disable, cmds=%v", ha.commands())
	}

	// HAProxy restart forgets the disable AND the socket now rejects
	// further disables; the backend is still wedged → re-apply fails.
	ha.mu.Lock()
	ha.disabled["hub1"] = false
	ha.failReply = map[string]string{"disable server": "permission denied\n"}
	ha.mu.Unlock()
	p.Cycle(context.Background())

	if got := countCmd(ha.commands(), "disable server kube_apiserver/hub1"); got != 2 {
		t.Fatalf("re-apply attempts=%d want 2, cmds=%v", got, ha.commands())
	}
	if !p.states["hub1"].drained {
		t.Fatal("drained flag cleared despite failed re-apply")
	}
	if got := testutil.ToFloat64(p.actions.WithLabelValues("hub1", "disable")); got != 1 {
		t.Fatalf("actions disable=%v want 1 (re-apply failed)", got)
	}
}

func TestVIPDisableFailureLeavesUPEnabled(t *testing.T) {
	// A wedged controller triggers a VIP disable, but the socket
	// rejects it — the VIP must keep serving (enabled stays 1).
	ctrl1 := newAPIStub(t)
	ctrl2 := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"api_datahub_ctrl", ctrl1.addr()},
		[2]string{"api_datahub_lb", "127.0.0.1:1"},
		[2]string{"api_contabo_ctrl", ctrl2.addr()},
	)
	ha.failReply = map[string]string{"disable server": "permission denied\n"}
	p := fixture(t, ha, ModeEnforce, nil)

	ctrl1.set(500, 500)
	ctrl2.set(100, 3000)
	for i := 0; i < 2; i++ {
		p.Cycle(context.Background())
	}

	if !hasCmd(ha.commands(), "disable server kube_apiserver/api_datahub_lb") {
		t.Fatalf("VIP disable never attempted, cmds=%v", ha.commands())
	}
	if got := testutil.ToFloat64(p.actions.WithLabelValues("api_datahub_lb", "disable")); got != 0 {
		t.Fatalf("VIP actions disable=%v want 0 (disable failed)", got)
	}
	if got := testutil.ToFloat64(p.enabled.WithLabelValues("api_datahub_lb")); got != 1 {
		t.Fatalf("enabled{api_datahub_lb}=%v want 1 (still serving)", got)
	}
	if p.states["api_datahub_lb"].drained {
		t.Fatal("VIP drained flag set despite failed disable")
	}
}

func TestVIPEnableFailure(t *testing.T) {
	// A MAINT VIP with healthy controllers gets an enable attempt;
	// when the socket rejects it the VIP stays MAINT — no action
	// recorded, flag unchanged.
	ctrl := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"api_datahub_ctrl", ctrl.addr()},
		[2]string{"api_datahub_lb", "127.0.0.1:1"},
	)
	ha.disabled["api_datahub_lb"] = true
	ha.failReply = map[string]string{"enable server": "permission denied\n"}
	p := fixture(t, ha, ModeEnforce, nil)

	ctrl.set(50, 50)
	p.Cycle(context.Background())

	if !hasCmd(ha.commands(), "enable server kube_apiserver/api_datahub_lb") {
		t.Fatalf("VIP enable never attempted, cmds=%v", ha.commands())
	}
	if got := testutil.ToFloat64(p.actions.WithLabelValues("api_datahub_lb", "enable")); got != 0 {
		t.Fatalf("VIP actions enable=%v want 0 (enable failed)", got)
	}
	if got := testutil.ToFloat64(p.enabled.WithLabelValues("api_datahub_lb")); got != 0 {
		t.Fatalf("enabled{api_datahub_lb}=%v want 0 (still MAINT)", got)
	}
}

func TestVIPDryRunTransitions(t *testing.T) {
	// Dry-run VIP transitions: wedge → dryrun_disable (which marks
	// drained in memory), recovery → dryrun_enable. No real socket
	// action is ever issued.
	ctrl1 := newAPIStub(t)
	ctrl2 := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"api_datahub_ctrl", ctrl1.addr()},
		[2]string{"api_datahub_lb", "127.0.0.1:1"},
		[2]string{"api_contabo_ctrl", ctrl2.addr()},
	)
	p := fixture(t, ha, ModeDryRun, nil)

	ctrl1.set(500, 500)
	ctrl2.set(100, 3000)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}
	if got := testutil.ToFloat64(p.actions.WithLabelValues("api_datahub_lb", "dryrun_disable")); got != 1 {
		t.Fatalf("VIP dryrun_disable=%v want 1", got)
	}

	// Controllers healthy again → the (in-memory) drained VIP is
	// re-enabled in dry-run terms.
	ctrl2.set(500, 500)
	for i := 0; i < 4; i++ { // RecoverCycles=3 for the direct ctrl
		p.Cycle(context.Background())
	}
	if got := testutil.ToFloat64(p.actions.WithLabelValues("api_datahub_lb", "dryrun_enable")); got != 1 {
		t.Fatalf("VIP dryrun_enable=%v want 1", got)
	}
	for _, c := range ha.commands() {
		if !strings.HasPrefix(c, "show stat") {
			t.Fatalf("dry-run issued socket action: %v", ha.commands())
		}
	}
}

// --- watchdog state files (module 34 backward-compat contract) ---

// gapFilePath/staleFilePath name the compat files for a backend addr.
func gapFilePath(dir, addr string) string {
	return filepath.Join(dir, "apibe-gap-"+dashedIP(addr))
}
func staleFilePath(dir, addr string) string {
	return filepath.Join(dir, "state-apiserver-backend-stale-"+dashedIP(addr))
}

func fileContent(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func TestWatchdogGapFileWritten(t *testing.T) {
	stub := newAPIStub(t)
	ha := newFakeHAProxy(t, [2]string{"hub1", stub.addr()})
	p := fixture(t, ha, ModeDryRun, nil)
	p.cfg.WatchdogStateDir = t.TempDir()

	stub.set(100, 900) // gap 800 — fresh (under GapMin)
	p.Cycle(context.Background())

	if got := fileContent(t, gapFilePath(p.cfg.WatchdogStateDir, stub.addr())); got != "800\n" {
		t.Fatalf("gap file=%q want %q", got, "800\n")
	}
	if _, err := os.Stat(staleFilePath(p.cfg.WatchdogStateDir, stub.addr())); !os.IsNotExist(err) {
		t.Fatal("stale latch exists on a fresh backend")
	}

	// Next cycle with a different gap → file tracks the latest probe.
	stub.set(200, 600)
	p.Cycle(context.Background())
	if got := fileContent(t, gapFilePath(p.cfg.WatchdogStateDir, stub.addr())); got != "400\n" {
		t.Fatalf("gap file=%q want %q", got, "400\n")
	}
}

func TestWatchdogStaleLatchEnterExit(t *testing.T) {
	bad := newAPIStub(t)
	ha := newFakeHAProxy(t, [2]string{"hub1", bad.addr()})
	p := fixture(t, ha, ModeDryRun, nil)
	dir := t.TempDir()
	p.cfg.WatchdogStateDir = dir
	latch := staleFilePath(dir, bad.addr())

	// gap > GapMin for FailCycles cycles → stale → latch created
	// (latching is independent of the dry-run drain fence).
	bad.set(100, 5000)
	p.Cycle(context.Background())
	p.Cycle(context.Background())
	fi, err := os.Stat(latch)
	if err != nil {
		t.Fatalf("stale latch not created: %v", err)
	}
	if fi.Size() == 0 {
		t.Fatal("stale latch empty — want epoch content")
	}
	if _, err := strconv.ParseInt(strings.TrimSpace(fileContent(t, latch)), 10, 64); err != nil {
		t.Fatalf("stale latch content not an epoch: %v", err)
	}

	// Fresh cycles < RecoverCycles → latch survives (shell hysteresis:
	// state_exit only after RECOVER_CYCLES consecutive fresh runs —
	// one lucky probe must not unblock 06's upstream gate).
	bad.set(60, 60)
	p.Cycle(context.Background())
	p.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatal("stale latch cleared before RecoverCycles fresh cycles")
	}
	// Third consecutive fresh cycle (== default RecoverCycles) → exit.
	p.Cycle(context.Background())
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("stale latch not cleared after RecoverCycles fresh cycles")
	}
}

func TestWatchdogLatchNotClearedOnInconclusive(t *testing.T) {
	bad := newAPIStub(t)
	ha := newFakeHAProxy(t, [2]string{"hub1", bad.addr()})
	p := fixture(t, ha, ModeDryRun, nil)
	dir := t.TempDir()
	p.cfg.WatchdogStateDir = dir
	latch := staleFilePath(dir, bad.addr())

	bad.set(100, 5000)
	p.Cycle(context.Background())
	p.Cycle(context.Background()) // stale → latch
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("stale latch not created: %v", err)
	}

	// TCP-unreachable cycle is inconclusive — the latch must survive
	// (hysteresis: no exit on an indeterminate probe).
	p.cfg.TCPCheck = func(_ context.Context, _ string) error {
		return fmt.Errorf("connect refused")
	}
	p.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatal("stale latch cleared on an inconclusive cycle")
	}

	// Query-fail-but-under-threshold is also inconclusive.
	p.cfg.TCPCheck = nil
	p.states["hub1"].qfail = 0 // reset to under-threshold
	bad.setFail(true)
	p.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatal("stale latch cleared on an inconclusive query-fail cycle")
	}
}

func TestWatchdogPruneRemovesRetiredBackends(t *testing.T) {
	good := newAPIStub(t)
	ha := newFakeHAProxy(t, [2]string{"hub2", good.addr()})
	p := fixture(t, ha, ModeDryRun, nil)
	dir := t.TempDir()
	p.cfg.WatchdogStateDir = dir

	// Files from a backend that left api-local-lb discovery.
	oldGap := gapFilePath(dir, "10.9.9.9:6443")
	oldLatch := staleFilePath(dir, "10.9.9.9:6443")
	for _, f := range []string{oldGap, oldLatch} {
		if err := os.WriteFile(f, []byte("1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	good.set(50, 50)
	p.Cycle(context.Background())

	for _, f := range []string{oldGap, oldLatch} {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Fatalf("file for retired backend not pruned: %s", f)
		}
	}
	// The discovered backend's own gap file survives.
	if _, err := os.Stat(gapFilePath(dir, good.addr())); err != nil {
		t.Fatalf("gap file for live backend pruned: %v", err)
	}
}

func TestWatchdogNoPruneOnEmptyDiscovery(t *testing.T) {
	// Discovery returned zero rows — never prune (a failed/empty scan
	// must not wipe latches other watchdog consumers still read).
	ha := newFakeHAProxy(t) // no servers
	p := fixture(t, ha, ModeDryRun, nil)
	dir := t.TempDir()
	p.cfg.WatchdogStateDir = dir
	f := staleFilePath(dir, "10.9.9.9:6443")
	if err := os.WriteFile(f, []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p.Cycle(context.Background())
	if _, err := os.Stat(f); err != nil {
		t.Fatal("latch pruned on an empty backend list")
	}
}

func TestWatchdogFilesSkippedWhenDirUnsetOrMissing(t *testing.T) {
	for _, tc := range []struct {
		name string
		wdir string
	}{
		{"empty", ""},
		{"missing", filepath.Join(t.TempDir(), "no-such-dir")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := newAPIStub(t)
			ha := newFakeHAProxy(t, [2]string{"hub1", bad.addr()})
			p := fixture(t, ha, ModeDryRun, nil)
			p.cfg.WatchdogStateDir = tc.wdir

			bad.set(100, 5000)
			p.Cycle(context.Background())
			p.Cycle(context.Background()) // stale — must not create the dir or panic
			if tc.wdir != "" {
				if _, err := os.Stat(tc.wdir); !os.IsNotExist(err) {
					t.Fatal("missing watchdog dir was created by file ops")
				}
			}
		})
	}
}

func TestDashedIP(t *testing.T) {
	if got := dashedIP("10.0.0.1:6443"); got != "10-0-0-1" {
		t.Fatalf("dashedIP=%q want 10-0-0-1", got)
	}
	// Raw addr without port — fallback keeps the host as-is.
	if got := dashedIP("10.0.0.1"); got != "10-0-0-1" {
		t.Fatalf("dashedIP=%q want 10-0-0-1", got)
	}
}

// --- stale-backend pruning (p.states + per-backend metric series) ---
// Series counts go through testutil.CollectAndCount rather than
// ToFloat64 — a WithLabelValues probe would re-create the very series
// the prune is supposed to have deleted.

func TestPruneStaleBackendsRemovesStateAndSeries(t *testing.T) {
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	p := fixture(t, ha, ModeEnforce, nil)

	// One healthy cycle seeds rvGap{hub1}/enabled{hub1}; then query
	// failures wedge hub1 → probeFailures{hub1,query},
	// actions{hub1,disable} and a drained states entry.
	bad.set(100, 900)
	good.set(50, 50)
	p.Cycle(context.Background())
	bad.setFail(true)
	p.Cycle(context.Background())
	p.Cycle(context.Background()) // qfail #2 → DEAD → disable

	if _, ok := p.states["hub1"]; !ok {
		t.Fatal("hub1 states entry missing before retire")
	}
	if testutil.CollectAndCount(p.probeFailures) != 1 ||
		testutil.CollectAndCount(p.actions) != 1 {
		t.Fatal("expected one hub1 probeFailures/actions series before retire")
	}

	// Retire hub1 from api-local-lb — the next discovery sees hub2 only.
	ha.mu.Lock()
	delete(ha.servers, "hub1")
	ha.order = []string{"hub2"}
	ha.mu.Unlock()
	p.Cycle(context.Background())

	if _, ok := p.states["hub1"]; ok {
		t.Fatal("stale hub1 states entry survived prune")
	}
	if got := testutil.CollectAndCount(p.rvGap); got != 1 {
		t.Fatalf("rvGap series=%d want 1 (hub2 only)", got)
	}
	if got := testutil.CollectAndCount(p.enabled); got != 1 {
		t.Fatalf("enabled series=%d want 1 (hub2 only)", got)
	}
	// The two-label vecs must lose every series whose backend label
	// matches — DeletePartialMatch coverage.
	if got := testutil.CollectAndCount(p.probeFailures); got != 0 {
		t.Fatalf("probeFailures series=%d want 0 after prune", got)
	}
	if got := testutil.CollectAndCount(p.actions); got != 0 {
		t.Fatalf("actions series=%d want 0 after prune", got)
	}
}

func TestPruneStaleBackendsSkippedOnEmptyOrFailedDiscovery(t *testing.T) {
	// A transient socket error or an empty scan must not wipe state the
	// next good cycle still needs — the len(backends)>0 gate.
	seed := func(p *Prober) {
		p.states["gone"] = &backendState{drained: true}
		p.rvGap.WithLabelValues("gone").Set(7)
		p.enabled.WithLabelValues("gone").Set(0)
		p.probeFailures.WithLabelValues("gone", "query").Inc()
		p.actions.WithLabelValues("gone", "disable").Inc()
	}
	assertKept := func(t *testing.T, p *Prober) {
		t.Helper()
		if _, ok := p.states["gone"]; !ok {
			t.Fatal("states entry pruned on a non-discovery cycle")
		}
		for name, vec := range map[string]prometheus.Collector{
			"rvGap":         p.rvGap,
			"enabled":       p.enabled,
			"probeFailures": p.probeFailures,
			"actions":       p.actions,
		} {
			if got := testutil.CollectAndCount(vec); got != 1 {
				t.Fatalf("%s series=%d want 1 kept", name, got)
			}
		}
	}

	t.Run("empty discovery", func(t *testing.T) {
		ha := newFakeHAProxy(t) // header only — zero kube_apiserver rows
		p := fixture(t, ha, ModeDryRun, nil)
		seed(p)
		p.Cycle(context.Background())
		assertKept(t, p)
	})

	t.Run("failed discovery", func(t *testing.T) {
		p, err := New(Config{
			DialSocket: func(context.Context, string) (net.Conn, error) {
				return nil, errors.New("admin socket gone")
			},
			HTTPClient: newAPIStub(t).srv.Client(),
		}, prometheus.NewRegistry())
		if err != nil {
			t.Fatal(err)
		}
		seed(p)
		p.Cycle(context.Background())
		assertKept(t, p)
	})
}

func TestPruneStaleBackendsKeepsVIP(t *testing.T) {
	// *_lb VIP entries are part of the live discovery set — pruning on
	// direct backends only (the pruneWatchdogFiles filter) would drop
	// the VIP's drained flag and enabled series every cycle.
	ctrl := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"api_datahub_ctrl", ctrl.addr()},
		[2]string{"api_datahub_lb", "127.0.0.1:1"},
	)
	p := fixture(t, ha, ModeDryRun, nil)

	ctrl.set(50, 50)
	p.Cycle(context.Background())

	if _, ok := p.states["api_datahub_lb"]; !ok {
		t.Fatal("VIP states entry pruned while still in discovery")
	}
	if got := testutil.CollectAndCount(p.enabled); got != 2 {
		t.Fatalf("enabled series=%d want 2 (ctrl + VIP)", got)
	}
}

func TestListRVSendsPartialObjectMetadataAccept(t *testing.T) {
	var gotAccept string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		io.WriteString(w, `{"metadata":{"resourceVersion":"42"}}`)
	}))
	defer srv.Close()
	p, err := New(Config{HTTPClient: srv.Client()}, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	rv, ok := p.listRV(context.Background(),
		strings.TrimPrefix(srv.URL, "https://"), "/api/v1/nodes?limit=1")
	if !ok || rv != 42 {
		t.Fatalf("listRV = %d, %v want 42, true", rv, ok)
	}
	const want = "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1"
	if gotAccept != want {
		t.Fatalf("Accept=%q want %q", gotAccept, want)
	}
}

// readTracker wraps a reader, recording total bytes consumed — proves
// listRV drains the response body to EOF past the 1 MiB decode cap so
// keep-alive can reuse the connection.
type readTracker struct {
	r     io.Reader
	total int64
}

func (t *readTracker) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	t.total += int64(n)
	return n, err
}

func (t *readTracker) Close() error { return nil }

func TestListRVDrainsBodyPastReadCap(t *testing.T) {
	// Valid JSON up front, then >1 MiB of trailing whitespace (legal
	// for json.Unmarshal): the capped read captures the document and
	// the drain must consume the rest to EOF.
	payload := `{"metadata":{"resourceVersion":"42"}}` +
		strings.Repeat(" ", 2<<20)
	body := &readTracker{r: strings.NewReader(payload)}
	p, err := New(Config{
		HTTPClient: &http.Client{Transport: rtFunc(
			func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode:    http.StatusOK,
					Header:        make(http.Header),
					Body:          body,
					ContentLength: int64(len(payload)),
				}, nil
			})},
	}, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	rv, ok := p.listRV(context.Background(), "127.0.0.1:6443", "/x")
	if !ok || rv != 42 {
		t.Fatalf("listRV = %d, %v want 42, true", rv, ok)
	}
	if body.total != int64(len(payload)) {
		t.Fatalf("body read %d/%d bytes — tail past the cap not drained",
			body.total, len(payload))
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
				return fmt.Errorf("connect refused")
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

func TestCompanionBackendsReceiveActions(t *testing.T) {
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	ha.failReply = map[string]string{
		"disable server konn_back/hub1": "No such server konn_back/hub1\n",
	}
	p := fixtureExt(t, ha, ModeEnforce, nil, func(c *Config) {
		c.CompanionBackends = []string{"konn_back"}
	})

	// Frozen wedge on hub1 for FrozenCycles.
	bad.set(100, 200)
	good.set(500, 500)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}

	cmds := ha.commands()
	if !hasCmd(cmds, "disable server kube_apiserver/hub1") {
		t.Fatalf("primary backend disable missing, cmds=%v", cmds)
	}
	if !hasCmd(cmds, "disable server konn_back/hub1") {
		t.Fatalf("companion backend disable missing, cmds=%v", cmds)
	}
	// "No such server" on the companion is a no-op — the action
	// still counted as a disable, not an error path.
	if got := testutil.ToFloat64(p.actions.WithLabelValues("hub1", "disable")); got != 1 {
		t.Fatalf("actions disable=%v want 1", got)
	}
}

func TestCompanionErrorDoesNotBlockDrain(t *testing.T) {
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	// Companion returns a REAL error (not "No such server") — the
	// primary already drained; the error surfaces in the log only.
	ha.failReply = map[string]string{
		"disable server konn_back/hub1": "permission denied for socket\n",
	}
	p := fixtureExt(t, ha, ModeEnforce, nil, func(c *Config) {
		c.CompanionBackends = []string{"konn_back"}
	})
	bad.set(100, 200)
	good.set(500, 500)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}
	if !hasCmd(ha.commands(), "disable server kube_apiserver/hub1") {
		t.Fatalf("primary disable missing, cmds=%v", ha.commands())
	}
	// Primary disable succeeded → drained flag set.
	if !p.states["hub1"].drained {
		t.Fatal("hub1 not drained despite companion error")
	}
}

func TestStaticBackendsMergedAndDrained(t *testing.T) {
	bad := newAPIStub(t)
	good := newAPIStub(t)
	// HAProxy knows only hub2; hub1 comes from StaticBackends (the
	// api-backend-guard.conf API_BACKENDS model).
	ha := newFakeHAProxy(t, [2]string{"hub2", good.addr()})
	wdir := t.TempDir()
	p := fixtureExt(t, ha, ModeEnforce, nil, func(c *Config) {
		c.WatchdogStateDir = wdir
		c.StaticBackends = []StaticBackend{
			{Name: "hub1", Addr: bad.addr()},
		}
	})

	bad.set(100, 200) // frozen wedge
	good.set(500, 500)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}

	if !hasCmd(ha.commands(), "disable server kube_apiserver/hub1") {
		t.Fatalf("static backend disable missing, cmds=%v", ha.commands())
	}
	if got := testutil.ToFloat64(p.backendCount); got != 2 {
		t.Fatalf("backendCount=%v want 2 (static merged)", got)
	}
	// The stale latch is written for the static backend too — module
	// 06's upstream gate reads it by dashed IP.
	dashed := strings.ReplaceAll(strings.Split(bad.addr(), ":")[0], ".", "-")
	if _, err := os.Stat(wdir + "/state-apiserver-backend-stale-" + dashed); err != nil {
		t.Fatalf("stale latch missing for static backend: %v", err)
	}
}

func TestDiscoverFillsEmptyAddrFromStatic(t *testing.T) {
	stub := newAPIStub(t)
	// External API LB VM shape: server row with no addr column —
	// resolved from StaticBackends by name instead of failing.
	ha := newFakeHAProxy(t, [2]string{"hub1", ""}, [2]string{"hub2", stub.addr()})
	p := fixtureExt(t, ha, ModeDryRun, nil, func(c *Config) {
		c.StaticBackends = []StaticBackend{{Name: "hub1", Addr: "10.0.0.1:6443"}}
	})
	backends, err := p.discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if backends[0].Addr != "10.0.0.1:6443" {
		t.Fatalf("hub1 addr=%q want static fill", backends[0].Addr)
	}
	if backends[1].Addr != stub.addr() {
		t.Fatalf("hub2 addr=%q want discovered", backends[1].Addr)
	}
}

func TestDiscoverEmptyAddrWithoutStaticSkips(t *testing.T) {
	// No addr and no API_BACKENDS name match → the row is skipped
	// (log-and-continue), never a whole-cycle failure.
	ha := newFakeHAProxy(t, [2]string{"hub1", ""})
	p := fixtureExt(t, ha, ModeDryRun, nil, nil)
	backends, err := p.discover(context.Background())
	if err != nil {
		t.Fatalf("empty addr without static config want skip, err=%v", err)
	}
	if len(backends) != 0 {
		t.Fatalf("backends=%v want none (unresolvable row skipped)", backends)
	}
}

func TestStaticBackendDedupedAgainstDiscovery(t *testing.T) {
	stub := newAPIStub(t)
	ha := newFakeHAProxy(t, [2]string{"hub1", stub.addr()})
	p := fixtureExt(t, ha, ModeDryRun, nil, func(c *Config) {
		c.StaticBackends = []StaticBackend{
			{Name: "hub1", Addr: "10.9.9.9:6443"}, // same name — discovery wins
			{Name: "hub2", Addr: "10.0.0.2:6443"}, // new name — appended
		}
	})
	backends, err := p.discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	merged := mergeStatic(backends, p.cfg.StaticBackends)
	if len(merged) != 2 {
		t.Fatalf("merged=%v want 2 backends", merged)
	}
	if merged[0].Addr != stub.addr() {
		t.Fatalf("discovered addr overwritten by static: %q", merged[0].Addr)
	}
	if merged[1].Name != "hub2" || merged[1].Addr != "10.0.0.2:6443" || !merged[1].up() {
		t.Fatalf("static append wrong: %+v", merged[1])
	}
}

func TestStagedDrainSpendsFreshPerDisable(t *testing.T) {
	// fresh=1 with 2 wedged backends: the first disable decrements
	// fresh (shell `fresh=$((fresh - 1))` parity), so the second
	// wedge hits the fence — staged drain, not drain-all.
	good := newAPIStub(t)
	bad1 := newAPIStub(t)
	bad2 := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", good.addr()},
		[2]string{"hub2", bad1.addr()},
		[2]string{"hub3", bad2.addr()},
	)
	p := fixtureExt(t, ha, ModeEnforce, nil, nil)
	good.set(50, 50)
	bad1.set(100, 200)
	bad2.set(100, 200)
	// Three cycles: cycle 1 seeds prevCache, frozen reaches
	// FrozenCycles on cycle 3 → ONE drain round — and the per-cycle
	// budget allows exactly `fresh` disables.
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}
	disables := 0
	for _, c := range ha.commands() {
		if strings.HasPrefix(c, "disable server") {
			disables++
		}
	}
	if disables != 1 {
		t.Fatalf("disables=%d want 1 (staged drain), cmds=%v", disables, ha.commands())
	}
	if got := testutil.ToFloat64(p.actions.WithLabelValues("hub3", "fence_skip")); got < 1 {
		t.Fatalf("hub3 fence_skip=%v want >=1", got)
	}
}

// --- /etc/api-backend-guard.conf (LoadGuardConf) ---

func TestLoadGuardConfMissingFile(t *testing.T) {
	g, err := LoadGuardConf(filepath.Join(t.TempDir(), "absent.conf"))
	if err != nil {
		t.Fatalf("missing conf err=%v want nil (zero defaults)", err)
	}
	if g.SocketPath != "" || g.BackendName != "" || g.Mode != "" ||
		g.TokenFile != "" || g.CAFile != "" ||
		len(g.CompanionBackends) != 0 || len(g.StaticBackends) != 0 {
		t.Fatalf("missing conf guard=%+v want zero value", g)
	}
}

func TestLoadGuardConfParse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api-backend-guard.conf")
	content := `# guard conf — comment lines skipped
MODE=enforce

# quoted list with an inline comment
API_BACKENDS="hub1=10.0.0.1:6443 hub2=10.0.0.2:6443 10.0.0.3:6443" # trailing

HAPROXY_BACKEND=kubeAPI_backend
HAPROXY_BACKENDS="kubeAPI_backend konnectivity_back"
HAPROXY_SOCKET=/run/haproxy-admin/admin.sock

TOKEN_FILE=/etc/api-backend-guard/token
CA_FILE='/etc/api-backend-guard/ca.crt'
export EXTRA=ignored
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	g, err := LoadGuardConf(path)
	if err != nil {
		t.Fatal(err)
	}
	if g.Mode != "enforce" {
		t.Fatalf("Mode=%q want enforce", g.Mode)
	}
	if g.SocketPath != "/run/haproxy-admin/admin.sock" {
		t.Fatalf("SocketPath=%q", g.SocketPath)
	}
	if g.BackendName != "kubeAPI_backend" {
		t.Fatalf("BackendName=%q", g.BackendName)
	}
	// The primary backend is NOT a companion — HAPROXY_BACKENDS
	// includes it, and the prober already acts on BackendName.
	if len(g.CompanionBackends) != 1 || g.CompanionBackends[0] != "konnectivity_back" {
		t.Fatalf("CompanionBackends=%v want [konnectivity_back]", g.CompanionBackends)
	}
	want := []StaticBackend{
		{Name: "hub1", Addr: "10.0.0.1:6443"},
		{Name: "hub2", Addr: "10.0.0.2:6443"},
		// Bare "ip:port" entries name themselves (watchdogconf parity).
		{Name: "10.0.0.3:6443", Addr: "10.0.0.3:6443"},
	}
	if len(g.StaticBackends) != len(want) {
		t.Fatalf("StaticBackends=%v want %v", g.StaticBackends, want)
	}
	for i, sb := range want {
		if g.StaticBackends[i] != sb {
			t.Fatalf("StaticBackends[%d]=%+v want %+v", i, g.StaticBackends[i], sb)
		}
	}
	if g.TokenFile != "/etc/api-backend-guard/token" {
		t.Fatalf("TokenFile=%q", g.TokenFile)
	}
	if g.CAFile != "/etc/api-backend-guard/ca.crt" {
		t.Fatalf("CAFile=%q (single quotes must strip)", g.CAFile)
	}
}

func TestLoadGuardConfUnreadableErrors(t *testing.T) {
	// A path that exists but is a directory → real read error
	// (distinct from the absent-file zero-defaults contract).
	_, err := LoadGuardConf(t.TempDir())
	if err == nil {
		t.Fatal("LoadGuardConf on a directory want error")
	}
}

func TestLoadGuardConfOriginalKeySpelling(t *testing.T) {
	// The deployed ansible contract (api-backend-guard.conf.j2) —
	// VMs in the field carry ONLY this spelling.
	path := filepath.Join(t.TempDir(), "api-backend-guard.conf")
	content := `MODE=enforce
HAPROXY_SOCKET=/run/haproxy-admin/admin.sock
API_TOKEN_FILE=/etc/api-backend-guard/token
API_CA_FILE=/etc/api-backend-guard/ca.crt
GAP_MIN=10000
FAIL_CYCLES=2
FROZEN_CYCLES=2
RECOVER_CYCLES=3
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	g, err := LoadGuardConf(path)
	if err != nil {
		t.Fatal(err)
	}
	if g.TokenFile != "/etc/api-backend-guard/token" {
		t.Fatalf("TokenFile=%q want API_TOKEN_FILE value", g.TokenFile)
	}
	if g.CAFile != "/etc/api-backend-guard/ca.crt" {
		t.Fatalf("CAFile=%q want API_CA_FILE value", g.CAFile)
	}
	if g.GapMin != 10000 || g.FailCycles != 2 || g.FrozenCycles != 2 || g.RecoverCycles != 3 {
		t.Fatalf("thresholds=%+v want 10000/2/2/3", g)
	}
}

func TestLoadGuardConfAPIPrefixWins(t *testing.T) {
	// Both spellings present → API_-prefixed (original contract) wins.
	path := filepath.Join(t.TempDir(), "api-backend-guard.conf")
	content := `TOKEN_FILE=/short/token
API_TOKEN_FILE=/orig/token
CA_FILE=/short/ca
API_CA_FILE=/orig/ca
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	g, err := LoadGuardConf(path)
	if err != nil {
		t.Fatal(err)
	}
	if g.TokenFile != "/orig/token" || g.CAFile != "/orig/ca" {
		t.Fatalf("API_-prefixed keys must win: %+v", g)
	}
}

func TestMergeStaticDedupsStaticNames(t *testing.T) {
	// The same server name in two conf layers must not be appended
	// twice — it would be double-probed every cycle.
	merged := mergeStatic(nil, []StaticBackend{
		{Name: "hub1", Addr: "10.0.0.1:6443"},
		{Name: "hub1", Addr: "10.0.0.1:6443"}, // duplicate name
		{Name: "hub2", Addr: "10.0.0.2:6443"},
	})
	if len(merged) != 2 {
		t.Fatalf("merged=%v want 2 (same-named statics deduped)", merged)
	}
}

func TestMergeStaticDedupsByAddr(t *testing.T) {
	// The production incident shape: discovery returns the HAProxy
	// svname for an addr that API_BACKENDS also carries as a bare
	// self-named "ip:port" entry — the same physical apiserver must
	// be tracked ONCE under its svname, or the addr-keyed twin
	// drains under a name HAProxy does not know.
	merged := mergeStatic(
		[]backend{
			{Name: "api_contabo_ctrl", Addr: "147.93.159.255:6443",
				Status: "UP", discovered: true},
			{Name: "api_datahub_ctrl", Addr: "103.186.101.25:6443",
				Status: "UP", discovered: true},
		},
		[]StaticBackend{
			// worker API_BACKENDS = bare apiserver_probe_backends
			// addrs — both are already discovered under svnames.
			{Name: "147.93.159.255:6443", Addr: "147.93.159.255:6443"},
			{Name: "103.186.101.25:6443", Addr: "103.186.101.25:6443"},
			{Name: "api_contabo_ctrl", Addr: "147.93.159.255:6443"}, // name dedup too
			{Name: "ghost", Addr: "10.9.9.9:6443"},                  // genuinely absent
		})
	if len(merged) != 3 {
		t.Fatalf("merged=%v want 3 (2 discovered + ghost)", merged)
	}
	if merged[2].Name != "ghost" || merged[2].discovered {
		t.Fatalf("merged[2]=%+v want undiscovered ghost", merged[2])
	}
}

func TestMergeStaticPrefersConfiguredNameOverBareAddr(t *testing.T) {
	// Static-vs-static same-addr: the configured name claims the
	// identity even when the bare self-named entry is listed first
	// — the addr is never the preferred key.
	merged := mergeStatic(nil, []StaticBackend{
		{Name: "10.0.0.1:6443", Addr: "10.0.0.1:6443"}, // bare, listed first
		{Name: "ctrl1", Addr: "10.0.0.1:6443"},
	})
	if len(merged) != 1 || merged[0].Name != "ctrl1" {
		t.Fatalf("merged=%v want [ctrl1] — named entry must win the addr", merged)
	}
}

func TestActionTarget(t *testing.T) {
	byAddr := map[string]string{"10.0.0.1:6443": "api_ctrl1"}
	cases := []struct {
		b        backend
		wantName string
		wantPrim bool
	}{
		{backend{Name: "api_ctrl1", Addr: "10.0.0.1:6443", discovered: true},
			"api_ctrl1", true},
		// Non-discovered row shadowing a discovered addr → the real
		// svname, never the addr key.
		{backend{Name: "10.0.0.1:6443", Addr: "10.0.0.1:6443"},
			"api_ctrl1", true},
		// Static-only name — absent from the primary backend.
		{backend{Name: "ghost", Addr: "10.9.9.9:6443"}, "ghost", false},
	}
	for _, tc := range cases {
		name, prim := actionTarget(tc.b, byAddr)
		if name != tc.wantName || prim != tc.wantPrim {
			t.Fatalf("actionTarget(%+v) = %q,%v want %q,%v",
				tc.b, name, prim, tc.wantName, tc.wantPrim)
		}
	}
}

func TestMergeStaticDefaultPort(t *testing.T) {
	// Bare-IP API_BACKENDS entry → bash default port 443; without it
	// every TCP preflight failed "missing port in address" → the
	// backend counted unreachable forever.
	merged := mergeStatic(nil, []StaticBackend{
		{Name: "hub1", Addr: "10.0.0.1"},
		{Name: "hub2", Addr: "10.0.0.2:6443"},
	})
	if merged[0].Addr != "10.0.0.1:443" {
		t.Fatalf("bare IP addr=%q want :443 default", merged[0].Addr)
	}
	if merged[1].Addr != "10.0.0.2:6443" {
		t.Fatalf("explicit port clobbered: %q", merged[1].Addr)
	}
}

func TestWithDefaultPort(t *testing.T) {
	for in, want := range map[string]string{
		"10.0.0.1":      "10.0.0.1:443",
		"10.0.0.1:6443": "10.0.0.1:6443",
		"host.example":  "host.example:443",
		"[::1]":         "[::1]:443",
		"":              "",
	} {
		if got := withDefaultPort(in); got != want {
			t.Fatalf("withDefaultPort(%q)=%q want %q", in, got, want)
		}
	}
}

func TestGuardReloaderRefreshesAndKeepsLastGood(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guard.conf")
	rl := NewGuardReloader(path, GuardDefaults{})
	// Missing file → zero defaults.
	if g := rl.Get(); g.Mode != "" {
		t.Fatalf("missing conf Mode=%q want zero", g.Mode)
	}
	if err := os.WriteFile(path, []byte("MODE=dry-run\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if g := rl.Get(); g.Mode != "dry-run" {
		t.Fatalf("Mode=%q want dry-run", g.Mode)
	}
	if err := os.WriteFile(path, []byte("MODE=enforce\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if g := rl.Get(); g.Mode != "enforce" {
		t.Fatalf("edited conf not picked up: Mode=%q", g.Mode)
	}
	// Unreadable path (directory replaces the file) → last good kept.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if g := rl.Get(); g.Mode != "enforce" {
		t.Fatalf("unreadable conf must keep last good, Mode=%q", g.Mode)
	}
}

func TestGuardConfAppliesMidRun(t *testing.T) {
	// The incident shape: agent up before hostconfig renders the
	// conf. dry-run at startup; once the conf lands MODE=enforce
	// mid-run, the NEXT cycle drains — no restart.
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	confPath := filepath.Join(t.TempDir(), "api-backend-guard.conf")
	p := fixtureExt(t, ha, ModeDryRun, nil, func(c *Config) {
		c.GuardSrc = NewGuardReloader(confPath, GuardDefaults{})
	})
	bad.set(100, 200) // frozen wedge signature
	good.set(500, 500)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}
	if hasCmd(ha.commands(), "disable server") {
		t.Fatalf("drain under dry-run: %v", ha.commands())
	}
	// hostconfig's first render lands mid-run.
	if err := os.WriteFile(confPath, []byte("MODE=enforce\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p.Cycle(context.Background())
	if !hasCmd(ha.commands(), "disable server kube_apiserver/hub1") {
		t.Fatalf("enforce MODE from mid-run conf not applied: %v", ha.commands())
	}
}

func TestGuardConfOverlayFields(t *testing.T) {
	confPath := filepath.Join(t.TempDir(), "api-backend-guard.conf")
	content := `MODE=enforce
HAPROXY_SOCKET=/run/other.sock
HAPROXY_BACKEND=other_back
HAPROXY_BACKENDS="other_back extra_back"
API_BACKENDS="ctl1=10.0.0.9 ctl2=10.0.0.10:6443"
API_TOKEN_FILE=/g/token
API_CA_FILE=/g/ca
GAP_MIN=500
FAIL_CYCLES=4
`
	if err := os.WriteFile(confPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	ha := newFakeHAProxy(t, [2]string{"hub1", "10.0.0.1:6443"})
	p := fixtureExt(t, ha, ModeDryRun, nil, func(c *Config) {
		c.GuardSrc = NewGuardReloader(confPath, GuardDefaults{})
		c.StaticBackends = []StaticBackend{{Name: "ctl1", Addr: "10.9.9.9:6443"}}
	})
	p.refreshGuard()
	if p.eff.mode != ModeEnforce || p.eff.socket != "/run/other.sock" ||
		p.eff.backend != "other_back" || p.eff.tokenFile != "/g/token" ||
		p.eff.caFile != "/g/ca" || p.eff.gapMin != 500 || p.eff.failCycles != 4 {
		t.Fatalf("eff=%+v", p.eff)
	}
	if len(p.eff.companions) != 1 || p.eff.companions[0] != "extra_back" {
		t.Fatalf("companions=%v", p.eff.companions)
	}
	// Conf ctl1 (10.0.0.9) wins over the startup ctl1 — first-seen
	// in the conf-first ordering.
	if len(p.eff.statics) != 2 || p.eff.statics[0].Addr != "10.0.0.9" {
		t.Fatalf("statics=%v want conf-first dedup", p.eff.statics)
	}
	if got := p.staticAddr("ctl1"); got != "10.0.0.9:443" {
		t.Fatalf("staticAddr=%q want conf addr + :443", got)
	}
}

func TestAddrKeyedStaticDoesNotDuplicateDiscoveredBackend(t *testing.T) {
	// The reported incident: API_BACKENDS on workers carries bare
	// apiserver_probe_backends addrs ("147.93.159.255:6443") while
	// api-local-lb serves the same addrs under svnames
	// (api_contabo_ctrl). The bare entry must collapse onto the
	// discovered row — never a second probe identity, and the drain
	// must use the HAProxy svname.
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"api_contabo_ctrl", bad.addr()},
		[2]string{"api_datahub_ctrl", good.addr()},
	)
	p := fixtureExt(t, ha, ModeEnforce, nil, func(c *Config) {
		c.StaticBackends = []StaticBackend{
			{Name: bad.addr(), Addr: bad.addr()},   // bare ip:port
			{Name: good.addr(), Addr: good.addr()}, // bare ip:port
		}
	})

	bad.set(100, 200) // frozen wedge
	good.set(500, 500)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}

	if !hasCmd(ha.commands(), "disable server kube_apiserver/api_contabo_ctrl") {
		t.Fatalf("disable must use the HAProxy svname, cmds=%v", ha.commands())
	}
	addrCmd := "disable server kube_apiserver/" + bad.addr()
	if hasCmd(ha.commands(), addrCmd) {
		t.Fatalf("disable issued under the addr key %q — 'No such server' bug, cmds=%v",
			bad.addr(), ha.commands())
	}
	if _, ok := p.states[bad.addr()]; ok {
		t.Fatal("addr-keyed phantom backend got its own probe state")
	}
	if got := testutil.ToFloat64(p.backendCount); got != 2 {
		t.Fatalf("backendCount=%v want 2 (addr-keyed static deduped)", got)
	}
}

func TestStaticOnlyBackendMissingServerDrainOnce(t *testing.T) {
	// A static-only backend (API_BACKENDS entry absent from every
	// HAProxy backend) going stale: the primary replies "No such
	// server" — the expected no-op — so the drain is recorded once
	// and NOT retried as an error every cycle.
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t, [2]string{"hub2", good.addr()})
	ha.failReply = map[string]string{
		"disable server kube_apiserver/ghost": "No such server.\n",
		"enable server kube_apiserver/ghost":  "No such server.\n",
	}
	p := fixtureExt(t, ha, ModeEnforce, nil, func(c *Config) {
		c.StaticBackends = []StaticBackend{{Name: "ghost", Addr: bad.addr()}}
	})

	bad.set(100, 200) // frozen wedge
	good.set(500, 500)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}
	if !hasCmd(ha.commands(), "disable server kube_apiserver/ghost") {
		t.Fatalf("disable never attempted, cmds=%v", ha.commands())
	}
	if !p.states["ghost"].drained {
		t.Fatal("ghost not marked drained — tolerated 'No such server' must not block the drain record")
	}
	if got := testutil.ToFloat64(p.actions.WithLabelValues("ghost", "disable")); got != 1 {
		t.Fatalf("actions disable=%v want 1", got)
	}

	// Still wedged for several more cycles — the missing-server
	// drain must not retry/spam the socket every round.
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}
	if got := countCmd(ha.commands(), "disable server kube_apiserver/ghost"); got != 1 {
		t.Fatalf("disable re-issued %d times for an absent server, cmds=%v",
			got, ha.commands())
	}

	// Recovery: the tolerated "No such server" enable clears the
	// drained flag the same way.
	for i := 0; i < 3; i++ {
		bad.set(300+int64(i), 300)
		p.Cycle(context.Background())
	}
	if p.states["ghost"].drained {
		t.Fatal("drained flag not cleared after tolerated enable")
	}
}
