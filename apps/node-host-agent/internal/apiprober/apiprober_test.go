package apiprober

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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
	a := &apiStub{}
	a.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
