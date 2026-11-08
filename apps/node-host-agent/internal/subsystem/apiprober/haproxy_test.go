// haproxy_test.go — admin-socket machinery: socketCmd failure
// modes, `show stat` discovery (CSV edge cases, static fill),
// haproxyServer reply handling, and the missing-socket gate.
package apiprober

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

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

func TestDiscoverFailCounted(t *testing.T) {
	// Force a parse failure by serving garbage instead of CSV.
	p, err := New(Config{
		SocketPath:  "unused",
		BackendName: "kube_apiserver",
		DialSocket: func(_ context.Context, _ string) (net.Conn, error) {
			c1, c2 := net.Pipe()
			go func() {
				defer func() { _ = c2.Close() }()
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
	if got := promtest.ToFloat64(p.cycles.WithLabelValues("discover_fail")); got != 1 {
		t.Fatalf("discover_fail=%v want 1", got)
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

	t.Run("glued header marker still parses", func(t *testing.T) {
		// "#pxname" (no space after the marker): the old
		// TrimPrefix("# ") left the header unparsed — pxname never
		// mapped and every row silently skipped.
		csv := "#pxname,svname,status,addr\nkube_apiserver,hub1,UP,10.0.0.1:6443\n"
		backends, err := mkProber(t, csv).discover(context.Background())
		if err != nil {
			t.Fatalf("discover err=%v want nil", err)
		}
		if len(backends) != 1 || backends[0].Name != "hub1" {
			t.Fatalf("backends=%v want [hub1]", backends)
		}
	})

	t.Run("missing required column is fatal", func(t *testing.T) {
		// A header without pxname/svname/status is a schema break —
		// error instead of silently discovering zero backends.
		csv := "# pxname,svname\nkube_apiserver,hub1\n"
		if _, err := mkProber(t, csv).discover(context.Background()); err == nil ||
			!strings.Contains(err.Error(), "missing") {
			t.Fatalf("discover err=%v want 'missing column'", err)
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
	if got := promtest.ToFloat64(p.cycles.WithLabelValues("discover_fail")); got != 1 {
		t.Fatalf("discover_fail=%v want 1 while socket absent", got)
	}
	if got := promtest.ToFloat64(p.backendCount); got != 0 {
		t.Fatalf("backendCount=%v want 0", got)
	}

	// api-local-lb installed mid-run → the next cycle discovers it.
	sockDown.Store(false)
	p.Cycle(context.Background())
	if got := promtest.ToFloat64(p.cycles.WithLabelValues("ok")); got != 1 {
		t.Fatalf("cycles ok=%v want 1 after socket appeared", got)
	}
	if got := promtest.ToFloat64(p.backendCount); got != 1 {
		t.Fatalf("backendCount=%v want 1", got)
	}
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
	if got := promtest.ToFloat64(p.cycles.WithLabelValues("no_socket")); got != 3 {
		t.Fatalf("no_socket=%v want 3", got)
	}
	if got := promtest.ToFloat64(p.cycles.WithLabelValues("discover_fail")); got != 0 {
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
	if got := promtest.ToFloat64(p.cycles.WithLabelValues("no_socket")); got != 1 {
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
	t.Cleanup(func() { _ = ln.Close() })
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
	if got := promtest.ToFloat64(p.cycles.WithLabelValues("ok")); got != 1 {
		t.Fatalf("cycles ok=%v want 1 after socket appeared", got)
	}
	if got := promtest.ToFloat64(p.backendCount); got != 1 {
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
	testutil.WriteFile(t, sockPath, "regular file")
	p, err := New(Config{
		SocketPath:  sockPath,
		BackendName: "kube_apiserver",
		HTTPClient:  newAPIStub(t).srv.Client(),
	}, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	p.Cycle(context.Background())
	if got := promtest.ToFloat64(p.cycles.WithLabelValues("discover_fail")); got != 1 {
		t.Fatalf("discover_fail=%v want 1 — existing-but-broken socket is a real error", got)
	}
	if got := promtest.ToFloat64(p.cycles.WithLabelValues("no_socket")); got != 0 {
		t.Fatalf("no_socket=%v want 0", got)
	}
	if logs := buf.String(); !strings.Contains(logs, "level=ERROR") {
		t.Fatalf("broken socket produced no ERROR line:\n%s", logs)
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

// TestSocketCmdCapsReplyRead: one admin reply is capped at
// haproxyReplyMaxBytes — a wedged HAProxy streaming garbage forever
// must not slurp unbounded bytes into the agent's heap. The read
// still returns what arrived under the cap (parse then fails loudly
// downstream, never hangs).
func TestSocketCmdCapsReplyRead(t *testing.T) {
	p := &Prober{cfg: Config{TCPTimeout: 2 * time.Second}}
	p.eff.socket = "unused"
	p.cfg.DialSocket = func(_ context.Context, _ string) (net.Conn, error) {
		c1, c2 := net.Pipe()
		go func() {
			defer func() { _ = c2.Close() }()
			buf := make([]byte, 256)
			_, _ = c2.Read(buf) // consume the command — pipe is synchronous
			flood := bytes.Repeat([]byte("x\n"), haproxyReplyMaxBytes)
			for len(flood) > 0 {
				n, err := c2.Write(flood)
				if err != nil {
					return // reader stopped at the cap — done
				}
				flood = flood[n:]
			}
		}()
		return c1, nil
	}
	out, err := p.socketCmd(context.Background(), "show stat")
	if err != nil {
		// The cap closes the read side; a concurrent-write error is
		// acceptable — the bound still held if nothing above the cap
		// was retained.
		if len(out) > haproxyReplyMaxBytes {
			t.Fatalf("reply = %d bytes, over the cap", len(out))
		}
		return
	}
	if len(out) > haproxyReplyMaxBytes {
		t.Fatalf("reply = %d bytes, over the cap", len(out))
	}
}
