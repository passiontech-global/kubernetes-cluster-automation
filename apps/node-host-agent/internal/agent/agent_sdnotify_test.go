// agent_sdnotify_test.go — sd-watchdog sd_notify self-watchdog: the
// unixgram READY=1/WATCHDOG=1 feed, the probe-mux health gate and
// the no-NOTIFY_SOCKET no-op path.
package agent

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// notifySink is a unixgram listener pretending to be PID 1's notify
// socket — messages are consumed into a channel the test drains.
func notifySink(t *testing.T) (string, chan string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "notify.sock")
	conn, err := net.ListenUnixgram("unixgram",
		&net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	msgs := make(chan string, 16)
	go func() {
		buf := make([]byte, 4096)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			msgs <- string(buf[:n])
		}
	}()
	return path, msgs
}

func waitMsg(t *testing.T, msgs chan string) string {
	t.Helper()
	select {
	case m := <-msgs:
		return m
	case <-time.After(3 * time.Second):
		t.Fatal("no sd_notify datagram within 3s")
		return ""
	}
}

func TestSdNotifyLoopFeedsWhileProbeHealthy(t *testing.T) {
	path, msgs := notifySink(t)
	t.Setenv("NOTIFY_SOCKET", path)

	a := New(Config{NodeName: "node-a"})
	srv := httptest.NewServer(a.probeMux())
	defer srv.Close()
	// ProbeAddr "<host>:<port>" — probeSelfURL builds the loopback URL.
	a.cfg.ProbeAddr = strings.TrimPrefix(srv.URL, "http://")
	a.ready.Store(true)

	orig := sdWatchdogInterval
	sdWatchdogInterval = 20 * time.Millisecond
	defer func() { sdWatchdogInterval = orig }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { a.sdNotifyLoop(ctx); close(done) }()

	if got := waitMsg(t, msgs); got != "READY=1\n" {
		t.Fatalf("first datagram=%q want READY=1", got)
	}
	if got := waitMsg(t, msgs); got != "WATCHDOG=1\n" {
		t.Fatalf("second datagram=%q want WATCHDOG=1", got)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("sdNotifyLoop did not exit on ctx cancel")
	}
}

func TestSdNotifyLoopStopsFeedingWhenProbeDead(t *testing.T) {
	path, msgs := notifySink(t)
	t.Setenv("NOTIFY_SOCKET", path)

	a := New(Config{NodeName: "node-a"})
	srv := httptest.NewServer(a.probeMux())
	a.cfg.ProbeAddr = strings.TrimPrefix(srv.URL, "http://")
	a.ready.Store(true)

	orig := sdWatchdogInterval
	sdWatchdogInterval = 20 * time.Millisecond
	defer func() { sdWatchdogInterval = orig }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.sdNotifyLoop(ctx)
	if got := waitMsg(t, msgs); got != "READY=1\n" {
		t.Fatalf("first datagram=%q want READY=1", got)
	}
	if got := waitMsg(t, msgs); got != "WATCHDOG=1\n" {
		t.Fatalf("second datagram=%q want WATCHDOG=1", got)
	}
	// Kill the mux — the feed must STOP (a deaf agent must not mask
	// its own hang; systemd sees the silence at WatchdogSec).
	srv.Close()
	deadline := time.After(500 * time.Millisecond)
	for {
		select {
		case m := <-msgs:
			t.Fatalf("WATCHDOG fed while probe dead: %q", m)
		case <-deadline:
			return
		}
	}
}

func TestSdNotifyLoopNoSocketNoop(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	a := New(Config{NodeName: "node-a"})
	a.ready.Store(true)
	done := make(chan struct{})
	go func() { a.sdNotifyLoop(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("sdNotifyLoop blocked without NOTIFY_SOCKET")
	}
}

// probeSelfURL maps cfg.ProbeAddr onto the loopback /healthz — a
// wildcard bind self-dials 127.0.0.1 and an unparseable addr
// degrades to "" (ready-flag-only verdicts).
func TestProbeSelfURL(t *testing.T) {
	a := New(Config{NodeName: "node-a"})
	a.cfg.ProbeAddr = "127.0.0.1:8091"
	if got := a.probeSelfURL(); got != "http://127.0.0.1:8091/healthz" {
		t.Fatalf("probeSelfURL=%q", got)
	}
	a.cfg.ProbeAddr = ":8091" // wildcard bind → loopback self-dial
	if got := a.probeSelfURL(); got != "http://127.0.0.1:8091/healthz" {
		t.Fatalf("wildcard probeSelfURL=%q", got)
	}
	a.cfg.ProbeAddr = "not-an-addr"
	if got := a.probeSelfURL(); got != "" {
		t.Fatalf("unparseable probeSelfURL=%q want \"\"", got)
	}
}

// probeHealthy gates on BOTH the ready flag and a live probe mux —
// each failing input in isolation.
func TestProbeHealthy(t *testing.T) {
	a := New(Config{NodeName: "node-a"})
	if a.probeHealthy(http.DefaultClient, "") {
		t.Fatal("unready agent reported healthy")
	}
	a.ready.Store(true)
	// "" URL = unparseable ProbeAddr → the flag alone is the verdict.
	if !a.probeHealthy(http.DefaultClient, "") {
		t.Fatal("empty probeURL must fall back to the ready flag")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if !a.probeHealthy(srv.Client(), srv.URL+"/healthz") {
		t.Fatal("200 healthz reported unhealthy")
	}
	if a.probeHealthy(srv.Client(), srv.URL+"/wedged") {
		t.Fatal("500 healthz reported healthy")
	}
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()
	if a.probeHealthy(dead.Client(), deadURL+"/healthz") {
		t.Fatal("dead probe mux reported healthy")
	}
}

// A NOTIFY_SOCKET the process cannot dial warns and disables the
// feed — the loop returns, never hangs.
func TestSdNotifyLoopDialFailure(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", filepath.Join(t.TempDir(), "gone", "notify.sock"))
	a := New(Config{NodeName: "node-a"})
	a.ready.Store(true)
	done := make(chan struct{})
	go func() { a.sdNotifyLoop(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("sdNotifyLoop blocked on a bad NOTIFY_SOCKET")
	}
}

// A send that fails (the notify socket vanished) warns and keeps
// ticking — the watchdog feed is fail-open, ctx cancel still exits.
func TestSdNotifyLoopSendFailureWarns(t *testing.T) {
	path, msgs := notifySink(t)
	t.Setenv("NOTIFY_SOCKET", path)

	a := New(Config{NodeName: "node-a"})
	srv := httptest.NewServer(a.probeMux())
	defer srv.Close()
	a.cfg.ProbeAddr = strings.TrimPrefix(srv.URL, "http://")
	a.ready.Store(true)

	orig := sdWatchdogInterval
	sdWatchdogInterval = 20 * time.Millisecond
	defer func() { sdWatchdogInterval = orig }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { a.sdNotifyLoop(ctx); close(done) }()

	if got := waitMsg(t, msgs); got != "READY=1\n" {
		t.Fatalf("first datagram=%q want READY=1", got)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	// A few failed WATCHDOG ticks, then a clean exit on cancel.
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("sdNotifyLoop did not exit after send failures")
	}
}
