// agent_sdnotify_test.go — W13-OBS2 sd_notify self-watchdog: the
// unixgram READY=1/WATCHDOG=1 feed, the probe-mux health gate and
// the no-NOTIFY_SOCKET no-op path.
package agent

import (
	"context"
	"net"
	"net/http/httptest"
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
