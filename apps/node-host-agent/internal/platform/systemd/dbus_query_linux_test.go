//go:build linux

package systemd

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdbus "github.com/coreos/go-systemd/v22/dbus"
	godbus "github.com/godbus/dbus/v5"
)

type fakeDBusPeer struct {
	mu       sync.Mutex
	delay    time.Duration
	dropNext atomic.Bool
	onCall   func(iface, member string)
	conns    []net.Conn
}

func readLineRaw(r io.Reader) (string, error) {
	var buf []byte
	b := make([]byte, 1)
	for {
		n, err := r.Read(b)
		if n > 0 {
			buf = append(buf, b[0])
			if bytes.HasSuffix(buf, []byte("\r\n")) {
				return string(buf[:len(buf)-2]), nil
			}
		}
		if err != nil {
			return "", err
		}
	}
}

func startFakeDBusPeer(t *testing.T) (hostRoot string, peer *fakeDBusPeer) {
	t.Helper()
	// Use /tmp directly so the unix socket path stays well below 108 bytes.
	hostRoot, err := os.MkdirTemp("/tmp", "nhadb-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(hostRoot) })

	sockDir := filepath.Join(hostRoot, "run", "systemd")
	if err := os.MkdirAll(sockDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sockPath := filepath.Join(sockDir, "private")
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	peer = &fakeDBusPeer{}
	t.Cleanup(func() {
		peer.mu.Lock()
		for _, c := range peer.conns {
			_ = c.Close()
		}
		peer.mu.Unlock()
	})

	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			peer.mu.Lock()
			peer.conns = append(peer.conns, nc)
			peer.mu.Unlock()
			go serveFakeDBusConn(nc, peer)
		}
	}()
	return hostRoot, peer
}

func writeDBusReply(nc net.Conn, outSeq uint32, replyTo uint32, sig string, body ...any) error {
	headers := map[godbus.HeaderField]godbus.Variant{
		godbus.FieldReplySerial: godbus.MakeVariant(replyTo),
	}
	if sig != "" {
		headers[godbus.FieldSignature] = godbus.MakeVariant(godbus.ParseSignatureMust(sig))
	}
	msg := &godbus.Message{
		Type:    godbus.TypeMethodReply,
		Headers: headers,
		Body:    body,
	}
	var buf bytes.Buffer
	if err := msg.EncodeTo(&buf, binary.LittleEndian); err != nil {
		return err
	}
	raw := buf.Bytes()
	binary.LittleEndian.PutUint32(raw[8:12], outSeq)
	_, err := nc.Write(raw)
	return err
}

func serveFakeDBusConn(nc net.Conn, peer *fakeDBusPeer) {
	defer func() { _ = nc.Close() }()
	nul := make([]byte, 1)
	if _, err := io.ReadFull(nc, nul); err != nil || nul[0] != 0 {
		return
	}
	for {
		line, err := readLineRaw(nc)
		if err != nil {
			return
		}
		switch {
		case line == "AUTH":
			_, _ = nc.Write([]byte("REJECTED EXTERNAL\r\n"))
		case strings.HasPrefix(line, "AUTH EXTERNAL"):
			_, _ = nc.Write([]byte("OK 0123456789abcdef0123456789abcdef\r\n"))
		case line == "NEGOTIATE_UNIX_FD":
			_, _ = nc.Write([]byte("ERROR\r\n"))
		case line == "BEGIN":
			serveFakeDBusMessages(nc, peer)
			return
		default:
			_, _ = nc.Write([]byte("REJECTED EXTERNAL\r\n"))
		}
	}
}

func serveFakeDBusMessages(nc net.Conn, peer *fakeDBusPeer) {
	var outSeq uint32
	for {
		msg, err := godbus.DecodeMessage(nc)
		if err != nil {
			return
		}
		if msg.Type != godbus.TypeMethodCall {
			continue
		}
		member, _ := msg.Headers[godbus.FieldMember].Value().(string)
		iface, _ := msg.Headers[godbus.FieldInterface].Value().(string)
		serial := msg.Serial()
		outSeq++

		switch member {
		case "AddMatch", "Subscribe":
			if err := writeDBusReply(nc, outSeq, serial, ""); err != nil {
				return
			}
			continue
		}

		if peer.dropNext.Swap(false) {
			return
		}
		peer.mu.Lock()
		d := peer.delay
		cb := peer.onCall
		peer.mu.Unlock()
		if cb != nil {
			cb(iface, member)
		}
		if d > 0 {
			time.Sleep(d)
		}

		switch {
		case iface == "org.freedesktop.systemd1.Manager" && member == "GetUnit":
			err = writeDBusReply(nc, outSeq, serial, "o",
				godbus.ObjectPath("/org/freedesktop/systemd1/unit/k0sworker_2eservice"))
		case iface == "org.freedesktop.DBus.Properties" && member == "Get":
			var prop string
			if len(msg.Body) >= 2 {
				prop, _ = msg.Body[1].(string)
			}
			switch prop {
			case "ActiveState":
				err = writeDBusReply(nc, outSeq, serial, "v", godbus.MakeVariant("active"))
			case "LoadState":
				err = writeDBusReply(nc, outSeq, serial, "v", godbus.MakeVariant("loaded"))
			case "MainPID":
				err = writeDBusReply(nc, outSeq, serial, "v", godbus.MakeVariant(uint32(12345)))
			case "SystemState":
				err = writeDBusReply(nc, outSeq, serial, "v", godbus.MakeVariant("running"))
			default:
				err = writeDBusReply(nc, outSeq, serial, "v", godbus.MakeVariant(""))
			}
		case iface == "org.freedesktop.systemd1.Manager" && (member == "ListUnits" || member == "ListUnitsByPatterns"):
			units := []sdbus.UnitStatus{{
				Name:        "k0sworker.service",
				Description: "k0s worker",
				LoadState:   "loaded",
				ActiveState: "active",
				SubState:    "running",
				Path:        "/org/freedesktop/systemd1/unit/k0sworker_2eservice",
				JobPath:     "/",
			}}
			err = writeDBusReply(nc, outSeq, serial, "a(ssssssouso)", units)
		case iface == "org.freedesktop.systemd1.Manager" && member == "GetUnitFileState":
			err = writeDBusReply(nc, outSeq, serial, "s", "enabled")
		case iface == "org.freedesktop.systemd1.Manager" && member == "RestartUnit":
			err = writeDBusReply(nc, outSeq, serial, "o",
				godbus.ObjectPath("/org/freedesktop/systemd1/job/1"))
		default:
			err = writeDBusReply(nc, outSeq, serial, "")
		}
		if err != nil {
			return
		}
	}
}

func TestDBusQueryCallerDeadlineDoesNotDropConnOrFallback(t *testing.T) {
	hostRoot, peer := startFakeDBusPeer(t)
	var cliCalled atomic.Bool
	c := New(Config{
		HostRoot: hostRoot,
		Timeout:  2 * time.Second,
		RunCmd: func(context.Context, []string) (string, error) {
			cliCalled.Store(true)
			return "", errors.New("unexpected cli fallback")
		},
	})
	c.dbus = newDBusBackend(hostRoot)
	defer c.Close()

	// Warm up shared connection and verify happy paths.
	active, err := c.Active(context.Background(), "k0sworker")
	if err != nil || !active {
		t.Fatalf("warmup Active = (%v,%v)", active, err)
	}
	pid, err := c.MainPID(context.Background(), "k0sworker")
	if err != nil || pid != 12345 {
		t.Fatalf("warmup MainPID = (%d,%v)", pid, err)
	}
	enabled, err := c.Enabled(context.Background(), "k0sworker")
	if err != nil || !enabled {
		t.Fatalf("warmup Enabled = (%v,%v)", enabled, err)
	}
	units, err := c.ListUnitsByPatterns(context.Background(), "*.service")
	if err != nil || len(units) != 1 {
		t.Fatalf("warmup ListUnitsByPatterns = (%+v,%v)", units, err)
	}
	state, err := c.SystemState(context.Background())
	if err != nil || state != "running" {
		t.Fatalf("warmup SystemState = (%q,%v)", state, err)
	}

	c.dbus.mu.Lock()
	origConn := c.dbus.conn
	c.dbus.mu.Unlock()
	if origConn == nil {
		t.Fatal("expected live shared D-Bus conn after warmup")
	}

	// Slow the D-Bus peer past caller's short deadline.
	peer.mu.Lock()
	peer.delay = 80 * time.Millisecond
	peer.mu.Unlock()

	checkCallerTimeout := func(name string, fn func(context.Context) error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
		defer cancel()
		err := fn(ctx)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("%s err = %v, want context.DeadlineExceeded", name, err)
		}
		if errors.Is(err, errDBusUnavailable) {
			t.Fatalf("%s wrapped errDBusUnavailable on caller deadline: %v", name, err)
		}
		if cliCalled.Load() {
			t.Fatalf("%s unexpectedly invoked CLI fallback on caller deadline", name)
		}
		c.dbus.mu.Lock()
		gotConn := c.dbus.conn
		c.dbus.mu.Unlock()
		if gotConn != origConn || gotConn == nil || !gotConn.Connected() {
			t.Fatalf("%s dropped or replaced healthy shared D-Bus conn on caller deadline", name)
		}
	}

	checkCallerTimeout("Active", func(ctx context.Context) error {
		_, err := c.Active(ctx, "k0sworker")
		return err
	})
	checkCallerTimeout("MainPID", func(ctx context.Context) error {
		_, err := c.MainPID(ctx, "k0sworker")
		return err
	})
	checkCallerTimeout("Enabled", func(ctx context.Context) error {
		_, err := c.Enabled(ctx, "k0sworker")
		return err
	})
	checkCallerTimeout("ListUnitsByPatterns", func(ctx context.Context) error {
		_, err := c.ListUnitsByPatterns(ctx, "*.service")
		return err
	})
	checkCallerTimeout("SystemState", func(ctx context.Context) error {
		_, err := c.SystemState(ctx)
		return err
	})

	// Also verify explicit caller cancellation preserves shared conn.
	cctx, ccancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(15 * time.Millisecond)
		ccancel()
	}()
	if _, err := c.Enabled(cctx, "k0sworker"); !errors.Is(err, context.Canceled) || errors.Is(err, errDBusUnavailable) {
		t.Fatalf("Enabled cancel err = %v, want context.Canceled without errDBusUnavailable", err)
	}
	c.dbus.mu.Lock()
	if c.dbus.conn != origConn {
		c.dbus.mu.Unlock()
		t.Fatal("Enabled cancel dropped shared D-Bus conn")
	}
	c.dbus.mu.Unlock()

	// Wait slightly past peer.delay so queued replies drain cleanly before restoring delay.
	time.Sleep(100 * time.Millisecond)
	peer.mu.Lock()
	peer.delay = 0
	peer.mu.Unlock()
	if active, err := c.Active(context.Background(), "k0sworker"); err != nil || !active {
		t.Fatalf("post-timeout Active on same conn = (%v,%v)", active, err)
	}
}

func TestDBusSystemConnLockedFastFailsPreCancelledCtx(t *testing.T) {
	b := newDBusBackend(t.TempDir())
	defer b.close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, err := b.systemConn(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("systemConn(canceled) err = %v, want context.Canceled", err)
	}
	if errors.Is(err, errDBusUnavailable) {
		t.Fatalf("systemConn(canceled) should not wrap errDBusUnavailable: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("systemConn(canceled) took %v", elapsed)
	}

	expCtx, expCancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer expCancel()
	if _, err := b.systemConn(expCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("systemConn(expired) err = %v, want context.DeadlineExceeded", err)
	}
}

func TestDBusInternalTimeoutAndDeadTransportDropConn(t *testing.T) {
	hostRoot, peer := startFakeDBusPeer(t)
	b := newDBusBackend(hostRoot)
	defer b.close()

	if _, err := b.dbusActive(context.Background(), "k0sworker"); err != nil {
		t.Fatalf("warmup dbusActive: %v", err)
	}
	b.mu.Lock()
	firstConn := b.conn
	b.mu.Unlock()

	// 1) Dead transport mid-call (parentCtx.Err() == nil) must dropConn and retry on fresh conn.
	peer.dropNext.Store(true)
	if active, err := b.dbusActive(context.Background(), "k0sworker"); err != nil || !active {
		t.Fatalf("dbusActive after dead transport = (%v,%v), want (true, nil) after drop+retry", active, err)
	}
	b.mu.Lock()
	secondConn := b.conn
	b.mu.Unlock()
	if secondConn == nil || secondConn == firstConn {
		t.Fatal("expected dead transport to drop firstConn and rebuild secondConn")
	}

	peer.dropNext.Store(true)
	if units, err := b.dbusListUnitsByPatterns(context.Background(), []string{"*.service"}); err != nil || len(units) != 1 {
		t.Fatalf("dbusListUnitsByPatterns after dead transport = (%+v,%v), want 1 unit", units, err)
	}
	peer.dropNext.Store(true)
	if enabled, err := b.dbusEnabled(context.Background(), "k0sworker"); err != nil || !enabled {
		t.Fatalf("dbusEnabled after dead transport = (%v,%v), want (true, nil)", enabled, err)
	}
	peer.dropNext.Store(true)
	if state, err := b.dbusSystemState(context.Background()); err != nil || state != "running" {
		t.Fatalf("dbusSystemState after dead transport = (%q,%v), want (\"running\", nil)", state, err)
	}

	// 2) Internal op timeout (fetch returns DeadlineExceeded while parentCtx.Err() == nil)
	// must dropConn, retry, and return errDBusUnavailable.
	b.mu.Lock()
	beforeInternal := b.conn
	b.mu.Unlock()
	var calls int
	_, err := b.getProp(context.Background(), "k0sworker", "ActiveState",
		func(_ *sdbus.Conn, _ context.Context, _, _ string) (*sdbus.Property, error) {
			calls++
			return nil, context.DeadlineExceeded
		})
	if !errors.Is(err, errDBusUnavailable) {
		t.Fatalf("getProp internal DeadlineExceeded err = %v, want errDBusUnavailable", err)
	}
	if calls != 2 {
		t.Fatalf("getProp internal DeadlineExceeded calls = %d, want 2 (initial + 1 retry)", calls)
	}
	b.mu.Lock()
	thirdConn := b.conn
	b.mu.Unlock()
	if thirdConn == beforeInternal {
		t.Fatal("expected internal DeadlineExceeded to drop beforeInternal and rebuild")
	}
}

func TestIsTransportDeadMatchesGodbusErrClosed(t *testing.T) {
	if !isTransportDead(godbus.ErrClosed) {
		t.Fatal("isTransportDead(godbus.ErrClosed) = false, want true")
	}
	if !isTransportDead(fmt.Errorf("wrapped: %w", godbus.ErrClosed)) {
		t.Fatal("isTransportDead(wrapped godbus.ErrClosed) = false, want true")
	}
	if isTransportDead(nil) {
		t.Fatal("isTransportDead(nil) = true, want false")
	}
}

func TestDBusDropConnIdempotentAndGenerationSafe(t *testing.T) {
	hostRoot, _ := startFakeDBusPeer(t)
	b := newDBusBackend(hostRoot)
	defer b.close()

	// dropConn(nil) on a cold backend must not panic.
	b.dropConn(nil)

	if _, err := b.dbusActive(context.Background(), "k0sworker"); err != nil {
		t.Fatalf("warmup dbusActive: %v", err)
	}
	b.mu.Lock()
	conn1 := b.conn
	b.mu.Unlock()
	if conn1 == nil || !conn1.Connected() {
		t.Fatal("expected live conn1 after warmup")
	}

	// Concurrent dropConn on the same conn1 must be idempotent and race-free.
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			b.dropConn(conn1)
		})
	}
	wg.Wait()
	b.mu.Lock()
	if b.conn != nil {
		b.mu.Unlock()
		t.Fatal("expected b.conn == nil after dropConn(conn1)")
	}
	b.mu.Unlock()

	// Rebuild a new generation conn2, then call dropConn with stale conn1:
	// sibling callers seeing ErrClosed on conn1 must never drop conn2.
	if _, err := b.dbusActive(context.Background(), "k0sworker"); err != nil {
		t.Fatalf("rebuild dbusActive: %v", err)
	}
	b.mu.Lock()
	conn2 := b.conn
	b.mu.Unlock()
	if conn2 == nil || conn2 == conn1 || !conn2.Connected() {
		t.Fatal("expected fresh live conn2 != conn1")
	}
	b.dropConn(conn1)
	b.mu.Lock()
	afterStaleDrop := b.conn
	b.mu.Unlock()
	if afterStaleDrop != conn2 || !conn2.Connected() {
		t.Fatal("stale dropConn(conn1) dropped newer conn2")
	}
}

func TestDBusDropConnMidFlightRetriesAndFallsBackWithoutErrClosed(t *testing.T) {
	hostRoot, peer := startFakeDBusPeer(t)
	var cliCalls atomic.Int32
	c := New(Config{
		HostRoot: hostRoot,
		Timeout:  2 * time.Second,
		RunCmd: func(_ context.Context, args []string) (string, error) {
			cliCalls.Add(1)
			joined := strings.Join(args, " ")
			switch {
			case strings.Contains(joined, "is-active"):
				return "active\n", nil
			case strings.Contains(joined, "LoadState"):
				return "loaded\n", nil
			case strings.Contains(joined, "MainPID"):
				return "12345\n", nil
			case strings.Contains(joined, "is-enabled"):
				return "enabled\n", nil
			case strings.Contains(joined, "list-units"):
				return "k0sworker.service loaded active running k0s worker\n", nil
			case strings.Contains(joined, "is-system-running"):
				return "running\n", nil
			default:
				return "", nil
			}
		},
	})
	c.dbus = newDBusBackend(hostRoot)
	defer c.Close()

	// 1) Deterministic single mid-flight dropConn across every query verb:
	// each verb sees godbus.ErrClosed on attempt 0, retries on a fresh conn,
	// and succeeds via D-Bus with zero CLI fallback.
	assertOneShotRetry := func(name, targetMember string, fn func() error) {
		t.Helper()
		if _, err := c.Active(context.Background(), "k0sworker"); err != nil {
			t.Fatalf("%s pre-warmup: %v", name, err)
		}
		c.dbus.mu.Lock()
		origConn := c.dbus.conn
		c.dbus.mu.Unlock()

		var dropped atomic.Bool
		peer.mu.Lock()
		peer.onCall = func(_, member string) {
			if member == targetMember && dropped.CompareAndSwap(false, true) {
				c.dbus.dropConn(origConn)
			}
		}
		peer.mu.Unlock()
		defer func() {
			peer.mu.Lock()
			peer.onCall = nil
			peer.mu.Unlock()
		}()

		beforeCLI := cliCalls.Load()
		if err := fn(); err != nil {
			t.Fatalf("%s failed after mid-flight dropConn: %v (ErrClosed=%v)",
				name, err, errors.Is(err, godbus.ErrClosed))
		}
		if !dropped.Load() {
			t.Fatalf("%s did not trigger onCall for %s", name, targetMember)
		}
		if cliCalls.Load() != beforeCLI {
			t.Fatalf("%s fell back to CLI instead of retrying on fresh D-Bus conn", name)
		}
		c.dbus.mu.Lock()
		newConn := c.dbus.conn
		c.dbus.mu.Unlock()
		if newConn == nil || newConn == origConn {
			t.Fatalf("%s did not rebuild shared conn", name)
		}
	}

	assertOneShotRetry("Active(Properties.Get)", "Get", func() error {
		ok, err := c.Active(context.Background(), "k0sworker")
		if err != nil || !ok {
			return fmt.Errorf("got (%v, %w)", ok, err)
		}
		return nil
	})
	// Deterministically verify getProp retries on a closed conn: closing
	// conn before GetUnitPropertyContext usually yields godbus.ErrClosed,
	// or net.ErrClosed if inWorker finalizes calls between calls.track
	// and sendMessageAndIfClosed inside godbus.(*Conn).send.
	var sawClosedErr atomic.Bool
	var propCalls atomic.Int32
	v, err := c.dbus.getProp(context.Background(), "k0sworker", "ActiveState",
		func(conn *sdbus.Conn, fctx context.Context, unit, prop string) (*sdbus.Property, error) {
			if propCalls.Add(1) == 1 {
				c.dbus.dropConn(conn)
				p, ferr := conn.GetUnitPropertyContext(fctx, unit, prop)
				if errors.Is(ferr, godbus.ErrClosed) || errors.Is(ferr, net.ErrClosed) {
					sawClosedErr.Store(true)
				}
				return p, ferr
			}
			return conn.GetUnitPropertyContext(fctx, unit, prop)
		})
	if err != nil || propString(v) != "active" || !sawClosedErr.Load() || propCalls.Load() != 2 {
		t.Fatalf("deterministic getProp closed-conn retry: v=%v err=%v sawClosedErr=%v calls=%d",
			v, err, sawClosedErr.Load(), propCalls.Load())
	}
	assertOneShotRetry("Exists(Properties.Get)", "Get", func() error {
		ok, err := c.Exists(context.Background(), "k0sworker")
		if err != nil || !ok {
			return fmt.Errorf("got (%v, %w)", ok, err)
		}
		return nil
	})
	assertOneShotRetry("MainPID", "Get", func() error {
		pid, err := c.MainPID(context.Background(), "k0sworker")
		if err != nil || pid != 12345 {
			return fmt.Errorf("got (%d, %w)", pid, err)
		}
		return nil
	})
	assertOneShotRetry("ListUnitsByPatterns", "ListUnitsByPatterns", func() error {
		units, err := c.ListUnitsByPatterns(context.Background(), "*.service")
		if err != nil || len(units) != 1 {
			return fmt.Errorf("got (%d, %w)", len(units), err)
		}
		return nil
	})
	assertOneShotRetry("Enabled", "GetUnitFileState", func() error {
		ok, err := c.Enabled(context.Background(), "k0sworker")
		if err != nil || !ok {
			return fmt.Errorf("got (%v, %w)", ok, err)
		}
		return nil
	})
	assertOneShotRetry("SystemState", "Get", func() error {
		st, err := c.SystemState(context.Background())
		if err != nil || st != "running" {
			return fmt.Errorf("got (%q, %w)", st, err)
		}
		return nil
	})

	// 2) Persistent mid-flight dropConn across both attempt 0 and retry
	// (and across job verbs in dbus_jobs.go) must wrap errDBusUnavailable
	// and fall back cleanly to CLI, never surfacing raw godbus.ErrClosed.
	peer.mu.Lock()
	peer.onCall = func(_, _ string) {
		c.dbus.mu.Lock()
		cur := c.dbus.conn
		c.dbus.mu.Unlock()
		c.dbus.dropConn(cur)
	}
	peer.mu.Unlock()

	checkFallback := func(name string, fn func() error) {
		t.Helper()
		beforeCLI := cliCalls.Load()
		err := fn()
		if err != nil {
			t.Fatalf("%s returned error instead of CLI fallback: %v (ErrClosed=%v)",
				name, err, errors.Is(err, godbus.ErrClosed))
		}
		if cliCalls.Load() <= beforeCLI {
			t.Fatalf("%s did not invoke CLI fallback", name)
		}
	}

	checkFallback("Active_persistent_drop", func() error {
		ok, err := c.Active(context.Background(), "k0sworker")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("expected active=true")
		}
		return nil
	})
	checkFallback("Enabled_persistent_drop", func() error {
		ok, err := c.Enabled(context.Background(), "k0sworker")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("expected enabled=true")
		}
		return nil
	})
	checkFallback("ListUnitsByPatterns_persistent_drop", func() error {
		units, err := c.ListUnitsByPatterns(context.Background(), "*.service")
		if err != nil {
			return err
		}
		if len(units) != 1 {
			return fmt.Errorf("got %d units", len(units))
		}
		return nil
	})
	checkFallback("SystemState_persistent_drop", func() error {
		st, err := c.SystemState(context.Background())
		if err != nil {
			return err
		}
		if st != "running" {
			return fmt.Errorf("got %q", st)
		}
		return nil
	})
	checkFallback("Restart_midflight_drop", func() error {
		return c.Restart(context.Background(), "k0sworker")
	})
	checkFallback("Signal_midflight_drop", func() error {
		return c.Signal(context.Background(), "k0sworker", "SIGTERM")
	})
	checkFallback("DaemonReload_midflight_drop", func() error {
		return c.DaemonReload(context.Background())
	})
	checkFallback("ResetFailed_midflight_drop", func() error {
		return c.ResetFailed(context.Background(), "k0sworker")
	})

	// Also verify the direct backend helpers wrap errDBusUnavailable (not raw godbus.ErrClosed).
	if _, err := c.dbus.dbusActive(context.Background(), "k0sworker"); !errors.Is(err, errDBusUnavailable) || errors.Is(err, godbus.ErrClosed) {
		t.Fatalf("dbusActive persistent drop = %v, want errDBusUnavailable without raw godbus.ErrClosed", err)
	}
	if err := c.dbus.dbusDaemonReload(context.Background()); !errors.Is(err, errDBusUnavailable) || errors.Is(err, godbus.ErrClosed) {
		t.Fatalf("dbusDaemonReload mid-flight drop = %v, want errDBusUnavailable without raw godbus.ErrClosed", err)
	}
	if err := c.dbus.dbusJob(context.Background(), "k0sworker", "restart"); !errors.Is(err, errDBusUnavailable) || errors.Is(err, godbus.ErrClosed) {
		t.Fatalf("dbusJob mid-flight drop = %v, want errDBusUnavailable without raw godbus.ErrClosed", err)
	}
}

func TestDBusConcurrentDropConnStormRace(t *testing.T) {
	hostRoot, peer := startFakeDBusPeer(t)
	peer.mu.Lock()
	peer.delay = time.Millisecond
	peer.mu.Unlock()

	var cliCalls atomic.Int32
	c := New(Config{
		HostRoot: hostRoot,
		Timeout:  2 * time.Second,
		RunCmd: func(_ context.Context, args []string) (string, error) {
			cliCalls.Add(1)
			joined := strings.Join(args, " ")
			switch {
			case strings.Contains(joined, "is-active"):
				return "active\n", nil
			case strings.Contains(joined, "LoadState"):
				return "loaded\n", nil
			case strings.Contains(joined, "MainPID"):
				return "12345\n", nil
			case strings.Contains(joined, "is-enabled"):
				return "enabled\n", nil
			case strings.Contains(joined, "list-units"):
				return "k0sworker.service loaded active running k0s worker\n", nil
			case strings.Contains(joined, "is-system-running"):
				return "running\n", nil
			default:
				return "", nil
			}
		},
	})
	c.dbus = newDBusBackend(hostRoot)
	defer c.Close()

	if _, err := c.Active(context.Background(), "k0sworker"); err != nil {
		t.Fatalf("warmup Active: %v", err)
	}

	stop := make(chan struct{})
	var disrupters sync.WaitGroup
	disrupters.Go(func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Millisecond):
				c.dbus.mu.Lock()
				cur := c.dbus.conn
				c.dbus.mu.Unlock()
				if cur != nil {
					c.dbus.dropConn(cur)
				}
			}
		}
	})
	disrupters.Go(func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(3 * time.Millisecond):
				peer.dropNext.Store(true)
			}
		}
	})

	errCh := make(chan error, 8*40)
	var workers sync.WaitGroup
	for g := range 8 {
		workers.Go(func() {
			for i := range 40 {
				ctx := context.Background()
				var err error
				switch (g + i) % 9 {
				case 0:
					var ok bool
					ok, err = c.Active(ctx, "k0sworker")
					if err == nil && !ok {
						err = errors.New("Active returned false")
					}
				case 1:
					var ok bool
					ok, err = c.Exists(ctx, "k0sworker")
					if err == nil && !ok {
						err = errors.New("Exists returned false")
					}
				case 2:
					var pid uint32
					pid, err = c.MainPID(ctx, "k0sworker")
					if err == nil && pid != 12345 {
						err = fmt.Errorf("MainPID=%d", pid)
					}
				case 3:
					var ok bool
					ok, err = c.Enabled(ctx, "k0sworker")
					if err == nil && !ok {
						err = errors.New("Enabled returned false")
					}
				case 4:
					var units []UnitInfo
					units, err = c.ListUnitsByPatterns(ctx, "*.service")
					if err == nil && len(units) != 1 {
						err = fmt.Errorf("ListUnits=%d", len(units))
					}
				case 5:
					var st string
					st, err = c.SystemState(ctx)
					if err == nil && st != "running" {
						err = fmt.Errorf("SystemState=%q", st)
					}
				case 6:
					err = c.DaemonReload(ctx)
				case 7:
					err = c.ResetFailed(ctx, "k0sworker")
				case 8:
					err = c.Signal(ctx, "k0sworker", "SIGTERM")
				}
				if err != nil {
					errCh <- fmt.Errorf("g=%d i=%d: %w", g, i, err)
					return
				}
			}
		})
	}
	workers.Wait()
	close(stop)
	disrupters.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrent dropConn storm surfaced error (ErrClosed=%v): %v",
			errors.Is(err, godbus.ErrClosed), err)
	}

	// Post-storm: verify D-Bus recovers cleanly on a fresh conn without CLI fallback.
	peer.mu.Lock()
	peer.delay = 0
	peer.mu.Unlock()
	peer.dropNext.Store(false)
	beforeCLI := cliCalls.Load()
	if active, err := c.Active(context.Background(), "k0sworker"); err != nil || !active {
		t.Fatalf("post-storm Active = (%v,%v)", active, err)
	}
	if cliCalls.Load() != beforeCLI {
		t.Fatalf("post-storm Active unexpectedly fell back to CLI (cliCalls %d -> %d)", beforeCLI, cliCalls.Load())
	}
}

func TestDBusFrameConnPartialHeaderPaddingCloseDoesNotPanic(t *testing.T) {
	hostRoot, err := os.MkdirTemp("/tmp", "nhadb-pad-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(hostRoot) })

	sockDir := filepath.Join(hostRoot, "run", "systemd")
	if err := os.MkdirAll(sockDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sockPath := filepath.Join(sockDir, "private")
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	srvErrCh := make(chan error, 1)
	go func() {
		srvConn, aerr := ln.Accept()
		if aerr != nil {
			srvErrCh <- aerr
			return
		}
		defer func() { _ = srvConn.Close() }()

		nul := make([]byte, 1)
		if _, err := io.ReadFull(srvConn, nul); err != nil {
			srvErrCh <- err
			return
		}
		for {
			line, err := readLineRaw(srvConn)
			if err != nil {
				srvErrCh <- err
				return
			}
			switch {
			case line == "AUTH":
				_, _ = srvConn.Write([]byte("REJECTED EXTERNAL\r\n"))
			case strings.HasPrefix(line, "AUTH EXTERNAL"):
				_, _ = srvConn.Write([]byte("OK 0123456789abcdef0123456789abcdef\r\n"))
			case line == "BEGIN":
				msg, err := godbus.DecodeMessage(srvConn)
				if err != nil {
					srvErrCh <- err
					return
				}
				// Build a deterministic little-endian TypeMethodReply with
				// FieldReplySerial (8B) followed by FieldSignature("s") (7B)
				// so a(yv) has rawHlen=15 (requiring 1 padding byte before body).
				const rawHlen = 15
				full := make([]byte, 44)
				full[0] = 'l'
				full[1] = byte(godbus.TypeMethodReply)
				full[2] = 0
				full[3] = 1
				binary.LittleEndian.PutUint32(full[4:8], 12) // body len: uint32(7) + "enabled\x00"
				binary.LittleEndian.PutUint32(full[8:12], 1) // reply serial
				binary.LittleEndian.PutUint32(full[12:16], rawHlen)
				// Header 1: FieldReplySerial (5), sig "u", uint32(msg.Serial())
				full[16] = byte(godbus.FieldReplySerial)
				full[17], full[18], full[19] = 1, 'u', 0
				binary.LittleEndian.PutUint32(full[20:24], msg.Serial())
				// Header 2: FieldSignature (8), sig "g", signature "s"
				full[24] = byte(godbus.FieldSignature)
				full[25], full[26], full[27] = 1, 'g', 0
				full[28], full[29], full[30] = 1, 's', 0
				// Byte 31 is the 8-byte alignment padding byte; bytes 32..43 are the body.
				binary.LittleEndian.PutUint32(full[32:36], 7)
				copy(full[36:44], "enabled\x00")
				if _, err := godbus.DecodeMessage(bytes.NewReader(full)); err != nil {
					srvErrCh <- fmt.Errorf("invalid test frame: %w", err)
					return
				}
				// Truncate right after a(yv), before its 8-byte alignment padding.
				partial := full[:16+rawHlen]
				if _, err := srvConn.Write(partial); err != nil {
					srvErrCh <- err
					return
				}
				srvErrCh <- nil
				return
			default:
				_, _ = srvConn.Write([]byte("REJECTED EXTERNAL\r\n"))
			}
		}
	}()

	c, _, err := dialSystemdPrivate(t.Context(), sockPath)
	if err != nil {
		t.Fatalf("dialSystemdPrivate: %v", err)
	}
	defer func() { _ = c.Close() }()

	call := c.Object("org.freedesktop.systemd1", "/org/freedesktop/systemd1").
		Call("org.freedesktop.systemd1.Manager.GetUnitFileState", 0, "k0sworker.service")
	if call.Err == nil {
		t.Fatal("expected error when peer closes mid-padding, got nil")
	}

	if err := <-srvErrCh; err != nil {
		t.Fatalf("fake peer error: %v", err)
	}

	select {
	case <-c.Context().Done():
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for inWorker to shut down conn after partial frame")
	}
}

func TestDBusFrameConnEdgeCases(t *testing.T) {
	t.Run("split BEGIN switches to framed mode", func(t *testing.T) {
		a, b := net.Pipe()
		defer func() { _ = a.Close() }()
		defer func() { _ = b.Close() }()

		fc := newDBusFrameConn(a)
		done := make(chan struct{})
		go func() {
			defer close(done)
			want := make([]byte, len("AUTH\r\nBEGIN\r\n"))
			if _, err := io.ReadFull(b, want); err != nil {
				return
			}
			// Send a complete minimal D-Bus message after split BEGIN.
			msg := &godbus.Message{
				Type: godbus.TypeMethodReply,
				Headers: map[godbus.HeaderField]godbus.Variant{
					godbus.FieldReplySerial: godbus.MakeVariant(uint32(1)),
				},
			}
			var enc bytes.Buffer
			if err := msg.EncodeTo(&enc, binary.LittleEndian); err == nil {
				raw := enc.Bytes()
				binary.LittleEndian.PutUint32(raw[8:12], 1)
				_, _ = b.Write(raw)
			}
		}()

		for _, chunk := range [][]byte{[]byte("AUTH\r\n"), []byte("BEG"), []byte("IN\r\n")} {
			if _, err := fc.Write(chunk); err != nil {
				t.Fatalf("Write(%q): %v", chunk, err)
			}
		}
		if !fc.framed.Load() {
			t.Fatal("expected split BEGIN\\r\\n to enable framed mode")
		}
		msg, err := godbus.DecodeMessage(fc)
		if err != nil {
			t.Fatalf("DecodeMessage after split BEGIN: %v", err)
		}
		if msg.Type != godbus.TypeMethodReply {
			t.Fatalf("msg.Type = %v, want TypeMethodReply", msg.Type)
		}
		<-done
	})

	t.Run("invalid byte order and oversized header return clean errors", func(t *testing.T) {
		a, b := net.Pipe()
		defer func() { _ = a.Close() }()
		defer func() { _ = b.Close() }()

		fc := newDBusFrameConn(a)
		fc.framed.Store(true)

		go func() {
			var bad [16]byte
			bad[0] = 'X'
			_, _ = b.Write(bad[:])
		}()
		var ime godbus.InvalidMessageError
		if _, err := godbus.DecodeMessage(fc); err == nil {
			t.Fatal("expected error on invalid byte order")
		} else if !errors.As(err, &ime) {
			t.Fatalf("err = %T (%v), want godbus.InvalidMessageError", err, err)
		}
		// Drain remaining 15 bytes of bad header before sending oversized header.
		var drain [15]byte
		if _, err := io.ReadFull(fc, drain[:]); err != nil {
			t.Fatalf("drain bad header remainder: %v", err)
		}

		go func() {
			var big [16]byte
			big[0] = 'l'
			binary.LittleEndian.PutUint32(big[4:8], 1<<27)
			binary.LittleEndian.PutUint32(big[12:16], 16)
			_, _ = b.Write(big[:])
		}()
		if _, err := godbus.DecodeMessage(fc); err == nil {
			t.Fatal("expected error on oversized header")
		} else if !errors.As(err, &ime) {
			t.Fatalf("err = %T (%v), want godbus.InvalidMessageError", err, err)
		}
	})
}

func TestDBusMidFramePaddingTruncateRetriesAndFallsBackToCLI(t *testing.T) {
	if !isTransportDead(io.ErrUnexpectedEOF) {
		t.Fatal("isTransportDead(io.ErrUnexpectedEOF) = false, want true")
	}
	if !isTransportDead(fmt.Errorf("wrapped: %w", io.ErrUnexpectedEOF)) {
		t.Fatal("isTransportDead(wrapped io.ErrUnexpectedEOF) = false, want true")
	}

	buildMidPaddingTruncatedReply := func(replySerial uint32, bodyWord string) []byte {
		const rawHlen = 15
		bodyBytes := 4 + len(bodyWord) + 1
		full := make([]byte, 16+rawHlen+1+bodyBytes)
		full[0] = 'l'
		full[1] = byte(godbus.TypeMethodReply)
		full[2] = 0
		full[3] = 1
		binary.LittleEndian.PutUint32(full[4:8], uint32(bodyBytes))
		binary.LittleEndian.PutUint32(full[8:12], 1)
		binary.LittleEndian.PutUint32(full[12:16], rawHlen)
		full[16] = byte(godbus.FieldReplySerial)
		full[17], full[18], full[19] = 1, 'u', 0
		binary.LittleEndian.PutUint32(full[20:24], replySerial)
		full[24] = byte(godbus.FieldSignature)
		full[25], full[26], full[27] = 1, 'g', 0
		full[28], full[29], full[30] = 1, 's', 0
		binary.LittleEndian.PutUint32(full[32:36], uint32(len(bodyWord)))
		copy(full[36:], bodyWord+"\x00")
		return full[:16+rawHlen]
	}

	runPeer := func(t *testing.T, truncateOnAccept func(acceptNum int32) bool) (string, *atomic.Int32) {
		t.Helper()
		hostRoot, err := os.MkdirTemp("/tmp", "nhadb-eof-*")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(hostRoot) })

		sockDir := filepath.Join(hostRoot, "run", "systemd")
		if err := os.MkdirAll(sockDir, 0o755); err != nil {
			t.Fatal(err)
		}
		ln, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", filepath.Join(sockDir, "private"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })

		var accepts atomic.Int32
		var connsMu sync.Mutex
		var conns []net.Conn
		t.Cleanup(func() {
			connsMu.Lock()
			for _, nc := range conns {
				_ = nc.Close()
			}
			connsMu.Unlock()
		})

		go func() {
			for {
				nc, aerr := ln.Accept()
				if aerr != nil {
					return
				}
				connsMu.Lock()
				conns = append(conns, nc)
				connsMu.Unlock()
				// NewConnection dials sysconn first, sigconn second; track sysconn generations via handshake order.
				acceptNum := accepts.Add(1)
				go func(c net.Conn, n int32) {
					defer func() { _ = c.Close() }()
					nul := make([]byte, 1)
					if _, err := io.ReadFull(c, nul); err != nil || nul[0] != 0 {
						return
					}
					for {
						line, err := readLineRaw(c)
						if err != nil {
							return
						}
						switch {
						case line == "AUTH":
							_, _ = c.Write([]byte("REJECTED EXTERNAL\r\n"))
						case strings.HasPrefix(line, "AUTH EXTERNAL"):
							_, _ = c.Write([]byte("OK 0123456789abcdef0123456789abcdef\r\n"))
						case line == "NEGOTIATE_UNIX_FD":
							_, _ = c.Write([]byte("ERROR\r\n"))
						case line == "BEGIN":
							var outSeq uint32
							for {
								msg, err := godbus.DecodeMessage(c)
								if err != nil {
									return
								}
								if msg.Type != godbus.TypeMethodCall {
									continue
								}
								member, _ := msg.Headers[godbus.FieldMember].Value().(string)
								iface, _ := msg.Headers[godbus.FieldInterface].Value().(string)
								serial := msg.Serial()
								outSeq++
								switch {
								case member == "AddMatch" || member == "Subscribe":
									if writeDBusReply(c, outSeq, serial, "") != nil {
										return
									}
								case iface == "org.freedesktop.systemd1.Manager" && member == "GetUnit":
									if writeDBusReply(c, outSeq, serial, "o",
										godbus.ObjectPath("/org/freedesktop/systemd1/unit/k0sworker_2eservice")) != nil {
										return
									}
								case (iface == "org.freedesktop.DBus.Properties" && member == "Get") ||
									(iface == "org.freedesktop.systemd1.Manager" && member == "GetUnitFileState"):
									if truncateOnAccept(n) {
										_, _ = c.Write(buildMidPaddingTruncatedReply(serial, "active"))
										return
									}
									if member == "GetUnitFileState" {
										if writeDBusReply(c, outSeq, serial, "s", "enabled") != nil {
											return
										}
									} else {
										if writeDBusReply(c, outSeq, serial, "v", godbus.MakeVariant("active")) != nil {
											return
										}
									}
								default:
									if writeDBusReply(c, outSeq, serial, "") != nil {
										return
									}
								}
							}
						default:
							_, _ = c.Write([]byte("REJECTED EXTERNAL\r\n"))
						}
					}
				}(nc, acceptNum)
			}
		}()
		return hostRoot, &accepts
	}

	t.Run("transient mid-padding EOF retries on fresh conn without CLI fallback", func(t *testing.T) {
		// First sdbus.NewConnection dials sysconn (#1) and sigconn (#2); truncate #1 only.
		hostRoot, accepts := runPeer(t, func(n int32) bool { return n <= 2 })
		var cliCalls atomic.Int32
		c := New(Config{
			HostRoot: hostRoot,
			Timeout:  2 * time.Second,
			RunCmd: func(context.Context, []string) (string, error) {
				cliCalls.Add(1)
				return "", errors.New("unexpected CLI fallback on transient mid-frame EOF")
			},
		})
		c.dbus = newDBusBackend(hostRoot)
		defer c.Close()

		active, err := c.Active(context.Background(), "k0sworker")
		if err != nil || !active {
			t.Fatalf("c.Active after transient mid-padding EOF = (%v, %v), want (true, nil)", active, err)
		}
		if cliCalls.Load() != 0 {
			t.Fatalf("cliCalls = %d, want 0 (should recover via D-Bus retry)", cliCalls.Load())
		}
		if accepts.Load() < 4 {
			t.Fatalf("accepts = %d, want >= 4 (initial + retry conn pair)", accepts.Load())
		}
	})

	t.Run("persistent mid-padding EOF drops conn and falls back to CLI", func(t *testing.T) {
		hostRoot, accepts := runPeer(t, func(int32) bool { return true })
		var cliCalls atomic.Int32
		c := New(Config{
			HostRoot: hostRoot,
			Timeout:  2 * time.Second,
			RunCmd: func(_ context.Context, args []string) (string, error) {
				cliCalls.Add(1)
				joined := strings.Join(args, " ")
				switch {
				case strings.Contains(joined, "is-active"):
					return "active\n", nil
				case strings.Contains(joined, "is-enabled"):
					return "enabled\n", nil
				default:
					return "", nil
				}
			},
		})
		c.dbus = newDBusBackend(hostRoot)
		defer c.Close()

		active, err := c.Active(context.Background(), "k0sworker")
		if err != nil || !active {
			t.Fatalf("c.Active on persistent mid-padding EOF = (%v, %v), want (true, nil) via CLI fallback", active, err)
		}
		enabled, err := c.Enabled(context.Background(), "k0sworker")
		if err != nil || !enabled {
			t.Fatalf("c.Enabled on persistent mid-padding EOF = (%v, %v), want (true, nil) via CLI fallback", enabled, err)
		}
		if cliCalls.Load() != 2 {
			t.Fatalf("cliCalls = %d, want 2", cliCalls.Load())
		}
		if accepts.Load() < 4 {
			t.Fatalf("accepts = %d, want >= 4 (initial + retry)", accepts.Load())
		}
	})
}
