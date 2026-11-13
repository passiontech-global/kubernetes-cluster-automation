//go:build linux

// dbus_linux.go — the zero-fork systemd control path: a persistent
// D-Bus connection to the host's /run/systemd/private (under
// HostRoot) replaces the per-call `nsenter -t 1 ... systemctl`
// fork for the hot unit-control verbs. This file owns the
// connection lifecycle (dial/auth, lazy rebuild, disable latch,
// teardown); the property reads + systemctl-mirroring query verbs
// live in dbus_query_linux.go and the job verbs in dbus_jobs.go.
// The conn is rebuilt lazily whenever the socket drops (systemd
// restart, socket GC). Only wired when the caller supplied NO exec
// seams — tests keep the 100% RunCmd path.
package systemd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"

	sdbus "github.com/coreos/go-systemd/v22/dbus"
	godbus "github.com/godbus/dbus/v5"
)

// errDBusUnavailable marks CONNECTION-level failures only (socket
// missing, dial/auth/hello refused) — the Client dispatch falls
// back to the nsenter systemctl path on it. Method-level errors
// (unknown unit, failed job) are returned unwrapped so a failed
// restart is never retried through a second transport.
var errDBusUnavailable = errors.New("systemd dbus unavailable")

// dbusBackend owns the lazy systemd private-bus connection.
type dbusBackend struct {
	mu   sync.Mutex
	conn *sdbus.Conn
	// rawSys/rawSig are the godbus conns NewConnection dialed —
	// sysconn first (the one LoadUnit/ListUnitFiles needs), sigconn
	// second (the one JobRemoved signals arrive on). Kept only to
	// issue the Manager calls go-systemd v22 does not wrap, and to
	// watch transport death (each godbus Conn's Context cancels on
	// Close). Both nil until a conn is built and reset whenever the
	// conn is.
	rawSys *godbus.Conn
	rawSig *godbus.Conn
	path   string
	// disabled latches the backend off for the process lifetime
	// when the socket is PERMANENTLY unreachable (EACCES — the
	// private socket is root-only and the agent runs unprivileged
	// under some unit configs — or ENOENT — no systemd at all).
	// Without the latch every verb would redial + re-warn each
	// cycle; with it the CLI fallback serves silently after one
	// warnOnce diagnostic.
	disabled atomic.Bool
	warnOnce sync.Once
}

// newDBusBackend returns the backend for hostRoot — the socket
// lives at <hostRoot>/run/systemd/private ("/" on a standalone
// host, "/host" in the DaemonSet mount).
func newDBusBackend(hostRoot string) *dbusBackend {
	return &dbusBackend{
		path: filepath.Join(hostRoot, "run", "systemd", "private"),
	}
}

// dialSystemdPrivate opens ONE authenticated connection to the
// systemd private socket. godbus.Connect is FORBIDDEN here: it ends
// in org.freedesktop.DBus.Hello, which the peer-to-peer
// /run/systemd/private socket rejects 100% of the time — every
// Connect failed and the client lived on the nsenter systemctl
// fallback forever. Dial + Auth(EXTERNAL, our uid) is the whole
// handshake this socket accepts — the same shape go-systemd's own
// NewSystemdConnectionContext uses (it skips Hello for exactly this
// reason). The host's private socket is root-only anyway.
func dialSystemdPrivate(path string) (*godbus.Conn, error) {
	c, err := godbus.Dial("unix:path=" + path)
	if err != nil {
		return nil, err
	}
	if err := c.Auth([]godbus.Auth{
		godbus.AuthExternal(strconv.Itoa(os.Getuid())),
	}); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

// systemConn returns a live conn, rebuilding it when the previous
// one dropped — NewConnection does NOT auto-reconnect (it dials
// sys+sig conns once), so liveness is checked per call.
//
// sdbus.NewConnection requires each dialed conn to be fully
// initialized, but "fully" for the private socket means Dial+Auth
// only — Hello is rejected there (see dialSystemdPrivate). After
// the conn is built, Subscribe() asks PID 1 to emit the
// JobRemoved/UnitNew/PropertiesChanged signals the job waits in
// dbusJob depend on; without it StartUnitContext-family calls
// enqueue fine but the completion channel never fires and every
// restart hangs until ctx timeout. The error is ignored: a refused
// Subscribe degrades to the pre-signal behaviour, not a dead conn.
func (b *dbusBackend) systemConn(ctx context.Context) (*sdbus.Conn, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.systemConnLocked(ctx)
}

// systemConnLocked is systemConn's body with the caller already
// holding b.mu — dbusJob uses it so the conn it gets and the raw
// transports it watches for death are the SAME generation (a
// concurrent rebuild between the two reads would otherwise leave
// the job wait watching a conn nobody is using).
func (b *dbusBackend) systemConnLocked(ctx context.Context) (*sdbus.Conn, error) {
	if b.disabled.Load() {
		// Permanently unreachable socket (EACCES/ENOENT latched on
		// an earlier dial) — skip straight to the unavailable
		// verdict so the CLI fallback serves without re-dialing.
		return nil, fmt.Errorf("%w: systemd dbus disabled (socket unreachable)",
			errDBusUnavailable)
	}
	if b.conn != nil && b.conn.Connected() {
		return b.conn, nil
	}
	if b.conn != nil {
		b.conn.Close()
		b.conn = nil
		b.rawSys = nil
		b.rawSig = nil
	}
	var rawSys, rawSig *godbus.Conn
	conn, err := sdbus.NewConnection(func() (*godbus.Conn, error) {
		c, err := dialSystemdPrivate(b.path)
		if err == nil {
			// NewConnection dials sysconn first, sigconn second —
			// capture each so loadUnit gets sysconn and dbusJob can
			// watch BOTH transports for death.
			if rawSys == nil {
				rawSys = c
			} else {
				rawSig = c
			}
		}
		return c, err
	})
	if err != nil {
		b.maybeDisable(err)
		return nil, fmt.Errorf("%w: systemd dbus dial %s: %v",
			errDBusUnavailable, b.path, err)
	}
	// Subscribe is REQUIRED, not best-effort: without it PID 1
	// never emits the JobRemoved signals the job waits in dbusJob
	// depend on — every restart would hang until ctx timeout. A
	// refused Subscribe kills the conn and reports unavailable so
	// the CLI fallback serves instead of a silently deaf bus.
	if err := conn.Subscribe(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("%w: systemd dbus subscribe: %v",
			errDBusUnavailable, err)
	}
	b.conn = conn
	b.rawSys = rawSys
	b.rawSig = rawSig
	return conn, nil
}

// isFatalDialErr reports whether a dial/auth failure can NEVER
// succeed later this boot: EACCES (socket is root-only) or ENOENT
// (no systemd private socket at all). Transient failures — bus
// restart, fd exhaustion — must keep retrying.
func isFatalDialErr(err error) bool {
	return errors.Is(err, os.ErrPermission) ||
		errors.Is(err, os.ErrNotExist)
}

// maybeDisable latches the backend off + warns once when err is a
// permanently-fatal dial failure; other errors leave the retry
// path open.
func (b *dbusBackend) maybeDisable(err error) {
	if !isFatalDialErr(err) {
		return
	}
	b.disabled.Store(true)
	b.warnOnce.Do(func() {
		logger().Warn("systemd: dbus socket permanently unreachable "+
			"(EACCES/ENOENT) — dbus backend disabled, systemctl "+
			"fallback serves for the process lifetime",
			"path", b.path, "error", err)
	})
}

// close releases the stored conn — Client.Close and tests call it;
// safe on a never-connected or already-dropped backend.
func (b *dbusBackend) close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn != nil {
		b.conn.Close()
		b.conn = nil
		b.rawSys = nil
		b.rawSig = nil
	}
}

// dropConn tears down the stored conn when it is still the one the
// caller saw — releasing the sdbus jobListener subscribers and the
// godbus transports so the next systemConn rebuilds clean. Called
// when a job wait is abandoned (ctx done) or a transport died: a
// pending job's completion channel would otherwise wait forever on
// a conn that can no longer deliver JobRemoved.
func (b *dbusBackend) dropConn(conn *sdbus.Conn) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn != conn {
		return
	}
	b.conn.Close()
	b.conn = nil
	b.rawSys = nil
	b.rawSig = nil
}
