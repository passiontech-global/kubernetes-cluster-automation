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
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

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
	// under some unit configs). Transient failures such as ENOENT
	// during `systemctl daemon-reexec` must NOT latch permanently.
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

// dbusHandshakeTimeout bounds the dial + SASL auth + Subscribe
// exchange. These run while systemConnLocked holds b.mu — an
// unbounded read against a wedged PID 1 would park every later
// systemd.Client call behind the mutex forever (the deadlock this
// bound exists to prevent). 5s is generous for a local socket
// handshake and still lands far inside any caller's op budget.
const dbusHandshakeTimeout = 5 * time.Second

const (
	dbusBeginLine   = "BEGIN\r\n"
	dbusMaxMsgBytes = 1 << 27
)

// dbusFrameConn wraps a stream net.Conn passed to godbus.NewConn so
// post-SASL D-Bus messages are buffered frame-by-frame before
// godbus.DecodeMessageWithFDs reads them. godbus.NewConn selects
// genericTransport, whose DecodeMessageWithFDs calls decoder.align(8)
// outside decoder.Decode's recover() and panics unrecoverably in
// inWorker if the peer or dropConn closes the socket between a(yv) and
// its 8-byte alignment padding. Buffering one full message frame from
// nc before returning bytes to DecodeMessageWithFDs turns mid-frame
// socket close/EOF into a clean Read error that shuts down inWorker.
type dbusFrameConn struct {
	nc       net.Conn
	framed   atomic.Bool
	authTail []byte
	frame    []byte
	off      int
}

func newDBusFrameConn(nc net.Conn) *dbusFrameConn {
	return &dbusFrameConn{nc: nc}
}

func (fc *dbusFrameConn) Close() error {
	return fc.nc.Close()
}

func (fc *dbusFrameConn) Write(p []byte) (int, error) {
	if !fc.framed.Load() && fc.sawBegin(p) {
		fc.authTail = nil
		fc.framed.Store(true)
	}
	return fc.nc.Write(p)
}

func (fc *dbusFrameConn) sawBegin(p []byte) bool {
	if len(p) == 0 {
		return false
	}
	if len(fc.authTail) == 0 {
		if bytes.Contains(p, []byte(dbusBeginLine)) {
			return true
		}
	} else {
		combined := make([]byte, 0, len(fc.authTail)+len(p))
		combined = append(combined, fc.authTail...)
		combined = append(combined, p...)
		if bytes.Contains(combined, []byte(dbusBeginLine)) {
			return true
		}
	}
	keep := len(dbusBeginLine) - 1
	if len(p) >= keep {
		fc.authTail = append(fc.authTail[:0], p[len(p)-keep:]...)
		return false
	}
	fc.authTail = append(fc.authTail, p...)
	if len(fc.authTail) > keep {
		copy(fc.authTail, fc.authTail[len(fc.authTail)-keep:])
		fc.authTail = fc.authTail[:keep]
	}
	return false
}

func (fc *dbusFrameConn) Read(p []byte) (int, error) {
	if !fc.framed.Load() {
		return fc.nc.Read(p)
	}
	if len(p) == 0 {
		return 0, nil
	}
	if fc.off >= len(fc.frame) {
		if err := fc.readNextFrame(); err != nil {
			return 0, err
		}
	}
	n := copy(p, fc.frame[fc.off:])
	fc.off += n
	if fc.off >= len(fc.frame) {
		fc.frame = nil
		fc.off = 0
	}
	return n, nil
}

func (fc *dbusFrameConn) readNextFrame() error {
	var hdr [16]byte
	if _, err := io.ReadFull(fc.nc, hdr[:]); err != nil {
		return err
	}
	var order binary.ByteOrder
	switch hdr[0] {
	case 'l':
		order = binary.LittleEndian
	case 'B':
		order = binary.BigEndian
	default:
		// Invalid byte order: buffer hdr[:] so DecodeMessageWithFDs
		// produces InvalidMessageError as before.
		hdrCopy := hdr
		fc.frame = hdrCopy[:]
		fc.off = 0
		return nil
	}
	blen := order.Uint32(hdr[4:8])
	hlen := order.Uint32(hdr[12:16])
	paddedHlen := uint64(hlen)
	if rem := paddedHlen % 8; rem != 0 {
		paddedHlen += 8 - rem
	}
	total := uint64(16) + paddedHlen + uint64(blen)
	if total > dbusMaxMsgBytes {
		// Oversized frame: buffer hdr[:] so DecodeMessageWithFDs
		// rejects it without allocating an unbounded buffer.
		hdrCopy := hdr
		fc.frame = hdrCopy[:]
		fc.off = 0
		return nil
	}
	frame := make([]byte, int(total))
	copy(frame[:16], hdr[:])
	if len(frame) > 16 {
		if _, err := io.ReadFull(fc.nc, frame[16:]); err != nil {
			return err
		}
	}
	fc.frame = frame
	fc.off = 0
	return nil
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
//
// The dial goes through net.DialTimeout + godbus.NewConn (not
// godbus.Dial) so the raw net.Conn stays reachable: its deadline is
// armed across Auth and cleared before return — the conn then lives
// deadline-free for signal traffic. The net.Conn comes back beside
// the godbus.Conn so systemConnLocked can arm the same bound across
// Subscribe, which likewise runs under b.mu.
func dialSystemdPrivate(ctx context.Context, path string) (*godbus.Conn, net.Conn, error) {
	d := net.Dialer{Timeout: dbusHandshakeTimeout}
	nc, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, nil, err
	}
	if err := nc.SetDeadline(time.Now().Add(dbusHandshakeTimeout)); err != nil {
		_ = nc.Close()
		return nil, nil, err
	}
	c, err := godbus.NewConn(newDBusFrameConn(nc))
	if err == nil {
		err = c.Auth([]godbus.Auth{
			godbus.AuthExternal(strconv.Itoa(os.Getuid())),
		})
	}
	// Clear BEFORE inspecting err: a failed handshake still leaves
	// the reader goroutine parked on this conn until Close, and a
	// live deadline would turn that park into a spin of i/o
	// timeouts. Close handles both the godbus wrapper and the
	// transport. A clear failure leaves the deadline armed — the
	// conn would die on its next read — so it fails the dial too.
	if cerr := nc.SetDeadline(time.Time{}); cerr != nil && err == nil {
		err = cerr
	}
	if err != nil {
		if c != nil {
			_ = c.Close()
		} else {
			_ = nc.Close()
		}
		return nil, nil, err
	}
	return c, nc, nil
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
		// Permanently unreachable socket (EACCES latched on an
		// earlier dial) — skip straight to the unavailable verdict
		// so the CLI fallback serves without re-dialing.
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
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var rawSys, rawSig *godbus.Conn
	var netSys, netSig net.Conn
	conn, err := sdbus.NewConnection(func() (*godbus.Conn, error) {
		c, nc, err := dialSystemdPrivate(ctx, b.path)
		if err == nil {
			// NewConnection dials sysconn first, sigconn second —
			// capture each so loadUnit gets sysconn and dbusJob can
			// watch BOTH transports for death; the net.Conns let
			// Subscribe run under the same handshake deadline.
			if rawSys == nil {
				rawSys, netSys = c, nc
			} else {
				rawSig, netSig = c, nc
			}
		}
		return c, err
	})
	if err != nil {
		b.maybeDisable(err)
		return nil, fmt.Errorf("%w: systemd dbus dial %s: %w",
			errDBusUnavailable, b.path, err)
	}
	// Subscribe is REQUIRED, not best-effort: without it PID 1
	// never emits the JobRemoved signals the job waits in dbusJob
	// depend on — every restart would hang until ctx timeout. A
	// refused Subscribe kills the conn and reports unavailable so
	// the CLI fallback serves instead of a silently deaf bus.
	// The call runs under b.mu with no ctx deadline of its own —
	// arm the handshake bound on both transports so a wedged PID 1
	// cannot park the mutex (and every later systemd.Client call)
	// on a Subscribe reply that never comes.
	deadline := time.Now().Add(dbusHandshakeTimeout)
	var armErr error
	for _, nc := range []net.Conn{netSys, netSig} {
		if nc == nil {
			continue
		}
		if err := nc.SetDeadline(deadline); err != nil && armErr == nil {
			armErr = err
		}
	}
	// A transport that refused the deadline arm cannot bound
	// Subscribe — skip the call entirely rather than park b.mu on
	// an unbounded wait, and report unavailable for the CLI
	// fallback.
	var subErr error
	if armErr != nil {
		subErr = armErr
	} else {
		subErr = conn.Subscribe()
	}
	for _, nc := range []net.Conn{netSys, netSig} {
		if nc == nil {
			continue
		}
		// A clear failure strands the deadline — the conn dies on
		// its next read and the lazy reconnect path serves; still
		// surface it as a subscribe failure when nothing else did.
		if err := nc.SetDeadline(time.Time{}); err != nil && subErr == nil {
			subErr = err
		}
	}
	if subErr != nil {
		conn.Close()
		return nil, fmt.Errorf("%w: systemd dbus subscribe: %w",
			errDBusUnavailable, subErr)
	}
	b.conn = conn
	b.rawSys = rawSys
	b.rawSig = rawSig
	return conn, nil
}

// isFatalDialErr reports whether a dial/auth failure can NEVER
// succeed later this boot: EACCES (socket is root-only). Transient
// failures — ENOENT during daemon-reexec, bus restart, fd exhaustion —
// must keep retrying.
func isFatalDialErr(err error) bool {
	return errors.Is(err, os.ErrPermission)
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
			"(EACCES) — dbus backend disabled, systemctl "+
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
	if b.conn == nil || b.conn != conn {
		return
	}
	b.conn.Close()
	b.conn = nil
	b.rawSys = nil
	b.rawSig = nil
}
