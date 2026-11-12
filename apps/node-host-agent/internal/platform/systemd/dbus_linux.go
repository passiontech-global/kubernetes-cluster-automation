//go:build linux

// dbus_linux.go — the zero-fork systemd control path: a persistent
// D-Bus connection to the host's /run/systemd/private (under
// HostRoot) replaces the per-call `nsenter -t 1 ... systemctl`
// fork for the hot unit-control verbs. The conn is rebuilt lazily
// whenever the socket drops (systemd restart, socket GC). Only
// wired when the caller supplied NO exec seams — tests keep the
// 100% RunCmd path.
package systemd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	sdbus "github.com/coreos/go-systemd/v22/dbus"
	godbus "github.com/godbus/dbus/v5"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
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

// unitSuffixes is the systemd unit-type vocabulary — a name ending
// in one is already canonical; anything else gets ".service"
// appended exactly like `systemctl` does for bare unit args
// ("k0scontroller" -> "k0scontroller.service",
// "nebula@interdc" -> "nebula@interdc.service"). The D-Bus API
// rejects unqualified names outright.
var unitSuffixes = []string{
	".service", ".socket", ".target", ".device", ".mount",
	".automount", ".swap", ".timer", ".path", ".slice", ".scope",
}

func normalizeUnit(unit string) string {
	for _, s := range unitSuffixes {
		if strings.HasSuffix(unit, s) {
			return unit
		}
	}
	return unit + ".service"
}

// loadUnit asks PID 1 to load the unit into RAM before the
// properties read — `systemctl show/is-active` does the same via
// LoadUnit, so an inactive unit that was GC'd from systemd's unit
// table still reports LoadState=loaded instead of UnknownObject.
// Errors are ignored on purpose: GetAllProperties surfaces the
// authoritative answer (a genuinely missing unit still 404s).
func (b *dbusBackend) loadUnit(ctx context.Context, unit string) {
	b.mu.Lock()
	raw := b.rawSys
	b.mu.Unlock()
	if raw == nil {
		return
	}
	var path godbus.ObjectPath
	_ = raw.Object("org.freedesktop.systemd1", "/org/freedesktop/systemd1").
		CallWithContext(ctx, "org.freedesktop.systemd1.Manager.LoadUnit",
			0, unit).Store(&path)
}

// unitProp fetches ONE unit property — GetUnitPropertyContext
// (org.freedesktop.DBus.Properties.Get on the Unit interface)
// instead of GetAllPropertiesContext, which decoded ~200 properties
// per call to read one word. LoadUnit still runs first so an
// inactive unit GC'd from systemd's unit table reports its real
// state instead of UnknownObject. The returned any is the
// variant's decoded Go value (string for state words, uint64 for
// the monotonic timestamp).
func (b *dbusBackend) unitProp(ctx context.Context, unit, prop string) (any, error) {
	conn, err := b.systemConn(ctx)
	if err != nil {
		return nil, err
	}
	unit = normalizeUnit(unit)
	b.loadUnit(ctx, unit)
	p, err := conn.GetUnitPropertyContext(ctx, unit, prop)
	if err != nil {
		return nil, err
	}
	return p.Value.Value(), nil
}

// propString reads a string-typed property value.
func propString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// propUint64 reads an unsigned-64 property value (timestamps are
// "t" — uint64 microseconds since boot for the monotonic clock).
func propUint64(v any) (uint64, bool) {
	switch t := v.(type) {
	case uint64:
		return t, true
	case uint32:
		return uint64(t), true
	case int64:
		return uint64(t), true
	case string:
		n, err := strconv.ParseUint(strings.TrimSpace(t), 10, 64)
		return n, err == nil
	}
	return 0, false
}

// isNotFoundErr reports whether a D-Bus error means "no such
// unit" — the answer systemctl prints as LoadState=not-found /
// is-active "inactive". Other errors are probe failures.
func isNotFoundErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, needle := range []string{
		"NoSuchUnit", "no such unit", "not-found", "NotFound",
		"UnknownObject", "org.freedesktop.DBus.Error.UnknownMethod",
		"BadUnitName",
	} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

// dbusActive mirrors `systemctl is-active` on the ActiveState
// property — the same word vocabulary the systemctl path matches.
func (b *dbusBackend) dbusActive(ctx context.Context, unit string) (bool, error) {
	v, err := b.unitProp(ctx, unit, "ActiveState")
	if err != nil {
		if isNotFoundErr(err) {
			return false, nil // missing unit = definitively not active
		}
		return false, fmt.Errorf("dbus Get ActiveState %s: %w", unit, err)
	}
	switch state := propString(v); state {
	case "active":
		return true, nil
	case "reloading", "activating", "deactivating", "inactive",
		"failed", "maintenance", "unknown", "":
		return false, nil
	default:
		return false, fmt.Errorf("%s: unexpected ActiveState %q", unit, state)
	}
}

// dbusExists mirrors `systemctl show -p LoadState` — the unit_load_
// state_table vocabulary maps identically to the systemctl path.
func (b *dbusBackend) dbusExists(ctx context.Context, unit string) (bool, error) {
	v, err := b.unitProp(ctx, unit, "LoadState")
	if err != nil {
		if isNotFoundErr(err) {
			return false, nil
		}
		return false, fmt.Errorf("dbus Get LoadState %s: %w", unit, err)
	}
	switch state := propString(v); state {
	case "loaded", "merged":
		return true, nil
	case "stub", "not-found", "bad-setting", "error", "masked", "":
		return false, nil
	default:
		logger().Warn("systemd: unexpected LoadState word — "+
			"treating unit as absent this probe",
			"unit", unit, "loadstate", state)
		return false, nil
	}
}

// dbusActiveAge mirrors ActiveAge: ActiveEnterTimestampMonotonic
// (µs since boot) vs /proc/uptime — same clock family, same math.
func (b *dbusBackend) dbusActiveAge(ctx context.Context, unit string,
	procUptimeFile string) (time.Duration, error) {
	v, err := b.unitProp(ctx, unit, "ActiveEnterTimestampMonotonic")
	if err != nil {
		return 0, fmt.Errorf("dbus Get ActiveEnterTimestampMonotonic %s: %w",
			unit, err)
	}
	monoUS, ok := propUint64(v)
	if !ok || monoUS == 0 {
		return 0, fmt.Errorf("%s: unusable ActiveEnterTimestampMonotonic (not active)",
			unit)
	}
	up, err := procfs.UptimeSeconds(procUptimeFile)
	if err != nil {
		return 0, fmt.Errorf("%s: read %s: %w", unit, procUptimeFile, err)
	}
	if age := up*1e6 - float64(monoUS); age > 0 {
		return time.Duration(age) * time.Microsecond, nil
	}
	return 0, nil
}

// dbusListUnitsByPatterns mirrors `systemctl list-units --all
// --no-legend --plain <patterns...>` over Manager.ListUnitsByPatterns
// — states nil means "every load/active state" (the --all flag's
// equivalent); an empty pattern list is the unfiltered ListUnits
// call. Unit-name glob matching stays PID 1's, exactly like the
// systemctl argv form.
func (b *dbusBackend) dbusListUnitsByPatterns(ctx context.Context, patterns []string) ([]UnitInfo, error) {
	conn, err := b.systemConn(ctx)
	if err != nil {
		return nil, err
	}
	var units []sdbus.UnitStatus
	if len(patterns) == 0 {
		units, err = conn.ListUnitsContext(ctx)
	} else {
		units, err = conn.ListUnitsByPatternsContext(ctx, nil, patterns)
	}
	if err != nil {
		return nil, fmt.Errorf("dbus ListUnits: %w", err)
	}
	out := make([]UnitInfo, 0, len(units))
	for _, u := range units {
		out = append(out, UnitInfo{
			Name:        u.Name,
			Description: u.Description,
			LoadState:   u.LoadState,
			ActiveState: u.ActiveState,
			SubState:    u.SubState,
		})
	}
	return out, nil
}

// dbusEnabled mirrors `systemctl is-enabled` via
// Manager.ListUnitFiles — go-systemd v22 wraps no GetUnitFileState,
// so the raw sysconn issues the call and the (unit,state) rows are
// matched client-side. The state vocabulary is identical to
// is-enabled's stdout words (enabled/enabled-runtime/static/
// indirect/alias/generated/transient/linked vs disabled/masked/
// masked-runtime/bad); a unit absent from the table is the
// not-found case — reported as an error so callers keep the
// "can't ask = error" distinction cliEnabled documents.
func (b *dbusBackend) dbusEnabled(ctx context.Context, unit string) (bool, error) {
	b.mu.Lock()
	_, err := b.systemConnLocked(ctx)
	raw := b.rawSys
	b.mu.Unlock()
	if err != nil {
		return false, err
	}
	if raw == nil {
		return false, fmt.Errorf("%w: no sysconn for ListUnitFiles", errDBusUnavailable)
	}
	unit = normalizeUnit(unit)
	var rows []struct {
		UnitFile string
		State    string
		Preset   string
	}
	call := raw.Object("org.freedesktop.systemd1", "/org/freedesktop/systemd1").
		CallWithContext(ctx, "org.freedesktop.systemd1.Manager.ListUnitFiles", 0)
	if err := call.Store(&rows); err != nil {
		return false, fmt.Errorf("dbus ListUnitFiles: %w", err)
	}
	for _, r := range rows {
		if r.UnitFile != unit {
			continue
		}
		switch r.State {
		case "enabled", "enabled-runtime", "static", "indirect",
			"alias", "generated", "transient", "linked", "linked-runtime":
			return true, nil
		case "disabled", "masked", "masked-runtime", "bad":
			return false, nil
		default:
			logger().Warn("systemd: unexpected unit-file state word — "+
				"treating unit as not enabled this probe",
				"unit", unit, "state", r.State)
			return false, nil
		}
	}
	return false, fmt.Errorf("systemctl is-enabled %s: unit not found in ListUnitFiles", unit)
}
