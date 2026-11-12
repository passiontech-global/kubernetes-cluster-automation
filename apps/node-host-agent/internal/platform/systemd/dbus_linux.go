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
	"time"

	sdbus "github.com/coreos/go-systemd/v22/dbus"
	godbus "github.com/godbus/dbus/v5"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
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
	// sysconn first (the one LoadUnit needs), sigconn second (the
	// one JobRemoved signals arrive on). Kept only to issue
	// Manager.LoadUnit, which go-systemd v22 does not wrap, and to
	// watch transport death (each godbus Conn's Context cancels on
	// Close). Both nil until a conn is built and reset whenever the
	// conn is.
	rawSys *godbus.Conn
	rawSig *godbus.Conn
	path   string
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
		return nil, fmt.Errorf("%w: systemd dbus dial %s: %v",
			errDBusUnavailable, b.path, err)
	}
	_ = conn.Subscribe()
	b.conn = conn
	b.rawSys = rawSys
	b.rawSig = rawSig
	return conn, nil
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

// unitProps fetches a unit's properties — LoadUnit + GetAll in one
// call, the D-Bus equivalent of `systemctl show -p LoadState
// ActiveState ActiveEnterTimestampMonotonic`.
func (b *dbusBackend) unitProps(ctx context.Context, unit string) (map[string]any, error) {
	conn, err := b.systemConn(ctx)
	if err != nil {
		return nil, err
	}
	unit = normalizeUnit(unit)
	b.loadUnit(ctx, unit)
	return conn.GetAllPropertiesContext(ctx, unit)
}

// propString reads a string-typed unit property.
func propString(props map[string]any, name string) string {
	if v, ok := props[name]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// propUint64 reads an unsigned-64 unit property (timestamps are
// "t" — uint64 microseconds since boot for the monotonic clock).
func propUint64(props map[string]any, name string) (uint64, bool) {
	switch v := props[name].(type) {
	case uint64:
		return v, true
	case uint32:
		return uint64(v), true
	case int64:
		return uint64(v), true
	case string:
		n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
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
	props, err := b.unitProps(ctx, unit)
	if err != nil {
		if isNotFoundErr(err) {
			return false, nil // missing unit = definitively not active
		}
		return false, fmt.Errorf("dbus GetAllProperties %s: %w", unit, err)
	}
	switch state := propString(props, "ActiveState"); state {
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
	props, err := b.unitProps(ctx, unit)
	if err != nil {
		if isNotFoundErr(err) {
			return false, nil
		}
		return false, fmt.Errorf("dbus GetAllProperties %s: %w", unit, err)
	}
	switch state := propString(props, "LoadState"); state {
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
	props, err := b.unitProps(ctx, unit)
	if err != nil {
		return 0, fmt.Errorf("dbus GetAllProperties %s: %w", unit, err)
	}
	monoUS, ok := propUint64(props, "ActiveEnterTimestampMonotonic")
	if !ok || monoUS == 0 {
		return 0, fmt.Errorf("%s: unusable ActiveEnterTimestampMonotonic (not active)",
			unit)
	}
	up, err := hostutil.UptimeSeconds(procUptimeFile)
	if err != nil {
		return 0, fmt.Errorf("%s: read %s: %w", unit, procUptimeFile, err)
	}
	if age := up*1e6 - float64(monoUS); age > 0 {
		return time.Duration(age) * time.Microsecond, nil
	}
	return 0, nil
}

// dbusJob runs a start-job verb (RestartUnit /
// ReloadOrRestartUnit) and waits for the job's completion signal —
// `systemctl restart` blocks until the job lands; the bare
// StartUnit call returns at enqueue time, so the wait channel is
// what preserves the blocking contract callers rely on.
func (b *dbusBackend) dbusJob(ctx context.Context, unit, method string) error {
	b.mu.Lock()
	conn, err := b.systemConnLocked(ctx)
	// Capture the raw transports of THIS conn generation under the
	// same lock — the job wait below watches them for death.
	rawSys, rawSig := b.rawSys, b.rawSig
	b.mu.Unlock()
	if err != nil {
		return err
	}
	unit = normalizeUnit(unit)
	ch := make(chan string, 1)
	var jobErr error
	switch method {
	case "restart":
		_, jobErr = conn.RestartUnitContext(ctx, unit, "replace", ch)
	case "reload-or-restart":
		_, jobErr = conn.ReloadOrRestartUnitContext(ctx, unit, "replace", ch)
	case "stop":
		_, jobErr = conn.StopUnitContext(ctx, unit, "replace", ch)
	default:
		return fmt.Errorf("dbus job: unknown method %q", method)
	}
	if jobErr != nil {
		return fmt.Errorf("dbus %s %s: %w", method, unit, jobErr)
	}
	// The completion channel is driven by JobRemoved signals on the
	// connection's signal leg; a dead transport would leave this
	// select parked until ctx timeout while the caller believed a
	// restart was still queued. Watch both raw transports — godbus
	// cancels Conn.Context() on Close or transport loss — and drop
	// the stored conn so the next call rebuilds instead of waiting
	// on signals a dead conn can never deliver.
	transportDead := make(chan struct{}, 1)
	for _, raw := range []*godbus.Conn{rawSys, rawSig} {
		if raw == nil {
			continue
		}
		go func(c *godbus.Conn) {
			<-c.Context().Done()
			select {
			case transportDead <- struct{}{}:
			default:
			}
		}(raw)
	}
	select {
	case res := <-ch:
		switch res {
		case "done":
			return nil
		case "":
			// Job completed before the listener saw the removal —
			// treat as done (the enqueue itself succeeded).
			return nil
		default:
			return fmt.Errorf("dbus %s %s: job %s", method, unit, res)
		}
	case <-ctx.Done():
		b.dropConn(conn)
		return ctx.Err()
	case <-transportDead:
		b.dropConn(conn)
		return fmt.Errorf("%w: systemd dbus transport lost during %s %s",
			errDBusUnavailable, method, unit)
	}
}

// dbusSignal mirrors `systemctl kill -s <sig> <unit>` via
// KillUnitWithTarget — the target is "all" (systemctl's default
// --kill-whom) and the signal name maps to its number.
func (b *dbusBackend) dbusSignal(ctx context.Context, unit, sig string) error {
	n, ok := signalNumber(sig)
	if !ok {
		return fmt.Errorf("dbus kill %s: unknown signal %q", unit, sig)
	}
	conn, err := b.systemConn(ctx)
	if err != nil {
		return err
	}
	if err := conn.KillUnitWithTarget(ctx, normalizeUnit(unit), sdbus.All, n); err != nil {
		return fmt.Errorf("dbus kill -s %s %s: %w", sig, unit, err)
	}
	return nil
}

// signalNumber maps the signal names callers pass (with or without
// the SIG prefix) to D-Bus signal numbers — the common set
// systemctl kill accepts by name.
func signalNumber(sig string) (int32, bool) {
	name := strings.ToUpper(strings.TrimPrefix(sig, "SIG"))
	switch name {
	case "HUP":
		return 1, true
	case "INT":
		return 2, true
	case "QUIT":
		return 3, true
	case "ILL":
		return 4, true
	case "TRAP":
		return 5, true
	case "ABRT":
		return 6, true
	case "BUS":
		return 7, true
	case "FPE":
		return 8, true
	case "KILL":
		return 9, true
	case "USR1":
		return 10, true
	case "SEGV":
		return 11, true
	case "USR2":
		return 12, true
	case "PIPE":
		return 13, true
	case "ALRM":
		return 14, true
	case "TERM":
		return 15, true
	case "STKFLT":
		return 16, true
	case "CHLD":
		return 17, true
	case "CONT":
		return 18, true
	case "STOP":
		return 19, true
	case "TSTP":
		return 20, true
	case "TTIN":
		return 21, true
	case "TTOU":
		return 22, true
	case "URG":
		return 23, true
	case "XCPU":
		return 24, true
	case "XFSZ":
		return 25, true
	case "VTALRM":
		return 26, true
	case "PROF":
		return 27, true
	case "WINCH":
		return 28, true
	case "IO":
		return 29, true
	case "PWR":
		return 30, true
	case "SYS":
		return 31, true
	}
	return 0, false
}

// dbusDaemonReload mirrors `systemctl daemon-reload` —
// Manager.Reload over the private bus.
func (b *dbusBackend) dbusDaemonReload(ctx context.Context) error {
	conn, err := b.systemConn(ctx)
	if err != nil {
		return err
	}
	if err := conn.ReloadContext(ctx); err != nil {
		return fmt.Errorf("dbus daemon-reload: %w", err)
	}
	return nil
}

// dbusListUnits mirrors `systemctl list-units --all --no-legend
// --plain` over ListUnits — every loaded unit with its state
// triple, no text parsing.
func (b *dbusBackend) dbusListUnits(ctx context.Context) ([]UnitInfo, error) {
	conn, err := b.systemConn(ctx)
	if err != nil {
		return nil, err
	}
	units, err := conn.ListUnitsContext(ctx)
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
