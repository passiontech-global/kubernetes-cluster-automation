//go:build linux

// dbus_query_linux.go — the READ side of the D-Bus backend: unit-name
// normalization, the single-property fetch (unitProp) + the variant
// decoders, and the systemctl-mirroring query verbs (is-active /
// is-enabled / show / list-units). Split out of dbus_linux.go so the
// connection-lifecycle file stays under the ~500-LOC bar; the mutating
// job verbs live in dbus_jobs.go.
package systemd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	sdbus "github.com/coreos/go-systemd/v22/dbus"
	godbus "github.com/godbus/dbus/v5"
)

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

// dbusOpTimeout bounds every READ-side D-Bus call. Callers pass
// the long-lived subsystem ctx — a wedged PID 1 that accepts the
// connection but never answers would otherwise park the check
// forever (godbus waits on the reply channel; ctx is the only
// escape). Job verbs keep caller ctx: a unit restart legitimately
// takes minutes.
const dbusOpTimeout = 15 * time.Second

// isTransportDead reports whether err is a dead-transport failure —
// EOF after a daemon-reexec/socket drop, a closed conn, or a reset
// peer. These mean "the conn is useless", not "the call failed" —
// callers retry once on a fresh conn and the Client layer falls
// back to the systemctl CLI.
func isTransportDead(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, net.ErrClosed) ||
		strings.Contains(err.Error(), "use of closed network connection") ||
		strings.Contains(err.Error(), "connection reset by peer")
}

// opCtx derives the bounded per-call ctx for read verbs.
func opCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, dbusOpTimeout)
}

// unitProp fetches ONE unit property — GetUnitPropertyContext
// (org.freedesktop.DBus.Properties.Get on the Unit interface)
// instead of GetAllPropertiesContext, which decoded ~200 properties
// per call to read one word. go-systemd resolves the unit object
// path through Manager.GetUnit, which LOADS the unit into RAM the
// same way the explicit LoadUnit round-trip this call used to make
// first did — an inactive unit GC'd from systemd's unit table still
// reports its real state, so the pre-read was one wasted D-Bus
// round trip per property. The returned any is the variant's
// decoded Go value (string for state words, uint64 for the
// monotonic timestamp).
func (b *dbusBackend) unitProp(ctx context.Context, unit, prop string) (any, error) {
	ctx, cancel := opCtx(ctx)
	defer cancel()
	conn, err := b.systemConn(ctx)
	if err != nil {
		return nil, err
	}
	p, err := conn.GetUnitPropertyContext(ctx, normalizeUnit(unit), prop)
	if err != nil && (isTransportDead(err) ||
		errors.Is(err, context.DeadlineExceeded)) {
		// Reconnect once: drop the dead/hung generation and retry
		// the read on a fresh conn — a daemon-reexec drops the
		// socket mid-call and the lazy rebuild only fires on the
		// NEXT systemConn, leaving this call to surface a spurious
		// unavailable to the CLI fallback. DeadlineExceeded counts:
		// an RPC that outlived its op budget leaves godbus reply
		// state ambiguous, so the conn generation is suspect too.
		// Caller cancellation (context.Canceled) never retries —
		// the work is already abandoned.
		b.dropConn(conn)
		conn, err = b.systemConn(ctx)
		if err != nil {
			return nil, err
		}
		p, err = conn.GetUnitPropertyContext(ctx, normalizeUnit(unit), prop)
	}
	if err != nil {
		if isTransportDead(err) || errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("%w: dbus Get %s %s: %v",
				errDBusUnavailable, prop, unit, err)
		}
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

// propUint32 reads an unsigned-32 property value (MainPID is "u" —
// the kernel pid space).
func propUint32(v any) (uint32, bool) {
	switch t := v.(type) {
	case uint32:
		return t, true
	case int32:
		return uint32(t), t >= 0
	case uint64:
		return uint32(t), t <= math.MaxUint32
	case int64:
		return uint32(t), t >= 0 && t <= math.MaxUint32
	case string:
		n, err := strconv.ParseUint(strings.TrimSpace(t), 10, 32)
		return uint32(n), err == nil
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
	state := propString(v)
	if state == "" {
		return false, nil
	}
	if active, ok := parseActiveStateWord(state); ok {
		return active, nil
	}
	return false, fmt.Errorf("%s: unexpected ActiveState %q", unit, state)
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
	return parseLoadStateWord(unit, propString(v)), nil
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
	return activeAgeFromMonoUS(unit, monoUS, procUptimeFile)
}

// dbusActiveEnterUSec reads ActiveEnterTimestamp — the WALL-CLOCK
// enter stamp as µs since the epoch (type 't' on the Unit
// interface), the locale-free integer form of the formatted
// "Mon 2006-01-02 15:04:05 MST" string systemctl show prints. The
// feeder's fresh-start grace needs exactly this: parsing the
// formatted string breaks under any TZ/systemd locale the agent's
// time.Local does not share. 0 = never activated this boot.
func (b *dbusBackend) dbusActiveEnterUSec(ctx context.Context, unit string) (uint64, error) {
	v, err := b.unitProp(ctx, unit, "ActiveEnterTimestamp")
	if err != nil {
		return 0, fmt.Errorf("dbus Get ActiveEnterTimestamp %s: %w", unit, err)
	}
	us, ok := propUint64(v)
	if !ok {
		return 0, fmt.Errorf("%s: unusable ActiveEnterTimestamp %v", unit, v)
	}
	return us, nil
}

// dbusMainPID mirrors `systemctl show -p MainPID --value` — the
// unit's main process pid. A unit that is not running answers 0;
// the manager answers 0 the same way for a not-found name (systemctl
// exits 0 with MainPID=0 there), so isNotFound reads as pid 0, not
// an error.
func (b *dbusBackend) dbusMainPID(ctx context.Context, unit string) (uint32, error) {
	v, err := b.unitProp(ctx, unit, "MainPID")
	if err != nil {
		if isNotFoundErr(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("dbus Get MainPID %s: %w", unit, err)
	}
	pid, ok := propUint32(v)
	if !ok {
		return 0, fmt.Errorf("%s: unusable MainPID %v", unit, v)
	}
	return pid, nil
}

// dbusListUnitsByPatterns mirrors `systemctl list-units --all
// --no-legend --plain <patterns...>` over Manager.ListUnitsByPatterns
// — states nil means "every load/active state" (the --all flag's
// equivalent); an empty pattern list is the unfiltered ListUnits
// call. Unit-name glob matching stays PID 1's, exactly like the
// systemctl argv form.
func (b *dbusBackend) dbusListUnitsByPatterns(ctx context.Context, patterns []string) ([]UnitInfo, error) {
	ctx, cancel := opCtx(ctx)
	defer cancel()
	conn, err := b.systemConn(ctx)
	if err != nil {
		return nil, err
	}
	var units []sdbus.UnitStatus
	list := func(c *sdbus.Conn) ([]sdbus.UnitStatus, error) {
		if len(patterns) == 0 {
			return c.ListUnitsContext(ctx)
		}
		return c.ListUnitsByPatternsContext(ctx, nil, patterns)
	}
	units, err = list(conn)
	if err != nil && (isTransportDead(err) ||
		errors.Is(err, context.DeadlineExceeded)) {
		// Same reconnect-once contract as unitProp: a daemon-reexec
		// drops the socket mid-call (and an over-budget RPC leaves
		// the conn generation suspect); retry on a fresh conn
		// before surfacing unavailable to the CLI fallback.
		b.dropConn(conn)
		conn, err = b.systemConn(ctx)
		if err != nil {
			return nil, err
		}
		units, err = list(conn)
	}
	if err != nil {
		if isTransportDead(err) || errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("%w: dbus ListUnits: %v",
				errDBusUnavailable, err)
		}
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
// Manager.GetUnitFileState — go-systemd v22 wraps no GetUnitFileState,
// so the raw sysconn issues the call directly. The state vocabulary is
// identical to is-enabled's stdout words (enabled/enabled-runtime/static/
// indirect/alias/generated/transient/linked vs disabled/masked/
// masked-runtime/bad); a systemd unit error (e.g. NoSuchUnit) is
// returned directly while transport failures wrap errDBusUnavailable.
func (b *dbusBackend) dbusEnabled(ctx context.Context, unit string) (bool, error) {
	ctx, cancel := opCtx(ctx)
	defer cancel()
	unit = normalizeUnit(unit)
	for attempt := 0; ; attempt++ {
		b.mu.Lock()
		conn, err := b.systemConnLocked(ctx)
		raw := b.rawSys
		b.mu.Unlock()
		if err != nil {
			return false, err
		}
		if raw == nil {
			return false, fmt.Errorf("%w: no sysconn for GetUnitFileState", errDBusUnavailable)
		}
		var state string
		call := raw.Object("org.freedesktop.systemd1", "/org/freedesktop/systemd1").
			CallWithContext(ctx, "org.freedesktop.systemd1.Manager.GetUnitFileState", 0, unit)
		err = call.Store(&state)
		if err != nil && attempt == 0 && (isTransportDead(err) ||
			errors.Is(err, context.DeadlineExceeded)) {
			// Reconnect once on a dead/hung transport — same
			// contract as unitProp. Caller cancellation is NOT
			// retried: the work is already abandoned, and the
			// unavailable wrap below still lets the CLI fallback
			// answer if the cycle ctx merely timed out.
			b.dropConn(conn)
			continue
		}
		if err != nil {
			var derr godbus.Error
			if errors.As(err, &derr) && strings.HasPrefix(derr.Name, "org.freedesktop.systemd1.") {
				return false, fmt.Errorf("systemctl is-enabled %s: %w", unit, err)
			}
			return false, fmt.Errorf("%w: dbus GetUnitFileState %s: %v", errDBusUnavailable, unit, err)
		}
		if enabled, ok := parseEnabledStateWord(state); ok {
			return enabled, nil
		}
		logger().Warn("systemd: unexpected unit-file state word — "+
			"treating unit as not enabled this probe",
			"unit", unit, "state", state)
		return false, nil
	}
}

// dbusSystemState reads Manager.SystemState — the manager's own
// health word (running/starting/stopping/degraded/offline/
// maintenance) — via org.freedesktop.DBus.Properties.Get on the
// manager object path. go-systemd wraps no manager-property getter,
// so the raw sysconn issues the call directly (the dbusEnabled
// pattern). Properties.Get returns a VARIANT — Store decodes it
// into godbus.Variant and Value() unwraps the string.
func (b *dbusBackend) dbusSystemState(ctx context.Context) (string, error) {
	ctx, cancel := opCtx(ctx)
	defer cancel()
	for attempt := 0; ; attempt++ {
		b.mu.Lock()
		conn, err := b.systemConnLocked(ctx)
		raw := b.rawSys
		b.mu.Unlock()
		if err != nil {
			return "", err
		}
		if raw == nil {
			return "", fmt.Errorf("%w: no sysconn for SystemState", errDBusUnavailable)
		}
		var v godbus.Variant
		call := raw.Object("org.freedesktop.systemd1", "/org/freedesktop/systemd1").
			CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0,
				"org.freedesktop.systemd1.Manager", "SystemState")
		err = call.Store(&v)
		if err != nil && attempt == 0 && (isTransportDead(err) ||
			errors.Is(err, context.DeadlineExceeded)) {
			b.dropConn(conn)
			continue
		}
		if err != nil {
			if isTransportDead(err) || errors.Is(err, context.DeadlineExceeded) {
				return "", fmt.Errorf("%w: dbus Get SystemState: %v",
					errDBusUnavailable, err)
			}
			return "", fmt.Errorf("dbus Get SystemState: %w", err)
		}
		state, _ := v.Value().(string)
		return state, nil
	}
}
