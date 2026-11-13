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
	"math"
	"strconv"
	"strings"
	"time"

	sdbus "github.com/coreos/go-systemd/v22/dbus"
	godbus "github.com/godbus/dbus/v5"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
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
	conn, err := b.systemConn(ctx)
	if err != nil {
		return nil, err
	}
	p, err := conn.GetUnitPropertyContext(ctx, normalizeUnit(unit), prop)
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
// Manager.GetUnitFileState — go-systemd v22 wraps no GetUnitFileState,
// so the raw sysconn issues the call directly. The state vocabulary is
// identical to is-enabled's stdout words (enabled/enabled-runtime/static/
// indirect/alias/generated/transient/linked vs disabled/masked/
// masked-runtime/bad); a systemd unit error (e.g. NoSuchUnit) is
// returned directly while transport failures wrap errDBusUnavailable.
func (b *dbusBackend) dbusEnabled(ctx context.Context, unit string) (bool, error) {
	b.mu.Lock()
	_, err := b.systemConnLocked(ctx)
	raw := b.rawSys
	b.mu.Unlock()
	if err != nil {
		return false, err
	}
	if raw == nil {
		return false, fmt.Errorf("%w: no sysconn for GetUnitFileState", errDBusUnavailable)
	}
	unit = normalizeUnit(unit)
	var state string
	call := raw.Object("org.freedesktop.systemd1", "/org/freedesktop/systemd1").
		CallWithContext(ctx, "org.freedesktop.systemd1.Manager.GetUnitFileState", 0, unit)
	if err := call.Store(&state); err != nil {
		var derr godbus.Error
		if errors.As(err, &derr) && strings.HasPrefix(derr.Name, "org.freedesktop.systemd1.") {
			return false, fmt.Errorf("systemctl is-enabled %s: %w", unit, err)
		}
		return false, fmt.Errorf("%w: dbus GetUnitFileState %s: %v", errDBusUnavailable, unit, err)
	}
	switch state {
	case "enabled", "enabled-runtime", "static", "indirect",
		"alias", "generated", "transient", "linked", "linked-runtime":
		return true, nil
	case "disabled", "masked", "masked-runtime", "bad":
		return false, nil
	default:
		logger().Warn("systemd: unexpected unit-file state word — "+
			"treating unit as not enabled this probe",
			"unit", unit, "state", state)
		return false, nil
	}
}
