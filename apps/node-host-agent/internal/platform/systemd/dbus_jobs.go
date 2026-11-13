//go:build linux

// dbus_jobs.go — the job-oriented half of the D-Bus backend: the
// blocking start-job verbs (RestartUnit/ReloadOrRestartUnit/
// StopUnit with JobRemoved completion waits), KillUnitWithTarget
// signal delivery, Manager.Reload and the signal-name table.
// Split out of dbus_linux.go so the conn-lifecycle file stays under
// the ~500-LOC bar; same package, same backend receiver.
package systemd

import (
	"context"
	"fmt"
	"strings"

	sdbus "github.com/coreos/go-systemd/v22/dbus"
	godbus "github.com/godbus/dbus/v5"
)

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
	//
	// done closes when dbusJob returns (job landed, ctx cancelled or
	// transport death observed) — the watcher goroutines select on it
	// so a LIVE connection does not leave one parked goroutine per
	// job watching a transport that never dies.
	transportDead := make(chan struct{}, 1)
	done := make(chan struct{})
	defer close(done)
	for _, raw := range []*godbus.Conn{rawSys, rawSig} {
		if raw == nil {
			continue
		}
		go func(c *godbus.Conn) {
			select {
			case <-c.Context().Done():
				select {
				case transportDead <- struct{}{}:
				default:
				}
			case <-done:
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

// dbusResetFailed mirrors `systemctl reset-failed <unit>` —
// Manager.ResetFailedUnit clears the failed bookkeeping of one
// unit. The glob form (`reset-failed <pattern>`) has no D-Bus
// equivalent: systemctl expands the pattern client-side and issues
// one call per match, so callers that used a glob resolve the unit
// set first (ListUnitsByPatterns) and call ResetFailed per name.
func (b *dbusBackend) dbusResetFailed(ctx context.Context, unit string) error {
	conn, err := b.systemConn(ctx)
	if err != nil {
		return err
	}
	if err := conn.ResetFailedUnitContext(ctx, normalizeUnit(unit)); err != nil {
		return fmt.Errorf("dbus reset-failed %s: %w", unit, err)
	}
	return nil
}
