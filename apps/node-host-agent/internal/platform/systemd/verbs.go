// verbs.go — the state-changing half of Client: Restart, Stop,
// ReloadOrRestart, Signal, ResetFailed and DaemonReload. Each tries
// the D-Bus backend first and falls back to the systemctl CLI only
// on connection-level failures (errDBusUnavailable) — a method-level
// error is returned as-is so a failed verb is never re-issued
// through a second transport. Split out of systemd.go so the
// dispatch file stays under the ~500-LOC bar; the query verbs
// (Active/Enabled/Exists/ActiveAge/MainPID/ListUnits) stay there.
package systemd

import (
	"context"
	"fmt"
	"strings"
)

// Restart mirrors `systemctl restart <unit>`.
func (c *Client) Restart(ctx context.Context, unit string) error {
	if c.dbus != nil {
		if err := c.dbus.dbusJob(ctx, unit, "restart"); err == nil {
			return nil
		} else if !c.dbusUnavailable(err) {
			return err
		}
	}
	out, err := c.systemctl(ctx, "restart", unit)
	if err != nil {
		return fmt.Errorf("systemctl restart %s: %w (%s)", unit, err,
			strings.TrimSpace(out))
	}
	return nil
}

// Stop mirrors `systemctl stop <unit>` — the same blocking job-wait
// contract as Restart (the D-Bus StopUnit job completion is awaited,
// not just the enqueue). Fallback rules match Restart: only a
// connection-level failure retries over systemctl, never a method-
// level error (a stop that reported failure must not be re-issued
// through a second transport).
func (c *Client) Stop(ctx context.Context, unit string) error {
	if c.dbus != nil {
		if err := c.dbus.dbusJob(ctx, unit, "stop"); err == nil {
			return nil
		} else if !c.dbusUnavailable(err) {
			return err
		}
	}
	out, err := c.systemctl(ctx, "stop", unit)
	if err != nil {
		return fmt.Errorf("systemctl stop %s: %w (%s)", unit, err,
			strings.TrimSpace(out))
	}
	return nil
}

// ReloadOrRestart mirrors `systemctl reload-or-restart <unit>`.
func (c *Client) ReloadOrRestart(ctx context.Context, unit string) error {
	if c.dbus != nil {
		if err := c.dbus.dbusJob(ctx, unit, "reload-or-restart"); err == nil {
			return nil
		} else if !c.dbusUnavailable(err) {
			return err
		}
	}
	out, err := c.systemctl(ctx, "reload-or-restart", unit)
	if err != nil {
		return fmt.Errorf("systemctl reload-or-restart %s: %w (%s)",
			unit, err, strings.TrimSpace(out))
	}
	return nil
}

// Signal mirrors `systemctl kill -s <sig> <unit>` — used to signal the
// unit's main processes (e.g. SIGUSR1 coredns reload paths) without a
// full restart.
func (c *Client) Signal(ctx context.Context, unit, sig string) error {
	if c.dbus != nil {
		if err := c.dbus.dbusSignal(ctx, unit, sig); err == nil {
			return nil
		} else if !c.dbusUnavailable(err) {
			return err
		}
	}
	out, err := c.systemctl(ctx, "kill", "-s", sig, unit)
	if err != nil {
		return fmt.Errorf("systemctl kill -s %s %s: %w (%s)",
			sig, unit, err, strings.TrimSpace(out))
	}
	return nil
}

// ResetFailed mirrors `systemctl reset-failed <unit>` for a single
// named unit — the D-Bus ResetFailedUnit call. Callers holding a
// glob (`reset-failed cri-*.scope`) resolve the unit set via
// ListUnitsByPatterns first and call this per name, matching how
// systemctl itself expands the pattern client-side.
func (c *Client) ResetFailed(ctx context.Context, unit string) error {
	if c.dbus != nil {
		if err := c.dbus.dbusResetFailed(ctx, unit); err == nil {
			return nil
		} else if !c.dbusUnavailable(err) {
			return err
		}
	}
	out, err := c.systemctl(ctx, "reset-failed", unit)
	if err != nil {
		return fmt.Errorf("systemctl reset-failed %s: %w (%s)",
			unit, err, strings.TrimSpace(out))
	}
	return nil
}

// DaemonReload mirrors `systemctl daemon-reload`.
func (c *Client) DaemonReload(ctx context.Context) error {
	if c.dbus != nil {
		if err := c.dbus.dbusDaemonReload(ctx); err == nil {
			return nil
		} else if !c.dbusUnavailable(err) {
			return err
		}
	}
	out, err := c.systemctl(ctx, "daemon-reload")
	if err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w (%s)", err,
			strings.TrimSpace(out))
	}
	return nil
}
