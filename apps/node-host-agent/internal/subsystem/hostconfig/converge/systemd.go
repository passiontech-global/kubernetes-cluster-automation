// systemd.go — the systemctl state verbs over a Runner: the
// enable/start/stop/restart/reload contract the ansible
// systemd_service tasks provided. Verbs return errors; callers own
// logging, metrics, and cycle attribution.
package converge

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Systemd drives systemctl through a Runner under a per-command
// Budget (see RunBudget — a wedged systemctl must fail, not hang
// the converge).
type Systemd struct {
	Runner Runner
	Budget time.Duration
}

func (s Systemd) run(ctx context.Context, args ...string) (string, error) {
	return RunBudget(ctx, s.Runner, s.Budget, "systemctl", args...)
}

func (s Systemd) DaemonReload(ctx context.Context) error {
	_, err := s.run(ctx, "daemon-reload")
	return err
}

// Active reports `is-active` with probe failure distinguished from
// "not active" — the error-aware semantics of systemd.Client.Active
// (converge keeps its own Runner seam; only the RESULT CONTRACT is
// aligned). `is-active` exits non-zero for EVERY non-active state,
// so a non-zero exit carrying a real ActiveState word on stdout is
// a legitimate "not active", while an error with empty/unexpected
// output means the check itself failed (dbus down, systemctl
// missing) — callers gating protective action on the result can
// fail closed instead of reading the failure as "down". The old
// single-word IsActive below keeps folding that failure to false.
func (s Systemd) Active(ctx context.Context, unit string) (bool, error) {
	out, err := s.run(ctx, "is-active", unit)
	switch strings.TrimSpace(out) {
	case "active":
		return true, nil
	case "reloading", "activating", "deactivating", "inactive",
		"failed", "maintenance", "unknown":
		// A real ActiveState — the probe answered "not active".
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("systemctl is-active %s: %w (%s)",
			unit, err, strings.TrimSpace(out))
	}
	return false, fmt.Errorf("systemctl is-active %s: unexpected output %q",
		unit, strings.TrimSpace(out))
}

// IsActive is Active with the error folded to false — a failing
// probe counts as inactive (the unit state is unknown either way;
// the caller decides whether to act).
func (s Systemd) IsActive(ctx context.Context, unit string) bool {
	active, err := s.Active(ctx, unit)
	return err == nil && active
}

// ServiceState returns the unit's ActiveState property ("" on
// failure — a unit that cannot be queried is treated as unknown).
func (s Systemd) ServiceState(ctx context.Context, unit string) string {
	out, _ := s.run(ctx, "show", unit, "-p", "ActiveState", "--value")
	return strings.TrimSpace(out)
}

func (s Systemd) EnableService(ctx context.Context, unit string) error {
	_, err := s.run(ctx, "enable", unit)
	return err
}

func (s Systemd) StartService(ctx context.Context, unit string) error {
	_, err := s.run(ctx, "start", unit)
	return err
}

func (s Systemd) StopService(ctx context.Context, unit string) error {
	_, err := s.run(ctx, "stop", unit)
	return err
}

func (s Systemd) RestartService(ctx context.Context, unit string) error {
	_, err := s.run(ctx, "restart", unit)
	return err
}

func (s Systemd) ReloadService(ctx context.Context, unit string) error {
	_, err := s.run(ctx, "reload", unit)
	return err
}

// EnsureService ports systemd_service enabled+state: enable is
// applied first, then start-or-stop. Failures join — the caller
// sees every verb that failed, not just the first.
func (s Systemd) EnsureService(ctx context.Context, unit string, enable, start bool) error {
	var errs []error
	if enable {
		errs = append(errs, s.EnableService(ctx, unit))
	}
	if start {
		errs = append(errs, s.StartService(ctx, unit))
	} else {
		errs = append(errs, s.StopService(ctx, unit))
	}
	return errors.Join(errs...)
}
