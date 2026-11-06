// systemd.go — the systemctl state verbs over a Runner: the
// enable/start/stop/restart/reload contract the ansible
// systemd_service tasks provided. Verbs return errors; callers own
// logging, metrics, and cycle attribution.
package converge

import (
	"context"
	"errors"
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

// IsActive reports `is-active` — a failing probe counts as inactive
// (the unit state is unknown either way; the caller decides whether
// to act).
func (s Systemd) IsActive(ctx context.Context, unit string) bool {
	out, err := s.run(ctx, "is-active", unit)
	return err == nil && strings.TrimSpace(out) == "active"
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
