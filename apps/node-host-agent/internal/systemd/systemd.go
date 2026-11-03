// Package systemd ports the node-watchdog modules' host systemd
// control into a testable client. The agent pod sees the host through
// a mounted host root: every command is wrapped in
// `nsenter -t 1 -m -u -i -n -p --` so systemctl/journalctl run inside
// the host PID-1 namespaces and talk to the REAL systemd — plain
// `systemctl` in-container would fail (no /run/systemd/private) or
// worse, act on the wrong namespace. When the agent runs directly on
// the host (HostRoot "/") the wrapper is skipped.
//
// All commands go through Config.RunCmd — one seam that tests replace
// with a fake recorder, and that production wires to
// exec.CommandContext. Shell parity:
//
//	systemctl is-active <u>        -> IsActive
//	systemctl cat <u>              -> UnitExists (WD_REQUIRES unit:<n>)
//	systemctl show -p ActiveEnterTimestamp --value -> ActiveAge
//	systemctl restart <u>          -> Restart
//	systemctl reload-or-restart <u> -> ReloadOrRestart
//	systemctl kill -s <SIG> <u>    -> Signal
//	systemctl daemon-reload        -> DaemonReload
//	journalctl -u <u> --since <s>  -> Journal (shared k0sworker snapshot)
package systemd

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Defaults — containerized default is the DaemonSet host-root mount.
const (
	defaultHostRoot = "/host"
	defaultTimeout  = 30 * time.Second
)

// Config carries the exec seam — all test-injectable.
type Config struct {
	// HostRoot is where the host filesystem is mounted. "/" means the
	// process runs on the host already — commands run unwrapped.
	HostRoot string
	// Timeout bounds every spawned command (the shell used timeout 15
	// on journald/ctr calls; 30s covers a loaded journald).
	Timeout time.Duration
	// RunCmd executes argv[0] argv[1:] and returns combined stdout.
	// nil → exec.CommandContext. The nsenter wrapping is applied to
	// argv BEFORE RunCmd sees it, so a fake runner observes the exact
	// production command line.
	RunCmd func(ctx context.Context, argv []string) (string, error)
}

func (c *Config) applyDefaults() {
	if c.HostRoot == "" {
		c.HostRoot = defaultHostRoot
	}
	if c.Timeout <= 0 {
		c.Timeout = defaultTimeout
	}
	if c.RunCmd == nil {
		c.RunCmd = func(ctx context.Context, argv []string) (string, error) {
			out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).Output()
			return string(out), err
		}
	}
}

// Client runs host systemd commands.
type Client struct {
	cfg Config
}

// New returns a Client for cfg.
func New(cfg Config) *Client {
	cfg.applyDefaults()
	return &Client{cfg: cfg}
}

// Exec runs an arbitrary host command — systemctl and journalctl are
// wrapped identically, and other host binaries (fail2ban-client, ip)
// share the same nsenter path. ctx is additionally bounded by
// Config.Timeout.
func (c *Client) Exec(ctx context.Context, name string, args ...string) (string, error) {
	argv := append([]string{name}, args...)
	if c.cfg.HostRoot != "/" {
		argv = append([]string{"nsenter", "-t", "1",
			"-m", "-u", "-i", "-n", "-p", "--"}, argv...)
	}
	cctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	return c.cfg.RunCmd(cctx, argv)
}

func (c *Client) systemctl(ctx context.Context, args ...string) (string, error) {
	return c.Exec(ctx, "systemctl", args...)
}

// IsActive mirrors `systemctl is-active <unit>`: true only on literal
// "active" (activating/failed/inactive all count as down — the shell
// compared the string).
func (c *Client) IsActive(ctx context.Context, unit string) bool {
	out, err := c.systemctl(ctx, "is-active", unit)
	if err != nil {
		return false
	}
	return strings.TrimSpace(out) == "active"
}

// IsEnabled mirrors `systemctl is-enabled <unit> >/dev/null` — the
// runner's WD_TINC_ACTIVE/WD_NEBULA_ACTIVE probes tested the EXIT
// CODE, not the string: rc=0 covers the whole enabled vocabulary
// (enabled, enabled-runtime, static, indirect, alias, generated,
// transient, linked) — a static or templated-instance unit counts as
// "installed" the same as enabled. Only rc!=0 (disabled, masked,
// not-found) means off.
func (c *Client) IsEnabled(ctx context.Context, unit string) bool {
	_, err := c.systemctl(ctx, "is-enabled", unit)
	return err == nil
}

// UnitExists mirrors `systemctl cat <unit>` — the WD_REQUIRES
// unit:<name> gate: the unit file is loadable (installed or
// generated), rc!=0 means absent.
func (c *Client) UnitExists(unit string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), c.cfg.Timeout)
	defer cancel()
	_, err := c.systemctl(ctx, "cat", unit)
	return err == nil
}

// ActiveAge returns how long the unit has been continuously active,
// from ActiveEnterTimestamp — the k0sworker_settled >=180s gate: a
// freshly restarted k0sworker gets a settle window before any new
// restart is spent on it. Error when the unit is not active or the
// timestamp is unreadable (both mean "not settled" to the caller).
func (c *Client) ActiveAge(ctx context.Context, unit string) (time.Duration, error) {
	out, err := c.systemctl(ctx, "show", "-p", "ActiveEnterTimestamp",
		"--value", unit)
	if err != nil {
		return 0, err
	}
	ts := strings.TrimSpace(out)
	if ts == "" || ts == "n/a" {
		return 0, fmt.Errorf("%s: no ActiveEnterTimestamp (not active)", unit)
	}
	// systemd prints e.g. "Sun 2026-01-04 10:11:12 UTC" — the Go
	// reference layout needs the weekday abbreviated, timezone as
	// zone name.
	t, err := time.Parse("Mon 2006-01-02 15:04:05 MST", ts)
	if err != nil {
		return 0, fmt.Errorf("%s: parse ActiveEnterTimestamp %q: %w", unit, ts, err)
	}
	return time.Since(t), nil
}

// Restart mirrors `systemctl restart <unit>`.
func (c *Client) Restart(ctx context.Context, unit string) error {
	out, err := c.systemctl(ctx, "restart", unit)
	if err != nil {
		return fmt.Errorf("systemctl restart %s: %w (%s)", unit, err,
			strings.TrimSpace(out))
	}
	return nil
}

// ReloadOrRestart mirrors `systemctl reload-or-restart <unit>`.
func (c *Client) ReloadOrRestart(ctx context.Context, unit string) error {
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
	out, err := c.systemctl(ctx, "kill", "-s", sig, unit)
	if err != nil {
		return fmt.Errorf("systemctl kill -s %s %s: %w (%s)",
			sig, unit, err, strings.TrimSpace(out))
	}
	return nil
}

// DaemonReload mirrors `systemctl daemon-reload`.
func (c *Client) DaemonReload(ctx context.Context) error {
	out, err := c.systemctl(ctx, "daemon-reload")
	if err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w (%s)", err,
			strings.TrimSpace(out))
	}
	return nil
}

// Journal mirrors `journalctl -u <unit> --since <since> --no-pager` —
// the shared k0sworker -10min snapshot the runner dumped once per
// watchdog run for modules 05/06. A journald error returns the error
// with whatever partial output came back (empty is fine — callers
// count grep hits, an empty journal means zero hits, and a fetch
// failure is logged, never fatal).
func (c *Client) Journal(ctx context.Context, unit, since string) (string, error) {
	return c.Exec(ctx, "journalctl", "-u", unit, "--since", since, "--no-pager")
}
