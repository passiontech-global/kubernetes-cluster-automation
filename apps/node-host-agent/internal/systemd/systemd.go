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
//	systemctl show -p ActiveEnterTimestampMonotonic --value -> ActiveAge
//	systemctl restart <u>          -> Restart
//	systemctl reload-or-restart <u> -> ReloadOrRestart
//	systemctl kill -s <SIG> <u>    -> Signal
//	systemctl daemon-reload        -> DaemonReload
//	journalctl -u <u> --since <s>  -> Journal (shared k0sworker snapshot)
package systemd

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Defaults — containerized default is the DaemonSet host-root mount.
const (
	defaultHostRoot = "/host"
	defaultTimeout  = 30 * time.Second
	// defaultProcUptimeFile: hostPID:true makes the pod's /proc the
	// HOST /proc, so the plain path is right even when HostRoot is
	// mounted at /host (the nsenter wrapping covers commands, not
	// this file read).
	defaultProcUptimeFile = "/proc/uptime"
	// maxCmdOutputBytes caps the stdout retained per spawned command —
	// a log storm (journalctl -10min snapshot on a sick node) must not
	// push unbounded child output into the agent's heap. The rest is
	// drained and discarded so the child can still exit cleanly.
	maxCmdOutputBytes = 16 << 20
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
	// ProcUptimeFile is read by ActiveAge to turn the unit's
	// monotonic-since-boot activation timestamp into an age.
	ProcUptimeFile string
}

func (c *Config) applyDefaults() {
	if c.HostRoot == "" {
		c.HostRoot = defaultHostRoot
	}
	if c.Timeout <= 0 {
		c.Timeout = defaultTimeout
	}
	if c.ProcUptimeFile == "" {
		c.ProcUptimeFile = defaultProcUptimeFile
	}
	if c.RunCmd == nil {
		c.RunCmd = func(ctx context.Context, argv []string) (string, error) {
			cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				return "", err
			}
			if err := cmd.Start(); err != nil {
				return "", err
			}
			out, _ := io.ReadAll(io.LimitReader(stdout, maxCmdOutputBytes))
			_, _ = io.Copy(io.Discard, stdout) // drain so Wait cannot deadlock
			// Partial output is returned alongside the error just
			// like exec.Cmd.Output (callers count grep hits —
			// truncated text is still useful evidence).
			return string(out), cmd.Wait()
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

// ActiveAge returns how long the unit has been continuously active —
// the k0sworker_settled >=180s gate: a freshly restarted k0sworker
// gets a settle window before any new restart is spent on it. The
// age comes from ActiveEnterTimestampMonotonic (µs since boot,
// numeric and locale-free) compared against /proc/uptime — exactly
// what the shell did. The formatted ActiveEnterTimestamp ("Sun
// 2026-01-04 10:11:12 UTC") is NOT usable: its zone abbrev is the
// host's local zone ("ICT", "MSK", ...), which time.Parse resolves
// only when it happens to be a name Go knows — a silent misparse
// under any non-UTC zone. Error when the unit is not active or
// either clock is unreadable (both mean "not settled" to the caller).
func (c *Client) ActiveAge(ctx context.Context, unit string) (time.Duration, error) {
	out, err := c.systemctl(ctx, "show", "-p",
		"ActiveEnterTimestampMonotonic", "--value", unit)
	if err != nil {
		return 0, err
	}
	ts := strings.TrimSpace(out)
	monoUS, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || monoUS <= 0 {
		// 0/"n/a"/empty = never activated this boot; unparseable =
		// unexpected systemctl output — both count as "not active".
		return 0, fmt.Errorf("%s: unusable ActiveEnterTimestampMonotonic %q (not active)",
			unit, ts)
	}
	up, err := procUptimeSeconds(c.cfg.ProcUptimeFile)
	if err != nil {
		return 0, fmt.Errorf("%s: read %s: %w", unit, c.cfg.ProcUptimeFile, err)
	}
	// Same clock family (CLOCK_MONOTONIC vs boot time) — the µs
	// rounding can push the delta a hair below zero on a unit that
	// just started.
	if age := up*1e6 - float64(monoUS); age > 0 {
		return time.Duration(age) * time.Microsecond, nil
	}
	return 0, nil
}

// procUptimeSeconds parses the first field of /proc/uptime — seconds
// since boot on the boot-relative timeline the kernel and systemd's
// *Monotonic properties share.
func procUptimeSeconds(path string) (float64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	f := strings.Fields(string(data))
	if len(f) == 0 {
		return 0, fmt.Errorf("empty uptime %s", path)
	}
	return strconv.ParseFloat(f[0], 64)
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
