// Package systemd ports the node-watchdog modules' host systemd
// control into a testable client. The agent pod sees the host through
// a mounted host root: every command goes through platform/hostexec,
// which wraps it in `nsenter -t 1 -m -u -i -n -p --` so
// systemctl/journalctl run inside the host PID-1 namespaces and talk
// to the REAL systemd — plain `systemctl` in-container would fail
// (no /run/systemd/private) or worse, act on the wrong namespace.
// When the agent runs directly on the host (HostRoot "/") the
// wrapper is skipped.
//
// All commands go through Config.RunCmd — one seam that tests replace
// with a fake recorder, and that production wires to
// exec.CommandContext (via hostexec). Shell parity:
//
//	systemctl is-active <u>        -> Active / IsActive
//	systemctl show -p LoadState <u> -> Exists / UnitExists (WD_REQUIRES unit:<n>)
//	systemctl show -p ActiveEnterTimestampMonotonic --value -> ActiveAge
//	systemctl restart <u>          -> Restart
//	systemctl reload-or-restart <u> -> ReloadOrRestart
//	systemctl kill -s <SIG> <u>    -> Signal
//	systemctl daemon-reload        -> DaemonReload
//	journalctl -u <u> --since <s>  -> Journal (shared k0sworker snapshot)
package systemd

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostexec"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
)

// Config is hostexec.Config — a type alias, not a field-for-field
// copy: the exec seam (HostRoot/Timeout/RunCmd/RunCmdCombined) is
// owned and defaulted by hostexec, and this package uses it verbatim,
// so a duplicate struct would only be a place for the two to drift.
// Consumers keep the systemd.Config spelling (composite literals
// unchanged). The one systemd-specific input — ActiveAge's
// uptime-file override — cannot ride an alias; it travels via
// WithProcUptimeFile (default /proc/uptime is right in every real
// deployment: hostPID:true mounts the HOST /proc at /proc).
type Config = hostexec.Config

// Option customizes a Client at construction beyond its Config.
type Option func(*Client)

// WithProcUptimeFile overrides the file ActiveAge reads to turn the
// unit's monotonic-since-boot activation timestamp into an age.
// Production keeps the default; tests point it at a temp copy.
func WithProcUptimeFile(path string) Option {
	return func(c *Client) { c.procUptimeFile = path }
}

// defaultProcUptimeFile: hostPID:true makes the pod's /proc the
// HOST /proc, so the plain path is right even when HostRoot is
// mounted at /host (the nsenter wrapping covers commands, not
// this file read).
const defaultProcUptimeFile = "/proc/uptime"

// UnitInfo is one row of `systemctl list-units` — the state triple
// plus description, transport-agnostic so the D-Bus and systemctl
// paths return the same shape.
type UnitInfo struct {
	Name        string
	Description string
	LoadState   string
	ActiveState string
	SubState    string
}

// Client runs host systemd commands.
type Client struct {
	cfg            Config // kept for Timeout: UnitExists' background bound
	host           *hostexec.Runner
	procUptimeFile string
	// dbus is the zero-fork control path — non-nil only when the
	// caller supplied no exec seams (production) on linux; tests
	// injecting RunCmd/RunCmdCombined keep the systemctl path.
	dbus *dbusBackend
}

// New returns a Client for cfg.
func New(cfg Config, opts ...Option) *Client {
	// The exec fields (HostRoot, nil RunCmd/RunCmdCombined seams) are
	// defaulted inside hostexec.New; only Timeout needs arming here —
	// the Client reads it directly for UnitExists' background bound
	// (the default value stays hostexec's, no local copy).
	if cfg.Timeout <= 0 {
		cfg.Timeout = hostexec.DefaultTimeout
	}
	c := &Client{
		cfg:            cfg,
		host:           hostexec.New(cfg),
		procUptimeFile: defaultProcUptimeFile,
	}
	// Zero-fork path: only when NO exec seam was injected — a fake
	// RunCmd in tests must keep observing the exact systemctl argv,
	// so the D-Bus backend never activates there. cfg is a value
	// copy (hostexec.New defaults its own), so the nil check here
	// still sees the caller's original seams.
	if cfg.RunCmd == nil && cfg.RunCmdCombined == nil {
		hostRoot := cfg.HostRoot
		if hostRoot == "" {
			hostRoot = hostexec.DefaultHostRoot
		}
		c.dbus = newDBusBackend(hostRoot)
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Exec runs an arbitrary host command — systemctl and journalctl are
// wrapped identically (hostexec.NSAll), and other host binaries
// (fail2ban-client, ip) share the same nsenter path. ctx is
// additionally bounded by Config.Timeout.
func (c *Client) Exec(ctx context.Context, name string, args ...string) (string, error) {
	return c.exec(ctx, 0, false, name, args...)
}

// ExecCombined is Exec with the child's STDERR folded into the
// returned output — for probes whose evidence lives off stdout
// (journalctl reports corrupt journal files on STDERR; a
// stdout-only capture makes the "corrupt" substring check dead
// code). Callers that only want stdout keep Exec — the signature
// contract is unchanged.
func (c *Client) ExecCombined(ctx context.Context, name string, args ...string) (string, error) {
	return c.exec(ctx, 0, true, name, args...)
}

// ExecBounded is Exec with a per-call budget replacing Config.Timeout
// — for remediations whose bound is deliberately longer than the
// shared 30s default (the apiserver wedge gate's `timeout 90
// systemctl restart`). ctx still bounds the call from above;
// budget <= 0 falls back to Config.Timeout.
func (c *Client) ExecBounded(ctx context.Context, budget time.Duration, name string, args ...string) (string, error) {
	return c.exec(ctx, budget, false, name, args...)
}

// ExecCombinedBounded is ExecBounded with stderr folded into the
// returned output — the ExecCombined/ExecBounded pairing.
func (c *Client) ExecCombinedBounded(ctx context.Context, budget time.Duration, name string, args ...string) (string, error) {
	return c.exec(ctx, budget, true, name, args...)
}

// dbusUnavailable reports whether err is a connection-level D-Bus
// failure — the only class of error worth retrying over the
// systemctl transport. Unit/job errors must NOT fall back: a
// failed restart retried through a second transport would bounce
// the unit twice.
func (c *Client) dbusUnavailable(err error) bool {
	if errors.Is(err, errDBusUnavailable) {
		logger().Warn("systemd: dbus unavailable — falling back to systemctl",
			"error", err)
		return true
	}
	return false
}

// exec is the shared body of the Client quartet: every systemd
// command enters NSAll, and the budget/combined pair selects which
// hostexec seam runs it. budget <= 0 (the unbounded Exec/ExecCombined
// pair) falls back to Config.Timeout inside hostexec.
func (c *Client) exec(ctx context.Context, budget time.Duration, combined bool, name string, args ...string) (string, error) {
	if combined {
		return c.host.ExecCombinedBounded(ctx, hostexec.NSAll, budget, name, args...)
	}
	return c.host.ExecBounded(ctx, hostexec.NSAll, budget, name, args...)
}

func (c *Client) systemctl(ctx context.Context, args ...string) (string, error) {
	return c.Exec(ctx, "systemctl", args...)
}

// Active mirrors `systemctl is-active <unit>`: true only on literal
// "active" (activating/failed/inactive all count as down — the shell
// compared the string). Unlike IsActive it reports probe failure
// separately: `is-active` exits non-zero for EVERY non-active state,
// so a non-zero exit carrying a real ActiveState word on stdout is a
// legitimate "not active", while an error with empty/unexpected
// output means the check itself failed (dbus down, systemctl
// missing) — callers gating protective action on the result can
// fail closed instead of reading the failure as "down".
func (c *Client) Active(ctx context.Context, unit string) (bool, error) {
	if c.dbus != nil {
		active, err := c.dbus.dbusActive(ctx, unit)
		if err == nil {
			return active, nil
		}
		if !c.dbusUnavailable(err) {
			return false, err
		}
	}
	out, err := c.systemctl(ctx, "is-active", unit)
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

// IsActive is Active with the error folded to false — legacy callers
// that cannot use the distinction keep the old "can't ask = down"
// semantics.
func (c *Client) IsActive(ctx context.Context, unit string) bool {
	active, err := c.Active(ctx, unit)
	return err == nil && active
}

// IsEnabled mirrors `systemctl is-enabled <unit> >/dev/null` — the
// runner's WD_TINC_ACTIVE/WD_NEBULA_ACTIVE probes tested the EXIT
// CODE, not the string: rc=0 covers the whole enabled vocabulary
// (enabled, enabled-runtime, static, indirect, alias, generated,
// transient, linked) — a static or templated-instance unit counts as
// "installed" the same as enabled. Only rc!=0 (disabled, masked,
// not-found) means off.
//
// Enabled additionally reports probe failure: a recognized state
// word on stdout is a real answer whatever the exit code, while an
// error with empty/unexpected output means the check itself failed.
// Caveat: a unit that does not exist at all produces an empty stdout
// + error — indistinguishable from a tool failure — so not-found
// surfaces as an error to callers using this variant (the IsEnabled
// wrapper still folds it to false, matching the old rc!=0 test).
func (c *Client) Enabled(ctx context.Context, unit string) (bool, error) {
	out, err := c.systemctl(ctx, "is-enabled", unit)
	switch strings.TrimSpace(out) {
	case "enabled", "enabled-runtime", "static", "indirect", "alias",
		"generated", "transient", "linked", "linked-runtime":
		// The whole "installed" vocabulary the rc==0 test accepted.
		return true, nil
	case "disabled", "masked", "masked-runtime", "bad":
		// is-enabled answered — the unit file exists but is off.
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("systemctl is-enabled %s: %w (%s)",
			unit, err, strings.TrimSpace(out))
	}
	return false, fmt.Errorf("systemctl is-enabled %s: unexpected output %q",
		unit, strings.TrimSpace(out))
}

// IsEnabled is Enabled with the error folded to false.
func (c *Client) IsEnabled(ctx context.Context, unit string) bool {
	enabled, err := c.Enabled(ctx, unit)
	return err == nil && enabled
}

// Exists is the error-aware UnitExists — the WD_REQUIRES unit:<name>
// gate answered by `systemctl show -p LoadState --value <unit>`
// instead of `systemctl cat`: cat fails identically for "unit file
// absent" and "systemctl itself broken" (both leave stdout empty),
// while `show` exits 0 for any unit name and reports LoadState — a
// non-zero exit unambiguously means the probe failed.
//
// LoadState → answer (systemd's unit_load_state_table vocabulary).
// "Exists" means "the manager holds a WORKING unit definition —
// the unit is real enough to start/restart", NOT "a file sits on
// disk": every caller gates an action (restart, down-latch, metrics
// collection) on this answer, and states whose unit cannot be
// started — or which the admin deliberately disabled — must not
// read as present:
//
//	loaded      → true   unit definition loaded — manageable
//	merged      → true   loaded, merged with transient config —
//	                     cat could read it and restart works
//	stub        → false  referenced by other units but NO
//	                     definition — cat finds no files, start
//	                     fails; nothing to act on
//	not-found   → false  no unit definition
//	bad-setting → false  file exists but fails to parse — not
//	                     startable; a restart cannot fix it
//	error       → false  load error — not manageable
//	masked      → false  administratively disabled — reads
//	                     inactive and every restart attempt fails,
//	                     so counting it present would make callers
//	                     fight the admin's intent each cycle
//	"" / other  → false  empty/unrecognized word — conservative
//	                     absent, warned below so a weird systemd
//	                     state stays diagnosable
func (c *Client) Exists(ctx context.Context, unit string) (bool, error) {
	if c.dbus != nil {
		exists, err := c.dbus.dbusExists(ctx, unit)
		if err == nil {
			return exists, nil
		}
		if !c.dbusUnavailable(err) {
			return false, err
		}
	}
	out, err := c.systemctl(ctx, "show", "-p", "LoadState", "--value", unit)
	if err != nil {
		return false, fmt.Errorf("systemctl show -p LoadState --value %s: %w (%s)",
			unit, err, strings.TrimSpace(out))
	}
	switch state := strings.TrimSpace(out); state {
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

// UnitExists is Exists on a bounded background context with the
// error folded to false — kept for callers that only need the old
// "can't ask = absent" answer.
func (c *Client) UnitExists(unit string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), c.cfg.Timeout)
	defer cancel()
	exists, err := c.Exists(ctx, unit)
	return err == nil && exists
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
	if c.dbus != nil {
		age, err := c.dbus.dbusActiveAge(ctx, unit, c.procUptimeFile)
		if err == nil {
			return age, nil
		}
		if !c.dbusUnavailable(err) {
			return 0, err
		}
	}
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
	up, err := hostutil.UptimeSeconds(c.procUptimeFile)
	if err != nil {
		return 0, fmt.Errorf("%s: read %s: %w", unit, c.procUptimeFile, err)
	}
	// Same clock family (CLOCK_MONOTONIC vs boot time) — the µs
	// rounding can push the delta a hair below zero on a unit that
	// just started.
	if age := up*1e6 - float64(monoUS); age > 0 {
		return time.Duration(age) * time.Microsecond, nil
	}
	return 0, nil
}

// (ActiveAge reads /proc/uptime through hostutil.UptimeSeconds — the
// shared parser; the systemd-local copy it replaced drifted only in
// an error string.)

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

// ListUnits mirrors `systemctl list-units --all --no-legend
// --plain` — every loaded unit with its state triple. The D-Bus
// path answers from ListUnits directly; the systemctl path parses
// the legend-free table (first four columns are the state fields,
// the rest is the free-text description).
func (c *Client) ListUnits(ctx context.Context) ([]UnitInfo, error) {
	if c.dbus != nil {
		units, err := c.dbus.dbusListUnits(ctx)
		if err == nil {
			return units, nil
		}
		if !c.dbusUnavailable(err) {
			return nil, err
		}
	}
	out, err := c.Exec(ctx, "systemctl", "list-units",
		"--all", "--no-legend", "--plain")
	if err != nil {
		return nil, fmt.Errorf("systemctl list-units: %w (%s)",
			err, strings.TrimSpace(out))
	}
	var units []UnitInfo
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		u := UnitInfo{
			Name:        f[0],
			LoadState:   f[1],
			ActiveState: f[2],
			SubState:    f[3],
		}
		if len(f) > 4 {
			u.Description = strings.Join(f[4:], " ")
		}
		units = append(units, u)
	}
	return units, nil
}

// Journal mirrors `journalctl -u <unit> --since <since> --no-pager` —
// the shared k0sworker -10min snapshot the runner dumped once per
// watchdog run for modules 05/06. Stderr is folded in via
// ExecCombined: journald reports corrupt journal files on STDERR
// ("File /var/log/journal/... is corrupt") and the A5 integrity
// check's "corrupt" substring test is dead code without it — the
// extra diagnostic lines can't false-positive the 05/06 signature
// greps (they match k0sworker log content, not journalctl notices).
// A journald error returns the error with whatever partial output
// came back (empty is fine — callers count grep hits, an empty
// journal means zero hits, and a fetch failure is logged, never
// fatal).
func (c *Client) Journal(ctx context.Context, unit, since string) (string, error) {
	return c.ExecCombined(ctx, "journalctl",
		"-u", unit, "--since", since, "--no-pager")
}
