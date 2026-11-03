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
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
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
	// RunCmdCombined is RunCmd with the child's STDERR folded into
	// the returned output — ExecCombined's seam. Needed for probes
	// whose evidence lives on stderr (journalctl prints
	// "File ... is corrupt" to stderr, not stdout). nil →
	// exec.CommandContext writing both streams into one capped
	// buffer.
	RunCmdCombined func(ctx context.Context, argv []string) (string, error)
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
	if c.RunCmdCombined == nil {
		c.RunCmdCombined = func(ctx context.Context, argv []string) (string, error) {
			cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
			// Both streams share one capped sink — the child never
			// blocks on an unread stderr pipe, and output over the
			// cap is swallowed (same budget as the stdout path).
			var buf cappedBuffer
			cmd.Stdout = &buf
			cmd.Stderr = &buf
			// Run waits for the copy goroutines — buf is complete
			// once it returns (partial output alongside an error,
			// same contract as the stdout path).
			err := cmd.Run()
			return buf.String(), err
		}
	}
}

// cappedBuffer is a goroutine-safe io.Writer retaining at most
// maxCmdOutputBytes — the combined runner's stdout+stderr sink
// (exec copies each stream on its own goroutine; excess is
// swallowed so the child still exits cleanly).
type cappedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.buf.Len() < maxCmdOutputBytes {
		b.buf.Write(p)
	}
	return len(p), nil
}

func (b *cappedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
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
	cctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	return c.cfg.RunCmd(cctx, c.hostArgv(name, args))
}

// ExecCombined is Exec with the child's STDERR folded into the
// returned output — for probes whose evidence lives off stdout
// (journalctl reports corrupt journal files on STDERR; a
// stdout-only capture makes the "corrupt" substring check dead
// code). Callers that only want stdout keep Exec — the signature
// contract is unchanged.
func (c *Client) ExecCombined(ctx context.Context, name string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	return c.cfg.RunCmdCombined(cctx, c.hostArgv(name, args))
}

// hostArgv applies the nsenter host-namespace wrap — shared by
// Exec and ExecCombined.
func (c *Client) hostArgv(name string, args []string) []string {
	argv := append([]string{name}, args...)
	if c.cfg.HostRoot != "/" {
		argv = append([]string{"nsenter", "-t", "1",
			"-m", "-u", "-i", "-n", "-p", "--"}, argv...)
	}
	return argv
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
		slog.Warn("systemd: unexpected LoadState word — "+
			"treating unit as absent this probe",
			"subsystem", "systemd", "unit", unit, "loadstate", state)
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
