// cli.go — the systemctl/journalctl CLI fallback branch of Client:
// every verb the D-Bus backend can't serve (or that fell back on a
// connection-level failure) lands here as a cliXxx method running
// the exact argv + output parsing the pre-D-Bus client had. Split
// out of systemd.go so the dispatch file stays under the ~500-LOC
// bar; nothing in this file knows D-Bus exists.
package systemd

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/journalwatch"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
)

func parseActiveStateWord(state string) (active, known bool) {
	switch state {
	case "active":
		return true, true
	case "reloading", "activating", "deactivating", "inactive",
		"failed", "maintenance", "unknown":
		return false, true
	default:
		return false, false
	}
}

func parseEnabledStateWord(state string) (enabled, known bool) {
	switch state {
	case "enabled", "enabled-runtime", "static", "indirect", "alias",
		"generated", "transient", "linked", "linked-runtime":
		return true, true
	case "disabled", "masked", "masked-runtime", "bad":
		return false, true
	default:
		return false, false
	}
}

func parseLoadStateWord(unit, state string) bool {
	switch state {
	case "loaded", "merged":
		return true
	case "stub", "not-found", "bad-setting", "error", "masked", "":
		return false
	default:
		logger().Warn("systemd: unexpected LoadState word — "+
			"treating unit as absent this probe",
			"unit", unit, "loadstate", state)
		return false
	}
}

func activeAgeFromMonoUS(unit string, monoUS uint64, procUptimeFile string) (time.Duration, error) {
	up, err := procfs.UptimeSeconds(procUptimeFile)
	if err != nil {
		return 0, fmt.Errorf("%s: read %s: %w", unit, procUptimeFile, err)
	}
	// Same clock family (CLOCK_MONOTONIC vs boot time) — the µs
	// rounding can push the delta a hair below zero on a unit that
	// just started.
	if age := up*1e6 - float64(monoUS); age > 0 {
		return time.Duration(age) * time.Microsecond, nil
	}
	return 0, nil
}

// cliActive is the systemctl is-active fallback for Active — same
// word vocabulary, same "output word vs probe failure" distinction.
func (c *Client) cliActive(ctx context.Context, unit string) (bool, error) {
	out, err := c.systemctl(ctx, "is-active", unit)
	state := strings.TrimSpace(out)
	if active, ok := parseActiveStateWord(state); ok {
		return active, nil
	}
	if err != nil {
		return false, fmt.Errorf("systemctl is-active %s: %w (%s)",
			unit, err, state)
	}
	return false, fmt.Errorf("systemctl is-active %s: unexpected output %q",
		unit, state)
}

// cliEnabled is the systemctl is-enabled fallback for Enabled —
// the rc==0 "installed" vocabulary mapped onto the stdout word.
func (c *Client) cliEnabled(ctx context.Context, unit string) (bool, error) {
	out, err := c.systemctl(ctx, "is-enabled", unit)
	state := strings.TrimSpace(out)
	if enabled, ok := parseEnabledStateWord(state); ok {
		return enabled, nil
	}
	if err != nil {
		return false, fmt.Errorf("systemctl is-enabled %s: %w (%s)",
			unit, err, state)
	}
	return false, fmt.Errorf("systemctl is-enabled %s: unexpected output %q",
		unit, state)
}

// cliExists is the systemctl show -p LoadState fallback for Exists —
// the unit_load_state_table vocabulary maps identically.
func (c *Client) cliExists(ctx context.Context, unit string) (bool, error) {
	out, err := c.systemctl(ctx, "show", "-p", "LoadState", "--value", unit)
	if err != nil {
		return false, fmt.Errorf("systemctl show -p LoadState --value %s: %w (%s)",
			unit, err, strings.TrimSpace(out))
	}
	return parseLoadStateWord(unit, strings.TrimSpace(out)), nil
}

// cliActiveAge is the systemctl show -p
// ActiveEnterTimestampMonotonic fallback for ActiveAge — the
// formatted ActiveEnterTimestamp ("Sun 2026-01-04 10:11:12 UTC") is
// NOT usable: its zone abbrev is the host's local zone, which
// time.Parse resolves only when it happens to be a name Go knows —
// a silent misparse under any non-UTC zone.
func (c *Client) cliActiveAge(ctx context.Context, unit string) (time.Duration, error) {
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
	return activeAgeFromMonoUS(unit, uint64(monoUS), c.procUptimeFile)
}

// cliListUnits is the systemctl list-units --all --no-legend --plain
// fallback for ListUnits/ListUnitsByPatterns — the legend-free table
// parse (first four columns are the state fields, the rest is the
// free-text description). patterns, when non-empty, are appended as
// argv exactly like `systemctl list-units <patterns>` — the glob
// matching stays systemctl's, not ours.
func (c *Client) cliListUnits(ctx context.Context, patterns []string) ([]UnitInfo, error) {
	args := []string{"list-units", "--all", "--no-legend", "--plain"}
	args = append(args, patterns...)
	out, err := c.Exec(ctx, "systemctl", args...)
	if err != nil {
		return nil, fmt.Errorf("systemctl list-units: %w (%s)",
			err, strings.TrimSpace(out))
	}
	var units []UnitInfo
	for line := range strings.SplitSeq(out, "\n") {
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
	argv := journalwatch.UnitWindowArgv(unit, since)
	return c.ExecCombined(ctx, argv[0], argv[1:]...)
}
