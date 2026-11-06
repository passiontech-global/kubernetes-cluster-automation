// runtime_systemd_sessions.go — the systemd-session-hygiene guard
// (wdeps.CheckSystemdSessions). Every login/cron session PID 1
// tracks costs a logind record; abandoned ones (dead ssh, wedged
// scopes) are never reaped and the whole list is walked by every
// D-Bus session call — past a few dozen, systemctl/loginctl/
// kubelet's D-Bus traffic visibly stalls. The check counts
// sessions, times the is-system-running round trip as the D-Bus
// health signal, and reaps stale sessions plus the failed-unit
// bookkeeping when either trips.
package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

const (
	// systemdSessionStaleAge is the "abandoned" evidence bar — a
	// closing/abandoned session file untouched this long is stuck,
	// not tearing down (logind rewrites the file on state change,
	// so mtime approximates when the state was entered).
	systemdSessionStaleAge = 2 * time.Hour
	// systemdSessionAbandonedMin is the stale-session count that
	// trips the bloat latch — a couple of stuck sessions are
	// normal; dozens walk every D-Bus session call.
	systemdSessionAbandonedMin = 20
	// systemdDbusSlowSeconds is the is-system-running round trip
	// above which D-Bus itself is counted degraded.
	systemdDbusSlowSeconds = 3.0
	// systemdSessionMaxTerminate bounds loginctl calls per cycle —
	// each terminate is a D-Bus round trip on the bus that is
	// already slow.
	systemdSessionMaxTerminate = 20
	// systemdResetFailedInterval is the last-systemd-reset-failed
	// budget — dead-unit bookkeeping also feeds the unit-table
	// bloat the session janitor fights.
	systemdResetFailedInterval = 30 * time.Minute
)

type SystemdSessionCheck struct{ d *wdeps.Deps }

// Name returns the check label / WD_SIG key.
func (c *SystemdSessionCheck) Name() string { return wdeps.CheckSystemdSessions }

// sessionState returns the STATE= value of a logind session file —
// "" when unreadable or absent.
func sessionState(data []byte) string {
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "STATE="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// scanSessions counts session state files and collects the ids of
// sessions stuck closing/abandoned longer than the stale-age bar.
// .ref companions and non-regular entries are skipped — they are
// bookkeeping, not sessions. An unreadable dir yields zeroes (a
// host without logind is a dormant check, not an error).
func (c *SystemdSessionCheck) scanSessions() (total int, stale []string) {
	dir := c.d.Cfg.Runtime.SessionsDir
	ents, err := os.ReadDir(dir)
	if err != nil {
		return 0, nil
	}
	now := c.d.Cfg.Seams.Host.NowFn()
	for _, en := range ents {
		if en.IsDir() || strings.HasSuffix(en.Name(), ".ref") {
			continue
		}
		total++
		st := ""
		if data, err := os.ReadFile(filepath.Join(dir, en.Name())); err == nil {
			st = sessionState(data)
		}
		if st != "closing" && st != "abandoned" {
			continue
		}
		info, err := en.Info()
		if err != nil || now.Sub(info.ModTime()) < systemdSessionStaleAge {
			continue
		}
		stale = append(stale, en.Name())
	}
	return total, stale
}

// Run executes one systemd-session round.
func (c *SystemdSessionCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if !e.WorkerActive {
		c.d.Cycles.WithLabelValues(wdeps.CheckSystemdSessions, "gated").Inc()
		return
	}
	total, stale := c.scanSessions()
	c.d.SystemdSessionsTotal = int64(total)
	c.d.SystemdSessionsStale = int64(len(stale))
	sd := c.d.Cfg.Systemd
	latency := -1.0
	if sd != nil {
		// The is-system-running call is itself the D-Bus probe —
		// ANY answer (running/degraded/offline) means D-Bus replied
		// and only the round-trip TIME is the signal. The
		// measurement uses the seam clock, not time.Now: the test
		// seam keeps latency deterministic.
		t0 := c.d.Cfg.Seams.Host.NowFn()
		if _, err := sd.Exec(ctx, "systemctl", "is-system-running"); err != nil {
			// A non-zero exit is still a D-Bus round trip (degraded
			// reports exit 1); only log at debug level via suspect
			// — the latency number already carries the verdict.
			logger().Debug("workerhygiene: is-system-running probe non-ok",
				"error", err)
		}
		latency = c.d.Cfg.Seams.Host.NowFn().Sub(t0).Seconds()
		c.d.SystemdDbusLatencySec = latency
	}
	triggered := len(stale) >= systemdSessionAbandonedMin ||
		latency > systemdDbusSlowSeconds
	if !triggered {
		c.d.State.Exit(hoststate.LatchSystemdSessionBloat, nil)
		c.d.Cycles.WithLabelValues(wdeps.CheckSystemdSessions, "ok").Inc()
		return
	}
	c.d.State.Enter(hoststate.LatchSystemdSessionBloat, fmt.Sprintf(
		"abandoned=%d dbus_latency=%.2fs", len(stale), latency))
	if sd == nil {
		// No host exec wired — evidence + latch only.
		c.d.Cycles.WithLabelValues(wdeps.CheckSystemdSessions, "ok").Inc()
		return
	}
	reaped := 0
	for _, id := range stale {
		if reaped >= systemdSessionMaxTerminate {
			break
		}
		if _, err := sd.Exec(ctx, "loginctl", "terminate-session", id); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: systemd-session-hygiene terminate-session %s failed: %v",
				id, err))
			continue
		}
		reaped++
	}
	if reaped > 0 {
		c.d.State.AppendLog(fmt.Sprintf(
			"ACTION: systemd-session-hygiene terminated %d stale session(s)", reaped))
		c.d.SystemdSessionsReaped += int64(reaped)
		c.d.Actions.WithLabelValues(wdeps.CheckSystemdSessions, "terminate_session").
			Add(float64(reaped))
	}
	if c.d.State.RateTrySpend("last-systemd-reset-failed", systemdResetFailedInterval) {
		if _, err := sd.Exec(ctx, "systemctl", "reset-failed"); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: systemd-session-hygiene reset-failed failed: %v", err))
		} else {
			c.d.Actions.WithLabelValues(wdeps.CheckSystemdSessions, "reset_failed").Inc()
		}
	}
	c.d.Cycles.WithLabelValues(wdeps.CheckSystemdSessions, "ok").Inc()
}
