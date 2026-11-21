// systemd_oomd.go — Wave-4 #9: systemd-oomd pod/k0s slice kill guard
// (detect-only).
//
// When systemd-oomd.service is active on a worker node, it can kill
// kubepods.slice or k0sworker.service cgroups silently outside kubelet's OOM
// accounting. This guard polls journald for _SYSTEMD_UNIT=systemd-oomd.service
// via journalwatch.Multiplexer, deduplicates observed kills by cursor/timestamp,
// increments node_agent_systemd_oomd_kills_total, and holds LatchSystemdOOMDKill
// for 30m after the most recent kill. Strictly detect-only: never cordons and
// never restarts systemd-oomd or k0sworker.
package guards

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/journalwatch"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

const (
	systemdOOMDUnit       = "systemd-oomd.service"
	systemdOOMDSubID      = "systemd-oomd"
	systemdOOMDWindow     = 30 * time.Minute
	systemdOOMDSuspectGap = 30 * time.Minute
	maxSeenOOMDKills      = 4096
	maxOOMDDetailLen      = 200
)

var (
	reOOMDKillAction = regexp.MustCompile(`(?i)\bkilled\b`)
	reOOMDKubeTarget = regexp.MustCompile(`(?i)(?:kubepods|k0s|cri-containerd-)`)
)

// SystemdOOMDCheck is the Wave-4 #9 systemd-oomd pod/k0s slice kill detector.
type SystemdOOMDCheck struct {
	d           *wdeps.Deps
	mux         *journalwatch.Multiplexer
	seenKills   map[string]time.Time
	lastKillAt  time.Time
	lastKillMsg string
}

func newSystemdOOMD(d *wdeps.Deps) *SystemdOOMDCheck {
	c := &SystemdOOMDCheck{
		d:         d,
		seenKills: map[string]time.Time{},
	}
	// Late-bind JournalExecFn so tests can re-stub d.Cfg.Seams.Host.JournalExecFn
	// after workerhygiene.New (wdepstest.Fixture.Bind pattern).
	mux := journalwatch.New(func(ctx context.Context, args ...string) (string, error) {
		if d.Cfg.Seams.Host.JournalExecFn == nil {
			return "", errors.New("systemd-oomd: no JournalExecFn wired")
		}
		return d.Cfg.Seams.Host.JournalExecFn(ctx, args...)
	})
	mux.Now = c.now
	mux.Lookback = systemdOOMDWindow
	mux.PollEvery = -1
	mux.Args = []string{"_SYSTEMD_UNIT=" + systemdOOMDUnit}
	_ = mux.Subscribe(systemdOOMDSubID, func(e journalwatch.Entry) bool {
		return e.Unit == "" || e.Unit == systemdOOMDUnit
	})
	c.mux = mux
	return c
}

// Name returns the check label / WD_SIG key.
func (c *SystemdOOMDCheck) Name() string { return wdeps.CheckSystemdOOMD }

func (c *SystemdOOMDCheck) now() time.Time {
	if c.d != nil && c.d.Cfg.Seams.Host.Clock != nil {
		return c.d.Cfg.Seams.Host.Clock.Now()
	}
	return time.Now()
}

// Run executes one systemd-oomd journald guard round.
func (c *SystemdOOMDCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckSystemdOOMD) {
		return
	}
	if ctx.Err() != nil {
		c.d.CycleResult(wdeps.CheckSystemdOOMD, "abort")
		return
	}
	if c.d.Cfg.Systemd == nil {
		c.d.CycleResult(wdeps.CheckSystemdOOMD, "gated")
		return
	}
	active, err := c.d.Cfg.Systemd.Active(ctx, systemdOOMDUnit)
	if err != nil {
		if ctx.Err() == nil {
			logger().Warn("workerhygiene: systemd-oomd active check failed", "error", err)
		}
		c.d.CycleResult(wdeps.CheckSystemdOOMD, "abort")
		return
	}
	if !active {
		now := c.now()
		c.lastKillAt = time.Time{}
		c.lastKillMsg = ""
		c.pruneSeenKills(now.Add(-systemdOOMDWindow))
		c.d.State.ExitClearSuspect(latchdefs.LatchSystemdOOMDKill)
		c.d.CycleResult(wdeps.CheckSystemdOOMD, "gated")
		return
	}

	entries, err := c.mux.Poll(ctx, systemdOOMDSubID)
	if err != nil {
		if ctx.Err() == nil {
			c.d.State.SuspectLog(wdeps.CheckSystemdOOMD+"-journal",
				"suspect: systemd-oomd journal poll failed: "+err.Error(),
				systemdOOMDSuspectGap)
		}
		c.d.CycleResult(wdeps.CheckSystemdOOMD, "abort")
		return
	}
	if ctx.Err() != nil {
		c.d.CycleResult(wdeps.CheckSystemdOOMD, "abort")
		return
	}

	now := c.now()
	cutoff := now.Add(-systemdOOMDWindow)
	c.pruneSeenKills(cutoff)

	for _, entry := range entries {
		if !isSystemdOOMDKubeKill(entry.Msg) {
			continue
		}
		ts := now
		if entry.TSUS > 0 {
			ts = time.UnixMicro(entry.TSUS)
		}
		if ts.Before(cutoff) {
			continue
		}
		key := oomdKillKey(entry)
		if _, seen := c.seenKills[key]; seen {
			continue
		}
		c.seenKills[key] = ts
		c.d.Series.SystemdOOMDKills++
		if c.lastKillAt.IsZero() || !ts.Before(c.lastKillAt) {
			c.lastKillAt = ts
			c.lastKillMsg = entry.Msg
		}
	}

	if !c.lastKillAt.IsZero() && !c.lastKillAt.Before(cutoff) {
		detail := formatOOMDDetail(c.lastKillMsg)
		// nodereporter/events_rules.go emits the SystemdOOMDKill Warning Event on
		// STATE-ENTER: systemd-oomd-kill and SystemdOOMDHealthy Normal Event on
		// STATE-EXIT; do not double-emit via EmitCheckEvent here.
		c.d.State.Enter(latchdefs.LatchSystemdOOMDKill, detail)
		c.d.State.SuspectLog(latchdefs.LatchSystemdOOMDKill,
			"suspect: systemd-oomd "+detail, systemdOOMDSuspectGap)
	} else {
		c.lastKillAt = time.Time{}
		c.lastKillMsg = ""
		c.d.State.ExitClearSuspect(latchdefs.LatchSystemdOOMDKill)
	}
	c.d.CycleResult(wdeps.CheckSystemdOOMD, "ok")
}

func (c *SystemdOOMDCheck) pruneSeenKills(cutoff time.Time) {
	for k, ts := range c.seenKills {
		if ts.Before(cutoff) {
			delete(c.seenKills, k)
		}
	}
	for len(c.seenKills) > maxSeenOOMDKills {
		var oldestKey string
		var oldestTS time.Time
		first := true
		for k, ts := range c.seenKills {
			if first || ts.Before(oldestTS) {
				oldestKey = k
				oldestTS = ts
				first = false
			}
		}
		if first {
			break
		}
		delete(c.seenKills, oldestKey)
	}
}

func isSystemdOOMDKubeKill(msg string) bool {
	return reOOMDKillAction.MatchString(msg) && reOOMDKubeTarget.MatchString(msg)
}

func oomdKillKey(e journalwatch.Entry) string {
	if e.Cursor != "" {
		return "cur:" + e.Cursor
	}
	return fmt.Sprintf("ts:%d\x00%s", e.TSUS, e.Msg)
}

func formatOOMDDetail(msg string) string {
	cleaned := strings.Join(strings.Fields(msg), " ")
	if len(cleaned) > maxOOMDDetailLen {
		return cleaned[:maxOOMDDetailLen]
	}
	return cleaned
}
