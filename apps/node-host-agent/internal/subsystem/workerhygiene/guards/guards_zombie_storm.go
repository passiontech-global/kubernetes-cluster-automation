// Check: A2 zombie-process storm detector.
// Split out of dstate_scopes.go (pure move).

package guards

import (
	"context"
	"fmt"
	"strconv"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/checkkit"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// ZombieStormCheck is the A2 storm detector as a Check. streaks
// counts consecutive cycles each parent has produced >
// ZombieStormThreshold defunct children (ex-Hygiene.zombieStreaks).
// Keyed by ZombieParent (pid + stat starttime), NOT raw pid — a
// pid recycled between cycles must not inherit a dead process's
// streak and hold the latch open for a storm that is over.
type ZombieStormCheck struct {
	d       *wdeps.Deps
	streaks map[ZombieParent]int
}

// Name returns the check label / WD_SIG key.
func (c *ZombieStormCheck) Name() string { return wdeps.CheckZombieStorm }

// Run executes one zombie-storm round.
func (c *ZombieStormCheck) Run(_ context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckZombieStorm) {
		return
	}
	byPPID := map[int]int{}
	for _, pid := range e.PidsOnce() {
		st, ok := statFor(e, c.d, pid)
		if !ok || len(st.Fields) < 2 {
			continue
		}
		if st.Fields[0] != "Z" {
			continue
		}
		ppid, err := strconv.Atoi(st.Fields[1])
		if err != nil || ppid < 0 {
			continue
		}
		byPPID[ppid]++
	}
	// Resolve each parent once — the starttime read hits the same
	// StatsOnce snapshot, not a fresh /proc stat.
	parents := map[int]ZombieParent{}
	keyOf := func(ppid int) ZombieParent {
		k, ok := parents[ppid]
		if !ok {
			st, sok := statFor(e, c.d, ppid)
			k = ZombieParent{pid: ppid, start: procStartTime(st, sok)}
			parents[ppid] = k
		}
		return k
	}
	// Loop 1 only PRUNES dead streaks — a stored streak must not set
	// storm here: this cycle's zombie count isn't re-validated yet,
	// so a parent that dropped below threshold would hold the latch
	// one extra cycle. Loop 2 re-validates against the current count
	// before any streak contributes to storm.
	storm := false
	for parent := range c.streaks {
		if _, ok := byPPID[parent.pid]; !ok || keyOf(parent.pid) != parent {
			delete(c.streaks, parent) // parent gone or pid recycled — streak dead
		}
	}
	for ppid, n := range byPPID {
		key := keyOf(ppid)
		if n <= c.d.Cfg.Pressure.ZombieStormThreshold {
			delete(c.streaks, key)
			continue
		}
		c.streaks[key]++
		switch streak := c.streaks[key]; {
		case streak == c.d.Cfg.ConsecNeeded:
			storm = true
			uid := podUIDForPID(c.d, ppid)
			// NPD contract: nodereporter maps this line to the
			// ZombieProcessStorm Event + problem_counter. Logged
			// on streak ENTRY only — repeating it every cycle while
			// the storm persists would spawn a fresh K8s Event per
			// interval (the !stateExists gating wdeps.CheckCiliumMTU
			// uses).
			c.d.State.AppendLog(fmt.Sprintf(
				latchdefs.ActionEntryPrefix(latchdefs.LatchZombieStorm)+
					"pod_uid=%s zombies=%d ppid=%d", uid, n, ppid))
		case streak > c.d.Cfg.ConsecNeeded:
			storm = true // latched storm continues — no repeated ACTION line
		default:
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: zombie-storm ppid=%d zombies=%d%s",
				ppid, n, checkkit.Progress(streak, c.d.Cfg.ConsecNeeded)))
		}
	}
	if storm {
		c.d.State.Enter(latchdefs.LatchZombieStorm, "")
	} else {
		c.d.State.Exit(latchdefs.LatchZombieStorm, nil)
	}
	c.d.CycleResult(wdeps.CheckZombieStorm, "ok")
}
