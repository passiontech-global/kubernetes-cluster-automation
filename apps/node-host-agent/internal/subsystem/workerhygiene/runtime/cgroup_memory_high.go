// cgroup_memory_high.go — Wave-7 cgroup v2 silent memory.high throttling
// detector (wdeps.CheckCgroupMemoryHighThrottle, latchdefs.LatchCgroupMemoryHighThrottle).
//
// Containers throttled by memory.high suffer severe direct-reclaim latency
// (rising memory.events "high" counter + memory.pressure "some avg60") without
// triggering OOMKill (oom_kill delta == 0), leaving pods Running and probes green.
// Unlike node-wide PSI thrash (which sets state-psi-memory-thrash), silent
// memory.high throttling is per-pod cgroup v2 throttling while node PSI stays quiet.
package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/ledger"
)

const (
	memHighSilentPSISomeAvg60 = 15.0
	memHighSuspectCadence     = 30 * time.Minute
)

// CgroupMemoryHighThrottleCheck detects pod cgroups under kubepods.slice
// silently throttled by cgroup v2 memory.high (growing memory.events:high
// without OOMKill, paired with elevated memory.pressure some avg60).
type CgroupMemoryHighThrottleCheck struct {
	d           *wdeps.Deps
	prevHigh    map[string]int64
	prevOOMKill map[string]int64
	streaks     ledger.StreakLedger
}

// NewCgroupMemoryHighThrottle builds the Wave-7 memory.high silent throttle check.
func NewCgroupMemoryHighThrottle(d *wdeps.Deps) *CgroupMemoryHighThrottleCheck {
	return &CgroupMemoryHighThrottleCheck{d: d}
}

// Name returns the check label / WD_SIG key.
func (c *CgroupMemoryHighThrottleCheck) Name() string {
	return wdeps.CheckCgroupMemoryHighThrottle
}

type memHighEvents struct {
	high       int64
	oomKill    int64
	hasHigh    bool
	hasOOMKill bool
}

func readMemHighEvents(path string) (memHighEvents, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return memHighEvents{}, false, err
	}
	var ev memHighEvents
	for line := range strings.SplitSeq(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		v, perr := strconv.ParseInt(f[1], 10, 64)
		if perr != nil {
			continue
		}
		switch f[0] {
		case "high":
			if !ev.hasHigh {
				ev.high, ev.hasHigh = v, true
			}
		case "oom_kill":
			if !ev.hasOOMKill {
				ev.oomKill, ev.hasOOMKill = v, true
			}
		}
	}
	return ev, ev.hasHigh, nil
}

// Run evaluates one cgroup-memory-high-throttle cycle across pod slices.
func (c *CgroupMemoryHighThrottleCheck) Run(_ context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckCgroupMemoryHighThrottle) {
		return
	}
	kubepods := filepath.Join(c.d.Cfg.Runtime.CgroupRoot, "kubepods.slice")
	if _, err := os.Stat(kubepods); err != nil {
		c.d.CycleResult(wdeps.CheckCgroupMemoryHighThrottle, "abort")
		return
	}
	dirs, err := podSliceDirsChecked(kubepods)
	if err != nil {
		c.d.State.SuspectLog(wdeps.CheckCgroupMemoryHighThrottle+"-read",
			fmt.Sprintf("suspect: %s read %s failed: %v — preserving state",
				wdeps.CheckCgroupMemoryHighThrottle, kubepods, err),
			memHighSuspectCadence)
		c.d.CycleResult(wdeps.CheckCgroupMemoryHighThrottle, "abort")
		return
	}

	if c.prevHigh == nil {
		c.prevHigh = map[string]int64{}
	}
	if c.prevOOMKill == nil {
		c.prevOOMKill = map[string]int64{}
	}

	nodeThrashing := c.d.State.Exists(latchdefs.LatchPSIMemoryThrash)
	consecNeeded := max(c.d.Cfg.ConsecNeeded, 2)
	seen := make(map[string]bool, len(dirs))
	var throttledUIDs []string
	anyInconclusive := false

	for _, dir := range dirs {
		ev, evOK, evErr := readMemHighEvents(filepath.Join(dir, "memory.events"))
		if evErr != nil {
			if os.IsNotExist(evErr) {
				continue
			}
			seen[dir] = true
			anyInconclusive = true
			continue
		}
		psi, psiOK := procfs.ParsePSIMemory(filepath.Join(dir, "memory.pressure"))
		if !evOK || !psiOK {
			seen[dir] = true
			anyInconclusive = true
			continue
		}
		seen[dir] = true

		var highDelta, oomDelta int64
		if prev, ok := c.prevHigh[dir]; ok && ev.high >= prev {
			highDelta = ev.high - prev
		}
		c.prevHigh[dir] = ev.high

		if ev.hasOOMKill {
			if prev, ok := c.prevOOMKill[dir]; ok && ev.oomKill >= prev {
				oomDelta = ev.oomKill - prev
			}
			c.prevOOMKill[dir] = ev.oomKill
		}

		silentThrottle := !nodeThrashing &&
			highDelta > 0 &&
			oomDelta == 0 &&
			psi.HasSome &&
			psi.SomeAvg60 >= memHighSilentPSISomeAvg60

		if silentThrottle {
			if c.streaks.Hit(dir) >= consecNeeded {
				throttledUIDs = append(throttledUIDs, podUIDFromSlice(dir))
			}
		} else {
			c.streaks.Reset(dir)
		}
	}

	for dir := range c.prevHigh {
		if !seen[dir] {
			delete(c.prevHigh, dir)
		}
	}
	for dir := range c.prevOOMKill {
		if !seen[dir] {
			delete(c.prevOOMKill, dir)
		}
	}
	c.streaks.Prune(func(k string) bool { return seen[k] })

	if c.d.CgroupMemoryHighThrottledPods != nil {
		c.d.CgroupMemoryHighThrottledPods.Set(float64(len(throttledUIDs)))
	}

	if len(throttledUIDs) > 0 {
		detail := fmt.Sprintf("pods=%s some_avg60>=%.0f%%", strings.Join(throttledUIDs, ","), memHighSilentPSISomeAvg60)
		wasLatched := c.d.State.Exists(latchdefs.LatchCgroupMemoryHighThrottle)
		c.d.State.Enter(latchdefs.LatchCgroupMemoryHighThrottle, detail)
		if !wasLatched {
			c.d.State.AppendLog(fmt.Sprintf(
				"ACTION: %s detected %d silently throttled pod(s) (%s)",
				wdeps.CheckCgroupMemoryHighThrottle, len(throttledUIDs), detail))
			c.d.Actions.WithLabelValues(wdeps.CheckCgroupMemoryHighThrottle, "detect").Inc()
		}
		c.d.State.SuspectLog(latchdefs.LatchCgroupMemoryHighThrottle,
			fmt.Sprintf("suspect: %s %s", wdeps.CheckCgroupMemoryHighThrottle, detail),
			memHighSuspectCadence)
	} else if !anyInconclusive {
		c.d.State.ExitClearSuspect(latchdefs.LatchCgroupMemoryHighThrottle)
	}

	if anyInconclusive && len(throttledUIDs) == 0 {
		c.d.CycleResult(wdeps.CheckCgroupMemoryHighThrottle, "abort")
		return
	}
	c.d.CycleResult(wdeps.CheckCgroupMemoryHighThrottle, "ok")
}
