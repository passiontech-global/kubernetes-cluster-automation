// runtime_inotify_pressure.go — the inotify-pressure-hygiene check
// (wdeps.CheckInotifyHygiene): the two-tier self-heal for
// fs/inotify exhaustion — the classic "failed to create fsnotify
// watcher" / EMFILE node wedge where a runaway pod's watch leak
// pins max_user_instances / max_user_watches and every new watcher
// on the node (kubelet sync, log shippers, ingress) starts failing.
//
// Tier 1 — auto-bump (usage >= 85% of either sysctl): on a 30m
// budget (last-inotify-bump) the check doubles
// /proc/sys/fs/inotify/max_user_instances and max_user_watches
// toward their ceilings — instances hard-capped at
// Pressure.InotifyMaxInstancesCeiling (8192), watches at
// min(Pressure.InotifyMaxWatchesCeiling (524288), the ~1KiB/watch
// RAM budget = 2% of MemTotal).
//
// Tier 2 — latch + evict (>= 95% AND the binding sysctl already at
// its ceiling, so bumping can no longer help): two consecutive
// cycles (checkkit.Pending via ConsecNeeded) arm
// state-inotify-pressure (NodeCondition InotifyPressure), released
// only when both ratios fall to <= 80%. While latched the check
// attributes inotify descriptors to pods through
// /proc/<pid>/cgroup and — when Pressure.InotifyEvictRunawayPod
// is on — evicts the single pod holding >= 50% of the node's
// inotify footprint, behind the shared eviction rails
// (EvictProtectedNamespaces, EvictCriticalPriorityClasses,
// CarriesDBQuorumLabel, DeletionTimestamp), the maintenance hold
// and a 15m last-inotify-evict cooldown, deleted with a UID
// precondition + LocalRemediation stamp.
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
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

const (
	// inotifyBumpRatio arms the tier-1 sysctl raise.
	inotifyBumpRatio = 0.85
	// inotifyLatchRatio is the tier-2 pressure level — only counts
	// once the binding sysctl sits at its ceiling.
	inotifyLatchRatio = 0.95
	// inotifyClearRatio releases the latch (hysteresis vs the 0.95
	// arm — a borderline ratio must not flap the condition).
	inotifyClearRatio = 0.80
	// inotifyBumpInterval rate-limits sysctl writes — each bump
	// doubles, so 30m between raises still converges fast while a
	// stuck-high usage can't write-loop the sysctls.
	inotifyBumpInterval = 30 * time.Minute
	// inotifyEvictInterval is the last-inotify-evict cooldown.
	inotifyEvictInterval = 15 * time.Minute
	// inotifyWatchBytes is the ~1KiB of unreclaimable kernel memory
	// one inotify watch pins (fsnotify mark + inode reference).
	inotifyWatchBytes = 1024
	// inotifyMemBudgetPct caps aggregate watches at this fraction
	// of MemTotal — beyond it the watches themselves become a
	// memory-pressure source.
	inotifyMemBudgetPct = 0.02
	// inotifyEvictShare is the runaway-pod threshold — one pod must
	// hold at least half the node's inotify footprint (instances +
	// watches) to be evictable; below it the pressure is diffuse
	// and no single delete buys the headroom back.
	inotifyEvictShare = 0.50
	// inotifyFDTTL matches hostmetrics' shared /proc/*/fd snapshot TTL.
	inotifyFDTTL = 60 * time.Second
)

// inotifyTotals is one scope's inotify footprint: instances =
// anon_inode:inotify descriptors held, watches = inotify wd: lines
// across their fdinfo files.
type inotifyTotals struct {
	instances int64
	watches   int64
}

// inotifyScan is one cycle's usage sweep: node totals, the
// per-real-UID aggregate the ucounts-correct ratios compare
// against (max_user_instances/watches are PER-UID budgets — a
// node-wide total vs a per-uid limit false-positives on any
// multi-uid fleet), and the per-pod-UID aggregate (only pids whose
// cgroup resolves to a pod land in byUID — host processes count
// toward the totals but are never eviction candidates). pids whose
// real uid is unreadable share the -1 bucket — merging unknowns
// keeps the degenerate all-unreadable case at the old
// node-wide behavior instead of going blind.
type inotifyScan struct {
	total        inotifyTotals
	byRUID       map[int64]inotifyTotals
	byUID        map[string]inotifyTotals
	byRUIDAndUID map[int64]map[string]inotifyTotals
}

// InotifyPressureCheck is the inotify pressure healer as a Check;
// it owns the tier-2 pending streak (ex-Hygiene.<check>Fails
// pattern — a plain int on the struct).
type InotifyPressureCheck struct {
	d     *wdeps.Deps
	fails int
	// lastScanAborted and lastAbortAt force direct ScanFDs(pids) across the
	// entire inotifyFDTTL (60s) window after any abort, and while building a
	// pre-arm streak (fails > 0), so a transient EACCES/ENOTDIR snapshot
	// cached in SharedFDCache cannot poison streak-building or recovery.
	lastScanAborted bool
	lastAbortAt     time.Time
	// instFrozen/watchFrozen mark a sysctl the agent provably
	// cannot raise (EROFS/EPERM write failure) — the current
	// value IS the effective ceiling, so tier-2 must not wait
	// forever for cur to reach the configured cap it can never
	// hit. Cleared by the next successful bump.
	instFrozen  bool
	watchFrozen bool
}

// Name returns the check label / WD_SIG key.
func (c *InotifyPressureCheck) Name() string { return wdeps.CheckInotifyHygiene }

// Run executes one inotify-pressure-hygiene round.
func (c *InotifyPressureCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckInotifyHygiene) {
		return
	}
	instCur, watchCur, ok := c.readSysctls()
	if !ok {
		c.d.CycleResult(wdeps.CheckInotifyHygiene, "abort")
		return
	}
	now := time.Now()
	if c.d.Cfg.Seams.Host.Clock != nil {
		now = c.d.Cfg.Seams.Host.Clock.Now()
	}
	abortActive := !c.lastAbortAt.IsZero() &&
		now.Sub(c.lastAbortAt) >= 0 && now.Sub(c.lastAbortAt) < inotifyFDTTL
	latched := c.d.State.Exists(latchdefs.LatchInotifyPressure)
	forceDirect := c.lastScanAborted || abortActive || (c.fails > 0 && !latched)
	scan, usedCache, scanOK := c.scanInotify(e, instCur, watchCur, forceDirect)
	if !scanOK {
		c.lastScanAborted = true
		c.lastAbortAt = now
		c.d.CycleResult(wdeps.CheckInotifyHygiene, "abort")
		return
	}
	instRatio := worstUIDRatio(scan.byRUID, instCeilAxis, instCur)
	watchRatio := worstUIDRatio(scan.byRUID, watchAxis, watchCur)
	maxRatio := max(instRatio, watchRatio)

	// Before releasing or downgrading an armed LatchInotifyPressure from a
	// cached SharedFDCache snapshot, verify with a direct ScanFDs(pids) walk
	// so a snapshot populated by hostmetrics during transient EACCES cannot
	// falsely clear the latch or hide pressure within inotifyFDTTL (60s).
	if maxRatio < inotifyLatchRatio && usedCache && latched {
		scan, _, scanOK = c.scanInotify(e, instCur, watchCur, true)
		if !scanOK {
			c.lastScanAborted = true
			c.lastAbortAt = now
			c.d.CycleResult(wdeps.CheckInotifyHygiene, "abort")
			return
		}
		instRatio = worstUIDRatio(scan.byRUID, instCeilAxis, instCur)
		watchRatio = worstUIDRatio(scan.byRUID, watchAxis, watchCur)
		maxRatio = max(instRatio, watchRatio)
	}
	c.lastScanAborted = false

	if maxRatio <= inotifyClearRatio {
		c.fails = 0
		c.d.State.Exit(latchdefs.LatchInotifyPressure, nil)
		c.d.CycleResult(wdeps.CheckInotifyHygiene, "ok")
		return
	}

	// Tier 1 — raise the sysctls while either ratio is past the
	// bump line and its ceiling still has headroom.
	c.maybeBumpSysctls(instCur, watchCur, instRatio, watchRatio)

	// Tier 2 — the latch only arms once the pressured resource can
	// no longer be raised: its current sysctl value already sits at
	// the effective ceiling. Each axis is tracked separately —
	// instances (ceiling ~8k) and watches (ceiling ~512k) are
	// different units 64x apart, so "which axis is binding" must be
	// known for the runaway-pod share math below.
	instCeil := c.d.Cfg.Pressure.InotifyMaxInstancesCeiling
	watchCeil := c.watchCeiling()
	// frozen axes count as at-ceiling — a sysctl the agent cannot
	// write (EROFS/EPERM) will never reach the configured cap, so
	// waiting for cur >= ceil would pin the latch false forever.
	instPressured := instRatio >= inotifyLatchRatio &&
		(instCur >= instCeil || c.instFrozen)
	watchPressured := watchRatio >= inotifyLatchRatio &&
		(watchCur >= watchCeil || c.watchFrozen)
	if !instPressured && !watchPressured {
		c.fails = 0
		c.d.CycleResult(wdeps.CheckInotifyHygiene, "ok")
		return
	}
	if c.d.StreakPending(&c.fails, fmt.Sprintf(
		"suspect: inotify-pressure-hygiene instances=%d/%d (%.0f%%) watches=%d/%d (%.0f%%) at sysctl ceiling",
		scan.total.instances, instCur, instRatio*100,
		scan.total.watches, watchCur, watchRatio*100)) {
		c.d.CycleResult(wdeps.CheckInotifyHygiene, "ok")
		return
	}
	if c.d.State.EnterFresh(latchdefs.LatchInotifyPressure, fmt.Sprintf(
		"instances=%d/%d watches=%d/%d",
		scan.total.instances, instCur, scan.total.watches, watchCur)) {
		// NPD contract: nodereporter maps this ACTION line to the
		// InotifyPressure NodeCondition event.
		c.d.State.AppendLog(latchdefs.ActionEntryPrefix(
			latchdefs.LatchInotifyPressure) + fmt.Sprintf(
			"instances=%d/%d watches=%d/%d fails=%d",
			scan.total.instances, instCur, scan.total.watches, watchCur, c.fails))
	}
	c.maybeEvictRunaway(ctx, e, scan, instCur, watchCur, instPressured, watchPressured)
	c.d.CycleResult(wdeps.CheckInotifyHygiene, "ok")
}

// readSysctls returns the current fs/inotify sysctl values —
// ok=false when either is unreadable or non-positive (inconclusive,
// never a 0-denominator ratio).
func (c *InotifyPressureCheck) readSysctls() (inst, watches int64, ok bool) {
	base := filepath.Join(c.d.Cfg.ProcRoot, "sys", "fs", "inotify")
	inst, ok1 := readInotifySysctl(filepath.Join(base, "max_user_instances"))
	watches, ok2 := readInotifySysctl(filepath.Join(base, "max_user_watches"))
	return inst, watches, ok1 && ok2 && inst > 0 && watches > 0
}

func readInotifySysctl(path string) (int64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

// memTotalBytes reads MemTotal from <ProcRoot>/meminfo in bytes —
// 0 when unreadable (the watches RAM budget then falls back to the
// configured ceiling alone; documented on watchCeiling).
func (c *InotifyPressureCheck) memTotalBytes() int64 {
	data, err := os.ReadFile(filepath.Join(c.d.Cfg.ProcRoot, "meminfo"))
	if err != nil {
		return 0
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "MemTotal:" {
			kb, err := strconv.ParseInt(f[1], 10, 64)
			if err != nil {
				return 0
			}
			return kb * 1024
		}
	}
	return 0
}

// watchCeiling is the effective max_user_watches ceiling: the
// configured cap narrowed by the ~1KiB/watch RAM budget (2% of
// MemTotal). An unreadable meminfo drops only the RAM term — the
// configured ceiling still bounds the bump.
func (c *InotifyPressureCheck) watchCeiling() int64 {
	ceil := c.d.Cfg.Pressure.InotifyMaxWatchesCeiling
	if total := c.memTotalBytes(); total > 0 {
		if budget := int64(float64(total) * inotifyMemBudgetPct / inotifyWatchBytes); budget < ceil {
			ceil = budget
		}
	}
	return ceil
}

// maybeBumpSysctls doubles whichever pressured sysctl still has
// ceiling headroom — one last-inotify-bump spend covers both writes
// per cycle.
func (c *InotifyPressureCheck) maybeBumpSysctls(instCur, watchCur int64,
	instRatio, watchRatio float64) {
	instCeil := c.d.Cfg.Pressure.InotifyMaxInstancesCeiling
	watchCeil := c.watchCeiling()
	needInst := instRatio >= inotifyBumpRatio && instCur < instCeil
	needWatch := watchRatio >= inotifyBumpRatio && watchCur < watchCeil
	if !needInst && !needWatch {
		return
	}
	if !c.d.State.RateTrySpend("last-inotify-bump", inotifyBumpInterval) {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: inotify-pressure-hygiene sysctl bump needed (instances=%d watches=%d) - in 30m cooldown, skip",
			instCur, watchCur))
		return
	}
	if needInst {
		c.instFrozen = !c.bumpSysctl("max_user_instances", instCur, instCeil)
	}
	if needWatch {
		c.watchFrozen = !c.bumpSysctl("max_user_watches", watchCur, watchCeil)
	}
}

// bumpSysctl writes min(cur*2, ceil) to one fs/inotify sysctl —
// the doubling keeps convergence fast while the ceiling keeps the
// kernel-side footprint bounded. Returns false when the write
// failed: the current value is then the EFFECTIVE ceiling (a
// read-only /proc/sys can never be raised), which the tier-2 gate
// honors via the frozen flags.
func (c *InotifyPressureCheck) bumpSysctl(name string, cur, ceil int64) bool {
	next := cur * 2
	if next > ceil {
		next = ceil
	}
	if next <= cur {
		return true // already at the cap — nothing to freeze
	}
	p := filepath.Join(c.d.Cfg.ProcRoot, "sys", "fs", "inotify", name)
	if err := os.WriteFile(p, []byte(strconv.FormatInt(next, 10)+"\n"), 0o644); err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: inotify-pressure-hygiene write %s=%d failed: %v", p, next, err))
		return false
	}
	c.d.State.AppendLog(fmt.Sprintf(
		"ACTION: inotify-pressure-hygiene raised %s %d -> %d", name, cur, next))
	c.d.Actions.WithLabelValues(wdeps.CheckInotifyHygiene, "sysctl_write").Inc()
	return true
}
