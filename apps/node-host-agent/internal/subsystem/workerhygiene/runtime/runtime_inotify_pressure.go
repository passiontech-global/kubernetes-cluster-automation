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
	"slices"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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

// inotifyFD is one inotify open file description for a pid.
type inotifyFD struct {
	key     string
	fdNum   int
	watches int64
}

// InotifyPressureCheck is the inotify pressure healer as a Check;
// it owns the tier-2 pending streak (ex-Hygiene.<check>Fails
// pattern — a plain int on the struct).
type InotifyPressureCheck struct {
	d     *wdeps.Deps
	fails int
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
	scan := c.scanInotify(e, instCur, watchCur)
	instRatio := worstUIDRatio(scan.byRUID, instCeilAxis, instCur)
	watchRatio := worstUIDRatio(scan.byRUID, watchAxis, watchCur)
	maxRatio := max(instRatio, watchRatio)

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

// scanInotify walks <ProcRoot>/<pid>/fd once per cycle counting
// anon_inode:inotify descriptors and their fdinfo watch lines —
// there is no global inotify usage counter, so the per-pid fd walk
// is the only evidence source (the unlinked-open-files guard's
// sweep shape). pids come from the cycle's shared PidsOnce when
// wired.
type inotifyRUIDEntry struct {
	pid     int
	fdNum   int
	podUID  string
	watches int64
}

func (c *InotifyPressureCheck) scanInotify(e *wdeps.CycleEnv, instLimit, watchLimit int64) inotifyScan {
	var pids []int
	if e != nil && e.PidsOnce != nil {
		pids = e.PidsOnce()
	} else {
		pids, _ = c.d.Proc.PIDs()
	}
	scan := inotifyScan{
		byRUID:       map[int64]inotifyTotals{},
		byUID:        map[string]inotifyTotals{},
		byRUIDAndUID: map[int64]map[string]inotifyTotals{},
	}
	// When an explicit InotifyFDIno test seam is wired, dedup on its returned
	// OFD key; otherwise keep each (pid, fd) distinct and run kcmp(KCMP_FILE)
	// only inside pressured RUIDs so Linux's shared anon_inode_inode never
	// collapses distinct instances to 1.
	seenExplicitOFD := map[string]bool{}
	rawEntriesByRUID := map[int64][]inotifyRUIDEntry{}

	for _, pid := range pids {
		fds, ok := inotifyProcUsage(c.d, pid)
		if !ok || len(fds) == 0 {
			continue
		}
		ruid, _ := procRealUID(c.d, pid) // -1 bucket on unreadable
		podUID, hasPodUID := wdeps.PodUIDForPID(c.d, pid)

		var u inotifyTotals
		for _, f := range fds {
			if strings.HasPrefix(f.key, "ino:") {
				if seenExplicitOFD[f.key] {
					continue
				}
				seenExplicitOFD[f.key] = true
			} else {
				rawEntriesByRUID[ruid] = append(rawEntriesByRUID[ruid], inotifyRUIDEntry{
					pid:     pid,
					fdNum:   f.fdNum,
					podUID:  podUID,
					watches: f.watches,
				})
			}
			u.instances++
			u.watches += f.watches
		}
		if u.instances == 0 {
			continue
		}
		scan.total.instances += u.instances
		scan.total.watches += u.watches
		a := scan.byRUID[ruid]
		a.instances += u.instances
		a.watches += u.watches
		scan.byRUID[ruid] = a
		if hasPodUID && podUID != "" {
			p := scan.byUID[podUID]
			p.instances += u.instances
			p.watches += u.watches
			scan.byUID[podUID] = p
			if scan.byRUIDAndUID[ruid] == nil {
				scan.byRUIDAndUID[ruid] = map[string]inotifyTotals{}
			}
			rp := scan.byRUIDAndUID[ruid][podUID]
			rp.instances += u.instances
			rp.watches += u.watches
			scan.byRUIDAndUID[ruid][podUID] = rp
		}
	}

	sameOFD := c.d.Cfg.Seams.Host.InotifySameOFDFn
	if sameOFD == nil || c.d.Cfg.Seams.Host.InotifyFDIno != nil {
		return scan
	}
	// Refine only RUIDs near or past the clear threshold using unix.Kcmp(KCMP_FILE).
	for ruid, entries := range rawEntriesByRUID {
		tot := scan.byRUID[ruid]
		if !ruidNeedsKCMP(tot, instLimit, watchLimit) || len(entries) <= 1 {
			continue
		}
		deduped := dedupRUIDEntriesKCMP(entries, sameOFD)
		if len(deduped) == len(entries) {
			continue
		}
		scan.total.instances -= tot.instances
		scan.total.watches -= tot.watches
		var newTot inotifyTotals
		newPodTotals := map[string]inotifyTotals{}
		for _, ent := range deduped {
			newTot.instances++
			newTot.watches += ent.watches
			if ent.podUID != "" {
				pt := newPodTotals[ent.podUID]
				pt.instances++
				pt.watches += ent.watches
				newPodTotals[ent.podUID] = pt
			}
		}
		scan.total.instances += newTot.instances
		scan.total.watches += newTot.watches
		scan.byRUID[ruid] = newTot
		for uid, oldPT := range scan.byRUIDAndUID[ruid] {
			cur := scan.byUID[uid]
			cur.instances -= oldPT.instances
			cur.watches -= oldPT.watches
			if cur.instances <= 0 && cur.watches <= 0 {
				delete(scan.byUID, uid)
			} else {
				scan.byUID[uid] = cur
			}
		}
		scan.byRUIDAndUID[ruid] = newPodTotals
		for uid, pt := range newPodTotals {
			cur := scan.byUID[uid]
			cur.instances += pt.instances
			cur.watches += pt.watches
			scan.byUID[uid] = cur
		}
	}
	return scan
}

func ruidNeedsKCMP(tot inotifyTotals, instLimit, watchLimit int64) bool {
	if instLimit > 0 && float64(tot.instances)/float64(instLimit) > inotifyClearRatio {
		return true
	}
	if watchLimit > 0 && float64(tot.watches)/float64(watchLimit) > inotifyClearRatio {
		return true
	}
	return false
}

const maxKCMPCompareKeepers = 512

func dedupRUIDEntriesKCMP(entries []inotifyRUIDEntry, sameOFD func(int, int, int, int) bool) []inotifyRUIDEntry {
	var kept []inotifyRUIDEntry
	for _, ent := range entries {
		dup := false
		limit := min(len(kept), maxKCMPCompareKeepers)
		for i := range limit {
			k := kept[i]
			if k.pid == ent.pid && k.fdNum == ent.fdNum {
				dup = true
				break
			}
			if sameOFD(k.pid, k.fdNum, ent.pid, ent.fdNum) {
				dup = true
				break
			}
		}
		if !dup {
			kept = append(kept, ent)
		}
	}
	return kept
}

// procRealUID reads the real uid from /proc/<pid>/status — the
// ucounts charging identity for inotify instances/watches.
// ok=false on unreadable/malformed status; callers bucket those
// pids under -1 rather than dropping their usage.
func procRealUID(d *wdeps.Deps, pid int) (int64, bool) {
	data, err := os.ReadFile(d.Proc.File(pid, "status"))
	if err != nil {
		return -1, false
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			return -1, false
		}
		uid, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			return -1, false
		}
		return uid, true
	}
	return -1, false
}

// instCeilAxis/watchAxis pick the pressured field out of one
// per-uid total for worstUIDRatio.
func instCeilAxis(u inotifyTotals) int64 { return u.instances }
func watchAxis(u inotifyTotals) int64    { return u.watches }

// worstUIDRatio returns the maximum usage/limit across every real
// uid — the ucounts-correct pressure signal. A uid with zero
// usage on the axis is skipped; an empty map (no inotify pids at
// all) reads 0.
func worstUIDRatio(byRUID map[int64]inotifyTotals,
	pick func(inotifyTotals) int64, limit int64) float64 {

	var worst float64
	for _, u := range byRUID {
		v := pick(u)
		if v <= 0 || limit <= 0 {
			continue
		}
		if r := float64(v) / float64(limit); r > worst {
			worst = r
		}
	}
	return worst
}

// inotifyProcUsage lists one pid's inotify open file descriptions
// — each entry carries its OFD dedup key (the fd inode via the
// InotifyFDIno seam; a "pidfd:<pid>/<fd>" fallback that never
// dedups when the stat can't resolve, so fork-shared evidence is
// only dropped when the kernel proves the sharing) plus the
// fdinfo watch count. ok=false when the fd dir is unreadable — a
// raced exit or a pid we may not inspect; the caller treats it as
// zero usage, never an error.
func inotifyProcUsage(d *wdeps.Deps, pid int) ([]inotifyFD, bool) {
	var out []inotifyFD
	fdDir := d.Proc.File(pid, "fd")
	fds, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, false
	}
	for _, fd := range fds {
		target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
		if err != nil || target != "anon_inode:inotify" {
			continue
		}
		key := fmt.Sprintf("pidfd:%d/%s", pid, fd.Name())
		if d.Cfg.Seams.Host.InotifyFDIno != nil {
			if ino, ok := d.Cfg.Seams.Host.InotifyFDIno(pid, fd.Name()); ok {
				key = fmt.Sprintf("ino:%d", ino)
			}
		}
		fdNum, _ := strconv.Atoi(fd.Name())
		out = append(out, inotifyFD{
			key:     key,
			fdNum:   fdNum,
			watches: inotifyFDWatches(d.Proc.File(pid, "fdinfo", fd.Name())),
		})
	}
	return out, true
}

// inotifyFDWatches counts the `inotify wd:` watch lines in one
// fdinfo file — one line per watch the descriptor holds.
func inotifyFDWatches(path string) int64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var n int64
	for ln := range strings.SplitSeq(string(data), "\n") {
		if strings.HasPrefix(ln, "inotify wd:") {
			n++
		}
	}
	return n
}

// maybeEvictRunaway deletes the pod dominating the axis that is
// actually exhausted — gated on the evict knob, a conclusive pod
// LIST, the shared eviction rails, the maintenance hold and the
// 15m cooldown. The budget is spent BEFORE the delete (rate_spend
// parity); the delete itself carries the UID precondition so a
// same-name recycle can't be killed by mistake.
//
// Share math is PER-AXIS, never summed: instances (ceiling ~8k) and
// watches (ceiling ~512k) are different units 64x apart, so a pod's
// instances+watches aggregate is meaningless — a pod leaking 8k
// instances would lose the "top pod" race to a healthy pod holding
// 16k watches while the instance ceiling stays pinned. Each
// pressured axis (instPressured/watchPressured — the ones that
// armed the latch) is scored independently: the victim must hold
// >= 50% of the node's usage ON THAT AXIS. When both axes are
// pressured the higher-share candidate wins.
func (c *InotifyPressureCheck) maybeEvictRunaway(ctx context.Context,
	e *wdeps.CycleEnv, scan inotifyScan, instLimit, watchLimit int64,
	instPressured, watchPressured bool) {
	if !c.d.Cfg.Pressure.InotifyEvictRunawayPod {
		return
	}
	if e == nil || !e.APIOK {
		c.d.State.AppendLog(
			"suspect: inotify-pressure-hygiene runaway-pod evict skipped - pod LIST inconclusive")
		return
	}
	if !instPressured && !watchPressured {
		return // latch evidence went stale between arm and evict
	}

	type axisPick struct {
		uid   string
		u     inotifyTotals
		axis  string
		share float64
	}
	var best *axisPick
	consider := func(axis string, pressured bool, limit int64,
		val func(inotifyTotals) int64) {
		if !pressured || limit <= 0 {
			return
		}
		// Pick the pressured RUID with highest usage on this axis, then score
		// only pods belonging to THAT RUID against that RUID's total.
		var worstRUID int64
		var worstRUIDTotal int64
		hasWorst := false
		for ruid, rt := range scan.byRUID {
			v := val(rt)
			if float64(v)/float64(limit) < inotifyLatchRatio {
				continue
			}
			if !hasWorst || v > worstRUIDTotal || (v == worstRUIDTotal && ruid < worstRUID) {
				worstRUID, worstRUIDTotal, hasWorst = ruid, v, true
			}
		}
		if !hasWorst || worstRUIDTotal <= 0 {
			return
		}
		podTotals := scan.byRUIDAndUID[worstRUID]
		uids := make([]string, 0, len(podTotals))
		for uid := range podTotals {
			uids = append(uids, uid)
		}
		slices.Sort(uids)
		var topUID string
		var topVal int64
		for _, uid := range uids {
			if v := val(podTotals[uid]); v > topVal {
				topVal, topUID = v, uid
			}
		}
		if topUID == "" {
			return
		}
		share := float64(topVal) / float64(worstRUIDTotal)
		if share < inotifyEvictShare {
			return
		}
		if best == nil || share > best.share {
			best = &axisPick{uid: topUID, u: podTotals[topUID],
				axis: axis, share: share}
		}
	}
	consider("instances", instPressured, instLimit,
		func(u inotifyTotals) int64 { return u.instances })
	consider("watches", watchPressured, watchLimit,
		func(u inotifyTotals) int64 { return u.watches })
	if best == nil {
		c.d.State.AppendLog(
			"suspect: inotify-pressure-hygiene no pod holds >=50% of a pressured axis - diffuse pressure, no evict")
		return
	}
	pod := e.PodByUID()[best.uid]
	if pod == nil {
		// The cgroup-attributed uid has no live pod object — a
		// terminating/gone pod's stragglers; nothing safe to delete.
		return
	}
	if pod.DeletionTimestamp != nil ||
		wdeps.IsEvictProtectedPod(pod) ||
		wdeps.PodHasPVC(pod) ||
		wdeps.IsMirrorPod(pod) ||
		metav1.GetControllerOf(pod) == nil ||
		wdeps.EvictProtectedNamespaces[pod.Namespace] ||
		wdeps.EvictCriticalPriorityClasses[pod.Spec.PriorityClassName] ||
		wdeps.CarriesDBQuorumLabel(pod) {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: inotify-pressure-hygiene pod %s/%s uid=%s protected by eviction rails - skip",
			pod.Namespace, pod.Name, best.uid))
		return
	}
	// L1↔L3 hold BEFORE the cooldown spend so a drain doesn't burn
	// last-inotify-evict.
	if c.d.HoldLocalAction(ctx) {
		c.d.State.AppendLog(
			"cleanup: inotify-pressure-hygiene evict held - cluster maintenance in progress")
		return
	}
	if !c.d.State.RateTrySpend("last-inotify-evict", inotifyEvictInterval) {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: inotify-pressure-hygiene victim %s/%s holds %.0f%% of %s - in evict cooldown (<15m), skip",
			pod.Namespace, pod.Name, best.share*100, best.axis))
		return
	}
	c.d.StampLocalRemediation(ctx)
	c.d.State.AppendLog(fmt.Sprintf(
		"ACTION: inotify-pressure-hygiene evicted pod %s/%s - holds %d instances + %d watches (%.0f%% of node %s)",
		pod.Namespace, pod.Name, best.u.instances, best.u.watches,
		best.share*100, best.axis))
	if err := c.d.DeletePodGraceful(ctx, pod); err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: inotify-pressure-hygiene evict %s/%s failed: %v",
			pod.Namespace, pod.Name, err))
		return
	}
	c.d.Actions.WithLabelValues(wdeps.CheckInotifyHygiene, "pod_delete").Inc()
}
