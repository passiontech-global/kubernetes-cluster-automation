package guards

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/kubeutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

const (
	psiEvictInterval = 15 * time.Minute // last-psi-evict budget
	// Slab-leak guard thresholds (SUnreclaim/MemTotal
	// enter/clear hysteresis + the drop_caches budget).
	slabLeakEnterRatio     = 0.35
	slabLeakClearRatio     = 0.25
	slabDropCachesInterval = time.Hour
	// selfheal-alert-coverage negative-dentry reclaim thresholds: /proc/sys/fs/dentry-state
	// nr_unused above 1.5M with >3GiB of reclaimable slab and memory
	// already under 15% available means the kernel is about to PSI-
	// thrash on dentries it could have dropped — drop_caches=2 hands
	// them back BEFORE the thrash latch arms. The 30m budget keeps a
	// permanently dentry-heavy node from write-looping the sysctl.
	dentryUnusedMin     = 1_500_000
	dentryReclaimMinKB  = 3 * 1024 * 1024 // 3 GiB of SReclaimable
	dentryMemAvailRatio = 0.15
	dentryDropInterval  = 30 * time.Minute
)

// psiMemoryFullAvg60 parses <ProcRoot>/pressure/memory — the
// `full avg60=` value of the memory pressure stall (percent). PSI
// files look like:
//
//	some avg10=1.23 avg60=4.56 avg300=0.78 total=12345
//	full avg10=0.89 avg60=26.10 avg300=0.54 total=6789
//
// ok=false when the file is unreadable or carries no full avg60
// (PSI disabled on this kernel — the whole check is then dormant).
func psiMemoryFullAvg60(d *wdeps.Deps) (float64, bool) {
	avg60, _, ok := procfs.ParsePSIFull(filepath.Join(d.Cfg.ProcRoot, "pressure", "memory"))
	return avg60, ok
}

// memInfo holds the <ProcRoot>/meminfo fields the memory checks
// consume — all values in kB as reported by the kernel.
type memInfo struct {
	totalKB      int64
	availKB      int64
	slabUnrecKB  int64 // SUnreclaim — slab the kernel cannot reclaim
	slabRecKB    int64 // SReclaimable — dentries/inodes the kernel CAN reclaim (selfheal-alert-coverage)
	pageTablesKB int64 // PageTables + SecPageTables (pagetables-memory-guard)
	parsed       bool  // at least MemTotal + MemAvailable seen
}

// readMeminfo parses <ProcRoot>/meminfo once for every consumer —
// MemTotal/MemAvailable drive the free-ratio floor, SUnreclaim the
// kernel-slab-leak slab-leak guard. ok=false semantics live on the callers:
// a missing MemTotal or MemAvailable means "unreadable".
func readMeminfo(d *wdeps.Deps) memInfo {
	var m memInfo
	data, err := os.ReadFile(filepath.Join(d.Cfg.ProcRoot, "meminfo"))
	if err != nil {
		return m
	}
	var total, avail, slab, slabRec, pageTables int64
	var sawTotal, sawAvail bool
	for line := range strings.SplitSeq(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			total, sawTotal = v, true
		case "MemAvailable:":
			avail, sawAvail = v, true
		case "SUnreclaim:":
			slab = v
		case "SReclaimable:":
			slabRec = v
		case "PageTables:", "SecPageTables:":
			// pagetables-memory-guard: page-table memory is kernel memory outside
			// SUnreclaim — a leaking/mapping-heavy workload grows it
			// invisibly to the slab ratio.
			pageTables += v
		}
	}
	if !sawTotal || !sawAvail || total <= 0 {
		return m
	}
	m.totalKB, m.availKB, m.slabUnrecKB, m.slabRecKB, m.pageTablesKB, m.parsed =
		total, avail, slab, slabRec, pageTables, true
	return m
}

// guardKernelSlabLeak is the kernel-slab-leak kernel slab-leak guard: while
// SUnreclaim/MemTotal sits above slabLeakEnterRatio the
// state-kernel-slab-leak latch is held and a 1h-budgeted
// drop_caches write ("2" — dentries+inodes) tries to hand the
// reclaimable share back. The latch is the PSI evictor's circuit
// breaker — a kernel leaking unreclaimable slab is a kernel bug,
// not a pod-size problem, and evicting workloads cannot fix it.
// Hysteresis: enter >0.35, clear <=0.25; between the two the latch
// (and its drop-caches cadence) simply persists. Returns true while
// the latch is held.
func guardKernelSlabLeak(d *wdeps.Deps, m memInfo) bool {
	// pagetables-memory-guard: PageTables/SecPageTables count toward the kernel-memory
	// numerator — they are unreclaimable-by-drop_caches kernel memory
	// like SUnreclaim, and a pagetable leak must trip the same latch.
	kernelKB := m.slabUnrecKB + m.pageTablesKB
	ratio := float64(kernelKB) / float64(m.totalKB)
	latched := d.State.Exists(latchdefs.LatchKernelSlabLeak)
	switch {
	case ratio > slabLeakEnterRatio:
		latched = true
	case ratio <= slabLeakClearRatio:
		if latched {
			d.State.Exit(latchdefs.LatchKernelSlabLeak, nil)
		}
		latched = false
	}
	if !latched {
		return false
	}
	// EnterFresh refreshes the latch mtime every cycle it is held —
	// the janitor's 24h reap must not retire a live condition.
	if d.State.EnterFresh(latchdefs.LatchKernelSlabLeak,
		fmt.Sprintf("sunreclaim_ratio=%.3f", ratio)) {
		// NPD contract parity: the ACTION line announces the
		// latch entry (nodereporter maps STATE-ENTER too).
		d.State.AppendLog(fmt.Sprintf(
			latchdefs.ActionEntryPrefix(latchdefs.LatchKernelSlabLeak)+
				"sunreclaim_ratio=%.3f sunreclaim_kb=%d memtotal_kb=%d",
			ratio, m.slabUnrecKB, m.totalKB))
	}
	if d.State.RateTrySpend("last-slab-drop-caches", slabDropCachesInterval) {
		dropKernelCaches(d)
	}
	return true
}

// dropKernelCaches writes "2" to <ProcRoot>/sys/vm/drop_caches —
// frees dentries/inodes/slab caches. Best-effort: a write failure
// is logged suspect and never counted as an action — the budget
// marker is already spent either way (rate_spend parity).
func dropKernelCaches(d *wdeps.Deps) {
	p := filepath.Join(d.Cfg.ProcRoot, "sys", "vm", "drop_caches")
	if err := os.WriteFile(p, []byte("2\n"), 0o644); err != nil {
		d.State.AppendLog(fmt.Sprintf(
			"suspect: kernel-slab-leak drop_caches write %s failed: %v",
			p, err))
		return
	}
	d.State.AppendLog("ACTION: kernel-slab-leak wrote 2 to sys/vm/drop_caches")
	d.Actions.WithLabelValues(wdeps.CheckPSIThrash, "drop_caches").Inc()
}

// dentryStateUnused reads <ProcRoot>/sys/fs/dentry-state field 2
// (nr_unused — dentries the kernel has already unlinked but not yet
// reclaimed). The file carries six counters
// (nr_dentry nr_unused age_limit want_pages nr_negative
// nr_unused_negative); a short/unparseable read reports -1 so the
// caller can tell "no data" from "zero unused".
func dentryStateUnused(d *wdeps.Deps) int64 {
	data, err := os.ReadFile(filepath.Join(
		d.Cfg.ProcRoot, "sys", "fs", "dentry-state"))
	if err != nil {
		return -1
	}
	f := strings.Fields(string(data))
	if len(f) < 2 {
		return -1
	}
	n, err := strconv.ParseInt(f[1], 10, 64)
	if err != nil {
		return -1
	}
	return n
}

// guardNegativeDentry is the selfheal-alert-coverage negative-dentry SLAB reclaim: churn
// workloads (build pods, log shippers, volume mounts) leave millions
// of unlinked dentries/inodes sitting in reclaimable slab. While
// nr_unused is past dentryUnusedMin AND the kernel still holds
// >3GiB of SReclaimable AND MemAvailable already sits under 15% of
// MemTotal, the node is one allocation burst away from PSI thrash
// the slab could have prevented — drop_caches=2 frees dentries and
// inodes (NOT pagecache, so no re-read storm) on a 30m budget.
//
// The gauge (node_agent_dentry_unused_count) publishes EVERY
// readable cycle — the alert watches the pressure even when the
// reclaim gate stays shut. A missing dentry-state (non-Linux test
// host, odd kernel) leaves the last value, never a fake 0.
func guardNegativeDentry(d *wdeps.Deps, m memInfo) {
	n := dentryStateUnused(d)
	if n < 0 {
		return
	}
	d.Series.DentryUnusedCount = n
	availRatio := float64(m.availKB) / float64(m.totalKB)
	if n <= dentryUnusedMin ||
		m.slabRecKB <= dentryReclaimMinKB ||
		availRatio >= dentryMemAvailRatio {
		return
	}
	if !d.State.RateTrySpend("last-dentry-drop-caches", dentryDropInterval) {
		return
	}
	p := filepath.Join(d.Cfg.ProcRoot, "sys", "vm", "drop_caches")
	if err := os.WriteFile(p, []byte("2\n"), 0o644); err != nil {
		d.State.AppendLog(fmt.Sprintf(
			"suspect: negative-dentry drop_caches write %s failed: %v",
			p, err))
		return
	}
	d.State.AppendLog(fmt.Sprintf(
		"ACTION: negative-dentry wrote 2 to sys/vm/drop_caches — nr_unused=%d sreclaimable_kb=%d memavail_ratio=%.3f",
		n, m.slabRecKB, availRatio))
	d.Actions.WithLabelValues(wdeps.CheckPSIThrash, "dentry_drop_caches").Inc()
}

// podCgroupRel returns the pod's cgroup-v2 path relative to
// CgroupRoot — the /proc/<pid>/cgroup `0::` line walked up to and
// including the pod<uid> component (kubepods-*.slice naming embeds
// the uid with underscores). memory.current on THAT cgroup is the
// pod's real footprint: it counts every container plus pod
// overhead exactly once, where summing /proc VmRSS per pid
// double-counts CoW-shared pages. "" when the line or component is
// absent (v1 hierarchy, non-pod cgroup).
func podCgroupRel(d *wdeps.Deps, pid int, uid string) string {
	data, err := os.ReadFile(d.Proc.File(pid, "cgroup"))
	if err != nil {
		return ""
	}
	want := "pod" + strings.ReplaceAll(uid, "-", "_")
	for line := range strings.SplitSeq(string(data), "\n") {
		if !strings.HasPrefix(line, "0::") {
			continue
		}
		rel := strings.TrimPrefix(strings.TrimSpace(strings.TrimPrefix(line, "0::")), "/")
		parts := strings.Split(rel, "/")
		for i, p := range parts {
			if strings.Contains(p, want) {
				return strings.Join(parts[:i+1], "/")
			}
		}
	}
	return ""
}

// podMemoryCurrent reads the pod cgroup's memory.current — the
// kernel-accounted byte total for the whole pod, immune to the CoW
// double-counting a VmRSS sum suffers. 0 when the cgroup file is
// unreadable or unparsable — callers treat 0 as "below the floor",
// never evicting on inconclusive memory evidence.
func podMemoryCurrent(d *wdeps.Deps, rel string) int64 {
	if rel == "" {
		return 0
	}
	data, err := os.ReadFile(filepath.Join(d.Cfg.Runtime.CgroupRoot, rel, "memory.current"))
	if err != nil {
		return 0
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// PSIThrashCheck is the psi-memory-thrash memory-thrash evictor as a Check; it
// owns the thrash streak (ex-Hygiene.psiThrashFails).
type PSIThrashCheck struct {
	d     *wdeps.Deps
	fails int
}

// Name returns the check label / WD_SIG key.
func (c *PSIThrashCheck) Name() string { return wdeps.CheckPSIThrash }

// Run executes one psi-memory-thrash round.
func (c *PSIThrashCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckPSIThrash) {
		return
	}
	avg60, psiOK := psiMemoryFullAvg60(c.d)
	m := readMeminfo(c.d)
	if !m.parsed {
		// meminfo unreadable — inconclusive, keep streak/latch
		// exactly like a failed probe (a transient read error must
		// not clear a live latch).
		c.d.CycleResult(wdeps.CheckPSIThrash, "abort")
		return
	}
	// pagetables-memory-guard: publish the page-table footprint for
	// node_agent_pagetables_bytes — set before the PSI early-outs so
	// the series stays live on PSI-less kernels too.
	c.d.PageTablesBytes = m.pageTablesKB * 1024
	// kernel-slab-leak: the slab-leak guard runs on EVERY readable-meminfo
	// cycle — its latch is this check's eviction circuit breaker,
	// and it must arm even on kernels without PSI or while PSI is
	// quiet (a kernel slab leak is a kernel problem, not a PSI one).
	slabLeaking := guardKernelSlabLeak(c.d, m)
	// selfheal-alert-coverage: the negative-dentry reclaim rides the same readable-
	// meminfo gate — it needs SReclaimable + MemAvailable, and a
	// kernel without PSI still has dentries worth dropping.
	guardNegativeDentry(c.d, m)
	if !psiOK {
		// PSI disabled on this kernel — the whole thrash check is
		// dormant, but the slab guard above still evaluated.
		c.d.CycleResult(wdeps.CheckPSIThrash, "abort")
		return
	}
	free := float64(m.availKB) / float64(m.totalKB)
	thrash := avg60 > c.d.Cfg.Pressure.PSIFullAvg60 && free < c.d.Cfg.Pressure.MemFreeMinRatio
	if !thrash {
		c.fails = 0
		c.d.State.Exit(latchdefs.LatchPSIMemoryThrash, nil)
		c.d.CycleResult(wdeps.CheckPSIThrash, "ok")
		return
	}
	if c.d.StreakPending(&c.fails, fmt.Sprintf(
		"suspect: psi-memory-thrash psi_full_avg60=%.1f mem_free=%.3f",
		avg60, free)) {
		c.d.CycleResult(wdeps.CheckPSIThrash, "ok")
		return
	}
	if c.d.State.EnterFresh(latchdefs.LatchPSIMemoryThrash,
		fmt.Sprintf("psi_full_avg60=%.1f mem_free=%.3f", avg60, free)) {
		// NPD contract: nodereporter maps this line to the
		// NodeMemoryPSIThrashing Event + problem_counter — logged
		// once per latch entry (wdeps.CheckCiliumMTU parity).
		c.d.State.AppendLog(fmt.Sprintf(
			latchdefs.ActionEntryPrefix(latchdefs.LatchPSIMemoryThrash)+
				"psi_full_avg60=%.1f mem_free=%.3f fails=%d",
			avg60, free, c.fails))
	}
	if !e.APIOK {
		c.d.State.AppendLog("suspect: psi-memory-thrash but API unreachable — skip pod evict")
		c.d.CycleResult(wdeps.CheckPSIThrash, "ok")
		return
	}
	if slabLeaking {
		// The kernel is leaking unreclaimable slab — evicting a
		// pod cannot fix that and would only remove capacity the
		// node needs to recover. drop_caches owns the reclaim;
		// the latch stays so the condition remains visible.
		c.d.State.AppendLog("suspect: psi-memory-thrash pod evict suppressed - kernel-slab-leak latched")
		c.d.CycleResult(wdeps.CheckPSIThrash, "ok")
		return
	}
	victim, mem := highestRSSPod(c.d, e.Pods, e.PidsOnce())
	if victim == nil {
		// No eligible victim above the memory floor — latch only;
		// the kernel OOM verdict then stands (nothing ours worth
		// giving it).
		c.d.CycleResult(wdeps.CheckPSIThrash, "ok")
		return
	}
	// L1↔L3 hold: check maintenance BEFORE spending the cooldown
	// budget so a drain does not burn last-psi-evict.
	if c.d.HoldLocalAction(ctx) {
		c.d.State.AppendLog("cleanup: psi-memory-thrash evict held — " +
			"cluster maintenance in progress")
		c.d.CycleResult(wdeps.CheckPSIThrash, "ok")
		return
	}
	if !c.d.State.RateTrySpend("last-psi-evict", psiEvictInterval) {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: psi-memory-thrash victim %s/%s mem=%d - in evict cooldown (<15m), skip",
			victim.Namespace, victim.Name, mem))
		c.d.CycleResult(wdeps.CheckPSIThrash, "ok")
		return
	}
	// Budget spent atomically BEFORE the eviction (rate_spend
	// parity). policy/v1 Eviction — NOT a raw pod delete: the
	// apiserver enforces the victim's PodDisruptionBudget
	// atomically, so a PDB-protected pod is refused instead of
	// silently disrupted. The UID precondition closes the
	// listing→evict race: a same-name pod is a different object and
	// the apiserver refuses (kubeutil.EvictPodV1).
	ev := kubeutil.EvictPodV1(victim)
	c.d.State.AppendLog(fmt.Sprintf(
		"ACTION: psi-memory-thrash evicted pod %s/%s - mem=%d bytes, psi_full_avg60=%.1f mem_free=%.3f",
		victim.Namespace, victim.Name, mem, avg60, free))
	if err := c.d.Cfg.Client.PolicyV1().Evictions(victim.Namespace).
		Evict(ctx, ev); err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: psi-memory-thrash evict %s/%s failed: %v",
			victim.Namespace, victim.Name, err))
	} else {
		c.d.Actions.WithLabelValues(wdeps.CheckPSIThrash, "pod_evict").Inc()
	}
	c.d.CycleResult(wdeps.CheckPSIThrash, "ok")
}
