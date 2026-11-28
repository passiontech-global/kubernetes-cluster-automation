// runtime_cgroup_throttle.go — the cgroup-pod-throttle guard
// (wdeps.CheckCgroupThrottle, cgroup-pod-throttle). kubelet MemoryQoS writes
// memory.high on pod cgroups: a container whose working set
// outgrows it is NOT OOM-killed — the kernel forces every
// allocation into direct reclaim / sleep-throttle instead, so the
// pod's own memory.pressure `full` spikes and memory.events:high
// keeps counting while node-wide PSI (psi-memory-thrash, psi-memory-thrash)
// stays flat. The pod stays Running, its probes answer, and p99
// goes 100x — the classic Datadog/Meta cgroup-v2 stall with no
// OOMKill to point at. The check walks the pod-level cgroups
// under kubepods.slice and refreshes two series:
//   - node_agent_pod_cgroup_memory_throttled (counter): pods seen
//     with memory.pressure full avg60 > 40% AND a growing
//     memory.events:high counter while the node-wide thrash latch
//     is OFF (a node event already owns that signal — counting
//     pods on top would double-report).
//   - PodMemoryHighThrottled Warning events on the owning Pod —
//     the stall is invisible in pod status (Running, probes
//     green), so the event is the operator-facing surface; deduped
//     per pod slice and re-armed on a conclusive non-throttle
//     cycle (an unreadable pressure/events file holds the marker,
//     same inconclusive posture as observability-pipeline-guard).
//   - node_cgroup_pids_utilization_max_ratio (gauge): the worst
//     pids.current / pids.max across pod cgroups — a ratio near 1
//     means the next clone() EAGAINs ("fork: resource temporarily
//     unavailable"); a growing pids.events:max counter proves
//     denials already landed.
package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

const (
	// podCgroupPSIFullHigh is the per-pod memory.pressure `full`
	// avg60 percent above which the pod cgroup is demonstrably
	// throttling — every task in the pod stalls on memory reclaim
	// this share of wall time.
	podCgroupPSIFullHigh     = 40.0
	podCgroupPSISomeAvg60    = 25.0
	podCgroupPSISomeAvg10    = 40.0
	memThrottleConfirmCycles = 2

	cpuCFSMinPeriodDelta = 20
	cpuCFSConfirmCycles  = 3
	// cpuHostIdleMinJiffies is the minimum /proc/stat delta before an idle
	// ratio is published — below it the tickless kernel's NOHZ jitter makes
	// the ratio meaningless (and a first read would be a since-boot value).
	cpuHostIdleMinJiffies = 10
	// cgroupSuspectLogCadence throttles the per-pod CPU CFS suspect lines —
	// a throttle episode lasts many cycles, one line per hour is ample.
	cgroupSuspectLogCadence = time.Hour
)

type cpuStatSample struct {
	periods   int64
	throttled int64
}

// CgroupThrottleCheck is the cgroup-pod-throttle pod-cgroup throttle guard as
// a Check. prevHigh / prevPidsDenials keep last cycle's
// memory.events:high / pids.events:max per pod slice — both
// verdicts are DELTAS, not levels (a high-but-flat counter means
// the throttle episode is over, not ongoing).
type CgroupThrottleCheck struct {
	d              *wdeps.Deps
	prevHigh       map[string]int64
	prevMax        map[string]int64
	memStreak      map[string]int
	prevPidsDenial map[string]int64
	// evented dedupes the PodMemoryHighThrottled Warning per pod
	// slice dir — re-armed by a conclusive non-throttle cycle or
	// the dir's disappearance (a recycled slice name must not
	// inherit the old pod's marker).
	evented map[string]bool

	// Wave-3 #9a: CPU CFS bandwidth throttling state.
	prevHostCPUTotal int64
	prevHostCPUIdle  int64
	hasPrevHostCPU   bool
	prevCPUStat      map[string]cpuStatSample
	cpuStreak        map[string]int
	cpuEvented       map[string]bool

	// Wave-3 #9b: per-PID VMA max_map_count event dedup.
	vmaEvented map[string]bool
}

// Name returns the check label / WD_SIG key.
func (c *CgroupThrottleCheck) Name() string { return wdeps.CheckCgroupThrottle }

type podMemoryEvents struct {
	high    int64
	max     int64
	hasHigh bool
	hasMax  bool
}

// readPodMemoryEvents parses "high <n>" and "max <n>" out of a pod
// cgroup's memory.events in a single read (first occurrence of each
// key wins). ok=true when at least one of high or max is present.
func readPodMemoryEvents(path string) (podMemoryEvents, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return podMemoryEvents{}, false
	}
	var ev podMemoryEvents
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
		case "max":
			if !ev.hasMax {
				ev.max, ev.hasMax = v, true
			}
		}
	}
	return ev, ev.hasHigh || ev.hasMax
}

// cgroupEventsValue parses "key <n>" out of a cgroup events file
// (memory.events "high", pids.events "max"). ok=false when the
// file or the key is absent.
func cgroupEventsValue(path, key string) (int64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == key {
			if v, err := strconv.ParseInt(f[1], 10, 64); err == nil {
				return v, true
			}
		}
	}
	return 0, false
}

// cgroupPidsLimit parses pids.max — the literal "max" sentinel
// means unlimited and yields ok=false (no ratio to compute).
func cgroupPidsLimit(path string) (int64, bool) {
	v, ok, _ := cgroupPidsLimitChecked(path)
	return v, ok
}

func cgroupPidsLimitChecked(path string) (v int64, ok, readErr bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false, !os.IsNotExist(err)
	}
	s := strings.TrimSpace(string(data))
	if s == "" || s == "max" {
		return 0, false, false
	}
	v, err = strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false, false
	}
	return v, true, false
}

func readCgroupIntChecked(path string) (v int64, ok, readErr bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false, !os.IsNotExist(err)
	}
	v, err = strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, false, false
	}
	return v, true, false
}

// podUIDFromSlice extracts the pod uid out of a pod slice dir
// name — kubepods[-<qos>]-pod<uid>.slice, with the uid's dashes
// flattened to underscores by systemd slice escaping.
func podUIDFromSlice(dir string) string {
	base := strings.TrimSuffix(filepath.Base(dir), ".slice")
	i := strings.LastIndex(base, "-pod")
	if i < 0 {
		return base
	}
	return strings.ReplaceAll(base[i+len("-pod"):], "_", "-")
}

// podSliceDirsChecked lists the pod cgroup dirs under kubepods.slice:
// Guaranteed pods nest directly (kubepods-pod<uid>.slice),
// Burstable/BestEffort nest under their QoS slice. The sibling
// flat fallbacks cover runtimes that don't nest the QoS slices —
// resolveSwapSliceDir's two-layout rule.
// Absent QoS subdirs (ENOENT) are normal; non-ENOENT read errors on
// kubepods.slice or any existing QoS subdir return an error so callers
// abort instead of clobbering gauges and state maps.
func podSliceDirsChecked(kubepods string) ([]string, error) {
	root := filepath.Dir(kubepods)
	specs := []struct {
		dir      string
		prefix   string
		required bool
	}{
		{kubepods, "kubepods-pod", true},
		{filepath.Join(kubepods, "kubepods-burstable.slice"), "kubepods-burstable-pod", false},
		{filepath.Join(kubepods, "kubepods-besteffort.slice"), "kubepods-besteffort-pod", false},
		{filepath.Join(root, "kubepods-burstable.slice"), "kubepods-burstable-pod", false},
		{filepath.Join(root, "kubepods-besteffort.slice"), "kubepods-besteffort-pod", false},
	}
	seen := map[string]bool{}
	var out []string
	for _, sp := range specs {
		entries, err := os.ReadDir(sp.dir)
		if err != nil {
			if !sp.required && os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		for _, en := range entries {
			name := en.Name()
			if !strings.HasPrefix(name, sp.prefix) || !strings.HasSuffix(name, ".slice") {
				continue
			}
			d := filepath.Join(sp.dir, name)
			if !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
		}
	}
	return out, nil
}

func podSliceDirs(kubepods string) []string {
	dirs, _ := podSliceDirsChecked(kubepods)
	return dirs
}

// Run executes one cgroup-pod-throttle round.
func (c *CgroupThrottleCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckCgroupThrottle) {
		clearPodSliceCache(c.d)
		return
	}
	kubepods := filepath.Join(c.d.Cfg.Runtime.CgroupRoot, "kubepods.slice")
	if _, err := os.Stat(kubepods); err != nil {
		// cgroup v1 host or no kubepods on this node — the check
		// is dormant (unreadable → abort, procfs-probe parity).
		clearPodSliceCache(c.d)
		c.d.CycleResult(wdeps.CheckCgroupThrottle, "abort")
		return
	}
	// The psi-memory-thrash node-wide thrash latch owns the signal while the WHOLE
	// node is under memory pressure — pod-level throttle verdicts
	// only mean anything when the node itself is quiet (a mis-sized
	// memory.request, not a global event).
	nodeThrashing := c.d.State.Exists(latchdefs.LatchPSIMemoryThrash)
	if c.prevHigh == nil {
		c.prevHigh = map[string]int64{}
	}
	if c.prevMax == nil {
		c.prevMax = map[string]int64{}
	}
	if c.memStreak == nil {
		c.memStreak = map[string]int{}
	}
	if c.prevPidsDenial == nil {
		c.prevPidsDenial = map[string]int64{}
	}
	if c.evented == nil {
		c.evented = map[string]bool{}
	}
	if c.prevCPUStat == nil {
		c.prevCPUStat = map[string]cpuStatSample{}
	}
	if c.cpuStreak == nil {
		c.cpuStreak = map[string]int{}
	}
	if c.cpuEvented == nil {
		c.cpuEvented = map[string]bool{}
	}
	dirs, err := podSliceDirsChecked(kubepods)
	if err != nil {
		clearPodSliceCache(c.d)
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cgroup-pod-throttle read %s failed: %v — inconclusive, keeping state",
			kubepods, err))
		c.d.CycleResult(wdeps.CheckCgroupThrottle, "abort")
		return
	}
	hostIdleRatio, hostIdleOK := c.readHostCPUIdleRatio()
	podByUID := e.PodByUID()
	seen := map[string]bool{}
	dirEnts := make(map[string]cachedDirRead, len(dirs))
	var maxRatio float64
	pidsInconclusive := false
	anyInconclusive := false
	for _, dir := range dirs {
		ents, derr := os.ReadDir(dir)
		dirEnts[dir] = cachedDirRead{ents: ents, err: derr}
		if derr != nil {
			if os.IsNotExist(derr) {
				continue // pod slice vanished mid-sweep — prune ledgers below
			}
			seen[dir] = true
			pidsInconclusive = true
			anyInconclusive = true
			continue
		}
		seen[dir] = true
		// --- memory.high / memory.max throttle half ---
		psi, psiOK := procfs.ParsePSIMemory(filepath.Join(dir, "memory.pressure"))
		memEv, eventsOK := readPodMemoryEvents(filepath.Join(dir, "memory.events"))
		var highDelta, maxDelta int64
		if memEv.hasHigh {
			if prev, ok := c.prevHigh[dir]; ok && memEv.high >= prev {
				highDelta = memEv.high - prev
			}
			c.prevHigh[dir] = memEv.high
		}
		if memEv.hasMax {
			if prev, ok := c.prevMax[dir]; ok && memEv.max >= prev {
				maxDelta = memEv.max - prev
			}
			c.prevMax[dir] = memEv.max
		}
		if psiOK && eventsOK {
			if nodeThrashing {
				c.memStreak[dir] = 0
				delete(c.evented, dir)
			} else {
				psiHot := (psi.HasSome && (psi.SomeAvg60 > podCgroupPSISomeAvg60 || psi.SomeAvg10 > podCgroupPSISomeAvg10)) ||
					(psi.HasFull && psi.FullAvg60 > podCgroupPSIFullHigh)
				if (highDelta > 0 || maxDelta > 0) && psiHot {
					c.memStreak[dir]++
				} else {
					c.memStreak[dir] = 0
				}
				sustained := c.memStreak[dir] >= memThrottleConfirmCycles
				if sustained {
					c.d.PodCgroupMemoryThrottled++
					uid := podUIDFromSlice(dir)
					c.d.State.SuspectLog("cgroup-mem-"+strings.ReplaceAll(uid, "/", "_"), fmt.Sprintf(
						"suspect: cgroup-pod-throttle pod uid=%s memory.pressure some_avg10=%.1f some_avg60=%.1f full_avg60=%.1f high_delta=+%d max_delta=+%d streak=%d — memory.high throttle stall without node PSI pressure (cgroup-pod-throttle)",
						uid, psi.SomeAvg10, psi.SomeAvg60, psi.FullAvg60, highDelta, maxDelta, c.memStreak[dir]),
						cgroupSuspectLogCadence)
					if !c.evented[dir] && c.throttledEvent(ctx, e, uid,
						psi, highDelta, maxDelta, podByUID[uid]) {
						c.evented[dir] = true
					}
				} else if c.memStreak[dir] == 0 {
					// Conclusive non-throttle cycle — re-arm the episode
					// marker so a LATER throttle burst emits a fresh event.
					// An unreadable pressure/events file is inconclusive
					// and holds the marker (a flap must not re-page).
					delete(c.evented, dir)
				}
			}
		}
		// --- pids.max utilization half ---
		cur, curOK, curReadErr := readCgroupIntChecked(filepath.Join(dir, "pids.current"))
		lim, limOK, limReadErr := cgroupPidsLimitChecked(filepath.Join(dir, "pids.max"))
		if curReadErr || limReadErr {
			pidsInconclusive = true
			anyInconclusive = true
		}
		if curOK && limOK && lim > 0 {
			if r := float64(cur) / float64(lim); r > maxRatio {
				maxRatio = r
			}
		}
		if denied, ok := cgroupEventsValue(
			filepath.Join(dir, "pids.events"), "max"); ok {
			if prev, seenPrev := c.prevPidsDenial[dir]; seenPrev &&
				denied > prev {
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: cgroup-pod-throttle pod uid=%s pids fork denials +%d (pids.current=%d pids.max=%d)",
					podUIDFromSlice(dir), denied-prev, cur, lim))
			}
			c.prevPidsDenial[dir] = denied
		}
		// --- CPU CFS bandwidth throttling half (Wave-3 #9a) ---
		if !c.evalCPUCFSThrottle(ctx, e, dir, ents, hostIdleRatio, hostIdleOK, podByUID) {
			anyInconclusive = true
		}
	}
	putPodSliceCache(c.d, kubepods, dirs, dirEnts)
	// Drop delta ledgers for vanished pod slices — a deleted pod's
	// counter must not carry into a recycled slice name.
	for dir := range c.prevHigh {
		if !seen[dir] {
			delete(c.prevHigh, dir)
		}
	}
	for dir := range c.prevMax {
		if !seen[dir] {
			delete(c.prevMax, dir)
		}
	}
	for dir := range c.memStreak {
		if !seen[dir] {
			delete(c.memStreak, dir)
		}
	}
	for dir := range c.prevPidsDenial {
		if !seen[dir] {
			delete(c.prevPidsDenial, dir)
		}
	}
	for dir := range c.evented {
		if !seen[dir] {
			delete(c.evented, dir)
		}
	}
	// CPU CFS deltas are keyed by cpu.stat PATH (pod slice + child scopes),
	// not by pod dir — map each key back to its slice before the prune.
	for key := range c.prevCPUStat {
		if !seen[cpuStatSliceOf(key)] {
			delete(c.prevCPUStat, key)
		}
	}
	for key := range c.cpuStreak {
		if !seen[cpuStatSliceOf(key)] {
			delete(c.cpuStreak, key)
		}
	}
	for dir := range c.cpuEvented {
		if !seen[dir] {
			delete(c.cpuEvented, dir)
		}
	}
	seenUIDs := make(map[string]bool, len(seen))
	for dir := range seen {
		uid := strings.ReplaceAll(podUIDFromSlice(dir), "/", "_")
		seenUIDs[uid] = true
	}
	c.d.State.PruneMarkers(hoststate.SuspectBudgetPrefix+"cgroup-cfs-", func(id string) bool {
		return seenUIDs[id]
	})
	if !pidsInconclusive {
		c.d.PodCgroupPIDsMaxUtilRatio = maxRatio
	}
	vmaOK := c.checkVMAPressure(ctx, e, podByUID)
	if anyInconclusive || !vmaOK {
		c.d.CycleResult(wdeps.CheckCgroupThrottle, "abort")
		return
	}
	c.d.CycleResult(wdeps.CheckCgroupThrottle, "ok")
}

func (c *CgroupThrottleCheck) readHostCPUIdleRatio() (float64, bool) {
	data, err := os.ReadFile(filepath.Join(c.d.Cfg.ProcRoot, "stat"))
	if err != nil {
		return 0, false
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		// Only the first 8 jiffy columns (user..steal) are the CPU time
		// accounting contract; newer kernels append guest/guest_nice etc.
		// Summing those double-counts the guest time already in user.
		if len(fields) < 9 {
			return 0, false
		}
		var total, idle int64
		for _, raw := range fields[1:9] {
			v, perr := strconv.ParseInt(raw, 10, 64)
			if perr != nil {
				return 0, false
			}
			total += v
		}
		idle, _ = strconv.ParseInt(fields[4], 10, 64) // fields[4] = field 4 "idle"

		// First read: record the baseline only. A since-boot cumulative
		// ratio is NOT current idle and must never gate a heal decision.
		if !c.hasPrevHostCPU || total <= c.prevHostCPUTotal || idle < c.prevHostCPUIdle {
			c.prevHostCPUTotal, c.prevHostCPUIdle, c.hasPrevHostCPU = total, idle, true
			return 0, false
		}
		dTotal := total - c.prevHostCPUTotal
		if dTotal < cpuHostIdleMinJiffies {
			// NOHZ jitter — keep the baseline so the delta accumulates
			// until it is statistically meaningful; no ratio this cycle.
			return 0, false
		}
		dIdle := idle - c.prevHostCPUIdle
		c.prevHostCPUTotal, c.prevHostCPUIdle = total, idle
		return float64(dIdle) / float64(dTotal), true
	}
	return 0, false
}

func readCPUStatChecked(path string) (cpuStatSample, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return cpuStatSample{}, false, err
	}
	var s cpuStatSample
	var gotPeriods, gotThrottled bool
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
		case "nr_periods":
			s.periods = v
			gotPeriods = true
		case "nr_throttled":
			s.throttled = v
			gotThrottled = true
		}
	}
	return s, gotPeriods && gotThrottled, nil
}

// cpuStatPathsFromEntries returns the pod-level cpu.stat plus every child
// *.scope/cpu.stat from a pre-read pod slice directory listing.
func cpuStatPathsFromEntries(dir string, ents []os.DirEntry) []string {
	paths := []string{filepath.Join(dir, "cpu.stat")}
	for _, en := range ents {
		if !strings.HasSuffix(en.Name(), ".scope") {
			continue
		}
		if en.IsDir() {
			paths = append(paths, filepath.Join(dir, en.Name(), "cpu.stat"))
		}
	}
	return paths
}

// cpuStatSliceOf maps a path-keyed CPU CFS ledger entry back to its pod slice.
func cpuStatSliceOf(key string) string {
	d := filepath.Dir(key)
	if filepath.Ext(d) == ".scope" {
		return filepath.Dir(d)
	}
	return d
}

func (c *CgroupThrottleCheck) evalCPUCFSThrottle(ctx context.Context, e *wdeps.CycleEnv, dir string, ents []os.DirEntry,
	hostIdleRatio float64, hostIdleOK bool, podByUID map[string]*corev1.Pod) bool {
	var worstPath string
	var worstDP, worstDT int64
	var worstRatio float64
	var worstStreak int
	fired := false
	nonENOENT := false
	paths := cpuStatPathsFromEntries(dir, ents)
	for _, path := range paths {
		cur, ok, rerr := readCPUStatChecked(path)
		if rerr != nil {
			if !os.IsNotExist(rerr) {
				nonENOENT = true
			}
			continue
		}
		if !ok {
			continue
		}
		prev, hadPrev := c.prevCPUStat[path]
		c.prevCPUStat[path] = cur
		if !hadPrev || cur.periods < prev.periods || cur.throttled < prev.throttled {
			c.cpuStreak[path] = 0
			continue
		}
		dPeriods := cur.periods - prev.periods
		dThrottled := cur.throttled - prev.throttled
		if dPeriods < cpuCFSMinPeriodDelta {
			c.cpuStreak[path] = 0
			continue
		}
		ratio := float64(dThrottled) / float64(dPeriods)
		if !(ratio > c.d.Cfg.Wave3.CPUCFSThrottleRatio && hostIdleOK &&
			hostIdleRatio >= c.d.Cfg.Wave3.CPUHostIdleMinRatio) {
			c.cpuStreak[path] = 0
			continue
		}
		c.cpuStreak[path]++
		if c.cpuStreak[path] < cpuCFSConfirmCycles {
			continue
		}
		fired = true
		if ratio > worstRatio {
			worstRatio, worstDP, worstDT = ratio, dPeriods, dThrottled
			worstPath, worstStreak = path, c.cpuStreak[path]
		}
	}
	if !fired {
		if nonENOENT {
			return false
		}
		delete(c.cpuEvented, dir)
		return true
	}
	c.d.Series.PodCgroupCPUThrottled++
	uid := podUIDFromSlice(dir)
	suspectKey := "cgroup-cfs-" + strings.ReplaceAll(uid, "/", "_")
	c.d.State.SuspectLog(suspectKey, fmt.Sprintf(
		"suspect: cgroup-pod-throttle pod uid=%s %s throttled=%d/%d (%.1f%%) host_idle=%.1f%% (%dx)",
		uid, filepath.Base(worstPath), worstDT, worstDP, worstRatio*100,
		hostIdleRatio*100, worstStreak), cgroupSuspectLogCadence)
	if !c.cpuEvented[dir] {
		pod := podByUID[uid]
		if pod == nil {
			if e == nil || !e.APIOK {
				return !nonENOENT
			}
			c.cpuEvented[dir] = true
			return !nonENOENT
		}
		if c.d.Cfg.Client == nil {
			c.cpuEvented[dir] = true
			return !nonENOENT
		}
		if err := c.d.EmitPodEvent(ctx, pod, "cpu-cfs", "PodCPUCFSThrottled",
			fmt.Sprintf("pod cgroup CPU CFS throttled %d/%d periods (%.1f%%) while host CPU idle=%.1f%% — CPU limit is starving pod despite ample host capacity",
				worstDT, worstDP, worstRatio*100, hostIdleRatio*100)); err == nil {
			c.cpuEvented[dir] = true
			c.d.Actions.WithLabelValues(wdeps.CheckCgroupThrottle, "cpu_event").Inc()
		}
	}
	return !nonENOENT
}

// throttledEvent creates the PodMemoryHighThrottled Warning Event on
// the owning Pod — the pod-level counterpart of the suspect line:
// the cgroup throttle stall is invisible in pod status (Running,
// probes green), so the event is the operator-facing surface.
// Returns true when the episode counts as handled — the event was
// created, the pod is unresolvable on a healthy API list (a dead pod's
// cgroup can't take an event anyway), or no events client exists
// (standalone/test posture). A create failure or inconclusive pod list
// (!e.APIOK) returns false so the caller's dedup marker does not
// advance and the next cycle retries.
func (c *CgroupThrottleCheck) throttledEvent(ctx context.Context,
	e *wdeps.CycleEnv, uid string, psi procfs.PSIMemoryStats, highDelta, maxDelta int64, pod *corev1.Pod) bool {

	if pod == nil {
		if e == nil || !e.APIOK {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: cgroup-pod-throttle pod uid=%s memory.high throttle — pod list inconclusive, event deferred",
				uid))
			return false
		}
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cgroup-pod-throttle pod uid=%s memory.high throttle — pod unresolvable, event skipped",
			uid))
		return true
	}
	if c.d.Cfg.Client == nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cgroup-pod-throttle pod uid=%s memory.high throttle — pod unresolvable, event skipped",
			uid))
		return true
	}
	if err := c.d.EmitPodEvent(ctx, pod, "", "PodMemoryHighThrottled",
		fmt.Sprintf(
			"pod cgroup under kubepods.slice throttled on memory.high/memory.max: memory.pressure some avg10=%.1f%% avg60=%.1f%% full avg60=%.1f%%, memory.events high +%d max +%d this cycle — pod stalls in direct reclaim while node PSI stays flat (memory.request mis-sized)",
			psi.SomeAvg10, psi.SomeAvg60, psi.FullAvg60, highDelta, maxDelta)); err != nil {
		return false
	}
	c.d.Actions.WithLabelValues(wdeps.CheckCgroupThrottle, "event").Inc()
	return true
}
