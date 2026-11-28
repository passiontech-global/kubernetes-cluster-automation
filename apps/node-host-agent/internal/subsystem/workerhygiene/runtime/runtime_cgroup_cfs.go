// runtime_cgroup_cfs.go — CPU CFS throttling evaluation and host /proc/stat
// idle-ratio tracking for CgroupThrottleCheck. Split out of
// runtime_cgroup_throttle.go.
package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

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
