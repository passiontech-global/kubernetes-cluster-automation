// runtime_vma_pressure.go — Wave-3 #9b: per-PID VMA vm.max_map_count guard.
//
// Picks the top-5 processes by VmSize from e.StatsOnce() (O(1) stat lookup),
// counts VMA mappings in <ProcRoot>/<pid>/maps against vm.max_map_count,
// exports node_agent_vma_max_utilization_ratio, auto-raises vm.max_map_count
// up to VMAMaxCeiling (1048576, 30m cooldown) at >= 0.85, and emits a deduped
// PodVMAMapCountPressure Warning Event on the owning Pod.
package runtime

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

const (
	vmaTopNPIDs        = 5
	vmaRaiseCooldown   = 30 * time.Minute
	vmaRaiseBudgetFile = "last-vma-max-raise"
)

type pidVMSize struct {
	pid    int
	vmSize int64
}

func (c *CgroupThrottleCheck) checkVMAPressure(ctx context.Context, e *wdeps.CycleEnv,
	podByUID map[string]*corev1.Pod) {
	maxMapPath := filepath.Join(c.d.Cfg.ProcRoot, "sys", "vm", "max_map_count")
	rawMax, err := os.ReadFile(maxMapPath)
	if err != nil {
		return
	}
	maxMapCount, err := strconv.ParseInt(strings.TrimSpace(string(rawMax)), 10, 64)
	if err != nil || maxMapCount <= 0 {
		return
	}

	var stats map[int]procfs.Stat
	if e != nil && e.StatsOnce != nil {
		stats = e.StatsOnce()
	} else {
		pids, perr := c.d.Proc.PIDs()
		if perr != nil {
			return
		}
		stats = make(map[int]procfs.Stat, len(pids))
		for _, pid := range pids {
			if st, ok := c.d.Proc.Stat(pid); ok {
				stats[pid] = st
			}
		}
	}

	candidates := make([]pidVMSize, 0, len(stats))
	for pid, st := range stats {
		if len(st.Fields) <= 20 {
			continue
		}
		// VmSize is a byte/page count — never negative. ParseUint makes a
		// malformed negative/garbage field inconclusive instead of feeding
		// a bogus ranking into the top-N selection.
		vsize, verr := strconv.ParseUint(st.Fields[20], 10, 64)
		if verr != nil || vsize == 0 || vsize > math.MaxInt64 {
			continue
		}
		candidates = append(candidates, pidVMSize{pid: pid, vmSize: int64(vsize)})
	}
	if len(candidates) == 0 {
		c.d.Series.VMAMaxUtilRatio = 0
		return
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].vmSize != candidates[j].vmSize {
			return candidates[i].vmSize > candidates[j].vmSize
		}
		return candidates[i].pid < candidates[j].pid
	})
	if len(candidates) > vmaTopNPIDs {
		candidates = candidates[:vmaTopNPIDs]
	}

	var worstPID int
	var worstVMACount int64
	for _, cand := range candidates {
		cnt, cerr := countProcMapsLines(c.d.Proc.File(cand.pid, "maps"))
		if cerr != nil {
			continue
		}
		if cnt > worstVMACount {
			worstVMACount = cnt
			worstPID = cand.pid
		}
	}
	if worstVMACount == 0 {
		c.d.Series.VMAMaxUtilRatio = 0
		return
	}

	util := float64(worstVMACount) / float64(maxMapCount)
	c.d.Series.VMAMaxUtilRatio = util
	if util < c.d.Cfg.Wave3.VMAPressureRatio {
		c.vmaEvented = nil
		return
	}

	// Keep the limit that TRIGGERED the event — a successful raise is a
	// separate remedy and must not rewrite the evidence in the Event note.
	prevMax := maxMapCount
	ceiling := c.d.Cfg.Wave3.VMAMaxCeiling
	held := c.d.HoldLocalAction(ctx)
	if maxMapCount < ceiling && !held &&
		c.d.State.RateTrySpend(vmaRaiseBudgetFile, vmaRaiseCooldown) {
		newMax := maxMapCount * 2
		if newMax > ceiling {
			newMax = ceiling
		}
		if werr := os.WriteFile(maxMapPath, []byte(fmt.Sprintf("%d\n", newMax)), 0o644); werr != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: vma-pressure raise vm.max_map_count %d->%d failed: %v",
				maxMapCount, newMax, werr))
		} else {
			c.d.State.AppendLog(fmt.Sprintf(
				"ACTION: vma-pressure raised vm.max_map_count %d->%d (pid=%d vmas=%d util=%.2f)",
				maxMapCount, newMax, worstPID, worstVMACount, util))
			c.d.Actions.WithLabelValues(wdeps.CheckCgroupThrottle, "raise_max_map_count").Inc()
			maxMapCount = newMax
			c.d.Series.VMAMaxUtilRatio = float64(worstVMACount) / float64(maxMapCount)
		}
	} else if held && maxMapCount < ceiling {
		c.d.State.SuspectLog("vma-max-raise-held", fmt.Sprintf(
			"suspect: vma-pressure vm.max_map_count raise held by maintenance (pid=%d vmas=%d util=%.2f)",
			worstPID, worstVMACount, util), cgroupSuspectLogCadence)
	}

	uid, ok := wdeps.PodUIDForPID(c.d, worstPID)
	if !ok {
		return
	}
	if c.vmaEvented == nil {
		c.vmaEvented = map[string]bool{}
	}
	if c.vmaEvented[uid] {
		return
	}
	pod := podByUID[uid]
	if pod == nil || c.d.Cfg.Client == nil {
		c.vmaEvented[uid] = true
		return
	}
	if err := c.d.EmitPodEvent(ctx, pod, "vma-pressure", "PodVMAMapCountPressure",
		fmt.Sprintf("pod process pid=%d holds %d VMA mappings (%.1f%% of vm.max_map_count=%d)",
			worstPID, worstVMACount, util*100, prevMax)); err == nil {
		c.vmaEvented[uid] = true
		c.d.Actions.WithLabelValues(wdeps.CheckCgroupThrottle, "vma_event").Inc()
	}
}

func countProcMapsLines(path string) (int64, error) {
	// /proc/<pid>/maps is line-oriented and bounded in practice; one read
	// plus bytes.Count is both faster and simpler than a buffered scanner
	// that had to handle ErrBufferFull on long mapping lines.
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	count := int64(bytes.Count(data, []byte{'\n'}))
	if len(data) > 0 && data[len(data)-1] != '\n' {
		count++ // unterminated final line
	}
	return count, nil
}
