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

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

const (
	// podCgroupPSIFullHigh is the per-pod memory.pressure `full`
	// avg60 percent above which the pod cgroup is demonstrably
	// throttling — every task in the pod stalls on memory reclaim
	// this share of wall time.
	podCgroupPSIFullHigh = 40.0
)

// CgroupThrottleCheck is the cgroup-pod-throttle pod-cgroup throttle guard as
// a Check. prevHigh / prevPidsDenials keep last cycle's
// memory.events:high / pids.events:max per pod slice — both
// verdicts are DELTAS, not levels (a high-but-flat counter means
// the throttle episode is over, not ongoing).
type CgroupThrottleCheck struct {
	d              *wdeps.Deps
	prevHigh       map[string]int64
	prevPidsDenial map[string]int64
}

// Name returns the check label / WD_SIG key.
func (c *CgroupThrottleCheck) Name() string { return wdeps.CheckCgroupThrottle }

// psiFullAvg60File parses the `full avg60=` value of a PSI
// pressure file — pod cgroup memory.pressure carries the same
// some/full format as /proc/pressure/memory (guards'
// psiMemoryFullAvg60 parity, parameterized by path).
func psiFullAvg60File(path string) (float64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] != "full" {
			continue
		}
		for _, kv := range f[1:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok || k != "avg60" {
				continue
			}
			if x, err := strconv.ParseFloat(v, 64); err == nil {
				return x, true
			}
		}
	}
	return 0, false
}

// cgroupEventsValue parses "key <n>" out of a cgroup events file
// (memory.events "high", pids.events "max"). ok=false when the
// file or the key is absent.
func cgroupEventsValue(path, key string) (int64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
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
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	s := strings.TrimSpace(string(data))
	if s == "" || s == "max" {
		return 0, false
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
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

// podSliceDirs lists the pod cgroup dirs under kubepods.slice:
// Guaranteed pods nest directly (kubepods-pod<uid>.slice),
// Burstable/BestEffort nest under their QoS slice. The sibling
// flat fallbacks cover runtimes that don't nest the QoS slices —
// resolveSwapSliceDir's two-layout rule.
func podSliceDirs(kubepods string) []string {
	root := filepath.Dir(kubepods)
	pats := []string{
		filepath.Join(kubepods, "kubepods-pod*.slice"),
		filepath.Join(kubepods, "kubepods-burstable.slice",
			"kubepods-burstable-pod*.slice"),
		filepath.Join(kubepods, "kubepods-besteffort.slice",
			"kubepods-besteffort-pod*.slice"),
		filepath.Join(root, "kubepods-burstable.slice",
			"kubepods-burstable-pod*.slice"),
		filepath.Join(root, "kubepods-besteffort.slice",
			"kubepods-besteffort-pod*.slice"),
	}
	seen := map[string]bool{}
	var out []string
	for _, p := range pats {
		m, err := filepath.Glob(p)
		if err != nil {
			continue
		}
		for _, d := range m {
			if !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
		}
	}
	return out
}

// Run executes one cgroup-pod-throttle round.
func (c *CgroupThrottleCheck) Run(_ context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckCgroupThrottle) {
		return
	}
	kubepods := filepath.Join(c.d.Cfg.Runtime.CgroupRoot, "kubepods.slice")
	if _, err := os.Stat(kubepods); err != nil {
		// cgroup v1 host or no kubepods on this node — the check
		// is dormant (unreadable → abort, procfs-probe parity).
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
	if c.prevPidsDenial == nil {
		c.prevPidsDenial = map[string]int64{}
	}
	dirs := podSliceDirs(kubepods)
	seen := map[string]bool{}
	var maxRatio float64
	for _, dir := range dirs {
		seen[dir] = true
		// --- memory.high throttle half ---
		avg60, psiOK := psiFullAvg60File(filepath.Join(dir, "memory.pressure"))
		high, highOK := cgroupEventsValue(filepath.Join(dir, "memory.events"), "high")
		var highDelta int64
		if highOK {
			if prev, ok := c.prevHigh[dir]; ok && high >= prev {
				highDelta = high - prev
			}
			c.prevHigh[dir] = high
		}
		if psiOK && highOK && highDelta > 0 &&
			avg60 > podCgroupPSIFullHigh && !nodeThrashing {
			c.d.PodCgroupMemoryThrottled++
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: cgroup-pod-throttle pod uid=%s memory.pressure full avg60=%.1f high_delta=+%d — memory.high throttle stall without node PSI pressure (cgroup-pod-throttle)",
				podUIDFromSlice(dir), avg60, highDelta))
		}
		// --- pids.max utilization half ---
		cur, curOK := readCgroupInt(filepath.Join(dir, "pids.current"))
		lim, limOK := cgroupPidsLimit(filepath.Join(dir, "pids.max"))
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
	}
	// Drop delta ledgers for vanished pod slices — a deleted pod's
	// counter must not carry into a recycled slice name.
	for dir := range c.prevHigh {
		if !seen[dir] {
			delete(c.prevHigh, dir)
		}
	}
	for dir := range c.prevPidsDenial {
		if !seen[dir] {
			delete(c.prevPidsDenial, dir)
		}
	}
	c.d.PodCgroupPIDsMaxUtilRatio = maxRatio
	c.d.CycleResult(wdeps.CheckCgroupThrottle, "ok")
}
