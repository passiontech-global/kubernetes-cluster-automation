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

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
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
	// evented dedupes the PodMemoryHighThrottled Warning per pod
	// slice dir — re-armed by a conclusive non-throttle cycle or
	// the dir's disappearance (a recycled slice name must not
	// inherit the old pod's marker).
	evented map[string]bool
}

// Name returns the check label / WD_SIG key.
func (c *CgroupThrottleCheck) Name() string { return wdeps.CheckCgroupThrottle }

// psiFullAvg60File parses the `full avg60=` value of a PSI
// pressure file — pod cgroup memory.pressure carries the same
// some/full format as /proc/pressure/memory (guards'
// psiMemoryFullAvg60 parity, parameterized by path).
func psiFullAvg60File(path string) (float64, bool) {
	avg60, _, ok := procfs.ParsePSIFull(path)
	return avg60, ok
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
func (c *CgroupThrottleCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
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
	if c.evented == nil {
		c.evented = map[string]bool{}
	}
	podByUID := e.PodByUID()
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
			uid := podUIDFromSlice(dir)
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: cgroup-pod-throttle pod uid=%s memory.pressure full avg60=%.1f high_delta=+%d — memory.high throttle stall without node PSI pressure (cgroup-pod-throttle)",
				uid, avg60, highDelta))
			if !c.evented[dir] && c.throttledEvent(ctx, uid,
				avg60, highDelta, podByUID[uid]) {
				c.evented[dir] = true
			}
		} else if psiOK && highOK {
			// Conclusive non-throttle cycle — re-arm the episode
			// marker so a LATER throttle burst emits a fresh event.
			// An unreadable pressure/events file is inconclusive
			// and holds the marker (a flap must not re-page).
			delete(c.evented, dir)
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
	for dir := range c.evented {
		if !seen[dir] {
			delete(c.evented, dir)
		}
	}
	c.d.PodCgroupPIDsMaxUtilRatio = maxRatio
	c.d.CycleResult(wdeps.CheckCgroupThrottle, "ok")
}

// throttledEvent creates the PodMemoryHighThrottled Warning Event on
// the owning Pod — the pod-level counterpart of the suspect line:
// the cgroup throttle stall is invisible in pod status (Running,
// probes green), so the event is the operator-facing surface.
// Returns true when the episode counts as handled — the event was
// created, the pod is unresolvable (a dead pod's cgroup can't take
// an event anyway), or no events client exists (standalone/test
// posture). A create failure returns false so the caller's dedup
// marker does not advance and the next cycle retries.
func (c *CgroupThrottleCheck) throttledEvent(ctx context.Context,
	uid string, avg60 float64, highDelta int64, pod *corev1.Pod) bool {

	if pod == nil || c.d.Cfg.Client == nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cgroup-pod-throttle pod uid=%s memory.high throttle — pod unresolvable, event skipped",
			uid))
		return true
	}
	if err := c.d.EmitPodEvent(ctx, pod, "", "PodMemoryHighThrottled",
		fmt.Sprintf(
			"pod cgroup under kubepods.slice throttled on memory.high: memory.pressure full avg60=%.1f%%, memory.events high +%d this cycle — pod stalls in direct reclaim while node PSI stays flat (memory.request mis-sized)",
			avg60, highDelta)); err != nil {
		return false
	}
	c.d.Actions.WithLabelValues(wdeps.CheckCgroupThrottle, "event").Inc()
	return true
}
