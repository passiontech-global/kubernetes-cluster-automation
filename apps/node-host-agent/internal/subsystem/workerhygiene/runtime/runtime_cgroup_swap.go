// runtime_cgroup_swap.go — the cgroup-swap-leak guard
// (wdeps.CheckCgroupSwap). Swap-out on a kubepods slice is a silent
// latency bomb: kubelet/containerd don't support swap, but a host
// with swap enabled lets the kernel swap pod memory anyway —
// memory.swap.current on kubepods.slice climbs while nothing but
// stall latency reports it. The check exports the kubepods swap
// usage as a gauge and, past the 64MiB floor, writes 0 to
// memory.swap.max on kubepods.slice and the QoS sub-slices —
// stopping further pod swap-out at the cgroup boundary (the sysctl
// vm.swappiness route is node-wide and out of scope for a
// worker-only check).
package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// kubepodsSwapHighBytes is the memory.swap.current floor above
// which pods are demonstrably swapping — any nonzero is suspicious,
// but a sub-page-cache residue doesn't justify rewriting cgroup
// limits every cycle (64MiB).
const kubepodsSwapHighBytes = int64(64) << 20

// kubepodsSwapSlices are the cgroup dirs that get memory.swap.max=0:
// kubepods.slice itself plus the QoS sub-slices (they nest under
// kubepods.slice on the systemd cgroup driver — resolveSwapSliceDir
// also accepts the flat top-level layout for runtimes that don't
// nest).
var kubepodsSwapSlices = []string{
	"kubepods.slice",
	"kubepods-burstable.slice",
	"kubepods-besteffort.slice",
}

// CgroupSwapCheck is the kubepods swap-leak guard as a Check.
type CgroupSwapCheck struct {
	d *wdeps.Deps
}

// Name returns the check label / WD_SIG key.
func (c *CgroupSwapCheck) Name() string { return wdeps.CheckCgroupSwap }

// readCgroupInt parses a bare-integer cgroupfs file — ok=false when
// the file is unreadable or non-numeric (cgroup v1 host, missing
// mount: the check is dormant there, same rule as cgroup-stat).
func readCgroupInt(path string) (int64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// resolveSwapSliceDir returns the dir that actually holds
// memory.swap.max for a named slice — kubepods QoS slices nest
// under kubepods.slice on systemd layout; the flat fallback covers
// runtimes that mount them at the root.
func (c *CgroupSwapCheck) resolveSwapSliceDir(name string) (string, bool) {
	root := c.d.Cfg.Runtime.CgroupRoot
	cands := []string{filepath.Join(root, name)}
	if name != "kubepods.slice" {
		// QoS slices nest under kubepods.slice on the systemd
		// driver — check the nested layout first, flat second.
		cands = []string{
			filepath.Join(root, "kubepods.slice", name),
			filepath.Join(root, name),
		}
	}
	for _, p := range cands {
		if _, err := os.Stat(filepath.Join(p, "memory.swap.max")); err == nil {
			return p, true
		}
	}
	return "", false
}

// Run executes one cgroup-swap-leak round.
func (c *CgroupSwapCheck) Run(_ context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckCgroupSwap) {
		return
	}
	root := c.d.Cfg.Runtime.CgroupRoot
	used, ok := readCgroupInt(filepath.Join(
		root, "kubepods.slice", "memory.swap.current"))
	if !ok {
		// cgroup v1 host or the unified hierarchy isn't mounted —
		// the check is dormant (unreadable → abort, same as the
		// other procfs/cgroupfs probes).
		c.d.CycleResult(wdeps.CheckCgroupSwap, "abort")
		return
	}
	c.d.KubepodsSwapUsedBytes = used
	if used <= kubepodsSwapHighBytes {
		c.d.CycleResult(wdeps.CheckCgroupSwap, "ok")
		return
	}
	// Pods are swapping — cap swap on kubepods.slice and the QoS
	// sub-slices. The write is skipped when the cap already stands
	// (already-swapped pages keep memory.swap.current high until
	// they're touched back in — a per-cycle rewrite would spam).
	capped := false
	for _, name := range kubepodsSwapSlices {
		dir, found := c.resolveSwapSliceDir(name)
		if !found {
			continue
		}
		maxFile := filepath.Join(dir, "memory.swap.max")
		if cur, ok := readCgroupInt(maxFile); ok && cur == 0 {
			continue // cap already in place
		}
		if err := os.WriteFile(maxFile, []byte("0\n"), 0o644); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: cgroup-swap-leak memory.swap.max write %s failed: %v",
				maxFile, err))
			continue
		}
		capped = true
	}
	if capped {
		c.d.State.AppendLog(fmt.Sprintf(
			"ACTION: cgroup-swap-leak capped pod swap - kubepods.slice memory.swap.current=%d, wrote memory.swap.max=0",
			used))
		c.d.Actions.WithLabelValues(wdeps.CheckCgroupSwap, "swap_cap").Inc()
	}
	c.d.CycleResult(wdeps.CheckCgroupSwap, "ok")
}
