// runtime_cgroup_dying.go — the cgroup-dying-reclaim guard
// (wdeps.CheckCgroupDying). On cgroup v2 a deleted cgroup lingers as
// "dying" while any page it accounted is still referenced —
// nr_dying_descendants counts them. Thousands of dying cgroups pin
// slab/page-cache the kernel cannot hand back, inflate every
// cgroupfs walk (runc list, cadvisor) and fake memory pressure on
// the node. Reclaim is the kernel's own escape hatch: drop_caches
// releases dentries/inodes/pagecache and memory.reclaim proactively
// reclaims without OOM pressure.
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
	// cgroupDyingThreshold is the nr_dying_descendants count above
	// which dying cgroups are considered leaked — the level where
	// cgroup-file walks and memory accounting visibly degrade
	// (kernel 5.4+ reclaim path is known to lag hard past ~10^3).
	cgroupDyingThreshold = 5000
	// cgroupReclaimInterval is the last-cgroup-drop-caches budget —
	// drop_caches is node-wide and costs real IO while it runs.
	cgroupReclaimInterval = 30 * time.Minute
	// cgroupReclaimBytes is the memory.reclaim write — a bounded
	// proactive reclaim nudge, not a limit change (the file takes
	// "amount to reclaim" values; an undersized pool just returns
	// fewer pages).
	cgroupReclaimBytes = "256M\n"
	// cgroupDyingChildThreshold is the per-slice
	// nr_dying_descendants count that earns a targeted
	// memory.reclaim write (W12-KR-C) — a dying-descendant pile
	// concentrates in a few first-level kubepods.slice children
	// (one noisy pod slice, a QoS slice), and reclaiming the
	// offender directly works far better than asking the
	// aggregate root.
	cgroupDyingChildThreshold = 100
)

type CgroupDyingCheck struct {
	d     *wdeps.Deps
	fails int
}

// Name returns the check label / WD_SIG key.
func (c *CgroupDyingCheck) Name() string { return wdeps.CheckCgroupDying }

// cgroupStatDying parses one cgroup.stat file for the
// nr_dying_descendants field — ok=false when the file or the field
// is unreadable (cgroup v1 host, missing mount: the check is
// dormant there).
func cgroupStatDying(path string) (int64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "nr_dying_descendants" {
			if v, err := strconv.ParseInt(f[1], 10, 64); err == nil {
				return v, true
			}
		}
	}
	return 0, false
}

// Run executes one cgroup-dying round.
func (c *CgroupDyingCheck) Run(_ context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckCgroupDying) {
		return
	}
	root := c.d.Cfg.Runtime.CgroupRoot
	var dying int64
	found := false
	for _, p := range []string{
		filepath.Join(root, "cgroup.stat"),
		filepath.Join(root, "kubepods.slice", "cgroup.stat"),
	} {
		if v, ok := cgroupStatDying(p); ok {
			found = true
			if v > dying {
				dying = v
			}
		}
	}
	if !found {
		// cgroup v1 host or the hierarchy isn't mounted — the whole
		// check is dormant (same "unreadable → abort" rule as the
		// other procfs probes).
		c.d.CycleResult(wdeps.CheckCgroupDying, "abort")
		return
	}
	c.d.CgroupDyingDescendants = dying
	if dying <= cgroupDyingThreshold {
		c.fails = 0
		c.d.State.Exit(latchdefs.LatchCgroupDyingLeak, nil)
		c.d.CycleResult(wdeps.CheckCgroupDying, "ok")
		return
	}
	if c.d.StreakPending(&c.fails, fmt.Sprintf(
		"suspect: cgroup-dying-leak nr_dying_descendants=%d",
		dying)) {
		c.d.CycleResult(wdeps.CheckCgroupDying, "ok")
		return
	}
	c.d.State.Enter(latchdefs.LatchCgroupDyingLeak,
		fmt.Sprintf("nr_dying_descendants=%d", dying))
	if !c.d.State.RateTrySpend("last-cgroup-drop-caches", cgroupReclaimInterval) {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cgroup-dying-leak nr_dying_descendants=%d - reclaim cooldown (<30m), skip",
			dying))
		c.d.CycleResult(wdeps.CheckCgroupDying, "ok")
		return
	}
	c.reclaim(root, dying)
	c.d.CycleResult(wdeps.CheckCgroupDying, "ok")
}

// reclaim runs the budgeted reclaim pass: drop_caches frees the
// dentry/inode/page cache pinning dying cgroups ("2" first — slab
// objects are the common pin; "1" as the pagecache-only fallback
// for kernels/configs that reject the level), then memory.reclaim
// asks the cgroup-v2 core to proactively reclaim on the root and
// the kubepods subtree. Writes are best-effort: memory.reclaim is
// absent on older kernels and drop_caches can EBUSY — neither
// turns the cycle into a failure, and the budget was already
// spent (rate_spend parity).
func (c *CgroupDyingCheck) reclaim(root string, dying int64) {
	p := filepath.Join(c.d.Cfg.ProcRoot, "sys", "vm", "drop_caches")
	if err := os.WriteFile(p, []byte("2\n"), 0o644); err != nil {
		if err2 := os.WriteFile(p, []byte("1\n"), 0o644); err2 != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: cgroup-dying-leak drop_caches writes failed: %v / %v",
				err, err2))
		}
	}
	for _, rec := range []string{
		filepath.Join(root, "memory.reclaim"),
		filepath.Join(root, "kubepods.slice", "memory.reclaim"),
	} {
		if err := os.WriteFile(rec, []byte(cgroupReclaimBytes), 0o644); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: cgroup-dying-leak memory.reclaim write %s failed: %v",
				rec, err))
		}
	}
	// W12-KR-C: targeted reclaim on the first-level kubepods.slice
	// children whose own nr_dying_descendants exceeds
	// cgroupDyingChildThreshold — the dying pile concentrates in a
	// few pod/QoS slices, and reclaiming the offender's subtree
	// frees the pinned pages the aggregate write can't reach.
	kubepods := filepath.Join(root, "kubepods.slice")
	if entries, err := os.ReadDir(kubepods); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			child := filepath.Join(kubepods, e.Name())
			childDying, ok := cgroupStatDying(
				filepath.Join(child, "cgroup.stat"))
			if !ok || childDying <= cgroupDyingChildThreshold {
				continue
			}
			rec := filepath.Join(child, "memory.reclaim")
			if err := os.WriteFile(rec, []byte(cgroupReclaimBytes), 0o644); err != nil {
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: cgroup-dying-leak memory.reclaim write %s failed: %v",
					rec, err))
				continue
			}
			c.d.State.AppendLog(fmt.Sprintf(
				"ACTION: cgroup-dying-leak targeted memory.reclaim %s - child nr_dying_descendants=%d",
				e.Name(), childDying))
			c.d.Actions.WithLabelValues(wdeps.CheckCgroupDying, "reclaim_child").Inc()
		}
	}
	c.d.State.AppendLog(fmt.Sprintf(
		"ACTION: cgroup-dying-leak reclaim - nr_dying_descendants=%d, wrote drop_caches + memory.reclaim",
		dying))
	c.d.CgroupReclaimRuns++
	c.d.Actions.WithLabelValues(wdeps.CheckCgroupDying, "reclaim").Inc()
}
