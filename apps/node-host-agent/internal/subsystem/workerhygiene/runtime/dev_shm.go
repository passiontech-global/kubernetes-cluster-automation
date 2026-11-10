// dev_shm.go — disk side-guard promoted out of DiskBloatCheck into
// its own wdeps.Check (wdeps.CheckDevShm): per-guard WD_SIG kill
// switch, cycles{check,result} series and action labels. The
// guard body is unchanged — it always ran on the shared *wdeps.Deps.
package runtime

import (
	"context"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

type DevShmCheck struct{ d *wdeps.Deps }

// NewDevShm builds the devShm disk guard check.
func NewDevShm(d *wdeps.Deps) *DevShmCheck { return &DevShmCheck{d: d} }

// Name returns the check label / WD_SIG key.
func (c *DevShmCheck) Name() string { return wdeps.CheckDevShm }

// Run executes one devShm round under its own gate.
func (c *DevShmCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckDevShm) {
		return
	}
	c.measureDevShm()
	c.d.CycleResult(wdeps.CheckDevShm, "ok")
}

// --- dev-shm: host /dev/shm tmpfs fill gauge (devshm-fill-guard) ---
//
// /dev/shm is a small tmpfs (typically half of RAM) that IPC-heavy
// workloads — postgres shared buffers, JVM heaps, chrome/chromium
// renderers — fill silently; once full every shm_open/mmap fails
// while disk watermarks stay green. The guard only MEASURES: statfs
// the shm mount for bytes+inodes, publish the worst ratio on
// node_agent_dev_shm_used_ratio every cycle. No remediation — a
// full shm is a workload bug, and deleting shm files corrupts
// running processes; the Prometheus alert owns the page.

// measureDevShm executes one dev-shm round.
func (c *DevShmCheck) measureDevShm() {
	var st unix.Statfs_t
	if err := c.d.Cfg.Seams.Host.StatfsFn(c.d.Cfg.Disk.HostShmDir, &st); err != nil ||
		st.Blocks == 0 {
		return // unmeasurable — keep the last ratio, never fake a 0
	}
	used := 1.0 - float64(st.Bavail)/float64(st.Blocks)
	if st.Files > 0 && st.Ffree <= st.Files {
		if iu := 1.0 - float64(st.Ffree)/float64(st.Files); iu > used {
			used = iu
		}
	}
	c.d.DevShmUsedRatio = used
}
