// cni_netns.go — the orphan /run/netns/cni-* reaper (hardened
// orphan-sandbox-netns): CNI plugins pin each pod sandbox's network namespace by
// bind-mounting its nsfs file at /run/netns/cni-<id>; a teardown
// that dies mid-DEL leaks the mount, and only a file whose nsfs
// inode NO live process (or live containerd task) still references
// is lazily unmounted + removed after the confirm window.
package guards

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

const (
	// defaultNetnsDir is the host /run/netns mount — the CNI
	// netns-file leak reaper scans cni-* entries here.
	// cniNetnsMinAge is the orphan CNI netns confirmation age
	// (the orphan-netns reaper).
	cniNetnsMinAge = 30 * time.Minute
	// cniNetnsMaxReapPerCycle bounds the per-cycle umount blast
	// radius (orphan-sandbox-netns) — a mass CNI DEL failure can leak dozens of
	// netns mounts at once; the reaper drains them at a fixed rate
	// rather than stalling the check budget on one cycle.
	cniNetnsMaxReapPerCycle = 10
)

// --- Check: orphan CNI netns reaper (hardened orphan-sandbox-netns) ---
// CNI plugins pin each pod sandbox's network namespace by
// bind-mounting its nsfs file at /run/netns/cni-<id>. A pod teardown
// that dies mid-DEL (crash, OOM kill, kubelet restart) leaks the
// mount: the file outlives the namespace, and `ip netns` listings
// accumulate dead entries that confuse operators and slow CNI
// scans — worse, a leaked net_namespace slab keeps Cilium IPAM from
// reclaiming the pod IP and pins any hostPort it held. The reaper
// stats every cni-* file — the nsfs inode is the namespace's
// identity, shared with /proc/<pid>/ns/net for every process still
// inside it — and only a file whose inode NO live process
// references is an orphan. Confirmation is the
// cni-netns-seen-<name> two-pass marker (veth-seen-* parity): first
// sighting records the epoch, and only a file still unreferenced
// >= cniNetnsMinAge later is lazily unmounted + removed. The umount
// runs through the systemd nsenter wrapper so the HOST mount
// namespace is the one modified; the file removal uses the /host
// view (NetnsDir). orphan-sandbox-netns adds three qualifiers to the reap
// itself: the file mtime must be older than the confirm window
// (a just-created mount point the sweep raced is never an
// orphan), the containerd task map must not show a live task
// still inside the netns, and reaps cap at
// cniNetnsMaxReapPerCycle per cycle. The scan runs on every
// worker — Cilium AND Calico pin netns the same way.

// netnsInode stats a netns file and returns the nsfs inode — the
// identity /proc/<pid>/ns/net entries share for the same network
// namespace (bind-mounted copies keep the inode).
func netnsInode(path string) (uint64, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Ino, true
}

// liveNetnsInodes collects the nsfs inode of every live process's
// network namespace. Unreadable entries are skipped — a pid that
// vanished mid-scan is not a reference.
func liveNetnsInodes(d *wdeps.Deps, pids []int) map[uint64]bool {
	out := map[uint64]bool{}
	for _, pid := range pids {
		if ino, ok := netnsInode(d.Proc.File(pid, "ns", "net")); ok {
			out[ino] = true
		}
	}
	return out
}

// netnsHeldByLiveTask reports whether any containerd task with a
// live init pid still sits inside the netns inode — the
// containerd-side half of the orphan-sandbox-netns orphan verdict (a live task
// pins the sandbox netns even when the /proc sweep raced it).
func netnsHeldByLiveTask(d *wdeps.Deps, tasks map[string][]wdeps.CtrTask,
	ino uint64) bool {

	for _, ts := range tasks {
		for _, t := range ts {
			if !t.Live || t.PID <= 0 {
				continue
			}
			if tino, ok := netnsInode(d.Proc.File(t.PID, "ns", "net")); ok &&
				tino == ino {
				return true
			}
		}
	}
	return false
}

// CNINetnsCheck is the orphan /run/netns/cni-* reaper as a Check.
type CNINetnsCheck struct{ d *wdeps.Deps }

// Name returns the check label / WD_SIG key.
func (c *CNINetnsCheck) Name() string { return wdeps.CheckCNINetns }

// Run executes one cni-netns-gc round.
func (c *CNINetnsCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckCNINetns) {
		return
	}
	entries, err := os.ReadDir(c.d.Cfg.Net.NetnsDir)
	if err != nil {
		if os.IsNotExist(err) {
			// No netns dir at all (non-CNI node, unmounted /run) —
			// prune stale markers and go quiet.
			pruneCNINetnsMarkers(c.d, nil)
			c.d.CycleResult(wdeps.CheckCNINetns, "ok")
			return
		}
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cni-netns-gc read %s failed: %v — scan skipped",
			c.d.Cfg.Net.NetnsDir, err))
		c.d.CycleResult(wdeps.CheckCNINetns, "abort")
		return
	}
	// Collect cni-* candidates first — the /proc ns/net stat sweep
	// only runs when there is something to check.
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "cni-") {
			continue
		}
		names = append(names, e.Name())
	}
	if len(names) == 0 {
		pruneCNINetnsMarkers(c.d, nil)
		c.d.CycleResult(wdeps.CheckCNINetns, "ok")
		return
	}
	live := liveNetnsInodes(c.d, e.PidsOnce())
	seen := map[string]bool{}
	reaped := 0
	for _, name := range names {
		seen[name] = true
		path := filepath.Join(c.d.Cfg.Net.NetnsDir, name)
		ino, ok := netnsInode(path)
		if !ok {
			continue // vanished or unreadable — next cycle re-reads
		}
		if live[ino] {
			// A live process still sits in this netns — the mount
			// is real. Drop any stale marker so a later orphan
			// episode re-arms the full confirmation window.
			_ = os.Remove(filepath.Join(
				c.d.Cfg.WatchdogStateDir, "cni-netns-seen-"+name))
			continue
		}
		marker := "cni-netns-seen-" + name
		if !c.d.StateFileExists(marker) {
			c.d.State.RateSpend(marker)
			c.d.State.AppendLog(fmt.Sprintf(
				"cni-netns-gc: orphan netns candidate %s - no live process, confirm in %dm",
				name, int(cniNetnsMinAge.Minutes())))
			continue
		}
		if !c.d.State.RateOK(marker, cniNetnsMinAge) {
			continue
		}
		// Re-stat before acting: the inode must STILL be
		// unreferenced (a process may have joined the netns since
		// the snapshot; `live` is a per-cycle map).
		ino2, ok2 := netnsInode(path)
		if !ok2 || live[ino2] {
			continue
		}
		// orphan-sandbox-netns: the netns file itself must be older than the
		// confirm window — a just-created mount point whose sweep
		// raced the CNI ADD is not an orphan no matter what the
		// inode check says.
		if fi, err := os.Stat(path); err != nil ||
			c.d.Cfg.Seams.Host.Clock.Now().Sub(fi.ModTime()) < cniNetnsMinAge {
			continue
		}
		// orphan-sandbox-netns: the containerd task map is the stronger liveness
		// verdict — a live task pins its sandbox netns even when
		// the pid sweep raced it. An unreadable map makes "no
		// live task" unverifiable → fail closed, retry next cycle.
		if e.TasksOnce != nil {
			tasks, complete := e.TasksOnce()
			if !complete || netnsHeldByLiveTask(c.d, tasks, ino2) {
				continue
			}
		}
		if reaped >= cniNetnsMaxReapPerCycle {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: cni-netns-gc reap cap %d reached — remaining orphans drain next cycle",
				cniNetnsMaxReapPerCycle))
			break
		}
		reapCNINetns(c.d, ctx, name)
		reaped++
	}
	pruneCNINetnsMarkers(c.d, seen)
	c.d.CycleResult(wdeps.CheckCNINetns, "ok")
}

// reapCNINetns lazily unmounts the orphan netns bind-mount inside
// the HOST mount namespace, then removes the file under the /host
// view. The marker is dropped only after the umount succeeds — a
// failed umount keeps the confirmation so the next cycle retries.
func reapCNINetns(d *wdeps.Deps, ctx context.Context, name string) {
	if d.Cfg.Systemd == nil {
		d.State.AppendLog(fmt.Sprintf(
			"suspect: cni-netns-gc orphan netns %s confirmed but no systemd client — skip umount",
			name))
		return
	}
	// The umount path is the HOST's /run/netns — NOT NetnsDir,
	// which is the /host-prefixed filesystem view used for scans.
	out, err := d.Cfg.Systemd.Exec(ctx, "umount", "-l",
		"/run/netns/"+name)
	if err != nil {
		d.State.AppendLog(fmt.Sprintf(
			"suspect: cni-netns-gc umount /run/netns/%s failed: %v (%s) — keeping marker",
			name, err, strings.TrimSpace(out)))
		return
	}
	if rerr := os.Remove(filepath.Join(d.Cfg.Net.NetnsDir, name)); rerr != nil &&
		!os.IsNotExist(rerr) {
		// The mount IS detached — the dangerous half is done; a
		// leftover plain file re-arms as a fresh candidate next
		// cycle rather than looping a doomed umount.
		d.State.AppendLog(fmt.Sprintf(
			"suspect: cni-netns-gc rm %s failed: %v — mount detached, file remains",
			filepath.Join(d.Cfg.Net.NetnsDir, name), rerr))
	}
	_ = os.Remove(filepath.Join(
		d.Cfg.WatchdogStateDir, "cni-netns-seen-"+name))
	d.State.AppendLog(fmt.Sprintf(
		"ACTION: cni-netns-gc reaped orphan netns %s - unmounted + removed (no live process >%dm)",
		name, int(cniNetnsMinAge.Minutes())))
	d.Actions.WithLabelValues(wdeps.CheckCNINetns, "umount_rm").Inc()
}

// pruneCNINetnsMarkers drops cni-netns-seen-* markers whose netns
// file vanished — a file that reappeared referenced or was cleaned
// up by other means must not keep a stale confirmation armed.
func pruneCNINetnsMarkers(d *wdeps.Deps, seen map[string]bool) {
	ms, err := filepath.Glob(filepath.Join(
		d.Cfg.WatchdogStateDir, "cni-netns-seen-*"))
	if err != nil {
		return
	}
	for _, m := range ms {
		name := strings.TrimPrefix(filepath.Base(m), "cni-netns-seen-")
		if seen != nil && seen[name] {
			continue
		}
		if _, err := os.Stat(filepath.Join(d.Cfg.Net.NetnsDir, name)); err != nil {
			_ = os.Remove(m)
		}
	}
}
