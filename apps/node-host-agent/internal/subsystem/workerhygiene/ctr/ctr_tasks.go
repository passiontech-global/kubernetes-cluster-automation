// ctr_tasks.go — the 31 ctr-tasks check: wedged containerd task
// dirs and orphan shims, the filesystem port of the shell's
// ctr-based checks (no ctr socket needed in the agent pod). The
// shim-scope machinery it shares with the ctr-meta sweep lives in
// ctr_shims.go; the image healer is ctr_images.go and the ingest GC
// is ctr_ingest_gc.go.
package ctr

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

var (
	// cri.container-type=sandbox inside task config.json — pause
	// tasks legitimately lack log.json (shell grep -q parity).
	sandboxTypeRe = regexp.MustCompile(`cri\.container-type[^,]*sandbox`)
	// hexTaskIDRe — a CRI task id is 64 lowercase hex (the container
	// ID containerd mints). Anything else under the task root is not
	// a task dir, and the wedged-cleanup path is kill-shaped: it
	// SIGKILLs init.pid and every process whose cmdline CONTAINS the
	// id (pkill -f parity). Gate the id first, or a stray dir named
	// "kubelet" would make that scan SIGKILL the kubelet itself.
	hexTaskIDRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// CtrTasksCheck cleans wedged containerd task dirs and orphan shims —
// the filesystem port of the shell's ctr-based checks (no ctr socket
// needed in the agent pod):
//
//   - Orphan shim: live containerd-shim-runc-v2 process scoped to THIS
//     containerd (-address names the k0s socket; -address/-namespace
//     absent or foreign → not ours, never touched) whose -id task dir
//     is gone from its namespace's task root AND the sandbox root,
//     proc age >=5m → SIGKILL (cap MaxShimKill/cycle).
//   - Wedged task dir: init.pid unreadable/dead/zombie, OR init alive
//     but log.json missing on a non-sandbox task — confirmed via a
//     wedged-seen-<id> marker persisting >=5m (the marker replaces
//     "dead >=5m": dir age can't distinguish a just-exited init from
//     a real wedge). Confirmed → SIGKILL live init + any process
//     holding the id, then remove the dir (cap MaxCtrTaskClean/cycle).
type CtrTasksCheck struct{ d *wdeps.Deps }

// Name returns the check label / WD_SIG key.
func (c *CtrTasksCheck) Name() string { return wdeps.CheckCtrTasks }

// Run executes one ctr-tasks round.
func (c *CtrTasksCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckCtrTasks) {
		return
	}
	entries, err := os.ReadDir(c.d.Cfg.CtrTaskRoot)
	if err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: ctr task root %s unreadable: %v — ctr-tasks check skipped",
			c.d.Cfg.CtrTaskRoot, err))
		c.d.CycleResult(wdeps.CheckCtrTasks, "abort")
		return
	}
	liveDirs := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			liveDirs[e.Name()] = true
		}
	}
	sbDirs := map[string]bool{}
	if es, err := os.ReadDir(c.d.Cfg.SandboxCtlRoot); err == nil {
		for _, e := range es {
			if e.IsDir() {
				sbDirs[e.Name()] = true
			}
		}
	}
	// Phase B — orphan shims (shell ran this FIRST: a shim whose task
	// dir vanished makes every shim-mediated kill fail forever). The
	// reaper is scoped by -address to the containerd that owns
	// CtrTaskRoot: a second containerd on the same host (host dockerd's
	// moby shims, a concourse worker's own daemon) has task dirs under
	// a DIFFERENT root, so its shims used to all read "orphan" and get
	// SIGKILLed every sweep — cold-restarting every foreign container
	// and saturating the node (NodeOverloaded incident 2026-11).
	nShim := 0
	// shimEscalated records whether phase B escalated any orphan
	// shim into the shared pod-teardown-wedged latch this round —
	// a completed scan with no escalation releases our owner hold
	// (shim reaped or recovered since the last cycle). killCapHit
	// marks an incomplete scan: the kill budget cut the pid walk
	// short, so unexamined shims may still be wedged and the hold
	// must be kept (inconclusive, never a flap).
	shimEscalated := false
	killCapHit := false
	// W16-KR2: every shim id scoped to OUR containerd this round —
	// a sandbox dir whose id a live shim holds is not an orphan,
	// whatever the task-dir scan says.
	shimIDs := map[string]bool{}
	pids := e.PidsOnce()
	for _, pid := range pids {
		if nShim >= c.d.Cfg.Ctr.MaxShimKill {
			killCapHit = true
			break
		}
		argv := c.d.Proc.Cmdline(pid)
		joined := strings.Join(argv, " ")
		if !strings.Contains(joined, "containerd-shim-runc-v2") {
			continue
		}
		ns, sid, inScope := ctrShimScope(c.d, argv)
		if !inScope {
			continue
		}
		shimIDs[sid] = true
		if ns == "k8s.io" {
			if liveDirs[sid] || sbDirs[sid] {
				continue
			}
		} else {
			// Foreign namespace on OUR containerd (e.g. a `ctr -n`
			// task): resolve the dir under the sibling namespace
			// root — only a genuinely missing dir is an orphan.
			if _, err := os.Stat(shimTaskDir(c.d, ns, sid)); err == nil ||
				sbDirs[sid] {
				continue
			}
		}
		if c.d.ProcAge(pid) < 5*time.Minute {
			continue
		}
		// W12-KR2: an orphan shim already wedged in D
		// (uninterruptible) or Z (zombie whose reaper never ran)
		// state cannot be SIGKILLed away — the signal pends inside
		// the kernel or lands on a corpse. Escalate the confirmed
		// orphan into the pod-teardown-wedged latch so the
		// node-level NHC→SNR remediation path sees the wedge
		// (kubelet/containerd teardown is dead by definition).
		// EnterFrom, not Enter: pod-teardown shares this latch and
		// must not clear OUR hold when its own pod scan finds
		// nothing wedged — multi-owner semantics keep the file
		// latched while ANY producer still sees the wedge.
		if state, _, ok := c.d.ProcStatStatePPID(pid); ok &&
			(state == "D" || state == "Z") {
			shimEscalated = true
			c.d.State.EnterFrom(latchdefs.LatchPodTeardownWedged,
				wdeps.CheckCtrTasks, fmt.Sprintf(
					"unkillable-orphan-shim pid=%d id=%.12s state=%s",
					pid, sid, state))
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: ctr-tasks orphan shim pid=%d id=%.12s state=%s — SIGKILL cannot clear it, escalated to pod-teardown-wedged",
				pid, sid, state))
			c.d.Actions.WithLabelValues(wdeps.CheckCtrTasks, "shim_escalate").Inc()
			continue
		}
		c.d.State.AppendLog(fmt.Sprintf(
			"ACTION: kill orphan shim pid=%d id=%.12s ns=%s - task dir missing",
			pid, sid, ns))
		if err := c.d.Cfg.Seams.Host.KillFn(pid, syscall.SIGKILL); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: kill orphan shim pid=%d failed: %v", pid, err))
		}
		nShim++
		c.d.Actions.WithLabelValues(wdeps.CheckCtrTasks, "shim_kill").Inc()
	}
	// Prune wedged-seen markers for dirs that disappeared between
	// runs (teardown finished or a previous cleanup won the race).
	if ms, err := filepath.Glob(
		filepath.Join(c.d.Cfg.WatchdogStateDir, "wedged-seen-*")); err == nil {
		for _, m := range ms {
			if !liveDirs[strings.TrimPrefix(filepath.Base(m), "wedged-seen-")] {
				_ = os.Remove(m)
			}
		}
	}
	// Scan task dirs → wedge candidates confirmed by a >=5m marker.
	var wedged []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id := e.Name()
		if !hexTaskIDRe.MatchString(id) {
			// Not a CRI task id — neither pid-scan nor SIGKILL
			// anything for it (the cleanup below is kill-shaped
			// over the id string; see hexTaskIDRe).
			continue
		}
		d := filepath.Join(c.d.Cfg.CtrTaskRoot, id)
		marker := "wedged-seen-" + id
		dead := false
		pidData, err := os.ReadFile(filepath.Join(d, "init.pid"))
		ipid, _ := strconv.Atoi(strings.TrimSpace(string(pidData)))
		if err != nil || ipid <= 0 || !c.d.PidLive(ipid) {
			// Unreadable init.pid = half-written dir (containerd
			// restart mid-create) or an exited init — both are
			// wedge-shaped, but a task STARTING writes init.pid a
			// few seconds after the dir: the 5m marker window absorbs
			// that race.
			dead = true
		} else if _, err := os.Stat(filepath.Join(d, "log.json")); err != nil {
			// init alive but log.json gone: runc kill fails with
			// ENOENT forever on non-sandbox tasks (pause tasks have
			// no log.json legitimately); unreadable config.json =
			// wreckage → dead too (grep miss parity).
			if cfg, err := os.ReadFile(filepath.Join(d, "config.json")); err != nil ||
				!sandboxTypeRe.Match(cfg) {
				dead = true
			}
		}
		if !dead {
			// Recovered between runs → cancel the pending confirm.
			_ = os.Remove(filepath.Join(c.d.Cfg.WatchdogStateDir, marker))
			continue
		}
		if !c.d.StateFileExists(marker) {
			c.d.State.RateSpend(marker)
			c.d.State.AppendLog(fmt.Sprintf("ctr-task-dead candidate %.12s - confirm next run", id))
			continue
		}
		if !c.d.State.RateOK(marker, 5*time.Minute) {
			continue
		}
		wedged = append(wedged, d)
	}
	nClean := 0
	for _, d := range wedged {
		id := filepath.Base(d)
		if nClean >= c.d.Cfg.Ctr.MaxTaskClean {
			c.d.State.AppendLog(fmt.Sprintf("suspect: "+latchdefs.ReasonCtrTaskWedged+
				" still pending cap=%d",
				c.d.Cfg.Ctr.MaxTaskClean))
			break
		}
		// Marker removal only once the dir is actually being
		// cleaned: a dir dropped by the cap must KEEP its
		// confirmed marker — removing it first made over-cap
		// dirs re-confirm for another 5m forever.
		_ = os.Remove(filepath.Join(c.d.Cfg.WatchdogStateDir, "wedged-seen-"+id))
		// Live init with missing log.json → SIGKILL it first so the
		// shim can drain and exit (shell's kill -9 init).
		if pidData, err := os.ReadFile(filepath.Join(d, "init.pid")); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(pidData))); err == nil &&
				pid > 0 && c.d.PidLive(pid) {
				c.d.State.AppendLog(fmt.Sprintf(
					"ACTION: kill -9 init %d of %.12s - log.json missing", pid, id))
				if err := c.d.Cfg.Seams.Host.KillFn(pid, syscall.SIGKILL); err != nil {
					c.d.State.AppendLog(fmt.Sprintf(
						"suspect: kill init %d of %.12s failed: %v", pid, id, err))
				}
			}
		}
		// pkill -9 -f "$id" parity: kill shim/runc leftovers holding
		// the task id, then remove the dir — containerd GCs the task
		// record once the shim is gone.
		for _, pid := range c.d.PidsWithCmdline(id, pids) {
			if err := c.d.Cfg.Seams.Host.KillFn(pid, syscall.SIGKILL); err != nil {
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: kill leftover pid=%d holding task %.12s failed: %v",
					pid, id, err))
			}
		}
		c.d.State.AppendLog(fmt.Sprintf("ACTION: rm wedged task dir %.12s - dead >=5m", id))
		// runc create mounts the bundle rootfs (overlay on
		// the snapshot) before exec — RemoveAll on a wedged task dir
		// then hits EBUSY and leaves the mountpoint leaking in the
		// host mountinfo table. Lazily unmount it in the HOST mount
		// namespace (systemd nsenter wrapper) first; failure is
		// logged and the removal is still attempted (best effort).
		c.lazyUnmountRootfs(ctx, d, id)
		if err := os.RemoveAll(d); err != nil {
			c.d.State.AppendLog(fmt.Sprintf("suspect: rm task dir %.12s failed: %v", id, err))
		}
		nClean++
		c.d.Actions.WithLabelValues(wdeps.CheckCtrTasks, "rm_dir").Inc()
	}
	// W16-KR2 — orphan CRI sandbox reaper: SandboxCtlRoot dirs with
	// neither a task dir under CtrTaskRoot nor a live shim holding
	// the id. Two-phase like the wedged dirs — sandbox-orphan-seen-<id>
	// marker on first observation, removal only once the marker is
	// >=30m old AND the dir ModTime is >=30m old (a sandbox dir
	// mid-creation has a fresh ModTime; the marker alone can't tell
	// creation from abandonment). A capped shim phase skips the
	// whole sweep: an unexamined shim may still hold a candidate id.
	if !killCapHit {
		const orphanSandboxAge = 30 * time.Minute
		now := c.d.Cfg.Seams.Host.Clock.Now()
		for id := range sbDirs {
			if liveDirs[id] || shimIDs[id] {
				continue
			}
			d := filepath.Join(c.d.Cfg.SandboxCtlRoot, id)
			info, err := os.Stat(d)
			if err != nil {
				continue
			}
			if now.Sub(info.ModTime()) < orphanSandboxAge {
				continue
			}
			marker := "sandbox-orphan-seen-" + id
			if !c.d.StateFileExists(marker) {
				c.d.State.RateSpend(marker)
				c.d.State.AppendLog(fmt.Sprintf(
					"orphan sandbox candidate %.12s - no task dir, no shim - confirm next run", id))
				continue
			}
			if !c.d.State.RateOK(marker, orphanSandboxAge) {
				continue
			}
			if nClean >= c.d.Cfg.Ctr.MaxTaskClean {
				c.d.State.AppendLog(fmt.Sprintf("suspect: orphan sandbox dir still pending cap=%d",
					c.d.Cfg.Ctr.MaxTaskClean))
				break
			}
			_ = os.Remove(filepath.Join(c.d.Cfg.WatchdogStateDir, marker))
			if err := os.RemoveAll(d); err != nil {
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: rm orphan sandbox dir %.12s failed: %v", id, err))
				continue
			}
			c.d.State.AppendLog(fmt.Sprintf(
				"ACTION: rm orphan sandbox dir %.12s - no task dir, no shim, dir+marker >=30m", id))
			nClean++
			c.d.Actions.WithLabelValues(wdeps.CheckCtrTasks, "rm_orphan_sandbox").Inc()
		}
	}
	// Prune orphan-sandbox markers whose sandbox dir disappeared
	// between runs (containerd GC'd it or a previous cleanup won).
	if ms, err := filepath.Glob(filepath.Join(c.d.Cfg.WatchdogStateDir,
		"sandbox-orphan-seen-*")); err == nil {
		for _, m := range ms {
			if !sbDirs[strings.TrimPrefix(filepath.Base(m), "sandbox-orphan-seen-")] {
				_ = os.Remove(m)
			}
		}
	}
	// Full scan with no D/Z orphan shim left → release our hold on
	// the shared latch (pod-teardown's own hold, if any, is
	// untouched). A capped or escalated scan keeps it.
	if !shimEscalated && !killCapHit {
		c.d.State.ExitFrom(latchdefs.LatchPodTeardownWedged,
			wdeps.CheckCtrTasks, nil)
	}
	c.d.CycleResult(wdeps.CheckCtrTasks, "ok")
}

// lazyUnmountRootfs lazily unmounts <d>/rootfs in the HOST mount
// namespace when it exists — the systemd exec seam runs
// nsenter -m wrapped, so the umount path must be the host-side view
// (the /host DaemonSet prefix stripped; fixture paths carry no
// prefix and pass through verbatim). No systemd client → log-only,
// the caller's RemoveAll still runs best-effort.
func (c *CtrTasksCheck) lazyUnmountRootfs(ctx context.Context, d, id string) {
	rootfs := filepath.Join(d, "rootfs")
	if _, err := os.Stat(rootfs); err != nil {
		return // not mounted (or already gone) — nothing to unmount
	}
	host := strings.TrimPrefix(rootfs, "/host")
	if c.d.Cfg.Systemd == nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: ctr-tasks rootfs %s of task %.12s still mounted but no systemd client — skip umount",
			host, id))
		return
	}
	out, err := c.d.Cfg.Systemd.Exec(ctx, "umount", "-l", host)
	if err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: ctr-tasks umount -l %s failed: %v (%s)",
			host, err, strings.TrimSpace(out)))
		return
	}
	c.d.State.AppendLog(fmt.Sprintf(
		"ACTION: umount -l rootfs of task %.12s - stale mount cleared before rm", id))
	c.d.Actions.WithLabelValues(wdeps.CheckCtrTasks, "umount_rootfs").Inc()
}
