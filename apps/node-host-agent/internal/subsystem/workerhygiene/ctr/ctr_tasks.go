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
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
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
	// podCgroupSubstr scopes the init-kill identity check: a
	// container init lives under the kubepods cgroup tree, so a
	// pid recycled onto an unrelated host process fails the check
	// and is never signalled.
	podCgroupSubstr = "kubepods"
)

// runtimeKillComm reports whether comm names a containerd runtime
// process the wedged-task sweeps may SIGKILL — shim or runc only.
// /proc stat comm truncates at TASK_COMM_LEN-1 (15 chars), so
// "containerd-shim-runc-v2" surfaces as "containerd-shim": the
// prefix covers all three spellings. A cmdlines-only match is not
// enough — `sh -c '... <task-id> ...'` or a monitor holding the id
// in argv must never eat the signal.
func runtimeKillComm(comm string) bool {
	return comm == "runc" || strings.HasPrefix(comm, "containerd-shim")
}

// commKillable reads /proc/<pid>/stat's comm field and applies the
// runtimeKillComm gate — ok=false (unreadable stat, no comm) means
// "cannot prove it is a runtime process" → do NOT kill.
func (c *CtrTasksCheck) commKillable(pid int) bool {
	st, ok := c.d.Proc.Stat(pid)
	return ok && st.HasComm && runtimeKillComm(st.Comm)
}

// shimReadInconclusive reports whether a /proc/<pid> stat or cmdline read
// failed for a non-ENOENT reason without touching mm-backed cmdline on D/Z
// processes.
func (c *CtrTasksCheck) shimReadInconclusive(pid int) bool {
	st, sok := c.d.Proc.Stat(pid)
	if !sok || len(st.Fields) == 0 {
		return procFileReadNonENOENT(c.d.Proc.File(pid, "stat"))
	}
	if st.Fields[0] == "D" || st.Fields[0] == "Z" || st.Fields[0] == "X" || st.Fields[0] == "x" {
		return false
	}
	return procFileReadNonENOENT(c.d.Proc.File(pid, "cmdline"))
}

// verifyHostRootShim confirms fail-closed that a containerd-shim candidate
// belongs to the host root namespace (never inside a kubepods cgroup) and
// runs as root (real and effective UID 0). Non-ENOENT read errors mark the
// scan inconclusive so sandbox reaping and latch release hold off.
func verifyHostRootShim(d *wdeps.Deps, pid int) (ok, inconclusive bool) {
	cgData, err := os.ReadFile(d.Proc.File(pid, "cgroup"))
	if err != nil {
		return false, !os.IsNotExist(err)
	}
	cg := strings.TrimSpace(string(cgData))
	if cg == "" || strings.Contains(cg, podCgroupSubstr) {
		return false, false
	}
	stData, err := os.ReadFile(d.Proc.File(pid, "status"))
	if err != nil {
		return false, !os.IsNotExist(err)
	}
	for line := range strings.SplitSeq(string(stData), "\n") {
		if rest, found := strings.CutPrefix(line, "Uid:"); found {
			fields := strings.Fields(rest)
			return len(fields) >= 2 && fields[0] == "0" && fields[1] == "0", false
		}
	}
	return false, false
}

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
	if es, err := os.ReadDir(c.d.Cfg.SandboxCtlRoot); err != nil {
		if !os.IsNotExist(err) {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: sandbox ctl root %s unreadable: %v — ctr-tasks check skipped",
				c.d.Cfg.SandboxCtlRoot, err))
			c.d.CycleResult(wdeps.CheckCtrTasks, "abort")
			return
		}
	} else {
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
	shimScanInconclusive := false
	taskReadErr := false
	// cri-sandbox-reaper: every shim id scoped to OUR containerd this round —
	// a sandbox dir whose id a live shim holds is not an orphan,
	// whatever the task-dir scan says.
	shimIDs := map[string]bool{}
	pids, pidsOK := c.d.CyclePIDs(e)
	if !pidsOK {
		c.d.State.AppendLog("suspect: ctr-tasks /proc scan inconclusive — skipped")
		c.d.CycleResult(wdeps.CheckCtrTasks, "inconclusive")
		return
	}
	for _, pid := range pids {
		if nShim >= c.d.Cfg.Ctr.MaxShimKill {
			killCapHit = true
			break
		}
		// Comm pre-filter: only containerd-shim* pids can scope —
		// the prefix matches dzShimScope's own gate, so D/Z-state
		// shims still reach the fd-table fallback while every
		// other pid skips the mm-backed cmdline read. An
		// unidentifiable comm falls through to the old path.
		if comm, known := procCommKnown(e, c.d, pid); known &&
			!strings.HasPrefix(comm, "containerd-shim") {
			continue
		}
		var argv []string
		var origStartTime string
		if st, ok := c.d.Proc.Stat(pid); !ok || len(st.Fields) == 0 {
			if procFileReadNonENOENT(c.d.Proc.File(pid, "stat")) {
				shimScanInconclusive = true
			}
			continue
		} else {
			origStartTime = statStartTime(st)
			switch st.Fields[0] {
			case "X", "x":
				continue
			case "D", "Z":
				// Skip mm-backed Cmdline entirely on D/Z tasks.
			default:
				argv = c.d.Proc.Cmdline(pid)
			}
		}
		joined := strings.Join(argv, " ")
		var ns, sid string
		var inScope bool
		switch {
		case strings.Contains(joined, "containerd-shim-runc-v2"):
			ns, sid, inScope = ctrShimScope(c.d, argv)
		case len(argv) == 0:
			// D/Z-state (or raced-exit) procs return no argv —
			// cmdline is mm-backed and the read would hang on
			// mmap_lock. A wedged orphan shim is exactly the case
			// this reaper must still see: comm + the shim's own
			// fd table replace the unreadable cmdline.
			var dzInc bool
			ns, sid, inScope, dzInc = dzShimScopeChecked(c.d, pid)
			if dzInc {
				shimScanInconclusive = true
			} else if !inScope && c.shimReadInconclusive(pid) {
				shimScanInconclusive = true
			}
		}
		if !inScope {
			continue
		}
		shimOK, shimInc := verifyHostRootShim(c.d, pid)
		if shimInc {
			shimScanInconclusive = true
		}
		if !shimOK {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: containerd-shim candidate pid=%d id=%.12s failed host-root verification — skipped",
				pid, sid))
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
				!os.IsNotExist(err) || sbDirs[sid] {
				continue
			}
		}
		if c.d.ProcAge(pid) < 5*time.Minute {
			continue
		}
		// orphan-sandbox-netns: an orphan shim already wedged in D
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
		if !c.commKillable(pid) {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: orphan shim candidate pid=%d comm not a runtime process — kill refused",
				pid))
			continue
		}
		if c.d.HoldLocalAction(ctx) {
			c.d.State.AppendLog(fmt.Sprintf(
				"cleanup: ctr-tasks orphan shim kill pid=%d held — cluster maintenance in progress",
				pid))
			continue
		}
		// Re-verify process identity and starttime immediately before
		// SIGKILL to close the PID-reuse TOCTOU window across HoldLocalAction.
		if curSt, ok := c.d.Proc.Stat(pid); !ok || len(curSt.Fields) == 0 ||
			curSt.Fields[0] == "D" || curSt.Fields[0] == "Z" ||
			curSt.Fields[0] == "X" || curSt.Fields[0] == "x" ||
			(origStartTime != "" && statStartTime(curSt) != origStartTime) ||
			!c.commKillable(pid) {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: orphan shim candidate pid=%d identity changed before kill — skipped",
				pid))
			continue
		}
		if curOK, _ := verifyHostRootShim(c.d, pid); !curOK {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: orphan shim candidate pid=%d failed host-root re-check before kill — skipped",
				pid))
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
	c.d.State.PruneMarkers("wedged-seen-", func(id string) bool {
		return liveDirs[id]
	})
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
		if err != nil {
			if !os.IsNotExist(err) {
				taskReadErr = true
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: ctr task %.12s init.pid unreadable: %v — skipped (marker preserved)",
					id, err))
				continue
			}
			// ENOENT init.pid = half-written dir (containerd restart
			// mid-create) — confirmed after the 5m marker window.
			dead = true
		} else {
			ipid, _ := strconv.Atoi(strings.TrimSpace(string(pidData)))
			if ipid <= 0 || !c.d.PidLive(ipid) {
				dead = true
			} else if _, lerr := os.Stat(filepath.Join(d, "log.json")); lerr != nil {
				if !os.IsNotExist(lerr) {
					taskReadErr = true
					c.d.State.AppendLog(fmt.Sprintf(
						"suspect: ctr task %.12s log.json unreadable: %v — skipped (marker preserved)",
						id, lerr))
					continue
				}
				// init alive but log.json gone: runc kill fails with
				// ENOENT forever on non-sandbox tasks (pause tasks have
				// no log.json legitimately); missing config.json =
				// wreckage, but non-ENOENT config.json error must abort.
				cfg, cerr := os.ReadFile(filepath.Join(d, "config.json"))
				if cerr != nil {
					if !os.IsNotExist(cerr) {
						taskReadErr = true
						c.d.State.AppendLog(fmt.Sprintf(
							"suspect: ctr task %.12s config.json unreadable: %v — skipped (marker preserved)",
							id, cerr))
						continue
					}
					dead = true
				} else if !sandboxTypeRe.Match(cfg) {
					dead = true
				}
			}
		}
		if !dead {
			// Recovered between runs → cancel the pending confirm.
			c.d.State.ClearBudget(marker)
			continue
		}
		firstSeen, confirmed := c.d.State.ConfirmMarker(marker, 5*time.Minute)
		if firstSeen {
			c.d.State.AppendLog(fmt.Sprintf("ctr-task-dead candidate %.12s - confirm next run", id))
			continue
		}
		if !confirmed {
			continue
		}
		wedged = append(wedged, d)
	}
	nClean := 0
	var killablePIDs []int
	killableBuilt := false
	for _, d := range wedged {
		id := filepath.Base(d)
		if nClean >= c.d.Cfg.Ctr.MaxTaskClean {
			c.d.State.AppendLog(fmt.Sprintf("suspect: "+latchdefs.ReasonCtrTaskWedged+
				" still pending cap=%d",
				c.d.Cfg.Ctr.MaxTaskClean))
			break
		}
		if c.d.HoldLocalAction(ctx) {
			c.d.State.AppendLog(fmt.Sprintf(
				"cleanup: ctr-tasks wedged task cleanup %.12s held — cluster maintenance in progress",
				id))
			break
		}
		if pidData, err := os.ReadFile(filepath.Join(d, "init.pid")); err != nil && !os.IsNotExist(err) {
			taskReadErr = true
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: ctr task %.12s init.pid unreadable before cleanup: %v — skipped",
				id, err))
			continue
		} else {
			// Marker removal only once the dir is actually being
			// cleaned: a dir dropped by the cap must KEEP its
			// confirmed marker — removing it first made over-cap
			// dirs re-confirm for another 5m forever.
			c.d.State.ClearBudget("wedged-seen-" + id)
			if err == nil {
				if pid, err := strconv.Atoi(strings.TrimSpace(string(pidData))); err == nil &&
					pid > 0 && c.d.PidLive(pid) {
					if !c.d.Proc.CgroupContains(pid, podCgroupSubstr) {
						c.d.State.AppendLog(fmt.Sprintf(
							"suspect: init pid=%d of %.12s not in a pod cgroup — kill refused (recycled pid?)",
							pid, id))
					} else {
						c.d.State.AppendLog(fmt.Sprintf(
							"ACTION: kill -9 init %d of %.12s - log.json missing", pid, id))
						if err := c.d.Cfg.Seams.Host.KillFn(pid, syscall.SIGKILL); err != nil {
							c.d.State.AppendLog(fmt.Sprintf(
								"suspect: kill init %d of %.12s failed: %v", pid, id, err))
						}
					}
				}
			}
		}
		// pkill -9 -f "$id" parity: kill shim/runc leftovers holding
		// the task id, then remove the dir — containerd GCs the task
		// record once the shim is gone. Filter commKillable FIRST so
		// PidsWithCmdline only reads /proc/<pid>/cmdline for
		// runc/containerd-shim* processes instead of touching every
		// process's mm (including D-state tasks) on the node.
		if !killableBuilt {
			killableBuilt = true
			for _, pid := range pids {
				if c.commKillable(pid) {
					killablePIDs = append(killablePIDs, pid)
				}
			}
		}
		for _, pid := range c.d.PidsWithCmdline(id, killablePIDs) {
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
	// cri-sandbox-reaper — orphan CRI sandbox reaper: SandboxCtlRoot dirs with
	// neither a task dir under CtrTaskRoot nor a live shim holding
	// the id. Two-phase like the wedged dirs — sandbox-orphan-seen-<id>
	// marker on first observation, removal only once the marker is
	// >=30m old AND the dir ModTime is >=30m old (a sandbox dir
	// mid-creation has a fresh ModTime; the marker alone can't tell
	// creation from abandonment). A capped shim phase skips the
	// whole sweep: an unexamined shim may still hold a candidate id.
	if !killCapHit && !shimScanInconclusive {
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
			firstSeen, confirmed := c.d.State.ConfirmMarker(marker, orphanSandboxAge)
			if firstSeen {
				c.d.State.AppendLog(fmt.Sprintf(
					"orphan sandbox candidate %.12s - no task dir, no shim - confirm next run", id))
				continue
			}
			if !confirmed {
				continue
			}
			if nClean >= c.d.Cfg.Ctr.MaxTaskClean {
				c.d.State.AppendLog(fmt.Sprintf("suspect: orphan sandbox dir still pending cap=%d",
					c.d.Cfg.Ctr.MaxTaskClean))
				break
			}
			if c.d.HoldLocalAction(ctx) {
				c.d.State.AppendLog(fmt.Sprintf(
					"cleanup: ctr-tasks orphan sandbox cleanup %.12s held — cluster maintenance in progress",
					id))
				break
			}
			c.d.State.ClearBudget(marker)
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
	c.d.State.PruneMarkers("sandbox-orphan-seen-", func(id string) bool {
		return sbDirs[id]
	})
	// Full scan with no D/Z orphan shim left → release our hold on
	// the shared latch (pod-teardown's own hold, if any, is
	// untouched). A capped, escalated, or inconclusive scan keeps it.
	if !shimEscalated && !killCapHit && !shimScanInconclusive {
		c.d.State.ExitFrom(latchdefs.LatchPodTeardownWedged,
			wdeps.CheckCtrTasks, nil)
	}
	if shimScanInconclusive || taskReadErr {
		c.d.CycleResult(wdeps.CheckCtrTasks, "abort")
		return
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
	host := fsx.HostSidePath(rootfs)
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
