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

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

var (
	// cri.container-type=sandbox inside task config.json — pause
	// tasks legitimately lack log.json (shell grep -q parity).
	sandboxTypeRe = regexp.MustCompile(`cri\.container-type[^,]*sandbox`)
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
	if !e.WorkerActive {
		c.d.Cycles.WithLabelValues(wdeps.CheckCtrTasks, "gated").Inc()
		return
	}
	entries, err := os.ReadDir(c.d.Cfg.CtrTaskRoot)
	if err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: ctr task root %s unreadable: %v — ctr-tasks check skipped",
			c.d.Cfg.CtrTaskRoot, err))
		c.d.Cycles.WithLabelValues(wdeps.CheckCtrTasks, "abort").Inc()
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
			c.d.State.EnterFrom(hoststate.LatchPodTeardownWedged,
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
			c.d.State.AppendLog(fmt.Sprintf("suspect: ctr-task-wedged still pending cap=%d",
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
		if err := os.RemoveAll(d); err != nil {
			c.d.State.AppendLog(fmt.Sprintf("suspect: rm task dir %.12s failed: %v", id, err))
		}
		nClean++
		c.d.Actions.WithLabelValues(wdeps.CheckCtrTasks, "rm_dir").Inc()
	}
	// Full scan with no D/Z orphan shim left → release our hold on
	// the shared latch (pod-teardown's own hold, if any, is
	// untouched). A capped or escalated scan keeps it.
	if !shimEscalated && !killCapHit {
		c.d.State.ExitFrom(hoststate.LatchPodTeardownWedged,
			wdeps.CheckCtrTasks, nil)
	}
	c.d.Cycles.WithLabelValues(wdeps.CheckCtrTasks, "ok").Inc()
}
