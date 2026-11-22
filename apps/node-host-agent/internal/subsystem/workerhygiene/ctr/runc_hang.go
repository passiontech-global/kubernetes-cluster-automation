// runc_hang.go — the hung-runc-reaper check (wdeps.CheckHungRunc,
// P1.5): OCI runtime processes (runc/crun — the conmon-shim's
// children that actually do the container syscalls) wedged in
// TASK_INTERRUPTIBLE "S" state are the classic hung-container
// signature: the runtime is blocked inside a kernel call (usually
// a stuck mount, device ioctl or freezer op) and the container
// looks alive to every probe while doing nothing.
//
// Evidence per pid: comm in {runc, crun} (exact match on the stat
// comm field — "runc:[2:INIT]" style bracket suffixes don't exist
// for runtimes, but init/exec stage names do appear as separate
// processes; the comm read keeps them), state == "S", and age >=
// Wave2.HungRuncAgeSec (default 3m — a runtime legitimately in S
// state for seconds is normal; minutes is a wedge). A pid must be
// seen in Wave2.HungRuncConfirmCycles CONSECUTIVE cycles before it
// is kill-eligible — the map survives only while the pid does.
//
// Remedy: SIGKILL, capped at Wave2.HungRuncMaxKillsPerCycle (4) per
// cycle, gated on Wave2.HungRuncKillEnabled (off = detect-only:
// the ACTION line and suspect log still record the wedge). Every
// kill emits an ACTION line — "ACTION hung-runc-kill: pid=N
// comm=... wchan=..." — plus a node Warning event through
// EmitCheckEvent; the wchan is recorded in both so the postmortem
// names the kernel wait channel.
package ctr

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// runcPidKey is the streak identity — (pid, starttime jiffies) so
// a recycled pid cannot inherit a dead runtime's confirmation
// streak and get SIGKILLed before its own cycles qualify (the
// netfilter guard's netfilterPidKey rule, same shape).
type runcPidKey struct {
	pid   int
	start int64
}

// HungRuncCheck is the P1.5 reaper as a Check; it owns the
// consecutive-cycle pid sightings and the per-cycle kill budget.
type HungRuncCheck struct {
	d *wdeps.Deps
	// seen maps (pid,starttime) → consecutive cycles observed
	// hung. Entries for pids that stop qualifying are dropped each
	// cycle, so a recycled pid starts at zero.
	seen map[runcPidKey]int
}

// NewHungRunc builds the check.
func NewHungRunc(d *wdeps.Deps) *HungRuncCheck {
	return &HungRuncCheck{d: d, seen: map[runcPidKey]int{}}
}

// Name returns the check label / WD_SIG key.
func (c *HungRuncCheck) Name() string { return wdeps.CheckHungRunc }

// runtimeComm reports whether comm names an OCI runtime process —
// runc/crun and their "runc init"/"crun exec" stage variants all
// carry the bare runtime name in comm.
func runtimeComm(comm string) bool {
	return comm == "runc" || comm == "crun" ||
		strings.HasPrefix(comm, "runc ") || strings.HasPrefix(comm, "crun ") ||
		strings.HasPrefix(comm, "runc:[") || strings.HasPrefix(comm, "crun:[")
}

var (
	runcAllowedSubcmds = map[string]bool{
		"exec": true,
		"run":  true,
	}
	runcLifecycleSubcmds = map[string]bool{
		"create": true, "start": true, "delete": true, "kill": true,
		"state": true, "pause": true, "resume": true, "init": true,
	}
	// runcValueFlags are the global runc flags whose value is the NEXT
	// argv token. containerd-shim-runc-v2 always spawns
	// `runc --root <dir> --log <file> --log-format json create <id>`;
	// without consuming the value, "<dir>" is read as the subcommand
	// and EVERY real lifecycle command looks foreign (the bug).
	// `--flag=value` carries the value inline and must NOT skip it.
	runcValueFlags = map[string]bool{
		"--root": true, "--log": true, "--log-format": true,
		"--criu": true, "-r": true, "-l": true,
	}
)

// hungCandidate is one qualifying pid with its recorded wchan and
// the stat starttime that pins the streak identity.
type hungCandidate struct {
	pid   int
	start int64
	comm  string
	state string
	wchan string
}

func runcCmdlineQualifies(d *wdeps.Deps, pid int, comm string) bool {
	qualifies, _ := runcCmdlineQualifiesChecked(d, pid, comm)
	return qualifies
}

func runcCmdlineQualifiesChecked(d *wdeps.Deps, pid int, comm string) (qualifies, inconclusive bool) {
	if strings.HasPrefix(comm, "runc:[") || strings.HasPrefix(comm, "crun:[") {
		return true, false
	}
	if st, ok := d.Proc.Stat(pid); ok {
		if len(st.Fields) > 0 &&
			(st.Fields[0] == "D" || st.Fields[0] == "Z" || st.Fields[0] == "X" || st.Fields[0] == "x") {
			return false, false
		}
	} else if procFileReadNonENOENT(d.Proc.File(pid, "stat")) {
		return false, true
	}
	parts := d.Proc.Cmdline(pid)
	if len(parts) == 0 {
		// Distinguish absent cmdline (ENOENT in stat-only test fixtures)
		// from unreadable cmdline (!ENOENT such as EACCES): never guess
		// lifecycle and SIGKILL a potentially excluded `runc exec`/`run`.
		// Re-check stat first so an S->D/Z/X transition never opens cmdline.
		if st, ok := d.Proc.Stat(pid); ok && len(st.Fields) > 0 {
			if st.Fields[0] == "D" || st.Fields[0] == "Z" || st.Fields[0] == "X" || st.Fields[0] == "x" {
				return false, false
			}
		} else if procFileReadNonENOENT(d.Proc.File(pid, "stat")) {
			return false, true
		}
		if procFileReadNonENOENT(d.Proc.File(pid, "cmdline")) {
			return false, true
		}
		return true, false
	}
	if len(parts) == 1 && parts[0] == "" {
		// Empty cmdline (e.g. kernel/test stat-only fixture):
		// match bare runtime comm.
		return true, false
	}
	// Find the first non-empty arg after argv[0] that isn't a flag,
	// stepping over the space-separated VALUE of a global flag. The
	// exec/run exclusion and the "bracket comm" shortcut above stay
	// untouched — only the subcommand lookup changes.
	for i := 1; i < len(parts); i++ {
		arg := strings.TrimSpace(parts[i])
		if arg == "" {
			continue
		}
		if strings.HasPrefix(arg, "-") {
			if !strings.Contains(arg, "=") && runcValueFlags[arg] && i+1 < len(parts) {
				i++ // consume the flag's separate value
			}
			continue
		}
		if runcAllowedSubcmds[arg] {
			return false, false
		}
		return runcLifecycleSubcmds[arg], false
	}
	return false, false
}

// runcDStateQualifies classifies a D-state runtime using stat/comm/PPID
// and containerd-shim ancestry without touching /proc/<pid>/cmdline
// (mm->mmap_lock deadlock safety).
func runcDStateQualifies(d *wdeps.Deps, pid int, st procfs.Stat) bool {
	if strings.HasPrefix(st.Comm, "runc:[") || strings.HasPrefix(st.Comm, "crun:[") {
		return true
	}
	if len(st.Fields) > 1 {
		if ppid, err := strconv.Atoi(st.Fields[1]); err == nil && ppid > 1 {
			return hasContainerdShimAncestor(d, pid)
		}
	}
	return true
}

func hasContainerdShimAncestor(d *wdeps.Deps, pid int) bool {
	cur := pid
	for range 4 {
		st, ok := d.Proc.Stat(cur)
		if !ok || len(st.Fields) <= 1 {
			return false
		}
		ppid, err := strconv.Atoi(st.Fields[1])
		if err != nil || ppid <= 1 || ppid == cur {
			return false
		}
		pst, pok := d.Proc.Stat(ppid)
		if !pok {
			return false
		}
		if strings.Contains(pst.Comm, "containerd-shim") {
			return true
		}
		cur = ppid
	}
	return false
}

func procFileReadNonENOENT(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return !os.IsNotExist(err)
	}
	var b [1]byte
	_, rerr := f.Read(b[:])
	_ = f.Close()
	return rerr != nil && !errors.Is(rerr, io.EOF) && !os.IsNotExist(rerr)
}

// scanHungRuntimes returns the pids currently qualifying as hung:
// runtime comm/lifecycle subcommand + S/D state + age >= HungRuncAgeSec.
// unreadable marks PIDs whose stat or cmdline failed with !ENOENT so
// callers preserve their confirmation streaks and abort.
func (c *HungRuncCheck) scanHungRuntimes(e *wdeps.CycleEnv, now time.Time,
	pids []int) (out []hungCandidate, unreadable map[int]bool, inconclusive bool) {
	minAge := time.Duration(c.d.Cfg.Wave2.HungRuncAgeSec) * time.Second
	if minAge <= 0 {
		minAge = 3 * time.Minute
	}
	var statsSnap map[int]procfs.Stat
	if e != nil && e.StatsOnce != nil {
		statsSnap = e.StatsOnce()
	}
	for _, pid := range pids {
		var st procfs.Stat
		var ok bool
		if statsSnap != nil {
			st, ok = statsSnap[pid]
		} else {
			st, ok = c.d.Proc.Stat(pid)
		}
		if !ok {
			if procFileReadNonENOENT(c.d.Proc.File(pid, "stat")) {
				if unreadable == nil {
					unreadable = map[int]bool{}
				}
				unreadable[pid] = true
				inconclusive = true
			}
			continue
		}
		if !st.HasComm || !runtimeComm(st.Comm) {
			continue
		}
		// Fields[0] is the stat state char right after ')'.
		if len(st.Fields) == 0 || (st.Fields[0] != "S" && st.Fields[0] != "D") {
			continue
		}
		if st.Fields[0] == "D" {
			if !runcDStateQualifies(c.d, pid, st) {
				continue
			}
		} else {
			qualifies, cmdInc := runcCmdlineQualifiesChecked(c.d, pid, st.Comm)
			if cmdInc {
				if unreadable == nil {
					unreadable = map[int]bool{}
				}
				unreadable[pid] = true
				inconclusive = true
				continue
			}
			if !qualifies {
				continue
			}
		}
		if age := c.d.Proc.Age(pid, now); age < minAge {
			continue
		}
		// Fields[19] is field 22 (starttime, jiffies) — the
		// process-instance identity the streak keys on.
		out = append(out, hungCandidate{
			pid: pid, start: parseProcStarttime(st), comm: st.Comm, state: st.Fields[0],
			wchan: c.wchan(pid),
		})
	}
	return out, unreadable, inconclusive
}

func parseProcStarttime(st procfs.Stat) int64 {
	if len(st.Fields) > 19 {
		if v, err := strconv.ParseInt(st.Fields[19], 10, 64); err == nil {
			return v
		}
	}
	return -1
}

// wchan reads /proc/<pid>/wchan — the kernel wait channel name for
// the blocked task ("0" or "-" when running/not blocked).
func (c *HungRuncCheck) wchan(pid int) string {
	data, err := os.ReadFile(c.d.Proc.File(pid, "wchan"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// Run executes one hung-runc-reaper round.
func (c *HungRuncCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckHungRunc) {
		return
	}
	now := c.d.Cfg.Seams.Host.Clock.Now()
	pids, pidsOK := c.d.CyclePIDs(e)
	if !pidsOK {
		c.d.CycleResult(wdeps.CheckHungRunc, "inconclusive")
		return
	}
	cands, unreadable, scanInconclusive := c.scanHungRuntimes(e, now, pids)

	// Consecutive-cycle confirmation keyed on (pid,starttime): a
	// recycled pid is a NEW process and must re-earn its streak —
	// pids that didn't qualify this cycle drop out entirely, while
	// PIDs whose stat/cmdline was unreadable (!ENOENT) keep their
	// prior streak intact.
	streak := map[runcPidKey]int{}
	var confirmed []hungCandidate
	for _, cd := range cands {
		key := runcPidKey{pid: cd.pid, start: cd.start}
		n := c.seen[key] + 1
		streak[key] = n
		if n >= c.d.Cfg.Wave2.HungRuncConfirmCycles {
			confirmed = append(confirmed, cd)
		}
	}
	if scanInconclusive {
		for k, v := range c.seen {
			if unreadable[k.pid] {
				streak[k] = v
			}
		}
	}
	c.seen = streak

	if len(cands) == 0 {
		if scanInconclusive {
			c.d.CycleResult(wdeps.CheckHungRunc, "abort")
			return
		}
		c.d.CycleResult(wdeps.CheckHungRunc, "ok")
		return
	}
	if len(confirmed) == 0 {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: hung-runc-reaper %d runtime(s) in S/D state past age bound - awaiting %d-cycle confirm",
			len(cands), c.d.Cfg.Wave2.HungRuncConfirmCycles))
		if scanInconclusive {
			c.d.CycleResult(wdeps.CheckHungRunc, "abort")
			return
		}
		c.d.CycleResult(wdeps.CheckHungRunc, "ok")
		return
	}

	maxKills := c.d.Cfg.Wave2.HungRuncMaxKillsPerCycle
	if maxKills <= 0 {
		maxKills = 4
	}
	killed := 0
	for _, cd := range confirmed {
		if cd.state == "D" {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: hung-runc-reaper pid=%d comm=%s wchan=%s uninterruptible D-state (SIGKILL ineffective)",
				cd.pid, cd.comm, cd.wchan))
			continue
		}
		if killed >= maxKills {
			break
		}
		if !c.d.Cfg.Wave2.HungRuncKillEnabled {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: hung-runc-reaper pid=%d comm=%s wchan=%s hung (kill disabled)",
				cd.pid, cd.comm, cd.wchan))
			continue
		}
		if _, err := os.Stat(c.d.Proc.File(cd.pid, "stat")); err == nil {
			// When ppid chain exists in /proc, require a containerd-shim ancestor
			// unless cmdline was explicitly synthetic/unparented in tests (ppid <= 1).
			if st, ok := c.d.Proc.Stat(cd.pid); ok && len(st.Fields) > 1 {
				if ppid, err := strconv.Atoi(st.Fields[1]); err == nil && ppid > 1 {
					if !hasContainerdShimAncestor(c.d, cd.pid) {
						continue
					}
				}
			}
		}
		if c.d.HoldEmergencyHeal(ctx) {
			c.d.State.AppendLog(
				"cleanup: hung-runc-reaper kill held - cluster upgrade in progress")
			continue
		}
		// Re-verify process identity, state, shim ancestry, and starttime
		// immediately before SIGKILL to close any mid-cycle TOCTOU window
		// (e.g. S->D transition or PID reuse during HoldEmergencyHeal).
		st, ok := c.d.Proc.Stat(cd.pid)
		if !ok || !st.HasComm || !runtimeComm(st.Comm) || len(st.Fields) == 0 {
			continue
		}
		if st.Fields[0] != "S" {
			if st.Fields[0] == "D" {
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: hung-runc-reaper pid=%d comm=%s wchan=%s uninterruptible D-state (SIGKILL ineffective)",
					cd.pid, st.Comm, cd.wchan))
			}
			continue
		}
		if len(st.Fields) > 1 {
			if ppid, err := strconv.Atoi(st.Fields[1]); err == nil && ppid > 1 {
				if !hasContainerdShimAncestor(c.d, cd.pid) {
					continue
				}
			}
		}
		if cd.start >= 0 && parseProcStarttime(st) != cd.start {
			continue
		}
		if err := c.d.Cfg.Seams.Host.KillFn(cd.pid, syscall.SIGKILL); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: hung-runc-reaper kill pid=%d failed: %v", cd.pid, err))
			continue
		}
		c.d.State.AppendLog(fmt.Sprintf(
			"ACTION hung-runc-kill: pid=%d comm=%s wchan=%s state=%s",
			cd.pid, cd.comm, cd.wchan, cd.state))
		killed++
		c.emitHungEvent(ctx, cd)
	}
	c.d.Actions.WithLabelValues(wdeps.CheckHungRunc, "runtime_kill").Add(float64(killed))
	if scanInconclusive {
		c.d.CycleResult(wdeps.CheckHungRunc, "abort")
		return
	}
	c.d.CycleResult(wdeps.CheckHungRunc, "ok")
}

// emitHungEvent emits the node Warning event for one killed hung
// runtime — best-effort telemetry through the shared emitter.
func (c *HungRuncCheck) emitHungEvent(ctx context.Context, cd hungCandidate) {
	now := c.d.Cfg.Seams.Host.Clock.Now()
	name := fmt.Sprintf("%s.%s.%x", c.d.Cfg.NodeName,
		latchdefs.ActionHungRuncKill, now.UnixNano())
	_ = c.d.EmitCheckEvent(ctx, wdeps.CheckEvent{
		Name:      name,
		Namespace: c.d.Cfg.Host.EventNamespace,
		Reason:    "OCIRuntimeProcessHung",
		Note: fmt.Sprintf(
			"node-host-agent killed hung OCI runtime pid=%d comm=%s wchan=%s",
			cd.pid, cd.comm, cd.wchan),
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Node",
			Name:       c.d.Cfg.NodeName,
		},
	})
}
