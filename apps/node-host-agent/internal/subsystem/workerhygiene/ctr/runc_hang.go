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
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
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
		strings.HasPrefix(comm, "runc ") || strings.HasPrefix(comm, "crun ")
}

// hungCandidate is one qualifying pid with its recorded wchan and
// the stat starttime that pins the streak identity.
type hungCandidate struct {
	pid   int
	start int64
	comm  string
	wchan string
}

// scanHungRuntimes returns the pids currently qualifying as hung:
// runtime comm + S state + age >= HungRuncAgeSec.
func (c *HungRuncCheck) scanHungRuntimes(now time.Time,
	pids []int) []hungCandidate {
	minAge := time.Duration(c.d.Cfg.Wave2.HungRuncAgeSec) * time.Second
	if minAge <= 0 {
		minAge = 3 * time.Minute
	}
	var out []hungCandidate
	for _, pid := range pids {
		st, ok := c.d.Proc.Stat(pid)
		if !ok || !st.HasComm || !runtimeComm(st.Comm) {
			continue
		}
		// Fields[0] is the stat state char right after ')'.
		if len(st.Fields) == 0 || st.Fields[0] != "S" {
			continue
		}
		if age := c.d.Proc.Age(pid, now); age < minAge {
			continue
		}
		// Fields[19] is field 22 (starttime, jiffies) — the
		// process-instance identity the streak keys on. A stat too
		// short to carry it gets the -1 sentinel: streaks still
		// work cycle-to-cycle, they just cannot distinguish a pid
		// reuse on a malformed stat (vanishingly rare).
		var start int64 = -1
		if len(st.Fields) > 19 {
			if v, err := strconv.ParseInt(st.Fields[19], 10, 64); err == nil {
				start = v
			}
		}
		out = append(out, hungCandidate{
			pid: pid, start: start, comm: st.Comm,
			wchan: c.wchan(pid),
		})
	}
	return out
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
	var pids []int
	var err error
	if e != nil && e.PidsOnce != nil {
		pids = e.PidsOnce()
	} else {
		pids, err = c.d.Proc.PIDs()
	}
	if err != nil {
		c.d.CycleResult(wdeps.CheckHungRunc, "inconclusive")
		return
	}
	cands := c.scanHungRuntimes(now, pids)

	// Consecutive-cycle confirmation keyed on (pid,starttime): a
	// recycled pid is a NEW process and must re-earn its streak —
	// pids that didn't qualify this cycle drop out entirely.
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
	c.seen = streak

	if len(cands) == 0 {
		c.d.CycleResult(wdeps.CheckHungRunc, "ok")
		return
	}
	if len(confirmed) == 0 {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: hung-runc-reaper %d runtime(s) in S state past age bound - awaiting %d-cycle confirm",
			len(cands), c.d.Cfg.Wave2.HungRuncConfirmCycles))
		c.d.CycleResult(wdeps.CheckHungRunc, "pending")
		return
	}

	// Kill budget — at most MaxKillsPerCycle SIGKILLs per cycle,
	// oldest-looking first is meaningless without starttime; pid
	// order is stable enough (the cap just bounds blast radius).
	maxKills := c.d.Cfg.Wave2.HungRuncMaxKillsPerCycle
	if maxKills <= 0 {
		maxKills = 4
	}
	killed := 0
	for _, cd := range confirmed {
		if killed >= maxKills {
			break
		}
		if !c.d.Cfg.Wave2.HungRuncKillEnabled {
			// Detect-only: log the would-be kill once per cycle.
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: hung-runc-reaper pid=%d comm=%s wchan=%s hung (kill disabled)",
				cd.pid, cd.comm, cd.wchan))
			continue
		}
		c.d.State.AppendLog(fmt.Sprintf(
			"ACTION hung-runc-kill: pid=%d comm=%s wchan=%s state=S",
			cd.pid, cd.comm, cd.wchan))
		if err := c.d.Cfg.Seams.Host.KillFn(cd.pid, syscall.SIGKILL); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: hung-runc-reaper kill pid=%d failed: %v", cd.pid, err))
			continue
		}
		killed++
		c.emitHungEvent(ctx, cd)
	}
	c.d.Actions.WithLabelValues(wdeps.CheckHungRunc, "runtime_kill").Add(float64(killed))
	c.d.CycleResult(wdeps.CheckHungRunc, "firing")
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
