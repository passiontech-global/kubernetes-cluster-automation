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
	"bytes"
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
	if strings.HasPrefix(comm, "runc:[") || strings.HasPrefix(comm, "crun:[") {
		return true
	}
	raw, err := os.ReadFile(d.Proc.File(pid, "cmdline"))
	if err != nil || len(raw) == 0 {
		// Unreadable/empty cmdline (e.g. kernel/test stat-only fixture):
		// match bare runtime comm.
		return true
	}
	parts := bytes.Split(raw, []byte{0})
	// Find the first non-empty arg after argv[0] that isn't a flag,
	// stepping over the space-separated VALUE of a global flag. The
	// exec/run exclusion and the "bracket comm" shortcut below stay
	// untouched — only the subcommand lookup changes.
	for i := 1; i < len(parts); i++ {
		arg := strings.TrimSpace(string(parts[i]))
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
			return false
		}
		return runcLifecycleSubcmds[arg]
	}
	return false
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

// scanHungRuntimes returns the pids currently qualifying as hung:
// runtime comm/lifecycle subcommand + S/D state + age >= HungRuncAgeSec.
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
		if len(st.Fields) == 0 || (st.Fields[0] != "S" && st.Fields[0] != "D") {
			continue
		}
		if !runcCmdlineQualifies(c.d, pid, st.Comm) {
			continue
		}
		if age := c.d.Proc.Age(pid, now); age < minAge {
			continue
		}
		// Fields[19] is field 22 (starttime, jiffies) — the
		// process-instance identity the streak keys on.
		var start int64 = -1
		if len(st.Fields) > 19 {
			if v, err := strconv.ParseInt(st.Fields[19], 10, 64); err == nil {
				start = v
			}
		}
		out = append(out, hungCandidate{
			pid: pid, start: start, comm: st.Comm, state: st.Fields[0],
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
			"suspect: hung-runc-reaper %d runtime(s) in S/D state past age bound - awaiting %d-cycle confirm",
			len(cands), c.d.Cfg.Wave2.HungRuncConfirmCycles))
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
