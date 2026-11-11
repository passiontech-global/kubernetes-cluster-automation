// Check: d-state-storm detector (runtime-critical D-state procs).
// Split out of dstate_scopes.go (pure move).

package guards

import (
	"context"
	"fmt"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// DstateRuntimeComm reports whether a /proc/<pid>/stat comm belongs
// to the runtime-critical set — D-state here wedges the pod
// lifecycle (runc, containerd + containerd-shim, k0s workers,
// kubelet) or signals a hung fs journal (btrfs-*/jbd2/* kernel
// threads). Prefixes, not exact names: comm is truncated at 15
// bytes ("containerd-shim" is the shim's real comm) and jbd2
// threads embed the device (jbd2/vda1-8).
func DstateRuntimeComm(comm string) bool {
	for _, p := range []string{
		"runc", "containerd", "k0s", "kubelet", "btrfs-", "jbd2/",
	} {
		if strings.HasPrefix(comm, p) {
			return true
		}
	}
	return false
}

// DstateCheck is the d-state-storm storm detector as a Check; it owns the
// over-threshold streak (ex-Hygiene.dstateFails).
type DstateCheck struct {
	d     *wdeps.Deps
	fails int
}

// Name returns the check label / WD_SIG key.
func (c *DstateCheck) Name() string { return wdeps.CheckDState }

// Run executes one d-state-storm round.
func (c *DstateCheck) Run(_ context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckDState) {
		return
	}
	total, runtime := 0, 0
	// A small comm=wchan sample for the ACTION line — the kernel
	// function holding the tasks is the triage hint (umount_tree /
	// wait_transaction_locked / blk_mq_get_tag).
	wchans := make([]string, 0, 4)
	for _, pid := range e.PidsOnce() {
		comm, state, ok := procStatCommState(e, c.d, pid)
		if !ok || state != "D" {
			continue
		}
		total++
		if DstateRuntimeComm(comm) {
			runtime++
		}
		if len(wchans) < 4 {
			if w := procWchan(c.d, pid); w != "" {
				wchans = append(wchans, comm+"="+w)
			}
		}
	}
	if total < c.d.Cfg.Pressure.DStateStormThreshold && runtime < dStateRuntimeMin {
		c.fails = 0
		c.d.State.Exit(latchdefs.LatchDStateStorm, nil)
		c.d.CycleResult(wdeps.CheckDState, "ok")
		return
	}
	if c.d.StreakPending(&c.fails, fmt.Sprintf(
		"suspect: d-state-storm count=%d runtime=%d",
		total, runtime)) {
		c.d.CycleResult(wdeps.CheckDState, "ok")
		return
	}
	if !c.d.State.Exists(latchdefs.LatchDStateStorm) {
		// NPD contract: nodereporter maps this line to the
		// KernelHungTasks Event + problem_counter — logged once per
		// latch entry (the !stateExists gate, wdeps.CheckCiliumMTU parity).
		c.d.State.AppendLog(fmt.Sprintf(
			latchdefs.ActionEntryPrefix(latchdefs.LatchDStateStorm)+
				"count=%d runtime=%d wchan=%s",
			total, runtime, strings.Join(wchans, ",")))
	}
	c.d.State.Enter(latchdefs.LatchDStateStorm,
		fmt.Sprintf("count=%d runtime=%d", total, runtime))
	c.d.CycleResult(wdeps.CheckDState, "ok")
}
