// pod_teardown.go — the 36-pod-teardown check: force-delete pods
// stuck Terminating past the age gates (skipping finalizer/PVC/
// mirror pods and cycles with live containerd tasks or a held
// maintenance window) and latch pod-teardown-wedged when tasks
// outlive the wedge age. The konnectivity + dns-resolv checks live
// in konnectivity.go / dns_resolv.go.
package pods

import (
	"context"
	"fmt"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// PodTeardownCheck is the 36-pod-teardown check as a Check; it owns
// the wedged-pod streak (ex-Hygiene.wedgeFails).
type PodTeardownCheck struct {
	d     *wdeps.Deps
	fails int
}

// Name returns the check label / WD_SIG key.
func (c *PodTeardownCheck) Name() string { return wdeps.CheckTeardown }

// Run executes one pod-teardown round.
func (c *PodTeardownCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckTeardown) {
		return
	}
	if !e.APIOK {
		// Inconclusive — shell "exit 0" semantics: abort silently,
		// keep counters and latches (no state_exit flap on API blip).
		c.d.CycleResult(wdeps.CheckTeardown, "abort")
		return
	}
	// The task map is only worth building once a Terminating pod
	// exists — with none, the whole loop below is a no-op.
	var tasks map[string][]wdeps.CtrTask
	now := c.d.Cfg.Seams.Host.Clock.Now()
	wedged := 0
	ndel := 0
	for i := range e.Pods {
		p := &e.Pods[i]
		if p.DeletionTimestamp == nil {
			continue
		}
		if tasks == nil {
			var complete bool
			tasks, complete = e.TasksOnce()
			if !complete {
				// A task root was unreadable — "zero live tasks"
				// is unverifiable, so a force-delete could reap a
				// pod whose tasks the map never saw. Inconclusive
				// cycle: keep counters/latch, act on nothing
				// (wdeps.CheckCtrTasks unreadable-root parity).
				c.d.State.AppendLog(
					"suspect: pod-teardown aborted — ctr task map incomplete, force-deletes unverifiable")
				c.d.CycleResult(wdeps.CheckTeardown, "abort")
				return
			}
		}
		uid := string(p.UID)
		age := now.Sub(p.DeletionTimestamp.Time)
		// Wedge evidence is measured on pod level: Terminating long
		// past StuckWedgeAge AND containerd still holds a task dir
		// (live or not) — sig7/force-delete had their chance; only a
		// reboot clears a shim/kernel-level wedge.
		if age >= c.d.Cfg.Teardown.StuckWedgeAge && len(tasks[uid]) >= 1 {
			wedged++
		}
		if age < c.d.Cfg.Teardown.StuckDeleteAge {
			continue
		}
		// Rule C: external resources or kubelet mirrors → never
		// force-delete (finalizer = another controller owns cleanup;
		// PVC = dual-mount risk; mirror = pointless).
		if len(p.Finalizers) > 0 || wdeps.PodHasPVC(p) || wdeps.IsMirrorPod(p) {
			continue
		}
		if wdeps.CountLive(tasks[uid]) > 0 {
			continue // a live task exists — kubelet may still be tearing down
		}
		if ndel >= c.d.Cfg.Teardown.MaxForceDelete {
			continue // per-cycle cap bounds the blast radius
		}
		// L1↔L3 hold: force-deleting pods mid cluster-maintenance is
		// churn the drain then has to un-wedge — stop this cycle.
		if c.d.HoldLocalAction(ctx) {
			c.d.State.AppendLog("cleanup: pod-teardown force-delete held — " +
				"cluster maintenance in progress")
			break
		}
		// The heal stamp rides BEFORE the delete so the cluster side
		// sees the attribution even if this process dies mid-call.
		c.d.StampPodHealed(ctx, p.Namespace, p.Name)
		if err := c.d.ForceDeletePod(ctx, p); err != nil {
			c.d.State.AppendLog(fmt.Sprintf("suspect: force-delete %s/%s failed: %v",
				p.Namespace, p.Name, err))
			continue
		}
		ndel++
		c.d.Actions.WithLabelValues(wdeps.CheckTeardown, "force_delete").Inc()
	}

	switch {
	case wedged >= 1:
		if !c.d.StreakPending(&c.fails,
			fmt.Sprintf("suspect: pod-teardown-wedged stuck=%d", wedged)) {
			if c.d.State.Exists(latchdefs.LatchNodeOverloaded) {
				// Suppression parity: a wedge under overload is a
				// symptom — rebooting would dump 100% of its load
				// onto the remaining nodes (amplifier). Log-only,
				// once per suppression episode.
				if !c.d.State.Exists(latchdefs.LatchPodTeardownWedged) {
					c.d.State.AppendLog(fmt.Sprintf(
						"pod-teardown-wedged suppressed-overloaded stuck=%d", wedged))
				}
			} else {
				// EnterFrom: ctr-tasks shares this latch for
				// unkillable orphan shims — our exit below must
				// release only OUR hold, never theirs.
				c.d.State.EnterFrom(latchdefs.LatchPodTeardownWedged,
					wdeps.CheckTeardown, fmt.Sprintf("stuck=%d", wedged))
			}
		}
	default:
		c.fails = 0
		c.d.State.ExitFrom(latchdefs.LatchPodTeardownWedged,
			wdeps.CheckTeardown, nil)
	}
	c.d.CycleResult(wdeps.CheckTeardown, "ok")
}
