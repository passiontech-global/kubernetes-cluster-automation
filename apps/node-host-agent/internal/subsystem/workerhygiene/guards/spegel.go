// spegel.go — the spegel-mirror spegel-mirror guard: a Ready=False spegel
// mirror pod whose containerd mirror points at a wedged peer gets
// deleted (0s grace) so the DaemonSet rebuilds it.
package guards

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

const (
	spegelMinPodAge = 3 * time.Minute
	// spegelContainerdSock is the host socket the spegel pod
	// bind-mounts for its containerd registry mirror; a
	// k0sworker/containerd restart replaces the inode while the
	// pod keeps serving the dead one (spegel-stale-socket-guard).
	spegelContainerdSock  = "/run/k0s/containerd.sock"
	spegelSockStaleMargin = 2 * time.Minute
)

var (
	// pod matchers — anchored like konnPodRe/dnsPodRe.
	spegelPodRe = regexp.MustCompile(`^spegel-[a-z0-9]+$`) // H4 P2P mirror
)

// SpegelCheck is the spegel-mirror mirror-peer guard as a Check; it owns
// the Ready=False streak (ex-Hygiene.spegelFails).
type SpegelCheck struct {
	d     *wdeps.Deps
	Fails int
}

// Name returns the check label / WD_SIG key.
func (c *SpegelCheck) Name() string { return wdeps.CheckSpegel }

// Run executes one spegel-mirror round.
func (c *SpegelCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckSpegel) {
		return
	}
	if !e.APIOK {
		// Inconclusive — keep streak/latch exactly like teardown.
		c.d.CycleResult(wdeps.CheckSpegel, "abort")
		return
	}
	var sp *corev1.Pod
	for i := range e.Pods {
		p := &e.Pods[i]
		if (p.Namespace != "spegel" && p.Namespace != "kube-system") ||
			!spegelPodRe.MatchString(p.Name) ||
			p.DeletionTimestamp != nil ||
			p.Status.Phase != corev1.PodRunning ||
			c.d.Cfg.Seams.Host.Clock.Now().Sub(p.CreationTimestamp.Time) < spegelMinPodAge {
			continue
		}
		sp = p
		break
	}
	if sp == nil {
		// No spegel DS on this node — clear stale evidence like
		// wdeps.CheckCilium's no-agent path.
		c.Fails = 0
		c.d.State.Exit(latchdefs.LatchSpegelMirrorDegraded, nil)
		c.d.CycleResult(wdeps.CheckSpegel, "ok")
		return
	}
	// spegel-stale-socket-guard stale socket inode: the pod can read Ready while its
	// bind-mounted /run/k0s/containerd.sock points at a dead inode —
	// k0sworker/containerd restarted AFTER the pod started, so the
	// mirror serves a socket that no longer exists. ModTime newer
	// than pod creation + margin is the proof; a missing/unreadable
	// socket is inconclusive and skips (pod-mode agents without a
	// host /run view land here too).
	if spegelSocketStale(c.d.Cfg.Seams.Host.StatFn,
		spegelSockPath(c.d.Cfg.CtrSocket), sp.CreationTimestamp.Time) {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: spegel-mirror %s/%s holds stale containerd.sock inode (socket recreated after pod start)",
			sp.Namespace, sp.Name))
		// Hold check BEFORE the budget spend: a held delete must not
		// burn the restart cooldown — otherwise the next ungated
		// window waits a full MinRestartInterval for an action that
		// never ran. Same ordering the other guarded deletes carry.
		if c.d.HoldLocalAction(ctx) {
			c.d.State.AppendLog("suspect: spegel-mirror pod delete held — " +
				"cluster maintenance in progress")
			c.d.CycleResult(wdeps.CheckSpegel, "ok")
			return
		}
		if !c.d.State.RateTrySpend("last-spegel-restart",
			c.d.Cfg.MinRestartInterval) {
			c.d.State.AppendLog(
				"suspect: spegel stale socket but restart in cooldown (<30m), skip")
			c.d.CycleResult(wdeps.CheckSpegel, "ok")
			return
		}
		// Preconditions{UID} closes the listing→delete race: the
		// DaemonSet recycling the pod name between the CycleEnv list
		// and this call must 409, not kill the replacement pod (same
		// precondition the calico remedies carry). The heal stamp
		// rides BEFORE the delete so the cluster side sees the
		// attribution even if this process dies mid-call.
		c.d.State.AppendLog(fmt.Sprintf(
			"ACTION: spegel-mirror deleted pod %s/%s - stale containerd.sock inode (k0sworker/containerd restarted under it)",
			sp.Namespace, sp.Name))
		if err := c.d.DeletePodGraceful(ctx, sp); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: spegel-mirror delete %s/%s failed: %v",
				sp.Namespace, sp.Name, err))
		} else {
			c.Fails = 0
			c.d.Actions.WithLabelValues(wdeps.CheckSpegel, "pod_delete").Inc()
		}
		c.d.CycleResult(wdeps.CheckSpegel, "ok")
		return
	}
	if wdeps.PodReady(sp) {
		// Pod healthy and socket fresh — the mirror datapath isn't
		// our problem; clear stale evidence.
		c.Fails = 0
		c.d.State.Exit(latchdefs.LatchSpegelMirrorDegraded, nil)
		c.d.CycleResult(wdeps.CheckSpegel, "ok")
		return
	}
	if c.d.StreakPending(&c.Fails, fmt.Sprintf(
		"suspect: spegel-mirror pod %s/%s Ready=False",
		sp.Namespace, sp.Name)) {
		c.d.CycleResult(wdeps.CheckSpegel, "ok")
		return
	}
	c.d.State.Enter(latchdefs.LatchSpegelMirrorDegraded,
		fmt.Sprintf("pod=%s/%s ready_fails=%d", sp.Namespace, sp.Name, c.Fails))
	// Hold BEFORE budget spend (same rule as the stale-socket path
	// above): a maintenance-held delete must not consume the restart
	// cooldown for an action that never ran.
	if c.d.HoldLocalAction(ctx) {
		c.d.State.AppendLog("suspect: spegel-mirror pod delete held — " +
			"cluster maintenance in progress")
		c.d.CycleResult(wdeps.CheckSpegel, "ok")
		return
	}
	if !c.d.State.RateTrySpend("last-spegel-restart", c.d.Cfg.MinRestartInterval) {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: spegel-mirror %s/%s Ready=False %dx but restart in cooldown (<30m), skip",
			sp.Namespace, sp.Name, c.Fails))
		c.d.CycleResult(wdeps.CheckSpegel, "ok")
		return
	}
	// Budget spent atomically BEFORE the delete (rate_spend parity).
	// The heal stamp rides BEFORE the delete so the cluster side sees
	// the attribution even if this process dies mid-call.
	c.d.State.AppendLog(fmt.Sprintf(
		"ACTION: spegel-mirror deleted pod %s/%s - Ready=False %dx (containerd mirror points at a wedged peer)",
		sp.Namespace, sp.Name, c.Fails))
	if err := c.d.DeletePodGraceful(ctx, sp); err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: spegel-mirror delete %s/%s failed: %v",
			sp.Namespace, sp.Name, err))
	} else {
		c.Fails = 0
		c.d.Actions.WithLabelValues(wdeps.CheckSpegel, "pod_delete").Inc()
	}
	c.d.CycleResult(wdeps.CheckSpegel, "ok")
}

// spegelSockPath resolves the HOST-side containerd socket the
// staleness stat must read: Cfg.CtrSocket is the /host/run view the
// agent's other containerd probes use (ctr + kubelet share it), and
// spegelContainerdSock is only the fallback for fixtures/callers
// that never populated it.
func spegelSockPath(ctrSocket string) string {
	if ctrSocket == "" {
		return spegelContainerdSock
	}
	return ctrSocket
}

// spegelSocketStale reports whether the host's containerd socket was
// recreated after the spegel pod started — ModTime newer than pod
// creation plus spegelSockStaleMargin proves k0sworker/containerd
// restarted under the pod, leaving it bound to a dead inode. The
// stat rides the Seams.Host.StatFn seam and sockPath is a parameter
// (not the const) so tests can point the read at a temp file — the
// real socket lives on the HOST, a path rootless tests cannot
// create. Any stat failure (no host /run view, socket absent
// mid-restart) is inconclusive → false, never a false-positive
// delete.
func spegelSocketStale(stat func(string) (os.FileInfo, error),
	sockPath string, podCreated time.Time) bool {
	fi, err := stat(sockPath)
	if err != nil {
		return false
	}
	return fi.ModTime().After(podCreated.Add(spegelSockStaleMargin))
}
