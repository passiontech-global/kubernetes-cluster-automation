// spegel.go — the W7-H4 spegel-mirror guard: a Ready=False spegel
// mirror pod whose containerd mirror points at a wedged peer gets
// deleted (0s grace) so the DaemonSet rebuilds it.
package guards

import (
	"context"
	"fmt"
	"regexp"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

const (
	spegelMinPodAge = 3 * time.Minute
)

var (
	// W7 pod matchers — anchored like konnPodRe/dnsPodRe.
	spegelPodRe = regexp.MustCompile(`^spegel-[a-z0-9]+$`) // H4 P2P mirror
)

// SpegelCheck is the W7-H4 mirror-peer guard as a Check; it owns
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
	if sp == nil || wdeps.PodReady(sp) {
		// No spegel DS on this node, or the pod is healthy — either
		// way the mirror datapath isn't our problem; clear stale
		// evidence like wdeps.CheckCilium's no-agent path.
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
	if !c.d.State.RateTrySpend("last-spegel-restart", c.d.Cfg.MinRestartInterval) {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: spegel-mirror %s/%s Ready=False %dx but restart in cooldown (<30m), skip",
			sp.Namespace, sp.Name, c.Fails))
		c.d.CycleResult(wdeps.CheckSpegel, "ok")
		return
	}
	// Budget spent atomically BEFORE the delete (rate_spend parity).
	c.d.State.AppendLog(fmt.Sprintf(
		"ACTION: spegel-mirror deleted pod %s/%s - Ready=False %dx (containerd mirror points at a wedged peer)",
		sp.Namespace, sp.Name, c.Fails))
	if err := c.d.Cfg.Client.CoreV1().Pods(sp.Namespace).Delete(ctx, sp.Name,
		metav1.DeleteOptions{GracePeriodSeconds: ptr.To[int64](0)}); err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: spegel-mirror delete %s/%s failed: %v",
			sp.Namespace, sp.Name, err))
	} else {
		c.Fails = 0
		c.d.Actions.WithLabelValues(wdeps.CheckSpegel, "pod_delete").Inc()
	}
	c.d.CycleResult(wdeps.CheckSpegel, "ok")
}
