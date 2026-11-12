// pods.go — the pod-level helpers several domain checks share:
// the API-side verdicts (Ready, mirror, PVC consumer) and the
// verified force-delete the teardown check spends after its
// zero-live-task proof. ForceDeletePod lives here (not in pods/)
// because the log line is an NPD contract shared by every caller.
package wdeps

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
)

// PodHasPVC reports whether the pod mounts a persistentVolumeClaim —
// force-deleting a PVC consumer on a wrong "dead" verdict risks a
// dual-mount of an RWO volume.
func PodHasPVC(p *corev1.Pod) bool {
	for _, v := range p.Spec.Volumes {
		// PVC + generic ephemeral volumes share the same dual-mount
		// risk class on a wrong "dead" verdict.
		if v.PersistentVolumeClaim != nil || v.Ephemeral != nil {
			return true
		}
	}
	return false
}

// IsMirrorPod reports kubelet-static mirror pods — deleting the
// mirror object changes nothing on disk.
func IsMirrorPod(p *corev1.Pod) bool {
	_, ok := p.Annotations["kubernetes.io/config.mirror"]
	return ok
}

// PodReady reports whether the pod's Ready condition is True — the
// API-side verdict the datapath guards contrast against (a pod
// Ready=True whose service listener is dead is exactly the wedge
// these checks heal).
func PodReady(p *corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// ForceDeletePod removes the pod object with grace 0 + Background
// propagation — reached only after zero-live-task verification, so it
// is pure object cleanup (no split-brain/dual-mount risk).
func (d *Deps) ForceDeletePod(ctx context.Context, p *corev1.Pod) error {
	// Log line is an NPD contract: ends in "force-delete pod ..." so
	// the StuckPodForceDeleted filelog pattern still fires.
	d.State.AppendLog(fmt.Sprintf(
		"POD-TEARDOWN-FORCE-DELETE: "+latchdefs.ReasonForceDeletePod+
			"%s/%s (uid %.8s) - Terminating %ds, zero live tasks",
		p.Namespace, p.Name, string(p.UID),
		int64(d.Cfg.Seams.Host.Clock.Now().Sub(p.DeletionTimestamp.Time).Seconds())))
	return d.Cfg.Client.CoreV1().Pods(p.Namespace).Delete(ctx, p.Name,
		metav1.DeleteOptions{
			GracePeriodSeconds: ptr.To[int64](0),
			PropagationPolicy:  ptr.To(metav1.DeletePropagationBackground),
			Preconditions:      &metav1.Preconditions{UID: &p.UID},
		})
}

// HoldLocalAction is the L1↔L3 maintenance gate every destructive
// path consults before a pod delete or policy eviction: true while
// the cluster verifiably holds the maintenance mutex (upgrade /
// kured drain) OR the verdict is unverifiable — nodecoord fails
// closed. Nil Coord (tests, unwired builds) never holds.
func (d *Deps) HoldLocalAction(ctx context.Context) bool {
	return d.Cfg.Coord != nil && d.Cfg.Coord.HoldLocalAction(ctx)
}

// StampLocalRemediation marks NodeCondition LocalRemediationInProgress
// on nodes/status — call BEFORE a node-local restart (k0sworker)
// so the cluster side yields remote remediation while L1 self-heals.
// Best-effort, rides nodecoord's own StampTimeout, errors only
// logged. Nil Coord is a no-op.
func (d *Deps) StampLocalRemediation(ctx context.Context) {
	if d.Cfg.Coord == nil {
		return
	}
	if err := d.Cfg.Coord.StampLocalRemediation(ctx); err != nil {
		d.State.AppendLog(fmt.Sprintf(
			"suspect: local-remediation stamp failed (attribution hint only): %v", err))
	}
}

// StampPodHealed records that L1 bounced infra pod ns/name — patches
// the pod's last-pod-healed-at annotation and refreshes the
// LocalRemediationInProgress node condition so the L3 side can
// attribute the churn — best-effort, rides nodecoord's own
// StampTimeout, errors only logged. Nil Coord is a no-op.
func (d *Deps) StampPodHealed(ctx context.Context, ns, name string) {
	if d.Cfg.Coord == nil {
		return
	}
	if err := d.Cfg.Coord.StampPodHealed(ctx, ns, name); err != nil {
		d.State.AppendLog(fmt.Sprintf(
			"suspect: pod-healed stamp failed (attribution hint only): %v", err))
	}
}
