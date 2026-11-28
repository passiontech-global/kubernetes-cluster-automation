// restore_audit.go — R6-K9a Velero Restore stuck-InProgress audit and
// wedged velero server pod bounce: detects velero.io/v1 Restore CRs
// held in status.phase == "InProgress" past veleroStuckMaxAge (6h),
// emits node_automation_velero_restore_stuck{namespace,restore}, a
// 1h-cooldown-deduped Warning Event (VeleroRestoreStuck), and bounces
// the oldest wedged velero server pod via heal.EvictPodV (explicitly
// excluding node-agent / DaemonSet pods).
package velerobackupauditor

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

const (
	veleroRestoreEventCooldown = time.Hour
	veleroRestoreHealCooldown  = time.Hour
	veleroRestoreEventReason   = "VeleroRestoreStuck"
)

var veleroRestoreGVR = kube.GVVeleroRestore

func (a *veleroBackupAuditor) auditRestores(ctx context.Context) error {
	a.seenStuckRestore.Begin()
	log := logf.FromContext(ctx)
	now := a.now.Now()
	a.restoreEventSent.PruneExpired(now, veleroRestoreEventCooldown)
	a.restoreHealed.PruneExpired(now, veleroRestoreHealCooldown)

	stuckCount := 0
	var earliestStart time.Time

	err := a.veleroListEach(ctx, veleroRestoreGVR, func(page []unstructured.Unstructured) error {
		for i := range page {
			r := &page[i]
			phase, _ := kube.NestedString(r.Object, "status", "phase")
			if phase == "Failed" || phase == "PartiallyFailed" {
				log.Info("WARN: velero restore failed",
					"restore", r.GetNamespace()+"/"+r.GetName(), "phase", phase)
				continue
			}
			if phase != "InProgress" {
				continue
			}
			since := inFlightSince(r)
			if since.IsZero() || now.Sub(since) <= veleroStuckMaxAge {
				continue
			}
			ns, name := r.GetNamespace(), r.GetName()
			k := pausedKey{ns, name}
			a.seenStuckRestore.Set(metrics.VeleroRestoreStuck, 1, k, ns, name)
			stuckCount++
			if earliestStart.IsZero() || since.Before(earliestStart) {
				earliestStart = since
			}
			log.Info("ALERT: velero restore stuck InProgress >6h",
				"restore", ns+"/"+name, "startedAt", since)

			if a.cs == nil {
				continue
			}
			evKey := ns + "/" + name
			if a.restoreEventSent.CooledDown(evKey, veleroRestoreEventCooldown, now) {
				continue
			}
			instance := a.queue
			if instance == "" {
				instance = "velero-backup-auditor"
			}
			if evErr := kube.EmitWarningEvent(ctx, a.cs, kube.WarningEvent{
				Name:      fmt.Sprintf("velero-restore-stuck.%s.%x", name, now.UnixNano()),
				Namespace: ns,
				Regarding: corev1.ObjectReference{
					APIVersion: "velero.io/v1",
					Kind:       "Restore",
					Namespace:  ns,
					Name:       name,
					UID:        r.GetUID(),
				},
				Reason:            veleroRestoreEventReason,
				Note:              fmt.Sprintf("Velero Restore %s/%s stuck InProgress since %s (>%s)", ns, name, since.UTC().Format(time.RFC3339), veleroStuckMaxAge),
				ReportingInstance: instance,
				Now:               now,
			}); evErr != nil {
				log.Info("WARN: failed to emit VeleroRestoreStuck warning event",
					"restore", evKey, "error", evErr)
			} else {
				a.restoreEventSent.Stamp(evKey, now)
			}
		}
		return nil
	})
	if kube.IsCRDAbsent(err) {
		a.seenStuckRestore.Prune(metrics.VeleroRestoreStuck.DeleteLabelValues)
		return nil
	}
	if err != nil {
		return fmt.Errorf("list velero restores: %w", err)
	}
	a.seenStuckRestore.Prune(metrics.VeleroRestoreStuck.DeleteLabelValues)

	if stuckCount > 0 && a.cs != nil {
		a.bounceWedgedVeleroServer(ctx, log, earliestStart, stuckCount, now)
	}
	return nil
}

func (a *veleroBackupAuditor) bounceWedgedVeleroServer(ctx context.Context,
	log logr.Logger, earliestStart time.Time, stuckCount int, now time.Time) {

	pods, err := kube.ListAll(ctx, metav1.ListOptions{
		Limit: kube.DefaultListPageSize,
	}, kube.Pods(a.cs, a.veleroInstallNS()))
	if err != nil {
		metrics.IncError(a.queue)
		log.Error(err, "velero server pod list failed — bounce skipped",
			"namespace", a.veleroInstallNS(), "stuckRestores", stuckCount)
		return
	}
	target := pickWedgedVeleroServerPod(pods, earliestStart, now)
	if target == nil {
		return
	}
	key := "velero-server/" + kube.PodControllerKey(target)
	proceed, unverifiable, evicted, refused, err := heal.EvictPodV(
		ctx, log, a.verdict, a.cs, a.dyn, &a.restoreHealed, key,
		veleroRestoreHealCooldown, target, now)
	if !proceed {
		if unverifiable {
			metrics.IncError(a.queue)
		}
		return
	}
	if refused {
		log.Info("DEFER: velero server pod eviction refused",
			"pod", target.Namespace+"/"+target.Name, "stuckRestores", stuckCount)
		return
	}
	if err != nil {
		metrics.IncError(a.queue)
		log.Error(err, "velero server pod eviction failed",
			"pod", target.Namespace+"/"+target.Name)
		return
	}
	if evicted {
		metrics.VeleroWedgedObjectsCleanedTotal.
			WithLabelValues(a.veleroInstallNS(), "pod_restarted").Inc()
		log.Info("ACTION: evicted wedged velero server pod",
			"pod", target.Namespace+"/"+target.Name, "stuckRestores", stuckCount)
	}
}

func isVeleroServerPod(p *corev1.Pod) bool {
	if p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning {
		return false
	}
	ref := metav1.GetControllerOf(p)
	if ref == nil || ref.Kind == "DaemonSet" {
		return false
	}
	if p.Labels["name"] == "node-agent" ||
		p.Labels["component"] == "node-agent" ||
		strings.HasPrefix(p.Name, "node-agent-") {
		return false
	}
	return p.Labels["name"] == "velero" ||
		p.Labels["app.kubernetes.io/name"] == "velero" ||
		strings.HasPrefix(p.Name, "velero-")
}

func veleroServerPodWedged(earliestStuckStart time.Time, p *corev1.Pod, now time.Time) bool {
	if !kube.PodReadyCond(p) {
		return true
	}
	podStart := p.CreationTimestamp.Time
	if p.Status.StartTime != nil && !p.Status.StartTime.IsZero() {
		podStart = p.Status.StartTime.Time
	}
	if podStart.IsZero() {
		return false
	}
	return !podStart.After(earliestStuckStart) || now.Sub(podStart) > veleroStuckMaxAge
}

func pickWedgedVeleroServerPod(pods []corev1.Pod, earliestStuckStart, now time.Time) *corev1.Pod {
	var oldest *corev1.Pod
	for i := range pods {
		p := &pods[i]
		if !isVeleroServerPod(p) || !veleroServerPodWedged(earliestStuckStart, p, now) {
			continue
		}
		if oldest == nil || p.CreationTimestamp.Before(&oldest.CreationTimestamp) ||
			(p.CreationTimestamp.Equal(&oldest.CreationTimestamp) && p.Name < oldest.Name) {
			oldest = p
		}
	}
	return oldest
}
