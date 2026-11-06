// inflight_pvb_audit.go — W10-ST6 of velero-backup-auditor: the
// in-flight transfer audit. Backups and PodVolumeBackups held
// InProgress|Deleting past veleroStuckMaxAge have lost the thread —
// Backups are mark-only (a delete can abort a real backup); a PVB
// whose node-agent pod provably lost its Kopia thread is deleted and
// the agent bounced so the next backup is not blocked behind it.
package velerobackupauditor

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// ---------------------------------------------------------------------------
// W10-ST6 — in-flight Backup / PodVolumeBackup wedge audit
// ---------------------------------------------------------------------------

// auditInFlightTransfers is the W10-ST6 sweep: every Backup and
// PodVolumeBackup held InProgress or Deleting past veleroStuckMaxAge
// (6h) has lost the thread — the velero server or node-agent that
// owned it is gone. Backups are mark-only (deleting a Backup CR can
// abort a genuinely-running backup); PodVolumeBackups get the
// stronger treatment the plan calls for: when the owning node-agent
// provably lost its Kopia thread (pod gone, recreated after the PVB
// started, not Running, or a container restarted mid-backup), the
// wedged PVB is deleted AND its node-agent pod bounced so the next
// scheduled backup is not blocked behind it.
func (a *veleroBackupAuditor) auditInFlightTransfers(ctx context.Context,
	backups *unstructured.UnstructuredList) error {
	a.seenStuckBackup.Begin() // drop any aborted sweep's leftover emissions
	a.seenWedgedPVB.Begin()   // drop any aborted sweep's leftover emissions
	log := logf.FromContext(ctx)
	now := a.now.Now()

	// --- Backups: mark-only gauge over the already-listed set ---
	if backups != nil {
		for i := range backups.Items {
			b := &backups.Items[i]
			phase, _ := kube.NestedString(b.Object, "status", "phase")
			if phase != "InProgress" && phase != "Deleting" {
				continue
			}
			since := inFlightSince(b)
			if now.Sub(since) <= veleroStuckMaxAge {
				continue
			}
			k := pausedKey{b.GetNamespace(), b.GetName()}
			a.seenStuckBackup.Set(metrics.VeleroBackupStuck, 1, k, k.namespace, k.schedule)
			log.Info("velero backup wedged in-flight >6h",
				"backup", k.namespace+"/"+k.schedule, "phase", phase)
		}
	}
	a.seenStuckBackup.Prune(metrics.VeleroBackupStuck.DeleteLabelValues)

	// --- PodVolumeBackups: mark + conditional cleanup ---
	pvbs, err := a.veleroList(ctx, veleroPVBGVR)
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		// CRD absent — clear any stale wedge series and stop.
		a.seenWedgedPVB.Prune(metrics.VeleroPodVolumeBackupWedged.DeleteLabelValues)
		return nil
	case err != nil:
		return fmt.Errorf("list velero podvolumebackups: %w", err)
	}

	cleaned := 0
	for i := range pvbs.Items {
		pvb := &pvbs.Items[i]
		phase, _ := kube.NestedString(pvb.Object, "status", "phase")
		if phase != "InProgress" && phase != "Deleting" {
			continue
		}
		since := inFlightSince(pvb)
		if now.Sub(since) <= veleroStuckMaxAge {
			continue
		}
		ns, name := pvb.GetNamespace(), pvb.GetName()
		k := pausedKey{ns, name}
		a.seenWedgedPVB.Set(metrics.VeleroPodVolumeBackupWedged, 1, k, ns, name)
		log.Info("velero podvolumebackup wedged in-flight >6h",
			"pvb", ns+"/"+name, "phase", phase)

		// Only an InProgress PVB is a cleanup candidate — a
		// Deleting one is already on its way out.
		if phase != "InProgress" || cleaned >= veleroPVBCleanupMaxPerRun {
			continue
		}
		// The cleanup cooldown is keyed on the NODE, not the PVB:
		// the destructive half is the node-agent pod bounce, and
		// several wedged PVBs can share one agent — per-PVB keys
		// would bounce the same pod once per wedged backup.
		coolKey := "node-agent/" + pvbNode(pvb)
		if a.pvbHealed.CooledDown(coolKey, veleroPVBCleanupCooldown, now) {
			continue
		}
		if a.cleanWedgedPVB(ctx, pvb, since, now) {
			a.pvbHealed.Stamp(coolKey, now)
			cleaned++
		}
	}
	a.seenWedgedPVB.Prune(metrics.VeleroPodVolumeBackupWedged.DeleteLabelValues)
	// Cooldown hygiene once per cycle: a stamp past the window can
	// never cool again, so expired entries are dead weight in an
	// otherwise append-only ledger.
	a.pvbHealed.Prune(func(_ string, last time.Time) bool {
		return now.Sub(last) < veleroPVBCleanupCooldown
	})
	return nil
}

// pvbNode resolves the node the PVB's Kopia transfer runs on —
// spec.node (the snapshot's node) first, status.node as the
// older-velero fallback so pre-upgrade PVBs still resolve.
func pvbNode(pvb *unstructured.Unstructured) string {
	node, ok := kube.NestedString(pvb.Object, "spec", "node")
	if !ok || node == "" {
		node, _ = kube.NestedString(pvb.Object, "status", "node")
	}
	return node
}

// inFlightSince is the wedge-age clock for an in-flight velero
// object: status.startTimestamp when parseable, else
// creationTimestamp — the same convention flagBadBackup uses.
func inFlightSince(u *unstructured.Unstructured) time.Time {
	since := u.GetCreationTimestamp().Time
	if st, ok := kube.NestedString(u.Object, "status", "startTimestamp"); ok {
		if t, err := time.Parse(time.RFC3339, st); err == nil {
			since = t
		}
	}
	return since
}

// cleanWedgedPVB decides whether the PVB's node-agent provably lost
// its Kopia thread and, if so, deletes the PVB and bounces the agent
// pod. The delete phase is destructive on TWO counts — a CR object
// and a LIVE pod — so it gates on heal.AllowedV (cooldown +
// maintenance mutex, fail closed on unverifiable) before any write.
// Returns true when the cleanup ran (cooldown-worthy).
func (a *veleroBackupAuditor) cleanWedgedPVB(ctx context.Context,
	pvb *unstructured.Unstructured, pvbStart, now time.Time) bool {
	log := logf.FromContext(ctx)
	agent, err := a.pvbAgentPod(ctx, pvb)
	if err != nil {
		log.Error(err, "pvb agent pod lookup failed — cleanup skipped",
			"pvb", pvb.GetNamespace()+"/"+pvb.GetName())
		metrics.IncError(a.queue)
		return false
	}
	if !pvbAgentWedged(pvbStart, agent) {
		return false // agent still owns the thread — not provably wedged
	}
	ns, name := pvb.GetNamespace(), pvb.GetName()
	// The whole delete phase (PVB object + node-agent pod bounce)
	// defers while deliberate maintenance is in flight — a cordon or
	// k0s upgrade already removes agent pods, and an unverifiable
	// mutex fails closed with the error surfaced on the queue. The
	// cooldown key is the node-agent's node — the same key the
	// caller stamped under.
	proceed, unverifiable := heal.AllowedV(ctx, log, &a.verdict, a.cs, a.dyn,
		&a.pvbHealed, "node-agent/"+pvbNode(pvb), veleroPVBCleanupCooldown, now)
	switch {
	case unverifiable:
		metrics.IncError(a.queue)
		return false
	case !proceed:
		return false
	}
	uid := pvb.GetUID()
	if err := a.dyn.Resource(veleroPVBGVR).Namespace(ns).Delete(ctx, name,
		kube.UIDDeleteOptions(uid, "")); err != nil && !apierrors.IsNotFound(err) {
		log.Error(err, "wedged pvb delete failed", "pvb", ns+"/"+name)
		metrics.IncError(a.queue)
		return false
	}
	metrics.VeleroWedgedObjectsCleanedTotal.
		WithLabelValues(ns, "pvb_deleted").Inc()
	log.Info("ACTION: deleted wedged podvolumebackup",
		"pvb", ns+"/"+name, "agentPod", agentPodName(agent))

	// Bounce the node-agent pod so its next scheduled backup starts
	// clean — the DaemonSet recreates it. A missing agent pod needs
	// no bounce (it is already gone).
	if agent != nil {
		agentUID := agent.UID
		if err := a.cs.CoreV1().Pods(agent.Namespace).Delete(ctx, agent.Name,
			kube.UIDDeleteOptions(agentUID, "")); err != nil && !apierrors.IsNotFound(err) {
			log.Error(err, "node-agent bounce failed",
				"pod", agent.Namespace+"/"+agent.Name)
			metrics.IncError(a.queue)
		} else {
			metrics.VeleroWedgedObjectsCleanedTotal.
				WithLabelValues(ns, "pod_restarted").Inc()
			log.Info("ACTION: bounced node-agent pod",
				"pod", agent.Namespace+"/"+agent.Name)
		}
	}
	return true
}

// pvbAgentPod resolves the node-agent pod that owns the PVB's Kopia
// thread. PodVolumeBackupSpec carries spec.node (the node the
// snapshot runs on) and spec.pod (the WORKLOAD pod — not the
// agent); status has no pod/node fields. The velero node-agent
// DaemonSet runs one pod per node, so spec.node identifies it.
// nil,nil means "no agent pod found" which IS wedge evidence.
func (a *veleroBackupAuditor) pvbAgentPod(ctx context.Context,
	pvb *unstructured.Unstructured) (*corev1.Pod, error) {
	ns := pvb.GetNamespace()
	node := pvbNode(pvb)
	if node == "" {
		return nil, nil
	}
	pods, err := kube.ListAll(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + node,
		Limit:         kube.DefaultListPageSize,
	}, kube.Pods(a.cs, ns))
	if err != nil {
		return nil, err
	}
	// Only an actual node-agent pod counts — the DaemonSet names
	// them "node-agent-*". The spec.nodeName check runs in code too
	// (fake clientsets ignore field selectors), and there is NO
	// fallback to "any pod on the node": velero's namespace also
	// hosts the velero server Deployment, and the old pods[0]
	// fallback could hand that server pod to cleanWedgedPVB's
	// bounce — deleting it would abort every backup in flight.
	for i := range pods {
		if strings.Contains(pods[i].Name, "node-agent") &&
			pods[i].Spec.NodeName == node {
			return &pods[i], nil
		}
	}
	return nil, nil
}

// pvbAgentWedged reports whether the agent pod provably lost its
// Kopia thread: the pod is gone, not Running, was (re)created after
// the PVB started, or any container restarted/terminated after the
// PVB started — in every case the in-process kopia backup is dead
// while the PVB object still claims InProgress.
func pvbAgentWedged(pvbStart time.Time, pod *corev1.Pod) bool {
	if pod == nil {
		return true // agent gone — nothing owns the thread
	}
	if pod.Status.Phase != corev1.PodRunning {
		return true
	}
	if pod.Status.StartTime != nil && pod.Status.StartTime.After(pvbStart) {
		return true
	}
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.State.Running != nil && cs.State.Running.StartedAt.After(pvbStart) {
			return true
		}
		if cs.LastTerminationState.Terminated != nil &&
			cs.LastTerminationState.Terminated.FinishedAt.After(pvbStart) {
			return true
		}
	}
	return false
}

func agentPodName(p *corev1.Pod) string {
	if p == nil {
		return "<none>"
	}
	return p.Namespace + "/" + p.Name
}
