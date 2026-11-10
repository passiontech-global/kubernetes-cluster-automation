// inflight_pvb_audit.go — velero-inflight-audit of velero-backup-auditor: the
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

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// ---------------------------------------------------------------------------
// velero-inflight-audit — in-flight Backup / PodVolumeBackup wedge audit
// ---------------------------------------------------------------------------

// auditInFlightTransfers is the velero-inflight-audit sweep: every Backup and
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

	// --- PodVolumeBackups + PodVolumeRestores: mark + conditional
	// cleanup (W20-ST3 added the restore side — same lost-thread
	// signature, same node-agent bounce) ---
	if err := a.auditWedgedTransferKind(ctx, veleroPVBGVR, "pvb",
		metrics.VeleroPodVolumeBackupWedged, &a.seenWedgedPVB); err != nil {
		return err
	}
	if err := a.auditWedgedTransferKind(ctx, veleroPVRGVR, "pvr",
		metrics.VeleroPodVolumeRestoreWedged, &a.seenWedgedPVR); err != nil {
		return err
	}
	// Cooldown hygiene once per cycle: a stamp past the window can
	// never cool again, so expired entries are dead weight in an
	// otherwise append-only ledger. pvbHealed is shared across both
	// kinds — the cooldown key is the node-agent's node either way.
	a.pvbHealed.Prune(func(_ string, last time.Time) bool {
		return now.Sub(last) < veleroPVBCleanupCooldown
	})
	return nil
}

// auditWedgedTransferKind is the per-GVR body of the
// velero-inflight-audit wedge sweep shared by PodVolumeBackup and
// PodVolumeRestore (W20-ST3): every object held InProgress|Deleting
// past veleroStuckMaxAge (6h) has lost its node-agent thread —
// Backups are mark-only, but a wedged volume transfer whose agent
// provably died gets deleted AND its node-agent pod bounced so the
// next backup/restore is not blocked behind it. CRD absence prunes
// the kind's series and stops quietly.
func (a *veleroBackupAuditor) auditWedgedTransferKind(ctx context.Context,
	gvr schema.GroupVersionResource, kind string,
	gauge *prometheus.GaugeVec, seen *state.GaugeLedger[pausedKey]) error {

	seen.Begin() // drop any aborted sweep's leftover emissions
	log := logf.FromContext(ctx)
	now := a.now.Now()

	items, err := a.veleroList(ctx, gvr)
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		// CRD absent — clear any stale wedge series and stop.
		seen.Prune(gauge.DeleteLabelValues)
		return nil
	case err != nil:
		return fmt.Errorf("list velero %s: %w", gvr.Resource, err)
	}

	cleaned := 0
	for i := range items.Items {
		obj := &items.Items[i]
		phase, _ := kube.NestedString(obj.Object, "status", "phase")
		if phase != "InProgress" && phase != "Deleting" {
			continue
		}
		since := inFlightSince(obj)
		if now.Sub(since) <= veleroStuckMaxAge {
			continue
		}
		ns, name := obj.GetNamespace(), obj.GetName()
		k := pausedKey{ns, name}
		seen.Set(gauge, 1, k, ns, name)
		log.Info("velero transfer object wedged in-flight >6h",
			"kind", kind, "object", ns+"/"+name, "phase", phase)

		// Only an InProgress object is a cleanup candidate — a
		// Deleting one is already on its way out.
		if phase != "InProgress" || cleaned >= veleroPVBCleanupMaxPerRun {
			continue
		}
		// A PVB the controller has not assigned a node yet owns no
		// node-agent to bounce — skipping beats keying the cooldown
		// (and the heal) on the bogus "node-agent/" target.
		if pvbNode(obj) == "" {
			continue
		}
		// The cleanup cooldown is keyed on the NODE, not the object:
		// the destructive half is the node-agent pod bounce, and
		// several wedged transfers can share one agent — per-object
		// keys would bounce the same pod once per wedged transfer.
		coolKey := "node-agent/" + pvbNode(obj)
		if a.pvbHealed.CooledDown(coolKey, veleroPVBCleanupCooldown, now) {
			continue
		}
		if a.cleanWedgedTransfer(ctx, gvr, obj, since, now, kind) {
			a.pvbHealed.Stamp(coolKey, now)
			cleaned++
		}
	}
	seen.Prune(gauge.DeleteLabelValues)
	return nil
}

// ---------------------------------------------------------------------------
// cnpg-backup-audit — velero.io/v2alpha1 DataUpload / DataDownload wedge audit
// ---------------------------------------------------------------------------

// dataMovementStuckPhases are the in-flight phases of the velero
// data-mover CRDs — a DataUpload/DataDownload held in any of these
// past veleroStuckMaxAge has lost its node-agent thread, same wedge
// shape as a PodVolumeBackup (cnpg-backup-audit).
var dataMovementStuckPhases = map[string]bool{
	"InProgress": true,
	"Accepted":   true,
	"Prepared":   true,
	"Canceling":  true,
}

// veleroDataMovementWedgedGauge marks (1) each DataUpload or
// DataDownload stuck in an in-flight phase past the 6h window —
// mark-only: unlike a PodVolumeBackup there is no provably-dead
// node-agent thread to bounce a delete would safely restart, so the
// wedged object pages and waits for operator/velero cleanup.
var veleroDataMovementWedgedGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_velero_data_movement_wedged",
	Help: "1 while a velero.io/v2alpha1 DataUpload/DataDownload is stuck in an in-flight phase (InProgress/Accepted/Prepared/Canceling) past 6h — cnpg-backup-audit.",
}, []string{"namespace", "name", "kind"})

func init() {
	ctrlmetrics.Registry.MustRegister(veleroDataMovementWedgedGauge)
}

// auditDataMovement scans DataUpload and DataDownload objects for
// wedged in-flight phases, marking
// veleroDataMovementWedgedGauge{namespace,name,kind} and pruning the
// series the moment the object resolves or is deleted. CRD absence
// (clusters without the data-mover CRDs installed) is a quiet no-op,
// same contract as the rest of the module.
func (a *veleroBackupAuditor) auditDataMovement(ctx context.Context) error {
	a.seenDataMovement.Begin() // drop any aborted sweep's leftover emissions
	log := logf.FromContext(ctx)
	now := a.now.Now()

	for _, gvr := range []schema.GroupVersionResource{
		kube.GVRVeleroDataUpload, kube.GVRVeleroDataDownload,
	} {
		kind := gvr.Resource
		items, err := a.veleroList(ctx, gvr)
		switch {
		case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
			continue // CRD absent — nothing to scan, stale series still prune below
		case err != nil:
			err = fmt.Errorf("list velero %s: %w", kind, err)
			a.seenDataMovement.Prune(veleroDataMovementWedgedGauge.DeleteLabelValues)
			return err
		}
		for i := range items.Items {
			u := &items.Items[i]
			phase, _ := kube.NestedString(u.Object, "status", "phase")
			if !dataMovementStuckPhases[phase] {
				continue
			}
			if now.Sub(inFlightSince(u)) <= veleroStuckMaxAge {
				continue
			}
			k := kind + "/" + u.GetNamespace() + "/" + u.GetName()
			a.seenDataMovement.Set(veleroDataMovementWedgedGauge, 1, k,
				u.GetNamespace(), u.GetName(), kind)
			log.Info("velero data movement object wedged in-flight >6h",
				"kind", kind, "object", u.GetNamespace()+"/"+u.GetName(),
				"phase", phase)
		}
	}
	a.seenDataMovement.Prune(veleroDataMovementWedgedGauge.DeleteLabelValues)
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
	// startTimestamp is the PVB convention; velero.io/v2alpha1
	// DataUpload/DataDownload expose startedAt instead.
	if st, ok := kube.NestedString(u.Object, "status", "startTimestamp"); ok {
		if t, err := time.Parse(time.RFC3339, st); err == nil {
			since = t
		}
	} else if st, ok := kube.NestedString(u.Object, "status", "startedAt"); ok {
		if t, err := time.Parse(time.RFC3339, st); err == nil {
			since = t
		}
	}
	return since
}

// cleanWedgedTransfer decides whether the transfer object's
// node-agent provably lost its Kopia thread and, if so, deletes the
// object and bounces the agent pod. kind is "pvb" or "pvr" — it only
// feeds log fields and the cleaned-counter action label. The delete
// phase is destructive on TWO counts — a CR object and a LIVE pod —
// so it gates on heal.AllowedV (cooldown + maintenance mutex, fail
// closed on unverifiable) before any write. Returns true when the
// cleanup ran (cooldown-worthy).
func (a *veleroBackupAuditor) cleanWedgedTransfer(ctx context.Context,
	gvr schema.GroupVersionResource, obj *unstructured.Unstructured,
	objStart, now time.Time, kind string) bool {
	log := logf.FromContext(ctx)
	agent, err := a.pvbAgentPod(ctx, obj)
	if err != nil {
		log.Error(err, "transfer agent pod lookup failed — cleanup skipped",
			"kind", kind, "object", obj.GetNamespace()+"/"+obj.GetName())
		metrics.IncError(a.queue)
		return false
	}
	if !pvbAgentWedged(objStart, agent) {
		return false // agent still owns the thread — not provably wedged
	}
	ns, name := obj.GetNamespace(), obj.GetName()
	// The whole delete phase (PVB object + node-agent pod bounce)
	// defers while deliberate maintenance is in flight — a cordon or
	// k0s upgrade already removes agent pods, and an unverifiable
	// mutex fails closed with the error surfaced on the queue. The
	// cooldown key is the node-agent's node — the same key the
	// caller stamped under.
	proceed, unverifiable := heal.AllowedV(ctx, log, &a.verdict, a.cs, a.dyn,
		&a.pvbHealed, "node-agent/"+pvbNode(obj), veleroPVBCleanupCooldown, now)
	switch {
	case unverifiable:
		metrics.IncError(a.queue)
		return false
	case !proceed:
		return false
	}
	uid := obj.GetUID()
	if err := a.dyn.Resource(gvr).Namespace(ns).Delete(ctx, name,
		kube.UIDDeleteOptions(uid, "")); err != nil && !apierrors.IsNotFound(err) {
		log.Error(err, "wedged transfer delete failed",
			"kind", kind, "object", ns+"/"+name)
		metrics.IncError(a.queue)
		return false
	}
	metrics.VeleroWedgedObjectsCleanedTotal.
		WithLabelValues(ns, kind+"_deleted").Inc()
	log.Info("ACTION: deleted wedged velero transfer object",
		"kind", kind, "object", ns+"/"+name,
		"agentPod", agentPodName(agent))

	// Bounce the node-agent pod so its next scheduled backup starts
	// clean — the DaemonSet recreates it. A missing agent pod needs
	// no bounce (it is already gone). A FAILED bounce reports
	// not-healed: the caller skips the cooldown stamp, so the next
	// sweep retries the half-done heal (the PVB delete tolerates
	// NotFound on retry) instead of parking it for 30m wedged.
	if agent != nil {
		agentUID := agent.UID
		if err := a.cs.CoreV1().Pods(agent.Namespace).Delete(ctx, agent.Name,
			kube.UIDDeleteOptions(agentUID, "")); err != nil && !apierrors.IsNotFound(err) {
			log.Error(err, "node-agent bounce failed",
				"pod", agent.Namespace+"/"+agent.Name)
			metrics.IncError(a.queue)
			return false
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
