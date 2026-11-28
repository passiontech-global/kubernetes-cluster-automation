// pvc_lifecycle_guard.go — health check "pvc-lifecycle-guard" (#72):
// detect-only storage lifecycle guard covering four non-terminating storage
// failure modes (explicitly skipping DeletionTimestamp != nil on PVCs, PVs,
// and VolumeSnapshots to avoid overlap with stuck_terminating_storage.go):
//  1. PVC Pending deadlock >= 10m (classified into StorageClassNotFound,
//     FailedProvisioning, WaitForFirstConsumer, PendingTimeout).
//  2. Pod fsGroup recursive chown stall (ContainerCreating >= 5m, all claimed
//     PVCs Bound, no recent <=15m FailedAttachVolume/FailedMount events,
//     FSGroup != nil and FSGroupChangePolicy != OnRootMismatch).
//  3. Released non-terminating PVs older than NODE_AUTOMATION_PV_RELEASED_MAX_AGE
//     (default 168h).
//  4. Non-terminating failed VolumeSnapshots (readyToUse != true or
//     status.error != nil) older than 2h, with 403/404 graceful skip.
package pvc

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

const (
	// CheckNamePVCLifecycleGuard is the registry check name for #7/#72.
	CheckNamePVCLifecycleGuard = "pvc-lifecycle-guard"

	pvcLifecycleDefaultReleasedMaxAge = 168 * time.Hour
	pvcPendingDeadlockMinAge          = 10 * time.Minute
	podFSGroupStallMinAge             = 5 * time.Minute
	podFSGroupMountErrMaxAge          = 15 * time.Minute
	volumeSnapshotFailedMinAge        = 2 * time.Hour

	pvcDeadlockStorageClassNotFound = "StorageClassNotFound"
	pvcDeadlockFailedProvisioning   = "FailedProvisioning"
	pvcDeadlockWaitForFirstConsumer = "WaitForFirstConsumer"
	pvcDeadlockPendingTimeout       = "PendingTimeout"
)

var (
	pvcPendingDeadlockGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_pvc_pending_deadlock",
		Help: "1 while a non-terminating PVC remains Pending past 10m with a classified deadlock reason.",
	}, []string{"namespace", "pvc", "reason"})

	podFSGroupStallGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_pod_fsgroup_stall",
		Help: "1 while a Pod with Bound PVCs and fsGroup (without OnRootMismatch) is stalled in ContainerCreating past 5m.",
	}, []string{"namespace", "pod"})

	pvReleasedStaleGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_pv_released_stale",
		Help: "1 while a non-terminating PersistentVolume remains Released older than NODE_AUTOMATION_PV_RELEASED_MAX_AGE.",
	}, []string{"pv", "storageclass"})

	volumeSnapshotFailedGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_volumesnapshot_failed",
		Help: "1 while a non-terminating VolumeSnapshot has readyToUse!=true or status.error set past 2h.",
	}, []string{"namespace", "snapshot"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		pvcPendingDeadlockGauge,
		podFSGroupStallGauge,
		pvReleasedStaleGauge,
		volumeSnapshotFailedGauge,
	)
}

type pvcLifecycleGuardCheck struct {
	*probefw.Deps

	pvReleasedMaxAge time.Duration

	pendingSeen state.FirstSeenLedger
	fsgroupSeen state.FirstSeenLedger

	pendingEmitted state.GaugeLedger[string]
	fsgroupEmitted state.GaugeLedger[string]
	pvEmitted      state.GaugeLedger[string]
	vsEmitted      state.GaugeLedger[string]
}

// NewPVCLifecycleGuardCheck builds the pvc-lifecycle-guard check, resolving
// NODE_AUTOMATION_PV_RELEASED_MAX_AGE once at construction.
func NewPVCLifecycleGuardCheck(d *probefw.Deps) probefw.Check {
	return &pvcLifecycleGuardCheck{
		Deps:             d,
		pvReleasedMaxAge: envx.GetenvDuration("NODE_AUTOMATION_PV_RELEASED_MAX_AGE", pvcLifecycleDefaultReleasedMaxAge),
	}
}

func (c *pvcLifecycleGuardCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := c.Now()

	var pendingRep, fsgroupRep, pvRep, vsRep, summaryRep probefw.SweepReport

	c.scanPVCsAndFSGroup(ctx, log, now, &pendingRep, &fsgroupRep, &summaryRep)
	c.scanReleasedPVs(ctx, log, now, &pvRep, &summaryRep)
	c.scanVolumeSnapshots(ctx, log, now, &vsRep, &summaryRep)

	pendingRep.Close(&c.pendingEmitted, pvcPendingDeadlockGauge.DeleteLabelValues)
	fsgroupRep.Close(&c.fsgroupEmitted, podFSGroupStallGauge.DeleteLabelValues)
	pvRep.Close(&c.pvEmitted, pvReleasedStaleGauge.DeleteLabelValues)
	vsRep.Close(&c.vsEmitted, volumeSnapshotFailedGauge.DeleteLabelValues)
	return summaryRep.Verdict("pvc lifecycle guard: ", ", ")
}

func (c *pvcLifecycleGuardCheck) scanPVCsAndFSGroup(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	pendingRep *probefw.SweepReport,
	fsgroupRep *probefw.SweepReport,
	summaryRep *probefw.SweepReport,
) {
	pvcs, err := c.AllPVCs(ctx)
	if err != nil {
		if apierrors.IsForbidden(err) {
			log.V(1).Info("PVC list skipped (403)", "error", err)
		} else {
			summaryRep.InfraErr(fmt.Errorf("list pvcs: %w", err))
		}
		for k, lv := range c.pendingEmitted.Last() {
			pendingRep.Carry(k, lv)
		}
		for k, lv := range c.fsgroupEmitted.Last() {
			fsgroupRep.Carry(k, lv)
		}
		return
	}

	var pendingPVCs []*corev1.PersistentVolumeClaim
	boundPVCs := map[string]bool{}
	pendingSeenKeep := map[string]bool{}

	for i := range pvcs {
		pvc := &pvcs[i]
		if pvc.DeletionTimestamp != nil {
			continue
		}
		switch pvc.Status.Phase {
		case corev1.ClaimBound:
			boundPVCs[pvc.Namespace+"/"+pvc.Name] = true
		case corev1.ClaimPending:
			key := pvc.Namespace + "/" + pvc.Name
			persisted := false
			if !pvc.CreationTimestamp.IsZero() {
				persisted = now.Sub(pvc.CreationTimestamp.Time) >= pvcPendingDeadlockMinAge
			} else {
				pendingSeenKeep[key] = true
				persisted = probefw.Persisted(&c.pendingSeen, key, now, pvcPendingDeadlockMinAge, log)
			}
			if persisted {
				pendingPVCs = append(pendingPVCs, pvc)
			}
		}
	}
	c.pendingSeen.Prune(func(k string) bool { return pendingSeenKeep[k] })

	if len(pendingPVCs) == 0 && len(boundPVCs) == 0 {
		c.fsgroupSeen.Prune(func(string) bool { return false })
		return
	}

	// Lazily fetch Pods & Events only when at least 1 Pending or Bound PVC exists
	// (keeps empty-cluster TestRunInfraErrorMarksFail clean).
	pods, podsErr := c.AllPods(ctx)
	if podsErr != nil {
		if apierrors.IsForbidden(podsErr) {
			log.V(1).Info("Pod list skipped (403)", "error", podsErr)
		} else {
			summaryRep.InfraErr(fmt.Errorf("list pods: %w", podsErr))
		}
	}
	events, eventsErr := c.AllEvents(ctx)
	if eventsErr != nil {
		if apierrors.IsForbidden(eventsErr) {
			log.V(1).Info("Event list skipped (403)", "error", eventsErr)
		} else {
			summaryRep.InfraErr(fmt.Errorf("list events: %w", eventsErr))
		}
	}

	var scMap map[string]*storagev1.StorageClass
	scKnown := false
	if len(pendingPVCs) > 0 {
		scs, scErr := c.AllStorageClasses(ctx)
		switch {
		case scErr == nil:
			scKnown = true
			scMap = make(map[string]*storagev1.StorageClass, len(scs))
			for i := range scs {
				sc := &scs[i]
				scMap[sc.Name] = sc
			}
		case apierrors.IsForbidden(scErr) || kube.IsCRDAbsent(scErr):
			log.V(1).Info("StorageClass list skipped", "error", scErr)
		default:
			summaryRep.InfraErr(fmt.Errorf("list storageclasses: %w", scErr))
		}
	}

	var pvcEvents map[string][]*corev1.Event
	var podEvents map[string][]*corev1.Event
	if eventsErr == nil {
		pvcEvents = map[string][]*corev1.Event{}
		podEvents = map[string][]*corev1.Event{}
		for i := range events {
			ev := &events[i]
			ns := ev.InvolvedObject.Namespace
			if ns == "" {
				ns = ev.Namespace
			}
			key := ns + "/" + ev.InvolvedObject.Name
			switch ev.InvolvedObject.Kind {
			case "PersistentVolumeClaim":
				pvcEvents[key] = append(pvcEvents[key], ev)
			case "Pod":
				podEvents[key] = append(podEvents[key], ev)
			}
		}
	}

	// Build Pending Pod -> claimed PVC map for WaitForFirstConsumer correlation.
	pendingPodsByPVC := map[string][]*corev1.Pod{}
	if podsErr == nil {
		for i := range pods {
			pod := &pods[i]
			if pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodPending {
				continue
			}
			for _, claim := range kube.PodClaimedPVCs(pod) {
				pendingPodsByPVC[pod.Namespace+"/"+claim] = append(pendingPodsByPVC[pod.Namespace+"/"+claim], pod)
			}
		}
	}

	for _, pvc := range pendingPVCs {
		pvcKey := pvc.Namespace + "/" + pvc.Name
		reason := classifyPendingPVC(pvc, scMap, scKnown, pvcEvents[pvcKey], pendingPodsByPVC[pvcKey], podEvents)
		pendingRep.Flag(pvcPendingDeadlockGauge, pvcKey+"/"+reason, []string{pvc.Namespace, pvc.Name, reason})
		summaryRep.Find(fmt.Sprintf("pvc/%s (%s)", pvcKey, reason))
	}

	if len(boundPVCs) == 0 {
		c.fsgroupSeen.Prune(func(string) bool { return false })
		return
	}
	if podsErr != nil || eventsErr != nil {
		for k, lv := range c.fsgroupEmitted.Last() {
			fsgroupRep.Carry(k, lv)
		}
		return
	}

	fsgroupSeenKeep := map[string]bool{}
	for i := range pods {
		pod := &pods[i]
		if pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodPending {
			continue
		}
		if !podHasContainerCreating(pod) {
			continue
		}
		if pod.Spec.SecurityContext == nil || pod.Spec.SecurityContext.FSGroup == nil {
			continue
		}
		if pod.Spec.SecurityContext.FSGroupChangePolicy != nil &&
			*pod.Spec.SecurityContext.FSGroupChangePolicy == corev1.FSGroupChangeOnRootMismatch {
			continue
		}
		claims := kube.PodClaimedPVCs(pod)
		if len(claims) == 0 {
			continue
		}
		allBound := true
		for _, claim := range claims {
			if !boundPVCs[pod.Namespace+"/"+claim] {
				allBound = false
				break
			}
		}
		if !allBound {
			continue
		}
		podKey := pod.Namespace + "/" + pod.Name
		if hasRecentMountError(podEvents[podKey], now) {
			continue
		}

		persisted := false
		if scheduledSince, ok := podScheduledSince(pod); ok {
			persisted = now.Sub(scheduledSince) >= podFSGroupStallMinAge
		} else {
			fsgroupSeenKeep[podKey] = true
			persisted = probefw.Persisted(&c.fsgroupSeen, podKey, now, podFSGroupStallMinAge, log)
		}
		if !persisted {
			continue
		}
		fsgroupRep.Flag(podFSGroupStallGauge, podKey, []string{pod.Namespace, pod.Name})
		summaryRep.Find(fmt.Sprintf("pod/%s (fsgroup_chown_stall)", podKey))
	}
	c.fsgroupSeen.Prune(func(k string) bool { return fsgroupSeenKeep[k] })
}

func classifyPendingPVC(
	pvc *corev1.PersistentVolumeClaim,
	scMap map[string]*storagev1.StorageClass,
	scKnown bool,
	evs []*corev1.Event,
	claimingPods []*corev1.Pod,
	podEvents map[string][]*corev1.Event,
) string {
	scName := ""
	if pvc.Spec.StorageClassName != nil {
		scName = *pvc.Spec.StorageClassName
	}
	if scKnown && scName != "" && scMap[scName] == nil {
		return pvcDeadlockStorageClassNotFound
	}
	for _, ev := range evs {
		msgLower := strings.ToLower(ev.Message)
		if strings.Contains(msgLower, "storageclass") &&
			(strings.Contains(msgLower, "not found") || strings.Contains(msgLower, "does not exist")) {
			return pvcDeadlockStorageClassNotFound
		}
	}

	for _, ev := range evs {
		if ev.Reason == "ProvisioningFailed" ||
			ev.Reason == "FailedProvisioning" ||
			ev.Reason == "VolumeFailedProvisioning" ||
			strings.Contains(strings.ToLower(ev.Message), "failed to provision") {
			return pvcDeadlockFailedProvisioning
		}
	}

	for _, ev := range evs {
		if ev.Reason == "WaitForFirstConsumer" {
			return pvcDeadlockWaitForFirstConsumer
		}
	}
	scKnownImmediate := false
	if scKnown && scName != "" {
		if sc := scMap[scName]; sc != nil && sc.VolumeBindingMode != nil {
			if *sc.VolumeBindingMode == storagev1.VolumeBindingWaitForFirstConsumer {
				return pvcDeadlockWaitForFirstConsumer
			}
			if *sc.VolumeBindingMode == storagev1.VolumeBindingImmediate {
				scKnownImmediate = true
			}
		}
	}
	for _, pod := range claimingPods {
		for _, pev := range podEvents[pod.Namespace+"/"+pod.Name] {
			msgLower := strings.ToLower(pev.Message)
			if strings.Contains(msgLower, "volume node affinity conflict") ||
				strings.Contains(msgLower, "didn't match persistentvolume") {
				return pvcDeadlockWaitForFirstConsumer
			}
			if !scKnownImmediate && pev.Reason == "FailedScheduling" {
				return pvcDeadlockWaitForFirstConsumer
			}
		}
		if !scKnownImmediate {
			for _, cond := range pod.Status.Conditions {
				if cond.Type == corev1.PodScheduled && cond.Status == corev1.ConditionFalse {
					return pvcDeadlockWaitForFirstConsumer
				}
			}
		}
	}

	return pvcDeadlockPendingTimeout
}

func podHasContainerCreating(pod *corev1.Pod) bool {
	for i := range pod.Status.ContainerStatuses {
		w := pod.Status.ContainerStatuses[i].State.Waiting
		if w != nil && w.Reason == "ContainerCreating" {
			return true
		}
	}
	for i := range pod.Status.InitContainerStatuses {
		w := pod.Status.InitContainerStatuses[i].State.Waiting
		if w != nil && w.Reason == "ContainerCreating" {
			return true
		}
	}
	return false
}

func podScheduledSince(pod *corev1.Pod) (time.Time, bool) {
	for _, cond := range pod.Status.Conditions {
		if cond.Type == corev1.PodScheduled &&
			cond.Status == corev1.ConditionTrue &&
			!cond.LastTransitionTime.IsZero() {
			return cond.LastTransitionTime.Time, true
		}
	}
	return time.Time{}, false
}

func hasRecentMountError(evs []*corev1.Event, now time.Time) bool {
	for _, ev := range evs {
		if ev.Reason != "FailedAttachVolume" && ev.Reason != "FailedMount" {
			continue
		}
		d := now.Sub(kube.EventTime(ev))
		if d >= 0 && d <= podFSGroupMountErrMaxAge {
			return true
		}
	}
	return false
}

func (c *pvcLifecycleGuardCheck) scanReleasedPVs(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	pvRep *probefw.SweepReport,
	summaryRep *probefw.SweepReport,
) {
	pvs, err := c.AllPersistentVolumes(ctx)
	if err != nil {
		if apierrors.IsForbidden(err) {
			log.V(1).Info("PersistentVolume list skipped (403)", "error", err)
		} else {
			summaryRep.InfraErr(fmt.Errorf("list persistentvolumes: %w", err))
		}
		for k, lv := range c.pvEmitted.Last() {
			pvRep.Carry(k, lv)
		}
		return
	}

	maxAge := c.pvReleasedMaxAge
	if maxAge <= 0 {
		maxAge = pvcLifecycleDefaultReleasedMaxAge
	}

	for i := range pvs {
		pv := &pvs[i]
		if pv.DeletionTimestamp != nil {
			continue
		}
		if pv.Status.Phase != corev1.VolumeReleased {
			continue
		}
		releasedAt := pv.CreationTimestamp.Time
		if pv.Status.LastPhaseTransitionTime != nil && !pv.Status.LastPhaseTransitionTime.IsZero() {
			releasedAt = pv.Status.LastPhaseTransitionTime.Time
		}
		if releasedAt.IsZero() || now.Sub(releasedAt) <= maxAge {
			continue
		}
		sc := pv.Spec.StorageClassName
		pvRep.Flag(pvReleasedStaleGauge, pv.Name+"/"+sc, []string{pv.Name, sc})
		summaryRep.Find(fmt.Sprintf("pv/%s (released>%s)", pv.Name, maxAge))
	}
}

func (c *pvcLifecycleGuardCheck) scanVolumeSnapshots(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	vsRep *probefw.SweepReport,
	summaryRep *probefw.SweepReport,
) {
	if c.Dyn == nil {
		return
	}
	vss, err := c.AllUnstructured(ctx, kube.GVRVolumeSnapshot)
	switch {
	case kube.IsCRDAbsent(err):
		return
	case apierrors.IsForbidden(err):
		log.V(1).Info("VolumeSnapshot list skipped (403)", "error", err)
		for k, lv := range c.vsEmitted.Last() {
			vsRep.Carry(k, lv)
		}
		return
	case err != nil:
		summaryRep.InfraErr(fmt.Errorf("list volumesnapshots: %w", err))
		for k, lv := range c.vsEmitted.Last() {
			vsRep.Carry(k, lv)
		}
		return
	}

	for i := range vss {
		vs := &vss[i]
		if vs.GetDeletionTimestamp() != nil {
			continue
		}
		ct := vs.GetCreationTimestamp().Time
		if ct.IsZero() || now.Sub(ct) <= volumeSnapshotFailedMinAge {
			continue
		}
		readyToUse, _ := kube.NestedBool(vs.Object, "status", "readyToUse")
		errMap, hasErrMap := kube.NestedMap(vs.Object, "status", "error")
		errStr, hasErrStr := kube.NestedString(vs.Object, "status", "error")
		hasErr := (hasErrMap && len(errMap) > 0) || (hasErrStr && errStr != "")
		if readyToUse && !hasErr {
			continue
		}
		ns, name := vs.GetNamespace(), vs.GetName()
		key := ns + "/" + name
		vsRep.Flag(volumeSnapshotFailedGauge, key, []string{ns, name})
		summaryRep.Find("volumesnapshot/" + key)
	}
}
