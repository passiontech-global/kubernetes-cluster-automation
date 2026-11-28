// pvc_lifecycle_extensions.go — Wave 7 extensions for pvc-lifecycle-guard:
//  1. Default StorageClass count != 1 anomaly (multiple_defaults | zero_defaults).
//  2. Deployment(RollingUpdate) + RWO/RWOP PVC Multi-Attach deadlock >= 10m on live node
//     with opt-in old-pod UID deletion (NODE_AUTOMATION_RWO_DEADLOCK_HEAL_ENABLED).
//  3. CSINode allocatable.count volume attachment exhaustion >= 90%
//     with opt-in PreferNoSchedule taint (NODE_AUTOMATION_CSINODE_TAINT_ENABLED).
package pvc

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

const (
	pvcExtEventCooldown     = 30 * time.Minute
	rwoDeadlockMinAge       = 10 * time.Minute
	rwoDeadlockHealCooldown = 15 * time.Minute
	csiTaintCooldown        = 30 * time.Minute
	csiVolumePressureTaint  = "passiontech.dev/csi-volume-pressure"
)

func (c *pvcLifecycleGuardCheck) scanDefaultStorageClasses(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	scDefaultRep *probefw.SweepReport,
	summaryRep *probefw.SweepReport,
) {
	scs, err := c.AllStorageClasses(ctx)
	switch {
	case kube.IsCRDAbsent(err):
		return
	case apierrors.IsForbidden(err):
		log.V(1).Info("StorageClass list skipped (403)", "error", err)
		for k, lv := range c.scDefaultEmitted.Last() {
			scDefaultRep.Carry(k, lv)
		}
		return
	case err != nil:
		summaryRep.InfraErr(fmt.Errorf("list storageclasses for default check: %w", err))
		for k, lv := range c.scDefaultEmitted.Last() {
			scDefaultRep.Carry(k, lv)
		}
		return
	}

	defaultCount := 0
	for i := range scs {
		annos := scs[i].Annotations
		if annos["storageclass.kubernetes.io/is-default-class"] == "true" ||
			annos["storageclass.beta.kubernetes.io/is-default-class"] == "true" {
			defaultCount++
		}
	}
	if defaultCount == 1 {
		return
	}

	reason := "multiple_defaults"
	note := fmt.Sprintf("cluster has %d default StorageClasses; expected exactly 1", defaultCount)
	if defaultCount == 0 {
		reason = "zero_defaults"
		note = fmt.Sprintf("cluster has 0 default StorageClasses across %d StorageClasses; expected 1", len(scs))
	}
	scDefaultRep.Flag(storageClassDefaultAnomalyGauge, reason, []string{reason})
	probefw.EmitWarningDeduped(ctx, c.CS, log, &c.eventCooldown, "sc-default/"+reason,
		pvcExtEventCooldown, now, kube.WarningEvent{
			Name:      kube.TruncatedEventName("sc-default."+reason, reason, now),
			Namespace: "default",
			Reason:    "StorageClassDefaultAnomaly",
			Note:      note,
			Regarding: corev1.ObjectReference{
				APIVersion: "v1",
				Kind:       "Namespace",
				Name:       "default",
			},
			ReportingInstance: c.Name,
		})
}

func isRWOPVC(pvc *corev1.PersistentVolumeClaim) bool {
	for _, m := range pvc.Spec.AccessModes {
		if m == corev1.ReadWriteOnce || m == corev1.ReadWriteOncePod {
			return true
		}
	}
	return false
}

func (c *pvcLifecycleGuardCheck) scanRWORollingUpdateDeadlocks(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	rwoRep *probefw.SweepReport,
	summaryRep *probefw.SweepReport,
) {
	pvcs, err := c.AllPVCs(ctx)
	if err != nil {
		for k, lv := range c.rwoEmitted.Last() {
			rwoRep.Carry(k, lv)
		}
		return
	}

	var pendRWO []*corev1.PersistentVolumeClaim
	for i := range pvcs {
		p := &pvcs[i]
		if p.DeletionTimestamp != nil || !isRWOPVC(p) {
			continue
		}
		if p.Status.Phase == corev1.ClaimBound {
			// Also include Bound PVCs: an RWO PVC already Bound on an old pod's node
			// stays Bound while the RollingUpdate replacement Pending pod Multi-Attaches.
			pendRWO = append(pendRWO, p)
		}
	}
	if len(pendRWO) == 0 {
		c.rwoSeen.Prune(func(string) bool { return false })
		return
	}

	pods, podsErr := c.AllPods(ctx)
	events, eventsErr := c.AllEvents(ctx)
	deps, depsErr := c.AllDeployments(ctx)
	rss, rssErr := c.AllReplicaSets(ctx)
	nodes, nodesErr := c.AllNodes(ctx)
	if podsErr != nil || eventsErr != nil || depsErr != nil || rssErr != nil || nodesErr != nil {
		for _, lerr := range []error{podsErr, eventsErr, depsErr, rssErr, nodesErr} {
			if lerr != nil && !apierrors.IsForbidden(lerr) {
				summaryRep.InfraErr(fmt.Errorf("rwo deadlock census: %w", lerr))
				break
			}
		}
		for k, lv := range c.rwoEmitted.Last() {
			rwoRep.Carry(k, lv)
		}
		return
	}

	liveReadyNodes := make(map[string]bool, len(nodes))
	for i := range nodes {
		if kube.NodeReady(&nodes[i]) {
			liveReadyNodes[nodes[i].Name] = true
		}
	}

	rollingDeps := map[string]*appsv1.Deployment{}
	for i := range deps {
		d := &deps[i]
		if d.DeletionTimestamp != nil {
			continue
		}
		if d.Spec.Strategy.Type == "" || d.Spec.Strategy.Type == appsv1.RollingUpdateDeploymentStrategyType {
			rollingDeps[d.Namespace+"/"+d.Name] = d
		}
	}

	rsToDep := map[string]string{}
	for i := range rss {
		rs := &rss[i]
		for _, ref := range rs.OwnerReferences {
			if ref.Kind == "Deployment" && ref.Name != "" {
				rsToDep[rs.Namespace+"/"+rs.Name] = rs.Namespace + "/" + ref.Name
				break
			}
		}
	}

	multiAttachByPod := map[string]*corev1.Event{}
	for i := range events {
		ev := &events[i]
		if ev.InvolvedObject.Kind != "Pod" {
			continue
		}
		msgLower := strings.ToLower(ev.Message)
		if ev.Reason != "FailedAttachVolume" && !strings.Contains(msgLower, "multi-attach") {
			continue
		}
		if !strings.Contains(msgLower, "multi-attach") && !strings.Contains(msgLower, "already exclusively attached") {
			continue
		}
		ns := ev.InvolvedObject.Namespace
		if ns == "" {
			ns = ev.Namespace
		}
		pk := ns + "/" + ev.InvolvedObject.Name
		if prev, ok := multiAttachByPod[pk]; !ok || kube.EventTime(ev).After(kube.EventTime(prev)) {
			multiAttachByPod[pk] = ev
		}
	}

	podsByPVC := map[string][]*corev1.Pod{}
	for i := range pods {
		pod := &pods[i]
		if pod.DeletionTimestamp != nil || kube.IsPodDeleted(ctx, pod.UID) {
			continue
		}
		for _, claim := range kube.PodClaimedPVCs(pod) {
			podsByPVC[pod.Namespace+"/"+claim] = append(podsByPVC[pod.Namespace+"/"+claim], pod)
		}
	}

	podDep := func(pod *corev1.Pod) string {
		for _, ref := range pod.OwnerReferences {
			if ref.Kind == "ReplicaSet" && ref.Name != "" {
				return rsToDep[pod.Namespace+"/"+ref.Name]
			}
		}
		return ""
	}

	rwoKeep := map[string]bool{}
	for _, pvc := range pendRWO {
		pvcKey := pvc.Namespace + "/" + pvc.Name
		claimPods := podsByPVC[pvcKey]
		if len(claimPods) < 2 {
			continue
		}
		var newPod *corev1.Pod
		var multiEv *corev1.Event
		var depKey string
		for _, pod := range claimPods {
			if pod.Status.Phase != corev1.PodPending {
				continue
			}
			ev := multiAttachByPod[pod.Namespace+"/"+pod.Name]
			if ev == nil {
				continue
			}
			dk := podDep(pod)
			if dk == "" || rollingDeps[dk] == nil {
				continue
			}
			newPod, multiEv, depKey = pod, ev, dk
			break
		}
		if newPod == nil {
			continue
		}

		// Find an older pod from the same Deployment still holding the PVC on a live node.
		var oldPod *corev1.Pod
		for _, pod := range claimPods {
			if pod.UID == newPod.UID && pod.Name == newPod.Name {
				continue
			}
			if pod.Spec.NodeName == "" || !liveReadyNodes[pod.Spec.NodeName] {
				continue
			}
			if podDep(pod) != depKey {
				continue
			}
			if oldPod == nil || pod.CreationTimestamp.Before(&oldPod.CreationTimestamp) {
				oldPod = pod
			}
		}
		if oldPod == nil {
			continue
		}

		evAt := multiEv.FirstTimestamp.Time
		if evAt.IsZero() {
			evAt = kube.EventTime(multiEv)
		}
		persisted := false
		if !evAt.IsZero() && now.Sub(evAt) >= rwoDeadlockMinAge {
			persisted = true
		} else {
			rwoKeep[pvcKey] = true
			persisted = probefw.Persisted(&c.rwoSeen, pvcKey, now, rwoDeadlockMinAge, log)
		}
		if !persisted {
			continue
		}

		dep := rollingDeps[depKey]
		rwoRep.Flag(rwoRollingUpdateDeadlockGauge, pvcKey, []string{pvc.Namespace, dep.Name, pvc.Name})
		summaryRep.Find(fmt.Sprintf("pvc/%s (rwo_rollingupdate_deadlock dep=%s)", pvcKey, dep.Name))
		probefw.EmitWarningDeduped(ctx, c.CS, log, &c.eventCooldown, "rwo/"+pvcKey,
			pvcExtEventCooldown, now, kube.WarningEvent{
				Name:      kube.TruncatedEventName("rwo-deadlock."+pvc.Name, pvcKey, now),
				Namespace: pvc.Namespace,
				Reason:    "RWORollingUpdateDeadlock",
				Note: fmt.Sprintf(
					"Deployment %s/%s RollingUpdate is deadlocked on RWO/RWOP PVC %s: pod %s Multi-Attach blocked by pod %s on live node %s",
					dep.Namespace, dep.Name, pvc.Name, newPod.Name, oldPod.Name, oldPod.Spec.NodeName),
				Regarding: corev1.ObjectReference{
					APIVersion: "v1",
					Kind:       "PersistentVolumeClaim",
					Namespace:  pvc.Namespace,
					Name:       pvc.Name,
					UID:        pvc.UID,
				},
				ReportingInstance: c.Name,
			})

		if c.rwoHealEnabled {
			c.maybeDeleteOldRWOPod(ctx, log, now, dep.Name, oldPod)
		}
	}
	c.rwoSeen.Prune(func(k string) bool { return rwoKeep[k] })
}

func (c *pvcLifecycleGuardCheck) maybeDeleteOldRWOPod(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	depName string,
	oldPod *corev1.Pod,
) {
	ck := probefw.SelfHealKey(CheckNamePVCLifecycleGuard, "rwo/"+oldPod.Namespace+"/"+depName)
	proceed, unverifiable := c.HealAllowed(ctx, log, &c.rwoHeals, ck, rwoDeadlockHealCooldown, now)
	switch {
	case unverifiable:
		metrics.IncError(c.Name)
		return
	case !proceed:
		return
	}
	err := c.CS.CoreV1().Pods(oldPod.Namespace).Delete(ctx, oldPod.Name, kube.UIDDeleteOptions(oldPod.UID, ""))
	switch {
	case apierrors.IsNotFound(err) || apierrors.IsConflict(err):
		heal.RefundGrant(now)
		kube.MarkPodDeleted(ctx, oldPod.UID)
	case apierrors.IsForbidden(err):
		heal.RefundGrant(now)
		log.V(1).Info("WARN: RWO deadlock pod delete forbidden", "pod", oldPod.Namespace+"/"+oldPod.Name)
	case err != nil:
		metrics.IncError(c.Name)
		log.Error(err, "RWO deadlock old pod delete failed", "pod", oldPod.Namespace+"/"+oldPod.Name)
	default:
		c.rwoHeals.Stamp(ck, now)
		kube.MarkPodDeleted(ctx, oldPod.UID)
		c.InvalidatePods(ctx)
		log.Info("ACTION: deleted old RWO-holding pod to unblock Deployment RollingUpdate",
			"pod", oldPod.Namespace+"/"+oldPod.Name, "deployment", depName, "node", oldPod.Spec.NodeName)
	}
}

func (c *pvcLifecycleGuardCheck) scanCSINodeVolumePressure(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	csiRep *probefw.SweepReport,
	summaryRep *probefw.SweepReport,
) {
	csiNodes, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: probefw.HealthListPageSize, ResourceVersion: "0"},
		func(ctx context.Context, opts metav1.ListOptions) ([]storagev1.CSINode, string, error) {
			l, lerr := c.CS.StorageV1().CSINodes().List(ctx, opts)
			if lerr != nil {
				return nil, "", lerr
			}
			return l.Items, l.Continue, nil
		})
	switch {
	case err == nil:
	case apierrors.IsForbidden(err) || kube.IsCRDAbsent(err):
		return
	default:
		summaryRep.InfraErr(fmt.Errorf("list csinodes: %w", err))
		for k, lv := range c.csiEmitted.Last() {
			csiRep.Carry(k, lv)
		}
		return
	}
	if len(csiNodes) == 0 {
		return
	}

	vas, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: probefw.HealthListPageSize, ResourceVersion: "0"},
		func(ctx context.Context, opts metav1.ListOptions) ([]storagev1.VolumeAttachment, string, error) {
			l, lerr := c.CS.StorageV1().VolumeAttachments().List(ctx, opts)
			if lerr != nil {
				return nil, "", lerr
			}
			return l.Items, l.Continue, nil
		})
	switch {
	case err == nil:
	case apierrors.IsForbidden(err) || kube.IsCRDAbsent(err):
		return
	default:
		summaryRep.InfraErr(fmt.Errorf("list volumeattachments: %w", err))
		for k, lv := range c.csiEmitted.Last() {
			csiRep.Carry(k, lv)
		}
		return
	}

	attached := make(map[string]int, len(vas))
	for i := range vas {
		va := &vas[i]
		if va.DeletionTimestamp != nil || va.Spec.NodeName == "" || va.Spec.Attacher == "" {
			continue
		}
		attached[va.Spec.NodeName+"/"+va.Spec.Attacher]++
	}

	for i := range csiNodes {
		cn := &csiNodes[i]
		for _, drv := range cn.Spec.Drivers {
			if drv.Allocatable == nil || drv.Allocatable.Count == nil || *drv.Allocatable.Count <= 0 {
				continue
			}
			limit := int(*drv.Allocatable.Count)
			used := attached[cn.Name+"/"+drv.Name]
			if used*100 < 90*limit {
				continue
			}
			k := cn.Name + "/" + drv.Name
			csiRep.Flag(csiVolumePressureGauge, k, []string{cn.Name, drv.Name})
			summaryRep.Find(fmt.Sprintf("csinode/%s (%d/%d volumes)", k, used, limit))
			probefw.EmitWarningDeduped(ctx, c.CS, log, &c.eventCooldown, "csinode/"+k,
				pvcExtEventCooldown, now, kube.WarningEvent{
					Name:      kube.TruncatedEventName("csinode-pressure."+cn.Name+"."+drv.Name, k, now),
					Namespace: "default",
					Reason:    "CSINodeVolumePressure",
					Note: fmt.Sprintf(
						"CSINode %s driver %s volume attachments %d/%d (>=90%% of allocatable.count)",
						cn.Name, drv.Name, used, limit),
					Regarding: corev1.ObjectReference{
						APIVersion: "v1",
						Kind:       "Node",
						Name:       cn.Name,
					},
					ReportingInstance: c.Name,
				})
			if c.csiTaintEnabled {
				c.maybeTaintCSIPressureNode(ctx, log, now, cn.Name)
			}
		}
	}
}

func (c *pvcLifecycleGuardCheck) maybeTaintCSIPressureNode(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	nodeName string,
) {
	ck := probefw.SelfHealKey(CheckNamePVCLifecycleGuard, "csinode/"+nodeName)
	proceed, unverifiable := c.HealAllowed(ctx, log, &c.csiHeals, ck, csiTaintCooldown, now)
	switch {
	case unverifiable:
		metrics.IncError(c.Name)
		return
	case !proceed:
		return
	}
	err := kube.TaintNode(ctx, c.CS, nodeName, csiVolumePressureTaint, "true", corev1.TaintEffectPreferNoSchedule)
	switch {
	case apierrors.IsNotFound(err) || apierrors.IsForbidden(err):
		heal.RefundGrant(now)
	case err != nil:
		heal.RefundGrant(now)
		metrics.IncError(c.Name)
		log.Error(err, "taint CSINode volume-pressure node failed", "node", nodeName)
	default:
		c.csiHeals.Stamp(ck, now)
		c.InvalidateNodes(ctx)
		log.Info("ACTION: tainted node PreferNoSchedule for CSI volume attachment exhaustion",
			"node", nodeName, "taint", csiVolumePressureTaint)
	}
}
