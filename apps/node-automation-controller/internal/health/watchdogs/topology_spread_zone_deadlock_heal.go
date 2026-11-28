// topology_spread_zone_deadlock_heal.go — merge-patch builders and
// cluster-wide-only relax/restore actuation for
// topology-spread-zone-deadlock.
// Split from topology_spread_zone_deadlock.go.
package watchdogs

import (
	"context"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

func zoneConstraintsPatch(updated []corev1.TopologySpreadConstraint, annoVal any) ([]byte, bool) {
	doc := map[string]any{
		"metadata": map[string]any{
			"annotations": map[string]any{
				kube.AnnoTopologyRelaxedBy: annoVal,
			},
		},
		"spec": map[string]any{
			"template": map[string]any{
				"spec": map[string]any{
					"topologySpreadConstraints": updated,
				},
			},
		},
	}
	payload, err := json.Marshal(doc)
	if err != nil {
		return nil, false
	}
	return payload, true
}

func relaxZoneConstraintsPatch(tscs []corev1.TopologySpreadConstraint,
	deadZones []string) (payload []byte, rec topologyRelaxRecord, ok bool) {

	updated := make([]corev1.TopologySpreadConstraint, len(tscs))
	rec = topologyRelaxRecord{
		By:    topologyRelaxedMarkerValue,
		Zones: slices.Clone(deadZones),
	}
	for i := range tscs {
		updated[i] = tscs[i]
		if tscs[i].TopologyKey != topologyZoneKey ||
			tscs[i].WhenUnsatisfiable != corev1.DoNotSchedule {
			continue
		}
		rec.Relaxed = append(rec.Relaxed, topologyRelaxEntry{
			Index: i, MinDomains: tscs[i].MinDomains,
		})
		updated[i].WhenUnsatisfiable = corev1.ScheduleAnyway
		updated[i].MinDomains = nil
	}
	if len(rec.Relaxed) == 0 {
		return nil, rec, false
	}
	anno, err := json.Marshal(rec)
	if err != nil {
		return nil, rec, false
	}
	payload, ok = zoneConstraintsPatch(updated, string(anno))
	return payload, rec, ok
}

func restoreZoneConstraintsPatch(tscs []corev1.TopologySpreadConstraint,
	anno string, healthyZoneCount int) ([]byte, bool) {

	rec, valid := parseTopologyRelaxRecord(anno)
	if !valid {
		return nil, false
	}
	updated := make([]corev1.TopologySpreadConstraint, len(tscs))
	copy(updated, tscs)
	deferred := make([]topologyRelaxEntry, 0, len(rec.Relaxed))
	restored := 0
	for _, e := range rec.Relaxed {
		if e.Index < 0 || e.Index >= len(updated) {
			continue
		}
		if e.MinDomains != nil && *e.MinDomains > int32(healthyZoneCount) {
			deferred = append(deferred, e)
			continue
		}
		c := &updated[e.Index]
		if c.TopologyKey != topologyZoneKey || c.WhenUnsatisfiable != corev1.ScheduleAnyway {
			continue
		}
		c.WhenUnsatisfiable = corev1.DoNotSchedule
		c.MinDomains = e.MinDomains
		restored++
	}
	if restored == 0 {
		if len(deferred) == 0 {
			return dropTopologyRelaxAnno()
		}
		return nil, false
	}
	var annoVal any
	if len(deferred) > 0 {
		rec.Relaxed = deferred
		kept, err := json.Marshal(rec)
		if err != nil {
			return nil, false
		}
		annoVal = string(kept)
	}
	return zoneConstraintsPatch(updated, annoVal)
}

func dropTopologyRelaxAnno() ([]byte, bool) {
	payload, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"annotations": map[string]any{kube.AnnoTopologyRelaxedBy: nil},
		},
	})
	if err != nil {
		return nil, false
	}
	return payload, true
}

func (c *topologySpreadZoneDeadlockCheck) restorePatchFor(tscs []corev1.TopologySpreadConstraint,
	anno string, healthyZoneCount int) ([]byte, bool) {

	rec, valid := parseTopologyRelaxRecord(anno)
	if valid && len(rec.Relaxed) > 0 && hasZoneScheduleAnywayConstraint(tscs) {
		return restoreZoneConstraintsPatch(tscs, anno, healthyZoneCount)
	}
	return dropTopologyRelaxAnno()
}

func (c *topologySpreadZoneDeadlockCheck) relaxDeployment(ctx context.Context, log interface {
	Info(string, ...any)
	Error(error, string, ...any)
}, rep *probefw.SweepReport, dep *appsv1.Deployment, deadZones []string, now time.Time) {
	wKey := dep.Namespace + "/Deployment/" + dep.Name
	proceed, unverifiable := c.HealAllowedClusterWideOnly(ctx, logf.FromContext(ctx),
		&c.healCooldowns, wKey, topologyPatchCooldown, now)
	if !proceed {
		if unverifiable {
			infraErr := errors.New("maintenance mutex unverifiable — relax deployment deferred")
			rep.InfraErr(infraErr)
			log.Error(infraErr, "skip relax deployment", "workload", wKey)
		}
		return
	}
	if !kube.TryReserveWorkloadKey(ctx, wKey) {
		heal.RefundGrant(now)
		return
	}
	if !heal.FluxPatchGate("deployment", dep, CheckNameTopologyZoneDeadlock+":"+wKey, now) {
		kube.ReleaseWorkloadKey(ctx, wKey)
		heal.RefundGrant(now)
		return
	}
	payload, _, ok := relaxZoneConstraintsPatch(dep.Spec.Template.Spec.TopologySpreadConstraints, deadZones)
	if !ok {
		kube.ReleaseWorkloadKey(ctx, wKey)
		heal.RefundGrant(now)
		return
	}
	if _, err := c.CS.AppsV1().Deployments(dep.Namespace).Patch(ctx, dep.Name, types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		kube.ReleaseWorkloadKey(ctx, wKey)
		rep.InfraErr(fmt.Errorf("topology zone relax Deployment %s: %w", wKey, err))
		log.Error(err, "topology zone relax Deployment patch failed", "workload", wKey)
		return
	}
	c.healCooldowns.Stamp(wKey, now)
	kube.RecordAnnoPatch(ctx, dep, payload)
	c.InvalidateDeployments(ctx)
	log.Info("ACTION: relaxed zone TopologySpreadConstraints DoNotSchedule -> ScheduleAnyway during dead zone", "workload", wKey)
}

func (c *topologySpreadZoneDeadlockCheck) relaxStatefulSet(ctx context.Context, log interface {
	Info(string, ...any)
	Error(error, string, ...any)
}, rep *probefw.SweepReport, sts *appsv1.StatefulSet, deadZones []string, now time.Time) {
	wKey := sts.Namespace + "/StatefulSet/" + sts.Name
	proceed, unverifiable := c.HealAllowedClusterWideOnly(ctx, logf.FromContext(ctx),
		&c.healCooldowns, wKey, topologyPatchCooldown, now)
	if !proceed {
		if unverifiable {
			infraErr := errors.New("maintenance mutex unverifiable — relax statefulset deferred")
			rep.InfraErr(infraErr)
			log.Error(infraErr, "skip relax statefulset", "workload", wKey)
		}
		return
	}
	if !kube.TryReserveWorkloadKey(ctx, wKey) {
		heal.RefundGrant(now)
		return
	}
	if !heal.FluxPatchGate("statefulset", sts, CheckNameTopologyZoneDeadlock+":"+wKey, now) {
		kube.ReleaseWorkloadKey(ctx, wKey)
		heal.RefundGrant(now)
		return
	}
	payload, _, ok := relaxZoneConstraintsPatch(sts.Spec.Template.Spec.TopologySpreadConstraints, deadZones)
	if !ok {
		kube.ReleaseWorkloadKey(ctx, wKey)
		heal.RefundGrant(now)
		return
	}
	if _, err := c.CS.AppsV1().StatefulSets(sts.Namespace).Patch(ctx, sts.Name, types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		kube.ReleaseWorkloadKey(ctx, wKey)
		rep.InfraErr(fmt.Errorf("topology zone relax StatefulSet %s: %w", wKey, err))
		log.Error(err, "topology zone relax StatefulSet patch failed", "workload", wKey)
		return
	}
	c.healCooldowns.Stamp(wKey, now)
	kube.RecordAnnoPatch(ctx, sts, payload)
	c.InvalidateStatefulSets(ctx)
	log.Info("ACTION: relaxed zone TopologySpreadConstraints DoNotSchedule -> ScheduleAnyway during dead zone", "workload", wKey)
}

func (c *topologySpreadZoneDeadlockCheck) restoreRelaxedWorkloads(ctx context.Context, log interface {
	Info(string, ...any)
	Error(error, string, ...any)
}, rep *probefw.SweepReport, deploys []appsv1.Deployment, stss []appsv1.StatefulSet, healthyZoneCount int, now time.Time) {
	for i := range deploys {
		dep := &deploys[i]
		anno := kube.EffectiveAnnos(ctx, dep)[kube.AnnoTopologyRelaxedBy]
		if anno == "" || dep.Spec.Paused {
			continue
		}
		payload, ok := c.restorePatchFor(dep.Spec.Template.Spec.TopologySpreadConstraints, anno, healthyZoneCount)
		if !ok {
			continue
		}
		wKey := dep.Namespace + "/Deployment/" + dep.Name
		proceed, unverifiable := c.HealAllowedClusterWideOnly(ctx, logf.FromContext(ctx),
			&c.healCooldowns, wKey, topologyPatchCooldown, now)
		if !proceed {
			if unverifiable {
				infraErr := errors.New("maintenance mutex unverifiable — restore deployment deferred")
				rep.InfraErr(infraErr)
				log.Error(infraErr, "skip restore deployment", "workload", wKey)
			}
			continue
		}
		if !kube.TryReserveWorkloadKey(ctx, wKey) {
			heal.RefundGrant(now)
			continue
		}
		if !heal.FluxPatchGate("deployment", dep, CheckNameTopologyZoneDeadlock+":"+wKey, now) {
			kube.ReleaseWorkloadKey(ctx, wKey)
			heal.RefundGrant(now)
			continue
		}
		if _, err := c.CS.AppsV1().Deployments(dep.Namespace).Patch(ctx, dep.Name, types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
			kube.ReleaseWorkloadKey(ctx, wKey)
			rep.InfraErr(fmt.Errorf("topology zone restore Deployment %s: %w", wKey, err))
			log.Error(err, "topology zone restore Deployment patch failed", "workload", wKey)
			continue
		}
		c.healCooldowns.Stamp(wKey, now)
		kube.RecordAnnoPatch(ctx, dep, payload)
		c.InvalidateDeployments(ctx)
		log.Info("ACTION: restored zone TopologySpreadConstraints ScheduleAnyway -> DoNotSchedule after zone recovery", "workload", wKey)
	}
	for i := range stss {
		sts := &stss[i]
		anno := kube.EffectiveAnnos(ctx, sts)[kube.AnnoTopologyRelaxedBy]
		if anno == "" {
			continue
		}
		payload, ok := c.restorePatchFor(sts.Spec.Template.Spec.TopologySpreadConstraints, anno, healthyZoneCount)
		if !ok {
			continue
		}
		wKey := sts.Namespace + "/StatefulSet/" + sts.Name
		proceed, unverifiable := c.HealAllowedClusterWideOnly(ctx, logf.FromContext(ctx),
			&c.healCooldowns, wKey, topologyPatchCooldown, now)
		if !proceed {
			if unverifiable {
				infraErr := errors.New("maintenance mutex unverifiable — restore statefulset deferred")
				rep.InfraErr(infraErr)
				log.Error(infraErr, "skip restore statefulset", "workload", wKey)
			}
			continue
		}
		if !kube.TryReserveWorkloadKey(ctx, wKey) {
			heal.RefundGrant(now)
			continue
		}
		if !heal.FluxPatchGate("statefulset", sts, CheckNameTopologyZoneDeadlock+":"+wKey, now) {
			kube.ReleaseWorkloadKey(ctx, wKey)
			heal.RefundGrant(now)
			continue
		}
		if _, err := c.CS.AppsV1().StatefulSets(sts.Namespace).Patch(ctx, sts.Name, types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
			kube.ReleaseWorkloadKey(ctx, wKey)
			rep.InfraErr(fmt.Errorf("topology zone restore StatefulSet %s: %w", wKey, err))
			log.Error(err, "topology zone restore StatefulSet patch failed", "workload", wKey)
			continue
		}
		c.healCooldowns.Stamp(wKey, now)
		kube.RecordAnnoPatch(ctx, sts, payload)
		c.InvalidateStatefulSets(ctx)
		log.Info("ACTION: restored zone TopologySpreadConstraints ScheduleAnyway -> DoNotSchedule after zone recovery", "workload", wKey)
	}
}
