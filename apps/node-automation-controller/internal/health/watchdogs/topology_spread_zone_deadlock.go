// topology_spread_zone_deadlock.go — health check "topology-spread-zone-deadlock" (#7):
// detects availability zones that previously hosted worker nodes and now have 0 Ready
// uncordoned workers continuously >=10m while >=1 other zone still has Ready workers.
// When Pending pods (>=10m) carry PodScheduled=False with "node topology spread
// constraints", emits node_automation_topology_zone_deadlock and Warning Events.
// When NODE_AUTOMATION_TOPOLOGY_ZONE_RELAX_ENABLED=true, relaxes
// topology.kubernetes.io/zone DoNotSchedule -> ScheduleAnyway on eligible stateless
// Deployments (excluding DB quorum labels and AnnoTopologyRelaxOptOut=="true") and
// opted-in StatefulSets (AnnoTopologyRelaxOptIn=="true") via HealAllowed + FluxPatchGate,
// stamping AnnoTopologyRelaxedBy. Auto-restores DoNotSchedule once all zones have >=1
// Ready uncordoned worker continuously >=10m.
package watchdogs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

const (
	// CheckNameTopologyZoneDeadlock is the registry check name for #7.
	CheckNameTopologyZoneDeadlock = "topology-spread-zone-deadlock"

	topologyDeadZoneMinAge     = 10 * time.Minute
	topologyPendingMinAge      = 10 * time.Minute
	topologyRestoreMinAge      = 10 * time.Minute
	topologyPatchCooldown      = 30 * time.Minute
	topologyEventCooldown      = 30 * time.Minute
	topologyZoneKey            = corev1.LabelTopologyZone
	topologyRelaxedMarkerValue = "topology-spread-zone-deadlock"
)

var topologyZoneDeadlockGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_topology_zone_deadlock",
	Help: "1 while a workload has pods Pending >=10m due to zone topology spread constraints against a dead zone.",
}, []string{"namespace", "workload", "zone"})

func init() {
	ctrlmetrics.Registry.MustRegister(topologyZoneDeadlockGauge)
}

type topologySpreadZoneDeadlockCheck struct {
	*probefw.Deps

	relaxEnabled        bool
	knownZones          map[string]bool
	zoneDeadSince       state.FirstSeenLedger
	zoneAllHealthySince state.FirstSeenLedger
	podPendingSince     state.FirstSeenLedger
	emitted             state.GaugeLedger[string]
	eventCooldown       state.CooldownSet
	healCooldowns       state.CooldownSet
}

// NewTopologySpreadZoneDeadlockCheck builds the topology-spread-zone-deadlock check.
func NewTopologySpreadZoneDeadlockCheck(d *probefw.Deps) probefw.Check {
	return &topologySpreadZoneDeadlockCheck{
		Deps:         d,
		relaxEnabled: envx.Gate("NODE_AUTOMATION_TOPOLOGY_ZONE_RELAX_ENABLED", true),
	}
}

func (c *topologySpreadZoneDeadlockCheck) Run(ctx context.Context) probefw.Result {
	now := c.Now()
	c.eventCooldown.PruneExpired(now, topologyEventCooldown)
	c.healCooldowns.PruneExpired(now, topologyPatchCooldown)
	if c.knownZones == nil {
		c.knownZones = map[string]bool{}
	}
	var rep probefw.SweepReport
	log := logf.FromContext(ctx)

	nodes, err := c.AllNodes(ctx)
	if err != nil {
		return carryTopologyOnErr(&rep, &c.emitted, err, "list nodes")
	}
	pods, err := c.AllPods(ctx)
	if err != nil {
		return carryTopologyOnErr(&rep, &c.emitted, err, "list pods")
	}
	rss, err := c.AllReplicaSets(ctx)
	if err != nil {
		return carryTopologyOnErr(&rep, &c.emitted, err, "list replicasets")
	}
	deploys, err := c.AllDeployments(ctx)
	if err != nil {
		return carryTopologyOnErr(&rep, &c.emitted, err, "list deployments")
	}
	stss, err := c.AllStatefulSets(ctx)
	if err != nil {
		return carryTopologyOnErr(&rep, &c.emitted, err, "list statefulsets")
	}

	healthyInZone := map[string]int{}
	for i := range nodes {
		n := &nodes[i]
		if kube.IsControlPlane(n) {
			continue
		}
		z := n.Labels[topologyZoneKey]
		if z == "" {
			continue
		}
		c.knownZones[z] = true
		if isWorkerReadyUncordoned(n) {
			healthyInZone[z]++
		}
	}

	healthyZoneCount := 0
	for z := range c.knownZones {
		if healthyInZone[z] > 0 {
			healthyZoneCount++
		}
	}

	deadZoneSeen := map[string]bool{}
	var confirmedDeadZones []string
	if len(c.knownZones) > 0 && healthyZoneCount >= 1 {
		for z := range c.knownZones {
			if healthyInZone[z] == 0 {
				deadZoneSeen[z] = true
				first, _ := c.zoneDeadSince.Observe(z, now)
				if now.Sub(first) >= topologyDeadZoneMinAge {
					confirmedDeadZones = append(confirmedDeadZones, z)
				}
			}
		}
	}
	c.zoneDeadSince.Prune(func(k string) bool { return deadZoneSeen[k] })

	allZonesHealthy := len(c.knownZones) > 0 && len(deadZoneSeen) == 0 && healthyZoneCount == len(c.knownZones)
	allZonesHealthyPersisted := false
	if allZonesHealthy {
		firstHealthy, _ := c.zoneAllHealthySince.Observe("all", now)
		if now.Sub(firstHealthy) >= topologyRestoreMinAge {
			allZonesHealthyPersisted = true
		}
	} else {
		c.zoneAllHealthySince.Forget("all")
	}

	rsOwner := make(map[string]string, len(rss))
	for i := range rss {
		rs := &rss[i]
		for j := range rs.OwnerReferences {
			ref := &rs.OwnerReferences[j]
			if ref.Controller != nil && *ref.Controller && ref.Kind == "Deployment" {
				rsOwner[rs.Namespace+"/"+rs.Name] = ref.Name
				break
			}
		}
	}
	deployMap := make(map[string]*appsv1.Deployment, len(deploys))
	for i := range deploys {
		d := &deploys[i]
		deployMap[d.Namespace+"/"+d.Name] = d
	}
	stsMap := make(map[string]*appsv1.StatefulSet, len(stss))
	for i := range stss {
		s := &stss[i]
		stsMap[s.Namespace+"/"+s.Name] = s
	}

	pendingSeen := map[string]bool{}
	defer c.podPendingSince.Prune(func(k string) bool { return pendingSeen[k] })

	if len(confirmedDeadZones) > 0 {
		slices.Sort(confirmedDeadZones)
		deadZoneLabel := strings.Join(confirmedDeadZones, ",")

		type targetWorkload struct {
			kind string
			ns   string
			name string
			dep  *appsv1.Deployment
			sts  *appsv1.StatefulSet
		}
		blocked := map[string]targetWorkload{}

		for i := range pods {
			p := &pods[i]
			if p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodPending {
				continue
			}
			cond := findPodCondition(p, corev1.PodScheduled)
			if cond == nil || cond.Status != corev1.ConditionFalse ||
				!strings.Contains(cond.Message, "topology spread constraints") {
				continue
			}
			podKey := p.Namespace + "/" + p.Name
			pendingSeen[podKey] = true
			firstSeen, _ := c.podPendingSince.Observe(podKey, now)
			stuckLongEnough := (!cond.LastTransitionTime.IsZero() && now.Sub(cond.LastTransitionTime.Time) >= topologyPendingMinAge) ||
				now.Sub(firstSeen) >= topologyPendingMinAge
			if !stuckLongEnough {
				continue
			}

			wKind, wName := tracePodOwnerWorkload(p, rsOwner)
			if wKind == "" || wName == "" {
				continue
			}
			wMapKey := wKind + "/" + p.Namespace + "/" + wName
			switch wKind {
			case "Deployment":
				dep := deployMap[p.Namespace+"/"+wName]
				if dep == nil || !hasZoneDoNotScheduleConstraint(dep.Spec.Template.Spec.TopologySpreadConstraints) {
					continue
				}
				blocked[wMapKey] = targetWorkload{kind: "Deployment", ns: p.Namespace, name: wName, dep: dep}
			case "StatefulSet":
				sts := stsMap[p.Namespace+"/"+wName]
				if sts == nil || !hasZoneDoNotScheduleConstraint(sts.Spec.Template.Spec.TopologySpreadConstraints) {
					continue
				}
				blocked[wMapKey] = targetWorkload{kind: "StatefulSet", ns: p.Namespace, name: wName, sts: sts}
			}
		}

		for _, k := range slices.Sorted(maps.Keys(blocked)) {
			tw := blocked[k]
			gaugeKey := tw.ns + "/" + tw.name + "/" + deadZoneLabel
			rep.Emit(topologyZoneDeadlockGauge, gaugeKey,
				[]string{tw.ns, tw.name, deadZoneLabel},
				fmt.Sprintf("%s/%s (%s blocked by dead zone %s)", tw.ns, tw.name, tw.kind, deadZoneLabel))
			c.emitTopologyEvent(ctx, tw.kind, tw.ns, tw.name, deadZoneLabel, now)

			if !c.relaxEnabled {
				continue
			}
			switch tw.kind {
			case "Deployment":
				if !eligibleDeploymentForRelax(tw.dep) {
					continue
				}
				c.relaxDeployment(ctx, log, tw.dep, now)
			case "StatefulSet":
				if tw.sts.Annotations[kube.AnnoTopologyRelaxOptIn] != "true" {
					continue
				}
				c.relaxStatefulSet(ctx, log, tw.sts, now)
			}
		}
	}

	if allZonesHealthyPersisted && c.relaxEnabled {
		c.restoreRelaxedWorkloads(ctx, log, deploys, stss, now)
	}

	return rep.Result(&c.emitted, topologyZoneDeadlockGauge.DeleteLabelValues,
		"topology spread zone deadlock: ", ", ")
}

func carryTopologyOnErr(rep *probefw.SweepReport, ledger *state.GaugeLedger[string], err error, what string) probefw.Result {
	for k, lv := range ledger.Last() {
		rep.Carry(k, lv)
	}
	rep.InfraErr(fmt.Errorf("%s: %w", what, err))
	return rep.Result(ledger, topologyZoneDeadlockGauge.DeleteLabelValues,
		"topology spread zone deadlock: ", ", ")
}

func isWorkerReadyUncordoned(n *corev1.Node) bool {
	if !kube.NodeReady(n) || n.Spec.Unschedulable {
		return false
	}
	return !kube.HasTaint(n.Spec.Taints, corev1.TaintNodeUnschedulable)
}

func findPodCondition(p *corev1.Pod, t corev1.PodConditionType) *corev1.PodCondition {
	for i := range p.Status.Conditions {
		if p.Status.Conditions[i].Type == t {
			return &p.Status.Conditions[i]
		}
	}
	return nil
}

func tracePodOwnerWorkload(p *corev1.Pod, rsOwner map[string]string) (kind, name string) {
	for i := range p.OwnerReferences {
		ref := &p.OwnerReferences[i]
		if ref.Controller == nil || !*ref.Controller {
			continue
		}
		switch ref.Kind {
		case "StatefulSet":
			return "StatefulSet", ref.Name
		case "ReplicaSet":
			if depName := rsOwner[p.Namespace+"/"+ref.Name]; depName != "" {
				return "Deployment", depName
			}
		}
	}
	return "", ""
}

func hasZoneDoNotScheduleConstraint(tscs []corev1.TopologySpreadConstraint) bool {
	for i := range tscs {
		if tscs[i].TopologyKey == topologyZoneKey &&
			tscs[i].WhenUnsatisfiable == corev1.DoNotSchedule {
			return true
		}
	}
	return false
}

func hasZoneScheduleAnywayConstraint(tscs []corev1.TopologySpreadConstraint) bool {
	for i := range tscs {
		if tscs[i].TopologyKey == topologyZoneKey &&
			tscs[i].WhenUnsatisfiable == corev1.ScheduleAnyway {
			return true
		}
	}
	return false
}

func eligibleDeploymentForRelax(dep *appsv1.Deployment) bool {
	if dep.Annotations[kube.AnnoTopologyRelaxOptOut] == "true" {
		return false
	}
	for _, k := range subPathDBQuorumLabels {
		if dep.Spec.Template.Labels[k] != "" {
			return false
		}
	}
	return true
}

func rewriteZoneConstraintsPatch(tscs []corev1.TopologySpreadConstraint, target corev1.UnsatisfiableConstraintAction, annoVal any) ([]byte, bool) {
	updated := make([]corev1.TopologySpreadConstraint, len(tscs))
	changed := false
	for i := range tscs {
		updated[i] = tscs[i]
		if updated[i].TopologyKey == topologyZoneKey && updated[i].WhenUnsatisfiable != target {
			updated[i].WhenUnsatisfiable = target
			changed = true
		}
	}
	if !changed {
		return nil, false
	}
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

func (c *topologySpreadZoneDeadlockCheck) relaxDeployment(ctx context.Context, log interface {
	Info(string, ...any)
	Error(error, string, ...any)
}, dep *appsv1.Deployment, now time.Time) {
	wKey := dep.Namespace + "/Deployment/" + dep.Name
	proceed, unverifiable := c.HealAllowed(ctx, logf.FromContext(ctx), &c.healCooldowns, wKey, topologyPatchCooldown, now)
	if !proceed {
		if unverifiable {
			log.Error(errors.New("maintenance mutex unverifiable"), "skip relax deployment", "workload", wKey)
		}
		return
	}
	if !kube.TryReserveWorkloadKey(ctx, wKey) ||
		!heal.FluxPatchGate("deployment", dep, dep.Namespace+"/"+dep.Name, now) {
		heal.RefundGrant(now)
		return
	}
	payload, ok := rewriteZoneConstraintsPatch(dep.Spec.Template.Spec.TopologySpreadConstraints, corev1.ScheduleAnyway, topologyRelaxedMarkerValue)
	if !ok {
		heal.RefundGrant(now)
		return
	}
	if _, err := c.CS.AppsV1().Deployments(dep.Namespace).Patch(ctx, dep.Name, types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		log.Error(err, "topology zone relax Deployment patch failed", "workload", wKey)
		return
	}
	c.healCooldowns.Stamp(wKey, now)
	c.InvalidateDeployments(ctx)
	log.Info("ACTION: relaxed zone TopologySpreadConstraints DoNotSchedule -> ScheduleAnyway during dead zone", "workload", wKey)
}

func (c *topologySpreadZoneDeadlockCheck) relaxStatefulSet(ctx context.Context, log interface {
	Info(string, ...any)
	Error(error, string, ...any)
}, sts *appsv1.StatefulSet, now time.Time) {
	wKey := sts.Namespace + "/StatefulSet/" + sts.Name
	proceed, unverifiable := c.HealAllowed(ctx, logf.FromContext(ctx), &c.healCooldowns, wKey, topologyPatchCooldown, now)
	if !proceed {
		if unverifiable {
			log.Error(errors.New("maintenance mutex unverifiable"), "skip relax statefulset", "workload", wKey)
		}
		return
	}
	if !kube.TryReserveWorkloadKey(ctx, wKey) ||
		!heal.FluxPatchGate("statefulset", sts, sts.Namespace+"/"+sts.Name, now) {
		heal.RefundGrant(now)
		return
	}
	payload, ok := rewriteZoneConstraintsPatch(sts.Spec.Template.Spec.TopologySpreadConstraints, corev1.ScheduleAnyway, topologyRelaxedMarkerValue)
	if !ok {
		heal.RefundGrant(now)
		return
	}
	if _, err := c.CS.AppsV1().StatefulSets(sts.Namespace).Patch(ctx, sts.Name, types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		log.Error(err, "topology zone relax StatefulSet patch failed", "workload", wKey)
		return
	}
	c.healCooldowns.Stamp(wKey, now)
	c.InvalidateStatefulSets(ctx)
	log.Info("ACTION: relaxed zone TopologySpreadConstraints DoNotSchedule -> ScheduleAnyway during dead zone", "workload", wKey)
}

func (c *topologySpreadZoneDeadlockCheck) restoreRelaxedWorkloads(ctx context.Context, log interface {
	Info(string, ...any)
	Error(error, string, ...any)
}, deploys []appsv1.Deployment, stss []appsv1.StatefulSet, now time.Time) {
	for i := range deploys {
		dep := &deploys[i]
		if dep.Annotations[kube.AnnoTopologyRelaxedBy] == "" ||
			!hasZoneScheduleAnywayConstraint(dep.Spec.Template.Spec.TopologySpreadConstraints) {
			continue
		}
		wKey := dep.Namespace + "/Deployment/" + dep.Name
		proceed, _ := c.HealAllowed(ctx, logf.FromContext(ctx), &c.healCooldowns, wKey, topologyPatchCooldown, now)
		if !proceed {
			continue
		}
		if !kube.TryReserveWorkloadKey(ctx, wKey) ||
			!heal.FluxPatchGate("deployment", dep, dep.Namespace+"/"+dep.Name, now) {
			heal.RefundGrant(now)
			continue
		}
		payload, ok := rewriteZoneConstraintsPatch(dep.Spec.Template.Spec.TopologySpreadConstraints, corev1.DoNotSchedule, nil)
		if !ok {
			heal.RefundGrant(now)
			continue
		}
		if _, err := c.CS.AppsV1().Deployments(dep.Namespace).Patch(ctx, dep.Name, types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
			log.Error(err, "topology zone restore Deployment patch failed", "workload", wKey)
			continue
		}
		c.healCooldowns.Stamp(wKey, now)
		c.InvalidateDeployments(ctx)
		log.Info("ACTION: restored zone TopologySpreadConstraints ScheduleAnyway -> DoNotSchedule after zone recovery", "workload", wKey)
	}
	for i := range stss {
		sts := &stss[i]
		if sts.Annotations[kube.AnnoTopologyRelaxedBy] == "" ||
			!hasZoneScheduleAnywayConstraint(sts.Spec.Template.Spec.TopologySpreadConstraints) {
			continue
		}
		wKey := sts.Namespace + "/StatefulSet/" + sts.Name
		proceed, _ := c.HealAllowed(ctx, logf.FromContext(ctx), &c.healCooldowns, wKey, topologyPatchCooldown, now)
		if !proceed {
			continue
		}
		if !kube.TryReserveWorkloadKey(ctx, wKey) ||
			!heal.FluxPatchGate("statefulset", sts, sts.Namespace+"/"+sts.Name, now) {
			heal.RefundGrant(now)
			continue
		}
		payload, ok := rewriteZoneConstraintsPatch(sts.Spec.Template.Spec.TopologySpreadConstraints, corev1.DoNotSchedule, nil)
		if !ok {
			heal.RefundGrant(now)
			continue
		}
		if _, err := c.CS.AppsV1().StatefulSets(sts.Namespace).Patch(ctx, sts.Name, types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
			log.Error(err, "topology zone restore StatefulSet patch failed", "workload", wKey)
			continue
		}
		c.healCooldowns.Stamp(wKey, now)
		c.InvalidateStatefulSets(ctx)
		log.Info("ACTION: restored zone TopologySpreadConstraints ScheduleAnyway -> DoNotSchedule after zone recovery", "workload", wKey)
	}
}

func (c *topologySpreadZoneDeadlockCheck) emitTopologyEvent(ctx context.Context, kind, ns, name, zone string, now time.Time) {
	key := ns + "/" + kind + "/" + name + "/" + zone
	if c.eventCooldown.CooledDown(key, topologyEventCooldown, now) {
		return
	}
	if err := kube.EmitWarningEvent(ctx, c.CS, kube.WarningEvent{
		Namespace: ns,
		Name:      fmt.Sprintf("%s.topology-zone-deadlock.%d", name, now.Unix()),
		Reason:    "TopologyZoneDeadlock",
		Note:      fmt.Sprintf("%s %s/%s has Pending pods >=10m blocked by topology.kubernetes.io/zone against dead zone(s) %s", kind, ns, name, zone),
		Regarding: corev1.ObjectReference{
			Kind:       kind,
			APIVersion: "apps/v1",
			Namespace:  ns,
			Name:       name,
		},
		ReportingInstance: c.Name,
		Now:               now,
	}); err == nil {
		c.eventCooldown.Stamp(key, now)
	}
}
