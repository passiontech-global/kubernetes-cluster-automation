// topology_spread_zone_deadlock.go — health check "topology-spread-zone-deadlock" (#7):
// detects availability zones that previously hosted worker nodes and now have 0 Ready
// uncordoned workers continuously >=10m while >=1 other zone still has Ready workers.
// When Pending pods (>=10m) carry PodScheduled=False with "node topology spread
// constraints", emits node_automation_topology_zone_deadlock and Warning Events.
//
// File layout: this file holds the check struct, Run sweep pipeline, dead-zone
// and Pending-pod evaluation, and Warning Event emission;
// topology_spread_zone_deadlock_heal.go holds the relax/restore merge patches
// and mutation paths.
package watchdogs

import (
	"context"
	json "encoding/json/v2"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

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

type topologyRelaxRecord struct {
	By      string               `json:"by"`
	Zones   []string             `json:"zones,omitempty"`
	Relaxed []topologyRelaxEntry `json:"relaxed"`
}

type topologyRelaxEntry struct {
	Index      int    `json:"i"`
	MinDomains *int32 `json:"m,omitzero"`
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
	c.knownZones = map[string]bool{}
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

	recordedZones := topologyRecordedZones(ctx, deploys, stss)
	healthyInZone := map[string]int{}
	presentWorkerZones := map[string]bool{}
	for i := range nodes {
		n := &nodes[i]
		if kube.IsControlPlane(n) || isVirtualWorkerNode(n) {
			continue
		}
		z := n.Labels[topologyZoneKey]
		if z == "" {
			continue
		}
		presentWorkerZones[z] = true
		c.knownZones[z] = true
		if isWorkerReadyUncordoned(n) {
			healthyInZone[z]++
		}
	}
	for z := range recordedZones {
		if presentWorkerZones[z] {
			c.knownZones[z] = true
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
			if subPathSystemNamespaces[p.Namespace] {
				continue
			}
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
				if dep == nil || dep.Spec.Paused ||
					!hasZoneDoNotScheduleConstraint(dep.Spec.Template.Spec.TopologySpreadConstraints) {
					continue
				}
				blocked[wMapKey] = targetWorkload{kind: "Deployment", ns: p.Namespace, name: wName, dep: dep}
			case "StatefulSet":
				sts := stsMap[p.Namespace+"/"+wName]
				if sts == nil ||
					!hasZoneDoNotScheduleConstraint(sts.Spec.Template.Spec.TopologySpreadConstraints) {
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
				if !eligibleDeploymentForRelax(ctx, tw.dep) {
					continue
				}
				c.relaxDeployment(ctx, log, &rep, tw.dep, confirmedDeadZones, now)
			case "StatefulSet":
				if kube.EffectiveAnnos(ctx, tw.sts)[kube.AnnoTopologyRelaxOptIn] != "true" {
					continue
				}
				c.relaxStatefulSet(ctx, log, &rep, tw.sts, confirmedDeadZones, now)
			}
		}
	}

	if allZonesHealthyPersisted && c.relaxEnabled {
		c.restoreRelaxedWorkloads(ctx, log, &rep, deploys, stss, healthyZoneCount, now)
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
	if kube.HasTaint(n.Spec.Taints, corev1.TaintNodeUnschedulable) {
		return false
	}
	return !kube.HasRemediationTaint(n)
}

func isVirtualWorkerNode(n *corev1.Node) bool {
	if n.Labels["liqo.io/type"] == "virtual-node" {
		return true
	}
	if n.Labels["virtual-kubelet.io/provider"] != "" {
		return true
	}
	if n.Labels["type"] == "virtual-kubelet" {
		return true
	}
	return n.Labels[corev1.LabelInstanceTypeStable] == "external"
}

func topologyRecordedZones(ctx context.Context, deploys []appsv1.Deployment, stss []appsv1.StatefulSet) map[string]bool {
	out := map[string]bool{}
	add := func(anno string) {
		rec, ok := parseTopologyRelaxRecord(anno)
		if !ok {
			return
		}
		for _, z := range rec.Zones {
			if z != "" {
				out[z] = true
			}
		}
	}
	for i := range deploys {
		add(kube.EffectiveAnnos(ctx, &deploys[i])[kube.AnnoTopologyRelaxedBy])
	}
	for i := range stss {
		add(kube.EffectiveAnnos(ctx, &stss[i])[kube.AnnoTopologyRelaxedBy])
	}
	return out
}

func parseTopologyRelaxRecord(anno string) (topologyRelaxRecord, bool) {
	var rec topologyRelaxRecord
	if anno == "" || json.Unmarshal([]byte(anno), &rec) != nil {
		return rec, false
	}
	if rec.By != topologyRelaxedMarkerValue {
		return rec, false
	}
	return rec, true
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

func eligibleDeploymentForRelax(ctx context.Context, dep *appsv1.Deployment) bool {
	if kube.EffectiveAnnos(ctx, dep)[kube.AnnoTopologyRelaxOptOut] == "true" {
		return false
	}
	return !isSubPathDBQuorumWorkload(dep.Spec.Template.Labels)
}

func (c *topologySpreadZoneDeadlockCheck) emitTopologyEvent(ctx context.Context, kind, ns, name, zone string, now time.Time) {
	key := ns + "/" + kind + "/" + name + "/" + zone
	probefw.EmitWarningDeduped(ctx, c.CS, logf.FromContext(ctx), &c.eventCooldown, key, topologyEventCooldown, now, kube.WarningEvent{
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
	})
}
