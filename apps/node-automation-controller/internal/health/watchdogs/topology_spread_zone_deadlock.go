// topology_spread_zone_deadlock.go — health check "topology-spread-zone-deadlock" (#7):
// detects availability zones that previously hosted worker nodes and now have 0 Ready
// uncordoned workers continuously >=10m while >=1 other zone still has Ready workers.
// When Pending pods (>=10m) carry PodScheduled=False with "node topology spread
// constraints", emits node_automation_topology_zone_deadlock and Warning Events.
// When NODE_AUTOMATION_TOPOLOGY_ZONE_RELAX_ENABLED=true, relaxes
// topology.kubernetes.io/zone DoNotSchedule -> ScheduleAnyway on eligible stateless
// Deployments (excluding DB quorum labels and AnnoTopologyRelaxOptOut=="true") and
// opted-in StatefulSets (AnnoTopologyRelaxOptIn=="true") via the cluster-wide-only
// heal gate + FluxPatchGate (a node-scoped cordon must not deadlock the very relax
// that unblocks its zone), stamping AnnoTopologyRelaxedBy with the exact changed
// constraint indices and their original minDomains. MinDomains is cleared on relax
// (ScheduleAnyway + minDomains is a 422 Invalid) and restored byte-for-byte on
// auto-restore — a user's own ScheduleAnyway constraint is never overwritten.
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

// topologyRelaxRecord is the value of AnnoTopologyRelaxedBy. It is
// deliberately an exact change-list, not a boolean marker: a restore
// must flip back ONLY the constraints this check relaxed, with their
// original minDomains, or it silently overwrites a ScheduleAnyway
// constraint the user wrote themselves. Zones records the dead zones
// that triggered the relax so a later sweep still knows which zone a
// pod restart / zone deletion should be attributed to.
type topologyRelaxRecord struct {
	By      string               `json:"by"`
	Zones   []string             `json:"zones,omitempty"`
	Relaxed []topologyRelaxEntry `json:"relaxed"`
}

type topologyRelaxEntry struct {
	Index      int    `json:"i"`
	MinDomains *int32 `json:"m,omitempty"`
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
	// knownZones is REBUILT every sweep. The old sticky map never
	// forgot a zone, so a zone deleted for maintenance stayed "known"
	// with zero healthy workers forever and the restore never fired.
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

	// Zones recorded on already-relaxed workloads survive pod
	// restarts and a controller that briefly drops the annotation.
	// They are merged into the known set ONLY when a real worker for
	// that zone still exists: a recorded zone whose nodes are all
	// gone was deleted, and keeping it known with zero healthy
	// workers would pin the restore deadlock forever.
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
			// Control-plane / GitOps namespaces manage their own
			// scheduling; relaxing their constraints would fight
			// the operator that owns them.
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
	// A remediation taint (kubelet-unresponsive, etc.) makes the node
	// just as unschedulable as a cordon — counting it healthy here is
	// what let a dead zone look alive while pods stayed Pending.
	return !kube.HasRemediationTaint(n)
}

// isVirtualWorkerNode filters liqo / virtual-kubelet shadow nodes out
// of the zone census: they carry zone labels but run no real workload
// capacity, so counting one as the zone's last healthy worker hides
// a genuinely dead zone. Besides the liqo and provider labels, some
// clusters stamp plain type=virtual-kubelet on the node or give it the
// stable node.kubernetes.io/instance-type=external label (virtual /
// out-of-cluster capacity).
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

// topologyRecordedZones collects the dead zones named on workloads
// already carrying AnnoTopologyRelaxedBy. The value also survives a
// pod restart / controller rewrite that temporarily drops the
// annotation's structured payload, keeping the zone attribution
// stable across such a gap.
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
	// Share the full DB-quorum signature with the other watchdogs —
	// a partial label list let a Percona/Dragonfly cluster through.
	return !isSubPathDBQuorumWorkload(dep.Spec.Template.Labels)
}

// zoneConstraintsPatch renders the template-spec + annotation half of
// a relax or restore in ONE merge patch. annoVal nil deletes the
// annotation (the restore direction).
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

// relaxZoneConstraintsPatch flips ONLY zone DoNotSchedule constraints
// to ScheduleAnyway and records each changed index with its original
// minDomains. MinDomains MUST be cleared: the apiserver rejects a
// ScheduleAnyway constraint carrying minDomains with 422 Invalid.
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

// restoreZoneConstraintsPatch reverses ONLY the recorded indices, and
// only while they are still ScheduleAnyway on the zone key — a
// ScheduleAnyway constraint the user added afterwards is never
// overwritten. Each original minDomains is put back so the constraint
// is byte-for-byte the one the user had before the relax. An exception
// is a zone that lost ALL its workers between relax and restore: the
// surviving-zone count makes a previously-valid minDomains a 422
// Invalid, so that entry stays relaxed AND stays in the annotation for
// a later sweep with enough healthy zones. Stale entries (index gone
// or constraint no longer relaxed) are dropped. When no entry can be
// restored at all, no patch is emitted — rewriting an unchanged spec
// and annotation would only burn a heal grant.
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
			continue // stale index — nothing left to restore
		}
		if e.MinDomains != nil && *e.MinDomains > int32(healthyZoneCount) {
			deferred = append(deferred, e) // keep for a later sweep
			continue
		}
		c := &updated[e.Index]
		if c.TopologyKey != topologyZoneKey || c.WhenUnsatisfiable != corev1.ScheduleAnyway {
			continue // stale constraint — someone else moved it
		}
		c.WhenUnsatisfiable = corev1.DoNotSchedule
		c.MinDomains = e.MinDomains
		restored++
	}
	if restored == 0 {
		if len(deferred) == 0 {
			// Every recorded entry is stale (constraint moved back by
			// its owner, or already restored) — drop the orphan
			// annotation instead of leaving it pinned forever.
			return dropTopologyRelaxAnno()
		}
		return nil, false // all deferred — nothing to patch this sweep
	}
	// Drop the annotation only when EVERY entry was restored. Keeping
	// the deferred entries (and the zone attribution) lets a later
	// sweep with more healthy zones finish the restore; dropping it
	// would leave those constraints relaxed forever with no record.
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

// dropTopologyRelaxAnno removes ONLY AnnoTopologyRelaxedBy. It is the
// patch for an orphan marker: an unparseable record, an empty relaxed
// list, or a workload whose constraints are no longer relaxed. There
// is nothing to restore in those cases, but leaving the annotation
// would keep the zone attribution alive and invite another replay.
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

// restorePatchFor picks the merge patch for a workload that still
// carries AnnoTopologyRelaxedBy: an exact-index restore when the record
// and a relaxed zone constraint are both present, otherwise the
// annotation-only cleanup for an orphan.
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
	// Cluster-wide-only: a dead zone is usually cordoned (a node-scoped
	// maintenance hold). HealAllowed would let that very cordon defer
	// the relax that exists to unblock scheduling in that zone.
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
	if !kube.TryReserveWorkloadKey(ctx, wKey) ||
		!heal.FluxPatchGate("deployment", dep, dep.Namespace+"/"+dep.Name, now) {
		heal.RefundGrant(now)
		return
	}
	payload, _, ok := relaxZoneConstraintsPatch(dep.Spec.Template.Spec.TopologySpreadConstraints, deadZones)
	if !ok {
		heal.RefundGrant(now)
		return
	}
	if _, err := c.CS.AppsV1().Deployments(dep.Namespace).Patch(ctx, dep.Name, types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		rep.InfraErr(fmt.Errorf("topology zone relax Deployment %s: %w", wKey, err))
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
	if !kube.TryReserveWorkloadKey(ctx, wKey) ||
		!heal.FluxPatchGate("statefulset", sts, sts.Namespace+"/"+sts.Name, now) {
		heal.RefundGrant(now)
		return
	}
	payload, _, ok := relaxZoneConstraintsPatch(sts.Spec.Template.Spec.TopologySpreadConstraints, deadZones)
	if !ok {
		heal.RefundGrant(now)
		return
	}
	if _, err := c.CS.AppsV1().StatefulSets(sts.Namespace).Patch(ctx, sts.Name, types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		rep.InfraErr(fmt.Errorf("topology zone relax StatefulSet %s: %w", wKey, err))
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
		if !kube.TryReserveWorkloadKey(ctx, wKey) ||
			!heal.FluxPatchGate("deployment", dep, dep.Namespace+"/"+dep.Name, now) {
			heal.RefundGrant(now)
			continue
		}
		if _, err := c.CS.AppsV1().Deployments(dep.Namespace).Patch(ctx, dep.Name, types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
			rep.InfraErr(fmt.Errorf("topology zone restore Deployment %s: %w", wKey, err))
			log.Error(err, "topology zone restore Deployment patch failed", "workload", wKey)
			continue
		}
		c.healCooldowns.Stamp(wKey, now)
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
		if !kube.TryReserveWorkloadKey(ctx, wKey) ||
			!heal.FluxPatchGate("statefulset", sts, sts.Namespace+"/"+sts.Name, now) {
			heal.RefundGrant(now)
			continue
		}
		if _, err := c.CS.AppsV1().StatefulSets(sts.Namespace).Patch(ctx, sts.Name, types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
			rep.InfraErr(fmt.Errorf("topology zone restore StatefulSet %s: %w", wKey, err))
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
