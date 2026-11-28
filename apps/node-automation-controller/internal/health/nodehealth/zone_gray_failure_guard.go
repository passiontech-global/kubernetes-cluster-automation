// zone_gray_failure_guard.go — health check "zone-gray-failure-guard":
// multi-AZ / site gray-failure correlator and guarded zone shedding.
//
// Evaluates worker nodes grouped by topology.kubernetes.io/zone (fallback
// failure-domain.beta.kubernetes.io/zone) across >=2 distinct zones for:
//   - degraded node conditions (Ready!=True, DiskPressure, MemoryPressure,
//     PIDPressure, NetworkUnavailable, DiskSlowIO, ReadonlyFilesystem,
//     NebulaSlowpath, CoreDNSUpstreamDegraded), OR
//   - high ratio of NotReady/CrashLoop pods on that node, PLUS
//   - optional best-effort PromQL per-node error correlation via PromEndpointCtx.
//
// Classifies a zone as gray-degraded when >=50% of its workers are degraded
// simultaneously while >=2 healthy zones (<20% degraded) exist, sustained for
// >=NODE_AUTOMATION_ZONE_GRAY_HOLD_DURATION (default 10m). Always emits
// ZoneGrayFailureDetected Warning Events and Prometheus gauges (default-on).
//
// When NODE_AUTOMATION_ZONE_GRAY_SHED_ENABLED=true, applies temporary
// passiontech.dev/zone-gray-failure=true:PreferNoSchedule taint to worker nodes
// ONLY in the degraded zone under hard safety caps (>=3 zones, >=2 healthy
// zones remaining, max 1 zone shed at any time, heal.AllowedV + fleet Budget).
// Auto-untaints once a tainted zone remains healthy (<20% degraded) for
// >=NODE_AUTOMATION_ZONE_GRAY_RECOVER_DURATION (default 15m), even when shedding
// is disabled.
package nodehealth

import (
	"cmp"
	"context"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

const (
	// CheckNameZoneGrayFailureGuard is the registry check name for multi-AZ gray-failure detection & guarded zone shedding.
	CheckNameZoneGrayFailureGuard = "zone-gray-failure-guard"

	zoneGrayDefaultHoldDuration    = 10 * time.Minute
	zoneGrayDefaultRecoverDuration = 15 * time.Minute
	zoneGrayShedCooldown           = 15 * time.Minute
	zoneGrayEventCooldown          = 30 * time.Minute
	zoneGrayEventReason            = "ZoneGrayFailureDetected"
	zoneGrayTaintKey               = "passiontech.dev/zone-gray-failure"
	zoneGrayTaintValue             = "true"

	zoneGrayDegradedRatioThreshold = 0.50
	zoneGrayHealthyRatioThreshold  = 0.20
	zoneGrayMinZonesForAlert       = 2
	zoneGrayMinZonesForShed        = 3
	zoneGrayMinHealthyZones        = 2
	zoneGrayPromQuery              = `sum by (node) (rate(node_network_receive_errs_total[5m]) + rate(node_network_transmit_errs_total[5m]))`
	zoneGrayPromQueryTimeout       = 2 * time.Second
)

var (
	zoneGrayFailureGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_zone_gray_failure",
		Help: "1 while an availability zone exhibits sustained multi-worker gray failure with >=2 healthy zones remaining.",
	}, []string{"zone"})

	zoneGrayShedGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_zone_gray_shed",
		Help: "1 while worker nodes in an availability zone carry the passiontech.dev/zone-gray-failure PreferNoSchedule taint.",
	}, []string{"zone"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		zoneGrayFailureGauge,
		zoneGrayShedGauge,
	)
}

var zoneGrayDegradedCondTypes = []corev1.NodeConditionType{
	corev1.NodeDiskPressure,
	corev1.NodeMemoryPressure,
	corev1.NodePIDPressure,
	corev1.NodeNetworkUnavailable,
	corev1.NodeConditionType(nodecond.DiskSlowIO),
	corev1.NodeConditionType(nodecond.ReadonlyFilesystem),
	corev1.NodeConditionType(nodecond.NebulaSlowpath),
	corev1.NodeConditionType("NebulaSlowPath"),
	corev1.NodeConditionType("CoreDNSUpstreamDegraded"),
}

type zoneGrayFailureGuardCheck struct {
	*probefw.Deps

	holdDuration    time.Duration
	recoverDuration time.Duration
	shedEnabled     bool

	degradedSince state.FirstSeenLedger
	recoverSince  state.FirstSeenLedger
	emitted       state.GaugeLedger[string]
	shedEmitted   state.GaugeLedger[string]
	eventCooldown state.CooldownSet
}

// NewZoneGrayFailureGuardCheck constructs the zone-gray-failure-guard check.
func NewZoneGrayFailureGuardCheck(d *probefw.Deps) probefw.Check {
	hold := envx.GetenvDuration("NODE_AUTOMATION_ZONE_GRAY_HOLD_DURATION", zoneGrayDefaultHoldDuration)
	if hold <= 0 {
		hold = zoneGrayDefaultHoldDuration
	}
	recoverDur := envx.GetenvDuration("NODE_AUTOMATION_ZONE_GRAY_RECOVER_DURATION", zoneGrayDefaultRecoverDuration)
	if recoverDur <= 0 {
		recoverDur = zoneGrayDefaultRecoverDuration
	}
	return &zoneGrayFailureGuardCheck{
		Deps:            d,
		holdDuration:    hold,
		recoverDuration: recoverDur,
		shedEnabled:     envx.Gate("NODE_AUTOMATION_ZONE_GRAY_SHED_ENABLED", false),
	}
}

type zoneGrayZoneBucket struct {
	zone            string
	workers         []*corev1.Node
	degradedWorkers []*corev1.Node
	taintedWorkers  []*corev1.Node
	ratio           float64
}

func (c *zoneGrayFailureGuardCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := c.Now()
	c.eventCooldown.PruneExpired(now, zoneGrayEventCooldown)

	var rep, shedRep probefw.SweepReport

	nodes, err := c.AllNodes(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list nodes: %w", err)}
	}

	distinctZones := map[string]bool{}
	workerZoneMap := map[string]*zoneGrayZoneBucket{}
	for i := range nodes {
		n := &nodes[i]
		z := zoneGrayNodeZone(n)
		if z == "" {
			continue
		}
		distinctZones[z] = true
		if zoneGrayIsControlPlane(n) {
			continue
		}
		b := workerZoneMap[z]
		if b == nil {
			b = &zoneGrayZoneBucket{zone: z}
			workerZoneMap[z] = b
		}
		b.workers = append(b.workers, n)
		if kube.HasTaint(n.Spec.Taints, zoneGrayTaintKey) {
			b.taintedWorkers = append(b.taintedWorkers, n)
		}
	}

	if len(distinctZones) < zoneGrayMinZonesForAlert || len(workerZoneMap) < zoneGrayMinZonesForAlert {
		c.degradedSince.Prune(func(string) bool { return false })
		c.recoverSince.Prune(func(string) bool { return false })
		shedRep.Close(&c.shedEmitted, zoneGrayShedGauge.DeleteLabelValues)
		return rep.Result(&c.emitted, zoneGrayFailureGauge.DeleteLabelValues,
			"zone gray failure detected: ", ", ")
	}

	pods, err := c.AllPods(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}
	unhealthyPodsByNode := zoneGrayPodHealthByNode(pods)
	promErrNodes := c.zoneGrayPromNodeErrors(ctx, log)

	zoneNames := make([]string, 0, len(workerZoneMap))
	for z, b := range workerZoneMap {
		zoneNames = append(zoneNames, z)
		for _, w := range b.workers {
			if zoneGrayWorkerDegraded(w, unhealthyPodsByNode[w.Name], promErrNodes[w.Name]) {
				b.degradedWorkers = append(b.degradedWorkers, w)
			}
		}
		if len(b.workers) > 0 {
			b.ratio = float64(len(b.degradedWorkers)) / float64(len(b.workers))
		}
	}
	slices.Sort(zoneNames)

	healthyZones := 0
	taintedZones := map[string]bool{}
	for _, z := range zoneNames {
		b := workerZoneMap[z]
		if b.ratio < zoneGrayHealthyRatioThreshold {
			healthyZones++
		}
		if len(b.taintedWorkers) > 0 {
			taintedZones[z] = true
		}
	}

	liveDegraded := map[string]bool{}
	liveRecover := map[string]bool{}
	var confirmedGrayZones []*zoneGrayZoneBucket

	for _, z := range zoneNames {
		b := workerZoneMap[z]
		if b.ratio >= zoneGrayDegradedRatioThreshold && healthyZones >= zoneGrayMinHealthyZones {
			liveDegraded[z] = true
			if probefw.Persisted(&c.degradedSince, z, now, c.holdDuration, log) {
				confirmedGrayZones = append(confirmedGrayZones, b)
				rep.Emit(zoneGrayFailureGauge, z, []string{z},
					fmt.Sprintf("%s (%d/%d workers degraded)", z, len(b.degradedWorkers), len(b.workers)))
				c.zoneGrayEmitEvent(ctx, log, now, b)
			}
		}

		if len(b.taintedWorkers) > 0 {
			if b.ratio < zoneGrayHealthyRatioThreshold {
				liveRecover[z] = true
				if probefw.Persisted(&c.recoverSince, z, now, c.recoverDuration, log) {
					if c.zoneGrayUntaintZone(ctx, log, b) {
						delete(taintedZones, z)
						liveRecover[z] = false
					}
				}
			}
			if taintedZones[z] {
				shedRep.Flag(zoneGrayShedGauge, z, []string{z})
			}
		}
	}

	c.degradedSince.Prune(func(k string) bool { return liveDegraded[k] })
	c.recoverSince.Prune(func(k string) bool { return liveRecover[k] })

	if c.shedEnabled && len(confirmedGrayZones) > 0 && len(distinctZones) >= zoneGrayMinZonesForShed {
		for _, b := range confirmedGrayZones {
			healthyRemaining := healthyZones
			if b.ratio < zoneGrayHealthyRatioThreshold {
				healthyRemaining--
			}
			if healthyRemaining < zoneGrayMinHealthyZones {
				continue
			}
			// Hard safety cap: MAX 1 zone shed at any time.
			otherTainted := false
			for tz := range taintedZones {
				if tz != b.zone {
					otherTainted = true
					break
				}
			}
			if otherTainted {
				log.Info("SKIP: zone gray-failure shed blocked by max-1-zone cap",
					"zone", b.zone, "alreadyShedZones", len(taintedZones))
				continue
			}

			if c.zoneGrayShedZone(ctx, log, now, b) {
				taintedZones[b.zone] = true
				shedRep.Flag(zoneGrayShedGauge, b.zone, []string{b.zone})
			}
		}
	}

	shedRep.Close(&c.shedEmitted, zoneGrayShedGauge.DeleteLabelValues)
	return rep.Result(&c.emitted, zoneGrayFailureGauge.DeleteLabelValues,
		"zone gray failure detected: ", ", ")
}

func zoneGrayIsControlPlane(n *corev1.Node) bool {
	return kube.IsControlPlane(n) ||
		kube.HasTaint(n.Spec.Taints, "node-role.kubernetes.io/control-plane") ||
		kube.HasTaint(n.Spec.Taints, "node-role.kubernetes.io/master")
}

func zoneGrayNodeZone(n *corev1.Node) string {
	if z := n.Labels[corev1.LabelTopologyZone]; z != "" {
		return z
	}
	return n.Labels[corev1.LabelFailureDomainBetaZone]
}

type zoneGrayNodePods struct {
	total     int
	unhealthy int
}

func zoneGrayPodHealthByNode(pods []corev1.Pod) map[string]zoneGrayNodePods {
	out := map[string]zoneGrayNodePods{}
	for i := range pods {
		pod := &pods[i]
		if pod.Spec.NodeName == "" || pod.DeletionTimestamp != nil ||
			pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}
		np := out[pod.Spec.NodeName]
		np.total++
		if !probefw.PodRunningReady(pod) || zoneGrayPodCrashLoop(pod) {
			np.unhealthy++
		}
		out[pod.Spec.NodeName] = np
	}
	return out
}

func zoneGrayPodCrashLoop(pod *corev1.Pod) bool {
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.State.Waiting != nil && cs.State.Waiting.Reason == "CrashLoopBackOff" {
			return true
		}
	}
	for _, cs := range pod.Status.InitContainerStatuses {
		if cs.State.Waiting != nil && cs.State.Waiting.Reason == "CrashLoopBackOff" {
			return true
		}
	}
	return false
}

func zoneGrayWorkerDegraded(n *corev1.Node, np zoneGrayNodePods, promErr bool) bool {
	if !kube.NodeReady(n) {
		return true
	}
	for _, ct := range zoneGrayDegradedCondTypes {
		if c := kube.NodeCondition(n, ct); c != nil && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	if np.total >= 2 && np.unhealthy >= 2 && float64(np.unhealthy)/float64(np.total) >= 0.50 {
		return true
	}
	return promErr
}

func (c *zoneGrayFailureGuardCheck) zoneGrayPromNodeErrors(ctx context.Context, log logr.Logger) map[string]bool {
	if _, err := c.PromEndpointCtx(ctx); err != nil {
		return nil
	}
	qctx, cancel := context.WithTimeout(ctx, zoneGrayPromQueryTimeout)
	defer cancel()
	samples, err := c.PromQuery(qctx, zoneGrayPromQuery)
	if err != nil {
		log.V(1).Info("zone-gray-failure PromQL node error query unavailable — continuing without Prom signal",
			"error", err)
		return nil
	}
	if len(samples) == 0 {
		return nil
	}
	out := map[string]bool{}
	for _, s := range samples {
		nodeName := s.Label("node")
		if nodeName == "" || math.IsNaN(s.Value) || math.IsInf(s.Value, 0) || s.Value <= 0 {
			continue
		}
		out[nodeName] = true
	}
	return out
}

func (c *zoneGrayFailureGuardCheck) zoneGrayShedZone(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	b *zoneGrayZoneBucket,
) bool {
	var untainted []*corev1.Node
	for _, w := range b.workers {
		if zoneGrayIsControlPlane(w) {
			continue
		}
		if !kube.HasTaint(w.Spec.Taints, zoneGrayTaintKey) {
			untainted = append(untainted, w)
		}
	}
	if len(untainted) == 0 {
		return false
	}

	slices.SortFunc(untainted, func(a, b *corev1.Node) int {
		return cmp.Compare(a.Name, b.Name)
	})

	healKey := probefw.SelfHealKey(CheckNameZoneGrayFailureGuard, "shed/"+b.zone)
	proceed, unverifiable := c.HealAllowed(ctx, log, &c.Heals, healKey, zoneGrayShedCooldown, now)
	if unverifiable {
		metrics.IncError(c.Name)
		return false
	}
	if !proceed {
		return false
	}

	attempted := false
	taintedAny := false
	for _, w := range untainted {
		attempted = true
		if err := kube.TaintNode(ctx, c.CS, w.Name, zoneGrayTaintKey, zoneGrayTaintValue,
			corev1.TaintEffectPreferNoSchedule); err != nil {
			metrics.IncError(c.Name)
			log.Error(err, "zone gray-failure taint failed", "zone", b.zone, "node", w.Name)
			continue
		}
		taintedAny = true
	}
	if !attempted {
		heal.RefundGrant(now)
		return false
	}
	if taintedAny {
		c.Heals.Stamp(healKey, now)
		c.InvalidateNodes(ctx)
		log.Info("TAINT: zone gray-failure shed applied PreferNoSchedule to zone workers",
			"zone", b.zone, "degraded", len(b.degradedWorkers), "totalWorkers", len(b.workers))
	}
	return taintedAny
}

func (c *zoneGrayFailureGuardCheck) zoneGrayUntaintZone(
	ctx context.Context,
	log logr.Logger,
	b *zoneGrayZoneBucket,
) bool {
	if len(b.taintedWorkers) == 0 {
		return true
	}
	allUntainted := true
	untaintedAny := false
	for _, w := range b.taintedWorkers {
		if zoneGrayIsControlPlane(w) {
			continue
		}
		if err := kube.UntaintNode(ctx, c.CS, w.Name, zoneGrayTaintKey); err != nil {
			allUntainted = false
			metrics.IncError(c.Name)
			log.Error(err, "zone gray-failure untaint failed", "zone", b.zone, "node", w.Name)
			continue
		}
		untaintedAny = true
	}
	if untaintedAny {
		c.InvalidateNodes(ctx)
	}
	if allUntainted {
		c.Heals.Forget(probefw.SelfHealKey(CheckNameZoneGrayFailureGuard, "shed/"+b.zone))
		log.Info("UNTAINT: zone gray-failure recovered — removed PreferNoSchedule from zone workers",
			"zone", b.zone)
	}
	return allUntainted
}

func (c *zoneGrayFailureGuardCheck) zoneGrayEmitEvent(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	b *zoneGrayZoneBucket,
) {
	cooldownKey := "zonegray." + b.zone
	if c.eventCooldown.CooledDown(cooldownKey, zoneGrayEventCooldown, now) {
		return
	}
	var ref corev1.ObjectReference
	if len(b.degradedWorkers) > 0 {
		ref = corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Node",
			Name:       b.degradedWorkers[0].Name,
			UID:        b.degradedWorkers[0].UID,
		}
	} else if len(b.workers) > 0 {
		ref = corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Node",
			Name:       b.workers[0].Name,
			UID:        b.workers[0].UID,
		}
	}
	names := make([]string, 0, len(b.degradedWorkers))
	for _, w := range b.degradedWorkers {
		names = append(names, w.Name)
	}
	slices.Sort(names)
	note := fmt.Sprintf("Zone %s exhibits sustained gray failure (%d/%d workers degraded: %s)",
		b.zone, len(b.degradedWorkers), len(b.workers), strings.Join(names, ", "))
	probefw.EmitWarningDeduped(ctx, c.CS, log, &c.eventCooldown, cooldownKey, zoneGrayEventCooldown, now, kube.WarningEvent{
		Namespace:         "default",
		Regarding:         ref,
		Reason:            zoneGrayEventReason,
		Note:              note,
		ReportingInstance: c.Name,
	})
}
