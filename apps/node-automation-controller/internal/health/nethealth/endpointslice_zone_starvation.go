// endpointslice_zone_starvation.go — the endpointslice-zone-starvation
// check (zone-starvation): a Service opted into topology-aware routing must
// keep at least one READY endpoint hinted for every ACTIVE zone — a
// zone holding a Ready worker node plus a Running pod (a client).
// A zone left with zero covering endpoints starves: every consumer
// there loses its same-zone preference and falls back to random
// endpoints — the cross-zone choke / packet-blackhole class behind
// the AWS EKS + Cilium topology-routing post-mortem this check
// covers (2 replicas in `datahub`, 0 in `lanit` → lanit clients
// dropped packets while every readiness probe stayed green).
//
// Audited services are the ones topology routing can actually
// starve: service.kubernetes.io/topology-mode=Auto,
// spec.trafficDistribution=PreferClose/PreferSameZone, or any of
// their EndpointSlices already carrying hints.forZones (kube-proxy
// consumes ONLY hints.forZones — an endpoint without one serves no
// zone preferentially, so coverage is counted strictly on hints).
// A Service whose slices hold zero ready endpoints at all is a real
// outage, not a topology starvation — it is skipped here (the
// zero-endpoint alerts own that failure).
package nethealth

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	eventsv1 "k8s.io/api/events/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// endpointSliceZoneStarvationCheck is the zone-starvation topology-aware
// routing zone-starvation watchdog.
type endpointSliceZoneStarvationCheck struct {
	*probefw.Deps

	// emitted is the emitted-gauge ledger — a tuple that stops
	// being reported gets DeleteLabelValues'd rather than leaking a
	// stale 1 (zero value usable; the serial sweep needs no lock).
	emitted state.GaugeLedger[string]
	// evented dedupes the EndpointSliceZoneHintStarved K8s Event so
	// a persistently starved zone emits once per episode, not once
	// per sweep; entries prune when the zone is covered again so a
	// later starvation re-emits.
	evented state.SeenSet
}

// NewEndpointSliceZoneStarvationCheck builds the zone-starvation check —
// its only state is the emitted-gauge ledger and the event dedup
// set.
func NewEndpointSliceZoneStarvationCheck(d *probefw.Deps) probefw.Check {
	return &endpointSliceZoneStarvationCheck{Deps: d}
}

const (
	CheckNameEndpointSliceZoneStarvation = "endpointslice-zone-starvation"

	// starvedEventReason is the Warning Event reason stamped on the
	// starved Service — the byte-stable reason the zone-starvation alert
	// runbook references.
	starvedEventReason = "EndpointSliceZoneHintStarved"

	// topologyModeAuto is the service.kubernetes.io/topology-mode
	// value that opts a Service into topology-aware routing.
	topologyModeAuto = "Auto"
)

var (
	// zone-starvation — a topology-routed Service with zero ready endpoints
	// hinted for an active zone.
	serviceTopologyZoneStarvedGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_service_topology_zone_starved",
		Help: "1 while a topology-aware Service has no ready endpoint hinted for an active zone (Ready worker + running pods) — zone-starvation.",
	}, []string{"namespace", "service", "zone"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		serviceTopologyZoneStarvedGauge)
}

// topologyAuditedService reports whether the Service opted into
// topology-aware routing: the service.kubernetes.io/topology-mode
// annotation set to Auto, or spec.trafficDistribution requesting
// same-zone preference (PreferClose is the original spelling of
// PreferSameZone — both opt the EndpointSlice controller into
// writing hints.forZones).
func topologyAuditedService(svc *corev1.Service) bool {
	if svc.Annotations[corev1.AnnotationTopologyMode] == topologyModeAuto {
		return true
	}
	td := svc.Spec.TrafficDistribution
	return td != nil && (*td == corev1.ServiceTrafficDistributionPreferClose ||
		*td == corev1.ServiceTrafficDistributionPreferSameZone)
}

// checkEndpointSliceZoneStarvation computes the active zone set
// (zones holding a Ready worker node AND at least one Running pod —
// consumers that need a hinted endpoint) then audits every
// topology-opted Service for zones it serves no ready endpoint to.
// Findings emit the gauge plus a deduped Warning Event on the
// Service; a Service with zero ready endpoints cluster-wide is an
// outage, not a starvation, and is skipped.
func (p *endpointSliceZoneStarvationCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	nodes, err := p.AllNodes(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list nodes: %w", err)}
	}
	pods, err := p.AllPods(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}
	slices, err := p.AllEndpointSlices(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list endpointslices: %w", err)}
	}
	svcs, err := p.AllServices(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list services: %w", err)}
	}

	// nodeZone is the shared memoized placement join (a zoneless
	// node reads "" on lookup — presence was never distinguished);
	// workerZones still walks the raw census for the Ready-worker
	// classification (control-plane zones don't run client
	// workloads and can't starve consumers).
	nodeZone, _ := p.NodeZones(ctx) // the same memoized read AllNodes served
	workerZones := map[string]bool{}
	for i := range nodes {
		n := &nodes[i]
		if kube.NodeReady(n) && !kube.IsControlPlane(n) {
			if z := nodeZone[n.Name]; z != "" {
				workerZones[z] = true
			}
		}
	}
	activeZones := map[string]bool{}
	for i := range pods {
		pod := &pods[i]
		if pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning {
			continue
		}
		if z := nodeZone[pod.Spec.NodeName]; z != "" && workerZones[z] {
			activeZones[z] = true
		}
	}

	type svcKey struct{ ns, name string }
	// audited starts with the annotation/trafficDistribution opt-ins
	// and gains every Service whose slices already carry
	// hints.forZones — the controller writes hints only for opted-in
	// Services, so a hinted slice proves the service is in play even
	// when the opt-in lives on a field this census missed.
	audited := map[svcKey]bool{}
	for i := range svcs {
		svc := &svcs[i]
		if topologyAuditedService(svc) {
			audited[svcKey{svc.Namespace, svc.Name}] = true
		}
	}
	slicesBySvc := map[svcKey][]*discoveryv1.EndpointSlice{}
	for i := range slices {
		s := &slices[i]
		name := s.Labels[discoveryv1.LabelServiceName]
		if name == "" || s.DeletionTimestamp != nil {
			continue
		}
		key := svcKey{s.Namespace, name}
		slicesBySvc[key] = append(slicesBySvc[key], s)
		for _, ep := range s.Endpoints {
			if ep.Hints != nil && len(ep.Hints.ForZones) > 0 {
				audited[key] = true
				break
			}
		}
	}

	var rep probefw.SweepReport
	live := map[string]bool{}
	for key := range audited {
		covered := map[string]int{}
		readyTotal := 0
		for _, s := range slicesBySvc[key] {
			for _, ep := range s.Endpoints {
				if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
					continue
				}
				readyTotal++
				if ep.Hints == nil {
					continue
				}
				for _, fz := range ep.Hints.ForZones {
					covered[fz.Name]++
				}
			}
		}
		// A Service with zero ready endpoints anywhere is a real
		// outage the zero-endpoint alerts own — reporting every
		// active zone as "starved" would misattribute it.
		if readyTotal == 0 {
			continue
		}
		for z := range activeZones {
			if covered[z] > 0 {
				continue
			}
			k := key.ns + "/" + key.name + "/" + z
			live[k] = true
			rep.Emit(serviceTopologyZoneStarvedGauge, k,
				[]string{key.ns, key.name, z},
				fmt.Sprintf("%s/%s zone=%s", key.ns, key.name, z))
			if p.evented.Add(k) {
				p.emitStarvedEvent(ctx, log, key.ns, key.name, z)
			}
		}
	}
	p.evented.Prune(func(k string) bool { return live[k] })
	return rep.Result(&p.emitted, serviceTopologyZoneStarvedGauge.DeleteLabelValues,
		"topology-routed services starving an active zone: ", ", ")
}

// emitStarvedEvent stamps the EndpointSliceZoneHintStarved Warning
// Event on the Service — the events.k8s.io/v1 shape the node-agent
// emitters use (Regarding+Action, deprecated corev1 fields unset).
// Best-effort: the controller's ClusterRole does not grant cluster-
// wide events create today (only node-ops/leader-election), so a
// Forbidden is logged once per starve episode via the caller's
// dedup set and never escalates to an Infra error.
func (p *endpointSliceZoneStarvationCheck) emitStarvedEvent(
	ctx context.Context, log logr.Logger, ns, svc, zone string) {

	now := p.Now()
	ev := &eventsv1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s.%x", svc, now.UnixNano()),
			Namespace: ns,
		},
		EventTime:           metav1.NewMicroTime(now),
		Reason:              starvedEventReason,
		Note:                fmt.Sprintf("topology-aware Service has no ready endpoint hinted for zone %s — consumers there fall back to random endpoints (same-zone preference lost)", zone),
		Type:                corev1.EventTypeWarning,
		ReportingController: "node-automation-controller",
		ReportingInstance:   p.Name,
		Action:              starvedEventReason,
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Service",
			Namespace:  ns,
			Name:       svc,
		},
	}
	if _, err := p.CS.EventsV1().Events(ns).
		Create(ctx, ev, metav1.CreateOptions{}); err != nil {
		log.Info("WARN: EndpointSliceZoneHintStarved event create failed (RBAC?)",
			"service", ns+"/"+svc, "zone", zone, "error", err)
		return
	}
	log.Info("EVENT: EndpointSliceZoneHintStarved — active zone has no hinted ready endpoint",
		"service", ns+"/"+svc, "zone", zone)
}
