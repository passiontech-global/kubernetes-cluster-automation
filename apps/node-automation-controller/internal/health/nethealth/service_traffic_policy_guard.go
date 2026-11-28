// service_traffic_policy_guard.go — health check "service-traffic-policy-guard" (#71):
// audit-only guard detecting three graceful-shutdown and traffic-blackhole
// failure modes:
//  1. LoadBalancer/NodePort Services with externalTrafficPolicy: Local whose
//     ready non-terminating backends are concentrated on a single node (>=2
//     unique backends all on 1 node) or exclusively on unschedulable nodes,
//     sustained >= 10m -> node_automation_service_traffic_policy_degraded.
//  2. EndpointSlice entries with conditions.terminating == true whose target
//     Pod is missing, UID-mismatched, or terminating past
//     max(terminationGracePeriodSeconds + 60s, 5m)
//     -> node_automation_endpointslice_terminating_stuck.
//  3. Passive-only audit (never fails check): Deployments with replicas >= 2
//     backing LoadBalancer Services, HTTPRoutes, or Ingresses that lack
//     lifecycle.preStop -> node_automation_workload_missing_prestop.
//
// Reuses probefw snapshots and resolves Pods lazily only when an endpoint lacks
// ep.NodeName or has ep.Conditions.Terminating == true. Gracefully skips 403/404
// on HTTPRoute / Ingress.
package nethealth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

const (
	// CheckNameServiceTrafficPolicyGuard is the registry check name for #6/#71.
	CheckNameServiceTrafficPolicyGuard = "service-traffic-policy-guard"

	serviceTrafficPolicyMinAge    = 10 * time.Minute
	stuckTerminatingMinWindow     = 5 * time.Minute
	stuckTerminatingGracePad      = 60 * time.Second
	stuckTerminatingMissingMinAge = 2 * time.Minute
	defaultTerminationGraceSec    = int64(30)
)

var (
	serviceTrafficPolicyDegradedGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_service_traffic_policy_degraded",
		Help: "1 while an externalTrafficPolicy=Local Service has single-node endpoint concentration or all ready endpoints on unschedulable nodes >= 10m.",
	}, []string{"namespace", "service", "reason"})

	endpointSliceTerminatingStuckGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_endpointslice_terminating_stuck",
		Help: "1 while an EndpointSlice contains a Terminating endpoint whose target Pod is missing, UID-mismatched, or stuck terminating past grace.",
	}, []string{"namespace", "service"})

	workloadMissingPreStopGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_workload_missing_prestop",
		Help: "1 while a >=2-replica Deployment behind a LoadBalancer, HTTPRoute, or Ingress lacks lifecycle.preStop (passive audit only).",
	}, []string{"namespace", "deployment"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		serviceTrafficPolicyDegradedGauge,
		endpointSliceTerminatingStuckGauge,
		workloadMissingPreStopGauge,
	)
}

type serviceTrafficPolicyGuardCheck struct {
	*probefw.Deps

	policySeen       state.FirstSeenLedger
	stuckMissingSeen state.FirstSeenLedger

	policyEmitted  state.GaugeLedger[string]
	stuckEmitted   state.GaugeLedger[string]
	prestopEmitted state.GaugeLedger[string]
}

// NewServiceTrafficPolicyGuardCheck builds the service-traffic-policy-guard check.
func NewServiceTrafficPolicyGuardCheck(d *probefw.Deps) probefw.Check {
	return &serviceTrafficPolicyGuardCheck{Deps: d}
}

func (c *serviceTrafficPolicyGuardCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := c.Now()

	svcs, err := c.AllServices(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list services: %w", err)}
	}
	slices, err := c.AllEndpointSlices(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list endpointslices: %w", err)}
	}
	nodes, err := c.AllNodes(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list nodes: %w", err)}
	}

	var policyRep, stuckRep, prestopRep, summaryRep probefw.SweepReport

	slicesBySvc := make(map[string][]*discoveryv1.EndpointSlice)
	for i := range slices {
		s := &slices[i]
		if s.DeletionTimestamp != nil {
			continue
		}
		svcName := s.Labels[discoveryv1.LabelServiceName]
		if svcName == "" {
			continue
		}
		key := s.Namespace + "/" + svcName
		slicesBySvc[key] = append(slicesBySvc[key], s)
	}

	nodeByName := make(map[string]*corev1.Node, len(nodes))
	for i := range nodes {
		n := &nodes[i]
		nodeByName[n.Name] = n
	}

	c.auditLocalTrafficPolicy(ctx, log, now, svcs, slicesBySvc, nodeByName, &policyRep, &summaryRep)
	c.auditStuckTerminatingSlices(ctx, log, now, slices, &stuckRep, &summaryRep)
	c.auditMissingPreStop(ctx, log, svcs, &prestopRep, &summaryRep)

	policyRep.Close(&c.policyEmitted, serviceTrafficPolicyDegradedGauge.DeleteLabelValues)
	stuckRep.Close(&c.stuckEmitted, endpointSliceTerminatingStuckGauge.DeleteLabelValues)
	prestopRep.Close(&c.prestopEmitted, workloadMissingPreStopGauge.DeleteLabelValues)
	return summaryRep.Verdict("service traffic policy guard: ", ", ")
}

func (c *serviceTrafficPolicyGuardCheck) auditLocalTrafficPolicy(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	svcs []corev1.Service,
	slicesBySvc map[string][]*discoveryv1.EndpointSlice,
	nodeByName map[string]*corev1.Node,
	policyRep *probefw.SweepReport,
	summaryRep *probefw.SweepReport,
) {
	policySeenKeep := map[string]bool{}

	for i := range svcs {
		svc := &svcs[i]
		if svc.DeletionTimestamp != nil {
			continue
		}
		if (svc.Spec.Type != corev1.ServiceTypeLoadBalancer && svc.Spec.Type != corev1.ServiceTypeNodePort) ||
			svc.Spec.ExternalTrafficPolicy != corev1.ServiceExternalTrafficPolicyLocal {
			continue
		}

		svcKey := svc.Namespace + "/" + svc.Name
		readyBackends := map[string]bool{}
		readyNodes := map[string]bool{}
		podErr := false

		for _, s := range slicesBySvc[svcKey] {
			for j := range s.Endpoints {
				ep := &s.Endpoints[j]
				if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
					continue
				}
				if ep.Conditions.Terminating != nil && *ep.Conditions.Terminating {
					continue
				}
				// Deduplicate dual-stack (IPv4+IPv6) EndpointSlice entries
				// targeting the same Pod so a 1-replica Service is not counted
				// as >= 2 backends on a single node.
				readyBackends[readyEndpointBackendKey(s.Name, j, svc.Namespace, ep)] = true
				var nodeName string
				if ep.NodeName != nil && *ep.NodeName != "" {
					nodeName = *ep.NodeName
				} else if ep.TargetRef != nil && ep.TargetRef.Kind == "Pod" {
					refNS := ep.TargetRef.Namespace
					if refNS == "" {
						refNS = svc.Namespace
					}
					pod, err := c.Pod(ctx, refNS, ep.TargetRef.Name)
					if err != nil {
						summaryRep.InfraErr(fmt.Errorf("resolve endpoint pod %s/%s: %w", refNS, ep.TargetRef.Name, err))
						podErr = true
						break
					}
					if pod != nil {
						nodeName = pod.Spec.NodeName
					}
				}
				if nodeName != "" {
					readyNodes[nodeName] = true
				}
			}
			if podErr {
				break
			}
		}

		if podErr {
			for k, lv := range c.policyEmitted.Last() {
				if len(lv) >= 2 && lv[0] == svc.Namespace && lv[1] == svc.Name {
					policyRep.Carry(k, lv)
					policySeenKeep[k] = true
				}
			}
			continue
		}

		var reasons []string
		if len(readyBackends) >= 2 && len(readyNodes) == 1 {
			reasons = append(reasons, "single_node_concentration")
		}
		if len(readyNodes) > 0 && allNodesUnschedulable(readyNodes, nodeByName) {
			reasons = append(reasons, "all_ready_on_unschedulable")
		}

		for _, reason := range reasons {
			key := svcKey + "/" + reason
			policySeenKeep[key] = true
			if !probefw.Persisted(&c.policySeen, key, now, serviceTrafficPolicyMinAge, log) {
				continue
			}
			policyRep.Flag(serviceTrafficPolicyDegradedGauge, key, []string{svc.Namespace, svc.Name, reason})
			summaryRep.Find(fmt.Sprintf("%s (%s)", svcKey, reason))
		}
	}

	c.policySeen.Prune(func(k string) bool { return policySeenKeep[k] })
}

func readyEndpointBackendKey(sliceName string, idx int, defaultNS string, ep *discoveryv1.Endpoint) string {
	if ep.TargetRef != nil {
		if ep.TargetRef.Kind == "Pod" {
			if ep.TargetRef.Name != "" {
				ns := ep.TargetRef.Namespace
				if ns == "" {
					ns = defaultNS
				}
				return "pod/" + ns + "/" + ep.TargetRef.Name
			}
			if ep.TargetRef.UID != "" {
				return "pod-uid/" + string(ep.TargetRef.UID)
			}
		} else if ep.TargetRef.Kind != "" && ep.TargetRef.Name != "" {
			ns := ep.TargetRef.Namespace
			if ns == "" {
				ns = defaultNS
			}
			return "ref/" + ep.TargetRef.Kind + "/" + ns + "/" + ep.TargetRef.Name
		}
	}
	if len(ep.Addresses) > 0 {
		return fmt.Sprintf("slice/%s/%d/%s", sliceName, idx, ep.Addresses[0])
	}
	return fmt.Sprintf("slice/%s/%d", sliceName, idx)
}

func allNodesUnschedulable(readyNodes map[string]bool, nodeByName map[string]*corev1.Node) bool {
	for nodeName := range readyNodes {
		n, ok := nodeByName[nodeName]
		if !ok || !n.Spec.Unschedulable {
			return false
		}
	}
	return true
}

func (c *serviceTrafficPolicyGuardCheck) auditStuckTerminatingSlices(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	slices []discoveryv1.EndpointSlice,
	stuckRep *probefw.SweepReport,
	summaryRep *probefw.SweepReport,
) {
	stuckServices := map[string]bool{}
	podErrServices := map[string]bool{}
	missingSeenKeep := map[string]bool{}

	for i := range slices {
		s := &slices[i]
		if s.DeletionTimestamp != nil {
			continue
		}
		svcName := s.Labels[discoveryv1.LabelServiceName]
		if svcName == "" {
			continue
		}
		svcKey := s.Namespace + "/" + svcName
		if stuckServices[svcKey] {
			continue
		}

		for j := range s.Endpoints {
			ep := &s.Endpoints[j]
			if ep.Conditions.Terminating == nil || !*ep.Conditions.Terminating {
				continue
			}
			if ep.TargetRef == nil || ep.TargetRef.Kind != "Pod" {
				continue
			}
			refNS := ep.TargetRef.Namespace
			if refNS == "" {
				refNS = s.Namespace
			}
			pod, err := c.Pod(ctx, refNS, ep.TargetRef.Name)
			if err != nil {
				summaryRep.InfraErr(fmt.Errorf("resolve terminating endpoint pod %s/%s: %w", refNS, ep.TargetRef.Name, err))
				podErrServices[svcKey] = true
				break
			}
			var stuck bool
			if pod == nil {
				// Gate missing-pod terminating endpoints behind a 2m
				// persistence window so normal Pod delete vs EndpointSlice
				// cleanup races do not false-alarm.
				missingKey := svcKey + "/" + refNS + "/" + ep.TargetRef.Name
				missingSeenKeep[missingKey] = true
				stuck = probefw.Persisted(&c.stuckMissingSeen, missingKey, now, stuckTerminatingMissingMinAge, log)
			} else {
				stuck = isTerminatingEndpointStuck(now, ep, pod)
			}
			if stuck {
				stuckServices[svcKey] = true
				stuckRep.Flag(endpointSliceTerminatingStuckGauge, svcKey, []string{s.Namespace, svcName})
				summaryRep.Find(svcKey + " (stuck_terminating_endpoint)")
				break
			}
		}
	}

	c.stuckMissingSeen.Prune(func(k string) bool {
		if missingSeenKeep[k] {
			return true
		}
		for svcKey := range podErrServices {
			if strings.HasPrefix(k, svcKey+"/") {
				return true
			}
		}
		return false
	})

	for svcKey := range podErrServices {
		if stuckServices[svcKey] {
			continue
		}
		if lv, held := c.stuckEmitted.Last()[svcKey]; held {
			stuckRep.Carry(svcKey, lv)
		}
	}
}

func isTerminatingEndpointStuck(now time.Time, ep *discoveryv1.Endpoint, pod *corev1.Pod) bool {
	if pod == nil {
		return false
	}
	if ep.TargetRef != nil && ep.TargetRef.UID != "" && pod.UID != ep.TargetRef.UID {
		return true
	}
	if pod.DeletionTimestamp == nil {
		return false
	}
	grace := defaultTerminationGraceSec
	if pod.Spec.TerminationGracePeriodSeconds != nil {
		grace = *pod.Spec.TerminationGracePeriodSeconds
	}
	threshold := max(time.Duration(grace)*time.Second+stuckTerminatingGracePad, stuckTerminatingMinWindow)
	return now.Sub(pod.DeletionTimestamp.Time) > threshold
}

// auditMissingPreStop exports the passive-only node_automation_workload_missing_prestop
// gauge without ever calling summaryRep.Find (never fails the check).
func (c *serviceTrafficPolicyGuardCheck) auditMissingPreStop(
	ctx context.Context,
	log logr.Logger,
	svcs []corev1.Service,
	prestopRep *probefw.SweepReport,
	summaryRep *probefw.SweepReport,
) {
	deps, err := c.AllDeployments(ctx)
	if err != nil {
		summaryRep.InfraErr(fmt.Errorf("list deployments: %w", err))
		for k, lv := range c.prestopEmitted.Last() {
			prestopRep.Carry(k, lv)
		}
		return
	}

	exposedServices := map[string]bool{}
	for i := range svcs {
		svc := &svcs[i]
		if svc.DeletionTimestamp == nil && svc.Spec.Type == corev1.ServiceTypeLoadBalancer {
			exposedServices[svc.Namespace+"/"+svc.Name] = true
		}
	}

	prestopBlocked := false
	if c.Dyn != nil {
		routes, err := c.AllUnstructured(ctx, kube.GVRHTTPRoute)
		switch {
		case kube.IsCRDAbsent(err):
			// Gateway API CRD absent — skip cleanly.
		case apierrors.IsForbidden(err):
			log.V(1).Info("HTTPRoute list skipped (403)", "error", err)
			prestopBlocked = true
		case err != nil:
			summaryRep.InfraErr(fmt.Errorf("list httproutes: %w", err))
			prestopBlocked = true
		default:
			for i := range routes {
				collectHTTPRouteServiceRefs(&routes[i], exposedServices)
			}
		}
	}

	ingresses, err := c.AllIngresses(ctx)
	switch {
	case err == nil:
		for i := range ingresses {
			collectIngressServiceRefs(&ingresses[i], exposedServices)
		}
	case kube.IsCRDAbsent(err):
		// Ingress API absent — skip cleanly without pinning stale series.
	case apierrors.IsForbidden(err):
		log.V(1).Info("Ingress list skipped (403)", "error", err)
		prestopBlocked = true
	default:
		summaryRep.InfraErr(fmt.Errorf("list ingresses: %w", err))
		prestopBlocked = true
	}

	svcsByNS := map[string][]*corev1.Service{}
	for i := range svcs {
		svc := &svcs[i]
		if svc.DeletionTimestamp != nil || len(svc.Spec.Selector) == 0 {
			continue
		}
		if exposedServices[svc.Namespace+"/"+svc.Name] {
			svcsByNS[svc.Namespace] = append(svcsByNS[svc.Namespace], svc)
		}
	}

	eligibleDeps := map[string]bool{}
	flagged := map[string]bool{}
	for i := range deps {
		dep := &deps[i]
		if dep.DeletionTimestamp != nil || dep.Spec.Replicas == nil || *dep.Spec.Replicas < 2 {
			continue
		}
		if len(dep.Spec.Template.Spec.Containers) == 0 || deploymentHasPreStop(dep) {
			continue
		}
		key := dep.Namespace + "/" + dep.Name
		eligibleDeps[key] = true
		matched := false
		for _, svc := range svcsByNS[dep.Namespace] {
			if selectorMatchesLabels(svc.Spec.Selector, dep.Spec.Template.Labels) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		flagged[key] = true
		prestopRep.Flag(workloadMissingPreStopGauge, key, []string{dep.Namespace, dep.Name})
	}

	if prestopBlocked {
		for k, lv := range c.prestopEmitted.Last() {
			if !flagged[k] && eligibleDeps[k] {
				prestopRep.Carry(k, lv)
			}
		}
	}
}

func deploymentHasPreStop(dep *appsv1.Deployment) bool {
	for i := range dep.Spec.Template.Spec.Containers {
		ct := &dep.Spec.Template.Spec.Containers[i]
		if ct.Lifecycle != nil && ct.Lifecycle.PreStop != nil {
			return true
		}
	}
	return false
}

func collectHTTPRouteServiceRefs(route *unstructured.Unstructured, out map[string]bool) {
	if route.GetDeletionTimestamp() != nil {
		return
	}
	rules, ok := kube.NestedSlice(route.Object, "spec", "rules")
	if !ok {
		return
	}
	for _, r := range rules {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		refs, ok := kube.NestedSlice(rm, "backendRefs")
		if !ok {
			continue
		}
		for _, b := range refs {
			bm, ok := b.(map[string]any)
			if !ok {
				continue
			}
			group, _ := kube.NestedString(bm, "group")
			kind, _ := kube.NestedString(bm, "kind")
			if (group != "" && group != "core") || (kind != "" && kind != "Service") {
				continue
			}
			name, _ := kube.NestedString(bm, "name")
			if name == "" {
				continue
			}
			ns, _ := kube.NestedString(bm, "namespace")
			if ns == "" {
				ns = route.GetNamespace()
			}
			out[ns+"/"+name] = true
		}
	}
}

func collectIngressServiceRefs(ing *networkingv1.Ingress, out map[string]bool) {
	if ing.DeletionTimestamp != nil {
		return
	}
	if ing.Spec.DefaultBackend != nil && ing.Spec.DefaultBackend.Service != nil && ing.Spec.DefaultBackend.Service.Name != "" {
		out[ing.Namespace+"/"+ing.Spec.DefaultBackend.Service.Name] = true
	}
	for i := range ing.Spec.Rules {
		rule := &ing.Spec.Rules[i]
		if rule.HTTP == nil {
			continue
		}
		for j := range rule.HTTP.Paths {
			p := &rule.HTTP.Paths[j]
			if p.Backend.Service != nil && p.Backend.Service.Name != "" {
				out[ing.Namespace+"/"+p.Backend.Service.Name] = true
			}
		}
	}
}
