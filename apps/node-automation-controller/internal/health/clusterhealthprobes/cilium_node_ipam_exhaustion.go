// cilium_node_ipam_exhaustion.go — the
// cilium-node-ipam-exhaustion check (W10-NM6): node pod-IP free
// ratio below the threshold (Prometheus
// cilium_operator_ipam_{used,available}_ips vs podCIDR, pod-count
// fallback) FAILs the check and reaps terminal pods on the node so
// kubelet releases their IPs.
package clusterhealthprobes

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

const (
	checkNameCiliumNodeIPAM = "cilium-node-ipam-exhaustion"

	// W10-NM6 — cilium-node-ipam-exhaustion knobs.
	ciliumIPAMMinFreeRatio = 0.15
	ciliumIPAMNodeCool     = 30 * time.Minute
	ciliumIPAMMaxReaps     = 50
)

var (
	// W10-NM6 — free pod-IP ratio per node.
	ciliumIPAMFreeRatioGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_cilium_ipam_free_ratio",
		Help: "Free pod-IP ratio (0..1) per node — W10-NM6; <0.15 fails the check.",
	}, []string{"node"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		ciliumIPAMFreeRatioGauge)
}

// podCIDRCapacity returns the usable pod-IP count for a node
// podCIDR — total addresses minus network+broadcast (a /24 yields
// 254, matching the plan's convention). IPv6 podCIDRs and absent
// values report ok=false.
func podCIDRCapacity(podCIDR string) (int, bool) {
	if podCIDR == "" || strings.Contains(podCIDR, ":") {
		return 0, false
	}
	_, ipnet, err := net.ParseCIDR(podCIDR)
	if err != nil {
		return 0, false
	}
	ones, bits := ipnet.Mask.Size()
	if ones <= 0 || bits != 32 {
		return 0, false
	}
	total := int64(1) << uint(bits-ones)
	usable := total - 2
	if usable < 1 {
		usable = 1
	}
	return int(usable), true
}

// checkCiliumNodeIPAMExhaustion watches per-node pod-IP exhaustion:
// Prometheus cilium_operator_ipam_{used,available}_ips{target_node}
// vs the node's podCIDR
// capacity, with a non-hostNetwork pod count as the per-node
// fallback (and for nodes absent from the metric). Below 15% free
// the check FAILs (feeding CiliumNodeIPAMNearExhaustion) and, once
// per node per 30m, reaps Succeeded/Failed pods on that node —
// deleting the pod object makes kubelet tear down the sandbox and
// release the IP. Orphaned CRI sandboxes (pod object already gone)
// have no apiserver handle — noted, not actionable from here.
func (p *clusterHealthProber) checkCiliumNodeIPAMExhaustion(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	now := p.now()
	minFree := healthEnvFloat("CILIUM_NODE_IPAM_MIN_FREE_RATIO", ciliumIPAMMinFreeRatio)

	// Prometheus operator IPAM census — cilium_operator_ipam_{used,
	// available}_ips{target_node} (cilium >=1.15; the old
	// cilium_ipam_ips{type=used} metric does not exist). A query
	// failure or an empty result (metric absent on this Cilium
	// version) degrades to the pod-count path rather than
	// false-FAILing.
	usedProm := map[string]float64{}
	availProm := map[string]float64{}
	promOK := false
	if usedSeries, err := p.promInstantQuery(ctx,
		`cilium_operator_ipam_used_ips`); err == nil && len(usedSeries) > 0 {
		if availSeries, aerr := p.promInstantQuery(ctx,
			`cilium_operator_ipam_available_ips`); aerr == nil {
			promOK = true
			for _, s := range usedSeries {
				if node := promLabelValue(s, "target_node", "node",
					"kubernetes_node"); node != "" {
					usedProm[node] = s.value
				}
			}
			for _, s := range availSeries {
				if node := promLabelValue(s, "target_node", "node",
					"kubernetes_node"); node != "" {
					availProm[node] = s.value
				}
			}
		}
	} else if err != nil {
		log.Info("WARN: cilium_operator_ipam_used_ips query failed — pod-count fallback",
			"error", err)
	}

	nodes, err := shared.ListNodes(ctx, p.cs)
	if err != nil {
		return probeResult{infra: fmt.Errorf("list nodes: %w", err)}
	}
	pods, err := p.cs.CoreV1().Pods(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list pods: %w", err)}
	}
	podCount := map[string]int{}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Spec.HostNetwork || pod.Spec.NodeName == "" {
			continue
		}
		if pod.Status.Phase == corev1.PodSucceeded ||
			pod.Status.Phase == corev1.PodFailed {
			continue
		}
		podCount[pod.Spec.NodeName]++
	}

	current := map[string][]string{}
	var exhausted []string
	for i := range nodes {
		node := &nodes[i]
		capacity, ok := podCIDRCapacity(node.Spec.PodCIDR)
		if !ok {
			continue
		}
		used := float64(podCount[node.Name])
		free := float64(capacity) - used
		if free < 0 {
			free = 0
		}
		ratio := free / float64(capacity)
		// Operator IPAM accounting is authoritative when present —
		// it counts allocated pod IPs the pod census misses. With
		// used+available the free ratio comes straight from the
		// operator's own PodCIDR math.
		if promOK {
			if u, ok := usedProm[node.Name]; ok {
				if a, aok := availProm[node.Name]; aok && u+a > 0 {
					ratio = a / (u + a)
					free = a
				} else {
					used = u
					free = float64(capacity) - used
					if free < 0 {
						free = 0
					}
					ratio = free / float64(capacity)
				}
			}
		}
		lv := []string{node.Name}
		current[node.Name] = lv
		ciliumIPAMFreeRatioGauge.WithLabelValues(lv...).Set(ratio)
		if ratio >= minFree {
			continue
		}
		exhausted = append(exhausted, fmt.Sprintf(
			"%s(free=%.0f/%d=%.0f%%)", node.Name, free, capacity, ratio*100))
		p.reapTerminalPodsOnNode(ctx, log, node.Name, now)
	}
	sort.Strings(exhausted)
	reconcileEmittedGauges(checkNameCiliumNodeIPAM,
		ciliumIPAMFreeRatioGauge, current)
	if len(exhausted) == 0 {
		return probeResult{pass: true}
	}
	return probeResult{why: fmt.Sprintf(
		"nodes below %.0f%% free pod IPs: %s",
		minFree*100, strings.Join(exhausted, ", "))}
}

// reapTerminalPodsOnNode deletes Succeeded/Failed pods on an
// IP-exhausted node (capped) so kubelet releases their sandboxes and
// pod IPs — once per node per cooldown, maintenance-gated. Terminal
// pods hold no traffic; the delete is the safe existing shape (same
// as the evicted-pod janitor, scoped to the exhausted node).
func (p *clusterHealthProber) reapTerminalPodsOnNode(ctx context.Context,
	log logr.Logger, node string, now time.Time) {

	ck := "selfheal/" + checkNameCiliumNodeIPAM + "/reap/" + node
	if p.healCooledDown(ck, ciliumIPAMNodeCool, now) {
		return
	}
	held, why, err := shared.MaintenanceActive(ctx, p.cs, p.dyn)
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Info("WARN: maintenance check unverifiable — ipam reap deferred (fail closed)",
			"node", node, "error", err)
		return
	}
	if held {
		log.Info("maintenance in progress — ipam reap deferred",
			"node", node, "why", why)
		return
	}
	pods, err := p.cs.CoreV1().Pods(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{
			FieldSelector: "spec.nodeName=" + node,
		})
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Info("WARN: list node pods failed — ipam reap deferred",
			"node", node, "error", err)
		return
	}
	reaped := 0
	for i := range pods.Items {
		if reaped >= ciliumIPAMMaxReaps {
			break
		}
		pod := &pods.Items[i]
		if pod.DeletionTimestamp != nil ||
			(pod.Status.Phase != corev1.PodSucceeded &&
				pod.Status.Phase != corev1.PodFailed) {
			continue
		}
		uid := pod.UID
		if err := p.cs.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name,
			metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &uid},
			}); err != nil {
			metrics.IncError(clusterHealthQueue)
			log.Error(err, "ipam terminal-pod reap failed",
				"pod", pod.Namespace+"/"+pod.Name)
			continue
		}
		reaped++
	}
	if reaped > 0 {
		p.markHealStamp(ck, now)
		log.Info("REAP: deleted terminal pods on IP-exhausted node",
			"node", node, "count", reaped)
	}
}
