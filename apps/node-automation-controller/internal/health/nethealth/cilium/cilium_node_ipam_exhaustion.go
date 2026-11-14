// cilium_node_ipam_exhaustion.go — the
// cilium-node-ipam-exhaustion check (cilium-node-ipam-exhaustion): node pod-IP free
// ratio below the threshold (Prometheus
// cilium_operator_ipam_{used,available}_ips vs podCIDR, pod-count
// fallback) FAILs the check and reaps terminal pods on the node so
// kubelet releases their IPs.
package cilium

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

const ciliumNodeIPAMMinFreeDefault = 0.15

// ciliumNodeIPAMExhaustionCheck is the cilium node IPAM exhaustion
// watchdog with terminal-pod reaping.
type ciliumNodeIPAMExhaustionCheck struct {
	*probefw.Deps

	minFreeRatio float64

	// emitted is the emitted-gauge ledger — a tuple that stops
	// being reported gets DeleteLabelValues'd rather than leaking a
	// stale value (zero value usable; the serial sweep needs no
	// lock).
	emitted state.GaugeLedger[string]
}

// NewCiliumNodeIPAMExhaustionCheck builds the cilium-node-ipam-exhaustion check.
func NewCiliumNodeIPAMExhaustionCheck(d *probefw.Deps) probefw.Check {
	return &ciliumNodeIPAMExhaustionCheck{
		Deps:         d,
		minFreeRatio: envx.GetenvFloat("CILIUM_NODE_IPAM_MIN_FREE_RATIO", ciliumNodeIPAMMinFreeDefault),
	}
}

const (
	CheckNameCiliumNodeIPAM = "cilium-node-ipam-exhaustion"

	// cilium-node-ipam-exhaustion — cilium-node-ipam-exhaustion knobs.
	ciliumIPAMNodeCool = 30 * time.Minute
	ciliumIPAMMaxReaps = 50
)

var (
	// cilium-node-ipam-exhaustion — free pod-IP ratio per node.
	ciliumIPAMFreeRatioGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_cilium_ipam_free_ratio",
		Help: "Free pod-IP ratio (0..1) per node — cilium-node-ipam-exhaustion; <0.15 fails the check.",
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
func (p *ciliumNodeIPAMExhaustionCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()
	minFree := p.minFreeRatio
	if minFree <= 0 {
		minFree = ciliumNodeIPAMMinFreeDefault
	}

	// Prometheus operator IPAM census — cilium_operator_ipam_{used,
	// available}_ips{target_node} (cilium >=1.15; the old
	// cilium_ipam_ips{type=used} metric does not exist). A query
	// failure or an empty result (metric absent on this Cilium
	// version) degrades to the pod-count path rather than
	// false-FAILing.
	usedProm := map[string]float64{}
	availProm := map[string]float64{}
	promOK := false
	if usedSeries, err := p.PromQuery(ctx,
		`cilium_operator_ipam_used_ips`); err == nil && len(usedSeries) > 0 {
		if availSeries, aerr := p.PromQuery(ctx,
			`cilium_operator_ipam_available_ips`); aerr == nil {
			promOK = true
			for _, s := range usedSeries {
				if node := s.Label("target_node", "node",
					"kubernetes_node"); node != "" {
					usedProm[node] = s.Value
				}
			}
			for _, s := range availSeries {
				if node := s.Label("target_node", "node",
					"kubernetes_node"); node != "" {
					availProm[node] = s.Value
				}
			}
		}
	} else if err != nil {
		log.Info("WARN: cilium_operator_ipam_used_ips query failed — pod-count fallback",
			"error", err)
	}

	nodes, err := p.AllNodes(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list nodes: %w", err)}
	}
	pods, err := p.AllPods(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}
	podCount := map[string]int{}
	for i := range pods {
		pod := &pods[i]
		if pod.Spec.HostNetwork || pod.Spec.NodeName == "" {
			continue
		}
		if pod.Status.Phase == corev1.PodSucceeded ||
			pod.Status.Phase == corev1.PodFailed {
			continue
		}
		podCount[pod.Spec.NodeName]++
	}

	var rep probefw.SweepReport
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
		rep.Set(ciliumIPAMFreeRatioGauge, ratio, node.Name, []string{node.Name})
		if ratio >= minFree {
			continue
		}
		rep.Find(fmt.Sprintf(
			"%s(free=%.0f/%d=%.0f%%)", node.Name, free, capacity, ratio*100))
		p.reapTerminalPodsOnNode(ctx, log, node.Name, now)
	}
	return rep.Result(&p.emitted, ciliumIPAMFreeRatioGauge.DeleteLabelValues,
		fmt.Sprintf("nodes below %.0f%% free pod IPs: ", minFree*100), ", ")
}

// reapTerminalPodsOnNode deletes Succeeded/Failed pods on an
// IP-exhausted node (capped) so kubelet releases their sandboxes and
// pod IPs — once per node per cooldown, maintenance-gated. Terminal
// pods hold no traffic; the delete is the safe existing shape (same
// as the evicted-pod janitor, scoped to the exhausted node). The
// node/terminal/cap pick rides BounceOperatorPod: the shared gate
// runs once per node key and each delivered delete invalidates the
// pod census and stamps the cooldown ledger.
func (p *ciliumNodeIPAMExhaustionCheck) reapTerminalPodsOnNode(ctx context.Context,
	log logr.Logger, node string, now time.Time) {

	reaped := p.BounceOperatorPod(ctx, log, CheckNameCiliumNodeIPAM, "",
		func(pods []corev1.Pod) []*corev1.Pod {
			var targets []*corev1.Pod
			for i := range pods {
				pod := &pods[i]
				if pod.Spec.NodeName != node {
					continue // the old spec.nodeName FieldSelector, client-side
				}
				if pod.DeletionTimestamp != nil ||
					(pod.Status.Phase != corev1.PodSucceeded &&
						pod.Status.Phase != corev1.PodFailed) {
					continue
				}
				if len(targets) >= ciliumIPAMMaxReaps {
					break
				}
				targets = append(targets, pod)
			}
			return targets
		},
		&p.Heals, probefw.SelfHealKey(CheckNameCiliumNodeIPAM, "reap/"+node),
		ciliumIPAMNodeCool, now)
	if reaped > 0 {
		log.Info("REAP: deleted terminal pods on IP-exhausted node",
			"node", node, "count", reaped)
	}
}
