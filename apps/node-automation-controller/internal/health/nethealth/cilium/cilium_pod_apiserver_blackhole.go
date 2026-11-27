// cilium_pod_apiserver_blackhole.go — silent pod-to-apiserver
// (10.96.0.1:443) BPF/datapath blackhole detector and minority healer
// inside cilium-datapath-map-guard.
//
// Failure mode (live nonprod incident): cilium-agent passes its own
// /healthz and BPF map counters stay quiet, yet pods on a single
// Ready worker cannot reach the kubernetes Service VIP (10.96.0.1:443)
// — NPD's ClusterNetworkProblem reports "https-p2api-int" continuously
// while CiliumAgentDown is False. Deleting that worker's local
// kube-system/cilium-* DaemonSet pod rebuilds the BPF service/LB maps
// and restores pod->apiserver connectivity immediately.
//
// Safety:
//   - Only activates on Cilium clusters (at least one k8s-app=cilium
//     pod in kube-system).
//   - Requires Ready=True worker, ClusterNetworkProblem(s)=True with
//     "https-p2api-int" persisted >= 10m, CiliumAgentDown != True, and
//     NodeOverloaded != True.
//   - Always emits node_automation_cilium_datapath_degraded{reason="pod_apiserver_blackhole"}.
//   - Minority blast-radius guard: only heals when readyWorkers >= 2
//     and flagged*2 < readyWorkers (a cluster-wide apiserver outage
//     must never bounce cilium agents across the fleet).
//   - At most 1 cilium agent pod deleted per sweep, 30m per-node
//     cooldown, maintenance-mutex + UID-preconditioned via
//     DeletePodHealOnNode, skipping freshly started (<5m) agents.
package cilium

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

const (
	ciliumPodAPIServerBlackholeReason = "pod_apiserver_blackhole"
	ciliumPodAPIServerCondToken       = "https-p2api-int"
	ciliumPodAPIServerMinAge          = 10 * time.Minute
	ciliumPodAPIServerHealCool        = 30 * time.Minute
)

func (p *ciliumDatapathMapCheck) checkPodAPIServerBlackhole(
	ctx context.Context, log logr.Logger,
	last map[string][]string, rep *probefw.SweepReport,
) {
	kubeSystemPods, err := p.PodsIn(ctx, "kube-system")
	if err != nil {
		log.Info("WARN: cilium pod-apiserver blackhole check skipped — kube-system pods list failed",
			"error", err)
		rep.InfraErr(err)
		if lv, held := last[ciliumPodAPIServerBlackholeReason]; held {
			rep.Carry(ciliumPodAPIServerBlackholeReason, lv)
		}
		return
	}
	if !hasCiliumAgentPod(kubeSystemPods) {
		return // non-Cilium cluster (e.g. Calico) or empty test fixture
	}

	nodes, err := p.AllNodes(ctx)
	if err != nil {
		log.Info("WARN: cilium pod-apiserver blackhole check skipped — nodes list failed",
			"error", err)
		rep.InfraErr(err)
		if lv, held := last[ciliumPodAPIServerBlackholeReason]; held {
			rep.Carry(ciliumPodAPIServerBlackholeReason, lv)
		}
		return
	}

	now := p.Now()
	readyWorkers := 0
	var flagged []string
	for i := range nodes {
		n := &nodes[i]
		if kube.IsControlPlane(n) || !kube.NodeReady(n) {
			continue
		}
		readyWorkers++
		if !nodeHasPodAPIServerBlackhole(n, now) {
			continue
		}
		if nodeCondTrue(n, nodecond.CiliumAgentDown) || nodeCondTrue(n, nodecond.NodeOverloaded) {
			continue
		}
		flagged = append(flagged, n.Name)
	}
	if len(flagged) == 0 {
		return
	}
	slices.Sort(flagged)

	rep.Emit(ciliumDatapathDegradedGauge, ciliumPodAPIServerBlackholeReason,
		[]string{ciliumPodAPIServerBlackholeReason},
		fmt.Sprintf("%s (pod->apiserver 10.96.0.1:443 blackhole on %s)",
			ciliumPodAPIServerBlackholeReason, strings.Join(flagged, ",")))

	if readyWorkers < 2 || len(flagged)*2 >= readyWorkers {
		log.Info("SKIP cilium pod-apiserver blackhole heal: majority/single-worker blast-radius guard",
			"flagged", flagged, "readyWorkers", readyWorkers)
		return
	}

	for _, nodeName := range flagged {
		agent := ciliumAgentPodPtrOnNode(kubeSystemPods, nodeName)
		if agent == nil {
			continue
		}
		if !agent.CreationTimestamp.IsZero() && now.Sub(agent.CreationTimestamp.Time) < ciliumAgentFreshMinAge {
			log.Info("SKIP cilium pod-apiserver blackhole heal: agent pod already fresh",
				"node", nodeName, "pod", agent.Name)
			continue
		}
		if p.DeletePodHealOnNode(ctx, log, CheckNameCiliumDatapathMapGuard,
			"pod-apiserver-blackhole/"+nodeName, agent, ciliumPodAPIServerHealCool, now) {
			break // cap 1 agent restart per sweep
		}
	}
}

func hasCiliumAgentPod(pods []*corev1.Pod) bool {
	for _, pod := range pods {
		if pod != nil && pod.Labels["k8s-app"] == "cilium" {
			return true
		}
	}
	return false
}

func ciliumAgentPodPtrOnNode(pods []*corev1.Pod, node string) *corev1.Pod {
	for _, pod := range pods {
		if pod == nil || pod.DeletionTimestamp != nil ||
			pod.Spec.NodeName != node ||
			pod.Status.Phase != corev1.PodRunning ||
			pod.Labels["k8s-app"] != "cilium" {
			continue
		}
		return pod
	}
	return nil
}

func nodeCondTrue(n *corev1.Node, condType corev1.NodeConditionType) bool {
	c := kube.NodeCondition(n, condType)
	return c != nil && c.Status == corev1.ConditionTrue
}

func nodeHasPodAPIServerBlackhole(n *corev1.Node, now time.Time) bool {
	for _, ct := range []corev1.NodeConditionType{
		nodecond.ClusterNetworkProblem,
		nodecond.ClusterNetworkProblems,
	} {
		c := kube.NodeCondition(n, ct)
		if c == nil || c.Status != corev1.ConditionTrue {
			continue
		}
		if !strings.Contains(strings.ToLower(c.Message), ciliumPodAPIServerCondToken) {
			continue
		}
		if !c.LastTransitionTime.IsZero() && now.Sub(c.LastTransitionTime.Time) >= ciliumPodAPIServerMinAge {
			return true
		}
	}
	return false
}
