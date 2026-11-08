// node_condition_sweeper.go — the node-condition-sweeper check:
// clears watchdog-managed NodeConditions stuck True with a frozen
// lastHeartbeatTime — the reporter that owns them is dead or wedged
// and can never reconcile the zombie itself. 2026-11-07: a
// nodereporter Cycle wedge before syncConditions left
// KubeletPLEGUnhealthy=True on every cicd/production worker long
// after the host latch cleared; each stamped pre-cordon held until
// the conditions were patched by hand — this check is that hand.
package nodehealth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

// nodeCondSweepCheck is the zombie-condition sweeper — stateless,
// reads only Deps.
type nodeCondSweepCheck struct{ *probefw.Deps }

// NewNodeConditionSweeperCheck builds the check.
func NewNodeConditionSweeperCheck(d *probefw.Deps) probefw.Check {
	return &nodeCondSweepCheck{Deps: d}
}

const CheckNameNodeCondSweeper = "node-condition-sweeper"

// nodeCondSweptConds is the sweeper's allowlist — every condition
// nodereporter owns and re-stamps lastHeartbeatTime on while alive
// (nodecond.HeartbeatSweptNames in libs/hostkit, the single source of
// truth shared with the agent: the 40 latch-backed conditions plus
// the ReadonlyFilesystem mount monitor — a superset of the old
// precordon-hang + clock-skew lists). Kubelet-owned types (Ready,
// MemoryPressure/DiskPressure) are never touched, and InodePressure
// is deliberately absent — kubelet-native, the sweeper must never
// clear a kubelet condition — as is KernelDeadlock, the permanent
// latch whose frozen heartbeat means nothing. The sweeper only
// reconciles conditions whose writer is a node agent that re-stamps
// lastHeartbeatTime every ~2m while alive.
var nodeCondSweptConds = condTypes(nodecond.HeartbeatSweptNames)

var nodeCondSweepsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_node_condition_sweeps_total",
	Help: "Watchdog-managed node conditions cleared after their heartbeat froze (writer presumed dead).",
}, []string{"node", "condition"})

func init() {
	ctrlmetrics.Registry.MustRegister(nodeCondSweepsTotal)
}

// condZombie reports a managed condition that is True but unverifiable:
// its heartbeat is dead (zero or older than
// nodeHangCondHeartbeatMaxAge — the reporter re-stamps every ~2m
// while alive) AND the True is old enough that a live writer would
// have re-stamped by now. A fresh True with no heartbeat yet is
// left alone — a foreign writer that just set it may legitimately
// not stamp heartbeats.
func condZombie(c *corev1.NodeCondition, now time.Time) bool {
	if c.Status != corev1.ConditionTrue {
		return false
	}
	if condHeartbeatLive(c, now) {
		return false
	}
	return !c.LastTransitionTime.IsZero() &&
		now.Sub(c.LastTransitionTime.Time) >= nodeHangCondHeartbeatMaxAge
}

// Run patches every zombie managed condition back to False —
// nodereporter's strategic-merge shape on the status subresource,
// so a revived reporter's next cycle simply re-evaluates (its latch
// truth reconciles the condition either way; a real hang re-latches
// on the next heartbeat-refresh cycle and precordon re-arms).
func (p *nodeCondSweepCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()
	nodes, err := p.AllNodes(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list nodes: %w", err)}
	}
	var rep probefw.SweepReport
	for i := range nodes {
		n := &nodes[i]
		var stale []corev1.NodeCondition
		for _, t := range nodeCondSweptConds {
			c := kube.NodeCondition(n, t)
			if c == nil || !condZombie(c, now) {
				continue
			}
			hbAge := "never stamped"
			if !c.LastHeartbeatTime.IsZero() {
				hbAge = fmt.Sprintf("frozen %s",
					now.Sub(c.LastHeartbeatTime.Time).Round(time.Second))
			}
			stale = append(stale, corev1.NodeCondition{
				Type:   c.Type,
				Status: corev1.ConditionFalse,
				Reason: "StaleConditionCleared",
				Message: fmt.Sprintf("heartbeat %s — owning reporter presumed dead; cleared by %s",
					hbAge, CheckNameNodeCondSweeper),
				LastHeartbeatTime:  metav1.NewTime(now),
				LastTransitionTime: metav1.NewTime(now),
			})
		}
		if len(stale) == 0 {
			continue
		}
		payload, err := json.Marshal(map[string]any{
			"status": map[string]any{"conditions": stale},
		})
		if err != nil {
			metrics.IncError(p.Name)
			log.Error(err, "condition sweeper patch marshal failed", "node", n.Name)
			continue
		}
		if _, err := p.CS.CoreV1().Nodes().Patch(ctx, n.Name,
			types.StrategicMergePatchType, payload, metav1.PatchOptions{}, "status"); err != nil {
			metrics.IncError(p.Name)
			log.Error(err, "condition sweeper patch failed", "node", n.Name)
			continue
		}
		p.InvalidateSweep(ctx) // node status changed — drop the snapshot
		for _, c := range stale {
			nodeCondSweepsTotal.WithLabelValues(n.Name, string(c.Type)).Inc()
			rep.Find(n.Name + ":" + string(c.Type))
			log.Info("CONDITION CLEARED: zombie True with frozen heartbeat",
				"node", n.Name, "condition", c.Type)
		}
	}
	return rep.Verdict("zombie node conditions cleared: ", ", ")
}
