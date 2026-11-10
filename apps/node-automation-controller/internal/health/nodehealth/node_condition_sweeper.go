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

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
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

// nodeCondSweepHeartbeatMaxAge is the sweeper's zombie TTL — how
// long a managed condition may sit True with a frozen heartbeat
// before the sweeper calls its writer dead. Deliberately LARGER than
// the reporters' own ~2m re-stamp cadence, the 900s (15m) hardware/
// runtime condition thresholds and the 1200s (20m) WatchdogStale
// window inside the Medik8s NodeHealthCheck: the sweeper must lose
// to NHC/SNR/FAR remediation, never preempt it — and a node that
// just went NotReady keeps its conditions for the rescue path
// (Run skips NotReady nodes outright).
const nodeCondSweepHeartbeatMaxAge = 25 * time.Minute

// nodeCondSweptConds is the sweeper's allowlist — every condition
// nodereporter owns and re-stamps lastHeartbeatTime on while alive
// (nodecond.HeartbeatSweptNames in libs/hostkit, the single source of
// truth shared with the agent: the 41 latch-backed conditions
// (incl. InodePressure, agent-latched since inode-pressure) plus the
// ReadonlyFilesystem mount monitor — a superset of the old
// precordon-hang + clock-skew lists). Kubelet-owned types (Ready,
// MemoryPressure/DiskPressure) are never touched, as is
// KernelDeadlock, the permanent latch whose frozen heartbeat means
// nothing. The sweeper only reconciles conditions whose writer is a
// node agent that re-stamps lastHeartbeatTime every ~2m while alive.
var nodeCondSweptConds = kube.CondTypes(nodecond.HeartbeatSweptNames)

var nodeCondSweepsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_node_condition_sweeps_total",
	Help: "Watchdog-managed node conditions cleared after their heartbeat froze (writer presumed dead).",
}, []string{"node", "condition"})

func init() {
	ctrlmetrics.Registry.MustRegister(nodeCondSweepsTotal)
}

// condZombie reports a managed condition that is True but unverifiable:
// its heartbeat is dead (zero or older than
// nodeCondSweepHeartbeatMaxAge — the reporter re-stamps every ~2m
// while alive) AND the True is old enough that a live writer would
// have re-stamped by now. A fresh True with no heartbeat yet is
// left alone — a foreign writer that just set it may legitimately
// not stamp heartbeats.
func condZombie(c *corev1.NodeCondition, now time.Time) bool {
	if c.Status != corev1.ConditionTrue {
		return false
	}
	if kube.CondHeartbeatLive(c, nodeCondSweepHeartbeatMaxAge, now) {
		return false
	}
	return !c.LastTransitionTime.IsZero() &&
		now.Sub(c.LastTransitionTime.Time) >= nodeCondSweepHeartbeatMaxAge
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
		// A NotReady node is mid-rescue — NHC/SNR/FAR own its
		// conditions now; sweeping them would erase the evidence
		// the remediation path reads.
		if c := kube.NodeCondition(n, corev1.NodeReady); c != nil &&
			c.Status != corev1.ConditionTrue {
			continue
		}
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
		p.InvalidateNodes(ctx) // node status changed — drop the node census, arm a CS re-read
		for _, c := range stale {
			nodeCondSweepsTotal.WithLabelValues(n.Name, string(c.Type)).Inc()
			rep.Find(n.Name + ":" + string(c.Type))
			log.Info("CONDITION CLEARED: zombie True with frozen heartbeat",
				"node", n.Name, "condition", c.Type)
		}
	}
	return rep.Verdict("zombie node conditions cleared: ", ", ")
}
