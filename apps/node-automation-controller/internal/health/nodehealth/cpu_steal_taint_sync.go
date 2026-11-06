// cpu_steal_taint_sync.go — the cpu-steal-taint-sync check: mirrors
// the node-agent's CPUStealPressure latch into a PreferNoSchedule
// taint so the scheduler drains NEW pods off a hypervisor-throttled
// worker, and lifts the taint once the steal clears for good.
package nodehealth

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// cpuStealTaintSyncCheck is the CPUStealPressure taint mirror.
type cpuStealTaintSyncCheck struct {
	*probefw.Deps

	// clear tracks per node when the pressure condition was last seen
	// NOT True — the 10m clear window before this check lifts its own
	// taint (condition-absent has no timestamp, so the first-seen
	// ledger is the clock for both False and gone).
	clear state.FirstSeenLedger
	// emitted is the emitted-gauge ledger — a tuple that stops
	// being reported gets DeleteLabelValues'd rather than leaking a
	// stale 1 (zero value usable; the serial sweep needs no lock).
	emitted state.GaugeLedger[string]
}

// NewCPUStealTaintSyncCheck builds the cpu-steal taint sync check —
// its state is the clear-window ledger and the emitted-gauge ledger.
func NewCPUStealTaintSyncCheck(d *probefw.Deps) probefw.Check {
	return &cpuStealTaintSyncCheck{Deps: d}
}

const (
	CheckNameCPUStealTaintSync = "cpu-steal-taint-sync"

	// cpu-steal-taint-sync knobs.
	cpuStealCondMinAge  = 5 * time.Minute
	cpuStealClearMinAge = 10 * time.Minute
	cpuStealMinHealthy  = 2

	// cpuStealCond is the NodeCondition the node-agent latches while
	// hypervisor steal time crosses its threshold — no corev1
	// constant exists, same convention as the hang-latch literals.
	cpuStealCond corev1.NodeConditionType = "CPUStealPressure"

	// cpuStealTaintValue pairs with kube.TaintCPUSteal — the taint is
	// PreferNoSchedule so it drains new placements without evicting
	// the pods already running on the throttled worker (eviction is
	// NHC's call, not a taint's).
	cpuStealTaintValue = "high"
)

var (
	// Worker nodes carrying the cpu-steal taint.
	cpuStealTaintedGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_node_cpu_steal_tainted",
		Help: "1 while the worker carries the passiontech.dev/cpu-steal PreferNoSchedule taint.",
	}, []string{"node"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		cpuStealTaintedGauge)
}

// checkCPUStealTaintSync syncs the passiontech.dev/cpu-steal taint
// with the CPUStealPressure latch: a worker pressured for >=5m gets
// tainted PreferNoSchedule so fresh pods land elsewhere — but ONLY
// while >=2 other Ready, unpressured, untainted workers remain to
// absorb them (tainting the last healthy nodes strands the whole
// fleet's scheduling). A tainted worker whose pressure condition has
// been False or absent for >=10m gets untainted — the window rides
// the clear ledger because a vanished condition carries no timestamp.
// The check FAILs while any worker shows sustained steal pressure,
// tainted or not.
func (p *cpuStealTaintSyncCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()
	nodes, err := kube.ListNodes(ctx, p.CS)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list nodes: %w", err)}
	}

	// Pressure census — the heal guard counts OTHER healthy workers,
	// so it needs the whole fleet's pressure state before tainting
	// anyone.
	pressured := map[string]time.Duration{}
	condTrue := map[string]bool{}
	for i := range nodes {
		n := &nodes[i]
		if kube.IsControlPlane(n) {
			continue
		}
		c := kube.NodeCondition(n, cpuStealCond)
		if c == nil || c.Status != corev1.ConditionTrue {
			continue
		}
		condTrue[n.Name] = true
		if c.LastTransitionTime.IsZero() ||
			now.Sub(c.LastTransitionTime.Time) >= cpuStealCondMinAge {
			pressured[n.Name] = now.Sub(c.LastTransitionTime.Time)
		}
	}

	clearKeep := map[string]bool{}
	var rep probefw.SweepReport
	for i := range nodes {
		n := &nodes[i]
		if kube.IsControlPlane(n) {
			continue
		}
		tainted := kube.HasTaint(n.Spec.Taints, kube.TaintCPUSteal)
		if condTrue[n.Name] {
			// Pressure still on — the clear clock re-arms.
			clearKeep[n.Name] = false
			if age, ok := pressured[n.Name]; ok {
				rep.Find(fmt.Sprintf("%s(%s)", n.Name, age.Truncate(time.Minute)))
				if !tainted && p.stealHealthyWorkers(nodes, n.Name) >= cpuStealMinHealthy {
					if err := kube.TaintNode(ctx, p.CS, n.Name,
						kube.TaintCPUSteal, cpuStealTaintValue,
						corev1.TaintEffectPreferNoSchedule); err != nil {
						metrics.IncError(p.Name)
						log.Error(err, "cpu-steal taint failed", "node", n.Name)
					} else {
						tainted = true
						log.Info("TAINT: worker under sustained CPUStealPressure — PreferNoSchedule",
							"node", n.Name, "for", age.Truncate(time.Minute))
					}
				}
			}
		} else {
			clearKeep[n.Name] = true
			if tainted {
				// Quiet site: the clear window logs only on the
				// untaint itself, not on every observed sweep.
				if probefw.Persisted(&p.clear, n.Name, now,
					cpuStealClearMinAge, logr.Discard()) {
					if err := kube.UntaintNode(ctx, p.CS, n.Name, kube.TaintCPUSteal); err != nil {
						metrics.IncError(p.Name)
						log.Error(err, "cpu-steal untaint failed", "node", n.Name)
					} else {
						tainted = false
						p.clear.Forget(n.Name)
						log.Info("UNTAINT: CPUStealPressure cleared — worker back in the pool",
							"node", n.Name)
					}
				}
			}
		}
		if tainted {
			rep.Flag(cpuStealTaintedGauge, n.Name, []string{n.Name})
		}
	}
	p.clear.Prune(func(k string) bool { return clearKeep[k] })
	return rep.Result(&p.emitted, cpuStealTaintedGauge.DeleteLabelValues,
		fmt.Sprintf("workers under sustained CPUStealPressure >=%s: ",
			cpuStealCondMinAge), ", ")
}

// stealHealthyWorkers counts the Ready, schedulable, unpressured,
// steal-untainted workers excluding `exclude` — the fleet headroom
// that must stay >=cpuStealMinHealthy before another taint is safe.
func (p *cpuStealTaintSyncCheck) stealHealthyWorkers(nodes []corev1.Node, exclude string) int {
	n := 0
	for i := range nodes {
		w := &nodes[i]
		if w.Name == exclude || kube.IsControlPlane(w) ||
			!kube.NodeReady(w) || w.Spec.Unschedulable ||
			kube.HasTaint(w.Spec.Taints, kube.TaintCPUSteal) {
			continue
		}
		if c := kube.NodeCondition(w, cpuStealCond); c != nil &&
			c.Status == corev1.ConditionTrue {
			continue // pressured at any age is not healthy headroom
		}
		n++
	}
	return n
}
