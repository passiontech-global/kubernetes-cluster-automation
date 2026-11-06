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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// cpuStealTaintSyncCheck is the CPUStealPressure taint mirror.
type cpuStealTaintSyncCheck struct {
	*probefw.Deps

	// clear tracks per node when the pressure condition was last seen
	// NOT True — the 10m clear window before this check lifts its own
	// taint (condition-absent has no timestamp, so the first-seen
	// ledger is the clock for both False and gone). The window gates
	// the untaint remediation, so it runs the annotation-backed
	// variant — stamped on the Node under
	// kube.AnnoFirstSeenCPUStealClear so a restart resumes the count.
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
	nodes, err := p.AllNodes(ctx)
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
		// annoPatch delivers this node's first-seen merge patch —
		// the durable half of the clear window below: the window
		// gates the untaint remediation, so the stamp lives on the
		// Node for a restarted operator to resume (a restart that
		// re-armed the window would keep an already-quiet worker
		// tainted a full extra 10m).
		annoPatch := func(ctx context.Context, data []byte) error {
			_, err := p.CS.CoreV1().Nodes().Patch(ctx, n.Name,
				types.MergePatchType, data, metav1.PatchOptions{})
			return err
		}
		if condTrue[n.Name] {
			// Pressure still on — the clear clock re-arms. A
			// tainted worker may still carry the clear stamp from
			// before the pressure returned: drop it from BOTH
			// clocks so the stale window cannot fast-trip the next
			// untaint (a failed clear is Warn'd inside, tolerated —
			// clearKeep already marks the RAM side for pruning).
			clearKeep[n.Name] = false
			if tainted {
				_ = heal.ClearPersistedFirstSeen(ctx, logr.Discard(),
					&p.clear, n, kube.AnnoFirstSeenCPUStealClear,
					n.Name, annoPatch)
			}
			if age, ok := pressured[n.Name]; ok {
				rep.Find(fmt.Sprintf("%s(%s)", n.Name, age.Truncate(time.Minute)))
				if !tainted && p.stealHealthyWorkers(nodes, n.Name) >= cpuStealMinHealthy {
					if err := kube.TaintNode(ctx, p.CS, n.Name,
						kube.TaintCPUSteal, cpuStealTaintValue,
						corev1.TaintEffectPreferNoSchedule); err != nil {
						metrics.IncError(p.Name)
						log.Error(err, "cpu-steal taint failed", "node", n.Name)
					} else {
						p.InvalidateSweep(ctx) // node taints changed
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
				// untaint itself, not on every observed sweep. The
				// annotation-backed variant — the stamp on the Node
				// lets a restarted operator honor a clear window it
				// never saw in RAM.
				if heal.FirstSeenPersisted(ctx, logr.Discard(), &p.clear,
					n, kube.AnnoFirstSeenCPUStealClear, n.Name,
					cpuStealClearMinAge, now, annoPatch) {
					if err := kube.UntaintNode(ctx, p.CS, n.Name, kube.TaintCPUSteal); err != nil {
						metrics.IncError(p.Name)
						log.Error(err, "cpu-steal untaint failed", "node", n.Name)
					} else {
						p.InvalidateSweep(ctx) // node taints changed
						tainted = false
						// The untaint landed — the stamp leaves BOTH
						// clocks so the next taint cycle re-arms a
						// full window; a failed clear is Warn'd
						// inside and tolerated (the stamp dies with
						// the node's next pressured sweep anyway).
						_ = heal.ClearPersistedFirstSeen(ctx,
							logr.Discard(), &p.clear, n,
							kube.AnnoFirstSeenCPUStealClear, n.Name,
							annoPatch)
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
