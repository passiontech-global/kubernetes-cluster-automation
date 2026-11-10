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

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
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
	// hypervisor steal time crosses its threshold — spelled by
	// nodecond (libs/hostkit), the source of truth shared with the
	// agent.
	cpuStealCond corev1.NodeConditionType = nodecond.CPUStealPressure

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
		// CPUStealPressure is nodereporter-owned: a frozen or absent
		// heartbeat means the reporter is wedged and the True a
		// zombie — never taint on it. The latch reads as cleared (the
		// untaint path's own 10m clear window still applies before
		// the taint lifts).
		if !kube.CondHeartbeatLive(c, nodeHangCondHeartbeatMaxAge, now) {
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
				if !tainted && p.stealHealthyWorkers(nodes, n.Name, now) >= cpuStealMinHealthy {
					// Per-target non-convergent circuit breaker — the
					// 4th taint of the same worker inside the window
					// defers: steal pressure that keeps coming back
					// despite repeated taints is hypervisor-side, and
					// re-patching the same node every sweep is churn
					// the breaker stops. Defer semantics: log, skip —
					// the check still FAILs below so the pressure
					// stays visible; never an error. The untaint path
					// clears the history the moment the steal clears.
					// The module label is the check's canonical name
					// (the const), not Deps.Name — the latter is the
					// harness's shared name in tests.
					if allowed, reason := heal.TryAcquireTarget(
						CheckNameCPUStealTaintSync, n.Name, now); !allowed {
						log.Info("DEFER: heal target circuit open — taint skipped",
							"node", n.Name, "reason", reason)
					} else if err := kube.TaintNode(ctx, p.CS, n.Name,
						kube.TaintCPUSteal, cpuStealTaintValue,
						corev1.TaintEffectPreferNoSchedule); err != nil {
						metrics.IncError(p.Name)
						log.Error(err, "cpu-steal taint failed", "node", n.Name)
					} else {
						p.InvalidateNodes(ctx) // node taints changed
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
						p.InvalidateNodes(ctx) // node taints changed
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
						// Untainted — the steal cleared: the node's
						// own convergence evidence. Clear its breaker
						// history so a future pressure episode starts
						// from zero instead of tripping a circuit
						// half filled by the last one.
						heal.RecordTargetHealthy(CheckNameCPUStealTaintSync, n.Name)
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
// A zombie CPUStealPressure (frozen heartbeat) is NOT pressure
// evidence and its node still counts as absorbable headroom.
func (p *cpuStealTaintSyncCheck) stealHealthyWorkers(nodes []corev1.Node, exclude string, now time.Time) int {
	n := 0
	for i := range nodes {
		w := &nodes[i]
		if w.Name == exclude || kube.IsControlPlane(w) ||
			!kube.NodeReady(w) || w.Spec.Unschedulable ||
			kube.HasTaint(w.Spec.Taints, kube.TaintCPUSteal) {
			continue
		}
		if c := kube.NodeCondition(w, cpuStealCond); c != nil &&
			c.Status == corev1.ConditionTrue &&
			kube.CondHeartbeatLive(c, nodeHangCondHeartbeatMaxAge, now) {
			continue // pressured at any age is not healthy headroom
		}
		n++
	}
	return n
}
