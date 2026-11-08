// scheduler_watchdog.go — the scheduler-watchdog check (W8-CP3):
// detects a stopped kube-scheduler (Pending pods with no
// PodScheduled condition while Ready uncordoned workers exist) and
// reports node_automation_scheduler_frozen. Detect-only — restarting
// the scheduler is the platform's job.
//
// W12-SC1 adds the second scheduler fault signature: a
// PriorityClass preemption cascade (a high-priority pod preempts
// victims that preempt their own victims — the Monzo/Zalando domino
// eviction shape) reads as a burst of reason=Preempted events;
// >15 inside 5m raises node_automation_scheduler_preemption_storm
// and fails the check so the storm is paged, while
// descheduler-storm-gate reads the same signal to keep the
// descheduler from amplifying the cascade.
package watchdogs

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// schedulerWatchdogCheck is the W8-CP3 scheduler-watchdog — a stopped
// kube-scheduler detected via Pending pods with no PodScheduled
// condition while Ready uncordoned workers exist.
type schedulerWatchdogCheck struct{ *probefw.Deps }

// newSchedulerWatchdogCheck builds the W8-CP3 watchdog — stateless,
// it reads only Deps.
func NewSchedulerWatchdogCheck(d *probefw.Deps) probefw.Check {
	return &schedulerWatchdogCheck{Deps: d}
}

const (
	// W8-CP3 — scheduler-watchdog knobs.
	CheckNameSchedulerWatchdog = "scheduler-watchdog"
	schedulerPendingMinAge     = 5 * time.Minute

	// W12-SC1 — preemption-cascade knobs: an ordinary scheduler
	// emits a handful of Preempted events during placement churn;
	// more than the ceiling inside the window is a domino cascade —
	// each preempted victim requeues and preempts its own victims.
	schedulerPreemptionWindow = 5 * time.Minute
	schedulerPreemptionMax    = 15
)

var (
	// W8-CP3 — the scheduler-freeze signal: 1 while unscheduled
	// Pending pods accumulate past the fuse despite Ready uncordoned
	// workers. A plain gauge — the freeze is cluster-wide, not
	// per-object.
	schedulerFrozenGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_automation_scheduler_frozen",
		Help: "1 while unscheduled Pending pods accumulate past 5m despite Ready uncordoned workers.",
	})

	// W12-SC1 — the preemption-cascade signal: 1 while
	// reason=Preempted events outpace the ceiling — the same plain
	// cluster-wide shape as the freeze gauge.
	schedulerPreemptionStormGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_automation_scheduler_preemption_storm",
		Help: "1 while reason=Preempted events exceed 15 in 5m — a PriorityClass preemption cascade.",
	})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		schedulerFrozenGauge,
		schedulerPreemptionStormGauge)
}

// ---------------------------------------------------------------------------
// W8-CP3 — scheduler-watchdog
// ---------------------------------------------------------------------------

// checkSchedulerFrozen detects a stopped kube-scheduler: unscheduled
// pods accumulate (Pending >=5m, no nodeName, and — the freeze tell —
// no PodScheduled condition at all, because a live scheduler writes a
// PodScheduled=False verdict within seconds) while Ready uncordoned
// workers exist to place them on. Detect-only — restarting the
// scheduler is the platform's job; this check makes the freeze
// visible on node_automation_scheduler_frozen.
//
// The W12-SC1 preemption-cascade signal folds into the same sweep:
// a burst of reason=Preempted events (>15 in 5m) is a PriorityClass
// domino eviction storm, reported on
// node_automation_scheduler_preemption_storm — the freeze signal is
// about a DEAD scheduler, the storm signal about a scheduler that is
// too busy evicting to place anything. An events-list failure is
// tolerated (WARN + InfraErr) — the freeze half still judges on its
// own evidence, and an inconclusive storm signal must not read as
// "no storm".
func (p *schedulerWatchdogCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()
	var rep probefw.SweepReport

	// W12-SC1 — PriorityClass preemption cascade. The count ignores
	// reason alone (kube.CountRecentEvents re-checks it) so a
	// supported-field-selector variant can never over-report.
	preempted, err := kube.CountRecentEvents(ctx, p.CS,
		kube.PreemptedEventReason, schedulerPreemptionWindow, now)
	if err != nil {
		log.Info("WARN: preempted events list failed — preemption-storm signal inconclusive",
			"error", err)
		rep.InfraErr(fmt.Errorf("list preempted events: %w", err))
	} else if preempted > schedulerPreemptionMax {
		schedulerPreemptionStormGauge.Set(1)
		rep.Find(fmt.Sprintf(
			"preemption storm: %d Preempted events in %s (>%d)",
			preempted, schedulerPreemptionWindow, schedulerPreemptionMax))
	} else {
		schedulerPreemptionStormGauge.Set(0)
	}

	nodes, err := p.AllNodes(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list nodes: %w", err)}
	}
	schedulable := false
	for i := range nodes {
		if kube.NodeReady(&nodes[i]) && !nodes[i].Spec.Unschedulable &&
			!kube.IsControlPlane(&nodes[i]) {
			schedulable = true
			break
		}
	}
	if !schedulable {
		schedulerFrozenGauge.Set(0)
		// nowhere to schedule — the freeze signal is ambiguous, but
		// the preemption-storm finding above still reports.
		return rep.Verdict("scheduler fault signatures: ", ", ")
	}

	pods, err := p.AllPods(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pending pods: %w", err)}
	}
	pending := 0
	for i := range pods {
		pod := &pods[i]
		if pod.Status.Phase != corev1.PodPending ||
			pod.Spec.NodeName != "" ||
			// SchedulingGates block placement BY DESIGN (a gated
			// pod stays Pending until its gate controller removes
			// the gate) — a frozen scheduler must not be inferred
			// from pods the scheduler is forbidden to touch.
			len(pod.Spec.SchedulingGates) > 0 ||
			now.Sub(pod.CreationTimestamp.Time) < schedulerPendingMinAge {
			continue
		}
		scheduled := false
		for _, c := range pod.Status.Conditions {
			if c.Type == corev1.PodScheduled {
				scheduled = true
				break
			}
		}
		if !scheduled {
			pending++
			rep.Find(pod.Namespace + "/" + pod.Name)
		}
	}
	if pending == 0 {
		schedulerFrozenGauge.Set(0)
	} else {
		schedulerFrozenGauge.Set(1)
	}
	return rep.Verdict(fmt.Sprintf(
		"scheduler fault signatures (%d pods pending >=%s unscheduled with no PodScheduled condition despite Ready workers): ",
		pending, schedulerPendingMinAge), ", ")
}
