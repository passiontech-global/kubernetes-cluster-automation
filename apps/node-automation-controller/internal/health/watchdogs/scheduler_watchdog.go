// scheduler_watchdog.go — the scheduler-watchdog check (W8-CP3):
// detects a stopped kube-scheduler (Pending pods with no
// PodScheduled condition while Ready uncordoned workers exist) and
// reports node_automation_scheduler_frozen. Detect-only — restarting
// the scheduler is the platform's job.
package watchdogs

import (
	"context"
	"fmt"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
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
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		schedulerFrozenGauge)
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
func (p *schedulerWatchdogCheck) Run(ctx context.Context) probefw.Result {
	nodes, err := kube.ListNodes(ctx, p.CS)
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
		return probefw.Result{Pass: true} // nowhere to schedule — ambiguous
	}

	pods, err := p.CS.CoreV1().Pods(metav1.NamespaceAll).List(ctx,
		metav1.ListOptions{FieldSelector: "status.phase=Pending"})
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pending pods: %w", err)}
	}
	now := p.Now()
	var stuck []string
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Spec.NodeName != "" ||
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
			stuck = append(stuck, pod.Namespace+"/"+pod.Name)
		}
	}
	if len(stuck) == 0 {
		schedulerFrozenGauge.Set(0)
		return probefw.Result{Pass: true}
	}
	sort.Strings(stuck)
	schedulerFrozenGauge.Set(1)
	return probefw.Result{Why: fmt.Sprintf(
		"%d pods pending >=%s unscheduled with no PodScheduled condition despite Ready workers: %s",
		len(stuck), schedulerPendingMinAge, strings.Join(stuck, ", "))}
}
