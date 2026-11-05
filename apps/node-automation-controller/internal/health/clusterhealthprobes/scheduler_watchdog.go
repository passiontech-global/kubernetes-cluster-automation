// scheduler_watchdog.go — the scheduler-watchdog check (W8-CP3):
// detects a stopped kube-scheduler (Pending pods with no
// PodScheduled condition while Ready uncordoned workers exist) and
// reports node_automation_scheduler_frozen. Detect-only — restarting
// the scheduler is the platform's job.
package clusterhealthprobes

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

const (
	// W8-CP3 — scheduler-watchdog knobs.
	checkNameSchedulerWatchdog = "scheduler-watchdog"
	schedulerPendingMinAge     = 5 * time.Minute
)

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
func (p *clusterHealthProber) checkSchedulerFrozen(ctx context.Context) probeResult {
	nodes, err := shared.ListNodes(ctx, p.cs)
	if err != nil {
		return probeResult{infra: fmt.Errorf("list nodes: %w", err)}
	}
	schedulable := false
	for i := range nodes {
		if shared.NodeReady(&nodes[i]) && !nodes[i].Spec.Unschedulable &&
			!shared.IsControlPlane(&nodes[i]) {
			schedulable = true
			break
		}
	}
	if !schedulable {
		metrics.SchedulerFrozen.Set(0)
		return probeResult{pass: true} // nowhere to schedule — ambiguous
	}

	pods, err := p.cs.CoreV1().Pods(metav1.NamespaceAll).List(ctx,
		metav1.ListOptions{FieldSelector: "status.phase=Pending"})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list pending pods: %w", err)}
	}
	now := p.now()
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
		metrics.SchedulerFrozen.Set(0)
		return probeResult{pass: true}
	}
	sort.Strings(stuck)
	metrics.SchedulerFrozen.Set(1)
	return probeResult{why: fmt.Sprintf(
		"%d pods pending >=%s unscheduled with no PodScheduled condition despite Ready workers: %s",
		len(stuck), schedulerPendingMinAge, strings.Join(stuck, ", "))}
}
