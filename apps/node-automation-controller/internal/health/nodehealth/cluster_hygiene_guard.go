// cluster_hygiene_guard.go — health check "cluster-hygiene-guard":
// detects long-lived cluster hygiene drift:
//  1. Nodes with Spec.Unschedulable == true aged >= 24h carrying NO
//     maintenance, kured, NHC/medik8s, or precordon annotation or taint
//     ("forgotten_manual_cordon").
//  2. Unowned Pods matching node-debugger-* / kubectl-debug-* OR any Pod
//     carrying spec.ephemeralContainers aged >= 24h ("orphan_debug_pod").
//
// Emits node_automation_cluster_hygiene_issue{target,reason} and
// cooldown-deduped Warning Events (ClusterHygieneIssue).
//
// Opt-in GC (NODE_AUTOMATION_CLUSTER_HYGIENE_GC_ENABLED=true, default false):
// ONLY deletes unowned node-debugger-* / kubectl-debug-* Pods that are ALREADY
// terminal (Succeeded/Failed) and aged >= 24h via UID-preconditioned delete,
// bounded per sweep. Never deletes running Pods or Pods merely carrying
// ephemeralContainers.
package nodehealth

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

const (
	// CheckNameClusterHygieneGuard is the registry check name for cluster-hygiene-guard.
	CheckNameClusterHygieneGuard = "cluster-hygiene-guard"

	clusterHygieneMinAge         = 24 * time.Hour
	clusterHygieneEventCooldown  = 6 * time.Hour
	clusterHygieneMaxEventsSweep = 20
	clusterHygieneMaxGCSweep     = 5
	clusterHygieneEventReason    = "ClusterHygieneIssue"

	hygieneReasonForgottenCordon = "forgotten_manual_cordon"
	hygieneReasonOrphanDebugPod  = "orphan_debug_pod"
)

var clusterHygieneIssueGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_cluster_hygiene_issue",
	Help: "1 while a forgotten manual node cordon (>=24h) or orphan debug pod / long-lived ephemeral container pod (>=24h) exists.",
}, []string{"target", "reason"})

func init() {
	ctrlmetrics.Registry.MustRegister(clusterHygieneIssueGauge)
}

type clusterHygieneGuardCheck struct {
	*probefw.Deps

	gcEnabled bool

	firstSeen     state.FirstSeenLedger
	emitted       state.GaugeLedger[string]
	eventCooldown state.CooldownSet
}

// NewClusterHygieneGuardCheck constructs the cluster-hygiene-guard check.
func NewClusterHygieneGuardCheck(d *probefw.Deps) probefw.Check {
	return &clusterHygieneGuardCheck{
		Deps:      d,
		gcEnabled: envx.Gate("NODE_AUTOMATION_CLUSTER_HYGIENE_GC_ENABLED", false),
	}
}

type clusterHygieneFinding struct {
	target    string
	reason    string
	namespace string
	regarding corev1.ObjectReference
	detail    string
	gcPod     *corev1.Pod
}

func (c *clusterHygieneGuardCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := c.Now()
	c.eventCooldown.PruneExpired(now, clusterHygieneEventCooldown)

	nodes, err := c.AllNodes(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list nodes: %w", err)}
	}
	pods, err := c.AllPods(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}

	var rep probefw.SweepReport
	var findings []clusterHygieneFinding
	liveFirstSeen := map[string]bool{}

	for i := range nodes {
		n := &nodes[i]
		if !n.Spec.Unschedulable || hygieneHasMaintenanceMarker(ctx, n) {
			continue
		}
		cordonAt, ok := hygieneCordonTime(n)
		aged := false
		if ok {
			aged = kube.AgeAtLeast(cordonAt, now, clusterHygieneMinAge)
		} else {
			fsKey := "cordon/" + n.Name
			liveFirstSeen[fsKey] = true
			aged = probefw.Persisted(&c.firstSeen, fsKey, now, clusterHygieneMinAge, log)
		}
		if !aged {
			continue
		}
		findings = append(findings, clusterHygieneFinding{
			target:    n.Name,
			reason:    hygieneReasonForgottenCordon,
			namespace: "default",
			regarding: corev1.ObjectReference{
				APIVersion: "v1",
				Kind:       "Node",
				Name:       n.Name,
				UID:        n.UID,
			},
			detail: fmt.Sprintf("Node %s has been manually cordoned (unschedulable) for >=%s without maintenance/kured/NHC/precordon markers", n.Name, clusterHygieneMinAge),
		})
	}

	for i := range pods {
		pod := &pods[i]
		if pod.DeletionTimestamp != nil {
			continue
		}
		isDebugName := len(pod.OwnerReferences) == 0 &&
			(strings.HasPrefix(pod.Name, "node-debugger-") || strings.HasPrefix(pod.Name, "kubectl-debug-"))
		hasEphemeral := len(pod.Spec.EphemeralContainers) > 0
		if !isDebugName && !hasEphemeral {
			continue
		}

		aged := false
		if !pod.CreationTimestamp.IsZero() {
			aged = kube.AgeAtLeast(pod.CreationTimestamp.Time, now, clusterHygieneMinAge)
		} else {
			fsKey := "pod/" + pod.Namespace + "/" + pod.Name + "/" + string(pod.UID)
			liveFirstSeen[fsKey] = true
			aged = probefw.Persisted(&c.firstSeen, fsKey, now, clusterHygieneMinAge, log)
		}
		if !aged {
			continue
		}

		var gcPod *corev1.Pod
		if isDebugName && (pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed) {
			gcPod = pod
		}
		podKey := pod.Namespace + "/" + pod.Name
		findings = append(findings, clusterHygieneFinding{
			target:    podKey,
			reason:    hygieneReasonOrphanDebugPod,
			namespace: pod.Namespace,
			regarding: corev1.ObjectReference{
				APIVersion: "v1",
				Kind:       "Pod",
				Namespace:  pod.Namespace,
				Name:       pod.Name,
				UID:        pod.UID,
			},
			detail: fmt.Sprintf("Orphan debug/ephemeral Pod %s aged >=%s", podKey, clusterHygieneMinAge),
			gcPod:  gcPod,
		})
	}

	c.firstSeen.Prune(func(k string) bool { return liveFirstSeen[k] })

	slices.SortFunc(findings, func(a, b clusterHygieneFinding) int {
		if x := cmp.Compare(a.reason, b.reason); x != 0 {
			return x
		}
		return cmp.Compare(a.target, b.target)
	})

	for _, f := range findings {
		tupleKey := f.target + "/" + f.reason
		rep.Emit(clusterHygieneIssueGauge, tupleKey,
			[]string{f.target, f.reason},
			fmt.Sprintf("%s (%s)", f.target, f.reason))
	}

	c.emitEvents(ctx, log, now, findings)

	if c.gcEnabled && len(findings) > 0 {
		c.gcTerminalDebugPods(ctx, log, findings)
	}

	return rep.Result(&c.emitted, clusterHygieneIssueGauge.DeleteLabelValues,
		"cluster hygiene issue: ", ", ")
}

func hygieneCordonTime(n *corev1.Node) (time.Time, bool) {
	for _, t := range n.Spec.Taints {
		if t.Key == kube.UnschedulableTaintKey && t.TimeAdded != nil && !t.TimeAdded.IsZero() {
			return t.TimeAdded.Time, true
		}
	}
	return time.Time{}, false
}

func hygieneHasMaintenanceMarker(ctx context.Context, n *corev1.Node) bool {
	if kube.HasRemediationOrFenceTaint(n) || kube.HasTaint(n.Spec.Taints, kube.TaintKuredNodeReboot) {
		return true
	}
	for _, t := range n.Spec.Taints {
		if strings.HasPrefix(t.Key, "medik8s.io/") ||
			strings.HasPrefix(t.Key, "nodemaintenance.medik8s.io/") ||
			strings.HasPrefix(t.Key, "self-node-remediation.medik8s.io/") ||
			strings.HasPrefix(t.Key, "fence-agents-remediation.medik8s.io/") ||
			t.Key == zoneGrayTaintKey {
			return true
		}
	}
	annos := kube.EffectiveAnnos(ctx, n)
	if annos[kube.AnnoPreCordonedBy] != "" || annos[nodecond.KuredLockAnno] != "" {
		return true
	}
	for k := range annos {
		if strings.HasPrefix(k, "weave.works/kured") ||
			strings.HasPrefix(k, "medik8s.io/") ||
			strings.HasPrefix(k, "remediation.medik8s.io/") ||
			strings.HasPrefix(k, "nodemaintenance.medik8s.io/") ||
			strings.HasPrefix(k, "self-node-remediation.medik8s.io/") ||
			strings.HasPrefix(k, "autopilot.k0sproject.io/") {
			return true
		}
	}
	return false
}

func (c *clusterHygieneGuardCheck) emitEvents(ctx context.Context, log logr.Logger, now time.Time, findings []clusterHygieneFinding) {
	emitted := 0
	for _, f := range findings {
		if emitted >= clusterHygieneMaxEventsSweep {
			log.Info("SKIP rest: cluster-hygiene-guard event cap reached",
				"cap", clusterHygieneMaxEventsSweep)
			break
		}
		cooldownKey := "hygiene." + f.reason + "." + f.target
		if probefw.EmitWarningDeduped(ctx, c.CS, log, &c.eventCooldown, cooldownKey, clusterHygieneEventCooldown, now, kube.WarningEvent{
			Namespace:         f.namespace,
			Regarding:         f.regarding,
			Reason:            clusterHygieneEventReason,
			Note:              f.detail,
			ReportingInstance: cmp.Or(c.Name, CheckNameClusterHygieneGuard),
		}) {
			emitted++
		}
	}
}

func (c *clusterHygieneGuardCheck) gcTerminalDebugPods(ctx context.Context, log logr.Logger, findings []clusterHygieneFinding) {
	deleted := 0
	for _, f := range findings {
		if f.gcPod == nil {
			continue
		}
		if deleted >= clusterHygieneMaxGCSweep {
			log.Info("SKIP rest: cluster-hygiene-guard GC cap reached",
				"cap", clusterHygieneMaxGCSweep)
			break
		}
		pod := f.gcPod
		err := c.CS.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, kube.UIDDeleteOptions(pod.UID, ""))
		switch {
		case apierrors.IsNotFound(err):
			kube.MarkPodDeleted(ctx, pod.UID)
		case apierrors.IsConflict(err):
			// Recreated with different UID — skip cleanly.
		case err != nil:
			metrics.IncError(c.Name)
			log.Error(err, "orphan terminal debug pod GC failed", "pod", f.target)
		default:
			kube.MarkPodDeleted(ctx, pod.UID)
			deleted++
			log.Info("GC: deleted terminal orphan debug pod", "pod", f.target, "phase", pod.Status.Phase)
		}
	}
}
