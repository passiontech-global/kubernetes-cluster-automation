// pod_resize_wedge_guard.go — health check "pod-resize-wedge-guard" (K7):
// detects Pods wedged in an in-place resource resize state
// (PodResizePending=True or PodResizeInProgress=True) past min age
// (default 15m via NODE_AUTOMATION_POD_RESIZE_MIN_AGE).
//
// Emits node_automation_pod_resize_wedged{namespace,pod,reason} and a
// cooldown-deduped Warning Event (PodResizeWedged). When opt-in
// eviction is enabled (NODE_AUTOMATION_POD_RESIZE_EVICT_ENABLED=true),
// PDB-safely evicts eligible PodResizePending/Deferred pods so the
// controller can reschedule them onto a node with headroom.
package watchdogs

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

const (
	// CheckNamePodResizeWedgeGuard is the registry check name for K7.
	CheckNamePodResizeWedgeGuard = "pod-resize-wedge-guard"

	podResizeDefaultMinAge     = 15 * time.Minute
	podResizeEventCooldown     = 30 * time.Minute
	podResizeEvictCooldown     = 30 * time.Minute
	podResizeEventReason       = "PodResizeWedged"
	podResizeMaxEvictsPerSweep = 4

	podResizeReasonPendingDeferred   = "pending_deferred"
	podResizeReasonPendingInfeasible = "pending_infeasible"
	podResizeReasonPending           = "pending"
	podResizeReasonInProgressError   = "in_progress_error"
	podResizeReasonInProgress        = "in_progress"
)

var podResizeWedgedGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_pod_resize_wedged",
	Help: "1 while a Pod has a stuck PodResizePending or PodResizeInProgress condition past min age.",
}, []string{"namespace", "pod", "reason"})

func init() {
	ctrlmetrics.Registry.MustRegister(podResizeWedgedGauge)
}

var podResizeSystemNamespaces = map[string]bool{
	"kube-system":     true,
	"kube-public":     true,
	"kube-node-lease": true,
	"node-ops":        true,
	"flux-system":     true,
	"linkerd":         true,
	"linkerd-cni":     true,
	"cilium":          true,
	"cert-manager":    true,
	"medik8s":         true,
}

type podResizeWedgeGuardCheck struct {
	*probefw.Deps

	minAge       time.Duration
	evictEnabled bool

	firstSeen     state.FirstSeenLedger
	emitted       state.GaugeLedger[string]
	eventCooldown state.CooldownSet
}

// NewPodResizeWedgeGuardCheck constructs the pod-resize-wedge-guard check.
func NewPodResizeWedgeGuardCheck(d *probefw.Deps) probefw.Check {
	return &podResizeWedgeGuardCheck{
		Deps:         d,
		minAge:       envx.GetenvDuration("NODE_AUTOMATION_POD_RESIZE_MIN_AGE", podResizeDefaultMinAge),
		evictEnabled: envx.Gate("NODE_AUTOMATION_POD_RESIZE_EVICT_ENABLED", false),
	}
}

func (c *podResizeWedgeGuardCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := c.Now()
	c.eventCooldown.PruneExpired(now, podResizeEventCooldown)

	pods, err := c.AllPods(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}

	var rep probefw.SweepReport
	liveFirstSeen := map[string]bool{}
	var evictCandidates []*corev1.Pod
	seenEvict := map[string]bool{}

	for i := range pods {
		pod := &pods[i]
		if pod.DeletionTimestamp != nil ||
			pod.Status.Phase == corev1.PodSucceeded ||
			pod.Status.Phase == corev1.PodFailed {
			continue
		}
		for _, cond := range pod.Status.Conditions {
			reason, matched := classifyPodResizeCondition(cond)
			if !matched {
				continue
			}

			persisted := false
			if !cond.LastTransitionTime.IsZero() {
				persisted = now.Sub(cond.LastTransitionTime.Time) >= c.minAge
			} else {
				fsKey := pod.Namespace + "/" + pod.Name + "/" + string(pod.UID) + "/" + string(cond.Type) + "/" + reason
				liveFirstSeen[fsKey] = true
				persisted = probefw.Persisted(&c.firstSeen, fsKey, now, c.minAge, log)
			}
			if !persisted {
				continue
			}

			podKey := pod.Namespace + "/" + pod.Name
			tupleKey := podKey + "/" + reason
			rep.Emit(podResizeWedgedGauge, tupleKey,
				[]string{pod.Namespace, pod.Name, reason},
				fmt.Sprintf("%s (%s)", podKey, reason))

			cooldownKey := "podresize." + pod.Namespace + "." + pod.Name + "." + reason
			if !c.eventCooldown.CooledDown(cooldownKey, podResizeEventCooldown, now) {
				note := fmt.Sprintf("Pod %s stuck in resize (%s/%s): %s",
					podKey, cond.Type, cond.Reason, cond.Message)
				if err := kube.EmitWarningEvent(ctx, c.CS, kube.WarningEvent{
					Name:      kube.TruncatedEventName(cooldownKey, cooldownKey, now),
					Namespace: pod.Namespace,
					Regarding: corev1.ObjectReference{
						APIVersion: "v1",
						Kind:       "Pod",
						Namespace:  pod.Namespace,
						Name:       pod.Name,
						UID:        pod.UID,
					},
					Reason:            podResizeEventReason,
					Note:              note,
					ReportingInstance: c.Name,
					Now:               now,
				}); err != nil {
					log.Info("WARN: PodResizeWedged event create failed (RBAC?)",
						"pod", podKey, "error", err)
				} else {
					c.eventCooldown.Stamp(cooldownKey, now)
					log.Info("EVENT: PodResizeWedged", "pod", podKey, "reason", reason)
				}
			}

			if c.evictEnabled && cond.Type == corev1.PodResizePending &&
				cond.Reason == corev1.PodReasonDeferred && !seenEvict[podKey] {
				seenEvict[podKey] = true
				evictCandidates = append(evictCandidates, pod)
			}
		}
	}

	c.firstSeen.Prune(func(k string) bool { return liveFirstSeen[k] })

	if c.evictEnabled && len(evictCandidates) > 0 {
		c.evictDeferredPods(ctx, pods, evictCandidates, now)
	}

	return rep.Result(&c.emitted, podResizeWedgedGauge.DeleteLabelValues,
		"pod resize wedged: ", ", ")
}

func (c *podResizeWedgeGuardCheck) evictDeferredPods(
	ctx context.Context,
	allPods []corev1.Pod,
	candidates []*corev1.Pod,
	now time.Time,
) {
	log := logf.FromContext(ctx)
	readyByOwner := probefw.ReadyByOwner(allPods)

	eligible := make([]*corev1.Pod, 0, len(candidates))
	for _, pod := range candidates {
		if podResizeSystemNamespaces[pod.Namespace] {
			continue
		}
		if pod.Annotations["kubernetes.io/config.mirror"] != "" {
			continue
		}
		ctrl := metav1.GetControllerOf(pod)
		if ctrl == nil || ctrl.Kind == "DaemonSet" {
			continue
		}
		if probefw.ReadySiblings(readyByOwner, pod) < 1 {
			continue
		}
		eligible = append(eligible, pod)
	}

	slices.SortFunc(eligible, func(a, b *corev1.Pod) int {
		if c := cmp.Compare(a.Namespace, b.Namespace); c != 0 {
			return c
		}
		return cmp.Compare(a.Name, b.Name)
	})

	attempted := 0
	for _, pod := range eligible {
		if attempted >= podResizeMaxEvictsPerSweep {
			log.Info("SKIP rest: pod-resize eviction cap reached",
				"cap", podResizeMaxEvictsPerSweep)
			break
		}
		podKey := pod.Namespace + "/" + pod.Name
		ck := probefw.SelfHealKey(CheckNamePodResizeWedgeGuard, kube.PodControllerKey(pod))
		proceed, unverifiable := c.HealAllowed(ctx, log, &c.Heals, ck, podResizeEvictCooldown, now)
		if unverifiable {
			metrics.IncError(c.Name)
			break
		}
		if !proceed {
			continue
		}

		ctrl := metav1.GetControllerOf(pod)
		targetKey := pod.Namespace + "." + ctrl.Name
		if allowed, reason := heal.TryAcquireTarget(CheckNamePodResizeWedgeGuard, targetKey, now); !allowed {
			heal.RefundGrant(now)
			log.Info("DEFER: pod-resize target circuit open",
				"pod", podKey, "target", targetKey, "reason", reason)
			continue
		}

		evicted, refused, notFound, err := heal.EvictPodNotFound(ctx, c.CS, &c.Heals, ck, pod, now)
		switch {
		case err != nil:
			attempted++
			metrics.IncError(c.Name)
			log.Error(err, "pod-resize eviction failed", "pod", podKey)
		case refused:
			heal.RefundTarget(CheckNamePodResizeWedgeGuard, targetKey, now)
			heal.RefundGrant(now)
			if notFound {
				log.V(1).Info("DEFER: pod-resize target vanished before eviction", "pod", podKey)
			} else {
				log.Info("DEFER: pod-resize eviction refused (PDB/hold/quorum)", "pod", podKey)
			}
		case evicted:
			attempted++
			metrics.ControlPlanePodHealsTotal.WithLabelValues(CheckNamePodResizeWedgeGuard).Inc()
			log.Info("EVICT: wedged PodResizePending(Deferred) pod evicted for reschedule", "pod", podKey)
		}
	}
}

func classifyPodResizeCondition(cond corev1.PodCondition) (string, bool) {
	if cond.Status != corev1.ConditionTrue {
		return "", false
	}
	switch cond.Type {
	case corev1.PodResizePending:
		switch cond.Reason {
		case corev1.PodReasonDeferred:
			return podResizeReasonPendingDeferred, true
		case corev1.PodReasonInfeasible:
			return podResizeReasonPendingInfeasible, true
		default:
			return podResizeReasonPending, true
		}
	case corev1.PodResizeInProgress:
		switch cond.Reason {
		case corev1.PodReasonError:
			return podResizeReasonInProgressError, true
		default:
			return podResizeReasonInProgress, true
		}
	default:
		return "", false
	}
}
