// init_container_wedge_guard.go — health check "init-container-wedge-guard":
// detects non-terminal Pods stuck in the init phase whose non-native
// initContainer (RestartPolicy == nil || *RestartPolicy != Always) has been
// wedged for >= NODE_AUTOMATION_INIT_WEDGE_MIN_AGE (default 30m), either:
//   - waiting in CrashLoopBackOff, ImagePullBackOff, ErrImagePull,
//     CreateContainerConfigError, CreateContainerError, PodInitializing, or
//     ContainerCreating; or
//   - running continuously for >= minAge while blocking main containers from
//     starting (unless opted out via passiontech.dev/ignore-init-wedge: "true").
//
// K8s 1.29+ native sidecars (initContainers with restartPolicy: Always) are
// explicitly excluded so long-running healthy sidecars are never flagged.
// Read-only (zero mutation); emits node_automation_init_container_wedged and
// capped, cooldown-deduped Warning Events (InitContainerWedged).
package watchdogs

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
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

const (
	// CheckNameInitContainerWedgeGuard is the registry check name for init-container-wedge-guard.
	CheckNameInitContainerWedgeGuard = "init-container-wedge-guard"

	initWedgeDefaultMinAge     = 30 * time.Minute
	initWedgeEventCooldown     = 30 * time.Minute
	initWedgeEventReason       = "InitContainerWedged"
	initWedgeMaxEventsPerSweep = 20
	initWedgeIgnoreAnnotation  = "passiontech.dev/ignore-init-wedge"

	initWedgeReasonCrashLoop    = "init_crash_loop"
	initWedgeReasonImagePull    = "init_image_pull"
	initWedgeReasonCreateError  = "init_create_error"
	initWedgeReasonInitializing = "init_initializing_stuck"
	initWedgeReasonLongRunning  = "init_long_running"
)

var initWedgeWedgedGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_init_container_wedged",
	Help: "1 while a non-terminal Pod has a non-native initContainer wedged past NODE_AUTOMATION_INIT_WEDGE_MIN_AGE.",
}, []string{"namespace", "pod", "init_container", "reason"})

func init() {
	ctrlmetrics.Registry.MustRegister(initWedgeWedgedGauge)
}

var initWedgeWaitingReasons = map[string]string{
	"CrashLoopBackOff":           initWedgeReasonCrashLoop,
	"ImagePullBackOff":           initWedgeReasonImagePull,
	"ErrImagePull":               initWedgeReasonImagePull,
	"CreateContainerConfigError": initWedgeReasonCreateError,
	"CreateContainerError":       initWedgeReasonCreateError,
	"PodInitializing":            initWedgeReasonInitializing,
	"ContainerCreating":          initWedgeReasonInitializing,
}

type initWedgeGuardCheck struct {
	*probefw.Deps

	minAge        time.Duration
	emitted       state.GaugeLedger[string]
	eventCooldown state.CooldownSet
}

// NewInitContainerWedgeGuardCheck constructs the init-container-wedge-guard check.
func NewInitContainerWedgeGuardCheck(d *probefw.Deps) probefw.Check {
	return &initWedgeGuardCheck{
		Deps:   d,
		minAge: envx.GetenvDuration("NODE_AUTOMATION_INIT_WEDGE_MIN_AGE", initWedgeDefaultMinAge),
	}
}

type initWedgeFinding struct {
	pod           *corev1.Pod
	initContainer string
	reason        string
	detail        string
}

func (c *initWedgeGuardCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := c.Now()
	c.eventCooldown.PruneExpired(now, initWedgeEventCooldown)

	pods, err := c.AllPods(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}

	var findings []initWedgeFinding
	var rep probefw.SweepReport

	for i := range pods {
		pod := &pods[i]
		found := initWedgeClassifyPod(pod, now, c.minAge)
		for _, f := range found {
			tupleKey := f.pod.Namespace + "/" + f.pod.Name + "/" + f.initContainer + "/" + f.reason
			rep.Emit(initWedgeWedgedGauge, tupleKey,
				[]string{f.pod.Namespace, f.pod.Name, f.initContainer, f.reason},
				fmt.Sprintf("%s/%s (%s: %s)", f.pod.Namespace, f.pod.Name, f.initContainer, f.reason))
			findings = append(findings, f)
		}
	}

	slices.SortFunc(findings, func(a, b initWedgeFinding) int {
		if x := cmp.Compare(a.pod.Namespace, b.pod.Namespace); x != 0 {
			return x
		}
		if x := cmp.Compare(a.pod.Name, b.pod.Name); x != 0 {
			return x
		}
		return cmp.Compare(a.initContainer, b.initContainer)
	})

	eventsEmitted := 0
	for _, f := range findings {
		if eventsEmitted >= initWedgeMaxEventsPerSweep {
			log.Info("SKIP rest: init-container-wedge-guard event cap reached",
				"cap", initWedgeMaxEventsPerSweep)
			break
		}
		if c.initWedgeEmitEvent(ctx, log, now, f) {
			eventsEmitted++
		}
	}

	return rep.Result(&c.emitted, initWedgeWedgedGauge.DeleteLabelValues,
		"init container wedged: ", ", ")
}

func (c *initWedgeGuardCheck) initWedgeEmitEvent(ctx context.Context, log logr.Logger, now time.Time, f initWedgeFinding) bool {
	podKey := f.pod.Namespace + "/" + f.pod.Name
	cooldownKey := "initwedge." + f.pod.Namespace + "." + f.pod.Name + "." + f.initContainer + "." + f.reason
	if c.eventCooldown.CooledDown(cooldownKey, initWedgeEventCooldown, now) {
		return false
	}
	note := fmt.Sprintf("Pod %s initContainer %q wedged (%s): %s",
		podKey, f.initContainer, f.reason, f.detail)
	if err := kube.EmitWarningEvent(ctx, c.CS, kube.WarningEvent{
		Name:      kube.TruncatedEventName(cooldownKey, cooldownKey, now),
		Namespace: f.pod.Namespace,
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Pod",
			Namespace:  f.pod.Namespace,
			Name:       f.pod.Name,
			UID:        f.pod.UID,
		},
		Reason:            initWedgeEventReason,
		Note:              note,
		ReportingInstance: cmp.Or(c.Name, CheckNameInitContainerWedgeGuard),
		Now:               now,
	}); err != nil {
		log.Info("WARN: InitContainerWedged event create failed (RBAC?)",
			"pod", podKey, "initContainer", f.initContainer, "error", err)
		return false
	}
	c.eventCooldown.Stamp(cooldownKey, now)
	log.Info("EVENT: InitContainerWedged", "pod", podKey,
		"initContainer", f.initContainer, "reason", f.reason)
	return true
}

func initWedgeClassifyPod(pod *corev1.Pod, now time.Time, minAge time.Duration) []initWedgeFinding {
	if pod.DeletionTimestamp != nil ||
		pod.Status.Phase == corev1.PodSucceeded ||
		pod.Status.Phase == corev1.PodFailed {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(pod.Annotations[initWedgeIgnoreAnnotation]), "true") {
		return nil
	}
	if !initWedgePodInInitPhase(pod) {
		return nil
	}

	nativeSidecars := make(map[string]bool, len(pod.Spec.InitContainers))
	for _, ic := range pod.Spec.InitContainers {
		if initWedgeIsNativeSidecar(ic) {
			nativeSidecars[ic.Name] = true
		}
	}

	regularRunning := initWedgeAnyRegularRunning(pod)
	podSince := initWedgePodSince(pod)

	var out []initWedgeFinding
	for _, st := range pod.Status.InitContainerStatuses {
		if nativeSidecars[st.Name] {
			continue
		}
		if reason, detail, ok := initWedgeClassifyStatus(st, podSince, regularRunning, now, minAge); ok {
			out = append(out, initWedgeFinding{
				pod:           pod,
				initContainer: st.Name,
				reason:        reason,
				detail:        detail,
			})
		}
	}
	return out
}

func initWedgeClassifyStatus(st corev1.ContainerStatus, podSince time.Time, regularRunning bool, now time.Time, minAge time.Duration) (reason, detail string, ok bool) {
	if w := st.State.Waiting; w != nil {
		cat, matched := initWedgeWaitingReasons[w.Reason]
		if !matched {
			return "", "", false
		}
		if !kube.AgeAtLeast(podSince, now, minAge) {
			return "", "", false
		}
		msg := w.Message
		if msg == "" {
			msg = w.Reason
		}
		return cat, fmt.Sprintf("waiting in %s for >=%s (%s)", w.Reason, minAge, msg), true
	}
	if r := st.State.Running; r != nil && !regularRunning {
		since := r.StartedAt.Time
		if since.IsZero() {
			since = podSince
		}
		if !kube.AgeAtLeast(since, now, minAge) {
			return "", "", false
		}
		return initWedgeReasonLongRunning,
			fmt.Sprintf("running continuously for >=%s blocking main containers", minAge), true
	}
	return "", "", false
}

func initWedgePodInInitPhase(pod *corev1.Pod) bool {
	if pod.Status.Phase == corev1.PodPending {
		return true
	}
	for _, cond := range pod.Status.Conditions {
		if cond.Type == corev1.PodInitialized && cond.Status == corev1.ConditionFalse {
			return true
		}
	}
	return false
}

func initWedgeIsNativeSidecar(c corev1.Container) bool {
	return c.RestartPolicy != nil && *c.RestartPolicy == corev1.ContainerRestartPolicyAlways
}

func initWedgeAnyRegularRunning(pod *corev1.Pod) bool {
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.State.Running != nil {
			return true
		}
	}
	return false
}

func initWedgePodSince(pod *corev1.Pod) time.Time {
	for _, cond := range pod.Status.Conditions {
		if cond.Type == corev1.PodInitialized && cond.Status == corev1.ConditionFalse {
			if !cond.LastTransitionTime.IsZero() {
				return cond.LastTransitionTime.Time
			}
			break
		}
	}
	if pod.Status.StartTime != nil && !pod.Status.StartTime.IsZero() {
		return pod.Status.StartTime.Time
	}
	return pod.CreationTimestamp.Time
}
