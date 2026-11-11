// linkerd_sidecar_oom_guard.go — the linkerd-sidecar-oom-guard check:
// a linkerd-proxy sidecar (injected as an initContainer with
// restartPolicy: Always under nativeSidecar) killed by the kernel
// OOM killer under its memory limit dies WITHOUT restarting the
// pod's app containers — the sidecar restarts alone, but every TCP/
// gRPC stream it held is severed while the pod keeps reporting
// Running/Ready (the invisible-disconnect class this guard flags).
// Both InitContainerStatuses (nativeSidecar) and ContainerStatuses
// (classic sidecar) are scanned for a linkerd-proxy OOMKilled inside
// the lookback window; each flagged pod emits the
// node_automation_linkerd_sidecar_oom gauge plus a deduped
// LinkerdSidecarOOMKilled Warning Event on the pod.
package linkerd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// linkerdSidecarOOMCheck is the linkerd-proxy OOMKill watchdog.
type linkerdSidecarOOMCheck struct {
	*probefw.Deps

	// emitted is the emitted-gauge ledger — a tuple that stops
	// being reported gets DeleteLabelValues'd rather than leaking a
	// stale 1 (zero value usable; the serial sweep needs no lock).
	emitted state.GaugeLedger[string]
	// evented dedupes the LinkerdSidecarOOMKilled K8s Event per pod
	// per termination count — a new OOM kill (restart bump) re-fires
	// while a repeating status is reported once.
	evented state.SeenSet

	// linkerd-init-deadlock (linkerdInitSidecarDeadlock): since tracks the
	// Init:Error / Init:CrashLoopBackOff signature per pod (the 5m
	// persistence window, pruned when the pod leaves the state so a
	// later flap re-arms); deadlockEmitted reconciles the deadlock
	// gauge; deadlockEvented dedupes the Warning Event per pod per
	// offending init's restart count.
	deadlockSince   state.FirstSeenLedger
	deadlockEmitted state.GaugeLedger[string]
	deadlockEvented state.SeenSet
}

// NewLinkerdSidecarOOMGuardCheck builds the linkerd-sidecar-oom-guard
// check — its only state is the emitted-gauge ledger + event dedup.
func NewLinkerdSidecarOOMGuardCheck(d *probefw.Deps) probefw.Check {
	return &linkerdSidecarOOMCheck{Deps: d}
}

const (
	CheckNameLinkerdSidecarOOMGuard = "linkerd-sidecar-oom-guard"

	// linkerdProxyContainer is the injected proxy's container name.
	linkerdProxyContainer = "linkerd-proxy"
	// linkerdOOMWindow bounds how fresh a termination must read —
	// an OOM kill older than the window is history, not a live
	// signature (the proxy has long since restarted).
	linkerdOOMWindow = 30 * time.Minute
	// linkerdOOMEventReason is the Warning Event reason stamped on
	// the pod — the byte-stable reason the alert runbook references.
	linkerdOOMEventReason = "LinkerdSidecarOOMKilled"

	// linkerd-init-deadlock — linkerdInitSidecarDeadlock knobs.
	// linkerdInitContainer is the injected mesh-setup init container
	// (runs BEFORE linkerd-proxy is injected into the init chain).
	linkerdInitContainer = "linkerd-init"
	// linkerdInitDeadlockMinAge is how long the Init:Error /
	// Init:CrashLoopBackOff signature must persist before a pod
	// counts as deadlocked — an init that retries transiently
	// settles inside it.
	linkerdInitDeadlockMinAge = 5 * time.Minute
	// linkerdInitDeadlockEventReason is the Warning Event reason
	// stamped on the deadlocked pod — byte-stable for the runbook.
	linkerdInitDeadlockEventReason = "LinkerdInitSidecarOrderDeadlock"
	// linkerdInitDeadlockRefused is the log line an app init container
	// prints when it dials the sidecar's inbound proxy BEFORE
	// linkerd-proxy (an always-running nativeSidecar ordered after
	// it) has started — the order deadlock's smoking gun.
	linkerdInitDeadlockRefused = "127.0.0.1:4140: connect: connection refused"
	// linkerdInitDeadlockRestarts is the restart-count arm of the
	// app-init crash predicate — a looping app init before the proxy.
	linkerdInitDeadlockRestarts = int32(2)
)

// The init backoff waiting reasons that read "stuck" — kubelet's
// Init:<reason> spelling on the init container's waiting state.
const (
	initWaitReasonError     = "Init:Error"
	initWaitReasonCrashLoop = "Init:CrashLoopBackOff"
)

var (
	// linkerd-sidecar-oom-guard — a pod whose linkerd-proxy was
	// OOMKilled inside the window.
	linkerdSidecarOOMGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_linkerd_sidecar_oom",
		Help: "1 while a pod's linkerd-proxy container shows an OOMKilled termination inside the 30m window.",
	}, []string{"namespace", "pod"})
	// linkerd-init-deadlock — a pod stuck Pending in Init:Error/Init:CrashLoopBackOff
	// past 5m whose completed linkerd-init proves the mesh setup ran
	// while an app init ordered before linkerd-proxy still crashes.
	linkerdInitDeadlockGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_linkerd_init_deadlock_pods",
		Help: "1 while a pod is stuck Pending with Init:Error/Init:CrashLoopBackOff past 5m, linkerd-init completed (exit 0), and an app initContainer ordered before linkerd-proxy crash-loops (restarts or 127.0.0.1:4140 connect: connection refused).",
	}, []string{"namespace", "pod"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		linkerdSidecarOOMGauge, linkerdInitDeadlockGauge)
}

// checkLinkerdSidecarOOM scans every pod for a linkerd-proxy
// OOMKilled termination inside the window, in BOTH status maps —
// nativeSidecar pods report the proxy under initContainerStatuses,
// classic sidecars under containerStatuses; scanning only one shape
// blinds the check to the other half of the fleet.
func (p *linkerdSidecarOOMCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()
	pods, err := p.AllPods(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}
	var rep probefw.SweepReport
	live := map[string]bool{}
	for i := range pods {
		pod := &pods[i]
		if pod.DeletionTimestamp != nil {
			continue
		}
		hits, found := linkerdProxyOOMKills(pod, now)
		if !found {
			continue
		}
		key := pod.Namespace + "/" + pod.Name
		live[key] = true
		rep.Emit(linkerdSidecarOOMGauge, key,
			[]string{pod.Namespace, pod.Name},
			fmt.Sprintf("%s (restarts=%d)", key, hits))
		if p.evented.Add(fmt.Sprintf("%s/%d", key, hits)) {
			p.emitOOMEvent(ctx, log, pod, hits)
		}
	}
	p.evented.Prune(func(k string) bool {
		for key := range live {
			if len(k) > len(key) && k[:len(key)] == key && k[len(key)] == '/' {
				return true
			}
		}
		return false
	})
	res := rep.Result(&p.emitted, linkerdSidecarOOMGauge.DeleteLabelValues,
		"linkerd-proxy OOMKilled inside 30m: ", ", ")

	// linkerd-init-deadlock — the init-order deadlock detector rides the same pod
	// census as its own gauge/window/event (the oom emitted ledger
	// keys into a different vec, so it carries its own report tail).
	res2 := p.scanInitDeadlock(ctx, log, pods, now)
	if res2.Infra != nil && res.Infra == nil {
		res.Infra = res2.Infra
	}
	if !res2.Pass {
		if res.Why != "" {
			res.Why += " | "
		}
		res.Why += res2.Why
		res.Pass = false
	}
	return res
}

// ---------------------------------------------------------------------------
// linkerd-init-deadlock — linkerdInitSidecarDeadlock
// ---------------------------------------------------------------------------

// scanInitDeadlock sweeps the pod census for the init-order deadlock:
// a pod stuck Pending with an init container reading Init:Error /
// Init:CrashLoopBackOff past the 5m window, where linkerd-init has
// ALREADY completed (Terminated.ExitCode == 0 — the mesh setup ran
// fine) and an app initContainer ordered before linkerd-proxy is
// crashing (RestartCount >= linkerdInitDeadlockRestarts, or its log
// tail carries the :4140 connection-refused dial against the proxy
// that has not started yet). Each flagged pod emits the deadlock
// gauge plus a deduped Warning Event; a pod that leaves the state
// prunes both (the gauge ledger reconciles the series away, the
// first-seen window re-arms on a later flap).
func (p *linkerdSidecarOOMCheck) scanInitDeadlock(
	ctx context.Context, log logr.Logger, pods []corev1.Pod,
	now time.Time) probefw.Result {

	var rep probefw.SweepReport
	live := map[string]bool{}
	// shape tracks every pod currently matching the deadlock shape —
	// the first-seen ledger prunes against THIS set (set at
	// signature-detection time), not against live: the 5m window must
	// be allowed to mature across sweeps, and pruning against the
	// fired set would reset it every sweep (dead detector).
	shape := map[string]bool{}
	for i := range pods {
		pod := &pods[i]
		if pod.DeletionTimestamp != nil {
			continue
		}
		offender, ok := linkerdInitDeadlockShape(pod)
		if !ok {
			continue
		}
		key := pod.Namespace + "/" + pod.Name
		shape[key] = true
		if !probefw.Persisted(&p.deadlockSince, key, now,
			linkerdInitDeadlockMinAge, logr.Discard()) {
			continue // inside the 5m window — a retrier, not a wedge
		}
		// Two arming channels: the restart-count crash loop, or the
		// offender's log tail dialing the proxy that has not started
		// (a first crash whose backoff has not bumped the counter
		// yet). A log read failure is inconclusive — not a flag.
		arm := offender.RestartCount >= linkerdInitDeadlockRestarts
		if !arm && offender.Name != "" {
			matched, err := kube.ReadPodLogTail(ctx, p.CS, pod,
				kube.PodLogOpts{
					TailLines: probefw.DefaultTailLines,
					MaxBytes:  probefw.LogMaxBytes,
					Timeout:   probefw.LogTimeout,
				}, func(line string) bool {
					return strings.Contains(line, linkerdInitDeadlockRefused)
				})
			if err != nil || !matched {
				continue
			}
		}
		live[key] = true
		rep.Emit(linkerdInitDeadlockGauge, key,
			[]string{pod.Namespace, pod.Name},
			fmt.Sprintf("%s init-deadlock (offender=%s restarts=%d)",
				key, offender.Name, offender.RestartCount))
		if p.deadlockEvented.Add(
			fmt.Sprintf("%s/%d", key, offender.RestartCount)) {
			p.emitDeadlockEvent(ctx, log, pod, offender.Name,
				int(offender.RestartCount))
		}
	}
	p.deadlockSince.Prune(func(k string) bool { _, ok := shape[k]; return ok })
	p.deadlockEvented.Prune(func(k string) bool {
		for key := range live {
			if len(k) > len(key) && k[:len(key)] == key && k[len(key)] == '/' {
				return true
			}
		}
		return false
	})
	return rep.Result(&p.deadlockEmitted,
		linkerdInitDeadlockGauge.DeleteLabelValues,
		"linkerd init-order deadlocked pods >=5m: ", ", ")
}

// linkerdInitDeadlockShape is the shape predicate: the pod must be
// Pending with an init waiting reason Init:Error /
// Init:CrashLoopBackOff, linkerd-init terminated exit 0, and a
// linkerd-proxy init container ordered AFTER the app inits. It
// returns the worst-crashing app init ordered before the proxy (the
// restart arm and the log arm's target) and whether the stuck shape
// holds. Pure — the unit tests cover each leg.
func linkerdInitDeadlockShape(pod *corev1.Pod) (corev1.ContainerStatus, bool) {
	var noStatus corev1.ContainerStatus
	if pod.Status.Phase != corev1.PodPending {
		return noStatus, false
	}
	inits := pod.Status.InitContainerStatuses
	proxyIdx, initIdx, completedInit := -1, -1, false
	for i, cs := range inits {
		switch cs.Name {
		case linkerdInitContainer:
			if t := cs.State.Terminated; t != nil && t.ExitCode == 0 {
				completedInit = true
			}
			initIdx = i
		case linkerdProxyContainer:
			proxyIdx = i
		}
	}
	if !completedInit || proxyIdx < 0 || initIdx > proxyIdx {
		// initIdx > proxyIdx: linkerd-init ordered after the proxy —
		// not the injected order this detector's diagnosis assumes.
		return noStatus, false
	}
	stuck := false
	for i, cs := range inits {
		// The deadlock is an ordering one: the dialing init must sit
		// BEFORE the proxy. A stuck init after the proxy (e.g. the
		// proxy itself crash-looping) is a mesh failure, not this
		// shape.
		if i < proxyIdx && cs.State.Waiting != nil &&
			(cs.State.Waiting.Reason == initWaitReasonError ||
				cs.State.Waiting.Reason == initWaitReasonCrashLoop) {
			stuck = true
			break
		}
	}
	if !stuck {
		return noStatus, false
	}
	var offender corev1.ContainerStatus
	for _, cs := range inits[:proxyIdx] {
		if cs.Name == linkerdInitContainer {
			continue
		}
		if cs.State.Terminated != nil && cs.State.Terminated.ExitCode == 0 {
			// Completed successfully — not the crash-looping offender;
			// naming it in the event would misdiagnose the wedge.
			continue
		}
		if cs.RestartCount >= offender.RestartCount {
			offender = cs
		}
	}
	if offender.Name == "" {
		// No pre-proxy candidate (e.g. the only stuck init is the
		// proxy itself) — not the app-init-before-proxy shape.
		return noStatus, false
	}
	return offender, true
}

// emitDeadlockEvent stamps the LinkerdInitSidecarOrderDeadlock
// Warning Event on the pod — the events.k8s.io/v1 shape
// emitOOMEvent uses. Best-effort: a Forbidden is logged, never
// escalated — the gauge stays the signal.
func (p *linkerdSidecarOOMCheck) emitDeadlockEvent(
	ctx context.Context, log logr.Logger, pod *corev1.Pod,
	initName string, restarts int) {

	now := p.Now()
	ev := &eventsv1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s.%x", pod.Name, now.UnixNano()),
			Namespace: pod.Namespace,
		},
		EventTime:           metav1.NewMicroTime(now),
		Reason:              linkerdInitDeadlockEventReason,
		Note:                fmt.Sprintf("init container %s crash-loops (%d restarts) while dialing 127.0.0.1:4140 before the linkerd-proxy nativeSidecar starts — linkerd-init already completed; reorder the app initContainers after linkerd-proxy or drop the proxy dial", initName, restarts),
		Type:                corev1.EventTypeWarning,
		ReportingController: "node-automation-controller",
		ReportingInstance:   p.Name,
		Action:              linkerdInitDeadlockEventReason,
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Pod",
			Namespace:  pod.Namespace,
			Name:       pod.Name,
		},
	}
	if _, err := p.CS.EventsV1().Events(pod.Namespace).
		Create(ctx, ev, metav1.CreateOptions{}); err != nil {
		log.Info("WARN: LinkerdInitSidecarOrderDeadlock event create failed (RBAC?)",
			"pod", pod.Namespace+"/"+pod.Name, "error", err)
		return
	}
	log.Info("EVENT: LinkerdInitSidecarOrderDeadlock — app init dials the not-yet-started proxy",
		"pod", pod.Namespace+"/"+pod.Name, "init", initName, "restarts", restarts)
}

// linkerdProxyOOMKills reports whether the pod's linkerd-proxy shows
// an OOMKilled termination inside the window — current or last
// terminated state — and returns the proxy's restart count for the
// event dedup key (a fresh kill bumps it, re-arming the event).
func linkerdProxyOOMKills(pod *corev1.Pod, now time.Time) (int, bool) {
	statuses := append([]corev1.ContainerStatus{},
		pod.Status.InitContainerStatuses...)
	statuses = append(statuses, pod.Status.ContainerStatuses...)
	for _, cs := range statuses {
		if cs.Name != linkerdProxyContainer {
			continue
		}
		oomkilled := func(t *corev1.ContainerStateTerminated) bool {
			return t != nil && t.Reason == "OOMKilled" &&
				now.Sub(t.FinishedAt.Time) <= linkerdOOMWindow
		}
		if oomkilled(cs.State.Terminated) ||
			oomkilled(cs.LastTerminationState.Terminated) {
			return int(cs.RestartCount), true
		}
		return 0, false
	}
	return 0, false
}

// emitOOMEvent stamps the LinkerdSidecarOOMKilled Warning Event on
// the pod — the events.k8s.io/v1 shape the other check emitters use
// (Regarding+Action, deprecated corev1 fields unset). Best-effort: a
// Forbidden is logged, never escalated — the gauge stays the signal.
func (p *linkerdSidecarOOMCheck) emitOOMEvent(
	ctx context.Context, log logr.Logger, pod *corev1.Pod, restarts int) {

	now := p.Now()
	ev := &eventsv1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s.%x", pod.Name, now.UnixNano()),
			Namespace: pod.Namespace,
		},
		EventTime:           metav1.NewMicroTime(now),
		Reason:              linkerdOOMEventReason,
		Note:                fmt.Sprintf("linkerd-proxy container OOMKilled inside the last %s — in-flight TCP/gRPC streams severed while the pod stayed Ready (restarts=%d)", linkerdOOMWindow, restarts),
		Type:                corev1.EventTypeWarning,
		ReportingController: "node-automation-controller",
		ReportingInstance:   p.Name,
		Action:              linkerdOOMEventReason,
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Pod",
			Namespace:  pod.Namespace,
			Name:       pod.Name,
		},
	}
	if _, err := p.CS.EventsV1().Events(pod.Namespace).
		Create(ctx, ev, metav1.CreateOptions{}); err != nil {
		log.Info("WARN: LinkerdSidecarOOMKilled event create failed (RBAC?)",
			"pod", pod.Namespace+"/"+pod.Name, "error", err)
		return
	}
	log.Info("EVENT: LinkerdSidecarOOMKilled — sidecar OOM severed live streams",
		"pod", pod.Namespace+"/"+pod.Name, "restarts", restarts)
}
