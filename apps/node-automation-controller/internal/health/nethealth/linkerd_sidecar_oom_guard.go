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
package nethealth

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
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
)

var (
	// linkerd-sidecar-oom-guard — a pod whose linkerd-proxy was
	// OOMKilled inside the window.
	linkerdSidecarOOMGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_linkerd_sidecar_oom",
		Help: "1 while a pod's linkerd-proxy container shows an OOMKilled termination inside the 30m window.",
	}, []string{"namespace", "pod"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		linkerdSidecarOOMGauge)
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
	return rep.Result(&p.emitted, linkerdSidecarOOMGauge.DeleteLabelValues,
		"linkerd-proxy OOMKilled inside 30m: ", ", ")
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
