// healwire.go — the boot-time wiring bridging platform/heal's
// per-target non-convergent breaker to the metrics counter and the
// Warning event emission. Lives in shared (not cmd/manager): shared
// may import metrics + platform while platform/heal — a depguard
// leaf — may import neither, so the hook bridges are the composition
// the leaf's hook points exist for. Moving it here keeps cmd/manager
// to flag parsing + manager/module wiring and makes the bridge
// unit-testable without re-executing the manager binary.
package shared

import (
	"context"
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
)

// eventReasonRemediationCircuitBreakerOpen is the Warning event
// reason stamped on the remediation target Node when its per-target
// heal circuit opens — one event per open episode (the breaker fires
// the hook once per transition).
const eventReasonRemediationCircuitBreakerOpen = "RemediationCircuitBreakerOpen"

// emitCircuitOpenEvent stamps the RemediationCircuitBreakerOpen
// Warning Event on the target Node — the events.k8s.io/v1 shape the
// health-check emitters use (Regarding+Action, deprecated corev1
// fields unset); the ClusterRole grants cluster-wide events create
// (the zone-starvation emitter's rule). Best-effort: a failure is
// logged and never escalates — the HealTargetCircuitBrokenTotal
// counter is the guaranteed signal.
func emitCircuitOpenEvent(cs kubernetes.Interface, module, target, reason string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now()
	ev := &eventsv1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s.%x", target, now.UnixNano()),
		},
		EventTime:           metav1.NewMicroTime(now),
		Reason:              eventReasonRemediationCircuitBreakerOpen,
		Note:                fmt.Sprintf("%s remediated this node repeatedly without convergence (%s) — further remediation is deferred until the window expires or the node reports healthy", module, reason),
		Type:                corev1.EventTypeWarning,
		ReportingController: "node-automation-controller",
		ReportingInstance:   module,
		Action:              eventReasonRemediationCircuitBreakerOpen,
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Node",
			Name:       target,
		},
	}
	// events.k8s.io/v1 Event is a NAMESPACED resource — NamespaceAll
	// would POST to the cluster-scoped collection path and the create
	// is rejected. The kubelet convention for node-scoped events is
	// the "default" namespace; the ClusterRole already grants events
	// create cluster-wide.
	if _, err := cs.EventsV1().Events("default").
		Create(ctx, ev, metav1.CreateOptions{}); err != nil {
		ctrl.Log.Error(err, "RemediationCircuitBreakerOpen event create failed",
			"module", module, "node", target)
		return
	}
	ctrl.Log.Info("EVENT: RemediationCircuitBreakerOpen — remediation deferred",
		"module", module, "node", target, "reason", reason)
}

// healTargetLedger is the bounded emitted-tuples ledger behind
// HealTargetCircuitBrokenTotal{module,target}: the open hook records
// every tuple it Inc'd and the breaker's forget hook (the expiry GC
// / healthy reset dropping the target's history — see
// heal.SetTargetCircuitForgetHook) retires exactly the recorded
// tuples, so a series lives no longer than the breaker's own state
// for that target instead of the process lifetime (a counter Inc is
// never undone by its own code path — the ledger is what lets the
// forget path find and delete it). Mutex-guarded: the hooks fire from
// several module sweep goroutines.
type healTargetLedger struct {
	mu      sync.Mutex
	emitted map[[2]string]struct{}
}

func (l *healTargetLedger) emit(module, target string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.emitted == nil {
		l.emitted = map[[2]string]struct{}{}
	}
	l.emitted[[2]string{module, target}] = struct{}{}
}

// forget deletes the series for a forgotten target — only when this
// ledger emitted it: the breaker forgets targets whose circuits never
// opened too (grants under the limit, then expired), and their series
// do not exist. Deleting a tuple that was never WithLabelValues'd is
// harmless, but gating on the ledger keeps `delete` doubling as the
// exists-probe honest for tests.
func (l *healTargetLedger) forget(module, target string,
	del func(labelValues ...string) bool) {
	l.mu.Lock()
	key := [2]string{module, target}
	_, ok := l.emitted[key]
	delete(l.emitted, key)
	l.mu.Unlock()
	if ok {
		del(module, target)
	}
}

// WireTargetBreaker installs the process-global per-target
// non-convergent breaker and its hook bridges — the boot-time wiring
// that keeps platform/heal a depguard leaf (the package cannot import
// internal/metrics or hold a clientset). The open transition
// increments HealTargetCircuitBrokenTotal, records the tuple in the
// ledger and stamps the RemediationCircuitBreakerOpen Warning event
// on the target Node (best-effort — see emitCircuitOpenEvent); the
// forget transition prunes exactly the recorded tuples, so a target
// the breaker no longer tracks cannot pin its series forever.
func WireTargetBreaker(cs kubernetes.Interface) {
	var ledger healTargetLedger
	heal.ConfigureTargetBreaker(heal.TargetBreakerLimit, heal.TargetBreakerWindow)
	heal.SetTargetCircuitOpenHook(func(module, target, reason string) {
		ledger.emit(module, target)
		metrics.HealTargetCircuitBrokenTotal.WithLabelValues(module, target).Inc()
		emitCircuitOpenEvent(cs, module, target, reason)
	})
	heal.SetTargetCircuitForgetHook(func(module, target string) {
		ledger.forget(module, target,
			metrics.HealTargetCircuitBrokenTotal.DeleteLabelValues)
	})
}
