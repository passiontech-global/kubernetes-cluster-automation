package shared

import (
	"errors"
	"strings"
	"testing"
	"time"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
)

// emitCircuitOpenEvent stamps the RemediationCircuitBreakerOpen
// Warning Event on the target Node — the events.k8s.io/v1 shape
// (Regarding+Action, deprecated corev1 fields unset) kubelet-style
// node events use. The fake clientset serves the create; a create
// failure is best-effort and only logs.
func TestEmitCircuitOpenEvent(t *testing.T) {
	cs := fake.NewSimpleClientset()
	emitCircuitOpenEvent(cs, "coredns-stale-watchdog", "worker-7",
		"3 heals in 30m")

	events, err := cs.EventsV1().Events("default").List(t.Context(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(events.Items) != 1 {
		t.Fatalf("events created = %d, want 1", len(events.Items))
	}
	ev := events.Items[0]
	if ev.Reason != eventReasonRemediationCircuitBreakerOpen ||
		ev.Type != corev1.EventTypeWarning {
		t.Fatalf("event reason/type = %q/%q", ev.Reason, ev.Type)
	}
	if ev.Regarding.Name != "worker-7" || ev.Regarding.Kind != "Node" {
		t.Fatalf("event regarding = %+v, want Node/worker-7", ev.Regarding)
	}
	if ev.ReportingInstance != "coredns-stale-watchdog" ||
		ev.ReportingController != "node-automation-controller" {
		t.Fatalf("reporting fields = %q/%q",
			ev.ReportingInstance, ev.ReportingController)
	}
	if !strings.Contains(ev.Note, "3 heals in 30m") {
		t.Fatalf("event note missing the reason: %q", ev.Note)
	}
}

// A failed event create is best-effort — logged, never escalated
// (the HealTargetCircuitBrokenTotal counter is the guaranteed
// signal). The reactor forces the create error; the call must not
// panic or surface it.
func TestEmitCircuitOpenEventCreateFailure(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("create", "events",
		func(action ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("events write denied")
		})
	emitCircuitOpenEvent(cs, "module-x", "worker-9", "why")
}

// The target-breaker wiring keeps HealTargetCircuitBrokenTotal's
// cardinality bounded: the open transition records the tuple in the
// ledger and emits the series, and every breaker forget (the healthy
// reset here, the expiry GC in the breaker tests) prunes exactly the
// recorded series. A forget for a target that never opened must not
// conjure one.
func TestWireTargetBreakerLedger(t *testing.T) {
	cs := fake.NewSimpleClientset()
	WireTargetBreaker(cs)
	t.Cleanup(func() { heal.ConfigureTargetBreaker(0, 0) })
	t.Cleanup(func() {
		metrics.HealTargetCircuitBrokenTotal.DeleteLabelValues("kubelet-liveness-reaper", "n1")
	})

	now := time.Unix(1_700_000_000, 0)
	// Trip the circuit: the open transition Inc'd the series once.
	for range heal.TargetBreakerLimit {
		if ok, _ := heal.TryAcquireTarget("kubelet-liveness-reaper", "n1", now); !ok {
			t.Fatal("grant denied inside the cap")
		}
	}
	if ok, reason := heal.TryAcquireTarget("kubelet-liveness-reaper", "n1", now); ok ||
		reason != heal.ReasonTargetNonConvergentCircuitOpen {
		t.Fatalf("4th grant = (%v,%q), want (false,%q)", ok, reason,
			heal.ReasonTargetNonConvergentCircuitOpen)
	}
	if got := promtest.ToFloat64(
		metrics.HealTargetCircuitBrokenTotal.
			WithLabelValues("kubelet-liveness-reaper", "n1")); got != 1 {
		t.Fatalf("open-episode series = %v, want 1", got)
	}

	// The recovery path converges the episode: the forget prunes the
	// series (the DeleteLabelValues call doubles as the exists-probe).
	heal.RecordTargetHealthy("kubelet-liveness-reaper", "n1")
	if metrics.HealTargetCircuitBrokenTotal.
		DeleteLabelValues("kubelet-liveness-reaper", "n1") {
		t.Fatal("healthy reset left the emitted series alive — forget must prune it")
	}
	// A forget with no history AND no open never emitted a series —
	// the prune must not conjure one.
	heal.RecordTargetHealthy("kubelet-liveness-reaper", "never-opened")
	if metrics.HealTargetCircuitBrokenTotal.
		DeleteLabelValues("kubelet-liveness-reaper", "never-opened") {
		t.Fatal("forget without an open emitted a series")
	}

	// A fresh episode re-emits, and the expiry GC prunes it again:
	// past the window the next consult GCs the fully-expired history
	// (and grants — fresh episode), firing the forget hook once.
	for range heal.TargetBreakerLimit + 1 {
		heal.TryAcquireTarget("kubelet-liveness-reaper", "n1", now)
	}
	if got := promtest.ToFloat64(
		metrics.HealTargetCircuitBrokenTotal.
			WithLabelValues("kubelet-liveness-reaper", "n1")); got != 1 {
		t.Fatalf("re-opened episode series = %v, want 1", got)
	}
	_, _ = heal.TryAcquireTarget("kubelet-liveness-reaper", "n1",
		now.Add(heal.TargetBreakerWindow+time.Second))
	if metrics.HealTargetCircuitBrokenTotal.
		DeleteLabelValues("kubelet-liveness-reaper", "n1") {
		t.Fatal("expiry GC left the emitted series alive — forget must prune it")
	}
}
