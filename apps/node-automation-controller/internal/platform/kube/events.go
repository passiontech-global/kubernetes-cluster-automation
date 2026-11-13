// events.go — the corev1.Event helpers shared by the preemption-cascade-signal
// preemption-storm detectors (scheduler-watchdog and
// descheduler-storm-gate both count recent reason=Preempted events
// to spot a PriorityClass cascade — the Monzo/Zalando domino
// eviction shape).
package kube

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// PreemptedEventReason is the scheduler's domino-eviction signal: a
// high-PriorityClass pod that cannot land directly evicts lower-
// priority victims, which preempt their own victims in turn.
const PreemptedEventReason = "Preempted"

// EventTime returns the freshest timestamp an Event carries —
// lastTimestamp is the recurring-event clock, eventTime the
// events.k8s.io-style one-shot, creationTimestamp the fallback for
// an event so new nothing else has stamped it yet. The order is the
// LAST-observed convention (a spamming recurring event must read by
// its latest hit, not its birth) — a zero time only when every
// field is unset.
func EventTime(e *corev1.Event) time.Time {
	// events.k8s.io series events report the latest hit on
	// Series.LastObservedTime — prefer it so a recurring event
	// reads by its most recent occurrence, not its first.
	if e.Series != nil && !e.Series.LastObservedTime.IsZero() {
		return e.Series.LastObservedTime.Time
	}
	if !e.LastTimestamp.IsZero() {
		return e.LastTimestamp.Time
	}
	if !e.EventTime.IsZero() {
		return e.EventTime.Time
	}
	return e.CreationTimestamp.Time
}

// CountRecentEvents returns how many corev1.Events with the given
// reason carry a timestamp inside window of now. The reason rides a
// field selector so the apiserver does the first cut (reason is a
// supported Event field selector), and the result is re-checked in
// code — belt-and-braces for apiserver variants that accept the
// selector silently, and it keeps the count honest under the fake
// clientset, which applies label selectors only.
// Paged like every cluster-wide read; a List error is returned —
// the callers' storm verdicts must not compute on an empty read.
func CountRecentEvents(ctx context.Context, cs kubernetes.Interface,
	reason string, window time.Duration, now time.Time) (int, error) {

	var count int
	err := ListEach(ctx,
		metav1.ListOptions{
			FieldSelector: "reason=" + reason,
			Limit:         DefaultListPageSize,
		},
		Events(cs, metav1.NamespaceAll),
		func(items []corev1.Event) error {
			for i := range items {
				e := &items[i]
				if e.Reason != reason {
					continue
				}
				// Future EventTime (clock skew) is outside the window:
				// a negative Sub must never count as "recent".
				if d := now.Sub(EventTime(e)); d >= 0 && d <= window {
					count++
				}
			}
			return nil
		})
	return count, err
}

// WarningEvent describes one events.k8s.io/v1 Warning Event — the
// exact shape every check emitter hand-rolled (Regarding + Action,
// deprecated corev1.Event fields unset, ReportingController pinned
// to this controller's name). Name/Namespace compose per site: one
// sweep can fire several events on different objects sharing one
// `now`, so every caller keeps its uniqueness suffix
// (object.hex-now, svc.zone.hex-now, prefix-timestamp) instead of
// the helper inventing one.
type WarningEvent struct {
	// Name is the full event object name — caller-composed so the
	// per-site uniqueness conventions survive verbatim.
	Name string
	// Namespace is the POST collection namespace — events.k8s.io/v1
	// is namespaced, so this must be a real namespace (regarding's,
	// or "default" for cluster-scoped regarding objects).
	Namespace string
	// Regarding references the object the event is about.
	Regarding corev1.ObjectReference
	// Reason doubles as Action (every emitter stamped Action=Reason).
	Reason string
	// Note is the human message.
	Note string
	// ReportingInstance is the emitting check/module name.
	ReportingInstance string
	// Now is the emission clock — EventTime and the caller's Name
	// suffix must read from the same instant.
	Now time.Time
}

// EmitWarningEvent creates one events.k8s.io/v1 Warning Event from
// we — the single shared emit path replacing the hand-rolled
// eventsv1.Event literals. Returns the create error so the caller
// keeps its own failure posture (log-only best-effort, or IncError —
// the zone-starvation relist-vs-relist split); a success returns nil
// and the caller logs its EVENT line.
func EmitWarningEvent(ctx context.Context, cs kubernetes.Interface,
	we WarningEvent) error {

	ev := &eventsv1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      we.Name,
			Namespace: we.Namespace,
		},
		EventTime:           metav1.NewMicroTime(we.Now),
		Reason:              we.Reason,
		Note:                we.Note,
		Type:                corev1.EventTypeWarning,
		ReportingController: "node-automation-controller",
		ReportingInstance:   we.ReportingInstance,
		Action:              we.Reason,
		Regarding:           we.Regarding,
	}
	_, err := cs.EventsV1().Events(we.Namespace).Create(ctx, ev, metav1.CreateOptions{})
	return err
}
