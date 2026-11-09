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
