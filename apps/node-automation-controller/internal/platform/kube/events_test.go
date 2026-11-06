package kube

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// EventTime prefers the recurring-event clock (lastTimestamp), then
// the one-shot eventTime, then creationTimestamp — an event with all
// three unset reads as the zero time.
func TestEventTimeFallbackChain(t *testing.T) {
	base := time.Now().Truncate(time.Second)
	e := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			CreationTimestamp: metav1.NewTime(base.Add(-time.Hour)),
		},
		EventTime:     metav1.NewMicroTime(base.Add(-30 * time.Minute)),
		LastTimestamp: metav1.NewTime(base.Add(-time.Minute)),
	}
	if got := EventTime(e); !got.Equal(base.Add(-time.Minute)) {
		t.Fatalf("lastTimestamp must win, got %s", got)
	}
	e.LastTimestamp = metav1.Time{}
	if got := EventTime(e); !got.Equal(base.Add(-30 * time.Minute)) {
		t.Fatalf("eventTime must win over creationTimestamp, got %s", got)
	}
	e.EventTime = metav1.MicroTime{}
	if got := EventTime(e); !got.Equal(base.Add(-time.Hour)) {
		t.Fatalf("creationTimestamp fallback, got %s", got)
	}
	e.CreationTimestamp = metav1.Time{}
	if got := EventTime(e); !got.IsZero() {
		t.Fatalf("fully unset event must read zero, got %s", got)
	}
}

// CountRecentEvents counts only matching-reason events inside the
// window — wrong-reason noise and stale events are both excluded.
func TestCountRecentEvents(t *testing.T) {
	now := time.Now()
	fresh := func(ns, name, reason string) *corev1.Event {
		return &corev1.Event{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: ns, Name: name,
				CreationTimestamp: metav1.NewTime(now.Add(-time.Minute)),
			},
			Reason:        reason,
			LastTimestamp: metav1.NewTime(now.Add(-time.Minute)),
		}
	}
	cs := fake.NewSimpleClientset(
		fresh("apps", "ev-1", "Preempted"),
		fresh("apps", "ev-2", "Preempted"),
		fresh("apps", "ev-3", "Scheduled"), // wrong reason — excluded
		fresh("apps", "ev-4", "Preempted"), // timestamp overridden below
		fresh("other", "ev-5", "Preempted"))
	// ev-4's last observed hit is stale — outside the window.
	stale, _ := cs.CoreV1().Events("apps").Get(
		context.Background(), "ev-4", metav1.GetOptions{})
	stale.LastTimestamp = metav1.NewTime(now.Add(-30 * time.Minute))
	if _, err := cs.CoreV1().Events("apps").Update(
		context.Background(), stale, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	got, err := CountRecentEvents(context.Background(), cs,
		"Preempted", 5*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if got != 3 {
		t.Fatalf("CountRecentEvents = %d, want 3 (2 fresh + ev-5)", got)
	}
}
