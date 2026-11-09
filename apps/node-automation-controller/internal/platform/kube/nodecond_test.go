// nodecond_test.go — tests for nodecond.go: the CondTypes name
// conversion and the CondHeartbeatLive freshness gate's boundary
// semantics (strictly-younger-than-maxAge, zero heartbeat = dead).
package kube

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCondTypes(t *testing.T) {
	if got := CondTypes(nil); len(got) != 0 {
		t.Fatalf("CondTypes(nil) = %v, want empty", got)
	}
	got := CondTypes([]string{"NodeHang", "NodeClockSkew"})
	want := []corev1.NodeConditionType{"NodeHang", "NodeClockSkew"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("CondTypes()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCondHeartbeatLive(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	const maxAge = 10 * time.Minute
	cond := func(hb time.Time) *corev1.NodeCondition {
		return &corev1.NodeCondition{
			Type:              corev1.NodeReady,
			LastHeartbeatTime: metav1.NewTime(hb),
		}
	}
	for _, tc := range []struct {
		name string
		hb   time.Time // zero value = never stamped
		want bool
	}{
		{"zero heartbeat is dead", time.Time{}, false},
		{"younger than maxAge is live", now.Add(-maxAge + time.Second), true},
		{"exactly maxAge is dead", now.Add(-maxAge), false},
		{"older than maxAge is dead", now.Add(-maxAge - time.Second), false},
		{"fresh stamp is live", now.Add(-time.Minute), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := CondHeartbeatLive(cond(tc.hb), maxAge, now); got != tc.want {
				t.Fatalf("CondHeartbeatLive(hb=%v) = %v, want %v",
					tc.hb, got, tc.want)
			}
		})
	}
}
