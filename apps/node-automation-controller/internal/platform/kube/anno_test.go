package kube

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestParseAnnoTime(t *testing.T) {
	rfc := time.Date(2026, 11, 5, 10, 30, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		in   string
		want time.Time
		ok   bool
	}{
		{"rfc3339", "2026-11-05T10:30:00Z", rfc, true},
		{"rfc3339 offset", "2026-11-05T12:30:00+02:00", rfc, true},
		{"unix seconds", "1762871400", time.Unix(1762871400, 0), true},
		{"empty", "", time.Time{}, false},
		{"garbage", "not-a-time", time.Time{}, false},
		// A partial timestamp is neither RFC3339 nor a bare integer —
		// it must read as absent, not as something approximate.
		{"date only", "2026-11-05", time.Time{}, false},
		{"unix garbage", "12345x", time.Time{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ParseAnnoTime(tc.in)
			if ok != tc.ok || !got.Equal(tc.want) {
				t.Fatalf("ParseAnnoTime(%q) = (%v,%v), want (%v,%v)",
					tc.in, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestAnnoTime(t *testing.T) {
	stamp := time.Date(2026, 11, 5, 10, 30, 0, 0, time.UTC)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Annotations: map[string]string{
			"node.ops/last-heal": stamp.Format(time.RFC3339),
			"node.ops/legacy":    "1762871400",
		},
	}}
	if got, ok := AnnoTime(pod, "node.ops/last-heal"); !ok || !got.Equal(stamp) {
		t.Fatalf("AnnoTime rfc3339 = (%v,%v)", got, ok)
	}
	if got, ok := AnnoTime(pod, "node.ops/legacy"); !ok ||
		!got.Equal(time.Unix(1762871400, 0)) {
		t.Fatalf("AnnoTime unix = (%v,%v)", got, ok)
	}
	// Absent key, nil annotations map, and a nil object all read as
	// "no stamp" — never a panic, never a zero-but-ok.
	if _, ok := AnnoTime(pod, "node.ops/absent"); ok {
		t.Fatal("absent annotation read as a stamp")
	}
	if _, ok := AnnoTime(&corev1.Pod{}, "node.ops/last-heal"); ok {
		t.Fatal("nil annotations map read as a stamp")
	}
	if _, ok := AnnoTime(nil, "node.ops/last-heal"); ok {
		t.Fatal("nil object read as a stamp")
	}
}

func TestStampAnno(t *testing.T) {
	stamp := time.Date(2026, 11, 5, 10, 30, 0, 0, time.UTC)

	// New stamps are always RFC3339 — even over a legacy unix value.
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Annotations: map[string]string{"node.ops/last-heal": "1762871400"},
	}}
	StampAnno(pod, "node.ops/last-heal", stamp)
	if got := pod.Annotations["node.ops/last-heal"]; got != "2026-11-05T10:30:00Z" {
		t.Fatalf("stamped value = %q, want RFC3339", got)
	}

	// A nil annotations map is created on write — and works on
	// unstructured objects too (the dyn-client callers).
	u := &unstructured.Unstructured{Object: map[string]any{}}
	StampAnno(u, "node.ops/last-heal", stamp)
	if got, ok := AnnoTime(u, "node.ops/last-heal"); !ok || !got.Equal(stamp) {
		t.Fatalf("round-trip on unstructured = (%v,%v)", got, ok)
	}
}
