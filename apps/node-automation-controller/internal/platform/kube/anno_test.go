package kube

import (
	"encoding/json"
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
			"passiontech.dev/last-heal": stamp.Format(time.RFC3339),
			"passiontech.dev/legacy":    "1762871400",
		},
	}}
	if got, ok := AnnoTime(pod, "passiontech.dev/last-heal"); !ok || !got.Equal(stamp) {
		t.Fatalf("AnnoTime rfc3339 = (%v,%v)", got, ok)
	}
	if got, ok := AnnoTime(pod, "passiontech.dev/legacy"); !ok ||
		!got.Equal(time.Unix(1762871400, 0)) {
		t.Fatalf("AnnoTime unix = (%v,%v)", got, ok)
	}
	// Absent key, nil annotations map, and a nil object all read as
	// "no stamp" — never a panic, never a zero-but-ok.
	if _, ok := AnnoTime(pod, "passiontech.dev/absent"); ok {
		t.Fatal("absent annotation read as a stamp")
	}
	if _, ok := AnnoTime(&corev1.Pod{}, "passiontech.dev/last-heal"); ok {
		t.Fatal("nil annotations map read as a stamp")
	}
	if _, ok := AnnoTime(nil, "passiontech.dev/last-heal"); ok {
		t.Fatal("nil object read as a stamp")
	}
}

func TestStampAnno(t *testing.T) {
	stamp := time.Date(2026, 11, 5, 10, 30, 0, 0, time.UTC)

	// New stamps are always RFC3339 — even over a legacy unix value.
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Annotations: map[string]string{"passiontech.dev/last-heal": "1762871400"},
	}}
	StampAnno(pod, "passiontech.dev/last-heal", stamp)
	if got := pod.Annotations["passiontech.dev/last-heal"]; got != "2026-11-05T10:30:00Z" {
		t.Fatalf("stamped value = %q, want RFC3339", got)
	}

	// A nil annotations map is created on write — and works on
	// unstructured objects too (the dyn-client callers).
	u := &unstructured.Unstructured{Object: map[string]any{}}
	StampAnno(u, "passiontech.dev/last-heal", stamp)
	if got, ok := AnnoTime(u, "passiontech.dev/last-heal"); !ok || !got.Equal(stamp) {
		t.Fatalf("round-trip on unstructured = (%v,%v)", got, ok)
	}
}

func TestMergePatchAnnos(t *testing.T) {
	patch, err := MergePatchAnnos(map[string]any{
		"passiontech.dev/last-es-nudge": "2026-11-06T00:00:00Z",
		"passiontech.dev/stale-marker":  nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	doc := map[string]any{}
	if err := json.Unmarshal(patch, &doc); err != nil {
		t.Fatal(err)
	}
	annos := doc["metadata"].(map[string]any)["annotations"].(map[string]any)
	if annos["passiontech.dev/last-es-nudge"] != "2026-11-06T00:00:00Z" {
		t.Fatalf("stamp missing: %v", annos)
	}
	if v, present := annos["passiontech.dev/stale-marker"]; !present || v != nil {
		t.Fatalf("nil value must serialize as JSON null for merge-patch delete: %v", annos)
	}
}
