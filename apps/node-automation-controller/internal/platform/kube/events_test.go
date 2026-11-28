package kube

import (
	"fmt"
	"strings"
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
		t.Context(), "ev-4", metav1.GetOptions{})
	stale.LastTimestamp = metav1.NewTime(now.Add(-30 * time.Minute))
	if _, err := cs.CoreV1().Events("apps").Update(
		t.Context(), stale, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	got, err := CountRecentEvents(t.Context(), cs,
		"Preempted", 5*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if got != 3 {
		t.Fatalf("CountRecentEvents = %d, want 3 (2 fresh + ev-5)", got)
	}
}

// A future event timestamp (clock skew) must not count as recent — a
// negative now.Sub would previously fall inside the window.
func TestCountRecentEventsSkipsFutureTimestamp(t *testing.T) {
	now := time.Now()
	future := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "ev-future",
			CreationTimestamp: metav1.NewTime(now.Add(time.Hour)),
		},
		Reason:        "Preempted",
		LastTimestamp: metav1.NewTime(now.Add(time.Hour)),
	}
	cs := fake.NewSimpleClientset(future)
	got, err := CountRecentEvents(t.Context(), cs,
		"Preempted", 5*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if got != 0 {
		t.Fatalf("CountRecentEvents = %d, want 0 — future timestamp counted as recent", got)
	}
}

// A long workload name or a findings blob must not make the whole
// Event create fail validation — Name/Note are clipped at the API's
// byte limits while the reason/action contract strings stay intact.
func TestEmitWarningEventClipsNameAndNote(t *testing.T) {
	cs := fake.NewSimpleClientset()
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	lbl := strings.Repeat("a", 60)
	err := EmitWarningEvent(t.Context(), cs, WarningEvent{
		Namespace:         "apps",
		Name:              strings.Join([]string{lbl, lbl, lbl, lbl, lbl}, "."),
		Reason:            "ServiceSelectorBlackhole",
		Note:              strings.Repeat("x", 1200),
		ReportingInstance: "cluster-health-probes",
		Now:               now,
	})
	if err != nil {
		t.Fatalf("EmitWarningEvent: %v", err)
	}
	evs, err := cs.EventsV1().Events("apps").List(t.Context(), metav1.ListOptions{})
	if err != nil || len(evs.Items) != 1 {
		t.Fatalf("events = %d err = %v", len(evs.Items), err)
	}
	got := evs.Items[0]
	if len(got.Name) != 253 {
		t.Fatalf("event name length = %d, want 253", len(got.Name))
	}
	if len(got.Note) != 1024 {
		t.Fatalf("event note length = %d, want 1024", len(got.Note))
	}
	if got.Reason != "ServiceSelectorBlackhole" || got.Action != got.Reason {
		t.Fatalf("reason/action must stay byte-stable: %q / %q", got.Reason, got.Action)
	}
	// Cutting a multi-byte rune must not leave invalid UTF-8 in Note.
	cs2 := fake.NewSimpleClientset()
	err = EmitWarningEvent(t.Context(), cs2, WarningEvent{
		Namespace: "apps", Name: "ev-utf8", Reason: "X",
		Note: strings.Repeat("é", 600), Now: now,
	})
	if err != nil {
		t.Fatalf("EmitWarningEvent utf8: %v", err)
	}
	got2, _ := cs2.EventsV1().Events("apps").List(t.Context(), metav1.ListOptions{})
	if len(got2.Items) != 1 || len(got2.Items[0].Note) > 1024 {
		t.Fatalf("utf8 note not clipped: %+v", got2.Items)
	}
}

// A long object name must be shortened from the FRONT while keeping
// the trailing ".unix" uniqueness suffix — otherwise every long name
// emitted in one sweep collapses to the same prefix and the second
// Create fails 422 AlreadyExists. The cut must also not leave a '.'
// or '-' at the end of the shortened segment (DNS-1123).
func TestEmitWarningEventClipKeepsTimestampSuffix(t *testing.T) {
	cs := fake.NewSimpleClientset()
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	const suffix = ".1752890400"
	// The '-' sits exactly at byte 242 (the 253-11 name budget), so a
	// naive prefix cut would leave a DNS-invalid trailing separator.
	name := strings.Repeat("a", 241) + "-" + strings.Repeat("b", 60) + suffix
	if err := EmitWarningEvent(t.Context(), cs, WarningEvent{
		Namespace: "apps", Name: name, Reason: "TopologyZoneDeadlock",
		Note: "long name", Now: now,
	}); err != nil {
		t.Fatalf("EmitWarningEvent: %v", err)
	}
	evs, err := cs.EventsV1().Events("apps").List(t.Context(), metav1.ListOptions{})
	if err != nil || len(evs.Items) != 1 {
		t.Fatalf("events = %d err = %v", len(evs.Items), err)
	}
	got := evs.Items[0].Name
	if len(got) > 253 {
		t.Fatalf("event name length = %d, want <=253", len(got))
	}
	if !strings.HasSuffix(got, suffix) {
		t.Fatalf("event name lost its timestamp suffix: %q", got)
	}
	segment := strings.TrimSuffix(got, suffix)
	if strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, "-") {
		t.Fatalf("shortened segment ends with DNS-invalid separator: %q", segment)
	}
	if got == name[:253] {
		t.Fatal("timestamp suffix was clipped away by a plain prefix cut")
	}
}

// The other emitter spelling uses ".%x" of UnixNano: a long name must
// keep that suffix too, with the same DNS-1123 separator trim.
func TestEmitWarningEventClipKeepsHexNanoSuffix(t *testing.T) {
	cs := fake.NewSimpleClientset()
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	suffix := fmt.Sprintf(".%x", now.UnixNano())
	// The '-' sits exactly at the first cut byte of the shortened
	// segment (253 - len(suffix)), so a naive prefix cut would leave a
	// DNS-invalid trailing separator.
	baseLen := 253 - len(suffix) - 1
	name := strings.Repeat("a", baseLen) + "-" + strings.Repeat("b", 60) + suffix
	if err := EmitWarningEvent(t.Context(), cs, WarningEvent{
		Namespace: "apps", Name: name, Reason: "TopologyZoneDeadlock",
		Note: "long name", Now: now,
	}); err != nil {
		t.Fatalf("EmitWarningEvent: %v", err)
	}
	evs, err := cs.EventsV1().Events("apps").List(t.Context(), metav1.ListOptions{})
	if err != nil || len(evs.Items) != 1 {
		t.Fatalf("events = %d err = %v", len(evs.Items), err)
	}
	got := evs.Items[0].Name
	if len(got) > 253 || !strings.HasSuffix(got, suffix) {
		t.Fatalf("hex nano suffix lost: %q (suffix %q)", got, suffix)
	}
	segment := strings.TrimSuffix(got, suffix)
	if strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, "-") {
		t.Fatalf("shortened segment ends with DNS-invalid separator: %q", segment)
	}
}

// Short a-f runs are ordinary DNS labels, not timestamps: only hex
// suffixes of at least 8 chars are preserved as uniqueness suffixes.
func TestClipEventNameHexSuffixMinimumLength(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		max         int
		want        string
	}{
		{"7-char hex is part of the name", "aaaaaaaaaa.abcdefa", 15, "aaaaaaaaaa.abcd"},
		{"8-char hex is a suffix", "aaaaaaaaaaaaaaaaaaaa.abcdefab", 15, "aaaaaa.abcdefab"},
	} {
		if got := clipEventName(tc.input, tc.max); got != tc.want {
			t.Errorf("%s: clipEventName = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// Even when the suffix alone exhausts the budget (or there is no
// suffix), the hard cut must not end on a DNS-invalid separator.
func TestClipEventNameTrimsSeparatorsWhenBudgetExhausted(t *testing.T) {
	longHexSuffix := strings.Repeat("f", 260)
	name := strings.Repeat("a", 252) + "-" + longHexSuffix // suffix 261 bytes > max
	if got := clipEventName(name, 253); strings.HasSuffix(got, ".") || strings.HasSuffix(got, "-") {
		t.Fatalf("hard cut left a trailing separator: %q", got)
	}
	if got := clipEventName("ab-cd-", 5); got != "ab-cd" {
		t.Fatalf("clipEventName = %q, want ab-cd", got)
	}
}

func TestClipEventNameEnforces63CharLabelCap(t *testing.T) {
	longA := strings.Repeat("a", 80)
	longB := strings.Repeat("a", 79) + "b"
	gotA := clipEventName("prefix."+longA+".1752890400", 253)
	gotB := clipEventName("prefix."+longB+".1752890400", 253)
	if len(gotA) > 253 {
		t.Fatalf("clipped name too long: %d", len(gotA))
	}
	for _, lbl := range strings.Split(gotA, ".") {
		if len(lbl) > 63 {
			t.Fatalf("DNS label exceeds 63 chars: %q (%d)", lbl, len(lbl))
		}
	}
	if !strings.HasSuffix(gotA, ".1752890400") {
		t.Fatalf("timestamp suffix lost: %q", gotA)
	}
	if gotA == gotB {
		t.Fatalf("distinct overlong labels collided: %q", gotA)
	}
	// Single overlong label with hyphens near the cut point trims cleanly.
	hyphenated := strings.Repeat("x", 53) + "---" + strings.Repeat("y", 20)
	gotH := clipEventName(hyphenated, 253)
	if len(gotH) > 63 {
		t.Fatalf("single overlong label len = %d, want <=63 (%q)", len(gotH), gotH)
	}
	if strings.Contains(gotH, "--") {
		t.Fatalf("hyphenated cut left double dash before hash: %q", gotH)
	}
}

func TestAgeSinceAndAgeAtLeast(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	if age, ok := AgeSince(time.Time{}, now); ok || age != 0 {
		t.Fatalf("AgeSince(zero) = (%v, %v), want (0, false)", age, ok)
	}
	if AgeAtLeast(time.Time{}, now, time.Minute) {
		t.Fatal("AgeAtLeast(zero) = true, want false")
	}
	t5m := now.Add(-5 * time.Minute)
	if age, ok := AgeSince(t5m, now); !ok || age != 5*time.Minute {
		t.Fatalf("AgeSince(5m) = (%v, %v), want (5m, true)", age, ok)
	}
	if !AgeAtLeast(t5m, now, 5*time.Minute) {
		t.Fatal("AgeAtLeast(5m, 5m) = false, want true")
	}
	if AgeAtLeast(t5m, now, 6*time.Minute) {
		t.Fatal("AgeAtLeast(5m, 6m) = true, want false")
	}
}
