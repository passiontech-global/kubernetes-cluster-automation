// event_test.go — the shared events.v1 Warning scaffold: nil-client
// seam, the seams-clock EventTime (with the back-dating override),
// the emitted shape and the create-failure suspect line.
package wdeps_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// TestEmitCheckEventNilClient — the nil-client seam is a
// distinguishable error, logged nowhere (callers gate on it).
func TestEmitCheckEventNilClient(t *testing.T) {
	e := fixture(t)
	e.D.Cfg.Client = nil
	err := e.D.EmitCheckEvent(context.Background(), wdeps.CheckEvent{Name: "x.1"})
	if !errors.Is(err, wdeps.ErrNoEventClient) {
		t.Fatalf("err=%v want ErrNoEventClient", err)
	}
	if e.LogLines(t) != "" {
		t.Fatalf("nil client logged:\n%s", e.LogLines(t))
	}
}

// TestEmitCheckEventCreate — the emitted object shape: Reason
// doubling as Action, the node-host-agent identity, the EventTime
// off the seams clock (When overrides for back-dated events) and the
// regarding reference.
func TestEmitCheckEventCreate(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()
	ev := wdeps.CheckEvent{
		Name:      "system-oom-victim.42",
		Namespace: "kube-system",
		Reason:    "SystemOOMVictim",
		Note:      "pid 123 killed",
		When:      e.Now.Add(-2 * time.Hour), // back-dated kernel epoch
		Regarding: corev1.ObjectReference{Kind: "Pod", Name: "victim", Namespace: "kube-system"},
		Owner:     "pod kube-system/victim",
	}
	if err := e.D.EmitCheckEvent(ctx, ev); err != nil {
		t.Fatalf("EmitCheckEvent: %v", err)
	}
	got, err := e.CS.EventsV1().Events("kube-system").Get(ctx, "system-oom-victim.42", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("event not created: %v", err)
	}
	if got.Reason != "SystemOOMVictim" || got.Action != "SystemOOMVictim" {
		t.Fatalf("reason=%q action=%q", got.Reason, got.Action)
	}
	if got.Note != "pid 123 killed" || got.Type != corev1.EventTypeWarning {
		t.Fatalf("note=%q type=%q", got.Note, got.Type)
	}
	if got.ReportingController != "node-host-agent" || got.ReportingInstance != "node-a" {
		t.Fatalf("reporter=%q instance=%q", got.ReportingController, got.ReportingInstance)
	}
	if want := ev.When.UnixMicro(); got.EventTime.UnixMicro() != want {
		t.Fatalf("eventTime=%v want back-dated %v", got.EventTime.Time, ev.When)
	}
	if got.Regarding.Name != "victim" || got.Regarding.Kind != "Pod" {
		t.Fatalf("regarding=%+v", got.Regarding)
	}

	// No When → the seams clock now (advance the fixture clock to
	// prove the EventTime really rides the seam).
	e2 := fixture(t)
	e2.Now = e2.Now.Add(3 * time.Hour)
	ev2 := wdeps.CheckEvent{Name: "later.1", Namespace: "default", Reason: "Later"}
	if err := e2.D.EmitCheckEvent(ctx, ev2); err != nil {
		t.Fatalf("EmitCheckEvent: %v", err)
	}
	got2, err := e2.CS.EventsV1().Events("default").Get(ctx, "later.1", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("event not created: %v", err)
	}
	if want := e2.Now.UnixMicro(); got2.EventTime.UnixMicro() != want {
		t.Fatalf("eventTime=%v want seams clock %v", got2.EventTime.Time, e2.Now)
	}
}

// TestEmitCheckEventCreateFailure — an API failure appends the
// shared suspect line (with the owner suffix when carried) and
// returns the error so callers can hold dedup markers.
func TestEmitCheckEventCreateFailure(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()
	// Pre-create the event so the Create collides.
	existing := &eventsv1.Event{ObjectMeta: metav1.ObjectMeta{
		Name: "dup.1", Namespace: "default",
	}}
	if _, err := e.CS.EventsV1().Events("default").Create(ctx, existing, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	ev := wdeps.CheckEvent{
		Name: "dup.1", Namespace: "default", Reason: "SystemOOMVictim",
		Owner: "pod default/victim",
	}
	if err := e.D.EmitCheckEvent(ctx, ev); err == nil {
		t.Fatal("collision must return the error")
	}
	if !strings.Contains(e.LogLines(t),
		"suspect: SystemOOMVictim event create failed for pod default/victim") {
		t.Fatalf("missing failure suspect line:\n%s", e.LogLines(t))
	}

	// An owner-less emitter logs without the " for " suffix.
	ev2 := wdeps.CheckEvent{Name: "dup.1", Namespace: "default", Reason: "NoOwner"}
	if err := e.D.EmitCheckEvent(ctx, ev2); err == nil {
		t.Fatal("collision must return the error")
	}
	if !strings.Contains(e.LogLines(t),
		"suspect: NoOwner event create failed: ") {
		t.Fatalf("missing owner-less line:\n%s", e.LogLines(t))
	}
}
