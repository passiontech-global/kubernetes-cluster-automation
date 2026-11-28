// events_logscan_test.go — unit tests for probefw.EmitWarningDeduped
// and logScanAt watermark helpers.
package probefw

import (
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

func TestEmitWarningDeduped(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	cs := fake.NewSimpleClientset()
	var failCreate bool
	cs.PrependReactor("create", "events", func(ktesting.Action) (bool, runtime.Object, error) {
		if failCreate {
			return true, nil, errors.New("forbidden")
		}
		return false, nil, nil
	})
	var cd state.CooldownSet
	we := kube.WarningEvent{
		Namespace:         "apps",
		Reason:            "TestWarning",
		Note:              "something happened",
		ReportingInstance: "test",
		Regarding:         corev1.ObjectReference{Kind: "Pod", Namespace: "apps", Name: "p1"},
	}

	// Failure must NOT stamp cooldown so subsequent sweeps retry.
	failCreate = true
	if ok := EmitWarningDeduped(t.Context(), cs, logr.Discard(), &cd, "k1", time.Hour, now, we); ok {
		t.Fatal("expected false on failed Event create")
	}
	failCreate = false
	if ok := EmitWarningDeduped(t.Context(), cs, logr.Discard(), &cd, "k1", time.Hour, now, we); !ok {
		t.Fatal("expected true on first succeeded Event create")
	}
	if ok := EmitWarningDeduped(t.Context(), cs, logr.Discard(), &cd, "k1", time.Hour, now.Add(10*time.Minute), we); ok {
		t.Fatal("expected false while inside cooldown")
	}
	evs, err := cs.EventsV1().Events("apps").List(t.Context(), metav1.ListOptions{})
	if err != nil || len(evs.Items) != 1 {
		t.Fatalf("events count = %d (err=%v), want 1", len(evs.Items), err)
	}
}

func TestLogScanWatermarkHelpers(t *testing.T) {
	t0 := time.Unix(1000, 0).UTC()
	t1 := t0.Add(time.Minute)
	t2 := t1.Add(time.Minute)

	var m map[string]time.Time
	if prev, scanned := ReadLogScanAt(m, "p1"); scanned || !prev.IsZero() {
		t.Fatalf("unseen ReadLogScanAt = (%v, %v), want (0, false)", prev, scanned)
	}
	if !LogLineFresh(false, t0, time.Time{}) {
		t.Fatal("first sweep must treat timestamped lines as fresh")
	}
	prev, scanned := AdvanceLogScanAt(&m, "p1", t1, t0)
	if scanned || !prev.IsZero() || !m["p1"].Equal(t1) {
		t.Fatalf("first AdvanceLogScanAt = (%v, %v, stored=%v), want (0, false, %v)", prev, scanned, m["p1"], t1)
	}
	if LogLineFresh(true, t1, t1) {
		t.Fatal("line at prevScan must not read fresh")
	}
	if !LogLineFresh(true, t2, t1) {
		t.Fatal("line after prevScan must read fresh")
	}
	if !LogLineFresh(true, time.Time{}, t1) {
		t.Fatal("unstamped line must fail toward alerting")
	}
	PruneLogScanAt(m, map[string]bool{})
	if len(m) != 0 {
		t.Fatalf("PruneLogScanAt left %d entries, want 0", len(m))
	}
}
