package velerobackupauditor

import (
	"errors"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic/fake"
	kfake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

// veleroSchedule builds a Schedule — age only ages creationTimestamp
// (realism; the pause verdict is measured by the firstSeenPaused
// ledger, not the object's age). A deterministic UID keeps the
// pause-ledger key non-empty; tests override it for recreate cases.
func veleroSchedule(ns, name string, paused bool, age time.Duration) *unstructured.Unstructured {
	o := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "velero.io/v1",
		"kind":       "Schedule",
		"metadata":   map[string]any{"namespace": ns, "name": name},
		"spec":       map[string]any{"paused": paused},
	}}
	o.SetUID(types.UID(ns + "/" + name))
	o.SetCreationTimestamp(metav1.NewTime(time.Now().Add(-age)))
	return o
}

// veleroBackup builds a Backup owned by `schedule`; phase plus the
// status counters drive the rot signatures. progress carries Velero's
// real fields — itemsBackedUp/totalItems (BackupProgress has no
// totalBytes; the old fixture field never existed upstream).
func veleroBackup(ns, name, schedule, phase string, age time.Duration,
	items, total, errs, warns int64) *unstructured.Unstructured {
	o := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "velero.io/v1",
		"kind":       "Backup",
		"metadata":   map[string]any{"namespace": ns, "name": name},
		"status": map[string]any{
			"phase":    phase,
			"errors":   errs,
			"warnings": warns,
			"progress": map[string]any{
				"itemsBackedUp": items,
				"totalItems":    total,
			},
		},
	}}
	if schedule != "" {
		o.SetLabels(map[string]string{veleroScheduleLabel: schedule})
	}
	o.SetCreationTimestamp(metav1.NewTime(time.Now().Add(-age)))
	return o
}

func newVeleroAuditor(dyn *fake.FakeDynamicClient, now time.Time) *veleroBackupAuditor {
	return &veleroBackupAuditor{
		cs:              kfake.NewSimpleClientset(),
		dyn:             dyn,
		nowFn:           func() time.Time { return now },
		seenPaused:      map[pausedKey]bool{},
		seenBad:         map[backupKey]bool{},
		firstSeenPaused: map[pausedLedgerKey]time.Time{},
	}
}

// pausedSeries / badSeries read the gauges through the non-creating
// gaugeSeriesValue helper — the returned bool distinguishes
// "emitted 0" from "no series", which ToFloat64(WithLabelValues)
// cannot (it instantiates the tuple at 0).
func pausedSeries(t *testing.T, ns, schedule string) (float64, bool) {
	t.Helper()
	return testutil.GaugeSeriesValue(t, "node_automation_velero_schedule_paused",
		map[string]string{"namespace": ns, "schedule": schedule})
}

func badSeries(t *testing.T, ns, schedule, reason string) (float64, bool) {
	t.Helper()
	return testutil.GaugeSeriesValue(t, "node_automation_velero_backup_empty_or_errored",
		map[string]string{"namespace": ns, "schedule": schedule, "reason": reason})
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// Clusters without Velero 404 on the Schedule list — a quiet no-op,
// not a run error (same contract as externalsecret-nudge).
func TestVeleroBackupAuditorCRDAbsent(t *testing.T) {
	dyn := newDynFake()
	dyn.PrependReactor("list", "schedules",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewNotFound(
				veleroScheduleGVR.GroupResource(), "")
		})
	a := newVeleroAuditor(dyn, time.Now())
	if err := a.run(ctx); err != nil {
		t.Fatalf("absent velero CRDs must skip cleanly, got %v", err)
	}
}

// A schedule list failure is a real run error — the periodic wrapper
// owns the IncError for it.
func TestVeleroBackupAuditorScheduleListError(t *testing.T) {
	dyn := newDynFake()
	dyn.PrependReactor("list", "schedules",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	a := newVeleroAuditor(dyn, time.Now())
	if err := a.run(ctx); err == nil {
		t.Fatal("expected error when the schedule list fails")
	}
}

// Check 1: a schedule paused CONTINUOUSLY for >24h gauges 1 — the
// firstSeenPaused ledger measures the real pause duration from first
// sight, so a 48h-old schedule paused only moments ago still starts
// at 0; an unpaused schedule emits no series.
func TestVeleroBackupAuditorPausedSchedule(t *testing.T) {
	now := time.Now()
	dyn := newDynFake(
		veleroSchedule("velero", "old-pause", true, 48*time.Hour),
		veleroSchedule("velero", "fresh-pause", true, time.Hour),
		veleroSchedule("velero", "active", false, 72*time.Hour))
	a := newVeleroAuditor(dyn, now)

	// First sight seeds the ledger — Schedule age is irrelevant to
	// pause duration, so even 48h-old "old-pause" starts its clock now.
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"old-pause", "fresh-pause"} {
		if v, ok := pausedSeries(t, "velero", s); !ok || v != 0 {
			t.Fatalf("%s paused series = %v,%v, want 0,true on first sight", s, v, ok)
		}
	}
	if _, ok := pausedSeries(t, "velero", "active"); ok {
		t.Fatal("unpaused schedule produced a paused series")
	}

	// Advance past the 24h threshold: both paused schedules alert.
	a.nowFn = func() time.Time { return now.Add(25 * time.Hour) }
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"old-pause", "fresh-pause"} {
		if v, ok := pausedSeries(t, "velero", s); !ok || v != 1 {
			t.Fatalf("%s paused series = %v,%v, want 1,true past 24h", s, v, ok)
		}
	}
}

// The pause clock is per schedule GENERATION: unpausing drops the
// ledger entry so a re-pause starts a fresh 24h measurement, and a
// delete+recreate under a new UID cannot inherit the dead object's
// pause time.
func TestVeleroBackupAuditorPauseLedgerReset(t *testing.T) {
	now := time.Now()
	dyn := newDynFake(veleroSchedule("velero", "flappy", true, 72*time.Hour))
	a := newVeleroAuditor(dyn, now)

	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	a.nowFn = func() time.Time { return now.Add(25 * time.Hour) }
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if v, ok := pausedSeries(t, "velero", "flappy"); !ok || v != 1 {
		t.Fatalf("paused series = %v,%v, want 1,true", v, ok)
	}

	setPaused := func(paused bool) {
		u, err := dyn.Resource(veleroScheduleGVR).Namespace("velero").
			Get(ctx, "flappy", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		_ = unstructured.SetNestedField(u.Object, paused, "spec", "paused")
		if _, err := dyn.Resource(veleroScheduleGVR).Namespace("velero").
			Update(ctx, u, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}

	// Unpause → ledger pruned + series dropped; re-pause re-arms the
	// clock — still >24h "now", but the pause itself is fresh.
	setPaused(false)
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := pausedSeries(t, "velero", "flappy"); ok {
		t.Fatal("paused series kept after unpause")
	}
	if len(a.firstSeenPaused) != 0 {
		t.Fatalf("firstSeenPaused not pruned on unpause: %+v", a.firstSeenPaused)
	}
	setPaused(true)
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if v, ok := pausedSeries(t, "velero", "flappy"); !ok || v != 0 {
		t.Fatalf("re-paused series = %v,%v, want 0,true — clock must restart", v, ok)
	}

	// Delete+recreate under a different UID: the ledger key carries
	// the UID, so the dead generation's pause time cannot transfer.
	if err := dyn.Resource(veleroScheduleGVR).Namespace("velero").
		Delete(ctx, "flappy", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	reborn := veleroSchedule("velero", "flappy", true, 72*time.Hour)
	reborn.SetUID("reborn-uid")
	if _, err := dyn.Resource(veleroScheduleGVR).Namespace("velero").
		Create(ctx, reborn, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if v, ok := pausedSeries(t, "velero", "flappy"); !ok || v != 0 {
		t.Fatalf("recreated series = %v,%v, want 0,true — new UID re-arms", v, ok)
	}
}

// Check 2: the LATEST schedule-owned backup — phase=Completed with
// zero items, errors>0, warnings>0 each flag their reason; a healthy
// newer backup clears the flag a broken older one would set; and a
// non-Completed phase flags nothing (partial counters, not rot).
func TestVeleroBackupAuditorEmptyOrErrored(t *testing.T) {
	// A Completed backup with NO progress block (older Velero,
	// stripped status) is "can't tell" — it must NOT flag zero_items;
	// a backup whose only progress field is totalItems==0 still flags.
	noProgress := veleroBackup("velero", "b-noprogress", "noprogress-sched",
		"Completed", time.Hour, 0, 0, 0, 0)
	delete(noProgress.Object["status"].(map[string]any), "progress")
	totalOnly := veleroBackup("velero", "b-totalonly", "totalonly-sched",
		"Completed", time.Hour, 0, 0, 0, 0)
	totalOnly.Object["status"].(map[string]any)["progress"] =
		map[string]any{"totalItems": int64(0)}

	dyn := newDynFake(
		veleroSchedule("velero", "empty-sched", false, 72*time.Hour),
		veleroSchedule("velero", "err-sched", false, 72*time.Hour),
		veleroSchedule("velero", "warn-sched", false, 72*time.Hour),
		veleroSchedule("velero", "healthy-sched", false, 72*time.Hour),
		// Old broken + NEW healthy for the same schedule — latest wins.
		veleroSchedule("velero", "recovered-sched", false, 72*time.Hour),
		// Non-Completed phases — errors/warnings there are partial
		// counters, NOT the rot signature (the Completed gate).
		veleroSchedule("velero", "inflight-sched", false, 72*time.Hour),
		veleroSchedule("velero", "failed-sched", false, 72*time.Hour),
		veleroSchedule("velero", "noprogress-sched", false, 72*time.Hour),
		veleroSchedule("velero", "totalonly-sched", false, 72*time.Hour),
		veleroBackup("velero", "b-empty", "empty-sched", "Completed",
			time.Hour, 0, 0, 0, 0),
		veleroBackup("velero", "b-err", "err-sched", "Completed",
			time.Hour, 100, 1000, 3, 0),
		veleroBackup("velero", "b-warn", "warn-sched", "Completed",
			time.Hour, 100, 1000, 0, 7),
		veleroBackup("velero", "b-ok", "healthy-sched", "Completed",
			time.Hour, 100, 1000, 0, 0),
		veleroBackup("velero", "b-old-bad", "recovered-sched", "Completed",
			2*time.Hour, 0, 0, 0, 0),
		veleroBackup("velero", "b-new-ok", "recovered-sched", "Completed",
			30*time.Minute, 50, 500, 0, 0),
		veleroBackup("velero", "b-inflight", "inflight-sched", "InProgress",
			time.Hour, 0, 0, 5, 3),
		veleroBackup("velero", "b-failed", "failed-sched", "Failed",
			time.Hour, 0, 0, 5, 3),
		noProgress, totalOnly,
		// Manual backup with no schedule label — must not leak into a schedule.
		veleroBackup("velero", "b-manual", "", "Completed",
			10*time.Minute, 0, 0, 0, 0))
	a := newVeleroAuditor(dyn, time.Now())

	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, tc := range [][3]string{
		{"velero", "empty-sched", "zero_items"},
		{"velero", "err-sched", "errors"},
		{"velero", "warn-sched", "warnings"},
		{"velero", "totalonly-sched", "zero_items"}, // totalItems==0 alone still flags
	} {
		if v, ok := badSeries(t, tc[0], tc[1], tc[2]); !ok || v != 1 {
			t.Fatalf("%s series = %v,%v, want 1,true", tc[2], v, ok)
		}
	}
	for _, tc := range [][3]string{
		{"velero", "healthy-sched", "zero_items"},
		{"velero", "healthy-sched", "errors"},
		{"velero", "healthy-sched", "warnings"},
		{"velero", "recovered-sched", "zero_items"},  // newest backup is healthy
		{"velero", "inflight-sched", "zero_items"},   // phase gate
		{"velero", "inflight-sched", "errors"},       // phase gate
		{"velero", "inflight-sched", "warnings"},     // phase gate
		{"velero", "failed-sched", "zero_items"},     // phase gate
		{"velero", "failed-sched", "errors"},         // phase gate
		{"velero", "failed-sched", "warnings"},       // phase gate
		{"velero", "noprogress-sched", "zero_items"}, // no progress block — can't tell
	} {
		if _, ok := badSeries(t, tc[0], tc[1], tc[2]); ok {
			t.Fatalf("non-Completed/healthy backup produced a %s series for %s", tc[2], tc[1])
		}
	}
}

// Resolving the condition clears the gauge on the next sweep —
// unpaused schedule and a fresh healthy backup both prune.
func TestVeleroBackupAuditorClearsResolvedSeries(t *testing.T) {
	now := time.Now()
	sched := veleroSchedule("velero", "rot", true, 48*time.Hour)
	dyn := newDynFake(sched,
		veleroBackup("velero", "b1", "rot", "Completed",
			time.Hour, 0, 0, 0, 0))
	a := newVeleroAuditor(dyn, now)

	// First sight seeds the pause clock; advance it past 24h so the
	// paused signature is actually firing before the resolve.
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	a.nowFn = func() time.Time { return now.Add(25 * time.Hour) }
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	pv, pok := pausedSeries(t, "velero", "rot")
	bv, bok := badSeries(t, "velero", "rot", "zero_items")
	if !pok || pv != 1 || !bok || bv != 1 {
		t.Fatalf("rot signatures not flagged before the resolve: paused=%v,%v zero_items=%v,%v",
			pv, pok, bv, bok)
	}

	// Schedule unpaused + a new healthy backup lands.
	u, err := dyn.Resource(veleroScheduleGVR).Namespace("velero").
		Get(ctx, "rot", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_ = unstructured.SetNestedField(u.Object, false, "spec", "paused")
	if _, err := dyn.Resource(veleroScheduleGVR).Namespace("velero").
		Update(ctx, u, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := dyn.Resource(veleroBackupGVR).Namespace("velero").Create(ctx,
		veleroBackup("velero", "b2", "rot", "Completed",
			time.Minute, 10, 100, 0, 0),
		metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if metrics.VeleroSchedulePaused.DeleteLabelValues("velero", "rot") {
		t.Fatal("paused series kept after the schedule unpaused")
	}
	if metrics.VeleroBackupEmptyOrErrored.DeleteLabelValues("velero", "rot", "zero_items") {
		t.Fatal("zero_items series kept after a healthy backup landed")
	}
}
