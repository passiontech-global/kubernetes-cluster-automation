package velerobackupauditor

import (
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
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

// W8-ST1 — Failed/partial backups and wedged in-flight phases flag
// on their own reason series; BSLs not phase=Available raise the
// unavailable gauge.
func TestVeleroBackupAuditorFailedAndBSL(t *testing.T) {
	sched := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "velero.io/v1", "kind": "Schedule",
		"metadata": map[string]any{"namespace": "velero", "name": "daily"}}}
	failed := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "velero.io/v1", "kind": "Backup",
		"metadata": map[string]any{
			"namespace": "velero", "name": "daily-x",
			"labels": map[string]any{"velero.io/schedule-name": "daily"}},
		"status": map[string]any{"phase": "PartiallyFailed"}}}
	bsl := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "velero.io/v1", "kind": "BackupStorageLocation",
		"metadata": map[string]any{"namespace": "velero", "name": "main"},
		"status":   map[string]any{"phase": "Unavailable"}}}
	dyn := newDynFake(sched, failed, bsl)
	a := &veleroBackupAuditor{dyn: dyn, nowFn: time.Now,
		seenPaused: map[pausedKey]bool{}, seenBad: map[backupKey]bool{},
		seenBSL: map[pausedKey]bool{}, firstSeenPaused: map[pausedLedgerKey]time.Time{}}
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got, ok := testutil.GaugeSeriesValue(t, "node_automation_velero_backup_empty_or_errored",
		map[string]string{"namespace": "velero", "schedule": "daily", "reason": "failed"}); !ok || got != 1 {
		t.Fatal("failed-phase backup not flagged")
	}
	if got, ok := testutil.GaugeSeriesValue(t, "node_automation_velero_bsl_unavailable",
		map[string]string{"namespace": "velero", "name": "main"}); !ok || got != 1 {
		t.Fatal("unavailable BSL not flagged")
	}
}

// ---------------------------------------------------------------------------
// W9-ST3 — Everest DatabaseCluster backup auditor
// ---------------------------------------------------------------------------

// everestDBCluster builds a DatabaseCluster — backupEnabled toggles
// spec.backup.enabled, paused spec.paused.
func everestDBCluster(ns, name string, backupEnabled, paused bool) *unstructured.Unstructured {
	o := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "everest.percona.com/v1alpha1",
		"kind":       "DatabaseCluster",
		"metadata":   map[string]any{"namespace": ns, "name": name},
		"spec": map[string]any{
			"backup": map[string]any{"enabled": backupEnabled},
			"paused": paused,
		},
	}}
	return o
}

// everestBackup builds a DatabaseClusterBackup for cluster `dc` —
// state is status.state, age backs creationTimestamp, completion is
// status.completionTime (RFC3339, "" omits it).
func everestBackup(ns, name, dc, state string, age time.Duration,
	completion string) *unstructured.Unstructured {
	status := map[string]any{"state": state}
	if completion != "" {
		status["completionTime"] = completion
	}
	o := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "everest.percona.com/v1alpha1",
		"kind":       "DatabaseClusterBackup",
		"metadata":   map[string]any{"namespace": ns, "name": name},
		"spec":       map[string]any{"dbClusterName": dc},
		"status":     status,
	}}
	o.SetCreationTimestamp(metav1.NewTime(time.Now().Add(-age)))
	return o
}

func everestSeries(t *testing.T, ns, cluster, reason string) (float64, bool) {
	t.Helper()
	return testutil.GaugeSeriesValue(t, "node_automation_db_backup_unhealthy",
		map[string]string{
			"namespace": ns, "cluster": cluster, "reason": reason})
}

// A cluster whose LATEST backup Failed flags reason=failed; one with
// a Running backup older than 6h flags stuck; a newest Succeeded
// older than 36h flags stale — and a healthy cluster emits nothing.
func TestVeleroAuditorEverestBackupHealth(t *testing.T) {
	now := time.Now()
	failedCluster := everestDBCluster("data", "db-failed", true, false)
	failedBackup := everestBackup("data", "b-failed", "db-failed",
		"Failed", 2*time.Hour, now.Add(-2*time.Hour).Format(time.RFC3339))
	stuckCluster := everestDBCluster("data", "db-stuck", true, false)
	stuckBackup := everestBackup("data", "b-stuck", "db-stuck",
		"Running", 7*time.Hour, "")
	staleCluster := everestDBCluster("data", "db-stale", true, false)
	staleBackup := everestBackup("data", "b-stale", "db-stale",
		"Succeeded", 48*time.Hour,
		now.Add(-40*time.Hour).Format(time.RFC3339))
	healthyCluster := everestDBCluster("data", "db-ok", true, false)
	healthyBackup := everestBackup("data", "b-ok", "db-ok",
		"Succeeded", 2*time.Hour, now.Add(-time.Hour).Format(time.RFC3339))
	pausedCluster := everestDBCluster("data", "db-paused", true, true)
	pausedBackup := everestBackup("data", "b-paused", "db-paused",
		"Failed", 48*time.Hour, "")
	disabledCluster := everestDBCluster("data", "db-disabled", false, false)
	disabledBackup := everestBackup("data", "b-disabled", "db-disabled",
		"Failed", 48*time.Hour, "")

	a := newVeleroAuditor(newDynFake(
		failedCluster, failedBackup,
		stuckCluster, stuckBackup,
		staleCluster, staleBackup,
		healthyCluster, healthyBackup,
		pausedCluster, pausedBackup,
		disabledCluster, disabledBackup), now)
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if v, ok := everestSeries(t, "data", "db-failed", "failed"); !ok || v != 1 {
		t.Fatalf("db-failed/failed series = %v,%v want 1,true", v, ok)
	}
	if v, ok := everestSeries(t, "data", "db-stuck", "stuck"); !ok || v != 1 {
		t.Fatalf("db-stuck/stuck series = %v,%v want 1,true", v, ok)
	}
	if v, ok := everestSeries(t, "data", "db-stale", "stale"); !ok || v != 1 {
		t.Fatalf("db-stale/stale series = %v,%v want 1,true", v, ok)
	}
	for _, r := range []string{"failed", "stuck", "stale"} {
		if _, ok := everestSeries(t, "data", "db-ok", r); ok {
			t.Fatalf("healthy db-ok must emit no %s series", r)
		}
		if _, ok := everestSeries(t, "data", "db-paused", r); ok {
			t.Fatalf("paused db-paused must emit no %s series", r)
		}
		if _, ok := everestSeries(t, "data", "db-disabled", r); ok {
			t.Fatalf("backup-disabled db-disabled must emit no %s series", r)
		}
	}
}

// Recovery and deletion clear the series — the seen-set prune keeps
// /metrics honest once a cluster heals or disappears.
func TestVeleroAuditorEverestClearsResolved(t *testing.T) {
	now := time.Now()
	dc := everestDBCluster("data", "db", true, false)
	bad := everestBackup("data", "b1", "db", "Failed", time.Hour,
		now.Add(-time.Hour).Format(time.RFC3339))
	a := newVeleroAuditor(newDynFake(dc, bad), now)
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := everestSeries(t, "data", "db", "failed"); !ok {
		t.Fatal("failed backup must flag the cluster")
	}
	// The latest backup succeeds — the failed series must clear.
	good := everestBackup("data", "b2", "db", "Succeeded", 30*time.Minute,
		now.Add(-30*time.Minute).Format(time.RFC3339))
	if err := a.dyn.Resource(everestDBBackupGVR).Namespace("data").
		Delete(ctx, "b1", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.dyn.Resource(everestDBBackupGVR).Namespace("data").
		Create(ctx, good, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := everestSeries(t, "data", "db", "failed"); ok {
		t.Fatal("recovered cluster must not keep the failed series")
	}
}

// ---------------------------------------------------------------------------
// W10-FIX6 — zero-backup blind spot
// ---------------------------------------------------------------------------

// A Schedule older than 36h that has produced ZERO Backup objects
// flags reason=missing — the old code returned early on b == nil and
// never noticed the schedule was silently unprotected.
func TestVeleroAuditorScheduleMissingBackups(t *testing.T) {
	now := time.Now()
	old := veleroSchedule("velero", "daily-old", false, 48*time.Hour)
	young := veleroSchedule("velero", "daily-young", false, 10*time.Hour)
	pausedOld := veleroSchedule("velero", "daily-paused", true, 72*time.Hour)
	dyn := newDynFake(old, young, pausedOld)
	a := newVeleroAuditor(dyn, now)
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if v, ok := badSeries(t, "velero", "daily-old", "missing"); !ok || v != 1 {
		t.Fatalf("old zero-backup schedule missing series = %v,%v want 1,true", v, ok)
	}
	for _, s := range []string{"daily-young", "daily-paused"} {
		if _, ok := badSeries(t, "velero", s, "missing"); ok {
			t.Fatalf("%s must not flag missing", s)
		}
	}
}

// The same zero-backup check applies to backup-enabled Everest
// DatabaseClusters: >36h old with zero DatabaseClusterBackups.
func TestVeleroAuditorEverestMissingBackups(t *testing.T) {
	now := time.Now()
	oldDC := everestDBCluster("data", "db-old", true, false)
	oldDC.SetCreationTimestamp(metav1.NewTime(now.Add(-48 * time.Hour)))
	youngDC := everestDBCluster("data", "db-young", true, false)
	youngDC.SetCreationTimestamp(metav1.NewTime(now.Add(-10 * time.Hour)))
	disabledDC := everestDBCluster("data", "db-disabled", false, false)
	disabledDC.SetCreationTimestamp(metav1.NewTime(now.Add(-72 * time.Hour)))
	a := newVeleroAuditor(newDynFake(oldDC, youngDC, disabledDC), now)
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if v, ok := everestSeries(t, "data", "db-old", "missing"); !ok || v != 1 {
		t.Fatalf("db-old/missing series = %v,%v want 1,true", v, ok)
	}
	for _, c := range []string{"db-young", "db-disabled"} {
		if _, ok := everestSeries(t, "data", c, "missing"); ok {
			t.Fatalf("%s must not flag missing", c)
		}
	}
}

// ---------------------------------------------------------------------------
// W10-ST6 — wedged in-flight Backup / PodVolumeBackup audit
// ---------------------------------------------------------------------------

// veleroPVB builds a PodVolumeBackup — phase + startTimestamp drive
// the wedge verdict; spec.node names the node whose node-agent owns
// the Kopia thread (spec.pod is the workload pod, unused here).
func veleroPVB(ns, name, phase string, age time.Duration,
	pod, node string) *unstructured.Unstructured {
	start := time.Now().Add(-age).UTC().Format(time.RFC3339)
	o := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "velero.io/v1",
		"kind":       "PodVolumeBackup",
		"metadata":   map[string]any{"namespace": ns, "name": name},
		"spec": map[string]any{
			"pod":  map[string]any{"name": pod},
			"node": node,
		},
		"status": map[string]any{
			"phase":          phase,
			"startTimestamp": start,
		},
	}}
	o.SetUID(types.UID(ns + "/" + name))
	o.SetCreationTimestamp(metav1.NewTime(time.Now().Add(-age)))
	return o
}

// nodeAgentPod builds the velero node-agent DaemonSet pod — start
// times drive the "agent restarted mid-backup" verdict.
func nodeAgentPod(ns, name, node string, podStart, containerStart time.Time) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: ns,
			Labels: map[string]string{"name": "node-agent"},
		},
		Spec: corev1.PodSpec{NodeName: node},
		Status: corev1.PodStatus{
			Phase:     corev1.PodRunning,
			StartTime: &metav1.Time{Time: podStart},
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:  "node-agent",
				State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.Time{Time: containerStart}}},
			}},
		},
	}
}

func pvbExists(t *testing.T, dyn *fake.FakeDynamicClient, ns, name string) bool {
	t.Helper()
	_, err := dyn.Resource(veleroPVBGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	return err == nil
}

func stuckSeries(t *testing.T, ns, backup string) (float64, bool) {
	t.Helper()
	return testutil.GaugeSeriesValue(t, "node_automation_velero_backup_stuck",
		map[string]string{"namespace": ns, "backup": backup})
}

func wedgedSeries(t *testing.T, ns, pvb string) (float64, bool) {
	t.Helper()
	return testutil.GaugeSeriesValue(t, "node_automation_velero_podvolumebackup_wedged",
		map[string]string{"namespace": ns, "pvb": pvb})
}

// A Backup held InProgress >6h marks the stuck gauge; a fresh one
// and a Completed one do not.
func TestVeleroAuditorStuckBackupGauge(t *testing.T) {
	now := time.Now()
	stuck := veleroBackup("velero", "b-stuck", "daily", "InProgress", 7*time.Hour, 0, 0, 0, 0)
	fresh := veleroBackup("velero", "b-fresh", "daily", "InProgress", time.Hour, 0, 0, 0, 0)
	done := veleroBackup("velero", "b-done", "daily", "Completed", 7*time.Hour, 5, 5, 0, 0)
	dyn := newDynFake(
		veleroSchedule("velero", "daily", false, time.Hour),
		stuck, fresh, done)
	a := newVeleroAuditor(dyn, now)
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if v, ok := stuckSeries(t, "velero", "b-stuck"); !ok || v != 1 {
		t.Fatalf("b-stuck series = %v,%v want 1,true", v, ok)
	}
	for _, n := range []string{"b-fresh", "b-done"} {
		if _, ok := stuckSeries(t, "velero", n); ok {
			t.Fatalf("%s must not flag stuck", n)
		}
	}
}

// The full ST6 cleanup: a PVB InProgress >6h whose node-agent
// container restarted AFTER the PVB started is deleted, and the
// agent pod is bounced so the next backup starts clean.
func TestVeleroAuditorWedgedPVBCleaned(t *testing.T) {
	now := time.Now()
	pvb := veleroPVB("velero", "pvb-1", "InProgress", 7*time.Hour,
		"node-agent-aaa", "node-1")
	// Agent pod itself is old (started before the PVB) but its
	// container restarted 6h ago — after the PVB began 7h ago.
	agent := nodeAgentPod("velero", "node-agent-aaa", "node-1",
		now.Add(-24*time.Hour), now.Add(-6*time.Hour))
	cs := kfake.NewSimpleClientset(agent)
	dyn := newDynFake(
		veleroSchedule("velero", "daily", false, time.Hour),
		pvb)
	a := newVeleroAuditor(dyn, now)
	a.cs = cs
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if pvbExists(t, dyn, "velero", "pvb-1") {
		t.Fatal("wedged PVB not deleted")
	}
	if _, err := cs.CoreV1().Pods("velero").Get(ctx, "node-agent-aaa",
		metav1.GetOptions{}); err == nil {
		t.Fatal("node-agent pod not bounced")
	}
	if v, ok := wedgedSeries(t, "velero", "pvb-1"); !ok || v != 1 {
		t.Fatalf("pvb-1 wedged series = %v,%v want 1,true", v, ok)
	}
}

// A PVB whose agent pod is healthy (Running, started before the
// PVB, no restarts) is marked wedged-age but NOT cleaned — the
// agent still owns the Kopia thread.
func TestVeleroAuditorWedgedPVBHealthyAgentKept(t *testing.T) {
	now := time.Now()
	pvb := veleroPVB("velero", "pvb-ok", "InProgress", 7*time.Hour,
		"node-agent-bbb", "node-2")
	agent := nodeAgentPod("velero", "node-agent-bbb", "node-2",
		now.Add(-24*time.Hour), now.Add(-24*time.Hour))
	cs := kfake.NewSimpleClientset(agent)
	dyn := newDynFake(
		veleroSchedule("velero", "daily", false, time.Hour),
		pvb)
	a := newVeleroAuditor(dyn, now)
	a.cs = cs
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !pvbExists(t, dyn, "velero", "pvb-ok") {
		t.Fatal("PVB deleted although its node-agent is healthy")
	}
	if _, err := cs.CoreV1().Pods("velero").Get(ctx, "node-agent-bbb",
		metav1.GetOptions{}); err != nil {
		t.Fatal("healthy node-agent pod bounced")
	}
	// Still old enough to mark — the gauge reports the wedge age
	// even when the agent looks alive.
	if v, ok := wedgedSeries(t, "velero", "pvb-ok"); !ok || v != 1 {
		t.Fatalf("pvb-ok wedged series = %v,%v want 1,true", v, ok)
	}
}

// A PVB in Deleting is marked but never cleaned — it is already on
// its way out; deleting it again buys nothing.
func TestVeleroAuditorDeletingPVBNotCleaned(t *testing.T) {
	now := time.Now()
	pvb := veleroPVB("velero", "pvb-del", "Deleting", 8*time.Hour,
		"node-agent-ccc", "node-3")
	dyn := newDynFake(
		veleroSchedule("velero", "daily", false, time.Hour),
		pvb)
	a := newVeleroAuditor(dyn, now)
	a.cs = kfake.NewSimpleClientset() // no agent pod at all
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !pvbExists(t, dyn, "velero", "pvb-del") {
		t.Fatal("Deleting PVB deleted — already terminating")
	}
	if v, ok := wedgedSeries(t, "velero", "pvb-del"); !ok || v != 1 {
		t.Fatalf("pvb-del wedged series = %v,%v want 1,true", v, ok)
	}
}

// Clusters without the Everest CRDs are a quiet no-op — same
// contract as the Velero half of this module.
func TestVeleroAuditorEverestCRDAbsent(t *testing.T) {
	// newDynFake registers the GVRs; an absent-CRD cluster is
	// simulated by a dyn fake whose List reactor 404s the Everest
	// resources — auditEverestBackups must return nil, not error.
	dyn := newDynFake()
	dyn.PrependReactor("list", "databaseclusters",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewNotFound(
				schema.GroupResource{Group: "everest.percona.com", Resource: "databaseclusters"}, "x")
		})
	a := newVeleroAuditor(dyn, time.Now())
	if err := a.auditEverestBackups(ctx); err != nil {
		t.Fatalf("absent Everest CRDs must be a quiet no-op: %v", err)
	}
}
