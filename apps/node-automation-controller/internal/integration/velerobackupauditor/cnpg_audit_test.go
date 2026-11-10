// cnpg_audit_test.go — coverage for the cnpg-backup-audit CloudNativePG backup
// audit: the classification matrix (failed / stuck / stale), the
// end-to-end audit against a fake dynamic client (missing, suspend
// skip, resolve-and-clear), and the cnpg-backup-audit DataUpload/DataDownload
// wedge scan.
package velerobackupauditor

import (
	"slices"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

// cnpgScheduledBackup builds a ScheduledBackup bound to cluster
// `cluster` — suspend toggles spec.suspend, age backs
// creationTimestamp.
func cnpgScheduledBackup(ns, name, cluster string, suspend bool,
	age time.Duration) *unstructured.Unstructured {
	o := testutil.Unstructured(
		cnpgScheduledBackupGVR.GroupVersion().WithKind("ScheduledBackup"),
		ns, name,
		map[string]any{
			"spec": map[string]any{
				"clusterName": cluster,
				"suspend":     suspend,
			},
		})
	o.SetCreationTimestamp(metav1.NewTime(time.Now().Add(-age)))
	return o
}

// cnpgBackup builds a Backup for cluster `cluster` — phase is
// status.phase, age backs creationTimestamp, started/stopped are
// status.startedAt / status.stoppedAt (RFC3339, "" omits them).
// Completed backups get healthy Barman restore metadata by default
// (method + backupId + beginWal) so the selfheal-alert-coverage empty_metadata check
// stays quiet — tests for that signature strip the fields after
// building.
func cnpgBackup(ns, name, cluster, phase string, age time.Duration,
	started, stopped string) *unstructured.Unstructured {
	status := map[string]any{"phase": phase}
	if started != "" {
		status["startedAt"] = started
	}
	if stopped != "" {
		status["stoppedAt"] = stopped
	}
	if phase == "completed" {
		status["method"] = "barmanObjectStore"
		status["backupId"] = "20261110T120000"
		status["beginWal"] = "0000000100000000000000A1"
	}
	o := testutil.Unstructured(
		cnpgBackupGVR.GroupVersion().WithKind("Backup"), ns, name,
		map[string]any{
			"spec":   map[string]any{"clusterName": cluster},
			"status": status,
		})
	o.SetCreationTimestamp(metav1.NewTime(time.Now().Add(-age)))
	return o
}

func cnpgSeries(t *testing.T, ns, cluster, reason string) (float64, bool) {
	t.Helper()
	return testutil.GaugeSeriesValue(t, "node_automation_db_backup_unhealthy",
		map[string]string{
			"namespace": ns, "cluster": cluster, "reason": reason})
}

func dmSeries(t *testing.T, ns, name, kind string) (float64, bool) {
	t.Helper()
	return testutil.GaugeSeriesValue(t, "node_automation_velero_data_movement_wedged",
		map[string]string{"namespace": ns, "name": name, "kind": kind})
}

// ---------------------------------------------------------------------------
// Pure classification matrix
// ---------------------------------------------------------------------------

// The reason matrix: the latest backup failed → failed; a backup
// running past 6h → stuck; the newest completed older than 36h →
// stale; a young healthy history → nothing; an empty list → nothing
// (missing is the caller's schedule-age judgment).
func TestCNPGBackupReasonsMatrix(t *testing.T) {
	now := time.Now()
	rfc := func(d time.Duration) string { return now.Add(-d).Format(time.RFC3339) }

	t.Run("failed", func(t *testing.T) {
		got := cnpgBackupReasons([]*unstructured.Unstructured{
			cnpgBackup("data", "b1", "db", "failed", 2*time.Hour, rfc(2*time.Hour), rfc(time.Hour)),
		}, now)
		if len(got) != 1 || got[0] != "failed" {
			t.Fatalf("want [failed], got %v", got)
		}
	})
	t.Run("failed only when latest", func(t *testing.T) {
		// An old failed backup under a newer completed one is history.
		newer := cnpgBackup("data", "b2", "db", "completed", 30*time.Minute,
			rfc(time.Hour), rfc(30*time.Minute))
		newer.SetCreationTimestamp(metav1.NewTime(now.Add(-30 * time.Minute)))
		older := cnpgBackup("data", "b1", "db", "failed", 2*time.Hour,
			rfc(3*time.Hour), rfc(2*time.Hour))
		older.SetCreationTimestamp(metav1.NewTime(now.Add(-2 * time.Hour)))
		if got := cnpgBackupReasons([]*unstructured.Unstructured{older, newer}, now); len(got) != 0 {
			t.Fatalf("recovered history must be clean, got %v", got)
		}
	})
	t.Run("stuck", func(t *testing.T) {
		got := cnpgBackupReasons([]*unstructured.Unstructured{
			cnpgBackup("data", "b1", "db", "running", 7*time.Hour, rfc(7*time.Hour), ""),
		}, now)
		if len(got) != 1 || got[0] != "stuck" {
			t.Fatalf("want [stuck], got %v", got)
		}
	})
	t.Run("young running not stuck", func(t *testing.T) {
		got := cnpgBackupReasons([]*unstructured.Unstructured{
			cnpgBackup("data", "b1", "db", "running", time.Hour, rfc(time.Hour), ""),
		}, now)
		if len(got) != 0 {
			t.Fatalf("a 1h running backup is not stuck, got %v", got)
		}
	})
	t.Run("stale", func(t *testing.T) {
		got := cnpgBackupReasons([]*unstructured.Unstructured{
			cnpgBackup("data", "b1", "db", "completed", 40*time.Hour,
				rfc(41*time.Hour), rfc(40*time.Hour)),
		}, now)
		if len(got) != 1 || got[0] != "stale" {
			t.Fatalf("want [stale], got %v", got)
		}
	})
	t.Run("stale falls back to startedAt then creation", func(t *testing.T) {
		if got := cnpgBackupReasons([]*unstructured.Unstructured{
			cnpgBackup("data", "b1", "db", "completed", 40*time.Hour, rfc(41*time.Hour), ""),
		}, now); len(got) != 1 || got[0] != "stale" {
			t.Fatalf("startedAt fallback must flag stale, got %v", got)
		}
		if got := cnpgBackupReasons([]*unstructured.Unstructured{
			cnpgBackup("data", "b1", "db", "completed", 40*time.Hour, "", ""),
		}, now); len(got) != 1 || got[0] != "stale" {
			t.Fatalf("creationTimestamp fallback must flag stale, got %v", got)
		}
	})
	t.Run("stuck and stale co-flag", func(t *testing.T) {
		got := cnpgBackupReasons([]*unstructured.Unstructured{
			cnpgBackup("data", "b1", "db", "completed", 40*time.Hour,
				rfc(41*time.Hour), rfc(40*time.Hour)),
			cnpgBackup("data", "b2", "db", "running", 7*time.Hour, rfc(7*time.Hour), ""),
		}, now)
		if len(got) != 2 {
			t.Fatalf("want [stuck stale], got %v", got)
		}
	})
	t.Run("healthy and empty", func(t *testing.T) {
		if got := cnpgBackupReasons([]*unstructured.Unstructured{
			cnpgBackup("data", "b1", "db", "completed", 2*time.Hour,
				rfc(3*time.Hour), rfc(2*time.Hour)),
		}, now); len(got) != 0 {
			t.Fatalf("healthy history must be clean, got %v", got)
		}
		if got := cnpgBackupReasons(nil, now); got != nil {
			t.Fatalf("empty list must judge nothing, got %v", got)
		}
	})

	// selfheal-alert-coverage empty_metadata — a completed backup with no usable restore
	// metadata: status.error set, or a Barman backup missing BOTH
	// backupId and beginWal. volumeSnapshot backups legitimately
	// carry neither WAL field.
	stripMeta := func(b *unstructured.Unstructured) *unstructured.Unstructured {
		st := b.Object["status"].(map[string]any)
		delete(st, "backupId")
		delete(st, "beginWal")
		return b
	}
	t.Run("empty_metadata barman no wal", func(t *testing.T) {
		got := cnpgBackupReasons([]*unstructured.Unstructured{
			stripMeta(cnpgBackup("data", "b1", "db", "completed", 2*time.Hour,
				rfc(3*time.Hour), rfc(2*time.Hour))),
		}, now)
		if !contains(got, "empty_metadata") {
			t.Fatalf("barman backup without backupId/beginWal must flag empty_metadata, got %v", got)
		}
	})
	t.Run("empty_metadata status error", func(t *testing.T) {
		b := cnpgBackup("data", "b1", "db", "completed", 2*time.Hour,
			rfc(3*time.Hour), rfc(2*time.Hour))
		b.Object["status"].(map[string]any)["error"] = "wal archiving failed"
		if got := cnpgBackupReasons([]*unstructured.Unstructured{b}, now); !contains(got, "empty_metadata") {
			t.Fatalf("completed backup with status.error must flag empty_metadata, got %v", got)
		}
	})
	t.Run("volumeSnapshot exempt from wal check", func(t *testing.T) {
		b := stripMeta(cnpgBackup("data", "b1", "db", "completed", 2*time.Hour,
			rfc(3*time.Hour), rfc(2*time.Hour)))
		b.Object["status"].(map[string]any)["method"] = "volumeSnapshot"
		if got := cnpgBackupReasons([]*unstructured.Unstructured{b}, now); contains(got, "empty_metadata") {
			t.Fatalf("volumeSnapshot backup must not flag empty_metadata, got %v", got)
		}
	})
}

// ---------------------------------------------------------------------------
// End-to-end audit
// ---------------------------------------------------------------------------

// The audit marks failed/stuck/stale on the owning cluster, skips a
// suspended schedule, and stays quiet on a healthy one.
func contains(list []string, s string) bool {
	return slices.Contains(list, s)
}

func TestVeleroAuditorCNPGBackupHealth(t *testing.T) {
	now := time.Now()
	rfc := func(d time.Duration) string { return now.Add(-d).Format(time.RFC3339) }
	objs := []runtime.Object{
		cnpgScheduledBackup("data", "sb-failed", "db-failed", false, 48*time.Hour),
		cnpgBackup("data", "b-failed", "db-failed", "failed", 2*time.Hour,
			rfc(2*time.Hour), rfc(time.Hour)),

		cnpgScheduledBackup("data", "sb-stuck", "db-stuck", false, 48*time.Hour),
		cnpgBackup("data", "b-stuck", "db-stuck", "running", 7*time.Hour,
			rfc(7*time.Hour), ""),

		cnpgScheduledBackup("data", "sb-stale", "db-stale", false, 96*time.Hour),
		cnpgBackup("data", "b-stale", "db-stale", "completed", 40*time.Hour,
			rfc(41*time.Hour), rfc(40*time.Hour)),

		cnpgScheduledBackup("data", "sb-suspended", "db-suspended", true, 96*time.Hour),
		cnpgBackup("data", "b-old", "db-suspended", "completed", 96*time.Hour,
			rfc(97*time.Hour), rfc(96*time.Hour)),

		cnpgScheduledBackup("data", "sb-ok", "db-ok", false, 48*time.Hour),
		cnpgBackup("data", "b-ok", "db-ok", "completed", 2*time.Hour,
			rfc(3*time.Hour), rfc(2*time.Hour)),
	}
	a := newVeleroAuditor(newDynFake(objs...), now)
	if err := a.auditCNPGBackups(ctx); err != nil {
		t.Fatalf("audit: %v", err)
	}
	// selfheal-alert-coverage: db-failed and db-stuck hold backup objects but NONE ever
	// completed — past the 36h schedule age they co-flag stale
	// (zero-completed-history) beside their primary reason.
	for cluster, want := range map[string][]string{
		"db-failed":    {"failed", "stale"},
		"db-stuck":     {"stuck", "stale"},
		"db-stale":     {"stale"},
		"db-suspended": nil,
		"db-ok":        nil,
	} {
		for _, reason := range []string{"failed", "stuck", "stale", "missing", "empty_metadata"} {
			v, ok := cnpgSeries(t, "data", cluster, reason)
			shouldBe := contains(want, reason)
			if ok != shouldBe || (shouldBe && v != 1) {
				t.Fatalf("cluster %s reason %s: want series=%v, got (%v,%v)",
					cluster, reason, shouldBe, v, ok)
			}
		}
	}
}

// A schedule older than 36h whose cluster produced ZERO backups
// flags missing; a young schedule does not.
func TestVeleroAuditorCNPGMissingBackups(t *testing.T) {
	old := cnpgScheduledBackup("data", "sb-old", "db-old", false, 48*time.Hour)
	young := cnpgScheduledBackup("data", "sb-young", "db-young", false, time.Hour)
	a := newVeleroAuditor(newDynFake(old, young), time.Now())
	if err := a.auditCNPGBackups(ctx); err != nil {
		t.Fatalf("audit: %v", err)
	}
	if v, ok := cnpgSeries(t, "data", "db-old", "missing"); !ok || v != 1 {
		t.Fatal("a 48h schedule with zero backups must flag missing")
	}
	if _, ok := cnpgSeries(t, "data", "db-young", "missing"); ok {
		t.Fatal("a 1h schedule with zero backups must not flag missing")
	}
}

// A recovered history clears the previous sweep's series.
func TestVeleroAuditorCNPGClearsResolved(t *testing.T) {
	now := time.Now()
	rfc := func(d time.Duration) string { return now.Add(-d).Format(time.RFC3339) }
	sb := cnpgScheduledBackup("data", "sb", "db", false, 48*time.Hour)
	bad := cnpgBackup("data", "b1", "db", "failed", 2*time.Hour,
		rfc(2*time.Hour), rfc(time.Hour))
	a := newVeleroAuditor(newDynFake(sb, bad), now)
	if err := a.auditCNPGBackups(ctx); err != nil {
		t.Fatalf("audit: %v", err)
	}
	if _, ok := cnpgSeries(t, "data", "db", "failed"); !ok {
		t.Fatal("failed backup must flag")
	}

	// Repair IN PLACE through the same fake client — a fresh auditor
	// carries an empty ledger and could never prune the old series.
	status := bad.Object["status"].(map[string]any)
	status["phase"] = "completed"
	status["stoppedAt"] = rfc(30 * time.Minute)
	if _, err := a.dyn.Resource(cnpgBackupGVR).Namespace("data").
		Update(ctx, bad, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update backup: %v", err)
	}
	if err := a.auditCNPGBackups(ctx); err != nil {
		t.Fatalf("audit: %v", err)
	}
	if _, ok := cnpgSeries(t, "data", "db", "failed"); ok {
		t.Fatal("a newer completed backup must clear the failed series")
	}
}

// CNPG CRDs absent (404) — a quiet no-op that still clears stale
// series.
func TestVeleroAuditorCNPGCRDAbsent(t *testing.T) {
	// newDynFake() registers the CNPG GVRs; seed nothing — the list
	// returns empty (CRD "not installed" is indistinguishable from
	// "no schedules" through the fake, and both must no-op quietly).
	a := newVeleroAuditor(newDynFake(), time.Now())
	if err := a.auditCNPGBackups(ctx); err != nil {
		t.Fatalf("absent CNPG CRDs must skip cleanly, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// cnpg-backup-audit — DataUpload / DataDownload wedge scan
// ---------------------------------------------------------------------------

// DataUpload/DataDownload objects stuck in an in-flight phase past
// 6h are marked with their kind; young ones and terminal phases are
// not.
func TestVeleroAuditorDataMovementWedged(t *testing.T) {
	now := time.Now()
	rfc := func(d time.Duration) string { return now.Add(-d).Format(time.RFC3339) }

	buildDM := func(gvr schema.GroupVersionResource, kind, ns, name, phase string,
		age time.Duration, started string) *unstructured.Unstructured {
		status := map[string]any{"phase": phase}
		// velero.io/v2alpha1 DU/DD carry status.startedAt (the PVB
		// startTimestamp field does not exist on these kinds).
		if started != "" {
			status["startedAt"] = started
		}
		o := testutil.Unstructured(
			gvr.GroupVersion().WithKind(kind), ns, name,
			map[string]any{"status": status})
		o.SetCreationTimestamp(metav1.NewTime(now.Add(-age)))
		return o
	}

	objs := []runtime.Object{
		buildDM(kube.GVRVeleroDataUpload, "DataUpload", "velero", "du-old", "InProgress", 7*time.Hour, rfc(7*time.Hour)),
		buildDM(kube.GVRVeleroDataUpload, "DataUpload", "velero", "du-young", "InProgress", time.Hour, rfc(time.Hour)),
		buildDM(kube.GVRVeleroDataUpload, "DataUpload", "velero", "du-accepted", "Accepted", 8*time.Hour, ""),
		buildDM(kube.GVRVeleroDataUpload, "DataUpload", "velero", "du-prepared", "Prepared", 8*time.Hour, ""),
		buildDM(kube.GVRVeleroDataUpload, "DataUpload", "velero", "du-canceling", "Canceling", 7*time.Hour, ""),
		buildDM(kube.GVRVeleroDataUpload, "DataUpload", "velero", "du-done", "Completed", 9*time.Hour, rfc(9*time.Hour)),
		buildDM(kube.GVRVeleroDataDownload, "DataDownload", "velero", "dd-old", "Prepared", 8*time.Hour, ""),
	}
	a := newVeleroAuditor(newDynFake(objs...), now)
	if err := a.auditDataMovement(ctx); err != nil {
		t.Fatalf("audit: %v", err)
	}
	for _, tc := range []struct {
		name, kind string
		want       bool
	}{
		{"du-old", "datauploads", true},
		{"du-young", "datauploads", false},
		{"du-accepted", "datauploads", true},
		{"du-prepared", "datauploads", true},
		{"du-canceling", "datauploads", true},
		{"du-done", "datauploads", false},
		{"dd-old", "datadownloads", true},
	} {
		v, ok := dmSeries(t, "velero", tc.name, tc.kind)
		if ok != tc.want || (tc.want && v != 1) {
			t.Fatalf("%s/%s: want wedged=%v, got (%v,%v)",
				tc.kind, tc.name, tc.want, v, ok)
		}
	}

	// A resolved object's series is pruned on the next sweep — the
	// repair goes through the SAME auditor/fake client, since a
	// fresh auditor carries an empty ledger and could never prune
	// the old series.
	for _, o := range objs {
		u := o.(*unstructured.Unstructured)
		if u.GetName() != "du-old" {
			continue
		}
		u.Object["status"].(map[string]any)["phase"] = "Completed"
		if _, err := a.dyn.Resource(kube.GVRVeleroDataUpload).
			Namespace("velero").Update(ctx, u, metav1.UpdateOptions{}); err != nil {
			t.Fatalf("update dataupload: %v", err)
		}
	}
	if err := a.auditDataMovement(ctx); err != nil {
		t.Fatalf("audit: %v", err)
	}
	if _, ok := dmSeries(t, "velero", "du-old", "datauploads"); ok {
		t.Fatal("a completed DataUpload must lose its wedged series")
	}
}
