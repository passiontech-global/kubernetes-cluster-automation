// schedule_retry_test.go — unit tests for Velero automatic failed-backup
// retry in schedule_audit.go.
package velerobackupauditor

import (
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	kfake "k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func veleroBSL(ns, name, phase string) *unstructured.Unstructured {
	return testutil.Unstructured(
		veleroBSLGVR.GroupVersion().WithKind("BackupStorageLocation"), ns, name,
		map[string]any{
			"status": map[string]any{"phase": phase},
		})
}

func veleroScheduleWithTemplate(ns, name string, paused bool, storageLocation string, tpl map[string]any) *unstructured.Unstructured {
	if tpl == nil {
		tpl = map[string]any{
			"includedNamespaces": []any{"apps"},
			"ttl":                "168h0m0s",
		}
	}
	if storageLocation != "" {
		tpl["storageLocation"] = storageLocation
	}
	o := testutil.Unstructured(
		veleroScheduleGVR.GroupVersion().WithKind("Schedule"), ns, name,
		map[string]any{
			"spec": map[string]any{
				"paused":   paused,
				"schedule": "0 2 * * *",
				"template": tpl,
			},
		})
	o.SetUID(types.UID("uid-" + ns + "-" + name))
	o.SetCreationTimestamp(metav1.NewTime(time.Now().Add(-48 * time.Hour)))
	return o
}

func listBackups(t *testing.T, a *veleroBackupAuditor, ns string) []unstructured.Unstructured {
	t.Helper()
	list, err := a.dyn.Resource(veleroBackupGVR).Namespace(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list backups: %v", err)
	}
	return list.Items
}

// Failed + BSL Available -> creates 1 retry Backup with copied spec, schedule
// & retry-of labels, and patches AnnoLastVeleroBackupRetry onto Schedule.
func TestVeleroAutoRetryFailedBackupCreatesBackupAndPatchesSchedule(t *testing.T) {
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	sched := veleroScheduleWithTemplate("velero", "daily-cluster-backup", false, "", map[string]any{
		"includedNamespaces": []any{"apps", "data"},
		"ttl":                "72h0m0s",
		"metadata": map[string]any{
			"labels": map[string]any{"tier": "gold"},
		},
	})
	failed := veleroBackup("velero", "daily-cluster-backup-202611270200", "daily-cluster-backup",
		"Failed", time.Hour, 0, 0, 1, 0)
	bsl := veleroBSL("velero", "default", "Available")

	dyn := newDynFake(sched, failed, bsl)
	a := newVeleroAuditor(dyn, now)
	a.retryEnabled = true
	a.retryCooldown = 2 * time.Hour

	if err := a.run(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}

	backups := listBackups(t, a, "velero")
	if len(backups) != 2 {
		t.Fatalf("backups count = %d, want 2 (original failed + 1 retry)", len(backups))
	}
	var retried *unstructured.Unstructured
	for i := range backups {
		if backups[i].GetName() != failed.GetName() {
			retried = &backups[i]
			break
		}
	}
	if retried == nil {
		t.Fatal("retry backup not found")
	}
	if !strings.HasPrefix(retried.GetName(), "daily-cluster-backup-retry-") || len(retried.GetName()) > 63 {
		t.Fatalf("unexpected retry backup name: %q", retried.GetName())
	}
	if got := retried.GetLabels()[veleroScheduleLabel]; got != "daily-cluster-backup" {
		t.Fatalf("schedule label = %q, want daily-cluster-backup", got)
	}
	if got := retried.GetLabels()[kube.LabelVeleroRetryOf]; got != failed.GetName() {
		t.Fatalf("retry-of label = %q, want %q", got, failed.GetName())
	}
	if got := retried.GetLabels()["tier"]; got != "gold" {
		t.Fatalf("inherited template label tier = %q, want gold", got)
	}
	if ttl, _ := kube.NestedString(retried.Object, "spec", "ttl"); ttl != "72h0m0s" {
		t.Fatalf("copied spec.ttl = %q, want 72h0m0s", ttl)
	}

	gotSched, err := dyn.Resource(veleroScheduleGVR).Namespace("velero").
		Get(ctx, "daily-cluster-backup", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get schedule: %v", err)
	}
	if anno := gotSched.GetAnnotations()[kube.AnnoLastVeleroBackupRetry]; anno != failed.GetName() {
		t.Fatalf("schedule %s = %q, want %q", kube.AnnoLastVeleroBackupRetry, anno, failed.GetName())
	}
}

// Long schedule names must still produce a valid <=63-char retry Backup name.
func TestVeleroAutoRetryLongScheduleNameTruncatesTo63(t *testing.T) {
	now := time.Unix(1795661472, 0)
	longName := strings.Repeat("a", 55)
	got := veleroRetryBackupName(longName, now)
	if len(got) > 63 {
		t.Fatalf("retry name len = %d > 63: %q", len(got), got)
	}
	if !strings.HasSuffix(got, "-retry-1795661472") {
		t.Fatalf("retry name lost suffix: %q", got)
	}
}

// Already retried the same failed Backup (schedule annotation matches) -> no-op.
func TestVeleroAutoRetryAlreadyRetriedNoOp(t *testing.T) {
	now := time.Now()
	sched := veleroScheduleWithTemplate("velero", "daily", false, "", nil)
	sched.SetAnnotations(map[string]string{
		kube.AnnoLastVeleroBackupRetry: "daily-failed-1",
	})
	failed := veleroBackup("velero", "daily-failed-1", "daily", "PartiallyFailed", time.Hour, 0, 0, 1, 0)
	bsl := veleroBSL("velero", "default", "Available")

	a := newVeleroAuditor(newDynFake(sched, failed, bsl), now)
	a.retryEnabled = true
	if err := a.run(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := len(listBackups(t, a, "velero")); got != 1 {
		t.Fatalf("already-retried backup must not trigger a second retry, backups = %d", got)
	}
}

// BSL Unavailable (or custom storageLocation Unavailable) -> no-op.
func TestVeleroAutoRetryBSLUnavailableNoOp(t *testing.T) {
	now := time.Now()
	sched := veleroScheduleWithTemplate("velero", "daily", false, "offsite", nil)
	failed := veleroBackup("velero", "daily-failed-1", "daily", "FailedValidation", time.Hour, 0, 0, 1, 0)
	bslDefault := veleroBSL("velero", "default", "Available")
	bslOffsite := veleroBSL("velero", "offsite", "Unavailable")

	a := newVeleroAuditor(newDynFake(sched, failed, bslDefault, bslOffsite), now)
	a.retryEnabled = true
	if err := a.run(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := len(listBackups(t, a, "velero")); got != 1 {
		t.Fatalf("unavailable target BSL must block retry, backups = %d", got)
	}
}

// Another Backup of the same schedule in InProgress / New /
// WaitingForPluginOperations -> no-op.
func TestVeleroAutoRetryActiveBackupInFlightNoOp(t *testing.T) {
	for _, activePhase := range []string{"InProgress", "New", "WaitingForPluginOperations"} {
		t.Run(activePhase, func(t *testing.T) {
			now := time.Now()
			sched := veleroScheduleWithTemplate("velero", "daily", false, "", nil)
			// Older active backup + newer Failed backup -> latest is Failed,
			// but schedule still has an active backup in flight.
			active := veleroBackup("velero", "daily-active", "daily", activePhase, 2*time.Hour, 0, 0, 0, 0)
			failed := veleroBackup("velero", "daily-failed", "daily", "Failed", 30*time.Minute, 0, 0, 1, 0)
			bsl := veleroBSL("velero", "default", "Available")

			a := newVeleroAuditor(newDynFake(sched, active, failed, bsl), now)
			a.retryEnabled = true
			if err := a.run(ctx); err != nil {
				t.Fatalf("run: %v", err)
			}
			if got := len(listBackups(t, a, "velero")); got != 2 {
				t.Fatalf("active %s backup must block retry, backups = %d", activePhase, got)
			}
		})
	}
}

// Paused schedule -> no-op.
func TestVeleroAutoRetryPausedScheduleNoOp(t *testing.T) {
	now := time.Now()
	sched := veleroScheduleWithTemplate("velero", "daily", true, "", nil)
	failed := veleroBackup("velero", "daily-failed-1", "daily", "Failed", time.Hour, 0, 0, 1, 0)
	bsl := veleroBSL("velero", "default", "Available")

	a := newVeleroAuditor(newDynFake(sched, failed, bsl), now)
	a.retryEnabled = true
	if err := a.run(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := len(listBackups(t, a, "velero")); got != 1 {
		t.Fatalf("paused schedule must not retry, backups = %d", got)
	}
}

// Disabled (VELERO_FAILED_BACKUP_RETRY_ENABLED=false) -> no-op.
func TestVeleroAutoRetryDisabledNoOp(t *testing.T) {
	now := time.Now()
	sched := veleroScheduleWithTemplate("velero", "daily", false, "", nil)
	failed := veleroBackup("velero", "daily-failed-1", "daily", "Failed", time.Hour, 0, 0, 1, 0)
	bsl := veleroBSL("velero", "default", "Available")

	a := newVeleroAuditor(newDynFake(sched, failed, bsl), now)
	a.retryEnabled = false
	if err := a.run(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := len(listBackups(t, a, "velero")); got != 1 {
		t.Fatalf("disabled retry must not create backup, backups = %d", got)
	}
}

// Cooldown prevents retrying a second new failure within retryCooldown, and
// allows retrying once the cooldown elapses.
func TestVeleroAutoRetryRespectsCooldown(t *testing.T) {
	base := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	sched := veleroScheduleWithTemplate("velero", "daily", false, "", nil)
	failed1 := veleroBackup("velero", "daily-failed-1", "daily", "Failed", 2*time.Hour, 0, 0, 1, 0)
	bsl := veleroBSL("velero", "default", "Available")

	dyn := newDynFake(sched, failed1, bsl)
	a := newVeleroAuditor(dyn, base)
	a.retryEnabled = true
	a.retryCooldown = 2 * time.Hour

	if err := a.run(ctx); err != nil {
		t.Fatalf("sweep 1: %v", err)
	}
	if got := len(listBackups(t, a, "velero")); got != 2 {
		t.Fatalf("sweep 1 backups = %d, want 2", got)
	}

	// New failure 30m later (inside 2h cooldown) -> no retry.
	t2 := base.Add(30 * time.Minute)
	failed2 := veleroBackup("velero", "daily-failed-2", "daily", "Failed", 0, 0, 0, 1, 0)
	failed2.SetCreationTimestamp(metav1.NewTime(t2))
	if _, err := dyn.Resource(veleroBackupGVR).Namespace("velero").
		Create(ctx, failed2, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create failed2: %v", err)
	}
	a.now = func() time.Time { return t2 }
	if err := a.run(ctx); err != nil {
		t.Fatalf("sweep 2: %v", err)
	}
	if got := len(listBackups(t, a, "velero")); got != 3 {
		t.Fatalf("inside cooldown must not retry, backups = %d, want 3", got)
	}

	// Advance past 2h cooldown -> retries failed2.
	t3 := base.Add(2*time.Hour + time.Minute)
	a.now = func() time.Time { return t3 }
	if err := a.run(ctx); err != nil {
		t.Fatalf("sweep 3: %v", err)
	}
	if got := len(listBackups(t, a, "velero")); got != 4 {
		t.Fatalf("past cooldown must retry failed2, backups = %d, want 4", got)
	}
}

// Setup parses VELERO_FAILED_BACKUP_RETRY_ENABLED and
// VELERO_FAILED_BACKUP_RETRY_COOLDOWN without error.
func TestVeleroSetupParsesRetryEnvKnobs(t *testing.T) {
	t.Setenv("VELERO_FAILED_BACKUP_RETRY_ENABLED", "false")
	t.Setenv("VELERO_FAILED_BACKUP_RETRY_COOLDOWN", "4h")
	mgr := &testutil.StubManager{}
	err := Setup(shared.Deps{
		Name: "velero-backup-auditor",
		Mgr:  mgr,
		CS:   kfake.NewSimpleClientset(),
		Dyn:  newDynFake(),
	})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if len(mgr.Added) != 1 {
		t.Fatalf("registered %d runnables, want 1", len(mgr.Added))
	}
}
