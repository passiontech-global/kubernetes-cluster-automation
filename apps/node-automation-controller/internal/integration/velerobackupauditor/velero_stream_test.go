// velero_stream_test.go — proof that the Backup/Schedule audits work
// on per-page callbacks rather than a collected whole list: a rot
// signature carried by a Backup on a later page is still found by
// collectBackups + auditSchedules + auditInFlightTransfers.
package velerobackupauditor

import (
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	ktesting "k8s.io/client-go/testing"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// The single streaming Backup read keeps the newest Backup per
// Schedule from EVERY page. A rot signature on page two is therefore
// still matched when page one's Schedule is audited.
func TestCollectBackupsStreamsEveryPage(t *testing.T) {
	now := time.Now()
	sched := veleroSchedule("velero", "rot", false, 48*time.Hour)
	// The latest backup for "rot" lands on the second page.
	late := veleroBackup("velero", "late", "rot", "Completed",
		time.Hour, 0, 0, 0, 0)
	dyn := newDynFake(sched)
	pages := 0
	dyn.PrependReactor("list", "backups",
		func(ktesting.Action) (bool, runtime.Object, error) {
			pages++
			list := &unstructured.UnstructuredList{}
			if pages == 1 {
				list.SetContinue("next-page")
			} else {
				list.Items = []unstructured.Unstructured{*late}
			}
			return true, list, nil
		})
	a := newVeleroAuditor(dyn, now)

	latest, _, stuck, err := a.collectBackups(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pages != 2 {
		t.Fatalf("backup list calls = %d, want 2", pages)
	}
	if got := latest["velero/rot"]; got == nil || got.GetName() != "late" {
		t.Fatalf("latest backup from page 2 not collected: %v", latest)
	}
	if len(stuck) != 0 {
		t.Fatalf("unexpected in-flight subset: %d", len(stuck))
	}
	// Page bodies are DeepCopied into the derived state — mutating
	// the source object must not change what the audit will judge.
	late.SetLabels(map[string]string{veleroScheduleLabel: "other"})
	if got := latest["velero/rot"]; got == nil ||
		got.GetLabels()[veleroScheduleLabel] != "rot" {
		t.Fatal("collected backup aliases the page body")
	}
}

// auditSchedules streams the Schedule census page by page: a paused
// Schedule on page two still gets its first-seen stamp and gauge.
func TestAuditSchedulesStreamsEveryPage(t *testing.T) {
	now := time.Now()
	dyn := newDynFake()
	pages := 0
	dyn.PrependReactor("list", "schedules",
		func(ktesting.Action) (bool, runtime.Object, error) {
			pages++
			list := &unstructured.UnstructuredList{}
			if pages == 1 {
				list.Items = []unstructured.Unstructured{
					*veleroSchedule("velero", "first", false, time.Hour)}
				list.SetContinue("next-page")
			} else {
				list.Items = []unstructured.Unstructured{
					*veleroSchedule("velero", "second", false, time.Hour)}
			}
			return true, list, nil
		})
	a := newVeleroAuditor(dyn, now)
	a.seenPaused.Begin()

	present, count, err := a.auditSchedules(ctx, nil, nil, logf.FromContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	if !present || pages != 2 || count != 2 {
		t.Fatalf("present=%v pages=%d count=%d, want true/2/2", present, pages, count)
	}
}

// The in-flight subset is collected from its own page walk — a wedged
// Backup on a later page is marked by the wedge audit after the
// collected subset is passed in.
func TestInFlightSubsetCollectedFromEveryPage(t *testing.T) {
	now := time.Now()
	dyn := newDynFake()
	pages := 0
	dyn.PrependReactor("list", "backups",
		func(ktesting.Action) (bool, runtime.Object, error) {
			pages++
			list := &unstructured.UnstructuredList{}
			if pages == 1 {
				list.SetContinue("next-page")
			} else {
				list.Items = []unstructured.Unstructured{
					*veleroBackup("velero", "wedged", "rot", "InProgress",
						8*time.Hour, 0, 0, 0, 0)}
			}
			return true, list, nil
		})
	a := newVeleroAuditor(dyn, now)

	_, _, stuck, err := a.collectBackups(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pages != 2 || len(stuck) != 1 || stuck[0].GetName() != "wedged" {
		t.Fatalf("pages=%d stuck=%v, want 2 and one 'wedged'", pages, stuck)
	}
	// The subset is independent of the page's lifetime.
	a.seenStuckBackup.Begin()
	if err := a.auditInFlightTransfers(ctx, stuck); err != nil {
		t.Fatal(err)
	}
	if v, ok := testutil.GaugeSeriesValue(t,
		"node_automation_velero_backup_stuck",
		map[string]string{"namespace": "velero", "backup": "wedged"}); !ok || v != 1 {
		t.Fatalf("wedged backup on page 2 not marked: value=%v ok=%v", v, ok)
	}
}
