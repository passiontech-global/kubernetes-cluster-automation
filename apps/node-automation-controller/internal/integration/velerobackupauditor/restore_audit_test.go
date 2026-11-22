// restore_audit_test.go — non-parallel table-driven unit tests for R6-K9a
// velero.io/v1 Restore stuck-InProgress detection, Warning Events,
// wedged velero server pod bounce via heal.EvictPodV, CRD-absent skip,
// and coexistence with Backup/PodVolumeBackup/PodVolumeRestore.
package velerobackupauditor

import (
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"
	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kfake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func veleroPVR(ns, name, phase string, age time.Duration, pod, node string) *unstructured.Unstructured {
	start := time.Now().Add(-age).UTC().Format(time.RFC3339)
	o := testutil.Unstructured(
		veleroPVRGVR.GroupVersion().WithKind("PodVolumeRestore"), ns, name,
		map[string]any{
			"spec": map[string]any{
				"pod":  map[string]any{"name": pod},
				"node": node,
			},
			"status": map[string]any{
				"phase":          phase,
				"startTimestamp": start,
			},
		})
	o.SetUID(types.UID(ns + "/" + name))
	o.SetCreationTimestamp(metav1.NewTime(time.Now().Add(-age)))
	return o
}

func veleroRestore(ns, name, phase string, started, created time.Time) *unstructured.Unstructured {
	status := map[string]any{"phase": phase}
	if !started.IsZero() {
		status["startTimestamp"] = started.UTC().Format(time.RFC3339)
	}
	u := testutil.Unstructured(
		veleroRestoreGVR.GroupVersion().WithKind("Restore"), ns, name,
		map[string]any{"status": status})
	u.SetUID(types.UID("uid-restore-" + ns + "-" + name))
	if !created.IsZero() {
		u.SetCreationTimestamp(metav1.NewTime(created))
	}
	return u
}

func veleroServerPod(ns, name string, start time.Time, ready bool, owned bool) *corev1.Pod {
	readyStatus := corev1.ConditionTrue
	if !ready {
		readyStatus = corev1.ConditionFalse
	}
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         ns,
			Name:              name,
			UID:               types.UID("uid-pod-" + ns + "-" + name),
			CreationTimestamp: metav1.NewTime(start),
			Labels: map[string]string{
				"app.kubernetes.io/name": "velero",
			},
		},
		Spec: corev1.PodSpec{NodeName: "node-1"},
		Status: corev1.PodStatus{
			Phase:     corev1.PodRunning,
			StartTime: &metav1.Time{Time: start},
			Conditions: []corev1.PodCondition{{
				Type:   corev1.PodReady,
				Status: readyStatus,
			}},
		},
	}
	if owned {
		p.OwnerReferences = []metav1.OwnerReference{{
			APIVersion: "apps/v1",
			Kind:       "ReplicaSet",
			Name:       "velero-rs",
			UID:        "uid-velero-rs",
			Controller: ptr.To(true),
		}}
	}
	return p
}

func restoreStuckSeries(t *testing.T, ns, restore string) (float64, bool) {
	t.Helper()
	return testutil.GaugeSeriesValue(t, "node_automation_velero_restore_stuck",
		map[string]string{"namespace": ns, "restore": restore})
}

func hasEvictActionWithUID(cs *kfake.Clientset, ns, name string, wantUID types.UID) bool {
	for _, a := range cs.Actions() {
		ca, ok := a.(ktesting.CreateAction)
		if !ok || a.GetVerb() != "create" || a.GetResource().Resource != "pods" || a.GetSubresource() != "eviction" {
			continue
		}
		ev, ok := ca.GetObject().(*policyv1.Eviction)
		if !ok {
			continue
		}
		if ev.Namespace == ns && ev.Name == name &&
			ev.DeleteOptions != nil && ev.DeleteOptions.Preconditions != nil &&
			ev.DeleteOptions.Preconditions.UID != nil && *ev.DeleteOptions.Preconditions.UID == wantUID {
			return true
		}
	}
	return false
}

// TestVeleroAuditorRestoreAudit exercises every R6-K9a Restore audit,
// Warning Event, and wedged velero server pod bounce contract.
// Non-parallel: mutates Prometheus vectors, global heal.ConfigureBudget,
// and shared queue error counters.
func TestVeleroAuditorRestoreAudit(t *testing.T) {
	base := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

	t.Run("stuck_inprogress_emits_metric_event_and_bounces_wedged_velero_pod", func(t *testing.T) {
		testutil.CleanupMetric(t, veleroRestoreStuckGauge, "velero", "r-stuck")
		testutil.CleanupMetric(t, veleroRestoreStuckGauge, "velero", "r-fallback-ct")
		r1 := veleroRestore("velero", "r-stuck", "InProgress", base.Add(-7*time.Hour), base.Add(-7*time.Hour))
		// Fallback to creationTimestamp when startTimestamp is absent.
		r2 := veleroRestore("velero", "r-fallback-ct", "InProgress", time.Time{}, base.Add(-8*time.Hour))
		srvOld := veleroServerPod("velero", "velero-old", base.Add(-24*time.Hour), true, true)
		srvNew := veleroServerPod("velero", "velero-new", base.Add(-12*time.Hour), true, true)
		agent := nodeAgentPod("velero", "node-agent-aaa", "node-1", base.Add(-24*time.Hour), base.Add(-24*time.Hour))
		agent.OwnerReferences = []metav1.OwnerReference{{
			APIVersion: "apps/v1", Kind: "DaemonSet", Name: "node-agent",
			UID: "uid-ds-na", Controller: ptr.To(true),
		}}

		cs := kfake.NewSimpleClientset(srvOld, srvNew, agent)
		testutil.EmulateEviction(cs)
		dyn := newDynFake(r1, r2)
		a := newVeleroAuditor(dyn, base)
		a.cs = cs
		a.queue = "velero-backup-auditor"

		restartedBefore := promtestutil.ToFloat64(metrics.VeleroWedgedObjectsCleanedTotal.WithLabelValues("velero", "pod_restarted"))
		if err := a.run(ctx); err != nil {
			t.Fatalf("run err = %v", err)
		}

		for _, rname := range []string{"r-stuck", "r-fallback-ct"} {
			if v, ok := restoreStuckSeries(t, "velero", rname); !ok || v != 1 {
				t.Fatalf("%s stuck metric = (%v,%v), want (1,true)", rname, v, ok)
			}
		}

		evs, err := cs.EventsV1().Events("velero").List(ctx, metav1.ListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(evs.Items) != 2 {
			t.Fatalf("events = %d, want 2 Warning Events", len(evs.Items))
		}
		for _, ev := range evs.Items {
			if ev.Type != corev1.EventTypeWarning || ev.Reason != veleroRestoreEventReason {
				t.Fatalf("unexpected event: %+v", ev)
			}
		}

		if !hasEvictActionWithUID(cs, "velero", "velero-old", srvOld.UID) {
			t.Fatal("expected Eviction on oldest wedged velero server pod with UIDDeleteOptions")
		}
		if testutil.PodExists(t, cs, "velero", "velero-old") {
			t.Fatal("oldest wedged velero server pod must be evicted")
		}
		if !testutil.PodExists(t, cs, "velero", "velero-new") {
			t.Fatal("newer velero server pod must not be evicted when oldest was targeted")
		}
		if !testutil.PodExists(t, cs, "velero", "node-agent-aaa") {
			t.Fatal("node-agent DaemonSet pod must never be bounced by Restore audit")
		}
		restartedDelta := promtestutil.ToFloat64(metrics.VeleroWedgedObjectsCleanedTotal.WithLabelValues("velero", "pod_restarted")) - restartedBefore
		if restartedDelta != 1 {
			t.Fatalf("pod_restarted counter delta = %v, want 1", restartedDelta)
		}
		if _, stamped := a.restoreHealed.Last("velero-server/velero/velero-rs"); !stamped {
			t.Fatal("restoreHealed cooldown not stamped after eviction")
		}
	})

	t.Run("fresh_inprogress_or_terminal_restore_ignored", func(t *testing.T) {
		testutil.CleanupMetric(t, veleroRestoreStuckGauge, "velero", "r-fresh")
		testutil.CleanupMetric(t, veleroRestoreStuckGauge, "velero", "r-done")
		testutil.CleanupMetric(t, veleroRestoreStuckGauge, "velero", "r-fail")
		rFresh := veleroRestore("velero", "r-fresh", "InProgress", base.Add(-2*time.Hour), base.Add(-2*time.Hour))
		rDone := veleroRestore("velero", "r-done", "Completed", base.Add(-10*time.Hour), base.Add(-10*time.Hour))
		rFail := veleroRestore("velero", "r-fail", "Failed", base.Add(-10*time.Hour), base.Add(-10*time.Hour))
		srv := veleroServerPod("velero", "velero-0", base.Add(-24*time.Hour), true, true)

		cs := kfake.NewSimpleClientset(srv)
		testutil.EmulateEviction(cs)
		a := newVeleroAuditor(newDynFake(rFresh, rDone, rFail), base)
		a.cs = cs
		a.queue = "velero-backup-auditor"

		if err := a.run(ctx); err != nil {
			t.Fatal(err)
		}
		for _, n := range []string{"r-fresh", "r-done", "r-fail"} {
			if _, ok := restoreStuckSeries(t, "velero", n); ok {
				t.Fatalf("%s must not emit stuck gauge", n)
			}
		}
		evs, _ := cs.EventsV1().Events("velero").List(ctx, metav1.ListOptions{})
		if len(evs.Items) != 0 {
			t.Fatalf("expected 0 events, got %d", len(evs.Items))
		}
		if !testutil.PodExists(t, cs, "velero", "velero-0") {
			t.Fatal("velero server pod evicted without any stuck Restore")
		}
	})

	t.Run("recently_restarted_ready_velero_pod_not_bounced", func(t *testing.T) {
		testutil.CleanupMetric(t, veleroRestoreStuckGauge, "velero", "r-stuck")
		r := veleroRestore("velero", "r-stuck", "InProgress", base.Add(-7*time.Hour), base.Add(-7*time.Hour))
		srv := veleroServerPod("velero", "velero-fresh", base.Add(-1*time.Hour), true, true)
		cs := kfake.NewSimpleClientset(srv)
		testutil.EmulateEviction(cs)
		a := newVeleroAuditor(newDynFake(r), base)
		a.cs = cs
		a.queue = "velero-backup-auditor"

		if err := a.run(ctx); err != nil {
			t.Fatal(err)
		}
		if v, ok := restoreStuckSeries(t, "velero", "r-stuck"); !ok || v != 1 {
			t.Fatalf("stuck metric = (%v,%v), want (1,true)", v, ok)
		}
		evs, _ := cs.EventsV1().Events("velero").List(ctx, metav1.ListOptions{})
		if len(evs.Items) != 1 {
			t.Fatalf("events = %d, want 1", len(evs.Items))
		}
		if !testutil.PodExists(t, cs, "velero", "velero-fresh") {
			t.Fatal("freshly restarted Ready velero server pod should not be evicted")
		}
	})

	t.Run("unready_velero_pod_bounced", func(t *testing.T) {
		testutil.CleanupMetric(t, veleroRestoreStuckGauge, "velero", "r-stuck")
		r := veleroRestore("velero", "r-stuck", "InProgress", base.Add(-7*time.Hour), base.Add(-7*time.Hour))
		srv := veleroServerPod("velero", "velero-unready", base.Add(-1*time.Hour), false, true)
		cs := kfake.NewSimpleClientset(srv)
		testutil.EmulateEviction(cs)
		a := newVeleroAuditor(newDynFake(r), base)
		a.cs = cs
		a.queue = "velero-backup-auditor"

		if err := a.run(ctx); err != nil {
			t.Fatal(err)
		}
		if testutil.PodExists(t, cs, "velero", "velero-unready") {
			t.Fatal("unready velero server pod should be evicted")
		}
	})

	t.Run("cooldown_prevents_second_bounce_and_event_deduped", func(t *testing.T) {
		testutil.CleanupMetric(t, veleroRestoreStuckGauge, "velero", "r-stuck")
		r := veleroRestore("velero", "r-stuck", "InProgress", base.Add(-7*time.Hour), base.Add(-7*time.Hour))
		srv1 := veleroServerPod("velero", "velero-1", base.Add(-24*time.Hour), true, true)
		cs := kfake.NewSimpleClientset(srv1)
		testutil.EmulateEviction(cs)

		curNow := base
		a := newVeleroAuditor(newDynFake(r), curNow)
		a.now = func() time.Time { return curNow }
		a.cs = cs
		a.queue = "velero-backup-auditor"

		if err := a.run(ctx); err != nil {
			t.Fatal(err)
		}
		if testutil.PodExists(t, cs, "velero", "velero-1") {
			t.Fatal("first sweep should evict velero-1")
		}

		// Replacement pod appears; second sweep within 1h cooldown must neither evict nor duplicate Warning Event.
		srv2 := veleroServerPod("velero", "velero-2", base.Add(-24*time.Hour), true, true)
		if _, err := cs.CoreV1().Pods("velero").Create(ctx, srv2, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		curNow = base.Add(20 * time.Minute)
		if err := a.run(ctx); err != nil {
			t.Fatal(err)
		}
		if !testutil.PodExists(t, cs, "velero", "velero-2") {
			t.Fatal("cooldown failed to suppress second bounce within 1h")
		}
		evs, _ := cs.EventsV1().Events("velero").List(ctx, metav1.ListOptions{})
		if len(evs.Items) != 1 {
			t.Fatalf("events = %d, want 1 (deduped inside 1h window)", len(evs.Items))
		}

		// After > 1h cooldown expires, bounce and Warning Event re-fire.
		curNow = base.Add(65 * time.Minute)
		if err := a.run(ctx); err != nil {
			t.Fatal(err)
		}
		if testutil.PodExists(t, cs, "velero", "velero-2") {
			t.Fatal("expected bounce to re-fire after 1h cooldown expired")
		}
		evs, _ = cs.EventsV1().Events("velero").List(ctx, metav1.ListOptions{})
		if len(evs.Items) != 2 {
			t.Fatalf("events = %d, want 2 after cooldown expiry", len(evs.Items))
		}
	})

	t.Run("maintenance_hold_defers_bounce_keeps_metric", func(t *testing.T) {
		testutil.CleanupMetric(t, veleroRestoreStuckGauge, "velero", "r-stuck")
		r := veleroRestore("velero", "r-stuck", "InProgress", base.Add(-7*time.Hour), base.Add(-7*time.Hour))
		srv := veleroServerPod("velero", "velero-0", base.Add(-24*time.Hour), true, true)
		plan := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "autopilot.k0sproject.io/v1beta2",
			"kind":       "Plan",
			"metadata":   map[string]any{"name": "upgrade"},
			"status":     map[string]any{"state": "Executing"},
		}}
		cs := kfake.NewSimpleClientset(srv)
		testutil.EmulateEviction(cs)
		dyn := newDynFake(r, plan)
		curNow := base
		a := newVeleroAuditor(dyn, curNow)
		a.now = func() time.Time { return curNow }
		a.cs = cs
		a.queue = "velero-backup-auditor"

		if err := a.run(ctx); err != nil {
			t.Fatal(err)
		}
		if v, ok := restoreStuckSeries(t, "velero", "r-stuck"); !ok || v != 1 {
			t.Fatalf("stuck metric = (%v,%v), want (1,true)", v, ok)
		}
		evs, _ := cs.EventsV1().Events("velero").List(ctx, metav1.ListOptions{})
		if len(evs.Items) != 1 {
			t.Fatalf("events = %d, want 1", len(evs.Items))
		}
		if !testutil.PodExists(t, cs, "velero", "velero-0") {
			t.Fatal("velero server pod evicted during active maintenance hold")
		}

		// Clear maintenance hold -> next sweep evicts.
		if err := dyn.Resource(kube.AutopilotPlanGVR).Delete(ctx, "upgrade", metav1.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
		curNow = base.Add(2 * time.Minute)
		if err := a.run(ctx); err != nil {
			t.Fatal(err)
		}
		if testutil.PodExists(t, cs, "velero", "velero-0") {
			t.Fatal("velero server pod should be evicted after maintenance hold cleared")
		}
	})

	t.Run("maintenance_unverifiable_incerrors_and_defers", func(t *testing.T) {
		testutil.CleanupMetric(t, veleroRestoreStuckGauge, "velero", "r-stuck")
		r := veleroRestore("velero", "r-stuck", "InProgress", base.Add(-7*time.Hour), base.Add(-7*time.Hour))
		srv := veleroServerPod("velero", "velero-0", base.Add(-24*time.Hour), true, true)
		cs := kfake.NewSimpleClientset(srv)
		testutil.EmulateEviction(cs)
		dyn := newDynFake(r)
		dyn.PrependReactor("list", "plans", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("plan list failed")
		})
		a := newVeleroAuditor(dyn, base)
		a.cs = cs
		a.queue = "velero-backup-auditor"

		before := testutil.QueueErrorCount(t, a.queue)
		if err := a.run(ctx); err != nil {
			t.Fatal(err)
		}
		if got := testutil.QueueErrorCount(t, a.queue) - before; got != 1 {
			t.Fatalf("queue error delta = %v, want 1", got)
		}
		if !testutil.PodExists(t, cs, "velero", "velero-0") {
			t.Fatal("velero server pod evicted when maintenance unverifiable")
		}
	})

	t.Run("pdb_429_refusal_refunds_budget_and_skips_cooldown", func(t *testing.T) {
		t.Cleanup(func() { heal.ConfigureBudget(0, 0) })
		heal.ConfigureBudget(1, time.Hour)
		testutil.CleanupMetric(t, veleroRestoreStuckGauge, "velero", "r-stuck")

		r := veleroRestore("velero", "r-stuck", "InProgress", base.Add(-7*time.Hour), base.Add(-7*time.Hour))
		srv := veleroServerPod("velero", "velero-0", base.Add(-24*time.Hour), true, true)
		cs := kfake.NewSimpleClientset(srv)
		cs.PrependReactor("create", "pods", func(a ktesting.Action) (bool, runtime.Object, error) {
			if a.GetSubresource() == "eviction" {
				return true, nil, apierrors.NewTooManyRequests("pdb busy", 1)
			}
			return false, nil, nil
		})
		dyn := newDynFake(r)
		a := newVeleroAuditor(dyn, base)
		a.cs = cs
		a.queue = "velero-backup-auditor"

		if err := a.run(ctx); err != nil {
			t.Fatal(err)
		}
		if !testutil.PodExists(t, cs, "velero", "velero-0") {
			t.Fatal("pod must survive PDB 429 refusal")
		}
		if _, stamped := a.restoreHealed.Last("velero-server/velero/velero-rs"); stamped {
			t.Fatal("cooldown must not be stamped on PDB 429 refusal")
		}
		if proceed, unverifiable := heal.Gate(ctx, logr.Discard(), nil, cs, dyn, "after-pdb", base.Add(time.Second)); !proceed || unverifiable {
			t.Fatalf("Gate after PDB 429 = (%v,%v), want (true,false) — grant not refunded", proceed, unverifiable)
		}
	})

	t.Run("restore_crd_absent_404_auto_skips_and_prunes", func(t *testing.T) {
		testutil.CleanupMetric(t, veleroRestoreStuckGauge, "velero", "r-stuck")
		r := veleroRestore("velero", "r-stuck", "InProgress", base.Add(-7*time.Hour), base.Add(-7*time.Hour))
		dyn := newDynFake(r)
		a := newVeleroAuditor(dyn, base)
		a.queue = "velero-backup-auditor"

		if err := a.run(ctx); err != nil {
			t.Fatal(err)
		}
		if v, ok := restoreStuckSeries(t, "velero", "r-stuck"); !ok || v != 1 {
			t.Fatalf("expected stuck metric=1 before CRD removal, got (%v,%v)", v, ok)
		}

		dyn.PrependReactor("list", "restores", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewNotFound(veleroRestoreGVR.GroupResource(), "")
		})
		if err := a.run(ctx); err != nil {
			t.Fatalf("expected nil on Restore CRD 404, got %v", err)
		}
		if _, ok := restoreStuckSeries(t, "velero", "r-stuck"); ok {
			t.Fatal("expected stuck restore series pruned when Restore CRD absent")
		}
	})

	t.Run("restore_list_error_preserves_series_and_returns_err", func(t *testing.T) {
		testutil.CleanupMetric(t, veleroRestoreStuckGauge, "velero", "r-stuck")
		r := veleroRestore("velero", "r-stuck", "InProgress", base.Add(-7*time.Hour), base.Add(-7*time.Hour))
		dyn := newDynFake(r)
		a := newVeleroAuditor(dyn, base)
		a.queue = "velero-backup-auditor"

		if err := a.run(ctx); err != nil {
			t.Fatal(err)
		}
		dyn.PrependReactor("list", "restores", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewInternalError(errors.New("apiserver 500"))
		})
		if err := a.run(ctx); err == nil {
			t.Fatal("expected error on 500 restores list")
		}
		if v, ok := restoreStuckSeries(t, "velero", "r-stuck"); !ok || v != 1 {
			t.Fatalf("expected stuck metric preserved on transient 500 error, got (%v,%v)", v, ok)
		}
	})

	t.Run("recovery_clears_restore_metric", func(t *testing.T) {
		testutil.CleanupMetric(t, veleroRestoreStuckGauge, "velero", "r-recover")
		r := veleroRestore("velero", "r-recover", "InProgress", base.Add(-7*time.Hour), base.Add(-7*time.Hour))
		dyn := newDynFake(r)
		a := newVeleroAuditor(dyn, base)
		a.queue = "velero-backup-auditor"

		if err := a.run(ctx); err != nil {
			t.Fatal(err)
		}
		if v, ok := restoreStuckSeries(t, "velero", "r-recover"); !ok || v != 1 {
			t.Fatalf("expected stuck metric=1, got (%v,%v)", v, ok)
		}

		_ = unstructured.SetNestedField(r.Object, "Completed", "status", "phase")
		if _, err := dyn.Resource(veleroRestoreGVR).Namespace("velero").UpdateStatus(ctx, r, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		if err := a.run(ctx); err != nil {
			t.Fatal(err)
		}
		if _, ok := restoreStuckSeries(t, "velero", "r-recover"); ok {
			t.Fatal("expected stuck restore series pruned after recovery to Completed")
		}
	})
}

func TestVeleroAuditorRestorePreservesBackupPVBAndPVR(t *testing.T) {
	base := time.Now()
	testutil.CleanupMetric(t, metrics.VeleroBackupStuck, "velero", "b-stuck")
	testutil.CleanupMetric(t, metrics.VeleroPodVolumeBackupWedged, "app", "pvb-wedged")
	testutil.CleanupMetric(t, metrics.VeleroPodVolumeRestoreWedged, "app", "pvr-wedged")
	testutil.CleanupMetric(t, veleroRestoreStuckGauge, "velero", "r-stuck")

	sched := veleroSchedule("velero", "daily", false, time.Hour)
	backup := veleroBackup("velero", "b-stuck", "daily", "InProgress", 7*time.Hour, 0, 0, 0, 0)
	pvb := veleroPVB("app", "pvb-wedged", "InProgress", 7*time.Hour, "node-agent-1", "node-1")
	pvr := veleroPVR("app", "pvr-wedged", "InProgress", 7*time.Hour, "node-agent-2", "node-2")
	rest := veleroRestore("velero", "r-stuck", "InProgress", base.Add(-7*time.Hour), base.Add(-7*time.Hour))

	// Both node-agent pods are unready & old -> PVB/PVR bounce node-agents only.
	agent1 := nodeAgentPod("velero", "node-agent-1", "node-1", base.Add(-24*time.Hour), base.Add(-24*time.Hour))
	agent1.Status.Conditions[0].Status = corev1.ConditionFalse
	agent2 := nodeAgentPod("velero", "node-agent-2", "node-2", base.Add(-24*time.Hour), base.Add(-24*time.Hour))
	agent2.Status.Conditions[0].Status = corev1.ConditionFalse
	// Velero server pod is old -> Restore audit bounces velero server pod only.
	srv := veleroServerPod("velero", "velero-srv", base.Add(-24*time.Hour), true, true)

	cs := kfake.NewSimpleClientset(agent1, agent2, srv)
	testutil.EmulateEviction(cs)
	dyn := newDynFake(sched, backup, pvb, pvr, rest)
	a := newVeleroAuditor(dyn, base)
	a.cs = cs
	a.queue = "velero-backup-auditor"

	if err := a.run(ctx); err != nil {
		t.Fatalf("coexistence run err = %v", err)
	}
	if v, ok := stuckSeries(t, "velero", "b-stuck"); !ok || v != 1 {
		t.Fatalf("Backup stuck series = (%v,%v), want (1,true)", v, ok)
	}
	if v, ok := wedgedSeries(t, "app", "pvb-wedged"); !ok || v != 1 {
		t.Fatalf("PVB wedged series = (%v,%v), want (1,true)", v, ok)
	}
	if v, ok := testutil.GaugeSeriesValue(t, "node_automation_velero_podvolumerestore_wedged",
		map[string]string{"namespace": "app", "pvr": "pvr-wedged"}); !ok || v != 1 {
		t.Fatalf("PVR wedged series = (%v,%v), want (1,true)", v, ok)
	}
	if v, ok := restoreStuckSeries(t, "velero", "r-stuck"); !ok || v != 1 {
		t.Fatalf("Restore stuck series = (%v,%v), want (1,true)", v, ok)
	}
	if testutil.PodExists(t, cs, "velero", "node-agent-1") || testutil.PodExists(t, cs, "velero", "node-agent-2") {
		t.Fatal("expected wedged node-agent pods to be bounced by PVB/PVR")
	}
	if testutil.PodExists(t, cs, "velero", "velero-srv") {
		t.Fatal("expected wedged velero server pod to be bounced by Restore")
	}
}
