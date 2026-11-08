// postgres_wal_archive_guard_test.go — coverage for the
// postgres-wal-archive-guard check: CR archive conditions, pod-log
// disk-full evidence and Prometheus archiver/slot/volume evidence.
package datastore

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// cnpgCluster builds a CNPG Cluster CR carrying a
// ContinuousArchiving=False condition transitioned `age` ago.
func cnpgCluster(ns, name string, age time.Duration) *unstructured.Unstructured {
	obj := testutil.Unstructured(
		kube.GVRCNPGCluster.GroupVersion().WithKind("Cluster"), ns, name,
		map[string]any{"status": map[string]any{
			"conditions": []any{map[string]any{
				"type":   "ContinuousArchiving",
				"status": "False",
				"lastTransitionTime": time.Now().
					Add(-age).UTC().Format(time.RFC3339)}},
		}})
	obj.SetUID(types.UID("uid-" + ns + "-" + name))
	return obj
}

func pgPod(ns, name, cluster string) *corev1.Pod {
	pod := probetest.PodWithPhase(ns, name, corev1.PodRunning, true, time.Hour)
	pod.Labels = map[string]string{"cnpg.io/cluster": cluster}
	pod.Spec.Containers = []corev1.Container{{Name: "postgres"}}
	return pod
}

func TestPostgresWALArchiveConditionFails(t *testing.T) {
	cr := cnpgCluster("db", "pg-main", time.Hour)
	cs := fake.NewSimpleClientset()
	p := testProberDyn(cs, probetest.OpDyn(cr))
	res := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("stale archiving condition must fail: %+v", res)
	}
	if !strings.Contains(res.Why, "archive_condition") {
		t.Fatalf("why missing archive_condition: %q", res.Why)
	}
	if v, ok := testutil.GaugeSeriesValue(t, "node_automation_postgres_wal_archive_unhealthy",
		map[string]string{"namespace": "db", "cluster": "pg-main", "reason": "archive_condition"}); !ok || v != 1 {
		t.Fatalf("gauge = %v,%v want 1,true", v, ok)
	}
}

func TestPostgresWALDiskFullLogEvidence(t *testing.T) {
	pod := pgPod("db", "pg-main-1", "pg-main")
	cs := fake.NewSimpleClientset(pod)
	cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		`2026-01-01 FATAL: PANIC: could not write to file "pg_wal/xlogtemp.42": No space left on device`+"\n", nil))
	p := testProber(cs)
	res := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("pg_wal disk-full evidence must fail: %+v", res)
	}
	if !strings.Contains(res.Why, "wal_disk_full") {
		t.Fatalf("why missing wal_disk_full: %q", res.Why)
	}
}

func TestPostgresHealthyClusterPasses(t *testing.T) {
	pod := pgPod("db", "pg-main-1", "pg-main")
	cs := fake.NewSimpleClientset(pod)
	cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		"INFO archive-push succeeded\n", nil))
	p := testProber(cs)
	res := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p).Run(ctx)
	if !res.Pass {
		t.Fatalf("clean cluster must pass: %+v", res)
	}
}

// W12-ST2 — an inactive replication slot retaining past 5GiB of WAL
// fires the dedicated bloat gauge carrying the slot name and the
// retained byte count, alongside the existing inactive_slot reason
// on the unhealthy gauge.
func TestPostgresInactiveSlotWALBloat(t *testing.T) {
	testutil.CleanupMetric(t, postgresInactiveSlotWALGauge, "db", "pg-main", "replica1")
	testutil.CleanupMetric(t, postgresWALUnhealthyGauge, "db", "pg-main", "inactive_slot")
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, "pg_replication_slots_retained_bytes") {
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "db",
					"postgres_cluster": "pg-main", "slot_name": "replica1"},
				Value: float64(8 << 30), // 8GiB retained
			}}
		}
		return nil
	})
	pod := pgPod("db", "pg-main-1", "pg-main")
	cs := fake.NewSimpleClientset(pod)
	cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		"INFO archive-push ok\n", nil))
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()

	res := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("inactive slot retaining >5GiB must fail")
	}
	if !strings.Contains(res.Why, "replica1") {
		t.Fatalf("why missing the slot name: %q", res.Why)
	}
	m := probetest.FindMetric(t, "node_automation_postgres_inactive_slot_wal_bloat",
		map[string]string{"namespace": "db", "cluster": "pg-main",
			"slot": "replica1"})
	if m == nil || m.GetGauge().GetValue() != float64(8<<30) {
		t.Fatalf("slot bloat gauge = %v, want 8GiB", m)
	}
	// The shared unhealthy gauge keeps its inactive_slot reason.
	if v, ok := testutil.GaugeSeriesValue(t, "node_automation_postgres_wal_archive_unhealthy",
		map[string]string{"namespace": "db", "cluster": "pg-main",
			"reason": "inactive_slot"}); !ok || v != 1 {
		t.Fatalf("unhealthy inactive_slot = %v,%v want 1,true", v, ok)
	}
}

// The postgres_exporter spelling — an active==0 series `and`-joined
// to a >5GiB lsn diff — flags 1 on the bloat gauge (that family
// returns value-0 samples, no byte count to carry).
func TestPostgresInactiveSlotActiveFlagSpelling(t *testing.T) {
	testutil.CleanupMetric(t, postgresInactiveSlotWALGauge, "db", "pg-main", "stale-slot")
	testutil.CleanupMetric(t, postgresWALUnhealthyGauge, "db", "pg-main", "inactive_slot")
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, "pg_replication_slots_active") {
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "db",
					"pod": "pg-main", "slot_name": "stale-slot"},
				Value: 0, // `and` returns the left-side samples
			}}
		}
		return nil
	})
	cs := fake.NewSimpleClientset()
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()

	res := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("active-flag spelling of slot bloat must fail")
	}
	m := probetest.FindMetric(t, "node_automation_postgres_inactive_slot_wal_bloat",
		map[string]string{"namespace": "db", "cluster": "pg-main",
			"slot": "stale-slot"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("slot bloat gauge = %v, want 1", m)
	}
}

// ---------------------------------------------------------------------------
// cnpg-health — CloudNativePG cluster health
// ---------------------------------------------------------------------------

// cnpgClusterHealth builds a CNPG Cluster CR carrying the cnpg-health
// status fields — phase, the declared/ready instance counts and an
// optional phaseTimestamp (age<0 omits it, forcing the first-seen
// ledger path).
func cnpgClusterHealth(ns, name, phase string, phaseAge time.Duration,
	instances, ready int64) *unstructured.Unstructured {
	status := map[string]any{
		"phase":          phase,
		"instances":      instances,
		"readyInstances": ready,
	}
	if phaseAge >= 0 {
		status["phaseTimestamp"] = time.Now().
			Add(-phaseAge).UTC().Format(time.RFC3339)
	}
	return testutil.Unstructured(
		kube.GVRCNPGCluster.GroupVersion().WithKind("Cluster"), ns, name,
		map[string]any{"status": status})
}

// cnpgSeries reads the cnpg_cluster_unhealthy gauge without
// instantiating the tuple.
func cnpgSeries(t *testing.T, ns, name, reason string) (float64, bool) {
	t.Helper()
	return testutil.GaugeSeriesValue(t, "node_automation_cnpg_cluster_unhealthy",
		map[string]string{"namespace": ns, "name": name, "reason": reason})
}

// A Failing-over phase whose status.phaseTimestamp is older than the
// 15m window flags stuck_phase on the first sweep — the operator's
// own transition stamp is the honest clock.
func TestCNPGStuckPhaseTimestampFlags(t *testing.T) {
	testutil.CleanupMetric(t, cnpgClusterUnhealthyGauge, "db", "pg-fo", "stuck_phase")
	cr := cnpgClusterHealth("db", "pg-fo", "Failing over",
		20*time.Minute, 3, 1)
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(cr))
	res := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("stuck failover phase must fail: %+v", res)
	}
	if v, ok := cnpgSeries(t, "db", "pg-fo", "stuck_phase"); !ok || v != 1 {
		t.Fatalf("stuck_phase series = %v,%v want 1,true", v, ok)
	}
}

// Without phaseTimestamp the first-seen ledger measures the hold:
// first sight arms the clock, a second sweep past the window flags —
// and the CamelCase enum spelling matches the spaced CRD value.
func TestCNPGStuckPhaseLedgerPath(t *testing.T) {
	testutil.CleanupMetric(t, cnpgClusterUnhealthyGauge, "db", "pg-wait", "stuck_phase")
	now := time.Now()
	cr := cnpgClusterHealth("db", "pg-wait",
		"WaitingForInstancesToBecomeActive", -1, 3, 0)
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(cr))
	chk := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, now)
	if res := chk.Run(ctx); res.Pass {
		if v, ok := cnpgSeries(t, "db", "pg-wait", "stuck_phase"); ok {
			t.Fatalf("stuck_phase flagged on first sight: %v", v)
		}
	}
	probetest.FreezeNow(p.Deps, now.Add(16*time.Minute))
	res := chk.Run(ctx)
	if res.Pass {
		t.Fatal("phase held past the window must fail")
	}
	if v, ok := cnpgSeries(t, "db", "pg-wait", "stuck_phase"); !ok || v != 1 {
		t.Fatalf("stuck_phase series = %v,%v want 1,true", v, ok)
	}
}

// readyInstances short of instances for two consecutive sweeps past
// the window flags under_replicated.
func TestCNPGUnderReplicatedFlags(t *testing.T) {
	testutil.CleanupMetric(t, cnpgClusterUnhealthyGauge, "db", "pg-short", "under_replicated")
	now := time.Now()
	cr := cnpgClusterHealth("db", "pg-short", "Healthy", -1, 3, 1)
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(cr))
	chk := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, now)
	if res := chk.Run(ctx); !res.Pass {
		t.Fatalf("first sight of the shortfall must arm, not fail: %+v", res)
	}
	probetest.FreezeNow(p.Deps, now.Add(16*time.Minute))
	res := chk.Run(ctx)
	if res.Pass {
		t.Fatal("ready<instances held past the window must fail")
	}
	if v, ok := cnpgSeries(t, "db", "pg-short",
		"under_replicated"); !ok || v != 1 {
		t.Fatalf("under_replicated series = %v,%v want 1,true", v, ok)
	}
}

// ContinuousArchiving=False flags archiving_disabled on the CNPG
// gauge — and still rides the WAL archive_condition reason (the
// cnpgCluster fixture's transition is an hour old).
func TestCNPGArchivingDisabledFlags(t *testing.T) {
	testutil.CleanupMetric(t, cnpgClusterUnhealthyGauge, "db", "pg-main", "archiving_disabled")
	cr := cnpgCluster("db", "pg-main", time.Hour)
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(cr))
	res := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("ContinuousArchiving=False must fail: %+v", res)
	}
	if v, ok := cnpgSeries(t, "db", "pg-main",
		"archiving_disabled"); !ok || v != 1 {
		t.Fatalf("archiving_disabled series = %v,%v want 1,true", v, ok)
	}
}

// A healthy CNPG cluster — Ready phase, full replica count, no
// disabling conditions — emits nothing.
func TestCNPGHealthyClusterPasses(t *testing.T) {
	cr := cnpgClusterHealth("db", "pg-ok", "Healthy",
		2*time.Hour, 3, 3)
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(cr))
	res := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p).Run(ctx)
	if !res.Pass {
		t.Fatalf("healthy cluster must pass: %+v", res)
	}
	for _, reason := range []string{
		"stuck_phase", "under_replicated", "archiving_disabled"} {
		if _, ok := cnpgSeries(t, "db", "pg-ok", reason); ok {
			t.Fatalf("healthy cluster produced a %s series", reason)
		}
	}
}

// Recovery prunes the series: a cluster that lands its phase and
// catches its replicas up loses the emitted tuple next sweep.
func TestCNPGRecoveryPrunesSeries(t *testing.T) {
	cnpgClusterUnhealthyGauge.DeleteLabelValues("db", "pg-heal", "stuck_phase")
	now := time.Now()
	cr := cnpgClusterHealth("db", "pg-heal", "Failing over",
		30*time.Minute, 3, 1)
	dyn := probetest.OpDyn(cr)
	p := testProberDyn(fake.NewSimpleClientset(), dyn)
	chk := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, now)
	if res := chk.Run(ctx); res.Pass {
		t.Fatal("stuck phase must fail first")
	}
	if _, ok := cnpgSeries(t, "db", "pg-heal", "stuck_phase"); !ok {
		t.Fatal("stuck_phase series missing before the resolve")
	}

	u, err := dyn.Resource(kube.GVRCNPGCluster).Namespace("db").
		Get(ctx, "pg-heal", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_ = unstructured.SetNestedField(u.Object, "Healthy", "status", "phase")
	_ = unstructured.SetNestedField(u.Object, int64(3),
		"status", "readyInstances")
	if _, err := dyn.Resource(kube.GVRCNPGCluster).Namespace("db").
		Update(ctx, u, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}

	probetest.FreezeNow(p.Deps, now.Add(31*time.Minute))
	res := chk.Run(ctx)
	if !res.Pass {
		// under_replicated resolves too — the replica count caught up.
		t.Fatalf("healed cluster must pass: %+v", res)
	}
	if cnpgClusterUnhealthyGauge.DeleteLabelValues("db", "pg-heal", "stuck_phase") {
		t.Fatal("stuck_phase series kept after the cluster healed")
	}
}
