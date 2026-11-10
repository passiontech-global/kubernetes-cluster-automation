// postgres_wal_archive_guard_test.go — coverage for the
// postgres-wal-archive-guard check: CR archive conditions, pod-log
// disk-full evidence and Prometheus archiver/slot/volume evidence.
package postgres

import (
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
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

// percona-degraded-quorum — an inactive replication slot retaining past 5GiB of WAL
// fires the dedicated bloat gauge carrying the slot name and the
// retained byte count, alongside the existing inactive_slot reason
// on the unhealthy gauge.
func TestPostgresInactiveSlotWALBloat(t *testing.T) {
	testutil.CleanupMetric(t, postgresInactiveSlotWALGauge, "db", "pg-main", "replica1")
	testutil.CleanupMetric(t, postgresWALUnhealthyGauge, "db", "pg-main", "inactive_slot")
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, "pg_replication_slots_retained_bytes") &&
			!strings.Contains(query, "cnpg_pg_") {
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
		if strings.Contains(query, "pg_replication_slots_active") &&
			!strings.Contains(query, "cnpg_pg_") {
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
		// A real cluster with instances always has an elected
		// primary — cnpg-cluster-health primary_mismatch flags its absence, so
		// the healthy fixture must carry one (mismatch tests
		// override it).
		"currentPrimary": name + "-1",
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
// cnpgCluster fixture's transition is an hour old). Like the sibling
// branches the emit persists CNPGUnhealthyMinAge via the first-seen
// ledger: first sight arms, a second sweep past the window flags.
func TestCNPGArchivingDisabledFlags(t *testing.T) {
	testutil.CleanupMetric(t, cnpgClusterUnhealthyGauge, "db", "pg-main", "archiving_disabled")
	cr := cnpgCluster("db", "pg-main", time.Hour)
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(cr))
	chk := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p)

	now := time.Now()
	probetest.FreezeNow(p.Deps, now)
	res := chk.Run(ctx)
	if res.Pass {
		t.Fatalf("ContinuousArchiving=False must fail: %+v", res)
	}
	if _, ok := cnpgSeries(t, "db", "pg-main",
		"archiving_disabled"); ok {
		t.Fatal("archiving_disabled flagged on first sight")
	}
	probetest.FreezeNow(p.Deps, now.Add(16*time.Minute))
	res = chk.Run(ctx)
	if res.Pass {
		t.Fatalf("ContinuousArchiving=False held past the window must fail: %+v", res)
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

// ---------------------------------------------------------------------------
// heal-budget — bounded log read + cluster-scoped volume pressure.
// ---------------------------------------------------------------------------

// The pod-log read is bounded BOTH by TailLines and SinceSeconds —
// a whole-lifetime tail would re-flag a crash that predates every
// other signal in the sweep.
func TestPostgresWALLogOptionsBounded(t *testing.T) {
	opts := pgWALLogOptions("postgres")
	if opts.Container != "postgres" {
		t.Fatalf("container = %q, want postgres", opts.Container)
	}
	if opts.TailLines == nil || *opts.TailLines != probefw.DefaultTailLines {
		t.Fatal("log read missing the tail bound")
	}
	if opts.SinceSeconds == nil ||
		*opts.SinceSeconds != int64(pgWALLogSinceWindow.Seconds()) ||
		*opts.SinceSeconds <= 0 {
		t.Fatalf("log read missing a positive SinceSeconds bound: %v", opts.SinceSeconds)
	}
}

// Volume pressure emits under the OPERATOR CLUSTER name, never the
// PVC name — the gauge series are per-cluster and a PVC-named series
// would match no alert label set.
func TestPostgresWALVolumePressureEmitsClusterName(t *testing.T) {
	testutil.CleanupMetric(t, postgresWALUnhealthyGauge, "db", "pg-main", "wal_volume_pressure")
	t.Cleanup(func() {
		postgresWALUnhealthyGauge.DeleteLabelValues("db", "pg-main", "wal_volume_pressure")
	})
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, "kubelet_volume_stats") {
			return []probetest.PromTestSample{{
				Labels: map[string]string{
					"namespace":             "db",
					"persistentvolumeclaim": "pg-main-data-pg-main-0",
				},
				Value: 0.9,
			}}
		}
		return nil
	})
	pod := pgPod("db", "pg-main-0", "pg-main")
	pod.Spec.Volumes = []corev1.Volume{{
		Name: "data",
		VolumeSource: corev1.VolumeSource{
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
				ClaimName: "pg-main-data-pg-main-0"}}}}
	cs := fake.NewSimpleClientset(pod)
	cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		"INFO archive-push ok\n", nil))
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()

	res := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("data volume past 60%% must fail: %+v", res)
	}
	if v, ok := testutil.GaugeSeriesValue(t, "node_automation_postgres_wal_archive_unhealthy",
		map[string]string{"namespace": "db", "cluster": "pg-main",
			"reason": "wal_volume_pressure"}); !ok || v != 1 {
		t.Fatalf("wal_volume_pressure under cluster name = %v,%v want 1,true", v, ok)
	}
}

// Component 3 — the per-pod probe fan-out is bounded at 4 (the
// sibling log-scan checks pin the same bound in their own package's
// tests).
func TestPostgresWALWorkerPoolBound(t *testing.T) {
	if postgresWALLogWorkers != 4 {
		t.Fatalf("postgres log workers = %d, want 4", postgresWALLogWorkers)
	}
}

// ---------------------------------------------------------------------------
// pgWALConditionUnhealthy — the exact-match gate (benign custom
// conditions must NOT flag; the operators' real types must)
// ---------------------------------------------------------------------------

func TestPgWALConditionUnhealthyExactMatch(t *testing.T) {
	now := time.Now()
	cond := func(typ string, age time.Duration) kube.Condition {
		return kube.Condition{Type: typ, Status: "False",
			LastTransitionTime: now.Add(-age)}
	}
	cnpg := []string{"ContinuousArchiving", "LastBackupSucceeded"}
	percona := []string{"ReadyForBackup", "PGBackRestManualBackupSuccessful"}
	cases := []struct {
		name     string
		c        kube.Condition
		conds    []string
		fallback bool
		want     bool
	}{
		{"cnpg archiving stale", cond("ContinuousArchiving", time.Hour), cnpg, false, true},
		{"cnpg last backup stale", cond("LastBackupSucceeded", time.Hour), cnpg, false, true},
		{"cnpg benign custom backup type", cond("BackupScheduleConfigured", time.Hour), cnpg, false, false},
		{"cnpg custom wal-ish type", cond("WALRolloutInProgress", time.Hour), cnpg, false, false},
		{"percona readyforbackup stale", cond("ReadyForBackup", time.Hour), percona, false, true},
		{"percona manual backup stale", cond("PGBackRestManualBackupSuccessful", time.Hour), percona, false, true},
		// Real Percona type, but NOT in the set the old substring net
		// ever matched ("pgbackrest..." does not contain "backup") —
		// pinned so the exact list stays prior-coverage-preserving.
		{"percona out-of-set real type", cond("PGBackRestRepoHostReady", time.Hour), percona, false, false},
		{"young condition", cond("ContinuousArchiving", time.Minute), cnpg, false, false},
		{"true condition", func() kube.Condition {
			c := cond("ContinuousArchiving", time.Hour)
			c.Status = "True"
			return c
		}(), cnpg, false, false},
		{"absent transition", kube.Condition{Type: "ContinuousArchiving",
			Status: "False"}, cnpg, false, false},
		// The bare substring net survives ONLY on the family that
		// opted in (Everest — condition types not a documented closed
		// enum): an undocumented wal type flags, AND so does a benign
		// custom backup type there — that is the documented
		// trade-off, detection-only check.
		{"everest fallback undocumented wal type", cond("WalArchiveDraining", time.Hour), nil, true, true},
		{"everest fallback custom backup type", cond("BackupScheduleConfigured", time.Hour), nil, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := pgWALConditionUnhealthy(c.c, c.conds, c.fallback, now); got != c.want {
				t.Fatalf("pgWALConditionUnhealthy(%s) = %v, want %v",
					c.c.Type, got, c.want)
			}
		})
	}
}

// scanCRConditions level: the family wiring — a benign custom
// "backup" condition on a documented family (CNPG) emits nothing, the
// family's real types flag, and the Everest bare-net family still
// surfaces an undocumented wal type.
func TestPostgresWALScanCRConditionFamilies(t *testing.T) {
	base := time.Now()
	stale := base.Add(-time.Hour).UTC().Format(time.RFC3339)
	benign := cnpgCluster("db", "pg-benign", time.Hour)
	benign.Object["status"].(map[string]any)["conditions"] = []any{
		map[string]any{
			"type": "BackupScheduleConfigured", "status": "False",
			"lastTransitionTime": stale}}
	known := cnpgCluster("db", "pg-known", time.Hour) // ContinuousArchiving=False
	everest := testutil.Unstructured(
		kube.GVREverestDatabaseCluster.GroupVersion().WithKind("DatabaseCluster"),
		"db", "ev1", map[string]any{"status": map[string]any{
			"conditions": []any{map[string]any{
				"type": "WalArchiveDraining", "status": "False",
				"lastTransitionTime": stale}}}})
	p := testProberDyn(fake.NewSimpleClientset(),
		probetest.OpDyn(benign, known, everest))
	chk := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p)
	var rep probefw.SweepReport
	s := newWALGuardSweep(chk, logr.Discard(), base, &rep)
	if _, err := s.scanCRConditions(ctx); err != nil {
		t.Fatal(err)
	}
	if _, hit := s.findings["db/pg-benign/archive_condition"]; hit {
		t.Fatal("benign custom backup condition flagged")
	}
	if _, hit := s.findings["db/pg-known/archive_condition"]; !hit {
		t.Fatal("known ContinuousArchiving condition did not flag")
	}
	if _, hit := s.findings["db/ev1/archive_condition"]; !hit {
		t.Fatal("undocumented everest wal condition did not flag " +
			"(bare-net fallback family)")
	}
}

// ---------------------------------------------------------------------------
// scanPromSignals — the two per-family OR queries + the series
// classification
// ---------------------------------------------------------------------------

// The slot/archiver signals collapse to TWO instant queries — one per
// exporter family, each ORing that family's archiver branch with its
// two inactive-slot spellings — plus the volume query. The exact
// strings are pinned: threshold, the `on(...)` join labels and the
// per-family metric names are the semantics contract.
func TestPostgresWALPromQueryStrings(t *testing.T) {
	var queries []string
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		queries = append(queries, query)
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
	if !res.Pass {
		t.Fatalf("no series — sweep must pass quietly: %+v", res)
	}
	const wantPG = `(increase(pg_stat_archiver_failed_count[30m]) > 0) or ` +
		`(pg_replication_slots_retained_bytes{active="false"} > 5368709120) or ` +
		`(pg_replication_slots_active == 0 and on(namespace, pod, slot_name) ` +
		`(pg_replication_slots_pg_wal_lsn_diff > 5368709120 or ` +
		`pg_replication_slots_confirmed_flush_lsn_wal_lsn_diff > 5368709120))`
	const wantCNPG = `(increase(cnpg_pg_stat_archiver_failed_count[30m]) > 0) or ` +
		`(cnpg_pg_replication_slots_retained_bytes{active="false"} > 5368709120) or ` +
		`(cnpg_pg_replication_slots_active == 0 and on(namespace, pod, slot_name) ` +
		`(cnpg_pg_replication_slots_retained_bytes > 5368709120 or ` +
		`cnpg_pg_replication_slots_pg_wal_lsn_diff > 5368709120))`
	if len(queries) != 3 {
		t.Fatalf("prom queries = %d (%v), want 3 (pg family, cnpg family, volume)",
			len(queries), queries)
	}
	if queries[0] != wantPG {
		t.Fatalf("postgres_exporter family query drifted:\n got %s\nwant %s",
			queries[0], wantPG)
	}
	if queries[1] != wantCNPG {
		t.Fatalf("cnpg exporter family query drifted:\n got %s\nwant %s",
			queries[1], wantCNPG)
	}
	if !strings.Contains(queries[2], "kubelet_volume_stats") {
		t.Fatalf("third query is not the volume query: %s", queries[2])
	}
}

// The archiver branch is a range-function call — increase() DROPS
// __name__ — so the classifier reads slot identity: a series with a
// slot_name label (or a replication_slots name) is inactive_slot +
// slot-bloat; everything else is archiver_failing. A nameless,
// slot-less archiver sample must NOT leak into the slot-bloat gauge.
func TestPostgresWALPromArchiverClassified(t *testing.T) {
	testutil.CleanupMetric(t, postgresWALUnhealthyGauge, "db", "pg-main", "archiver_failing")
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, "stat_archiver") &&
			!strings.Contains(query, "cnpg_pg_") {
			return []probetest.PromTestSample{{
				Labels: map[string]string{
					"__name__":  "pg_stat_archiver_failed_count",
					"namespace": "db", "cluster": "pg-main"},
				Value: 3,
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
		t.Fatal("archiver-failure series must fail the check")
	}
	if !strings.Contains(res.Why, "archiver_failing") {
		t.Fatalf("why missing archiver_failing: %q", res.Why)
	}
	if v, ok := testutil.GaugeSeriesValue(t, "node_automation_postgres_wal_archive_unhealthy",
		map[string]string{"namespace": "db", "cluster": "pg-main",
			"reason": "archiver_failing"}); !ok || v != 1 {
		t.Fatalf("archiver_failing gauge = %v,%v want 1,true", v, ok)
	}
	if m := probetest.FindMetric(t, "node_automation_postgres_inactive_slot_wal_bloat",
		map[string]string{"namespace": "db", "cluster": "pg-main", "slot": "-"}); m != nil {
		t.Fatal("archiver sample leaked into the slot-bloat gauge")
	}
}
