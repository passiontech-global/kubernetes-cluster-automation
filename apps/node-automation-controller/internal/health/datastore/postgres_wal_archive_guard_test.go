// postgres_wal_archive_guard_test.go — coverage for the
// postgres-wal-archive-guard check: CR archive conditions, pod-log
// disk-full evidence and Prometheus archiver/slot/volume evidence.
package datastore

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
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
