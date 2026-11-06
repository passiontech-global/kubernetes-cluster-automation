// scylla_compaction_schema_guard_test.go — coverage for the
// scylla-compaction-schema-guard check: backlog gauge above the
// threshold and divergent coordinator schema versions.
package datastore

import (
	"net/http"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// scyllaMember builds a Ready Scylla member pod carrying the cluster
// label and the given podIP.
func scyllaMember(ns, name, cluster, ip string) *corev1.Pod {
	pod := probetest.PodWithPhase(ns, name, corev1.PodRunning, true, time.Hour)
	pod.Labels = map[string]string{scyllaClusterLabel: cluster}
	pod.Status.PodIP = ip
	return pod
}

// scyllaMetricsTransport serves per-IP :9180/metrics bodies.
func scyllaMetricsTransport(bodies map[string]string) *testutil.StubTransport {
	return &testutil.StubTransport{Fn: func(r *http.Request) (*http.Response, error) {
		ip := strings.Split(r.URL.Host, ":")[0]
		if body, ok := bodies[ip]; ok {
			return testutil.ProbeResponse(200, body), nil
		}
		return testutil.ProbeResponse(500, ""), nil
	}}
}

func TestScyllaCompactionBacklogFails(t *testing.T) {
	pod := scyllaMember("scylla", "scylla-dc1-0", "dc1", "10.0.0.1")
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	p.HTTPClient = &http.Client{Transport: scyllaMetricsTransport(map[string]string{
		"10.0.0.1": "scylla_compaction_manager_pending_compactions{shard=\"0\"} 250\n" +
			"scylla_storage_proxy_coordinator_schema_version{shard=\"0\"} 7\n",
	})}
	res := probetest.MustCheck[*scyllaCompactionSchemaGuardCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("backlog >%d must fail: %+v", scyllaCompactionBacklogMax, res)
	}
	if !strings.Contains(res.Why, "scylla-dc1-0") {
		t.Fatalf("why missing pod: %q", res.Why)
	}
	if v, ok := testutil.GaugeSeriesValue(t, "node_automation_scylla_compaction_backlog",
		map[string]string{"namespace": "scylla", "pod": "scylla-dc1-0"}); !ok || v != 250 {
		t.Fatalf("backlog gauge = %v,%v want 250,true", v, ok)
	}
}

func TestScyllaSchemaSplitFails(t *testing.T) {
	p1 := scyllaMember("scylla", "scylla-dc1-0", "dc1", "10.0.0.1")
	p2 := scyllaMember("scylla", "scylla-dc1-1", "dc1", "10.0.0.2")
	cs := fake.NewSimpleClientset(p1, p2)
	p := testProber(cs)
	p.HTTPClient = &http.Client{Transport: scyllaMetricsTransport(map[string]string{
		"10.0.0.1": "scylla_storage_proxy_coordinator_schema_version{shard=\"0\"} 7\n",
		"10.0.0.2": "scylla_storage_proxy_coordinator_schema_version{shard=\"0\"} 9\n",
	})}
	res := probetest.MustCheck[*scyllaCompactionSchemaGuardCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("divergent schema versions must fail: %+v", res)
	}
	if v, ok := testutil.GaugeSeriesValue(t, "node_automation_scylla_schema_split",
		map[string]string{"namespace": "scylla", "cluster": "dc1"}); !ok || v != 1 {
		t.Fatalf("split gauge = %v,%v want 1,true", v, ok)
	}
}

func TestScyllaUniformVersionsPass(t *testing.T) {
	p1 := scyllaMember("scylla", "scylla-dc1-0", "dc1", "10.0.0.1")
	p2 := scyllaMember("scylla", "scylla-dc1-1", "dc1", "10.0.0.2")
	cs := fake.NewSimpleClientset(p1, p2)
	p := testProber(cs)
	p.HTTPClient = &http.Client{Transport: scyllaMetricsTransport(map[string]string{
		"10.0.0.1": "scylla_compaction_manager_pending_compactions{shard=\"0\"} 12\n" +
			"scylla_storage_proxy_coordinator_schema_version{shard=\"0\"} 7\n",
		"10.0.0.2": "scylla_storage_proxy_coordinator_schema_version{shard=\"0\"} 7\n",
	})}
	res := probetest.MustCheck[*scyllaCompactionSchemaGuardCheck](t, p).Run(ctx)
	if !res.Pass {
		t.Fatalf("uniform schema + low backlog must pass: %+v", res)
	}
}
