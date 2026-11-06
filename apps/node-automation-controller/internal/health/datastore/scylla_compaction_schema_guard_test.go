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

// W12-ST3 — a pod whose busiest shard is saturated (0.99) while the
// shard-average idles (~0.43) is the hot-partition skew: tracked on
// first sight, gauge + FAIL past the 10m window.
func TestScyllaShardImbalancePersists(t *testing.T) {
	scyllaShardImbalanceGauge.DeleteLabelValues("scylla", "scylla-dc1-0")
	t.Cleanup(func() {
		scyllaShardImbalanceGauge.DeleteLabelValues("scylla", "scylla-dc1-0")
	})
	base := time.Now()
	pod := scyllaMember("scylla", "scylla-dc1-0", "dc1", "10.0.0.1")
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	p.Now = func() time.Time { return base }
	p.HTTPClient = &http.Client{Transport: scyllaMetricsTransport(map[string]string{
		"10.0.0.1": "scylla_reactor_utilization{shard=\"0\"} 0.99\n" +
			"scylla_reactor_utilization{shard=\"1\"} 0.20\n" +
			"scylla_reactor_utilization{shard=\"2\"} 0.10\n" +
			"scylla_storage_proxy_coordinator_schema_version{shard=\"0\"} 7\n",
	})}

	if res := probetest.MustCheck[*scyllaCompactionSchemaGuardCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("first skew sighting inside the window must pass: %+v", res)
	}
	p.Now = func() time.Time {
		return base.Add(scyllaShardImbalanceMinAge + time.Minute)
	}
	res := probetest.MustCheck[*scyllaCompactionSchemaGuardCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("persisted shard skew did not fail the check")
	}
	m := probetest.FindMetric(t, "node_automation_scylla_shard_imbalance",
		map[string]string{"namespace": "scylla", "pod": "scylla-dc1-0"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("shard imbalance gauge = %v, want 1", m)
	}
}

// A pod with every shard busy is NOT the skew signature — a
// uniformly hot pod is load, not a hot partition.
func TestScyllaUniformHotShardsNoSkew(t *testing.T) {
	base := time.Now()
	pod := scyllaMember("scylla", "scylla-dc1-0", "dc1", "10.0.0.1")
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	p.Now = func() time.Time { return base }
	p.HTTPClient = &http.Client{Transport: scyllaMetricsTransport(map[string]string{
		"10.0.0.1": "scylla_reactor_utilization{shard=\"0\"} 0.99\n" +
			"scylla_reactor_utilization{shard=\"1\"} 0.98\n" +
			"scylla_reactor_utilization{shard=\"2\"} 0.99\n",
	})}
	probetest.MustCheck[*scyllaCompactionSchemaGuardCheck](t, p).Run(ctx)
	p.Now = func() time.Time {
		return base.Add(scyllaShardImbalanceMinAge + time.Minute)
	}
	if res := probetest.MustCheck[*scyllaCompactionSchemaGuardCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("uniformly hot shards must not read as imbalance: %+v", res)
	}
}

// W12-ST3 — a stall counter climbing between sweeps is a live
// overload stall: first scrape only stores the baseline, second
// scrape with +12 read timeouts emits the delta.
func TestScyllaOverloadStallDelta(t *testing.T) {
	scyllaOverloadStallGauge.DeleteLabelValues("scylla", "scylla-dc1-0",
		scyllaOverloadReasonReadTimeouts)
	t.Cleanup(func() {
		scyllaOverloadStallGauge.DeleteLabelValues("scylla", "scylla-dc1-0",
			scyllaOverloadReasonReadTimeouts)
	})
	pod := scyllaMember("scylla", "scylla-dc1-0", "dc1", "10.0.0.1")
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	bodies := map[string]string{
		"10.0.0.1": "scylla_storage_proxy_coordinator_read_timeouts{shard=\"0\"} 40\n" +
			"scylla_database_sstable_read_queue_overloads{shard=\"0\"} 3\n",
	}
	p.HTTPClient = &http.Client{Transport: scyllaMetricsTransport(bodies)}

	// First scrape only stores the counter baseline.
	if res := probetest.MustCheck[*scyllaCompactionSchemaGuardCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("baseline scrape must pass: %+v", res)
	}
	bodies["10.0.0.1"] = "scylla_storage_proxy_coordinator_read_timeouts{shard=\"0\"} 52\n" +
		"scylla_database_sstable_read_queue_overloads{shard=\"0\"} 3\n"
	res := probetest.MustCheck[*scyllaCompactionSchemaGuardCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("climbing read-timeouts must fail the check")
	}
	m := probetest.FindMetric(t, "node_automation_scylla_overload_stall",
		map[string]string{"namespace": "scylla", "pod": "scylla-dc1-0",
			"reason": scyllaOverloadReasonReadTimeouts})
	if m == nil || m.GetGauge().GetValue() != 12 {
		t.Fatalf("overload stall gauge = %v, want delta 12", m)
	}
}

// A counter that DROPPED between sweeps means the pod restarted its
// counters — no delta, no stall reading.
func TestScyllaOverloadCounterReset(t *testing.T) {
	pod := scyllaMember("scylla", "scylla-dc1-0", "dc1", "10.0.0.1")
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	bodies := map[string]string{
		"10.0.0.1": "scylla_database_querier_cache_drops{shard=\"0\"} 100\n",
	}
	p.HTTPClient = &http.Client{Transport: scyllaMetricsTransport(bodies)}
	probetest.MustCheck[*scyllaCompactionSchemaGuardCheck](t, p).Run(ctx)
	bodies["10.0.0.1"] = "scylla_database_querier_cache_drops{shard=\"0\"} 4\n"
	if res := probetest.MustCheck[*scyllaCompactionSchemaGuardCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("counter reset must pass: %+v", res)
	}
}
