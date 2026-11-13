// snapshot_bench_test.go — benchmarks for the Wave-5 lazy snapshot
// machinery: the workload censusIndex by-key lookups and the
// per-sweep promMemo dedupe. Inputs are synthesized (fake clientset,
// httptest Prometheus) — no cluster, no real sweeps.
package probefw

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

// benchIndexCensus is a check-scale Deployment census: the workload
// census one 32-module sweep sees on a loaded cluster.
const benchIndexCensus = 1000

func benchDeployments() []runtime.Object {
	objs := make([]runtime.Object, benchIndexCensus)
	for i := range objs {
		objs[i] = &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
			Namespace: fmt.Sprintf("ns%d", i%10),
			Name:      fmt.Sprintf("web-%d", i),
		}}
	}
	return objs
}

// BenchmarkSweepSnapshotIndex measures the steady-state by-key
// lookups the ownership/heal joins pay through the lazy censusIndex
// after the snapshot's Deployment census is warm — the path that
// used to linear-scan the whole census slice per lookup. One lookup
// in eleven misses (absent workload), mirroring a join that checks
// for a controller that may not exist.
func BenchmarkSweepSnapshotIndex(b *testing.B) {
	b.ReportAllocs()
	cs := fake.NewSimpleClientset(benchDeployments()...)
	d := &Deps{CS: cs}
	ctx := WithSweepSnapshot(context.Background())

	// Warm the census + index once — everything inside b.Loop is a
	// point lookup, never a re-LIST (the sweep snapshot memoizes
	// the census for the whole sweep).
	if _, err := d.Deployment(ctx, "ns0", "web-0"); err != nil {
		b.Fatalf("warmup lookup: %v", err)
	}

	type key struct{ ns, name string }
	keys := make([]key, 0, 110)
	for i := range 100 {
		keys = append(keys, key{fmt.Sprintf("ns%d", i%10), fmt.Sprintf("web-%d", i)})
	}
	for i := range 10 {
		keys = append(keys, key{"ns0", fmt.Sprintf("absent-%d", i)})
	}

	hits := 0
	i := 0
	for b.Loop() {
		k := keys[i%len(keys)]
		dep, err := d.Deployment(ctx, k.ns, k.name)
		if err != nil {
			b.Fatalf("lookup %s/%s: %v", k.ns, k.name, err)
		}
		if dep != nil {
			hits++
		}
		i++
	}
	if hits == 0 {
		b.Fatal("every lookup missed — index is not serving hits")
	}
}

// BenchmarkPromMemo measures the per-sweep promMemo dedupe path:
// repeated byte-identical PromQL inside one sweep hits the memo
// (map lock + key compose) instead of paying a Prometheus round
// trip — the join several checks used to pay once each.
func BenchmarkPromMemo(b *testing.B) {
	b.ReportAllocs()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"pod":"p1"},"value":[1700000000,"3.5"]}]}}`)
	}))
	defer srv.Close()

	d := NewDeps("", nil, nil, nil, Config{})
	d.promEndpointOverride = srv.URL + "/api/v1/query"
	d.HTTPClient = srv.Client()
	d.Prom.HTTP = d.HTTPClient
	ctx := WithSweepSnapshot(context.Background())

	// Warm the memo once — b.Loop measures the dedupe hit path.
	if _, err := d.PromQuery(ctx, "up"); err != nil {
		b.Fatalf("warmup query: %v", err)
	}
	for b.Loop() {
		if _, err := d.PromQuery(ctx, "up"); err != nil {
			b.Fatalf("query: %v", err)
		}
	}
}
