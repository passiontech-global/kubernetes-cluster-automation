// cnpg_health_test.go — coverage for the W19-ST1 cnpg-health
// additions: the primary_mismatch signature and the
// fenced_instances detect + safe auto-unfence path.
package datastore

import (
	"encoding/json"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// cnpgClusterPrimary builds a healthy CNPG Cluster whose
// status.currentPrimary/targetPrimary disagree — the
// primary_mismatch signature.
func cnpgClusterPrimary(ns, name, current, target string) *unstructured.Unstructured {
	cr := cnpgClusterHealth(ns, name, "Healthy", 2*time.Hour, 3, 3)
	_ = unstructured.SetNestedField(cr.Object, current,
		"status", "currentPrimary")
	_ = unstructured.SetNestedField(cr.Object, target,
		"status", "targetPrimary")
	return cr
}

// cnpgClusterFenced builds a healthy CNPG Cluster carrying the
// fencedInstances annotation — the fenced_instances signature.
func cnpgClusterFenced(ns, name, fenced string) *unstructured.Unstructured {
	cr := cnpgClusterHealth(ns, name, "Healthy", 2*time.Hour, 3, 3)
	cr.SetAnnotations(map[string]string{cnpgFencedInstancesAnno: fenced})
	return cr
}

// fencedPod builds the instance pod the unfence path resolves —
// Running on nodeName so cnpgInstanceOnHealthyNode can verify it.
func fencedPod(ns, cluster, inst, nodeName string) *corev1.Pod {
	pod := probetest.PodWithPhase(ns, inst, corev1.PodRunning, true, time.Hour)
	pod.Labels = map[string]string{
		"cnpg.io/cluster":      cluster,
		"cnpg.io/instanceName": inst,
	}
	pod.Spec.NodeName = nodeName
	return pod
}

// fencedAnnotation reads the fencedInstances annotation off the
// live object — "" when the key is absent.
func fencedAnnotation(t *testing.T, p *probetest.Prober,
	ns, name string) string {
	t.Helper()
	u, err := p.Deps.Dyn.Resource(kube.GVRCNPGCluster).Namespace(ns).
		Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	v, _, _ := unstructured.NestedString(u.Object,
		"metadata", "annotations", cnpgFencedInstancesAnno)
	return v
}

// currentPrimary != targetPrimary held past the window flags
// primary_mismatch on the first-seen ledger path — the operator has
// no transition timestamp for a target that never lands.
func TestCNPGPrimaryMismatchFlags(t *testing.T) {
	testutil.CleanupMetric(t, cnpgClusterUnhealthyGauge,
		"db", "pg-pm", "primary_mismatch")
	now := time.Now()
	cr := cnpgClusterPrimary("db", "pg-pm", "pg-pm-1", "pg-pm-2")
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(cr))
	chk := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, now)
	if res := chk.Run(ctx); res.Pass {
		if _, ok := cnpgSeries(t, "db", "pg-pm", "primary_mismatch"); ok {
			t.Fatal("primary_mismatch flagged on first sight")
		}
	}
	probetest.FreezeNow(p.Deps, now.Add(16*time.Minute))
	res := chk.Run(ctx)
	if res.Pass {
		t.Fatal("primary mismatch held past the window must fail")
	}
	if v, ok := cnpgSeries(t, "db", "pg-pm",
		"primary_mismatch"); !ok || v != 1 {
		t.Fatalf("primary_mismatch series = %v,%v want 1,true", v, ok)
	}
}

// Matching primaries emit nothing — a completed switchover where
// currentPrimary already equals targetPrimary is healthy.
func TestCNPGPrimaryMatchPasses(t *testing.T) {
	cr := cnpgClusterPrimary("db", "pg-pm-ok", "pg-pm-ok-1", "pg-pm-ok-1")
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(cr))
	res := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p).Run(ctx)
	if !res.Pass {
		t.Fatalf("matching primaries must pass: %+v", res)
	}
	if _, ok := cnpgSeries(t, "db", "pg-pm-ok", "primary_mismatch"); ok {
		t.Fatal("primary_mismatch series on matching primaries")
	}
}

// instances > 0 with NO elected primary (currentPrimary absent) is
// the other half of the signature — the cluster is read-only or
// stuck initializing.
func TestCNPGPrimaryEmptyFlags(t *testing.T) {
	testutil.CleanupMetric(t, cnpgClusterUnhealthyGauge,
		"db", "pg-noprimary", "primary_mismatch")
	now := time.Now()
	cr := cnpgClusterHealth("db", "pg-noprimary", "Healthy",
		-1, 3, 3)
	unstructured.RemoveNestedField(cr.Object, "status", "currentPrimary")
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(cr))
	chk := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, now)
	if res := chk.Run(ctx); !res.Pass {
		t.Fatalf("first sight must arm, not fail: %+v", res)
	}
	probetest.FreezeNow(p.Deps, now.Add(16*time.Minute))
	res := chk.Run(ctx)
	if res.Pass {
		t.Fatal("missing primary held past the window must fail")
	}
	if v, ok := cnpgSeries(t, "db", "pg-noprimary",
		"primary_mismatch"); !ok || v != 1 {
		t.Fatalf("primary_mismatch series = %v,%v want 1,true", v, ok)
	}
}

// A zero-instance cluster is still bootstrapping — no primary is
// expected, so primary_mismatch stays silent.
func TestCNPGPrimaryEmptyZeroInstancesPasses(t *testing.T) {
	cr := cnpgClusterHealth("db", "pg-bootstrap", "Healthy",
		-1, 0, 0)
	unstructured.RemoveNestedField(cr.Object, "status", "currentPrimary")
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(cr))
	res := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p).Run(ctx)
	if !res.Pass {
		t.Fatalf("zero-instance cluster must pass: %+v", res)
	}
	if _, ok := cnpgSeries(t, "db", "pg-bootstrap",
		"primary_mismatch"); ok {
		t.Fatal("primary_mismatch series on a bootstrapping cluster")
	}
}

// A non-empty fencedInstances annotation past the window flags
// fenced_instances — and with no pod census evidence the heal half
// must NOT touch the annotation (fail closed on partial evidence).
func TestCNPGFencedInstancesDetectOnly(t *testing.T) {
	testutil.CleanupMetric(t, cnpgClusterUnhealthyGauge,
		"db", "pg-f", "fenced_instances")
	now := time.Now()
	cr := cnpgClusterFenced("db", "pg-f", "pg-f-2")
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(cr))
	chk := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, now)
	if res := chk.Run(ctx); res.Pass {
		if _, ok := cnpgSeries(t, "db", "pg-f", "fenced_instances"); ok {
			t.Fatal("fenced_instances flagged on first sight")
		}
	}
	probetest.FreezeNow(p.Deps, now.Add(16*time.Minute))
	res := chk.Run(ctx)
	if res.Pass {
		t.Fatal("fenced instances held past the window must fail")
	}
	if v, ok := cnpgSeries(t, "db", "pg-f",
		"fenced_instances"); !ok || v != 1 {
		t.Fatalf("fenced_instances series = %v,%v want 1,true", v, ok)
	}
	if got := fencedAnnotation(t, p, "db", "pg-f"); got != "pg-f-2" {
		t.Fatalf("annotation = %q, want unchanged pg-f-2", got)
	}
}

// The safe auto-unfence: the fenced instance's pod is verifiably
// Running on a Ready, schedulable, untainted node — the fence is
// stale and the annotation loses that instance.
func TestCNPGFencedInstanceAutoUnfence(t *testing.T) {
	testutil.CleanupMetric(t, cnpgClusterUnhealthyGauge,
		"db", "pg-f", "fenced_instances")
	now := time.Now()
	cr := cnpgClusterFenced("db", "pg-f", "pg-f-1,pg-f-2")
	node := testutil.Node("w1", corev1.ConditionTrue, nil)
	pod1 := fencedPod("db", "pg-f", "pg-f-1", "w1")
	// pg-f-2 has no pod — stays fenced.
	cs := fake.NewSimpleClientset(node, pod1)
	p := testProberDyn(cs, probetest.OpDyn(cr))
	chk := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, now)
	if res := chk.Run(ctx); !res.Pass {
		t.Fatalf("first sight must arm, not fail: %+v", res)
	}
	probetest.FreezeNow(p.Deps, now.Add(16*time.Minute))
	res := chk.Run(ctx)
	if res.Pass {
		t.Fatal("fenced_instances held past the window must fail")
	}
	if got := fencedAnnotation(t, p, "db", "pg-f"); got != "pg-f-2" {
		t.Fatalf("annotation = %q, want pg-f-2 only", got)
	}
}

// The unfence merge patch pins the List snapshot's resourceVersion:
// a fence the CNPG operator writes between List and Patch turns the
// patch into a conflict (skipped this cycle — the operator's
// protective write survives) instead of being silently dropped by
// the merge.
func TestCNPGUnfencePatchPinsResourceVersion(t *testing.T) {
	testutil.CleanupMetric(t, cnpgClusterUnhealthyGauge,
		"db", "pg-f", "fenced_instances")
	now := time.Now()
	cr := cnpgClusterFenced("db", "pg-f", "pg-f-1")
	cr.SetResourceVersion("4217")
	node := testutil.Node("w1", corev1.ConditionTrue, nil)
	pod := fencedPod("db", "pg-f", "pg-f-1", "w1")
	cs := fake.NewSimpleClientset(node, pod)
	dyn := probetest.OpDyn(cr)
	var body string
	dyn.PrependReactor("patch", "clusters",
		func(action ktesting.Action) (bool, runtime.Object, error) {
			body = string(action.(ktesting.PatchAction).GetPatch())
			return false, nil, nil // fall through to the fake's write
		})
	p := testProberDyn(cs, dyn)
	chk := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, now)
	_ = chk.Run(ctx)
	probetest.FreezeNow(p.Deps, now.Add(16*time.Minute))
	chk.Run(ctx)
	if body == "" {
		t.Fatal("stale fence with a verified-healthy pod must unfence")
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("patch body %q: %v", body, err)
	}
	meta, _ := doc["metadata"].(map[string]any)
	if rv, _ := meta["resourceVersion"].(string); rv != "4217" {
		t.Fatalf("unfence patch must pin the List snapshot's resourceVersion, got %v", doc)
	}
	annos, _ := meta["annotations"].(map[string]any)
	if got, ok := annos[cnpgFencedInstancesAnno]; !ok || got != nil {
		t.Fatalf("single-instance unfence must delete the annotation key, got %v", annos)
	}
}

// A fenced instance whose pod sits on a remediation-tainted node is
// NOT auto-unfenced — the fence may be protective.
func TestCNPGFencedInstanceTaintedNodeStays(t *testing.T) {
	testutil.CleanupMetric(t, cnpgClusterUnhealthyGauge,
		"db", "pg-f", "fenced_instances")
	now := time.Now()
	cr := cnpgClusterFenced("db", "pg-f", "pg-f-1")
	node := testutil.Node("w1", corev1.ConditionTrue, nil,
		corev1.Taint{
			Key:    kube.TaintKubeletUnresponsive,
			Effect: corev1.TaintEffectNoSchedule,
		})
	pod := fencedPod("db", "pg-f", "pg-f-1", "w1")
	cs := fake.NewSimpleClientset(node, pod)
	p := testProberDyn(cs, probetest.OpDyn(cr))
	chk := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, now)
	if res := chk.Run(ctx); !res.Pass {
		t.Fatalf("first sight must arm, not fail: %+v", res)
	}
	probetest.FreezeNow(p.Deps, now.Add(16*time.Minute))
	res := chk.Run(ctx)
	if res.Pass {
		t.Fatal("fenced_instances held past the window must fail")
	}
	if got := fencedAnnotation(t, p, "db", "pg-f"); got != "pg-f-1" {
		t.Fatalf("annotation = %q, want unchanged pg-f-1", got)
	}
}

// An unschedulable node is out-of-service evidence too — no unfence.
func TestCNPGFencedInstanceUnschedulableStays(t *testing.T) {
	testutil.CleanupMetric(t, cnpgClusterUnhealthyGauge,
		"db", "pg-f", "fenced_instances")
	now := time.Now()
	cr := cnpgClusterFenced("db", "pg-f", "pg-f-1")
	node := testutil.Node("w1", corev1.ConditionTrue, nil)
	node.Spec.Unschedulable = true
	pod := fencedPod("db", "pg-f", "pg-f-1", "w1")
	cs := fake.NewSimpleClientset(node, pod)
	p := testProberDyn(cs, probetest.OpDyn(cr))
	chk := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, now)
	if res := chk.Run(ctx); !res.Pass {
		t.Fatalf("first sight must arm, not fail: %+v", res)
	}
	probetest.FreezeNow(p.Deps, now.Add(16*time.Minute))
	res := chk.Run(ctx)
	if res.Pass {
		t.Fatal("fenced_instances held past the window must fail")
	}
	if got := fencedAnnotation(t, p, "db", "pg-f"); got != "pg-f-1" {
		t.Fatalf("annotation = %q, want unchanged pg-f-1", got)
	}
}

// "*" fences the whole cluster — never auto-cleared even when a
// healthy pod exists; detection still fires.
func TestCNPGFencedWholeClusterStarStays(t *testing.T) {
	testutil.CleanupMetric(t, cnpgClusterUnhealthyGauge,
		"db", "pg-f", "fenced_instances")
	now := time.Now()
	cr := cnpgClusterFenced("db", "pg-f", "*")
	node := testutil.Node("w1", corev1.ConditionTrue, nil)
	pod := fencedPod("db", "pg-f", "pg-f-1", "w1")
	cs := fake.NewSimpleClientset(node, pod)
	p := testProberDyn(cs, probetest.OpDyn(cr))
	chk := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, now)
	if res := chk.Run(ctx); !res.Pass {
		t.Fatalf("first sight must arm, not fail: %+v", res)
	}
	probetest.FreezeNow(p.Deps, now.Add(16*time.Minute))
	res := chk.Run(ctx)
	if res.Pass {
		t.Fatal("fenced_instances held past the window must fail")
	}
	if got := fencedAnnotation(t, p, "db", "pg-f"); got != "*" {
		t.Fatalf("annotation = %q, want unchanged *", got)
	}
}

// First sight of a fence never unfences — the fence ledger has no
// persisted window yet even with a verified-healthy pod behind it.
func TestCNPGFencedInstanceFirstSweepStays(t *testing.T) {
	testutil.CleanupMetric(t, cnpgClusterUnhealthyGauge,
		"db", "pg-f", "fenced_instances")
	now := time.Now()
	cr := cnpgClusterFenced("db", "pg-f", "pg-f-1")
	node := testutil.Node("w1", corev1.ConditionTrue, nil)
	pod := fencedPod("db", "pg-f", "pg-f-1", "w1")
	cs := fake.NewSimpleClientset(node, pod)
	p := testProberDyn(cs, probetest.OpDyn(cr))
	chk := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, now)
	if res := chk.Run(ctx); !res.Pass {
		t.Fatalf("first sight must arm, not fail: %+v", res)
	}
	if got := fencedAnnotation(t, p, "db", "pg-f"); got != "pg-f-1" {
		t.Fatalf("annotation = %q, want unchanged pg-f-1", got)
	}
}
