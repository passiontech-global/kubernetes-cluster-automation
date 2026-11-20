// cnpg_health_test.go — coverage for the cnpg-cluster-health cnpg-health
// additions: the primary_mismatch signature and the
// fenced_instances detect + safe auto-unfence path.
package postgres

import (
	json "encoding/json/v2"
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
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
	// The unfence guard never touches the elected primary or a
	// cluster mid-failover — point status.primary at an instance the
	// fence lists never name so the fixture exercises the
	// stale-fence path, not the primary-protection block.
	_ = unstructured.SetNestedField(cr.Object, name+"-0",
		"status", "currentPrimary")
	_ = unstructured.SetNestedField(cr.Object, name+"-0",
		"status", "targetPrimary")
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
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); res.Pass {
		if _, ok := cnpgSeries(t, "db", "pg-pm", "primary_mismatch"); ok {
			t.Fatal("primary_mismatch flagged on first sight")
		}
	}
	probetest.FreezeNow(p.Deps, now.Add(16*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
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
	res := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
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
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("first sight must arm, not fail: %+v", res)
	}
	probetest.FreezeNow(p.Deps, now.Add(16*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
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
	res := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
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
	cr := cnpgClusterFenced("db", "pg-f", `["pg-f-2"]`)
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(cr))
	chk := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, now)
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); res.Pass {
		if _, ok := cnpgSeries(t, "db", "pg-f", "fenced_instances"); ok {
			t.Fatal("fenced_instances flagged on first sight")
		}
	}
	probetest.FreezeNow(p.Deps, now.Add(16*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatal("fenced instances held past the window must fail")
	}
	if v, ok := cnpgSeries(t, "db", "pg-f",
		"fenced_instances"); !ok || v != 1 {
		t.Fatalf("fenced_instances series = %v,%v want 1,true", v, ok)
	}
	if got := fencedAnnotation(t, p, "db", "pg-f"); got != `["pg-f-2"]` {
		t.Fatalf("annotation = %q, want unchanged [\"pg-f-2\"]", got)
	}
}

// The safe auto-unfence: the fenced instance's pod is verifiably
// Running on a Ready, schedulable, untainted node — the fence is
// stale and the annotation loses that instance.
func TestCNPGFencedInstanceAutoUnfence(t *testing.T) {
	testutil.CleanupMetric(t, cnpgClusterUnhealthyGauge,
		"db", "pg-f", "fenced_instances")
	now := time.Now()
	cr := cnpgClusterFenced("db", "pg-f", `["pg-f-1","pg-f-2"]`)
	node := testutil.Node("w1", corev1.ConditionTrue, nil)
	pod1 := fencedPod("db", "pg-f", "pg-f-1", "w1")
	// pg-f-2 has no pod — stays fenced.
	cs := fake.NewSimpleClientset(node, pod1)
	p := testProberDyn(cs, probetest.OpDyn(cr))
	chk := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, now)
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("first sight must arm, not fail: %+v", res)
	}
	probetest.FreezeNow(p.Deps, now.Add(16*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatal("fenced_instances held past the window must fail")
	}
	if got := fencedAnnotation(t, p, "db", "pg-f"); got != `["pg-f-2"]` {
		t.Fatalf("annotation = %q, want [\"pg-f-2\"] only", got)
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
	cr := cnpgClusterFenced("db", "pg-f", `["pg-f-1"]`)
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
	_ = chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	probetest.FreezeNow(p.Deps, now.Add(16*time.Minute))
	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
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
	cr := cnpgClusterFenced("db", "pg-f", `["pg-f-1"]`)
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
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("first sight must arm, not fail: %+v", res)
	}
	probetest.FreezeNow(p.Deps, now.Add(16*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatal("fenced_instances held past the window must fail")
	}
	if got := fencedAnnotation(t, p, "db", "pg-f"); got != `["pg-f-1"]` {
		t.Fatalf("annotation = %q, want unchanged [\"pg-f-1\"]", got)
	}
}

// An unschedulable node is out-of-service evidence too — no unfence.
func TestCNPGFencedInstanceUnschedulableStays(t *testing.T) {
	testutil.CleanupMetric(t, cnpgClusterUnhealthyGauge,
		"db", "pg-f", "fenced_instances")
	now := time.Now()
	cr := cnpgClusterFenced("db", "pg-f", `["pg-f-1"]`)
	node := testutil.Node("w1", corev1.ConditionTrue, nil)
	node.Spec.Unschedulable = true
	pod := fencedPod("db", "pg-f", "pg-f-1", "w1")
	cs := fake.NewSimpleClientset(node, pod)
	p := testProberDyn(cs, probetest.OpDyn(cr))
	chk := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, now)
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("first sight must arm, not fail: %+v", res)
	}
	probetest.FreezeNow(p.Deps, now.Add(16*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatal("fenced_instances held past the window must fail")
	}
	if got := fencedAnnotation(t, p, "db", "pg-f"); got != `["pg-f-1"]` {
		t.Fatalf("annotation = %q, want unchanged [\"pg-f-1\"]", got)
	}
}

// "*" fences the whole cluster — never auto-cleared even when a
// healthy pod exists; detection still fires.
func TestCNPGFencedWholeClusterStarStays(t *testing.T) {
	testutil.CleanupMetric(t, cnpgClusterUnhealthyGauge,
		"db", "pg-f", "fenced_instances")
	now := time.Now()
	cr := cnpgClusterFenced("db", "pg-f", `["*"]`)
	node := testutil.Node("w1", corev1.ConditionTrue, nil)
	pod := fencedPod("db", "pg-f", "pg-f-1", "w1")
	cs := fake.NewSimpleClientset(node, pod)
	p := testProberDyn(cs, probetest.OpDyn(cr))
	chk := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, now)
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("first sight must arm, not fail: %+v", res)
	}
	probetest.FreezeNow(p.Deps, now.Add(16*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatal("fenced_instances held past the window must fail")
	}
	if got := fencedAnnotation(t, p, "db", "pg-f"); got != `["*"]` {
		t.Fatalf("annotation = %q, want unchanged [\"*\"]", got)
	}
}

// A fenced instance whose pod is terminating, not Running, or has an
// explicitly non-running container status must stay fenced.
func TestCNPGUnfenceRequiresLiveRunningPod(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*corev1.Pod)
	}{
		{"terminating", func(pod *corev1.Pod) {
			now := metav1.Now()
			pod.DeletionTimestamp = &now
		}},
		{"pending", func(pod *corev1.Pod) {
			pod.Status.Phase = corev1.PodPending
		}},
		{"waiting container", func(pod *corev1.Pod) {
			pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
				Name: "postgres",
				State: corev1.ContainerState{
					Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"},
				},
			}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cr := cnpgClusterFenced("db", "pg-live", `["pg-live-1"]`)
			node := testutil.Node("w1", corev1.ConditionTrue, nil)
			pod := fencedPod("db", "pg-live", "pg-live-1", "w1")
			tc.mut(pod)
			p := testProberDyn(fake.NewSimpleClientset(node, pod), probetest.OpDyn(cr))
			chk := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p)
			base := time.Now()
			probetest.FreezeNow(p.Deps, base)
			chk.Run(probetest.SweepCtx(ctx, chk.Deps))
			probetest.FreezeNow(p.Deps, base.Add(16*time.Minute))
			chk.Run(probetest.SweepCtx(ctx, chk.Deps))
			if got := fencedAnnotation(t, p, "db", "pg-live"); got != `["pg-live-1"]` {
				t.Fatalf("%s pod must stay fenced, annotation = %q", tc.name, got)
			}
		})
	}
}

// Fencing stops postmaster, keeping PodReady=False until unfenced. A
// PodRunning pod with PodReady=False on a healthy node must still
// auto-unfence after the 15m settle window.
func TestCNPGUnfenceAllowsUnreadyRunningPod(t *testing.T) {
	cr := cnpgClusterFenced("db", "pg-unready", `["pg-unready-1"]`)
	node := testutil.Node("w1", corev1.ConditionTrue, nil)
	pod := fencedPod("db", "pg-unready", "pg-unready-1", "w1")
	pod.Status.Conditions = []corev1.PodCondition{{
		Type: corev1.PodReady, Status: corev1.ConditionFalse,
	}}
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
		Name:  "postgres",
		Ready: false,
		State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
	}}
	p := testProberDyn(fake.NewSimpleClientset(node, pod), probetest.OpDyn(cr))
	chk := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p)
	base := time.Now()
	probetest.FreezeNow(p.Deps, base)
	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	probetest.FreezeNow(p.Deps, base.Add(16*time.Minute))
	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if got := fencedAnnotation(t, p, "db", "pg-unready"); got != "" {
		t.Fatalf("unready Running pod on healthy node should unfence, annotation = %q", got)
	}
}

// The persistence window only matures while the unfence safety gates
// hold. An instance fenced on a dead node does NOT bank 15m of window
// time: when its node recovers the window starts fresh, so one
// Ready flicker cannot strip a protective fence.
func TestCNPGUnfenceWindowStartsOnlyWhenSafe(t *testing.T) {
	cr := cnpgClusterFenced("db", "pg-settle", `["pg-settle-1"]`)
	badNode := testutil.Node("w1", corev1.ConditionFalse, nil)
	pod := fencedPod("db", "pg-settle", "pg-settle-1", "w1")
	cs := fake.NewSimpleClientset(badNode, pod)
	p := testProberDyn(cs, probetest.OpDyn(cr))
	chk := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p)
	base := time.Now()

	probetest.FreezeNow(p.Deps, base)
	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	probetest.FreezeNow(p.Deps, base.Add(16*time.Minute))
	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	// The node recovers — the first healthy sweep must only ARM the
	// window, not unfence on time banked while the node was down.
	goodNode := testutil.Node("w1", corev1.ConditionTrue, nil)
	if _, err := cs.CoreV1().Nodes().Update(ctx, goodNode, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	probetest.FreezeNow(p.Deps, base.Add(17*time.Minute))
	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if got := fencedAnnotation(t, p, "db", "pg-settle"); got != `["pg-settle-1"]` {
		t.Fatalf("first healthy sweep must not unfence, annotation = %q", got)
	}
	// A full window of verifiable health later, the stale fence clears.
	probetest.FreezeNow(p.Deps, base.Add(17*time.Minute+16*time.Minute))
	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if got := fencedAnnotation(t, p, "db", "pg-settle"); got != "" {
		t.Fatalf("fence should clear after a fresh settle window, annotation = %q", got)
	}
}

// A fence that was settling on a healthy node must not bank that time
// when the node drops NotReady mid-window: the prune drops the key
// while the safety gate fails, so recovery re-arms a fresh 15m.
func TestCNPGUnfenceWindowResetsWhenNodeDropsNotReady(t *testing.T) {
	cr := cnpgClusterFenced("db", "pg-reset-node", `["pg-reset-node-1"]`)
	node := testutil.Node("w1", corev1.ConditionTrue, nil)
	pod := fencedPod("db", "pg-reset-node", "pg-reset-node-1", "w1")
	cs := fake.NewSimpleClientset(node, pod)
	p := testProberDyn(cs, probetest.OpDyn(cr))
	chk := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p)
	base := time.Now()

	probetest.FreezeNow(p.Deps, base)
	chk.Run(probetest.SweepCtx(ctx, chk.Deps)) // arm the window
	// Node fails mid-window — the safety gate fails and the key must
	// be pruned instead of aging in RAM.
	failed := testutil.Node("w1", corev1.ConditionFalse, nil)
	if _, err := cs.CoreV1().Nodes().Update(ctx, failed, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	probetest.FreezeNow(p.Deps, base.Add(8*time.Minute))
	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	// Node recovers — one healthy sweep must only re-arm, not spend
	// the 8m banked before the outage.
	if _, err := cs.CoreV1().Nodes().Update(ctx, node, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	probetest.FreezeNow(p.Deps, base.Add(20*time.Minute))
	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if got := fencedAnnotation(t, p, "db", "pg-reset-node"); got != `["pg-reset-node-1"]` {
		t.Fatalf("first sweep after recovery must not unfence, annotation = %q", got)
	}
	// A fresh full window of health finally clears the stale fence.
	probetest.FreezeNow(p.Deps, base.Add(20*time.Minute+16*time.Minute))
	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if got := fencedAnnotation(t, p, "db", "pg-reset-node"); got != "" {
		t.Fatalf("fence should clear after a fresh settle window, annotation = %q", got)
	}
}

// The other half of the same reset: a switchover starting mid-window
// (targetPrimary diverges) prunes the settle counter. A single
// healthy sweep after the failover lands must not unfence.
func TestCNPGUnfenceWindowResetsOnFailover(t *testing.T) {
	cr := cnpgClusterFenced("db", "pg-reset-fo", `["pg-reset-fo-1"]`)
	node := testutil.Node("w1", corev1.ConditionTrue, nil)
	pod := fencedPod("db", "pg-reset-fo", "pg-reset-fo-1", "w1")
	cs := fake.NewSimpleClientset(node, pod)
	p := testProberDyn(cs, probetest.OpDyn(cr))
	chk := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p)
	base := time.Now()

	setTarget := func(target string) {
		live, err := p.Deps.Dyn.Resource(kube.GVRCNPGCluster).Namespace("db").
			Get(ctx, "pg-reset-fo", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		next := live.DeepCopy()
		_ = unstructured.SetNestedField(next.Object, target,
			"status", "targetPrimary")
		if _, err := p.Deps.Dyn.Resource(kube.GVRCNPGCluster).Namespace("db").
			Update(ctx, next, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}

	probetest.FreezeNow(p.Deps, base)
	chk.Run(probetest.SweepCtx(ctx, chk.Deps)) // arm
	setTarget("pg-reset-fo-1")                 // failover in flight mid-window
	probetest.FreezeNow(p.Deps, base.Add(8*time.Minute))
	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	setTarget("pg-reset-fo-0") // failover lands
	probetest.FreezeNow(p.Deps, base.Add(20*time.Minute))
	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if got := fencedAnnotation(t, p, "db", "pg-reset-fo"); got != `["pg-reset-fo-1"]` {
		t.Fatalf("first sweep after failover must not unfence, annotation = %q", got)
	}
	probetest.FreezeNow(p.Deps, base.Add(20*time.Minute+16*time.Minute))
	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if got := fencedAnnotation(t, p, "db", "pg-reset-fo"); got != "" {
		t.Fatalf("fence should clear after a fresh settle window, annotation = %q", got)
	}
}

// First sight of a fence never unfences — the fence ledger has no
// persisted window yet even with a verified-healthy pod behind it.
func TestCNPGFencedInstanceFirstSweepStays(t *testing.T) {
	testutil.CleanupMetric(t, cnpgClusterUnhealthyGauge,
		"db", "pg-f", "fenced_instances")
	now := time.Now()
	cr := cnpgClusterFenced("db", "pg-f", `["pg-f-1"]`)
	node := testutil.Node("w1", corev1.ConditionTrue, nil)
	pod := fencedPod("db", "pg-f", "pg-f-1", "w1")
	cs := fake.NewSimpleClientset(node, pod)
	p := testProberDyn(cs, probetest.OpDyn(cr))
	chk := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, now)
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("first sight must arm, not fail: %+v", res)
	}
	if got := fencedAnnotation(t, p, "db", "pg-f"); got != `["pg-f-1"]` {
		t.Fatalf("annotation = %q, want unchanged [\"pg-f-1\"]", got)
	}
}

func TestCNPGFencedInstanceListJSONEdgeCases(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want int
	}{
		{"empty json array", `[]`, 0},
		{"whitespace json array", " [ ] ", 0},
		{"null json", "null", 0},
		{"blank", "", 0},
		{"invalid json", "[broken", 0},
		{"wrong json type", `{"a":1}`, 0},
		{"plain string", "not-json", 0},
		{"padded entries", ` [ "pg-1" , "" , " pg-2 " ] `, 2},
		{"star entry", `["*"]`, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cr := cnpgClusterFenced("db", "pg-edge", tc.raw)
			got := cnpgFencedInstanceList(ctx, cr)
			if len(got) != tc.want {
				t.Fatalf("cnpgFencedInstanceList(%q) = %v (len %d), want len %d",
					tc.raw, got, len(got), tc.want)
			}
		})
	}

	// ["*", "pg-1"] must keep the whole cluster fenced and not unfence pg-1.
	now := time.Now()
	cr := cnpgClusterFenced("db", "pg-star-mix", `["*","pg-star-mix-1"]`)
	node := testutil.Node("w1", corev1.ConditionTrue, nil)
	pod := fencedPod("db", "pg-star-mix", "pg-star-mix-1", "w1")
	p := testProberDyn(fake.NewSimpleClientset(node, pod), probetest.OpDyn(cr))
	chk := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p)
	probetest.FreezeNow(p.Deps, now)
	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	probetest.FreezeNow(p.Deps, now.Add(16*time.Minute))
	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if got := fencedAnnotation(t, p, "db", "pg-star-mix"); got != `["*","pg-star-mix-1"]` {
		t.Fatalf("cluster with * in fencedInstances must not unfence any member, got %q", got)
	}
}

func TestCNPGUnfencePatchConflictAndNotFoundRefundGrant(t *testing.T) {
	runErrs := func(name string) float64 {
		m := probetest.FindMetric(t, "shell_operator_hook_run_errors_total",
			map[string]string{"queue": name})
		if m == nil {
			return 0
		}
		return m.GetCounter().GetValue()
	}

	for _, tc := range []struct {
		name       string
		patchErr   error
		wantErrInc float64
		wantRefund bool
	}{
		{
			name:       "409 conflict refunds grant and skips IncError",
			patchErr:   apierrors.NewConflict(schema.GroupResource{Group: "postgresql.cnpg.io", Resource: "clusters"}, "pg-race", errors.New("rv mismatch")),
			wantErrInc: 0,
			wantRefund: true,
		},
		{
			name:       "404 not found refunds grant and skips IncError",
			patchErr:   apierrors.NewNotFound(schema.GroupResource{Group: "postgresql.cnpg.io", Resource: "clusters"}, "pg-race"),
			wantErrInc: 0,
			wantRefund: true,
		},
		{
			name:       "500 internal error increments IncError and spends grant",
			patchErr:   apierrors.NewInternalError(errors.New("etcd timeout")),
			wantErrInc: 1,
			wantRefund: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			heal.ConfigureBudget(1, time.Hour)
			defer heal.ConfigureBudget(0, 0)

			cr := cnpgClusterFenced("db", "pg-race", `["pg-race-1","pg-race-2"]`)
			node := testutil.Node("w1", corev1.ConditionTrue, nil)
			pod1 := fencedPod("db", "pg-race", "pg-race-1", "w1")
			pod2 := fencedPod("db", "pg-race", "pg-race-2", "w1")
			cs := fake.NewSimpleClientset(node, pod1, pod2)
			dyn := probetest.OpDyn(cr)
			var patchCalls int
			dyn.PrependReactor("patch", "clusters", func(ktesting.Action) (bool, runtime.Object, error) {
				patchCalls++
				return true, nil, tc.patchErr
			})
			p := testProberDyn(cs, dyn)
			chk := probetest.MustCheck[*postgresWALArchiveGuardCheck](t, p)

			base := time.Now()
			probetest.FreezeNow(p.Deps, base)
			chk.Run(probetest.SweepCtx(ctx, chk.Deps))

			at := base.Add(16 * time.Minute)
			probetest.FreezeNow(p.Deps, at)
			beforeErrs := runErrs(p.Name)
			chk.Run(probetest.SweepCtx(ctx, chk.Deps))

			if got := runErrs(p.Name) - beforeErrs; got != tc.wantErrInc {
				t.Fatalf("run_errors delta = %v, want %v", got, tc.wantErrInc)
			}
			if tc.wantRefund && patchCalls != 1 {
				t.Fatalf("conflict/404 must break per-cluster loop after 1 patch, got %d", patchCalls)
			}
			// Check whether the single budget grant at `at` is available again.
			proceed, unverifiable := chk.HealAllowed(ctx, logr.Discard(), nil, "probe-budget", time.Minute, at)
			if unverifiable {
				t.Fatal("unexpected unverifiable gate")
			}
			if proceed != tc.wantRefund {
				t.Fatalf("post-patch budget grant available = %v, want %v", proceed, tc.wantRefund)
			}
		})
	}
}
