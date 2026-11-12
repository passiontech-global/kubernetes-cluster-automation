// workload_scale_flapping_test.go — the scale-flap scale tug-of-war
// detector driven through the fake clientset.
package gitops

import (
	"fmt"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
)

// ---------------------------------------------------------------------------
// scale-flap — workload scale flapping
// ---------------------------------------------------------------------------

// scaleEvent builds a ScalingReplicaSet event on a workload — up
// selects the direction; when stamps the event clock.
func scaleEvent(ns, kind, name string, up bool, when time.Time) *corev1.Event {
	dir := "down"
	if up {
		dir = "up"
	}
	return &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      fmt.Sprintf("%s-%s-%d", name, dir, when.UnixNano()),
			UID:       types.UID(fmt.Sprintf("%s-%s-%d", name, dir, when.UnixNano())),
		},
		InvolvedObject: corev1.ObjectReference{
			Kind: kind, Namespace: ns, Name: name,
		},
		Reason:        "ScalingReplicaSet",
		Message:       fmt.Sprintf("Scaled %s replica set %s-abc to 2", dir, name),
		LastTimestamp: metav1.NewTime(when),
	}
}

// flapSeries emits n alternating-direction events ending at base,
// one every 2m — n flips requires n+1 events.
func flapSeries(ns, kind, name string, flips int, base time.Time, startUp bool) []runtimeObject {
	var objs []runtimeObject
	up := startUp
	for i := 0; i <= flips; i++ {
		objs = append(objs, scaleEvent(ns, kind, name, up,
			base.Add(-time.Duration(flips-i)*2*time.Minute)))
		up = !up
	}
	return objs
}

type runtimeObject = interface {
	metav1.Object
}

func flapObjs(flips int, base time.Time) []runtimeObject {
	return flapSeries("apps", "Deployment", "web", flips, base, true)
}

// >=6 direction flips in the hour FAILs and emits the gauge.
func TestScaleFlappingDetected(t *testing.T) {
	base := time.Now()
	cs := fake.NewSimpleClientset()
	for _, o := range flapObjs(6, base) {
		e := o.(*corev1.Event)
		_, err := cs.CoreV1().Events(e.Namespace).Create(ctx, e, metav1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }

	res := probetest.MustCheck[*workloadScaleFlappingCheck](t, p).Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatal("6 flips must FAIL")
	}
	m := probetest.FindMetric(t, "node_automation_workload_scale_flapping",
		map[string]string{"namespace": "apps", "kind": "Deployment", "name": "web"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("flapping gauge missing: %v", m)
	}
}

// 5 flips stays under the threshold; same-direction scaling never flips.
func TestScaleFlappingUnderThreshold(t *testing.T) {
	base := time.Now()
	cs := fake.NewSimpleClientset()
	for _, o := range flapObjs(5, base) {
		e := o.(*corev1.Event)
		if _, err := cs.CoreV1().Events(e.Namespace).Create(ctx, e, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	// 7 straight scale-ups on a second workload — 0 flips.
	for i := 0; i < 7; i++ {
		e := scaleEvent("apps", "Deployment", "up-only", true,
			base.Add(-time.Duration(i)*time.Minute))
		e.Name = fmt.Sprintf("up-only-%d", i)
		e.UID = types.UID(fmt.Sprintf("up-only-%d", i))
		if _, err := cs.CoreV1().Events(e.Namespace).Create(ctx, e, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*workloadScaleFlappingCheck](t, p).Run(probetest.SweepCtx(ctx)); !res.Pass {
		t.Fatalf("under-threshold flapping must pass: %+v", res)
	}
}

// Flapping that happened >1h ago is out of the window.
func TestScaleFlappingOldEventsIgnored(t *testing.T) {
	base := time.Now()
	cs := fake.NewSimpleClientset()
	for _, o := range flapSeries("apps", "Deployment", "web", 8,
		base.Add(-2*time.Hour), true) {
		e := o.(*corev1.Event)
		if _, err := cs.CoreV1().Events(e.Namespace).Create(ctx, e, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*workloadScaleFlappingCheck](t, p).Run(probetest.SweepCtx(ctx)); !res.Pass {
		t.Fatalf("stale flapping must pass: %+v", res)
	}
}

// StatefulSet tug-of-war is caught the same way — downscaler fights
// GitOps on either workload kind.
func TestScaleFlappingStatefulSet(t *testing.T) {
	base := time.Now()
	cs := fake.NewSimpleClientset()
	for _, o := range flapSeries("apps", "StatefulSet", "db", 6, base, false) {
		e := o.(*corev1.Event)
		if _, err := cs.CoreV1().Events(e.Namespace).Create(ctx, e, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*workloadScaleFlappingCheck](t, p).Run(probetest.SweepCtx(ctx)); res.Pass {
		t.Fatal("StatefulSet flapping must FAIL")
	}
}

// No events at all is a clean pass.
func TestScaleFlappingQuiet(t *testing.T) {
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn())
	if res := probetest.MustCheck[*workloadScaleFlappingCheck](t, p).Run(probetest.SweepCtx(ctx)); !res.Pass {
		t.Fatalf("empty event stream must pass: %+v", res)
	}
}

// rolloutScaleEvent builds a Rollouts-controller scale event — the
// direction rides the reason (RolloutScaledUp/RolloutScaledDown), the
// involved object is the parent Rollout.
func rolloutScaleEvent(ns, name string, up bool, when time.Time) *corev1.Event {
	reason := "RolloutScaledDown"
	dir := "down"
	if up {
		reason = "RolloutScaledUp"
		dir = "up"
	}
	return &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      fmt.Sprintf("%s-%s-%d", name, dir, when.UnixNano()),
			UID:       types.UID(fmt.Sprintf("%s-%s-%d", name, dir, when.UnixNano())),
		},
		InvolvedObject: corev1.ObjectReference{
			Kind: "Rollout", Namespace: ns, Name: name,
		},
		Reason:        reason,
		Message:       fmt.Sprintf("Scaled %s replica set %s-abc to 2", dir, name),
		LastTimestamp: metav1.NewTime(when),
	}
}

// rollout-scale-flap — a Rollout whose scale direction flipped >=6 times inside
// the window (GitOps vs downscaler vs KEDA on spec.replicas) is the
// same tug-of-war the Deployment path flags.
func TestScaleFlappingRollout(t *testing.T) {
	base := time.Now()
	cs := fake.NewSimpleClientset()
	up := true
	for i := range 7 {
		e := rolloutScaleEvent("apps", "canary-api", up,
			base.Add(-time.Duration(6-i)*2*time.Minute))
		if _, err := cs.CoreV1().Events(e.Namespace).Create(ctx, e, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		up = !up
	}
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }

	res := probetest.MustCheck[*workloadScaleFlappingCheck](t, p).Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatal("Rollout flapping must FAIL")
	}
}

// A steady one-directional Rollout scale-up series (no flips) passes.
func TestScaleFlappingRolloutSteadyUp(t *testing.T) {
	base := time.Now()
	cs := fake.NewSimpleClientset()
	for i := range 9 {
		e := rolloutScaleEvent("apps", "steady-api", true,
			base.Add(-time.Duration(8-i)*2*time.Minute))
		if _, err := cs.CoreV1().Events(e.Namespace).Create(ctx, e, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*workloadScaleFlappingCheck](t, p).Run(probetest.SweepCtx(ctx)); !res.Pass {
		t.Fatalf("steady one-direction Rollout scaling must pass: %+v", res)
	}
}

// ---------------------------------------------------------------------------
// ONE RollingUpdate exclusions — rollout cadence must not read as flap
// ---------------------------------------------------------------------------

// scaleRSEvent builds a ScalingReplicaSet event on a Deployment whose
// message names an explicit ReplicaSet — the pair-exclusion key.
func scaleRSEvent(ns, name, rs string, up bool, when time.Time) *corev1.Event {
	dir := "down"
	if up {
		dir = "up"
	}
	return &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      fmt.Sprintf("%s-%s-%d", rs, dir, when.UnixNano()),
			UID:       types.UID(fmt.Sprintf("%s-%s-%d", rs, dir, when.UnixNano())),
		},
		InvolvedObject: corev1.ObjectReference{
			Kind: "Deployment", Namespace: ns, Name: name,
		},
		Reason:        "ScalingReplicaSet",
		Message:       fmt.Sprintf("Scaled %s replica set %s to 2", dir, rs),
		LastTimestamp: metav1.NewTime(when),
	}
}

// One RollingUpdate's maxSurge cadence scales the NEW ReplicaSet up
// and the OLD one down in an alternating up/down rhythm — pairs that
// name two different ReplicaSets of the same Deployment are rollout
// churn, not tug-of-war, and must not flip.
func TestScaleFlappingRolloutPairsExcluded(t *testing.T) {
	// TestScaleFlappingDetected leaves its series in the shared
	// registry — clear it so the absence assertion below is real.
	workloadScaleFlappingGauge.DeleteLabelValues("apps", "Deployment", "web")
	base := time.Now()
	cs := fake.NewSimpleClientset()
	up := true
	for i := range 12 {
		rs := "web-5d8f7b9c4" // the new RS the rollout scales up
		if !up {
			rs = "web-6c9d8f7b5" // the old RS it drains
		}
		e := scaleRSEvent("apps", "web", rs, up,
			base.Add(-time.Duration(12-i)*2*time.Minute))
		if _, err := cs.CoreV1().Events("apps").Create(ctx, e, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		up = !up
	}
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*workloadScaleFlappingCheck](t, p).Run(probetest.SweepCtx(ctx)); !res.Pass {
		t.Fatalf("a single rolling update must not flag flapping: %+v", res)
	}
	if m := probetest.FindMetric(t, "node_automation_workload_scale_flapping",
		map[string]string{"namespace": "apps", "kind": "Deployment", "name": "web"}); m != nil {
		t.Fatal("rollout cadence must not emit the flapping gauge")
	}
}

// The exclusion only filters cross-ReplicaSet pairs: a workload whose
// SAME ReplicaSet keeps being scaled back and forth still flags, even
// when a rollout's churn is interleaved before it.
func TestScaleFlappingSameRSFlipsStillFlags(t *testing.T) {
	base := time.Now()
	cs := fake.NewSimpleClientset()
	mk := func(rs string, up bool, off time.Duration) {
		e := scaleRSEvent("apps", "web", rs, up, base.Add(-off))
		if _, err := cs.CoreV1().Events("apps").Create(ctx, e, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	// A rollout's tail (cross-RS pairs — no flips), then a real
	// tug-of-war on the surviving RS: up/down ×3 = 6 flips.
	off := 60 * time.Minute
	mk("web-oldrs", false, off)
	mk("web-newrs", true, off-2*time.Minute)
	off -= 4 * time.Minute
	mk("web-newrs", false, off)
	for i := range 7 {
		off -= 2 * time.Minute
		mk("web-newrs", i%2 == 1, off)
	}
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }

	res := probetest.MustCheck[*workloadScaleFlappingCheck](t, p).Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatalf("same-RS reversal must still flag: %+v", res)
	}
}

// stsScaleEvent builds the StatefulSet controller's pod create/delete
// event — create is a scale-up signal, delete a scale-down one.
func stsScaleEvent(ns, name string, del bool, when time.Time) *corev1.Event {
	verb, reason := "create", "SuccessfulCreate"
	if del {
		verb, reason = "delete", "SuccessfulDelete"
	}
	return &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      fmt.Sprintf("%s-%s-%d", name, verb, when.UnixNano()),
			UID:       types.UID(fmt.Sprintf("%s-%s-%d", name, verb, when.UnixNano())),
		},
		InvolvedObject: corev1.ObjectReference{
			Kind: "StatefulSet", Namespace: ns, Name: name,
		},
		Reason: reason,
		Message: fmt.Sprintf("%s Pod %s-%d in StatefulSet %s successful",
			verb, name, when.UnixNano(), name),
		LastTimestamp: metav1.NewTime(when),
	}
}

// stsMidRollout seeds a StatefulSet whose revisions either differ
// (mid-rollout) or match (settled).
func stsMidRollout(ns, name, current, update string) *appsv1.StatefulSet {
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Status: appsv1.StatefulSetStatus{
			CurrentRevision: current, UpdateRevision: update,
		},
	}
}

// A StatefulSet mid rolling update (currentRevision != updateRevision)
// delete/creates one pod pair per revision step — alternating
// directions that are the UPDATE controller's churn, not scaling.
// Pod create/delete events measure status.replicas churn and no
// longer count at all — the spec.replicas tracker owns the STS
// flap signal — so rollout churn can never flip.
func TestScaleFlappingSTSMidRolloutExcluded(t *testing.T) {
	base := time.Now()
	cs := fake.NewSimpleClientset(stsMidRollout("apps", "db", "db-1", "db-2"))
	del := false
	for i := range 12 {
		e := stsScaleEvent("apps", "db", del,
			base.Add(-time.Duration(12-i)*2*time.Minute))
		if _, err := cs.CoreV1().Events("apps").Create(ctx, e, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		del = !del
	}
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*workloadScaleFlappingCheck](t, p).Run(probetest.SweepCtx(ctx)); !res.Pass {
		t.Fatalf("a mid-rollout StatefulSet must not flag flapping: %+v", res)
	}
}

// The same create/delete cadence on a SETTLED StatefulSet must ALSO
// pass: SuccessfulCreate/SuccessfulDelete are pod churn
// (status.replicas) — reschedules and restarts fire them with no
// spec.replicas change, so they are not scale intent. Only spec
// reversals (TestScaleFlappingSTSSpecReplicas) flag a StatefulSet.
func TestScaleFlappingSTSSettledChurnPasses(t *testing.T) {
	base := time.Now()
	cs := fake.NewSimpleClientset(stsMidRollout("apps", "db", "db-2", "db-2"))
	del := false
	for i := range 7 {
		e := stsScaleEvent("apps", "db", del,
			base.Add(-time.Duration(7-i)*2*time.Minute))
		if _, err := cs.CoreV1().Events("apps").Create(ctx, e, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		del = !del
	}
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*workloadScaleFlappingCheck](t, p).Run(probetest.SweepCtx(ctx)); !res.Pass {
		t.Fatalf("settled-StatefulSet pod churn must not flag: %+v", res)
	}
}

// stsWithReplicas seeds a StatefulSet carrying an explicit
// spec.replicas — the value the flap tracker diffs across sweeps.
func stsWithReplicas(ns, name string, replicas int32) *appsv1.StatefulSet {
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: appsv1.StatefulSetSpec{
			Replicas: &replicas,
		},
	}
}

// The StatefulSet flap signal is spec.replicas reversals observed
// across sweeps: GitOps vs downscaler vs HPA writing the desired
// count back and forth IS the tug-of-war — pod churn is not.
func TestScaleFlappingSTSSpecReplicas(t *testing.T) {
	base := time.Now()
	cs := fake.NewSimpleClientset(stsWithReplicas("apps", "db", 3))
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	chk := probetest.MustCheck[*workloadScaleFlappingCheck](t, p)

	// Baseline observation — the first census arms the tracker.
	if res := chk.Run(probetest.SweepCtx(ctx)); !res.Pass {
		t.Fatalf("baseline sweep must pass: %+v", res)
	}
	// 3→1→3→1→3→1→3→1: seven desired-count moves, six direction
	// reversals — the flap threshold.
	for _, want := range []int32{1, 3, 1, 3, 1, 3, 1} {
		sts := stsWithReplicas("apps", "db", want)
		if _, err := cs.AppsV1().StatefulSets("apps").Update(ctx, sts,
			metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		chk.Run(probetest.SweepCtx(ctx))
	}
	if res := chk.Run(probetest.SweepCtx(ctx)); res.Pass {
		t.Fatal("six spec.replicas reversals must FAIL")
	}
	m := probetest.FindMetric(t, "node_automation_workload_scale_flapping",
		map[string]string{"namespace": "apps", "kind": "StatefulSet", "name": "db"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("flapping gauge missing: %v", m)
	}
}
