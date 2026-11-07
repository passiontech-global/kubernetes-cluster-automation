// workload_scale_flapping_test.go — the W13-SC1 scale tug-of-war
// detector driven through the fake clientset.
package gitops

import (
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
)

// ---------------------------------------------------------------------------
// W13-SC1 — workload scale flapping
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

	res := probetest.MustCheck[*workloadScaleFlappingCheck](t, p).Run(ctx)
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

	if res := probetest.MustCheck[*workloadScaleFlappingCheck](t, p).Run(ctx); !res.Pass {
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

	if res := probetest.MustCheck[*workloadScaleFlappingCheck](t, p).Run(ctx); !res.Pass {
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

	if res := probetest.MustCheck[*workloadScaleFlappingCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("StatefulSet flapping must FAIL")
	}
}

// No events at all is a clean pass.
func TestScaleFlappingQuiet(t *testing.T) {
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn())
	if res := probetest.MustCheck[*workloadScaleFlappingCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("empty event stream must pass: %+v", res)
	}
}
