package gitops

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func TestHPAScalingGuardMaxReplicasSaturated(t *testing.T) {
	ctx := t.Context()
	now := time.Now()
	t.Cleanup(func() {
		hpaMaxReplicasSaturatedGauge.DeleteLabelValues("prod", "api-hpa")
	})

	hpa := hpaObj("prod", "api-hpa", "Deployment", "api",
		map[string]string{"type": "AbleToScale", "status": "True", "reason": "ReadyForNewScale"},
	)
	_ = unstructured.SetNestedField(hpa.Object, int64(10), "spec", "maxReplicas")
	_ = unstructured.SetNestedField(hpa.Object, int64(10), "status", "currentReplicas")
	_ = unstructured.SetNestedSlice(hpa.Object, []any{
		map[string]any{"type": "AbleToScale", "status": "True", "reason": "ReadyForNewScale"},
		map[string]any{
			"type":               "ScalingLimited",
			"status":             "True",
			"reason":             "TooManyReplicas",
			"lastTransitionTime": now.Add(-10 * time.Minute).UTC().Format(time.RFC3339),
		},
	}, "status", "conditions")

	cs, chk := hpaDeps(hpa)
	// <30m must not flag.
	chk.Deps.Now = func() time.Time { return now }
	if res := chk.Run(probefw.WithSweepSnapshot(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("expected <30m saturated HPA not to flag, got %+v", res)
	}

	// >=30m emits gauge + Warning Event.
	chk.Deps.Now = func() time.Time { return now.Add(25 * time.Minute) }
	res2 := chk.Run(probefw.WithSweepSnapshot(ctx, chk.Deps))
	if res2.Pass {
		t.Fatalf("expected >=30m max_replicas_saturated failure, got %+v", res2)
	}
	if got, ok := testutil.GaugeSeriesValue(t, "node_automation_hpa_max_replicas_saturated", map[string]string{
		"namespace": "prod", "name": "api-hpa",
	}); !ok || got != 1 {
		t.Fatalf("hpa_max_replicas_saturated = (%v, %v), want (1, true)", got, ok)
	}
	evs, err := cs.EventsV1().Events("prod").List(ctx, metav1.ListOptions{})
	if err != nil || len(evs.Items) == 0 {
		t.Fatalf("expected Warning Event in prod, got err=%v count=%d", err, len(evs.Items))
	}

	// Drop currentReplicas below maxReplicas -> recovers and prunes series.
	_ = unstructured.SetNestedField(hpa.Object, int64(6), "status", "currentReplicas")
	_, _ = chk.Dyn.Resource(hpaGVR).Namespace("prod").Update(ctx, hpa, metav1.UpdateOptions{})
	if res3 := chk.Run(probefw.WithSweepSnapshot(ctx, chk.Deps)); !res3.Pass {
		t.Fatalf("expected recovered HPA to pass, got %+v", res3)
	}
	if _, ok := testutil.GaugeSeriesValue(t, "node_automation_hpa_max_replicas_saturated", map[string]string{
		"namespace": "prod", "name": "api-hpa",
	}); ok {
		t.Fatal("stale hpa_max_replicas_saturated gauge not pruned after recovery")
	}
}
