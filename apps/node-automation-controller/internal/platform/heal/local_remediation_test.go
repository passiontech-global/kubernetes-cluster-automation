package heal

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

func TestLocalRemediationHold(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()

	t.Run("nil_pod", func(t *testing.T) {
		hold, err := localRemediationHold(ctx, fake.NewClientset(), nil, now)
		if err != nil || hold {
			t.Fatalf("got (%v, %v), want (false, nil)", hold, err)
		}
	})

	t.Run("pod_last_healed_within_lease", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "p1", Namespace: "ns",
				Annotations: map[string]string{
					nodecond.AnnoLastPodHealedAt: now.Add(-1 * time.Minute).Format(time.RFC3339),
				},
			},
			Spec: corev1.PodSpec{NodeName: "n1"},
		}
		hold, err := localRemediationHold(ctx, fake.NewClientset(), pod, now)
		if err != nil || !hold {
			t.Fatalf("got (%v, %v), want (true, nil)", hold, err)
		}
	})

	t.Run("unscheduled_pod", func(t *testing.T) {
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "ns"}}
		hold, err := localRemediationHold(ctx, fake.NewClientset(), pod, now)
		if err != nil || hold {
			t.Fatalf("got (%v, %v), want (false, nil)", hold, err)
		}
	})

	t.Run("sweep_lookup_missing_node", func(t *testing.T) {
		sctx := kube.WithSweepNodeLookup(ctx, func(context.Context, string) (*corev1.Node, error) {
			return nil, nil
		})
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "ns"},
			Spec:       corev1.PodSpec{NodeName: "n1"},
		}
		hold, err := localRemediationHold(sctx, fake.NewClientset(), pod, now)
		if err != nil || hold {
			t.Fatalf("got (%v, %v), want (false, nil)", hold, err)
		}
	})

	t.Run("live_get_not_found", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "ns"},
			Spec:       corev1.PodSpec{NodeName: "missing-node"},
		}
		hold, err := localRemediationHold(ctx, fake.NewClientset(), pod, now)
		if err != nil || hold {
			t.Fatalf("got (%v, %v), want (false, nil)", hold, err)
		}
	})

	t.Run("live_get_error_propagates", func(t *testing.T) {
		cs := fake.NewClientset()
		cs.PrependReactor("get", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("apiserver down")
		})
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "ns"},
			Spec:       corev1.PodSpec{NodeName: "n1"},
		}
		hold, err := localRemediationHold(ctx, cs, pod, now)
		if err == nil || hold {
			t.Fatalf("got (%v, %v), want (false, err)", hold, err)
		}
	})

	t.Run("node_until_anno_active", func(t *testing.T) {
		node := &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: "n1",
				Annotations: map[string]string{
					nodecond.AnnoLocalRemediationUntil: now.Add(2 * time.Minute).Format(time.RFC3339),
				},
			},
		}
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "ns"},
			Spec:       corev1.PodSpec{NodeName: "n1"},
		}
		hold, err := localRemediationHold(ctx, fake.NewClientset(node), pod, now)
		if err != nil || !hold {
			t.Fatalf("got (%v, %v), want (true, nil)", hold, err)
		}
	})

	t.Run("node_condition_fresh_vs_stale", func(t *testing.T) {
		freshNode := &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "n-fresh"},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{{
					Type:              corev1.NodeConditionType(nodecond.CondLocalRemediation),
					Status:            corev1.ConditionTrue,
					LastHeartbeatTime: metav1.NewTime(now.Add(-1 * time.Minute)),
				}},
			},
		}
		staleNode := &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "n-stale"},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{{
					Type:              corev1.NodeConditionType(nodecond.CondLocalRemediation),
					Status:            corev1.ConditionTrue,
					LastHeartbeatTime: metav1.NewTime(now.Add(-5 * time.Minute)),
				}},
			},
		}
		cs := fake.NewClientset(freshNode, staleNode)

		hold, err := localRemediationHold(ctx, cs, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "ns"},
			Spec:       corev1.PodSpec{NodeName: "n-fresh"},
		}, now)
		if err != nil || !hold {
			t.Fatalf("fresh condition: got (%v, %v), want (true, nil)", hold, err)
		}

		hold, err = localRemediationHold(ctx, cs, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "p2", Namespace: "ns"},
			Spec:       corev1.PodSpec{NodeName: "n-stale"},
		}, now)
		if err != nil || hold {
			t.Fatalf("stale condition: got (%v, %v), want (false, nil)", hold, err)
		}
	})
}
