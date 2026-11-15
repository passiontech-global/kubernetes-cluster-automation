package kubeletreaper

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestKonnectivityDegraded(t *testing.T) {
	ctx := context.Background()
	now := metav1.Now()

	t.Run("no_pods", func(t *testing.T) {
		r := &kubeletReaper{cs: fake.NewClientset()}
		deg, err := r.konnectivityDegraded(ctx)
		if err != nil || deg {
			t.Fatalf("got (%v, %v), want (false, nil)", deg, err)
		}
	})

	t.Run("terminating_ignored", func(t *testing.T) {
		p := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "konnectivity-agent-1", Namespace: konnectivityAgentNS,
				DeletionTimestamp: &now,
			},
		}
		r := &kubeletReaper{cs: fake.NewClientset(p)}
		deg, err := r.konnectivityDegraded(ctx)
		if err != nil || deg {
			t.Fatalf("got (%v, %v), want (false, nil)", deg, err)
		}
	})

	t.Run("not_ready_is_degraded", func(t *testing.T) {
		p := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "konnectivity-agent-1", Namespace: konnectivityAgentNS},
			Status: corev1.PodStatus{
				Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionFalse}},
			},
		}
		r := &kubeletReaper{cs: fake.NewClientset(p)}
		deg, err := r.konnectivityDegraded(ctx)
		if err != nil || !deg {
			t.Fatalf("got (%v, %v), want (true, nil)", deg, err)
		}
	})

	t.Run("one_ready_not_degraded", func(t *testing.T) {
		p := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "konnectivity-agent-1", Namespace: konnectivityAgentNS},
			Status: corev1.PodStatus{
				Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			},
		}
		r := &kubeletReaper{cs: fake.NewClientset(p)}
		deg, err := r.konnectivityDegraded(ctx)
		if err != nil || deg {
			t.Fatalf("got (%v, %v), want (false, nil)", deg, err)
		}
	})

	t.Run("list_error", func(t *testing.T) {
		cs := fake.NewClientset()
		cs.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api error")
		})
		r := &kubeletReaper{cs: cs}
		if _, err := r.konnectivityDegraded(ctx); err == nil {
			t.Fatal("expected list error, got nil")
		}
	})
}
