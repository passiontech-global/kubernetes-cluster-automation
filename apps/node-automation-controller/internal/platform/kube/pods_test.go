// pods_test.go — tests for pods.go: the DaemonSet "rollout settled"
// verdict and the pod Ready-condition probe.
package kube

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func settledDaemonSet() *appsv1.DaemonSet {
	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Generation: 3},
		Status: appsv1.DaemonSetStatus{
			ObservedGeneration:     3,
			DesiredNumberScheduled: 4,
			UpdatedNumberScheduled: 4,
			NumberReady:            4,
		},
	}
}

// ---------------------------------------------------------------------------
// DaemonSetSettled — every lagging field must veto "settled".
// ---------------------------------------------------------------------------

func TestDaemonSetSettledFields(t *testing.T) {
	t.Run("settled", func(t *testing.T) {
		if !DaemonSetSettled(settledDaemonSet()) {
			t.Fatal("fully caught-up DaemonSet not settled")
		}
	})
	t.Run("observedGeneration lag", func(t *testing.T) {
		ds := settledDaemonSet()
		ds.Status.ObservedGeneration = 2 // controller hasn't seen gen 3
		if DaemonSetSettled(ds) {
			t.Fatal("settled despite stale observedGeneration")
		}
	})
	t.Run("updatedNumberScheduled lag", func(t *testing.T) {
		ds := settledDaemonSet()
		ds.Status.UpdatedNumberScheduled = 3 // old pod template on one node
		if DaemonSetSettled(ds) {
			t.Fatal("settled despite pods still on the old revision")
		}
	})
	t.Run("numberReady lag", func(t *testing.T) {
		ds := settledDaemonSet()
		ds.Status.NumberReady = 3 // updated but not ready yet
		if DaemonSetSettled(ds) {
			t.Fatal("settled despite unready pod")
		}
	})
}

func TestDaemonSetSettled(t *testing.T) {
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Generation: 3},
		Status: appsv1.DaemonSetStatus{
			ObservedGeneration:     3,
			DesiredNumberScheduled: 4,
			UpdatedNumberScheduled: 4,
			NumberReady:            4,
		},
	}
	if !DaemonSetSettled(ds) {
		t.Fatal("expected settled")
	}
	ds.Status.NumberReady = 3
	if DaemonSetSettled(ds) {
		t.Fatal("expected not settled when a replica is not ready")
	}
}

// PodReadyCond mirrors the bash Ready=True probe: absent condition and
// Ready=False both count as not ready.
func TestPodReadyCond(t *testing.T) {
	p := &corev1.Pod{}
	if PodReadyCond(p) {
		t.Fatal("pod with no conditions reported ready")
	}
	p.Status.Conditions = []corev1.PodCondition{
		{Type: corev1.PodReady, Status: corev1.ConditionFalse},
	}
	if PodReadyCond(p) {
		t.Fatal("Ready=False pod reported ready")
	}
	p.Status.Conditions[0].Status = corev1.ConditionTrue
	if !PodReadyCond(p) {
		t.Fatal("Ready=True pod reported not ready")
	}
}
