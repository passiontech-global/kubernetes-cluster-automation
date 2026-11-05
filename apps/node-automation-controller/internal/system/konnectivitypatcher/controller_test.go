package konnectivitypatcher

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// ---------------------------------------------------------------------------
// konnectivity-patcher
// ---------------------------------------------------------------------------

func TestKonnectivityPatcher(t *testing.T) {
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: "konnectivity-agent", Namespace: "kube-system", Generation: 2,
		},
		Spec: appsv1.DaemonSetSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{Containers: []corev1.Container{
					{Name: "konnectivity-agent"},
				}},
			},
		},
		Status: appsv1.DaemonSetStatus{
			ObservedGeneration:     2,
			DesiredNumberScheduled: 3,
			UpdatedNumberScheduled: 3,
			NumberReady:            3,
		},
	}
	cs := fake.NewSimpleClientset(ds)
	r := &konnectivityPatcher{cs: cs}
	if _, err := r.Reconcile(context.Background(), reconcile.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	got, err := cs.AppsV1().DaemonSets("kube-system").
		Get(context.Background(), "konnectivity-agent", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Spec.Template.Spec.PriorityClassName != "system-node-critical" {
		t.Fatalf("priorityClassName not patched: %q",
			got.Spec.Template.Spec.PriorityClassName)
	}
	c := got.Spec.Template.Spec.Containers[0]
	if c.Resources.Requests.Cpu().Cmp(resource.MustParse("25m")) != 0 ||
		c.Resources.Requests.Memory().Cmp(resource.MustParse("32Mi")) != 0 {
		t.Fatalf("requests not patched: %+v", c.Resources.Requests)
	}

	// Second pass is a no-op (already drift-free).
	if _, err := r.Reconcile(context.Background(), reconcile.Request{}); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
}

func TestKonnectivityPatcherSkipsRollout(t *testing.T) {
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: "konnectivity-agent", Namespace: "kube-system", Generation: 2,
		},
		Status: appsv1.DaemonSetStatus{
			ObservedGeneration:     1, // rollout in flight
			DesiredNumberScheduled: 3,
			UpdatedNumberScheduled: 3,
			NumberReady:            3,
		},
	}
	cs := fake.NewSimpleClientset(ds)
	r := &konnectivityPatcher{cs: cs}
	if _, err := r.Reconcile(context.Background(), reconcile.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got, _ := cs.AppsV1().DaemonSets("kube-system").
		Get(context.Background(), "konnectivity-agent", metav1.GetOptions{})
	if got.Spec.Template.Spec.PriorityClassName != "" {
		t.Fatal("patched during an unsettled rollout — should have skipped")
	}
}
