// delete_test.go — pins the UID-precondition shape: the sacred
// contract is DeleteOptions{Preconditions:{UID}} (+ optional
// propagation), and the eviction carrying it — the guard that makes
// "delete/evict the object I vetted" refuse a same-named recreate.
package kubeutil

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestUIDDeleteOptions(t *testing.T) {
	uid := types.UID("abc-123")
	opts := UIDDeleteOptions(uid, metav1.DeletePropagationBackground)
	if opts.Preconditions == nil || opts.Preconditions.UID == nil ||
		*opts.Preconditions.UID != uid {
		t.Fatalf("preconditions = %+v, want the vetted UID", opts.Preconditions)
	}
	if opts.PropagationPolicy == nil ||
		*opts.PropagationPolicy != metav1.DeletePropagationBackground {
		t.Fatalf("propagation = %v, want background", opts.PropagationPolicy)
	}

	// "" leaves the policy unset — the apiserver default.
	opts = UIDDeleteOptions(uid, "")
	if opts.PropagationPolicy != nil {
		t.Fatalf("empty propagation = %v, want unset", opts.PropagationPolicy)
	}
	if opts.Preconditions == nil || *opts.Preconditions.UID != uid {
		t.Fatalf("empty propagation lost the UID precondition: %+v", opts.Preconditions)
	}
}

func TestEvictPodV1(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "victim", Namespace: "app", UID: types.UID("u-1")}}
	ev := EvictPodV1(pod)
	if ev.Name != "victim" || ev.Namespace != "app" {
		t.Fatalf("eviction target = %s/%s", ev.Namespace, ev.Name)
	}
	if ev.DeleteOptions == nil || ev.DeleteOptions.Preconditions == nil ||
		ev.DeleteOptions.Preconditions.UID == nil ||
		*ev.DeleteOptions.Preconditions.UID != "u-1" {
		t.Fatalf("eviction delete options = %+v, want the UID precondition",
			ev.DeleteOptions)
	}
}
