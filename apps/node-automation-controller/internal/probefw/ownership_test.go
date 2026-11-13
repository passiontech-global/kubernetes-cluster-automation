// ownership_test.go — the healthy-sibling census (PodRunningReady /
// ReadyByOwner / ReadySiblings incl. the self-discount) and
// OwnerGone's fail-closed owner-existence resolution.
package probefw

import (
	"errors"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"
)

// censusPod builds a pod with the given phase/ready/delete state,
// owned by uid (uid "" = unowned).
func censusPod(name string, phase corev1.PodPhase, ready bool,
	deleting bool, uid types.UID) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: name},
		Status:     corev1.PodStatus{Phase: phase},
	}
	if ready {
		p.Status.Conditions = []corev1.PodCondition{{
			Type:   corev1.PodReady,
			Status: corev1.ConditionTrue}}
	}
	if deleting {
		ts := metav1.NewTime(time.Now())
		p.DeletionTimestamp = &ts
	}
	if uid != "" {
		p.OwnerReferences = []metav1.OwnerReference{{
			Kind: "ReplicaSet", Name: "rs-" + name,
			UID: uid, Controller: ptr.To(true)}}
	}
	return p
}

func TestPodRunningReady(t *testing.T) {
	cases := []struct {
		name string
		pod  *corev1.Pod
		want bool
	}{
		{"running and ready", censusPod("a", corev1.PodRunning, true, false, "u"), true},
		{"running but not ready", censusPod("b", corev1.PodRunning, false, false, "u"), false},
		{"running ready but deleting", censusPod("c", corev1.PodRunning, true, true, "u"), false},
		{"pending even if ready", censusPod("d", corev1.PodPending, true, false, "u"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := PodRunningReady(tc.pod); got != tc.want {
				t.Fatalf("PodRunningReady = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestReadyByOwnerAndSiblings(t *testing.T) {
	const ownerA, ownerB = types.UID("owner-a"), types.UID("owner-b")
	pods := []corev1.Pod{
		*censusPod("a1", corev1.PodRunning, true, false, ownerA),
		*censusPod("a2", corev1.PodRunning, true, false, ownerA),
		*censusPod("a3", corev1.PodRunning, false, false, ownerA), // unready
		*censusPod("a4", corev1.PodRunning, true, true, ownerA),   // deleting
		*censusPod("b1", corev1.PodRunning, true, false, ownerB),
		*censusPod("solo", corev1.PodRunning, true, false, ""), // unowned
	}
	byOwner := ReadyByOwner(pods)
	if got := byOwner[ownerA]; got != 2 {
		t.Fatalf("byOwner[A] = %d, want 2 (ready+running+not deleting only)", got)
	}
	if got := byOwner[ownerB]; got != 1 {
		t.Fatalf("byOwner[B] = %d, want 1", got)
	}
	if _, ok := byOwner[types.UID("")]; ok || len(byOwner) != 2 {
		t.Fatalf("byOwner = %v — unowned pods must land nowhere", byOwner)
	}

	// A ready degraded pod discounts itself: census 2 → 1 sibling.
	if got := ReadySiblings(byOwner, &pods[0]); got != 1 {
		t.Fatalf("ReadySiblings(ready a1) = %d, want 1", got)
	}
	// An unready pod is not in the census — no self-discount.
	if got := ReadySiblings(byOwner, &pods[2]); got != 2 {
		t.Fatalf("ReadySiblings(unready a3) = %d, want 2", got)
	}
	// An unowned pod reads 0 — fail closed, no sibling proof.
	if got := ReadySiblings(byOwner, &pods[5]); got != 0 {
		t.Fatalf("ReadySiblings(unowned) = %d, want 0", got)
	}
}

func TestOwnerGone(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "live"}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "dep"}},
		&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "job"}},
	)
	ref := func(kind, name string) *metav1.OwnerReference {
		return &metav1.OwnerReference{Kind: kind, Name: name}
	}
	cases := []struct {
		name           string
		ref            *metav1.OwnerReference
		kinds          []string
		gone, resolved bool
	}{
		{"nil ref is not a dead owner", nil, []string{"Pod"}, false, true},
		{"kind outside the whitelist is unresolvable",
			ref("ConfigMap", "x"), []string{"Pod"}, false, false},
		{"whitelisted kind with no resolver fails closed",
			ref("Foo", "x"), []string{"Foo"}, false, false},
		{"pod exists", ref("Pod", "live"), []string{"Pod"}, false, true},
		{"pod missing reads gone",
			ref("Pod", "gone"), []string{"Pod"}, true, true},
		{"deployment exists",
			ref("Deployment", "dep"), []string{"Deployment"}, false, true},
		{"deployment missing reads gone",
			ref("Deployment", "gone"), []string{"Deployment"}, true, true},
		{"job exists", ref("Job", "job"), []string{"Job"}, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gone, resolved := OwnerGone(t.Context(), cs, "ns",
				tc.ref, tc.kinds...)
			if gone != tc.gone || resolved != tc.resolved {
				t.Fatalf("OwnerGone = (%v,%v), want (%v,%v)",
					gone, resolved, tc.gone, tc.resolved)
			}
		})
	}
}

func TestOwnerGoneAPIErrorFailsClosed(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("get", "pods",
		func(action ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("apiserver boom")
		})
	gone, resolved := OwnerGone(t.Context(), cs, "ns",
		&metav1.OwnerReference{Kind: "Pod", Name: "any"}, "Pod")
	if gone || resolved {
		t.Fatalf("OwnerGone = (%v,%v), want (false,false) on API error",
			gone, resolved)
	}
}
