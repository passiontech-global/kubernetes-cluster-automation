// calico_node_patch_test.go — coverage for calico-node DaemonSet
// IP_AUTODETECTION_METHOD=kubernetes-internal-ip drift detection and patching.
package calicocontrollerspatcher

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func calicoNodeDS(autoMethod string, ready int32) *appsv1.DaemonSet {
	var env []corev1.EnvVar
	if autoMethod != "" {
		env = []corev1.EnvVar{{Name: calicoIPAutoEnvName, Value: autoMethod}}
	}
	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:       calicoNodeName,
			Namespace:  calicoControllersNamespace,
			Generation: 1,
		},
		Spec: appsv1.DaemonSetSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:  calicoNodeContainer,
						Image: "quay.io/k0sproject/calico-node:v3.32.2-1",
						Env:   env,
					}},
				},
			},
		},
		Status: appsv1.DaemonSetStatus{
			ObservedGeneration:     1,
			DesiredNumberScheduled: 3,
			UpdatedNumberScheduled: 3,
			NumberReady:            ready,
		},
	}
}

func TestCalicoNodeNeedsPatch(t *testing.T) {
	if !calicoNodeNeedsPatch(calicoNodeDS("", 3)) {
		t.Fatal("missing IP_AUTODETECTION_METHOD must read drifted")
	}
	if !calicoNodeNeedsPatch(calicoNodeDS("first-found", 3)) {
		t.Fatal("first-found IP_AUTODETECTION_METHOD must read drifted")
	}
	if calicoNodeNeedsPatch(calicoNodeDS(calicoIPAutoEnvWant, 3)) {
		t.Fatal("kubernetes-internal-ip must not read drifted")
	}
}

func TestCalicoControllersPatcherPatchesCalicoNodeDS(t *testing.T) {
	cs := fake.NewSimpleClientset(calicoDeployPinned(), calicoNodeDS("first-found", 3))
	var dsPatch string
	cs.PrependReactor("patch", "daemonsets", func(action ktesting.Action) (bool, runtime.Object, error) {
		pa := action.(ktesting.PatchAction)
		dsPatch = string(pa.GetPatch())
		return false, nil, nil
	})

	r := &calicoControllersPatcher{cs: cs}
	if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !strings.Contains(dsPatch, calicoIPAutoEnvWant) {
		t.Fatalf("calico-node DaemonSet was not patched with %s, patch=%q", calicoIPAutoEnvWant, dsPatch)
	}
}

func TestCalicoControllersPatcherSkipsCalicoNodeMidRollout(t *testing.T) {
	cs := fake.NewSimpleClientset(calicoDeployPinned(), calicoNodeDS("first-found", 1))
	patched := false
	cs.PrependReactor("patch", "daemonsets", func(action ktesting.Action) (bool, runtime.Object, error) {
		patched = true
		return false, nil, nil
	})
	r := &calicoControllersPatcher{cs: cs}
	if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if patched {
		t.Fatal("must not patch calico-node DaemonSet while rollout is unsettled")
	}
}
