// calico_controllers_patcher_test.go — unit tests for calico-controllers-patcher.
package calicocontrollerspatcher

import (
	"errors"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func calicoDeployPinned() *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      calicoControllersName,
			Namespace: calicoControllersNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(int32(1)),
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:  calicoControllersContainer,
						Image: "calico/kube-controllers:v3.28.0",
						ReadinessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								Exec: &corev1.ExecAction{
									Command: []string{"/usr/bin/check-status", "-r"},
								},
							},
							PeriodSeconds:    10,
							TimeoutSeconds:   calicoReadinessTimeoutSeconds,
							FailureThreshold: calicoReadinessFailureThreshold,
						},
					}},
				},
			},
		},
	}
}

func calicoDeployBare() *appsv1.Deployment {
	d := calicoDeployPinned()
	d.Spec.Template.Spec.Containers[0].ReadinessProbe.TimeoutSeconds = 1
	d.Spec.Template.Spec.Containers[0].ReadinessProbe.FailureThreshold = 3
	return d
}

func getCalicoDeploy(t *testing.T, cs *fake.Clientset) *appsv1.Deployment {
	t.Helper()
	d, err := cs.AppsV1().Deployments(calicoControllersNamespace).
		Get(t.Context(), calicoControllersName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get calico-kube-controllers: %v", err)
	}
	return d
}

func TestCalicoControllersNeedsPatch(t *testing.T) {
	mutate := func(fn func(*appsv1.Deployment)) *appsv1.Deployment {
		d := calicoDeployPinned()
		fn(d)
		return d
	}
	for _, tc := range []struct {
		name    string
		d       *appsv1.Deployment
		drifted bool
	}{
		{"k0s baseline", calicoDeployBare(), true},
		{"fully pinned", calicoDeployPinned(), false},
		{"nil readiness probe", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Containers[0].ReadinessProbe = nil
		}), false},
		{"timeoutSeconds drifted", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Containers[0].ReadinessProbe.TimeoutSeconds = 2
		}), true},
		{"failureThreshold drifted", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Containers[0].ReadinessProbe.FailureThreshold = 3
		}), true},
		{"missing container", mutate(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Containers = nil
		}), true},
		{"replicas change is not drift", mutate(func(d *appsv1.Deployment) {
			d.Spec.Replicas = ptr.To(int32(3))
		}), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := calicoControllersNeedsPatch(tc.d, 0); got != tc.drifted {
				t.Fatalf("calicoControllersNeedsPatch=%v, want %v", got, tc.drifted)
			}
		})
	}
}

func TestCalicoControllersPatcherAppliesPatch(t *testing.T) {
	bare := calicoDeployBare()
	bare.Spec.Replicas = ptr.To(int32(2))
	cs := fake.NewSimpleClientset(bare)
	var got []byte
	testutil.CaptureDeployPatch(cs, &got)

	r := &calicoControllersPatcher{cs: cs}
	res, err := r.Reconcile(t.Context(), reconcile.Request{})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter < 13*time.Minute+30*time.Second || res.RequeueAfter >= 16*time.Minute+30*time.Second {
		t.Fatalf("expected ~15m requeue, got %s", res.RequeueAfter)
	}
	if len(got) == 0 {
		t.Fatal("expected patch to be applied")
	}
	if strings.Contains(string(got), `"replicas"`) {
		t.Fatalf("patch must not pin replicas: %s", got)
	}
	after := getCalicoDeploy(t, cs)
	if calicoControllersNeedsPatch(after, 0) {
		t.Fatal("deployment still drifted after patch")
	}
	rp := after.Spec.Template.Spec.Containers[0].ReadinessProbe
	if rp == nil || rp.TimeoutSeconds != 5 || rp.FailureThreshold != 6 {
		t.Fatalf("readinessProbe = %+v, want timeoutSeconds=5 failureThreshold=6", rp)
	}
	if rp.Exec == nil || len(rp.Exec.Command) == 0 {
		t.Fatalf("strategic merge dropped existing exec handler: %+v", rp)
	}
	if after.Spec.Replicas == nil || *after.Spec.Replicas != 2 {
		t.Fatalf("replicas changed to %v, want 2 untouched", after.Spec.Replicas)
	}
}

func TestCalicoControllersPatcherNoDriftSkipsPatch(t *testing.T) {
	cs := fake.NewSimpleClientset(calicoDeployPinned())
	patched := false
	cs.PrependReactor("patch", "deployments", func(ktesting.Action) (bool, runtime.Object, error) {
		patched = true
		return false, nil, nil
	})
	r := &calicoControllersPatcher{cs: cs}
	res, err := r.Reconcile(t.Context(), reconcile.Request{})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Fatal("expected non-zero requeue")
	}
	if patched {
		t.Fatal("pinned deployment must not be patched")
	}
}

func TestCalicoControllersPatcherNotFoundNoops(t *testing.T) {
	// Cilium clusters have no kube-system/calico-kube-controllers Deployment.
	cs := fake.NewSimpleClientset()
	r := &calicoControllersPatcher{cs: cs}
	res, err := r.Reconcile(t.Context(), reconcile.Request{})
	if err != nil {
		t.Fatalf("NotFound must no-op without error, got: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Fatal("expected requeue after NotFound")
	}
}

func TestCalicoControllersPatcherMissingContainerSkipsPatch(t *testing.T) {
	d := calicoDeployBare()
	d.Spec.Template.Spec.Containers = []corev1.Container{{Name: "other", Image: "busybox"}}
	cs := fake.NewSimpleClientset(d)
	patched := false
	cs.PrependReactor("patch", "deployments", func(ktesting.Action) (bool, runtime.Object, error) {
		patched = true
		return false, nil, nil
	})
	r := &calicoControllersPatcher{cs: cs}
	if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err != nil {
		t.Fatalf("missing container must skip without error, got: %v", err)
	}
	if patched {
		t.Fatal("missing container must skip patch")
	}
}

func TestCalicoControllersPatcherErrorPropagates(t *testing.T) {
	cs := fake.NewSimpleClientset(calicoDeployBare())
	want := errors.New("apiserver timeout")
	cs.PrependReactor("patch", "deployments", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, want
	})
	r := &calicoControllersPatcher{cs: cs}
	if _, err := r.Reconcile(t.Context(), reconcile.Request{}); !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}

func TestOnlyCalicoControllersDeploymentPredicate(t *testing.T) {
	match := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "calico-kube-controllers", Namespace: "kube-system"}}
	otherName := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "coredns", Namespace: "kube-system"}}
	otherNS := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "calico-kube-controllers", Namespace: "default"}}

	if !onlyCalicoControllersDeployment.Create(event.CreateEvent{Object: match}) {
		t.Fatal("predicate rejected kube-system/calico-kube-controllers")
	}
	if onlyCalicoControllersDeployment.Create(event.CreateEvent{Object: otherName}) {
		t.Fatal("predicate accepted kube-system/coredns")
	}
	if onlyCalicoControllersDeployment.Create(event.CreateEvent{Object: otherNS}) {
		t.Fatal("predicate accepted default/calico-kube-controllers")
	}
}
