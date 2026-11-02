package controller

import (
	"errors"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// konnectivityDS builds a rollout-settled konnectivity-agent DaemonSet
// carrying the given priorityClassName and container requests ("" for
// either request dimension leaves that request unset).
func konnectivityDS(priorityClass, cpu, mem string) *appsv1.DaemonSet {
	req := corev1.ResourceRequirements{}
	if cpu != "" || mem != "" {
		req.Requests = corev1.ResourceList{}
		if cpu != "" {
			req.Requests[corev1.ResourceCPU] = resource.MustParse(cpu)
		}
		if mem != "" {
			req.Requests[corev1.ResourceMemory] = resource.MustParse(mem)
		}
	}
	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: "konnectivity-agent", Namespace: "kube-system", Generation: 2,
		},
		Spec: appsv1.DaemonSetSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					PriorityClassName: priorityClass,
					Containers: []corev1.Container{
						{Name: "konnectivity-agent", Resources: req},
					},
				},
			},
		},
		Status: appsv1.DaemonSetStatus{
			ObservedGeneration:     2,
			DesiredNumberScheduled: 3,
			UpdatedNumberScheduled: 3,
			NumberReady:            3,
		},
	}
}

func getKonnectivityDS(t *testing.T, cs *fake.Clientset) *appsv1.DaemonSet {
	t.Helper()
	ds, err := cs.AppsV1().DaemonSets("kube-system").
		Get(ctx, "konnectivity-agent", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get konnectivity-agent: %v", err)
	}
	return ds
}

// forbidDSPatch installs a reactor that records any patch attempt on
// daemonsets — the probe for "reconcile must not patch".
func forbidDSPatch(cs *fake.Clientset, patched *bool) {
	cs.PrependReactor("patch", "daemonsets",
		func(ktesting.Action) (bool, runtime.Object, error) {
			*patched = true
			return true, nil, nil
		})
}

func konnectivityContainer(t *testing.T, ds *appsv1.DaemonSet) corev1.Container {
	t.Helper()
	for _, c := range ds.Spec.Template.Spec.Containers {
		if c.Name == "konnectivity-agent" {
			return c
		}
	}
	t.Fatal("konnectivity-agent container missing")
	return corev1.Container{}
}

func TestKonnectivityDrifted(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ds      *appsv1.DaemonSet
		drifted bool
	}{
		{"bare manifest (k0s applier state)", konnectivityDS("", "", ""), true},
		{"priorityClassName wrong, requests right",
			konnectivityDS("", "25m", "32Mi"), true},
		{"requests cpu wrong only",
			konnectivityDS("system-node-critical", "10m", "32Mi"), true},
		{"requests memory wrong only",
			konnectivityDS("system-node-critical", "25m", "64Mi"), true},
		{"fully pinned", konnectivityDS("system-node-critical", "25m", "32Mi"), false},
		{"missing konnectivity-agent container", func() *appsv1.DaemonSet {
			ds := konnectivityDS("system-node-critical", "25m", "32Mi")
			ds.Spec.Template.Spec.Containers = nil
			return ds
		}(), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := konnectivityDrifted(tc.ds); got != tc.drifted {
				t.Fatalf("konnectivityDrifted=%v, want %v", got, tc.drifted)
			}
		})
	}
}

func TestKonnectivityPatcherNoOpWhenCorrect(t *testing.T) {
	cs := fake.NewSimpleClientset(
		konnectivityDS("system-node-critical", "25m", "32Mi"))
	var patched bool
	forbidDSPatch(cs, &patched)

	r := &konnectivityPatcher{cs: cs}
	res, err := r.Reconcile(ctx, reconcile.Request{})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if patched {
		t.Fatal("patched an already-correct DaemonSet")
	}
	if res.RequeueAfter != 15*time.Minute {
		t.Fatalf("expected 15m requeue safety net, got %s", res.RequeueAfter)
	}
}

func TestKonnectivityPatcherMissingDS(t *testing.T) {
	cs := fake.NewSimpleClientset()
	r := &konnectivityPatcher{cs: cs}
	res, err := r.Reconcile(ctx, reconcile.Request{})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter != 15*time.Minute {
		t.Fatalf("expected 15m requeue, got %s", res.RequeueAfter)
	}
}

func TestKonnectivityPatcherPriorityClassDriftOnly(t *testing.T) {
	// Requests are already right but the k0s applier reverted
	// priorityClassName — drift is drift, the whole patch must land.
	cs := fake.NewSimpleClientset(konnectivityDS("", "25m", "32Mi"))
	r := &konnectivityPatcher{cs: cs}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := getKonnectivityDS(t, cs)
	if got.Spec.Template.Spec.PriorityClassName != "system-node-critical" {
		t.Fatalf("priorityClassName not patched: %q",
			got.Spec.Template.Spec.PriorityClassName)
	}
	c := konnectivityContainer(t, got)
	if c.Resources.Requests.Cpu().Cmp(konnectivityWantCPU) != 0 ||
		c.Resources.Requests.Memory().Cmp(konnectivityWantMem) != 0 {
		t.Fatalf("correct requests were mangled: %+v", c.Resources.Requests)
	}
}

func TestKonnectivityPatcherRequestsDriftOnly(t *testing.T) {
	// priorityClassName already right, requests reverted to a
	// different value — still a full patch.
	cs := fake.NewSimpleClientset(
		konnectivityDS("system-node-critical", "250m", "256Mi"))
	r := &konnectivityPatcher{cs: cs}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := getKonnectivityDS(t, cs)
	c := konnectivityContainer(t, got)
	if c.Resources.Requests.Cpu().Cmp(konnectivityWantCPU) != 0 ||
		c.Resources.Requests.Memory().Cmp(konnectivityWantMem) != 0 {
		t.Fatalf("requests not patched back: %+v", c.Resources.Requests)
	}
}

// A DaemonSet get failure other than NotFound is a real error — only
// NotFound is the "no konnectivity on this cluster" no-op.
func TestKonnectivityPatcherGetError(t *testing.T) {
	cs := fake.NewSimpleClientset(
		konnectivityDS("", "", ""))
	cs.PrependReactor("get", "daemonsets",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	r := &konnectivityPatcher{cs: cs}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err == nil {
		t.Fatal("expected error when the daemonset get fails")
	}
}

// A failed drift patch errors the reconcile — the metric must surface
// a persistent failure to re-pin the requests.
func TestKonnectivityPatcherPatchError(t *testing.T) {
	cs := fake.NewSimpleClientset(
		konnectivityDS("", "", ""))
	cs.PrependReactor("patch", "daemonsets",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})
	r := &konnectivityPatcher{cs: cs}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err == nil {
		t.Fatal("expected error when the drift patch fails")
	}
	if got := getKonnectivityDS(t, cs).Spec.Template.Spec.PriorityClassName; got != "" {
		t.Fatalf("DS mutated despite the failed patch: %q", got)
	}
}
