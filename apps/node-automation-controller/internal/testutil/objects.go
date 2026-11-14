// objects.go — the shared k8s fixtures and fake-clientset seams:
// Node/Namespace builders, GetNode, GaugeSeriesValue,
// CaptureDeployPatch/ForbidDeployPatch, and the pod spec.nodeName
// field-selector emulator the fake clientset lacks.
package testutil

import (
	"context"
	"maps"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/testhelp"
)

// Re-exports over platform/testhelp (dynamic.go documents why the
// machinery lives at the platform leaf): EmulateEviction teaches the
// fake clientset the apiserver's pods/eviction contract, and
// PodExists/PodExistsStrict are the pod-presence probes the
// eviction/heal module tests share.
var (
	EmulateEviction = testhelp.EmulateEviction
	PodExists       = testhelp.PodExists
	PodExistsStrict = testhelp.PodExistsStrict
)

// Node builds a *corev1.Node fixture with a single Ready condition —
// the shape every node-sweep module test asserts on.
func Node(name string, ready corev1.ConditionStatus, labels map[string]string, taints ...corev1.Taint) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
		Spec:       corev1.NodeSpec{Taints: taints},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{
			Type:   corev1.NodeReady,
			Status: ready,
		}}},
	}
}

// GetNode fetches a Node out of the fake clientset or fails the test.
func GetNode(t *testing.T, cs *fake.Clientset, name string) *corev1.Node {
	t.Helper()
	n, err := cs.CoreV1().Nodes().Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get node %s: %v", name, err)
	}
	return n
}

// GaugeSeriesValue reads one GaugeVec series off the controller-
// runtime registry WITHOUT creating it — promtestutil.ToFloat64(
// vec.WithLabelValues(...)) instantiates the tuple at 0, which makes
// "want 0" assertions vacuous (absent and emitted-0 are
// indistinguishable). Returns (value, present).
func GaugeSeriesValue(t *testing.T, family string, want map[string]string) (float64, bool) {
	t.Helper()
	fams, err := ctrlmetrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, f := range fams {
		if f.GetName() != family {
			continue
		}
		for _, m := range f.GetMetric() {
			labels := map[string]string{}
			for _, lp := range m.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			if maps.Equal(labels, want) {
				return m.GetGauge().GetValue(), true
			}
		}
	}
	return 0, false
}

// Namespace builds a bare *corev1.Namespace fixture.
func Namespace(name string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

// CaptureDeployPatch records a Deployment patch body but lets the
// default reactor apply it to the tracker.
func CaptureDeployPatch(cs *fake.Clientset, got *[]byte) {
	cs.PrependReactor("patch", "deployments",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			*got = a.(ktesting.PatchAction).GetPatch()
			return false, nil, nil
		})
}

// EmulatePodNodeNameSelector teaches the fake clientset to honor the
// spec.nodeName field selector — the fake applies label selectors but
// silently ignores field selectors, so without this a pod on another
// node would leak into the per-node pod list.
func EmulatePodNodeNameSelector(cs *fake.Clientset) {
	gvr := schema.GroupVersionResource{Version: "v1", Resource: "pods"}
	gvk := schema.GroupVersionKind{Version: "v1", Kind: "Pod"}
	cs.PrependReactor("list", "pods",
		func(action ktesting.Action) (bool, runtime.Object, error) {
			la, ok := action.(ktesting.ListAction)
			if !ok {
				return false, nil, nil
			}
			restr := la.GetListRestrictions()
			nodeName, found := "", false
			if restr.Fields != nil {
				nodeName, found = restr.Fields.RequiresExactMatch("spec.nodeName")
			}
			if !found {
				return false, nil, nil // no nodeName filter -> fake default
			}
			obj, err := cs.Tracker().List(gvr, gvk, la.GetNamespace())
			if err != nil {
				return true, nil, err
			}
			all := obj.(*corev1.PodList)
			out := &corev1.PodList{ListMeta: all.ListMeta}
			for i := range all.Items {
				p := &all.Items[i]
				if p.Spec.NodeName != nodeName {
					continue
				}
				if restr.Labels != nil &&
					!restr.Labels.Matches(labels.Set(p.Labels)) {
					continue
				}
				out.Items = append(out.Items, *p)
			}
			return true, out, nil
		})
}

// ForbidResourcePatch records any patch attempt on resource.
func ForbidResourcePatch(cs *fake.Clientset, resource string, patched *bool) {
	cs.PrependReactor("patch", resource,
		func(ktesting.Action) (bool, runtime.Object, error) {
			*patched = true
			return true, nil, nil
		})
}

// ForbidDeployPatch records any patch attempt on deployments — the
// probe for "reconcile must not patch".
func ForbidDeployPatch(cs *fake.Clientset, patched *bool) {
	ForbidResourcePatch(cs, "deployments", patched)
}

// ForbidDaemonSetPatch records any patch attempt on daemonsets.
func ForbidDaemonSetPatch(cs *fake.Clientset, patched *bool) {
	ForbidResourcePatch(cs, "daemonsets", patched)
}
