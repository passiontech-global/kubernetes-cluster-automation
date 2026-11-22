package probefw

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/testhelp"
)

func TestHealAllowedVariantsAndDeletePodHealScoped(t *testing.T) {
	now := time.Now()
	dsPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "kube-system",
			Name:      "ds-pod",
			UID:       "u-ds",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1",
				Kind:       "DaemonSet",
				Name:       "agent",
				UID:        "u-owner-ds",
				Controller: ptr.To(true),
			}},
		},
		Spec: corev1.PodSpec{NodeName: "worker-1"},
	}
	depPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "dep-pod",
			UID:       "u-dep",
		},
		Spec: corev1.PodSpec{NodeName: "worker-1"},
	}
	obj := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cm-1",
			Annotations: map[string]string{
				"passiontech.dev/last-nudge": now.Add(-2 * time.Hour).UTC().Format(time.RFC3339),
			},
		},
	}

	cs := fake.NewSimpleClientset(dsPod, depPod)
	d := &Deps{
		Name: "probefw-test",
		CS:   cs,
		Dyn:  testhelp.NewDynamicClient(),
	}
	ctx := WithSweepSnapshot(context.Background(), d)

	var ledger state.CooldownSet
	if proceed, unver := d.HealAllowedOnNode(ctx, logr.Discard(), &ledger, "k1", "worker-1", time.Hour, now); !proceed || unver {
		t.Fatalf("HealAllowedOnNode = (%v,%v), want (true,false)", proceed, unver)
	}
	if proceed, unver := d.HealAllowedUpgradeOnly(ctx, logr.Discard(), "k2", now); !proceed || unver {
		t.Fatalf("HealAllowedUpgradeOnly = (%v,%v), want (true,false)", proceed, unver)
	}
	if proceed, unver := d.HealAllowedUpgradeOnlyPersisted(ctx, logr.Discard(), &ledger, obj, "passiontech.dev/last-nudge", "k3", time.Hour, now); !proceed || unver {
		t.Fatalf("HealAllowedUpgradeOnlyPersisted = (%v,%v), want (true,false)", proceed, unver)
	}

	if !d.DeletePodHealScoped(ctx, logr.Discard(), "chk", "ds-pod", dsPod, time.Minute, now) {
		t.Fatal("DeletePodHealScoped(DaemonSet) returned false")
	}
	if !d.DeletePodHealScoped(ctx, logr.Discard(), "chk", "dep-pod", depPod, time.Minute, now) {
		t.Fatal("DeletePodHealScoped(non-DaemonSet) returned false")
	}
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, "ds-pod", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("ds-pod not deleted: %v", err)
	}
	if _, err := cs.CoreV1().Pods("default").Get(ctx, "dep-pod", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("dep-pod not deleted: %v", err)
	}
}

func TestCensusHit(t *testing.T) {
	pods := []corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "p1", UID: types.UID("uid-1")}},
	}
	if found, uid := censusHit(pods, "ns1", "p1", func(p *corev1.Pod) metav1.Object { return p }); !found || uid != "uid-1" {
		t.Fatalf("censusHit hit = (%v,%q), want (true,uid-1)", found, uid)
	}
	if found, _ := censusHit(pods, "ns1", "missing", func(p *corev1.Pod) metav1.Object { return p }); found {
		t.Fatal("censusHit miss returned true")
	}
}

func TestSnapshotClusterNodesPVsUnstructuredAndInvalidations(t *testing.T) {
	vwc := &admissionv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "vwc-1"}}
	mwc := &admissionv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "mwc-1"}}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}}
	pv := &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "pv-1"}}
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "d1"}}
	sts := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "s1"}}
	cj := &batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "c1"}}

	gvr := schema.GroupVersionResource{Group: "example.com", Version: "v1", Resource: "widgets"}
	widget := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "example.com/v1",
			"kind":       "Widget",
			"metadata": map[string]any{
				"namespace": "default",
				"name":      "w1",
			},
		},
	}

	cs := fake.NewSimpleClientset(vwc, mwc, node, pv, dep, sts, cj)
	dyn := testhelp.NewDynamicClient(widget)
	d := &Deps{Name: "snap-test", CS: cs, Dyn: dyn}
	ctx := WithSweepSnapshot(context.Background(), d)

	if got, err := d.AllValidatingWebhookConfigurations(ctx); err != nil || len(got) != 1 {
		t.Fatalf("AllValidatingWebhookConfigurations = (%d,%v)", len(got), err)
	}
	if got, err := d.AllMutatingWebhookConfigurations(ctx); err != nil || len(got) != 1 {
		t.Fatalf("AllMutatingWebhookConfigurations = (%d,%v)", len(got), err)
	}
	if got, err := d.AllPersistentVolumes(ctx); err != nil || len(got) != 1 {
		t.Fatalf("AllPersistentVolumes = (%d,%v)", len(got), err)
	}
	if got, err := d.Node(ctx, "n1"); err != nil || got == nil || got.Name != "n1" {
		t.Fatalf("Node(n1) = (%v,%v)", got, err)
	}
	if got, err := d.Node(ctx, "missing"); err != nil || got != nil {
		t.Fatalf("Node(missing) = (%v,%v), want (nil,nil)", got, err)
	}
	if got, err := d.Unstructured(ctx, gvr, "default", "w1"); err != nil || got == nil || got.GetName() != "w1" {
		t.Fatalf("Unstructured(w1) = (%v,%v)", got, err)
	}
	if got, err := d.Unstructured(ctx, gvr, "default", "missing"); err != nil || got != nil {
		t.Fatalf("Unstructured(missing) = (%v,%v), want (nil,nil)", got, err)
	}

	// Exercise census invalidation helpers.
	d.InvalidateDeployments(ctx)
	d.InvalidateStatefulSets(ctx)
	d.InvalidateCronJobs(ctx)
	d.InvalidateReplicaSets(ctx)
	d.InvalidateUnstructured(ctx)
}
