package integration

import (
	"errors"
	"fmt"
	"testing"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/controller/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

var ciliumAuditListKinds = map[schema.GroupVersionResource]string{
	ciliumIdentityGVR: "CiliumIdentityList",
	ciliumEndpointGVR: "CiliumEndpointList",
}

func ciliumIdentity(name string) *unstructured.Unstructured {
	o := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "cilium.io/v2",
		"kind":       "CiliumIdentity",
	}}
	o.SetName(name)
	return o
}

func ciliumEndpoint(ns, name string, id int64) *unstructured.Unstructured {
	o := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "cilium.io/v2",
		"kind":       "CiliumEndpoint",
	}}
	o.SetNamespace(ns)
	o.SetName(name)
	_ = unstructured.SetNestedField(o.Object, id, "status", "identity", "id")
	return o
}

func identityPod(ns, name, identityID string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace:   ns,
		Name:        name,
		Annotations: map[string]string{ciliumIDAnnotation: identityID},
	}}
}

func TestCiliumIdentityAuditorSetupDisabled(t *testing.T) {
	if err := SetupCiliumIdentityAuditor(nil, nil, nil, false); err != nil {
		t.Fatalf("disabled setup must return nil, got %v", err)
	}
}

// Identity referenced by a CiliumEndpoint or a pod annotation is used;
// the rest are orphans — below the threshold they log only (no error,
// no deletion).
func TestCiliumIdentityAuditorDetectsOrphansBelowThreshold(t *testing.T) {
	dyn := newFakeDyn(ciliumAuditListKinds,
		ciliumIdentity("100"), ciliumIdentity("200"), ciliumIdentity("300"),
		ciliumEndpoint("app", "cep-1", 100))
	cs := fake.NewSimpleClientset(identityPod("app", "p-1", "200"))
	a := &ciliumIdentityAuditor{cs: cs, dyn: dyn}
	before := testutil.QueueErrorCount(t, ciliumAuditQueue)
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := testutil.QueueErrorCount(t, ciliumAuditQueue) - before; got != 0 {
		t.Fatalf("below-threshold orphans must not IncError, delta %v", got)
	}
	// Detect-only: nothing is ever deleted.
	for _, name := range []string{"100", "200", "300"} {
		if _, err := dyn.Resource(ciliumIdentityGVR).
			Get(ctx, name, metav1.GetOptions{}); err != nil {
			t.Fatalf("identity %s missing — auditor must never delete: %v", name, err)
		}
	}
}

// Clean cluster: every identity referenced -> no orphans.
func TestCiliumIdentityAuditorCleanCluster(t *testing.T) {
	dyn := newFakeDyn(ciliumAuditListKinds,
		ciliumIdentity("1"), ciliumIdentity("2"),
		ciliumEndpoint("a", "cep-1", 1),
		ciliumEndpoint("b", "cep-2", 2))
	a := &ciliumIdentityAuditor{cs: fake.NewSimpleClientset(), dyn: dyn}
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
}

// Orphans above the threshold surface through the legacy error counter
// (existing alert path) — but still no deletion in v1.
func TestCiliumIdentityAuditorOrphanThreshold(t *testing.T) {
	objs := make([]runtime.Object, 0, ciliumOrphanMax+1)
	for i := 0; i < ciliumOrphanMax+1; i++ {
		objs = append(objs, ciliumIdentity(fmt.Sprintf("%d", 5000+i)))
	}
	dyn := newFakeDyn(ciliumAuditListKinds, objs...)
	a := &ciliumIdentityAuditor{cs: fake.NewSimpleClientset(), dyn: dyn}
	before := testutil.QueueErrorCount(t, ciliumAuditQueue)
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := testutil.QueueErrorCount(t, ciliumAuditQueue) - before; got != 1 {
		t.Fatalf("expected exactly 1 IncError above threshold, got %v", got)
	}
	list, err := dyn.Resource(ciliumIdentityGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != ciliumOrphanMax+1 {
		t.Fatalf("auditor deleted identities in detect-only mode: %d left",
			len(list.Items))
	}
}

func TestCiliumIdentityAuditorAPIError(t *testing.T) {
	dyn := newFakeDyn(ciliumAuditListKinds)
	dyn.PrependReactor("list", "ciliumidentities",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	a := &ciliumIdentityAuditor{cs: fake.NewSimpleClientset(), dyn: dyn}
	before := testutil.QueueErrorCount(t, ciliumAuditQueue)
	if err := a.run(ctx); err == nil {
		t.Fatal("expected error when identity list fails")
	}
	if got := testutil.QueueErrorCount(t, ciliumAuditQueue) - before; got != 1 {
		t.Fatalf("expected IncError on API failure, delta %v", got)
	}
}

// The endpoint list feeds the "used" set — its failure aborts rather
// than flag every identity as orphaned on empty data.
func TestCiliumIdentityAuditorEndpointListError(t *testing.T) {
	dyn := newFakeDyn(ciliumAuditListKinds, ciliumIdentity("100"))
	dyn.PrependReactor("list", "ciliumendpoints",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	a := &ciliumIdentityAuditor{cs: fake.NewSimpleClientset(), dyn: dyn}
	before := testutil.QueueErrorCount(t, ciliumAuditQueue)
	if err := a.run(ctx); err == nil {
		t.Fatal("expected error when the ciliumendpoint list fails")
	}
	if got := testutil.QueueErrorCount(t, ciliumAuditQueue) - before; got != 1 {
		t.Fatalf("expected IncError on API failure, delta %v", got)
	}
}

// The pod annotation feed is also mandatory — same abort-on-empty rule.
func TestCiliumIdentityAuditorPodListError(t *testing.T) {
	dyn := newFakeDyn(ciliumAuditListKinds,
		ciliumIdentity("100"), ciliumEndpoint("app", "cep-1", 100))
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "pods",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	a := &ciliumIdentityAuditor{cs: cs, dyn: dyn}
	before := testutil.QueueErrorCount(t, ciliumAuditQueue)
	if err := a.run(ctx); err == nil {
		t.Fatal("expected error when the pod list fails")
	}
	if got := testutil.QueueErrorCount(t, ciliumAuditQueue) - before; got != 1 {
		t.Fatalf("expected IncError on API failure, delta %v", got)
	}
}

// .status.identity.id arrives as int64 in real objects, float64 in
// hand-built fixtures — anything else yields "".
func TestEndpointIdentityID(t *testing.T) {
	withID := func(v any) *unstructured.Unstructured {
		o := &unstructured.Unstructured{Object: map[string]interface{}{
			"apiVersion": "cilium.io/v2",
			"kind":       "CiliumEndpoint",
		}}
		if v != nil {
			_ = unstructured.SetNestedField(o.Object, v, "status", "identity", "id")
		}
		return o
	}
	for _, tc := range []struct {
		name string
		id   any
		want string
	}{
		{"int64", int64(12345), "12345"},
		{"float64", float64(6789), "6789"},
		{"absent", nil, ""},
		{"non-numeric string", "abc", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := endpointIdentityID(withID(tc.id)); got != tc.want {
				t.Fatalf("endpointIdentityID = %q, want %q", got, tc.want)
			}
		})
	}
}
