package testutil

import (
	"testing"

	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// dynObj builds a bare unstructured CR — the shape every module test
// builder produces.
func dynObj(apiVersion, kind, ns, name string) *unstructured.Unstructured {
	o := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": apiVersion,
		"kind":       kind,
	}}
	o.SetNamespace(ns)
	o.SetName(name)
	return o
}

// The whole point of NewDynamicClient: List on a CRD GVR works with
// zero per-call-site list-kind plumbing — the case StubDyn (empty
// scheme) and an unmapped NewFakeDyn both panic on.
func TestNewDynamicClientListsKnownCRDs(t *testing.T) {
	cert := dynObj("cert-manager.io/v1", "Certificate", "apps", "tls-a")
	hrV2beta2 := dynObj("helm.toolkit.fluxcd.io/v2beta2", "HelmRelease", "apps", "hr-old")
	plan := dynObj("autopilot.k0sproject.io/v1beta2", "Plan", "", "upgrade-1")
	dyn := NewDynamicClient(cert, hrV2beta2, plan)
	ctx := t.Context()

	certs, err := dyn.Resource(schema.GroupVersionResource{
		Group: "cert-manager.io", Version: "v1", Resource: "certificates",
	}).Namespace("apps").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list certificates: %v", err)
	}
	if len(certs.Items) != 1 || certs.Items[0].GetName() != "tls-a" {
		t.Fatalf("certificates = %v, want [tls-a]", certs.Items)
	}

	// v2beta2 HelmRelease is a distinct GVR from v2 — both must list.
	hrs, err := dyn.Resource(schema.GroupVersionResource{
		Group: "helm.toolkit.fluxcd.io", Version: "v2beta2", Resource: "helmreleases",
	}).Namespace("apps").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list helmreleases/v2beta2: %v", err)
	}
	if len(hrs.Items) != 1 || hrs.Items[0].GetName() != "hr-old" {
		t.Fatalf("helmreleases/v2beta2 = %v, want [hr-old]", hrs.Items)
	}

	plans, err := dyn.Resource(schema.GroupVersionResource{
		Group: "autopilot.k0sproject.io", Version: "v1beta2", Resource: "plans",
	}).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list plans: %v", err)
	}
	if len(plans.Items) != 1 || plans.Items[0].GetName() != "upgrade-1" {
		t.Fatalf("plans = %v, want [upgrade-1]", plans.Items)
	}
}

// An unseeded GVR must still List (empty, not panic) — the
// clusterhealthprobes pattern where every watched CRD is listed
// unconditionally and absence reads as "operator not installed".
func TestNewDynamicClientListsUnseededGVR(t *testing.T) {
	dyn := NewDynamicClient()
	list, err := dyn.Resource(schema.GroupVersionResource{
		Group: "cilium.io", Version: "v2", Resource: "ciliumidentities",
	}).List(t.Context(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list ciliumidentities: %v", err)
	}
	if len(list.Items) != 0 {
		t.Fatalf("ciliumidentities = %v, want empty", list.Items)
	}
}

// Create->Get round-trip on a GVR nothing seeded — proves the
// tracker stores under the same GVR the module code uses.
func TestNewDynamicClientCreateGet(t *testing.T) {
	dyn := NewDynamicClient()
	ctx := t.Context()
	gvr := schema.GroupVersionResource{
		Group: "external-secrets.io", Version: "v1beta1", Resource: "externalsecrets",
	}
	obj := dynObj("external-secrets.io/v1beta1", "ExternalSecret", "apps", "es-1")
	if _, err := dyn.Resource(gvr).Namespace("apps").Create(ctx, obj, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create externalsecret: %v", err)
	}
	got, err := dyn.Resource(gvr).Namespace("apps").Get(ctx, "es-1", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get externalsecret: %v", err)
	}
	if got.GetName() != "es-1" || got.GetAPIVersion() != "external-secrets.io/v1beta1" {
		t.Fatalf("got %v/%v", got.GetAPIVersion(), got.GetName())
	}
}

// Typed seeds work too: the client-go scheme inside NewDynamicClient
// converts them to unstructured (and resolves the GVK when TypeMeta
// is empty, the shape k8s test fixtures usually carry) — something
// NewFakeDyn's empty scheme cannot do.
func TestNewDynamicClientTypedSeed(t *testing.T) {
	lease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "lock"},
	}
	dyn := NewDynamicClient(lease)
	list, err := dyn.Resource(schema.GroupVersionResource{
		Group: "coordination.k8s.io", Version: "v1", Resource: "leases",
	}).Namespace("kube-system").List(t.Context(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list leases: %v", err)
	}
	if len(list.Items) != 1 || list.Items[0].GetName() != "lock" {
		t.Fatalf("leases = %v, want [lock]", list.Items)
	}
}

// The pluralization the fake's list-kind map depends on must match
// the resource strings the module GVR literals use — spot-check the
// irregular ones (trailing-s, trailing-y) plus a version variant.
func TestDynListKinds(t *testing.T) {
	kinds := DynListKinds()
	for gvr, want := range map[schema.GroupVersionResource]string{
		{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gatewayclasses"}: "GatewayClassList",
		// "gateways" is NOT the guessed plural (UnsafeGuessKindToResource
		// yields "gatewaies") — it comes from dynListKindOverrides.
		{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"}:   "GatewayList",
		{Group: "dragonflydb.io", Version: "v1alpha1", Resource: "dragonflies"}:     "DragonflyList",
		{Group: "cert-manager.io", Version: "v1", Resource: "certificaterequests"}:  "CertificateRequestList",
		{Group: "autopilot.k0sproject.io", Version: "v1beta2", Resource: "plans"}:   "PlanList",
		{Group: "cilium.io", Version: "v2alpha1", Resource: "ciliumendpointslices"}: "CiliumEndpointSliceList",
	} {
		if got := kinds[gvr]; got != want {
			t.Fatalf("DynListKinds[%v] = %q, want %q", gvr, got, want)
		}
	}
}

// DynScheme must recognize the List GVKs (that is what makes
// tracker.List's scheme.New(<Kind>List) succeed) and must be fresh
// per call so a caller can register extra types without poisoning
// the shared cached scheme.
func TestDynScheme(t *testing.T) {
	s := DynScheme()
	listGVK := schema.GroupVersionKind{
		Group: "cert-manager.io", Version: "v1", Kind: "CertificateList"}
	if !s.Recognizes(listGVK) {
		t.Fatalf("scheme does not recognize %v", listGVK)
	}
	obj, err := s.New(listGVK)
	if err != nil {
		t.Fatalf("scheme.New(%v): %v", listGVK, err)
	}
	if _, ok := obj.(*unstructured.UnstructuredList); !ok {
		t.Fatalf("scheme.New(%v) = %T, want *unstructured.UnstructuredList", listGVK, obj)
	}
	// Fresh-per-call: mutating one scheme must not affect the next.
	s.AddKnownTypeWithName(schema.GroupVersionKind{Version: "v1", Kind: "Widget"},
		&unstructured.Unstructured{})
	if DynScheme().Recognizes(schema.GroupVersionKind{Version: "v1", Kind: "Widget"}) {
		t.Fatal("DynScheme schemes are not independent")
	}
}
