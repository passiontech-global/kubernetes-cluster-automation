// guard_test.go — coverage for the shared dep bundle: the per-run
// snapshot (shared lists + node census + CRD list), the post-patch
// snapshot refreshers, the once-per-run ready census memoization and
// the maintenance-mutex pass-through.
package guardstate

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	admissionregclient "k8s.io/client-go/kubernetes/typed/admissionregistration/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	discoveryv1client "k8s.io/client-go/kubernetes/typed/discovery/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/testhelp"
)

// gsTaintedNode builds a node carrying a webhook-dead taint.
func gsTaintedNode(name string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: corev1.NodeSpec{Taints: []corev1.Taint{
			{Key: "node.kubernetes.io/unreachable", Effect: corev1.TaintEffectNoSchedule},
		}},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{
			Type: corev1.NodeReady, Status: corev1.ConditionTrue,
		}}},
	}
}

func TestTakeSnapshot(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "mwc1"}}
	vwc := &admissionv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "vwc1"}}
	crd := gsCRDWithConversion(map[string]any{"strategy": "None"})
	crd.SetName("crds.example.com")
	cs := fake.NewSimpleClientset(
		mwc, vwc,
		gsReadyNodeForSnapshot("healthy"),
		gsTaintedNode("bad-node"),
	)
	g := &Guard{
		CS:  cs,
		Dyn: testhelp.NewDynWithCRDs(crd),
		Now: func() time.Time { return time.Unix(1_700_000_000, 0) },
	}
	snap := g.TakeSnapshot(t.Context())
	if snap.NSErr != nil || snap.MWCErr != nil || snap.VWCErr != nil || snap.CRDErr != nil || snap.NodesErr != nil {
		t.Fatalf("unexpected snapshot errors: ns=%v mwc=%v vwc=%v crd=%v nodes=%v",
			snap.NSErr, snap.MWCErr, snap.VWCErr, snap.CRDErr, snap.NodesErr)
	}
	if snap.MWC == nil || len(snap.MWC.Items) != 1 {
		t.Fatalf("MWC list = %+v, want 1 item", snap.MWC)
	}
	if snap.VWC == nil || len(snap.VWC.Items) != 1 {
		t.Fatalf("VWC list = %+v, want 1 item", snap.VWC)
	}
	if len(snap.CRDs) != 1 || snap.CRDs[0].GetName() != "crds.example.com" {
		t.Fatalf("CRDs = %v, want 1 crds.example.com", snap.CRDs)
	}
	if !snap.UnhealthyNodes["bad-node"] || snap.UnhealthyNodes["healthy"] {
		t.Fatalf("UnhealthyNodes = %v, want only bad-node", snap.UnhealthyNodes)
	}
	if snap.G != g || snap.Ctx == nil {
		t.Fatal("snapshot must carry its guard and context")
	}

	// A nil dynamic client records the CRD list as skipped, not fatal.
	gNoDyn := &Guard{CS: cs}
	snap = gNoDyn.TakeSnapshot(t.Context())
	if snap.CRDErr == nil {
		t.Fatal("nil dyn must record a CRDErr")
	}
	if snap.MWCErr != nil {
		t.Fatalf("admission lists must still succeed: %v", snap.MWCErr)
	}
}

// gsReadyNodeForSnapshot is census_test.go's gsReadyNode minus the
// package-local name collision risk in this file's fixtures.
func gsReadyNodeForSnapshot(name string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{
			Type: corev1.NodeReady, Status: corev1.ConditionTrue,
		}}},
	}
}

func TestSetMWCSetVWC(t *testing.T) {
	orig := &admissionv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "mwc1"}}
	other := &admissionv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "absent"}}
	snap := &Snapshot{MWC: &admissionv1.MutatingWebhookConfigurationList{
		Items: []admissionv1.MutatingWebhookConfiguration{*orig}}}

	// nil cfg and absent name are no-ops.
	snap.SetMWC(nil)
	snap.SetMWC(other)
	if len(snap.MWC.Items) != 1 || snap.MWC.Items[0].Name != "mwc1" {
		t.Fatalf("no-op SetMWC mutated the list: %+v", snap.MWC.Items)
	}

	patched := orig.DeepCopy()
	fp := admissionv1.Ignore
	patched.Webhooks = []admissionv1.MutatingWebhook{{Name: "h", FailurePolicy: &fp}}
	snap.SetMWC(patched)
	if snap.MWC.Items[0].Webhooks[0].Name != "h" {
		t.Fatalf("SetMWC did not replace the entry: %+v", snap.MWC.Items[0])
	}

	// nil list guards.
	nilSnap := &Snapshot{}
	nilSnap.SetMWC(patched) // must not panic

	// Validating twin.
	vorig := &admissionv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "vwc1"}}
	vsnap := &Snapshot{VWC: &admissionv1.ValidatingWebhookConfigurationList{
		Items: []admissionv1.ValidatingWebhookConfiguration{*vorig}}}
	vpatched := vorig.DeepCopy()
	vpatched.Webhooks = []admissionv1.ValidatingWebhook{{Name: "vh"}}
	vsnap.SetVWC(vpatched)
	if vsnap.VWC.Items[0].Webhooks[0].Name != "vh" {
		t.Fatalf("SetVWC did not replace the entry: %+v", vsnap.VWC.Items[0])
	}
	vsnap.SetVWC(nil)
	vsnap.SetVWC(vorig)
	if len(vsnap.VWC.Items) != 1 {
		t.Fatalf("nil cfg must not mutate the list: %+v", vsnap.VWC.Items)
	}
	nilSnap.SetVWC(vpatched) // nil list guard must not panic
}

func TestReadyCountsMemoized(t *testing.T) {
	mwc := gsInjMWC("hook.example.com", nil, "ns", "svc", "")
	slice := gsInjSlice("ns", "svc", "")
	cs := fake.NewSimpleClientset(slice)
	probes := 0
	g := &Guard{CS: cs, EndpointProber: func(context.Context, string, int32) bool {
		probes++
		return true
	}}
	snap := g.TakeSnapshot(t.Context())
	snap.MWC = mwc

	first, err := snap.ReadyCounts()
	if err != nil {
		t.Fatal(err)
	}
	second, err := snap.ReadyCounts()
	if err != nil {
		t.Fatal(err)
	}
	if !gsMapsEqual(first.Raw, second.Raw) {
		t.Fatalf("memoized census differs: %v vs %v", first.Raw, second.Raw)
	}
	if probes == 0 {
		t.Fatal("census never probed the backend service")
	}
	if probes != 1 {
		t.Fatalf("census probed %d times across two ReadyCounts calls, want exactly 1", probes)
	}

	// The same error is memoized too — a snapshot whose node list
	// failed reports the identical error on every call.
	errSnap := &Snapshot{G: g, UnhealthyNodes: map[string]bool{}, NodesErr: errors.New("boom")}
	_, err1 := errSnap.ReadyCounts()
	_, err2 := errSnap.ReadyCounts()
	if err1 == nil || err1.Error() != err2.Error() {
		t.Fatalf("memoized error differs: %v vs %v", err1, err2)
	}
}

type listOptsRecorder struct {
	kubernetes.Interface
	opts map[string][]metav1.ListOptions
}

func newListOptsRecorder(cs kubernetes.Interface) *listOptsRecorder {
	return &listOptsRecorder{Interface: cs, opts: map[string][]metav1.ListOptions{}}
}

func (r *listOptsRecorder) record(res string, o metav1.ListOptions) {
	r.opts[res] = append(r.opts[res], o)
}

func (r *listOptsRecorder) CoreV1() corev1client.CoreV1Interface {
	return &recCoreV1{CoreV1Interface: r.Interface.CoreV1(), r: r}
}

func (r *listOptsRecorder) AdmissionregistrationV1() admissionregclient.AdmissionregistrationV1Interface {
	return &recAdmissionV1{AdmissionregistrationV1Interface: r.Interface.AdmissionregistrationV1(), r: r}
}

func (r *listOptsRecorder) DiscoveryV1() discoveryv1client.DiscoveryV1Interface {
	return &recDiscoveryV1{DiscoveryV1Interface: r.Interface.DiscoveryV1(), r: r}
}

type recCoreV1 struct {
	corev1client.CoreV1Interface
	r *listOptsRecorder
}

func (c *recCoreV1) Namespaces() corev1client.NamespaceInterface {
	return &recNamespaces{NamespaceInterface: c.CoreV1Interface.Namespaces(), r: c.r}
}

type recNamespaces struct {
	corev1client.NamespaceInterface
	r *listOptsRecorder
}

func (n *recNamespaces) List(ctx context.Context, opts metav1.ListOptions) (*corev1.NamespaceList, error) {
	n.r.record("namespaces", opts)
	return n.NamespaceInterface.List(ctx, opts)
}

type recAdmissionV1 struct {
	admissionregclient.AdmissionregistrationV1Interface
	r *listOptsRecorder
}

func (a *recAdmissionV1) MutatingWebhookConfigurations() admissionregclient.MutatingWebhookConfigurationInterface {
	return &recMWC{MutatingWebhookConfigurationInterface: a.AdmissionregistrationV1Interface.MutatingWebhookConfigurations(), r: a.r}
}

func (a *recAdmissionV1) ValidatingWebhookConfigurations() admissionregclient.ValidatingWebhookConfigurationInterface {
	return &recVWC{ValidatingWebhookConfigurationInterface: a.AdmissionregistrationV1Interface.ValidatingWebhookConfigurations(), r: a.r}
}

type recMWC struct {
	admissionregclient.MutatingWebhookConfigurationInterface
	r *listOptsRecorder
}

func (m *recMWC) List(ctx context.Context, opts metav1.ListOptions) (*admissionv1.MutatingWebhookConfigurationList, error) {
	m.r.record("mutatingwebhookconfigurations", opts)
	return m.MutatingWebhookConfigurationInterface.List(ctx, opts)
}

type recVWC struct {
	admissionregclient.ValidatingWebhookConfigurationInterface
	r *listOptsRecorder
}

func (v *recVWC) List(ctx context.Context, opts metav1.ListOptions) (*admissionv1.ValidatingWebhookConfigurationList, error) {
	v.r.record("validatingwebhookconfigurations", opts)
	return v.ValidatingWebhookConfigurationInterface.List(ctx, opts)
}

type recDiscoveryV1 struct {
	discoveryv1client.DiscoveryV1Interface
	r *listOptsRecorder
}

func (d *recDiscoveryV1) EndpointSlices(ns string) discoveryv1client.EndpointSliceInterface {
	return &recEndpointSlices{EndpointSliceInterface: d.DiscoveryV1Interface.EndpointSlices(ns), r: d.r}
}

type recEndpointSlices struct {
	discoveryv1client.EndpointSliceInterface
	r *listOptsRecorder
}

func (e *recEndpointSlices) List(ctx context.Context, opts metav1.ListOptions) (*discoveryv1.EndpointSliceList, error) {
	e.r.record("endpointslices", opts)
	return e.EndpointSliceInterface.List(ctx, opts)
}

type dynListOptsRecorder struct {
	dynamic.Interface
	opts []metav1.ListOptions
}

func (d *dynListOptsRecorder) Resource(gvr schema.GroupVersionResource) dynamic.NamespaceableResourceInterface {
	return &recDynRI{NamespaceableResourceInterface: d.Interface.Resource(gvr), d: d}
}

type recDynRI struct {
	dynamic.NamespaceableResourceInterface
	d *dynListOptsRecorder
}

func (r *recDynRI) List(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	r.d.opts = append(r.d.opts, opts)
	return r.NamespaceableResourceInterface.List(ctx, opts)
}

func TestSnapshotAndCensusResourceVersionOptions(t *testing.T) {
	mwc := gsInjMWC("hook.example.com", nil, "ns", "svc", "")
	slice := gsInjSlice("ns", "svc", "")
	crd := gsCRDWithConversion(map[string]any{"strategy": "None"})
	crd.SetName("crds.example.com")

	recCS := newListOptsRecorder(fake.NewSimpleClientset(mwc, slice))
	recDyn := &dynListOptsRecorder{Interface: testhelp.NewDynWithCRDs(crd)}
	g := &Guard{CS: recCS, Dyn: recDyn}

	snap := g.TakeSnapshot(t.Context())
	for _, res := range []string{"namespaces", "mutatingwebhookconfigurations", "validatingwebhookconfigurations"} {
		got := recCS.opts[res]
		if len(got) != 1 {
			t.Fatalf("%s list calls = %d, want 1", res, len(got))
		}
		if got[0].ResourceVersion != "0" {
			t.Fatalf("%s ResourceVersion = %q, want \"0\"", res, got[0].ResourceVersion)
		}
	}
	if len(recDyn.opts) != 1 {
		t.Fatalf("CRD fallback list calls = %d, want 1", len(recDyn.opts))
	}
	if recDyn.opts[0].ResourceVersion != "" || recDyn.opts[0].Limit != crdPageSize {
		t.Fatalf("CRD fallback ListOptions = %+v, want ResourceVersion=\"\" Limit=%d",
			recDyn.opts[0], crdPageSize)
	}

	// Filtered EndpointSlices (<=64 backend services) must use ResourceVersion="0".
	if _, err := snap.ReadyCounts(); err != nil {
		t.Fatalf("filtered ReadyCounts: %v", err)
	}
	esOpts := recCS.opts["endpointslices"]
	if len(esOpts) != 1 || esOpts[0].ResourceVersion != "0" || esOpts[0].LabelSelector == "" {
		t.Fatalf("filtered EndpointSlices ListOptions = %+v, want RV=\"0\" and non-empty LabelSelector", esOpts)
	}

	// Unfiltered EndpointSlices (>64 backend services) must keep ResourceVersion="" and Limit=ListPageSize.
	recCSUnfiltered := newListOptsRecorder(fake.NewSimpleClientset())
	gUnfiltered := &Guard{CS: recCSUnfiltered, EndpointProber: func(context.Context, string, int32) bool { return true }}
	hooks := make([]admissionv1.MutatingWebhook, 0, 65)
	for i := range 65 {
		hooks = append(hooks, admissionv1.MutatingWebhook{
			Name: fmt.Sprintf("h-%02d.example.com", i),
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: &admissionv1.ServiceReference{Namespace: "ns", Name: fmt.Sprintf("svc-%02d", i)},
			},
		})
	}
	unfilteredSnap := &Snapshot{
		G: gUnfiltered,
		MWC: &admissionv1.MutatingWebhookConfigurationList{Items: []admissionv1.MutatingWebhookConfiguration{{
			ObjectMeta: metav1.ObjectMeta{Name: "big-mwc"},
			Webhooks:   hooks,
		}}},
		VWC:            &admissionv1.ValidatingWebhookConfigurationList{},
		UnhealthyNodes: map[string]bool{},
	}
	if _, err := unfilteredSnap.ReadyCounts(); err != nil {
		t.Fatalf("unfiltered ReadyCounts: %v", err)
	}
	unfilteredESOpts := recCSUnfiltered.opts["endpointslices"]
	if len(unfilteredESOpts) != 1 ||
		unfilteredESOpts[0].ResourceVersion != "" ||
		unfilteredESOpts[0].Limit != ListPageSize ||
		unfilteredESOpts[0].LabelSelector != "" {
		t.Fatalf("unfiltered EndpointSlices ListOptions = %+v, want RV=\"\" Limit=%d LabelSelector=\"\"",
			unfilteredESOpts, ListPageSize)
	}
}
