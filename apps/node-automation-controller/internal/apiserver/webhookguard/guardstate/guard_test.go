// guard_test.go — coverage for the shared dep bundle: the per-run
// snapshot (shared lists + node census + CRD list), the post-patch
// snapshot refreshers, the once-per-run ready census memoization and
// the maintenance-mutex pass-through.
package guardstate

import (
	"context"
	"errors"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

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
	snap := g.TakeSnapshot(context.Background())
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
	snap = gNoDyn.TakeSnapshot(context.Background())
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
	snap := g.TakeSnapshot(context.Background())
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
