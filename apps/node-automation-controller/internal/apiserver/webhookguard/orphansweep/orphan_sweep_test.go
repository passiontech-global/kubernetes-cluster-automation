// orphan_sweep_test.go — duty-level coverage for the orphan sweep
// the facade tests cannot reach: the snapshot census is hand-built,
// so "namespace absent from the census but alive at the apiserver"
// (the TOCTOU the live Namespaces().Get confirm exists for) and the
// kube-system-missing API-flap abort are reproducible — the facade
// always lists the census from the same clientset it would Get
// against.
package orphansweep

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

var ctx = context.Background()

// ---------------------------------------------------------------------------
// Builders (os-prefixed to stay unique across sibling test files)
// ---------------------------------------------------------------------------

func osNamespace(name string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

func osSvcRef(ns, name string) *admissionv1.ServiceReference {
	return &admissionv1.ServiceReference{Namespace: ns, Name: name}
}

func osMutatingHook(name string, svc *admissionv1.ServiceReference) admissionv1.MutatingWebhook {
	return admissionv1.MutatingWebhook{
		Name:         name,
		ClientConfig: admissionv1.WebhookClientConfig{Service: svc},
	}
}

func osValidatingHook(name string, svc *admissionv1.ServiceReference) admissionv1.ValidatingWebhook {
	return admissionv1.ValidatingWebhook{
		Name:         name,
		ClientConfig: admissionv1.WebhookClientConfig{Service: svc},
	}
}

// osSnap builds the duty's input directly: guard over cs plus the
// census the facade would have listed — namespaces live BOTH places
// only when the census is honest (the TOCTOU tests deliberately
// diverge them). Webhook configs must be seeded in cs too: the
// sweep patches through g.CS and re-Gets the result.
func osSnap(cs *fake.Clientset, namespaces []string,
	mwc *admissionv1.MutatingWebhookConfigurationList,
	vwc *admissionv1.ValidatingWebhookConfigurationList) *guardstate.Snapshot {

	nsList := &corev1.NamespaceList{}
	for _, n := range namespaces {
		nsList.Items = append(nsList.Items, *osNamespace(n))
	}
	// TakeSnapshot always hands the sweep non-nil lists on success —
	// nil here means "no configs of that kind", never an unset field.
	if mwc == nil {
		mwc = &admissionv1.MutatingWebhookConfigurationList{}
	}
	if vwc == nil {
		vwc = &admissionv1.ValidatingWebhookConfigurationList{}
	}
	return &guardstate.Snapshot{
		G:   &guardstate.Guard{CS: cs, Queue: "admission-webhook-guard"},
		NS:  nsList,
		MWC: mwc,
		VWC: vwc,
	}
}

func osMutatingNames(snap *guardstate.Snapshot, cfg string) []string {
	for _, c := range snap.MWC.Items {
		if c.Name != cfg {
			continue
		}
		names := make([]string, 0, len(c.Webhooks))
		for _, w := range c.Webhooks {
			names = append(names, w.Name)
		}
		return names
	}
	return nil
}

func osPatchCounter(cs *fake.Clientset) *int32 {
	var calls int32
	cs.PrependReactor("patch", "*",
		func(action ktesting.Action) (bool, runtime.Object, error) {
			atomic.AddInt32(&calls, 1)
			return false, nil, nil // passthrough — let the tracker apply it
		})
	return &calls
}

// ---------------------------------------------------------------------------
// Census abort gates
// ---------------------------------------------------------------------------

// A namespace census missing kube-system is an API flap, not a
// cluster — the sweep must abort before queueing a single patch
// (every namespace it knows is suspect).
func TestSweepAbortsWhenKubeSystemMissing(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfigurationList{Items: []admissionv1.MutatingWebhookConfiguration{{
		ObjectMeta: metav1.ObjectMeta{Name: "cfg"},
		Webhooks: []admissionv1.MutatingWebhook{
			osMutatingHook("orphan.example.com", osSvcRef("dead-ns", "svc")),
		},
	}}}
	cs := fake.NewSimpleClientset(&mwc.Items[0])
	patches := osPatchCounter(cs)
	// The census lists a healthy namespace but NOT kube-system —
	// a partial list the apiserver returns mid-flap.
	snap := osSnap(cs, []string{"alive"}, mwc, nil)

	if err := Sweep(ctx, snap); err == nil {
		t.Fatal("kube-system absent from the census must abort the sweep")
	}
	if got := atomic.LoadInt32(patches); got != 0 {
		t.Fatalf("aborted sweep must patch nothing, got %d patch(es)", got)
	}
}

// ---------------------------------------------------------------------------
// orphanEntry's live namespace confirm — the census→apiserver TOCTOU
// ---------------------------------------------------------------------------

// The census can lag the apiserver (namespaces are listed BEFORE the
// webhook configs): an entry whose svcRef.Namespace is absent from
// the census but still exists live is NOT an orphan — the confirm
// Get proves the census stale and the entry is kept.
func TestSweepKeepsEntryWhenNamespaceConfirmShowsAlive(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfigurationList{Items: []admissionv1.MutatingWebhookConfiguration{{
		ObjectMeta: metav1.ObjectMeta{Name: "cfg"},
		Webhooks: []admissionv1.MutatingWebhook{
			osMutatingHook("racy.example.com", osSvcRef("fresh-ns", "svc")),
		},
	}}}
	// The apiserver knows fresh-ns — the census just hasn't seen it
	// (namespace+webhook created between the two snapshot lists).
	cs := fake.NewSimpleClientset(
		osNamespace("kube-system"), osNamespace("fresh-ns"), &mwc.Items[0])
	patches := osPatchCounter(cs)
	snap := osSnap(cs, []string{"kube-system"}, mwc, nil)

	if err := Sweep(ctx, snap); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(patches); got != 0 {
		t.Fatalf("live-confirmed namespace must keep the entry, got %d patch(es)", got)
	}
}

// A namespace confirm that ERRORS (non-NotFound — the apiserver
// cannot say whether the namespace is gone) fails closed: the entry
// is kept, the sub-failure is tolerated, and the sweep still
// completes so other duties are not held by one ambiguous entry.
func TestSweepKeepsEntryWhenNamespaceConfirmErrors(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfigurationList{Items: []admissionv1.MutatingWebhookConfiguration{{
		ObjectMeta: metav1.ObjectMeta{Name: "cfg"},
		Webhooks: []admissionv1.MutatingWebhook{
			osMutatingHook("ambiguous.example.com", osSvcRef("dead-ns", "svc")),
		},
	}}}
	cs := fake.NewSimpleClientset(
		osNamespace("kube-system"), &mwc.Items[0])
	cs.PrependReactor("get", "namespaces",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api flap on get")
		})
	patches := osPatchCounter(cs)
	snap := osSnap(cs, []string{"kube-system"}, mwc, nil)

	if err := Sweep(ctx, snap); err != nil {
		t.Fatalf("a failed confirm must be tolerated, not fatal: %v", err)
	}
	if got := atomic.LoadInt32(patches); got != 0 {
		t.Fatalf("unverifiable namespace must fail closed — got %d patch(es)", got)
	}
}

// The confirmed-gone twin: namespace absent from the census AND
// NotFound at the apiserver drops the entry — and the shared
// snapshot is refreshed so the duties running later on the same
// snap (circuit breaker, unmeshed audit) see the entry gone, not
// the stale pre-patch list.
func TestSweepDropsConfirmedOrphanAndRefreshesSnapshot(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfigurationList{Items: []admissionv1.MutatingWebhookConfiguration{{
		ObjectMeta: metav1.ObjectMeta{Name: "cfg"},
		Webhooks: []admissionv1.MutatingWebhook{
			osMutatingHook("keep.example.com", osSvcRef("alive", "svc")),
			osMutatingHook("orphan.example.com", osSvcRef("dead-ns", "svc")),
		},
	}}}
	vwc := &admissionv1.ValidatingWebhookConfigurationList{Items: []admissionv1.ValidatingWebhookConfiguration{{
		ObjectMeta: metav1.ObjectMeta{Name: "vcfg"},
		Webhooks: []admissionv1.ValidatingWebhook{
			osValidatingHook("v-orphan.example.com", osSvcRef("dead-ns", "svc")),
			osValidatingHook("v-keep.example.com", osSvcRef("alive", "svc")),
		},
	}}}
	cs := fake.NewSimpleClientset(
		osNamespace("kube-system"), osNamespace("alive"),
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "alive", Name: "svc"}},
		&mwc.Items[0], &vwc.Items[0])
	snap := osSnap(cs, []string{"kube-system", "alive"}, mwc, vwc)

	if err := Sweep(ctx, snap); err != nil {
		t.Fatal(err)
	}
	// The SNAPSHOT itself — not just the tracker — must show the
	// post-patch view: SetMWC/SetVWC write the patched configs back.
	if got := osMutatingNames(snap, "cfg"); len(got) != 1 || got[0] != "keep.example.com" {
		t.Fatalf("snapshot MWC webhooks = %v, want [keep.example.com]", got)
	}
	var vnames []string
	for _, w := range snap.VWC.Items[0].Webhooks {
		vnames = append(vnames, w.Name)
	}
	if len(vnames) != 1 || vnames[0] != "v-keep.example.com" {
		t.Fatalf("snapshot VWC webhooks = %v, want [v-keep.example.com]", vnames)
	}
}

// A failed patch on the VALIDATING kind is aggregated into the run
// error exactly like the mutating path the facade tests cover — a
// swallowed failure would leave a fail-closed orphan forever.
func TestSweepValidatingPatchFailureReturnsError(t *testing.T) {
	vwc := &admissionv1.ValidatingWebhookConfigurationList{Items: []admissionv1.ValidatingWebhookConfiguration{{
		ObjectMeta: metav1.ObjectMeta{Name: "vcfg"},
		Webhooks: []admissionv1.ValidatingWebhook{
			osValidatingHook("orphan.example.com", osSvcRef("dead-ns", "svc")),
		},
	}}}
	cs := fake.NewSimpleClientset(osNamespace("kube-system"), &vwc.Items[0])
	cs.PrependReactor("patch", "validatingwebhookconfigurations",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})
	snap := osSnap(cs, []string{"kube-system"}, nil, vwc)

	if err := Sweep(ctx, snap); err == nil {
		t.Fatal("a failed validating webhook patch must surface as an error")
	}
}

// ---------------------------------------------------------------------------
// CRD conversion backends — warn only, the CRD itself is never touched
// ---------------------------------------------------------------------------

// osConversionCRD builds a CRD whose spec.conversion webhook targets
// Service ns/name — the warn-only fixture.
func osConversionCRD(name, svcNS, svcName string) unstructured.Unstructured {
	crd := testutil.Unstructured(
		kube.GVRCustomResourceDefinition.GroupVersion().
			WithKind("CustomResourceDefinition"), "", name, nil)
	_ = unstructured.SetNestedField(crd.Object, "Webhook",
		"spec", "conversion", "strategy")
	_ = unstructured.SetNestedMap(crd.Object,
		map[string]any{"namespace": svcNS, "name": svcName},
		"spec", "conversion", "webhook", "clientConfig", "service")
	return *crd
}

// A CRD whose conversion backend is broken (namespace gone, or the
// Service missing under a live namespace) is WARN-only: no entry to
// drop and deleting the CRD is catastrophic — the sweep returns nil
// and issues zero writes of any kind.
func TestSweepCRDConversionBackendWarnOnly(t *testing.T) {
	cs := fake.NewSimpleClientset(
		osNamespace("kube-system"), osNamespace("alive"))
	snap := osSnap(cs, []string{"kube-system", "alive"},
		&admissionv1.MutatingWebhookConfigurationList{},
		&admissionv1.ValidatingWebhookConfigurationList{})
	snap.CRDs = []unstructured.Unstructured{
		osConversionCRD("gone-ns.example.com", "dead-ns", "conv-svc"),
		osConversionCRD("missing-svc.example.com", "alive", "not-created"),
	}

	if err := Sweep(ctx, snap); err != nil {
		t.Fatalf("CRD conversion warn paths must not fail the sweep: %v", err)
	}
	// The sweep holds no client for CRDs at all — prove no write
	// touched the cluster: every action beyond the service census
	// list must be absent.
	for _, a := range cs.Actions() {
		if a.GetVerb() != "list" && a.GetVerb() != "get" {
			t.Fatalf("warn-only CRD path issued a write: %v", a)
		}
	}
}
