// webhook_ca_audit_test.go — coverage for the injection-source CA
// lookup (secretCA): the ca.crt/tls.crt key fallback cainjector
// reads, and the routine-vs-real failure split (NotFound is quiet,
// any other Get failure is logged — both read "no CA").
package certdriftauditor

import (
	"context"
	"errors"
	"testing"
	"time"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ca.crt is where cainjector reads the bundle; tls.crt is the
// fallback for secrets carrying only the leaf pair. A secret with
// neither yields no CA, and any Get failure — NotFound included —
// resolves the lookup as "no CA" rather than an error.
func TestSecretCAResolution(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name    string
		secret  *corev1.Secret
		listErr bool
		wantCA  []byte
		wantOK  bool
	}{
		{"ca.crt wins", &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "s"},
			Data: map[string][]byte{
				"ca.crt": []byte("CA"), "tls.crt": []byte("LEAF")},
		}, false, []byte("CA"), true},
		{"tls.crt is the leaf-pair fallback", &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "s"},
			Data:       map[string][]byte{"tls.crt": []byte("LEAF")},
		}, false, []byte("LEAF"), true},
		{"no ca keys is no CA", &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "s"},
			Data:       map[string][]byte{"other": []byte("x")},
		}, false, nil, false},
		{"missing secret is routine", nil, false, nil, false},
		{"get failure is no CA too", nil, true, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var objs []runtime.Object
			if tc.secret != nil {
				objs = append(objs, tc.secret)
			}
			cs := fake.NewSimpleClientset(objs...)
			if tc.listErr {
				cs.PrependReactor("get", "secrets",
					func(ktesting.Action) (bool, runtime.Object, error) {
						return true, nil, errors.New("api down")
					})
			}
			a := newCertDriftAuditor(cs, nil, now)
			ca, ok := a.secretCA(ctx, "ns", "s",
				"MutatingWebhookConfiguration", "cfg")
			if ok != tc.wantOK || string(ca) != string(tc.wantCA) {
				t.Fatalf("secretCA = (%q,%v), want (%q,%v)",
					ca, ok, tc.wantCA, tc.wantOK)
			}
		})
	}
}

type fakeCRDReader struct {
	items []apiextensionsv1.CustomResourceDefinition
	err   error
	calls int
}

func (f *fakeCRDReader) List(_ context.Context, list client.ObjectList, _ ...client.ListOption) error {
	f.calls++
	if f.err != nil {
		return f.err
	}
	if crds, ok := list.(*apiextensionsv1.CustomResourceDefinitionList); ok {
		crds.Items = append([]apiextensionsv1.CustomResourceDefinition(nil), f.items...)
	}
	return nil
}

type clientStubManager struct {
	*testutil.StubManager
	cli client.Client
}

func (m *clientStubManager) GetClient() client.Client { return m.cli }

type crdListSpyClient struct {
	client.Client
	crdListCalls int
}

func (c *crdListSpyClient) List(_ context.Context, list client.ObjectList, _ ...client.ListOption) error {
	if _, ok := list.(*apiextensionsv1.CustomResourceDefinitionList); ok {
		c.crdListCalls++
	}
	return nil
}

func TestCertDriftAuditorCRDInformerReuse(t *testing.T) {
	now := time.Now()
	caPEM := makeCertPEM(t, now.Add(60*24*time.Hour))
	port := int32(8443)
	typedCRD := apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "widgets.example.io",
			Annotations: map[string]string{injectCAFromSecretAnno: "apps/ca-sec"},
		},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Conversion: &apiextensionsv1.CustomResourceConversion{
				Strategy: apiextensionsv1.WebhookConverter,
				Webhook: &apiextensionsv1.WebhookConversion{
					ClientConfig: &apiextensionsv1.WebhookClientConfig{
						CABundle: []byte("stale-ca"),
						Service: &apiextensionsv1.ServiceReference{
							Namespace: "apps", Name: "conv-svc", Port: &port,
						},
					},
				},
			},
		},
	}

	t.Run("CRDInformerEnabled true uses nodeReader with 0 dynamic CRD lists", func(t *testing.T) {
		defer kube.SetCRDInformerEnabled(true)
		kube.SetCRDInformerEnabled(true)
		metrics.WebhookCABundleMismatch.Reset()

		cs := fake.NewSimpleClientset(caSecret("apps", "ca-sec", "ca.crt", caPEM))
		dyn := cdaDyn()
		var dynCRDLists int
		dyn.PrependReactor("list", "customresourcedefinitions", func(ktesting.Action) (bool, runtime.Object, error) {
			dynCRDLists++
			return false, nil, nil
		})
		reader := &fakeCRDReader{items: []apiextensionsv1.CustomResourceDefinition{typedCRD}}
		a := newCertDriftAuditor(cs, dyn, now)
		a.nodeReader = reader

		if err := a.auditWebhookCABundles(ctx); err != nil {
			t.Fatalf("auditWebhookCABundles: %v", err)
		}
		if reader.calls != 1 {
			t.Fatalf("nodeReader.List calls = %d, want 1", reader.calls)
		}
		if dynCRDLists != 0 {
			t.Fatalf("dynamic CRD lists = %d, want 0", dynCRDLists)
		}
		if got := promtestutil.ToFloat64(metrics.WebhookCABundleMismatch.WithLabelValues(
			"CustomResourceDefinition", "widgets.example.io", "conversion")); got != 1 {
			t.Fatalf("CRD mismatch gauge = %v, want 1", got)
		}
		if gotPort, ok := a.liveRunCRDRefs["apps/conv-svc"]; !ok || gotPort != 8443 {
			t.Fatalf("liveRunCRDRefs = %v, want apps/conv-svc:8443", a.liveRunCRDRefs)
		}

		// collectReferencedTLSServices with warm cache hits neither reader nor dyn.
		refs, err := a.collectReferencedTLSServices(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if refs["apps/conv-svc"] != 8443 || reader.calls != 1 || dynCRDLists != 0 {
			t.Fatalf("warm cache check: refs=%v calls=%d dynLists=%d", refs, reader.calls, dynCRDLists)
		}

		// collectReferencedTLSServices standalone (cold cache) uses nodeReader with 0 dyn lists.
		a.liveRunCRDRefsSet = false
		a.liveRunCRDRefs = nil
		refs2, err := a.collectReferencedTLSServices(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if refs2["apps/conv-svc"] != 8443 || reader.calls != 2 || dynCRDLists != 0 {
			t.Fatalf("cold cache check: refs=%v calls=%d dynLists=%d", refs2, reader.calls, dynCRDLists)
		}
	})

	t.Run("CRDInformerEnabled false skips nodeReader and falls back to dyn", func(t *testing.T) {
		defer kube.SetCRDInformerEnabled(true)
		kube.SetCRDInformerEnabled(false)

		cs := fake.NewSimpleClientset()
		dyn := cdaDyn()
		var dynCRDLists int
		dyn.PrependReactor("list", "customresourcedefinitions", func(ktesting.Action) (bool, runtime.Object, error) {
			dynCRDLists++
			return false, nil, nil
		})
		reader := &fakeCRDReader{items: []apiextensionsv1.CustomResourceDefinition{typedCRD}}
		a := newCertDriftAuditor(cs, dyn, now)
		a.nodeReader = reader

		if err := a.auditWebhookCABundles(ctx); err != nil {
			t.Fatalf("auditWebhookCABundles: %v", err)
		}
		if reader.calls != 0 {
			t.Fatalf("nodeReader.List calls = %d, want 0 when CRD informer disabled", reader.calls)
		}
		if dynCRDLists != 1 {
			t.Fatalf("dynamic CRD lists = %d, want 1 fallback", dynCRDLists)
		}
	})

	t.Run("nodeReader.List error falls back to dyn", func(t *testing.T) {
		defer kube.SetCRDInformerEnabled(true)
		kube.SetCRDInformerEnabled(true)

		cs := fake.NewSimpleClientset()
		dyn := cdaDyn()
		var dynCRDLists int
		dyn.PrependReactor("list", "customresourcedefinitions", func(ktesting.Action) (bool, runtime.Object, error) {
			dynCRDLists++
			return false, nil, nil
		})
		reader := &fakeCRDReader{err: errors.New("cache not synced")}
		a := newCertDriftAuditor(cs, dyn, now)
		a.nodeReader = reader

		if err := a.auditWebhookCABundles(ctx); err != nil {
			t.Fatalf("auditWebhookCABundles: %v", err)
		}
		if reader.calls != 1 {
			t.Fatalf("nodeReader.List calls = %d, want 1", reader.calls)
		}
		if dynCRDLists != 1 {
			t.Fatalf("dynamic CRD lists = %d, want 1 fallback", dynCRDLists)
		}
	})
}

func TestSetupWiresNodeReader(t *testing.T) {
	defer kube.SetCRDInformerEnabled(true)
	kube.SetCRDInformerEnabled(true)

	spy := &crdListSpyClient{}
	mgr := &clientStubManager{StubManager: testutil.NewStubManager(), cli: spy}
	err := Setup(shared.Deps{
		Name: "cert-drift-auditor",
		Mgr:  mgr,
		CS:   fake.NewSimpleClientset(),
		Dyn:  cdaDyn(),
	})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if len(mgr.Added) != 1 {
		t.Fatalf("Added runnables = %d, want 1", len(mgr.Added))
	}
	p, ok := mgr.Added[0].(*shared.Periodic)
	if !ok {
		t.Fatalf("Added[0] = %T, want *shared.Periodic", mgr.Added[0])
	}
	if err := p.Fn(ctx); err != nil {
		t.Fatalf("periodic Fn: %v", err)
	}
	if spy.crdListCalls != 1 {
		t.Fatalf("manager client CRD list calls = %d, want 1 (nodeReader wired by Setup)", spy.crdListCalls)
	}
}
