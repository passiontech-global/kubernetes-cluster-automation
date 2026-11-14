// webhooks_test.go — coverage for the shared webhook-config helpers:
// the circuit annotation parser, the fail-closed predicate, the
// injector-health verdict and the CRD conversion service key.
package guardstate

import (
	"context"
	"errors"
	"testing"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

func TestParseCircuitAnnotation(t *testing.T) {
	for _, tc := range []struct {
		name string
		v    string
		want []string
	}{
		{"empty", "", nil},
		{"single", "hook.example.com", []string{"hook.example.com"}},
		{"multiple with spaces", "a.example.com, b.example.com",
			[]string{"a.example.com", "b.example.com"}},
		{"trailing comma", "a.example.com,", []string{"a.example.com"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseCircuitAnnotation(tc.v)
			if len(got) != len(tc.want) {
				t.Fatalf("ParseCircuitAnnotation(%q) = %v, want %v", tc.v, got, tc.want)
			}
			for _, k := range tc.want {
				if !got[k] {
					t.Fatalf("ParseCircuitAnnotation(%q) missing %q: %v", tc.v, k, got)
				}
			}
		})
	}
}

func TestFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		fp   *admissionv1.FailurePolicyType
		want bool
	}{
		{"nil defaults to fail", nil, true},
		{"explicit Fail", new(admissionv1.Fail), true},
		{"Ignore fails open", new(admissionv1.Ignore), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := FailClosed(tc.fp); got != tc.want {
				t.Fatalf("FailClosed = %v, want %v", got, tc.want)
			}
		})
	}
}

// gsCRDWithConversion builds a bare unstructured CRD carrying the
// given spec.conversion block (nil → none).
func gsCRDWithConversion(conv any) *unstructured.Unstructured {
	o := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apiextensions.k8s.io/v1",
		"kind":       "CustomResourceDefinition",
		"metadata":   map[string]any{"name": "widgets.example.com"},
	}}
	if conv != nil {
		o.Object["spec"] = map[string]any{"conversion": conv}
	}
	return o
}

func TestCRDConversionServiceKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		crd  *unstructured.Unstructured
		key  string
		ok   bool
	}{
		{"no conversion block", gsCRDWithConversion(nil), "", false},
		{"none strategy", gsCRDWithConversion(map[string]any{"strategy": "None"}), "", false},
		{"webhook + service", gsCRDWithConversion(map[string]any{
			"strategy": "Webhook",
			"webhook": map[string]any{
				"clientConfig": map[string]any{
					"service": map[string]any{"namespace": "backend", "name": "conv-svc"},
				},
			},
		}), "backend/conv-svc", true},
		{"url backend", gsCRDWithConversion(map[string]any{
			"strategy": "Webhook",
			"webhook": map[string]any{
				"clientConfig": map[string]any{"url": "https://example.com:9443"},
			},
		}), "", false},
		{"service missing name", gsCRDWithConversion(map[string]any{
			"strategy": "Webhook",
			"webhook": map[string]any{
				"clientConfig": map[string]any{
					"service": map[string]any{"namespace": "backend"},
				},
			},
		}), "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, ns, name, ok := CRDConversionServiceKey(tc.crd)
			if ok != tc.ok || key != tc.key {
				t.Fatalf("CRDConversionServiceKey = (%q, %v), want (%q, %v)",
					key, ok, tc.key, tc.ok)
			}
			if ok && ns+"/"+name != key {
				t.Fatalf("CRDConversionServiceKey ns/name %q inconsistent with key %q",
					ns+"/"+name, key)
			}
		})
	}
}

// gsInjMWC builds a MWC list carrying one webhook with the given
// failure policy and circuit annotation value, targeting
// svcNS/svcName (both empty → no ServiceReference).
func gsInjMWC(hook string, fp *admissionv1.FailurePolicyType,
	svcNS, svcName, brokenAnno string) *admissionv1.MutatingWebhookConfigurationList {
	cc := admissionv1.WebhookClientConfig{}
	if svcNS != "" || svcName != "" {
		cc.Service = &admissionv1.ServiceReference{Namespace: svcNS, Name: svcName}
	}
	cfg := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "inj-mwc"},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          hook,
			FailurePolicy: fp,
			ClientConfig:  cc,
		}},
	}
	if brokenAnno != "" {
		cfg.Annotations = map[string]string{CircuitBrokenAnno: brokenAnno}
	}
	return &admissionv1.MutatingWebhookConfigurationList{
		Items: []admissionv1.MutatingWebhookConfiguration{*cfg}}
}

// gsInjSlice builds one ready endpoint bound to ns/svc, optionally
// pinned to nodeName ("" → no NodeName, the unattributable case).
func gsInjSlice(ns, svc, nodeName string) *discoveryv1.EndpointSlice {
	ep := discoveryv1.Endpoint{
		Addresses:  []string{"10.10.0.1"},
		Conditions: discoveryv1.EndpointConditions{Ready: new(true)},
	}
	if nodeName != "" {
		ep.NodeName = new(nodeName)
	}
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: svc + "-slice",
			Labels: map[string]string{discoveryv1.LabelServiceName: svc},
		},
		Endpoints: []discoveryv1.Endpoint{ep},
	}
}

func TestInjectorHealthy(t *testing.T) {
	responsive := func(context.Context, string, int32) bool { return true }
	hung := func(context.Context, string, int32) bool { return false }

	const hook = "linkerd-proxy-injector.linkerd.io"

	for _, tc := range []struct {
		name      string
		mwc       *admissionv1.MutatingWebhookConfigurationList
		prober    EndpointProber
		slices    []runtime.Object
		mwcErr    error
		nodesErr  error
		unhealthy map[string]bool
		want      bool
		wantErr   bool
	}{
		{"healthy, never probed", gsInjMWC(hook, nil, "linkerd", "injector", ""),
			responsive, []runtime.Object{gsInjSlice("linkerd", "injector", "")},
			nil, nil, nil, true, false},
		{"probed and responsive", gsInjMWC(hook, nil, "linkerd", "injector", ""),
			responsive, []runtime.Object{gsInjSlice("linkerd", "injector", "")},
			nil, nil, nil, true, false},
		{"probed and unresponsive", gsInjMWC(hook, nil, "linkerd", "injector", ""),
			hung, []runtime.Object{gsInjSlice("linkerd", "injector", "")},
			nil, nil, nil, false, false},
		{"circuit broken", gsInjMWC(hook, nil, "linkerd", "injector", hook),
			responsive, []runtime.Object{gsInjSlice("linkerd", "injector", "")},
			nil, nil, nil, false, false},
		{"failure policy ignore", gsInjMWC(hook, new(admissionv1.Ignore), "linkerd", "injector", ""),
			responsive, []runtime.Object{gsInjSlice("linkerd", "injector", "")},
			nil, nil, nil, false, false},
		{"endpoints only on unhealthy node", gsInjMWC(hook, nil, "linkerd", "injector", ""),
			responsive, []runtime.Object{gsInjSlice("linkerd", "injector", "bad-node")},
			nil, nil, map[string]bool{"bad-node": true}, false, false},
		{"lookalike name only", gsInjMWC("linkerd-proxy-injector.lookalike.io", nil, "linkerd", "injector", ""),
			responsive, []runtime.Object{gsInjSlice("linkerd", "injector", "")},
			nil, nil, nil, false, false},
		{"no service ref", gsInjMWC(hook, nil, "", "", ""),
			responsive, nil, nil, nil, nil, false, false},
		{"mwc list error", nil, responsive, nil,
			errors.New("mwc boom"), nil, nil, false, true},
		{"census error", gsInjMWC(hook, nil, "linkerd", "injector", ""),
			responsive, nil, nil, errors.New("nodes boom"), nil, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewSimpleClientset(tc.slices...)
			unhealthy := tc.unhealthy
			if unhealthy == nil {
				unhealthy = map[string]bool{}
			}
			snap := &Snapshot{
				G:              &Guard{CS: cs, EndpointProber: tc.prober},
				MWC:            tc.mwc,
				MWCErr:         tc.mwcErr,
				UnhealthyNodes: unhealthy,
				NodesErr:       tc.nodesErr,
			}
			got, err := InjectorHealthy(snap)
			if (err != nil) != tc.wantErr {
				t.Fatalf("InjectorHealthy err = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("InjectorHealthy = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestForEachWebhookConfig(t *testing.T) {
	fail := admissionv1.Fail
	ignore := admissionv1.Ignore
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "mwc-a",
			Annotations: map[string]string{CircuitBrokenAnno: "m.example.com"},
		},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          "m.example.com",
			FailurePolicy: &ignore,
			ClientConfig:  admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Namespace: "ns", Name: "svc"}},
		}},
	}
	vwc := &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "vwc-a"},
		Webhooks: []admissionv1.ValidatingWebhook{{
			Name:          "v.example.com",
			FailurePolicy: &fail,
		}},
	}
	cs := fake.NewSimpleClientset(mwc, vwc)
	snap := &Snapshot{
		G:   &Guard{CS: cs},
		MWC: &admissionv1.MutatingWebhookConfigurationList{Items: []admissionv1.MutatingWebhookConfiguration{*mwc}},
		VWC: &admissionv1.ValidatingWebhookConfigurationList{Items: []admissionv1.ValidatingWebhookConfiguration{*vwc}},
	}
	var seen []string
	snap.ForEachWebhookConfig(func(cfg WebhookConfigView) {
		seen = append(seen, cfg.Kind+"/"+cfg.Resource+"/"+cfg.Name+"/"+cfg.Hooks[0].Name)
	})
	want := []string{
		KindMutating + "/mutatingwebhookconfigurations/mwc-a/m.example.com",
		KindValidating + "/validatingwebhookconfigurations/vwc-a/v.example.com",
	}
	if len(seen) != len(want) || seen[0] != want[0] || seen[1] != want[1] {
		t.Fatalf("ForEachWebhookConfig saw %v, want %v", seen, want)
	}
}
