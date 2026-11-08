// census_probe_test.go — coverage for the W9-CP1 census/probe plumbing:
// the ready-endpoint census, the webhook backend probe set, the
// slice-port preference, the probe-candidate collector and the
// production TCP+TLS prober.
package guardstate

import (
	"context"
	"fmt"
	"net"
	"net/http/httptest"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
)

func TestReadyEndpointCounts(t *testing.T) {
	up, down := true, false
	svcSlice := func(ns, svc string, eps ...discoveryv1.Endpoint) *discoveryv1.EndpointSlice {
		return &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: ns, Name: svc + "-slice",
				Labels: map[string]string{discoveryv1.LabelServiceName: svc},
			},
			Endpoints: eps,
		}
	}
	nodeName := func(n string) *string { return new(n) }

	tests := []struct {
		name       string
		nodesErr   error
		unhealthy  map[string]bool
		slices     []*discoveryv1.EndpointSlice
		prober     EndpointProber
		raw        map[string]int
		effective  map[string]int
		responsive map[string]bool
	}{
		{
			name:      "raw vs effective with node discount",
			unhealthy: map[string]bool{"bad-node": true},
			slices: []*discoveryv1.EndpointSlice{svcSlice("ns", "svc",
				discoveryv1.Endpoint{Addresses: []string{"10.0.0.1"},
					Conditions: discoveryv1.EndpointConditions{Ready: &up}},
				discoveryv1.Endpoint{Addresses: []string{"10.0.0.2"}, NodeName: nodeName("bad-node"),
					Conditions: discoveryv1.EndpointConditions{Ready: &up}},
				discoveryv1.Endpoint{Addresses: []string{"10.0.0.3"},
					Conditions: discoveryv1.EndpointConditions{Ready: &down}},
			)},
			raw:       map[string]int{"ns/svc": 2},
			effective: map[string]int{"ns/svc": 1},
		},
		{
			name: "nil ready counts as ready and probed responsive",
			slices: []*discoveryv1.EndpointSlice{svcSlice("ns", "svc",
				discoveryv1.Endpoint{Addresses: []string{"10.0.0.1"}})},
			prober:     func(context.Context, string, int32) bool { return true },
			raw:        map[string]int{"ns/svc": 1},
			effective:  map[string]int{"ns/svc": 1},
			responsive: map[string]bool{"ns/svc": true},
		},
		{
			name: "no service label skipped",
			slices: []*discoveryv1.EndpointSlice{{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "orphan"},
				Endpoints: []discoveryv1.Endpoint{{
					Addresses:  []string{"10.0.0.1"},
					Conditions: discoveryv1.EndpointConditions{Ready: &up},
				}},
			}},
			raw: map[string]int{}, effective: map[string]int{},
		},
		{
			name:     "nodes error skips census",
			nodesErr: fmt.Errorf("boom"),
			raw:      map[string]int{}, effective: map[string]int{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.prober == nil {
				tc.prober = func(context.Context, string, int32) bool { return false }
			}
			ro := make([]runtime.Object, 0, len(tc.slices))
			for _, s := range tc.slices {
				ro = append(ro, s)
			}
			g := &Guard{CS: fake.NewSimpleClientset(ro...), EndpointProber: tc.prober}
			snap := &Snapshot{
				G:              g,
				MWC:            gsInjMWC("hook.example.com", nil, "ns", "svc", ""),
				VWC:            &admissionv1.ValidatingWebhookConfigurationList{},
				UnhealthyNodes: tc.unhealthy,
				NodesErr:       tc.nodesErr,
			}
			if snap.UnhealthyNodes == nil {
				snap.UnhealthyNodes = map[string]bool{}
			}
			got, err := g.readyEndpointCounts(context.Background(), snap)
			if tc.nodesErr != nil {
				if err == nil {
					t.Fatal("expected nodes error to skip the census")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !gsMapsEqual(got.Raw, tc.raw) || !gsMapsEqual(got.Effective, tc.effective) {
				t.Fatalf("raw/effective = %v/%v, want %v/%v", got.Raw, got.Effective, tc.raw, tc.effective)
			}
			for k, want := range tc.responsive {
				if got.Responsive[k] != want {
					t.Fatalf("Responsive[%q] = %v, want %v", k, got.Responsive[k], want)
				}
			}
		})
	}
}

func gsMapsEqual(got, want map[string]int) bool {
	if len(got) != len(want) {
		return false
	}
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}

func TestWebhookBackendServices(t *testing.T) {
	svcRef := func(ns, name string, port *int32) *admissionv1.ServiceReference {
		return &admissionv1.ServiceReference{Namespace: ns, Name: name, Port: port}
	}
	mwc := &admissionv1.MutatingWebhookConfigurationList{Items: []admissionv1.MutatingWebhookConfiguration{{
		ObjectMeta: metav1.ObjectMeta{Name: "mwc"},
		Webhooks: []admissionv1.MutatingWebhook{
			{Name: "a", ClientConfig: admissionv1.WebhookClientConfig{Service: svcRef("ns", "a", nil)}},
			{Name: "b", ClientConfig: admissionv1.WebhookClientConfig{Service: svcRef("ns", "b", new(int32(9443)))}},
			// Empty ServiceReference and URL backends contribute nothing.
			{Name: "c", ClientConfig: admissionv1.WebhookClientConfig{Service: svcRef("", "x", nil)}},
			{Name: "d", ClientConfig: admissionv1.WebhookClientConfig{URL: new("https://x/y")}},
		},
	}}}
	vwc := &admissionv1.ValidatingWebhookConfigurationList{Items: []admissionv1.ValidatingWebhookConfiguration{{
		ObjectMeta: metav1.ObjectMeta{Name: "vwc"},
		Webhooks: []admissionv1.ValidatingWebhook{
			// Same Service as the mutating default — port set dedupes to 443 once.
			{Name: "e", ClientConfig: admissionv1.WebhookClientConfig{Service: svcRef("ns", "a", new(int32(443)))}},
		},
	}}}
	crd := gsCRDWithConversion(map[string]any{
		"strategy": "Webhook",
		"webhook": map[string]any{"clientConfig": map[string]any{
			"service": map[string]any{"namespace": "crdns", "name": "conv", "port": int64(8443)},
		}},
	})
	urlCRD := gsCRDWithConversion(map[string]any{
		"strategy": "Webhook",
		"webhook": map[string]any{"clientConfig": map[string]any{
			"url": "https://example.com:9443",
		}},
	})
	snap := &Snapshot{MWC: mwc, VWC: vwc, CRDs: []unstructured.Unstructured{*crd, *urlCRD}}
	got := webhookBackendServices(snap)
	want := map[string][]int32{"ns/a": {443}, "ns/b": {9443}, "crdns/conv": {8443}}
	if len(got) != len(want) {
		t.Fatalf("webhookBackendServices = %v, want %v", got, want)
	}
	for k, ports := range want {
		if len(got[k]) != len(ports) || got[k][0] != ports[0] {
			t.Fatalf("webhookBackendServices[%q] = %v, want %v", k, got[k], ports)
		}
	}
	// Nil config lists contribute nothing.
	if got := webhookBackendServices(&Snapshot{}); len(got) != 0 {
		t.Fatalf("empty snapshot probe set = %v, want empty", got)
	}
}

func TestResolveSlicePortPref(t *testing.T) {
	svc := func(name string, ports ...corev1.ServicePort) *corev1.Service {
		return &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: name},
			Spec:       corev1.ServiceSpec{Ports: ports},
		}
	}
	cs := fake.NewSimpleClientset(
		svc("webhook",
			corev1.ServicePort{Name: "Webhook", Port: 8443, TargetPort: intstr.FromInt32(9443)},
			corev1.ServicePort{Name: "metrics", Port: 9090, TargetPort: intstr.FromInt32(9090)}),
		svc("str", corev1.ServicePort{Port: 8443, TargetPort: intstr.FromString("tls-svc")}),
	)
	pref := resolveSlicePortPref(context.Background(), cs, "ns/webhook", []int32{8443})
	if !pref.names["https"] || !pref.names["webhook"] || !pref.names["tls"] {
		t.Fatalf("conventional names missing: %v", pref.names)
	}
	if !pref.names["webhook"] || !pref.numbers[9443] {
		t.Fatalf("declared port mapping missing: names=%v numbers=%v", pref.names, pref.numbers)
	}
	if pref.numbers[9090] {
		t.Fatalf("undeclared port leaked into pref: names=%v numbers=%v", pref.names, pref.numbers)
	}
	// String targetPort resolves to a name.
	pref = resolveSlicePortPref(context.Background(), cs, "ns/str", []int32{8443})
	if !pref.names["tls-svc"] {
		t.Fatalf("string targetPort not resolved into names: %v", pref.names)
	}
	// Unresolvable Service degrades to name matching alone.
	pref = resolveSlicePortPref(context.Background(), cs, "ns/missing", []int32{8443})
	if len(pref.numbers) != 0 || len(pref.names) != len(webhookPortNames) {
		t.Fatalf("unresolvable service pref = %v/%v, want names-only", pref.names, pref.numbers)
	}
}

func TestPickSlicePort(t *testing.T) {
	p := func(port int32, name string) discoveryv1.EndpointPort {
		ep := discoveryv1.EndpointPort{Port: new(port)}
		if name != "" {
			ep.Name = new(name)
		}
		return ep
	}
	pref := slicePortPref{
		names:   map[string]bool{"https": true, "webhook": true, "tls": true, "webhook-svc": true},
		numbers: map[int32]bool{9443: true},
	}
	for _, tc := range []struct {
		name  string
		ports []discoveryv1.EndpointPort
		want  int32
	}{
		{"named https wins", []discoveryv1.EndpointPort{p(9090, "metrics"), p(9443, "https")}, 9443},
		{"resolved service name wins", []discoveryv1.EndpointPort{p(9090, "metrics"), p(9444, "Webhook-Svc")}, 9444},
		{"resolved targetPort wins", []discoveryv1.EndpointPort{p(9090, "metrics"), p(9443, "")}, 9443},
		{"first port fallback", []discoveryv1.EndpointPort{p(8080, "sidecar"), p(9090, "metrics")}, 8080},
		{"nil first port falls to default 443", []discoveryv1.EndpointPort{{Port: nil}, p(9090, "metrics")}, 443},
		{"empty ports default 443", nil, 443},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := pickSlicePort(&discoveryv1.EndpointSlice{Ports: tc.ports}, pref); got != tc.want {
				t.Fatalf("pickSlicePort = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestCollectProbeCandidates(t *testing.T) {
	up := true
	port9443 := int32(9443)
	namePtr := new("https")
	s := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns"},
		Ports:      []discoveryv1.EndpointPort{{Port: new(port9443), Name: namePtr}},
	}
	pref := slicePortPref{
		names:   map[string]bool{"https": true},
		numbers: map[int32]bool{},
	}
	ready := &EndpointCensus{
		ProbeIPs:    map[string][]string{},
		ProbePort:   map[string]int32{},
		BackingPods: map[string][]PodRef{},
	}
	for i := range probeMaxPerSvc + 2 {
		addr := fmt.Sprintf("10.0.0.%d", i+1)
		collectProbeCandidates(ready, "ns/svc", s, &discoveryv1.Endpoint{
			Addresses:  []string{addr, addr}, // duplicate within one endpoint
			Conditions: discoveryv1.EndpointConditions{Ready: &up},
			TargetRef:  &corev1.ObjectReference{Kind: "Pod", Name: "pod-" + addr},
		}, pref)
	}
	if len(ready.ProbeIPs["ns/svc"]) != probeMaxPerSvc {
		t.Fatalf("ProbeIPs capped at %d, got %v", probeMaxPerSvc, ready.ProbeIPs["ns/svc"])
	}
	if ready.ProbePort["ns/svc"] != 9443 {
		t.Fatalf("ProbePort = %d, want 9443", ready.ProbePort["ns/svc"])
	}
	if len(ready.BackingPods["ns/svc"]) != probeMaxPerSvc+2 {
		t.Fatalf("BackingPods = %v, want %d refs", ready.BackingPods["ns/svc"], probeMaxPerSvc+2)
	}
	for _, r := range ready.BackingPods["ns/svc"] {
		if r.Namespace != "ns" {
			t.Fatalf("pod ref namespace = %q, want slice-local default %q", r.Namespace, "ns")
		}
	}
	// Non-Pod targetRef carries no backing pod.
	collectProbeCandidates(ready, "ns/other", s, &discoveryv1.Endpoint{
		Addresses: []string{"10.9.9.9"},
		TargetRef: &corev1.ObjectReference{Kind: "Node", Name: "n1"},
	}, pref)
	if len(ready.BackingPods["ns/other"]) != 0 {
		t.Fatalf("non-pod targetRef recorded: %v", ready.BackingPods["ns/other"])
	}
}

func TestTCPTLSEndpointProber(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	var port int32
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatal(err)
	}
	if !tcpTLSEndpointProber(context.Background(), host, port) {
		t.Fatal("probe against a live TLS server must succeed")
	}
	// Nothing listening on the port — probe fails fast.
	if tcpTLSEndpointProber(context.Background(), "127.0.0.1", 1) {
		t.Fatal("probe against a closed port must fail")
	}
	// Cancelled context short-circuits.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if tcpTLSEndpointProber(ctx, host, port) {
		t.Fatal("probe with cancelled context must fail")
	}
}
