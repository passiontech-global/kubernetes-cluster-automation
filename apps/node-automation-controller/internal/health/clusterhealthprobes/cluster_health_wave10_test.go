// cluster_health_wave10_test.go — coverage for the nine Wave-10
// checks in cluster_health_wave10.go (W10-NM1/NM3/NM5/NM6, W10-CP1,
// W10-CP6, W10-ST3, W10-ST4, W10-GI5). Helpers are w10-prefixed —
// the wave10 prefix is already claimed by
// cluster_health_wave10_edits_test.go.
package clusterhealthprobes

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// Builders + seams (w10-prefixed)
// ---------------------------------------------------------------------------

// w10Sample is one Prometheus instant-vector sample for the fake
// query API.
type w10Sample struct {
	labels map[string]string
	value  float64
}

// w10PromBody renders a Prometheus /api/v1/query vector response.
func w10PromBody(samples []w10Sample) string {
	var b strings.Builder
	b.WriteString(`{"status":"success","data":{"resultType":"vector","result":[`)
	for i, s := range samples {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"metric":{`)
		first := true
		for k, v := range s.labels {
			if !first {
				b.WriteString(",")
			}
			first = false
			fmt.Fprintf(&b, "%q:%q", k, v)
		}
		b.WriteString(`},"value":[1,"` +
			strconv.FormatFloat(s.value, 'f', -1, 64) + `"]}`)
	}
	b.WriteString(`]}}`)
	return b.String()
}

// w10PromSrv serves w10PromBody(respond(query)) at /api/v1/query and
// returns the server plus the last query string seen (for assertion).
func w10PromSrv(t *testing.T, respond func(query string) []w10Sample) (*httptest.Server, *string) {
	t.Helper()
	var lastQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		lastQuery = r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, w10PromBody(respond(lastQuery)))
	}))
	t.Cleanup(srv.Close)
	return srv, &lastQuery
}

// w10Pod builds a pod with explicit phase, readiness and age.
func w10Pod(ns, name string, phase corev1.PodPhase, ready bool, age time.Duration) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         ns,
			Name:              name,
			CreationTimestamp: metav1.NewTime(time.Now().Add(-age)),
			UID:               types.UID("uid-" + ns + "-" + name),
		},
		Status: corev1.PodStatus{Phase: phase},
	}
	if ready {
		p.Status.Conditions = []corev1.PodCondition{{
			Type:   corev1.PodReady,
			Status: corev1.ConditionTrue,
		}}
	} else {
		p.Status.Conditions = []corev1.PodCondition{{
			Type:               corev1.PodReady,
			Status:             corev1.ConditionFalse,
			LastTransitionTime: metav1.NewTime(time.Now().Add(-age)),
		}}
	}
	return p
}

// w10LinkerdPod builds a Running meshed pod exposing the given
// container ports, optionally carrying linkerd port annotations.
func w10LinkerdPod(ns, name string, ports []int32, opaque, skip string) *corev1.Pod {
	pod := w10Pod(ns, name, corev1.PodRunning, true, time.Hour)
	containers := []corev1.Container{{Name: "app"}}
	for _, port := range ports {
		containers[0].Ports = append(containers[0].Ports, corev1.ContainerPort{
			ContainerPort: port,
			Protocol:      corev1.ProtocolTCP,
		})
	}
	containers = append(containers, corev1.Container{Name: "linkerd-proxy"})
	pod.Spec.Containers = containers
	pod.Annotations = map[string]string{}
	if opaque != "" {
		pod.Annotations["config.linkerd.io/opaque-ports"] = opaque
	}
	if skip != "" {
		pod.Annotations["config.linkerd.io/skip-inbound-ports"] = skip
	}
	return pod
}

// w10OwnerSTS gives the pod a controller ownerRef to a StatefulSet —
// the realistic shape for stateful meshed workloads.
func w10OwnerSTS(pod *corev1.Pod, stsName string) {
	pod.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: "apps/v1",
		Kind:       "StatefulSet",
		Name:       stsName,
		Controller: ptr.To(true),
	}}
}

// w10STSObj builds a bare StatefulSet with an empty pod template —
// the heal target for the linkerd opaque-ports patch.
func w10STSObj(ns, name string) *appsv1.StatefulSet {
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: appsv1.StatefulSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": name}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
			},
		},
	}
}

// w10Deployment builds a bare Deployment — the live-owner fixture
// for the finalizer-sweep tests.
func w10Deployment(ns, name string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
	}
}

// w10App builds an ArgoCD Application unstructured carrying the
// given health status and conditions.
func w10App(ns, name, health string, conds ...map[string]any) *unstructured.Unstructured {
	obj := map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Application",
		"metadata":   map[string]any{"namespace": ns, "name": name},
	}
	if health != "" {
		obj["status"] = map[string]any{
			"health": map[string]any{"status": health},
		}
	}
	if len(conds) > 0 {
		status, _ := obj["status"].(map[string]any)
		if status == nil {
			status = map[string]any{}
			obj["status"] = status
		}
		var list []any
		for _, c := range conds {
			list = append(list, c)
		}
		status["conditions"] = list
	}
	return &unstructured.Unstructured{Object: obj}
}

// ---------------------------------------------------------------------------
// W10-NM1 — cilium-bpf-map-pressure
// ---------------------------------------------------------------------------

func TestWave10CiliumBPFMapPressureFailsAboveThreshold(t *testing.T) {
	srv, lastQuery := w10PromSrv(t, func(query string) []w10Sample {
		return []w10Sample{{
			labels: map[string]string{"node": "w1", "map_name": "ct4_global"},
			value:  0.92,
		}}
	})
	p := testProber(fake.NewSimpleClientset())
	p.cfg.httpURL = srv.URL
	p.httpClient = srv.Client()
	res := p.checkCiliumBPFMapPressure(ctx)
	if res.pass {
		t.Fatalf("expected FAIL above threshold, got %+v", res)
	}
	if !strings.Contains(res.why, "ct4_global") || !strings.Contains(res.why, "w1") {
		t.Fatalf("why missing node/map diagnostics: %q", res.why)
	}
	if !strings.Contains(*lastQuery, "cilium_bpf_map_pressure") ||
		!strings.Contains(*lastQuery, "0.85") {
		t.Fatalf("query = %q, want cilium_bpf_map_pressure > 0.85", *lastQuery)
	}
	if m := findMetric(t, "node_automation_cilium_bpf_map_pressure",
		map[string]string{"node": "w1", "map_name": "ct4_global"}); m == nil ||
		m.GetGauge().GetValue() != 0.92 {
		t.Fatalf("gauge missing/wrong: %+v", m)
	}
}

func TestWave10CiliumBPFMapPressureEmptyPasses(t *testing.T) {
	srv, _ := w10PromSrv(t, func(string) []w10Sample { return nil })
	p := testProber(fake.NewSimpleClientset())
	p.cfg.httpURL = srv.URL
	p.httpClient = srv.Client()
	if res := p.checkCiliumBPFMapPressure(ctx); !res.pass {
		t.Fatalf("empty result must pass: %+v", res)
	}
}

func TestWave10CiliumBPFMapPressurePromDownInconclusive(t *testing.T) {
	p := testProber(fake.NewSimpleClientset()) // httpURL is dead by default
	if res := p.checkCiliumBPFMapPressure(ctx); !res.pass {
		t.Fatalf("prometheus outage must be inconclusive-pass, got %+v", res)
	}
}

// ---------------------------------------------------------------------------
// W10-NM3 — linkerd-protocol-detection-stall
// ---------------------------------------------------------------------------

func TestWave10LinkerdOpaquePortsHealPatchesTemplateAndDeletesPod(t *testing.T) {
	sts := w10STSObj("apps", "cache")
	pod := w10LinkerdPod("apps", "cache-0", []int32{6379, 8080}, "", "")
	w10OwnerSTS(pod, "cache")
	cs := fake.NewSimpleClientset(sts, pod)
	p := testProber(cs)

	res := p.checkLinkerdProtocolDetectionStall(ctx)
	if res.pass {
		t.Fatalf("unannotated binary port must fail: %+v", res)
	}
	if !strings.Contains(res.why, "6379") {
		t.Fatalf("why missing port diagnostics: %q", res.why)
	}
	got, err := cs.AppsV1().StatefulSets("apps").Get(ctx, "cache", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Spec.Template.Annotations["config.linkerd.io/opaque-ports"] != "6379" {
		t.Fatalf("template opaque-ports = %q, want 6379",
			got.Spec.Template.Annotations["config.linkerd.io/opaque-ports"])
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "cache-0", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("pod should be deleted after template patch, err=%v", err)
	}
	if m := findMetric(t, "node_automation_linkerd_opaque_port_missing",
		map[string]string{"namespace": "apps", "pod": "cache-0", "port": "6379"}); m == nil {
		t.Fatal("opaque-port-missing gauge absent")
	}
}

func TestWave10LinkerdOpaquePortsAnnotatedPasses(t *testing.T) {
	pod := w10LinkerdPod("apps", "cache-0", []int32{6379}, "6379", "")
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	if res := p.checkLinkerdProtocolDetectionStall(ctx); !res.pass {
		t.Fatalf("annotated port must pass: %+v", res)
	}
}

func TestWave10LinkerdSkipInboundCoversPort(t *testing.T) {
	pod := w10LinkerdPod("apps", "cache-0", []int32{6379}, "", "6379")
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	if res := p.checkLinkerdProtocolDetectionStall(ctx); !res.pass {
		t.Fatalf("skip-inbound-ports must cover the port: %+v", res)
	}
}

func TestWave10LinkerdNonBinaryPortPasses(t *testing.T) {
	pod := w10LinkerdPod("apps", "web-0", []int32{8080, 9090}, "", "")
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	if res := p.checkLinkerdProtocolDetectionStall(ctx); !res.pass {
		t.Fatalf("non-binary ports must pass: %+v", res)
	}
}

func TestWave10ParsePortSetRanges(t *testing.T) {
	got := wave10ParsePortSet("6379, 8000-8002")
	for _, want := range []int{6379, 8000, 8001, 8002} {
		if !got[want] {
			t.Fatalf("port %d missing from %v", want, got)
		}
	}
	if len(got) != 4 {
		t.Fatalf("unexpected ports: %v", got)
	}
}

// ---------------------------------------------------------------------------
// W10-NM5 — coredns-upstream
// ---------------------------------------------------------------------------

// w10CoreDNSSrv answers the two coredns queries: the healthcheck
// query reports pod "bad" failing; the SERVFAIL query reports none.
func w10CoreDNSSrv(t *testing.T) *httptest.Server {
	t.Helper()
	srv, _ := w10PromSrv(t, func(query string) []w10Sample {
		if strings.Contains(query, "ForwardHealthcheckFailureCount") {
			return []w10Sample{{
				labels: map[string]string{"pod": "coredns-bad", "namespace": "kube-system"},
				value:  1.4,
			}}
		}
		return nil
	})
	return srv
}

func TestWave10CoreDNSUpstreamDeletesIsolatedFailingPod(t *testing.T) {
	srv := w10CoreDNSSrv(t)
	bad := w10Pod("kube-system", "coredns-bad", corev1.PodRunning, false, time.Hour)
	good := w10Pod("kube-system", "coredns-good", corev1.PodRunning, true, time.Hour)
	cs := fake.NewSimpleClientset(bad, good)
	p := testProber(cs)
	p.cfg.httpURL = srv.URL
	p.httpClient = srv.Client()

	res := p.checkCoreDNSUpstream(ctx)
	if res.pass {
		t.Fatalf("isolated upstream failure must fail: %+v", res)
	}
	if !strings.Contains(res.why, "coredns-bad") {
		t.Fatalf("why missing pod: %q", res.why)
	}
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, "coredns-bad", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("isolated failing pod should be deleted, err=%v", err)
	}
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, "coredns-good", metav1.GetOptions{}); err != nil {
		t.Fatalf("healthy sibling must survive: %v", err)
	}
}

func TestWave10CoreDNSUpstreamFleetWideDoesNotDelete(t *testing.T) {
	// Both dns pods flagged -> no healthy sibling -> detection only.
	srv, _ := w10PromSrv(t, func(query string) []w10Sample {
		if strings.Contains(query, "ForwardHealthcheckFailureCount") {
			return []w10Sample{
				{labels: map[string]string{"pod": "coredns-a", "namespace": "kube-system"}, value: 1},
				{labels: map[string]string{"pod": "coredns-b", "namespace": "kube-system"}, value: 1},
			}
		}
		return nil
	})
	a := w10Pod("kube-system", "coredns-a", corev1.PodRunning, true, time.Hour)
	b := w10Pod("kube-system", "coredns-b", corev1.PodRunning, true, time.Hour)
	cs := fake.NewSimpleClientset(a, b)
	p := testProber(cs)
	p.cfg.httpURL = srv.URL
	p.httpClient = srv.Client()

	res := p.checkCoreDNSUpstream(ctx)
	if res.pass {
		t.Fatalf("fleet-wide failure must fail: %+v", res)
	}
	for _, name := range []string{"coredns-a", "coredns-b"} {
		if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, name, metav1.GetOptions{}); err != nil {
			t.Fatalf("fleet-wide failure must not delete %s: %v", name, err)
		}
	}
}

func TestWave10CoreDNSFallbackUnreadyPod(t *testing.T) {
	// Prometheus dead -> readiness fallback: unready >10m + sibling.
	bad := w10Pod("kube-system", "node-local-dns-x1", corev1.PodPending, false, 15*time.Minute)
	good := w10Pod("kube-system", "node-local-dns-x2", corev1.PodRunning, true, time.Hour)
	cs := fake.NewSimpleClientset(bad, good)
	p := testProber(cs) // dead httpURL -> both prom queries fail

	res := p.checkCoreDNSUpstream(ctx)
	if res.pass {
		t.Fatalf("fallback must detect the unready dns pod: %+v", res)
	}
	if !strings.Contains(res.why, "node-local-dns-x1") {
		t.Fatalf("why missing pod: %q", res.why)
	}
}

// ---------------------------------------------------------------------------
// W10-NM6 — cilium-node-ipam-exhaustion
// ---------------------------------------------------------------------------

func TestWave10IPAMExhaustionFailsAndReapsTerminalPods(t *testing.T) {
	// /30 podCIDR -> 2 usable IPs; 2 running pods exhaust it.
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "w-exhaust"},
		Spec: corev1.NodeSpec{PodCIDR: "10.240.0.0/30"}}
	p1 := w10Pod("apps", "app-1", corev1.PodRunning, true, time.Hour)
	p1.Spec.NodeName = "w-exhaust"
	p2 := w10Pod("apps", "app-2", corev1.PodRunning, true, time.Hour)
	p2.Spec.NodeName = "w-exhaust"
	dead := w10Pod("apps", "app-dead", corev1.PodSucceeded, false, time.Hour)
	dead.Spec.NodeName = "w-exhaust"
	cs := fake.NewSimpleClientset(node, p1, p2, dead)
	// The fake ignores field selectors — teach it spec.nodeName so
	// the per-node reap list stays scoped like the real apiserver.
	testutil.EmulatePodNodeNameSelector(cs)
	p := testProber(cs) // dead prom -> pod-count fallback

	res := p.checkCiliumNodeIPAMExhaustion(ctx)
	if res.pass {
		t.Fatalf("exhausted node must fail: %+v", res)
	}
	if !strings.Contains(res.why, "w-exhaust") {
		t.Fatalf("why missing node: %q", res.why)
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "app-dead", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("terminal pod should be reaped, err=%v", err)
	}
	for _, name := range []string{"app-1", "app-2"} {
		if _, err := cs.CoreV1().Pods("apps").Get(ctx, name, metav1.GetOptions{}); err != nil {
			t.Fatalf("live pod %s must survive: %v", name, err)
		}
	}
}

func TestWave10IPAMHealthyNodePasses(t *testing.T) {
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "w-ok"},
		Spec: corev1.NodeSpec{PodCIDR: "10.240.1.0/24"}}
	cs := fake.NewSimpleClientset(node)
	p := testProber(cs)
	if res := p.checkCiliumNodeIPAMExhaustion(ctx); !res.pass {
		t.Fatalf("empty /24 must pass: %+v", res)
	}
}

func TestWave10PodCIDRCapacity(t *testing.T) {
	if got, ok := wave10PodCIDRCapacity("10.0.0.0/24"); !ok || got != 254 {
		t.Fatalf("/24 capacity = %d,%v want 254,true", got, ok)
	}
	if _, ok := wave10PodCIDRCapacity("fd00::/64"); ok {
		t.Fatal("IPv6 podCIDR must be skipped")
	}
	if _, ok := wave10PodCIDRCapacity(""); ok {
		t.Fatal("empty podCIDR must be skipped")
	}
}

// ---------------------------------------------------------------------------
// W10-CP1 — namespace-terminating-wedged
// ---------------------------------------------------------------------------

func TestWave10NamespaceTerminatingWedged(t *testing.T) {
	now := time.Now()
	wedged := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "dead-app",
			DeletionTimestamp: &metav1.Time{Time: now.Add(-25 * time.Minute)},
		},
		Spec: corev1.NamespaceSpec{
			Finalizers: []corev1.FinalizerName{"kubernetes"},
		},
		Status: corev1.NamespaceStatus{
			Phase: corev1.NamespaceTerminating,
			Conditions: []corev1.NamespaceCondition{{
				Type:   corev1.NamespaceContentRemaining,
				Status: corev1.ConditionTrue,
			}},
		},
	}
	fresh := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "fresh-app",
			DeletionTimestamp: &metav1.Time{Time: now.Add(-2 * time.Minute)},
		},
	}
	cs := fake.NewSimpleClientset(wedged, fresh)
	p := testProber(cs)

	res := p.checkNamespaceTerminatingWedged(ctx)
	if res.pass {
		t.Fatalf("wedged namespace must fail: %+v", res)
	}
	if !strings.Contains(res.why, "dead-app") ||
		!strings.Contains(res.why, "NamespaceContentRemaining") {
		t.Fatalf("why missing namespace diagnostics: %q", res.why)
	}
	if strings.Contains(res.why, "fresh-app") {
		t.Fatalf("fresh terminating namespace must not be flagged: %q", res.why)
	}
	if m := findMetric(t, "node_automation_namespace_terminating_wedged",
		map[string]string{"namespace": "dead-app"}); m == nil {
		t.Fatal("wedged gauge absent")
	}
}

// wave10DeadOwnerCR exercises the finalizer sweep's strip path
// directly: a terminating CR owned by a Deployment that no longer
// exists gets its non-protected finalizer removed while
// kubernetes.io/* finalizers stay.
func TestWave10MaybeStripFinalizersDeadOwner(t *testing.T) {
	gvr := schema.GroupVersionResource{Group: "example.com", Version: "v1", Resource: "foos"}
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "example.com/v1",
		"kind":       "Foo",
		"metadata": map[string]any{
			"namespace":         "dead-ns",
			"name":              "foo-1",
			"resourceVersion":   "100",
			"finalizers":        []any{"example.com/finalizer", "kubernetes.io/pvc-protection"},
			"deletionTimestamp": time.Now().UTC().Format(time.RFC3339),
			"ownerReferences": []any{map[string]any{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"name":       "gone-deploy",
				"controller": true,
				"uid":        "uid-gone",
			}},
		},
	}}
	cs := fake.NewSimpleClientset() // owner Deployment absent
	dyn := testutil.NewFakeDyn(map[schema.GroupVersionResource]string{
		gvr:                     "FooList",
		shared.AutopilotPlanGVR: "PlanList",
	}, obj)
	p := testProberDyn(cs, dyn)

	if !p.wave10MaybeStripFinalizers(ctx, logr.Discard(), gvr, obj) {
		t.Fatal("dead-owner CR should be stripped")
	}
	got, err := dyn.Resource(gvr).Namespace("dead-ns").Get(ctx, "foo-1", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	fins := got.GetFinalizers()
	if len(fins) != 1 || fins[0] != "kubernetes.io/pvc-protection" {
		t.Fatalf("finalizers after strip = %v, want only kubernetes.io/pvc-protection", fins)
	}
}

func TestWave10MaybeStripFinalizersLiveOwnerSkipped(t *testing.T) {
	gvr := schema.GroupVersionResource{Group: "example.com", Version: "v1", Resource: "foos"}
	dep := w10Deployment("dead-ns", "live-deploy")
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "example.com/v1",
		"kind":       "Foo",
		"metadata": map[string]any{
			"namespace":         "dead-ns",
			"name":              "foo-2",
			"resourceVersion":   "100",
			"finalizers":        []any{"example.com/finalizer"},
			"deletionTimestamp": time.Now().UTC().Format(time.RFC3339),
			"ownerReferences": []any{map[string]any{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"name":       "live-deploy",
				"controller": true,
			}},
		},
	}}
	cs := fake.NewSimpleClientset(dep)
	dyn := testutil.NewFakeDyn(map[schema.GroupVersionResource]string{
		gvr:                     "FooList",
		shared.AutopilotPlanGVR: "PlanList",
	}, obj)
	p := testProberDyn(cs, dyn)

	if p.wave10MaybeStripFinalizers(ctx, logr.Discard(), gvr, obj) {
		t.Fatal("live-owner CR must not be stripped")
	}
	got, _ := dyn.Resource(gvr).Namespace("dead-ns").Get(ctx, "foo-2", metav1.GetOptions{})
	if len(got.GetFinalizers()) != 1 {
		t.Fatalf("finalizers = %v, want untouched", got.GetFinalizers())
	}
}

func TestWave10MaybeStripFinalizersProtectedOnly(t *testing.T) {
	gvr := schema.GroupVersionResource{Group: "example.com", Version: "v1", Resource: "foos"}
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "example.com/v1",
		"kind":       "Foo",
		"metadata": map[string]any{
			"namespace":         "dead-ns",
			"name":              "foo-3",
			"resourceVersion":   "100",
			"finalizers":        []any{"kubernetes.io/pvc-protection", "foregroundDeletion"},
			"deletionTimestamp": time.Now().UTC().Format(time.RFC3339),
		},
	}}
	cs := fake.NewSimpleClientset()
	dyn := testutil.NewFakeDyn(map[schema.GroupVersionResource]string{
		gvr: "FooList",
	}, obj)
	p := testProberDyn(cs, dyn)

	if p.wave10MaybeStripFinalizers(ctx, logr.Discard(), gvr, obj) {
		t.Fatal("protected-only finalizers must never be stripped")
	}
}

// ---------------------------------------------------------------------------
// W10-CP6 — argocd-app-stuck
// ---------------------------------------------------------------------------

func TestWave10ArgoCDAppStuckSkipsWhenCRDAbsent(t *testing.T) {
	dyn := testutil.NewFakeDyn(map[schema.GroupVersionResource]string{
		argocdAppGVR:            "ApplicationList",
		shared.AutopilotPlanGVR: "PlanList",
	})
	dyn.PrependReactor("list", "applications",
		func(action ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewNotFound(
				schema.GroupResource{Group: "argoproj.io", Resource: "applications"}, "")
		})
	cs := fake.NewSimpleClientset()
	p := testProberDyn(cs, dyn)
	if res := p.checkArgoCDAppStuck(ctx); !res.pass {
		t.Fatalf("absent Application CRD must pass: %+v", res)
	}
}

func TestWave10ArgoCDAppStuckProgressingRefreshPatch(t *testing.T) {
	app := w10App("argocd", "my-app", "Progressing")
	dyn := testutil.NewFakeDyn(map[schema.GroupVersionResource]string{
		argocdAppGVR:            "ApplicationList",
		shared.AutopilotPlanGVR: "PlanList",
	}, app)
	cs := fake.NewSimpleClientset()
	p := testProberDyn(cs, dyn)
	base := time.Now()
	p.now = func() time.Time { return base }

	// First sighting stamps the first-seen ledger — still inside 45m.
	if res := p.checkArgoCDAppStuck(ctx); !res.pass {
		t.Fatalf("young Progressing app must pass: %+v", res)
	}
	base = base.Add(50 * time.Minute)
	res := p.checkArgoCDAppStuck(ctx)
	if res.pass {
		t.Fatalf("Progressing >45m must fail: %+v", res)
	}
	if !strings.Contains(res.why, "my-app") {
		t.Fatalf("why missing app: %q", res.why)
	}
	got, err := dyn.Resource(argocdAppGVR).Namespace("argocd").
		Get(ctx, "my-app", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ann := got.GetAnnotations()
	if ann["argocd.argoproj.io/refresh"] != "hard" {
		t.Fatalf("refresh annotation = %q, want hard", ann["argocd.argoproj.io/refresh"])
	}
}

func TestWave10ArgoCDComparisonErrorsRestartOldestRepoServer(t *testing.T) {
	cond := func() map[string]any {
		return map[string]any{
			// ArgoCD ApplicationCondition has no status field —
			// presence in status.conditions is the active signal.
			"type":               "ComparisonError",
			"lastTransitionTime": time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339),
		}
	}
	appA := w10App("argocd", "app-a", "", cond())
	appB := w10App("argocd", "app-b", "", cond())
	dyn := testutil.NewFakeDyn(map[schema.GroupVersionResource]string{
		argocdAppGVR:            "ApplicationList",
		shared.AutopilotPlanGVR: "PlanList",
	}, appA, appB)

	older := w10Pod("argocd", "argocd-repo-server-0", corev1.PodRunning, true, 2*time.Hour)
	older.Labels = map[string]string{"app.kubernetes.io/name": "argocd-repo-server"}
	newer := w10Pod("argocd", "argocd-repo-server-1", corev1.PodRunning, true, time.Hour)
	newer.Labels = map[string]string{"app.kubernetes.io/name": "argocd-repo-server"}
	cs := fake.NewSimpleClientset(older, newer)
	p := testProberDyn(cs, dyn)

	res := p.checkArgoCDAppStuck(ctx)
	if res.pass {
		t.Fatalf("two ComparisonErrors must fail: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("argocd").Get(ctx, "argocd-repo-server-0", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("oldest repo-server pod should be restarted, err=%v", err)
	}
	if _, err := cs.CoreV1().Pods("argocd").Get(ctx, "argocd-repo-server-1", metav1.GetOptions{}); err != nil {
		t.Fatalf("newer repo-server pod must survive: %v", err)
	}
}

// ---------------------------------------------------------------------------
// W10-ST3 — rabbitmq-quorum-health
// ---------------------------------------------------------------------------

func w10RabbitPod(ns, name string, ready bool) *corev1.Pod {
	pod := w10Pod(ns, name, corev1.PodRunning, ready, time.Hour)
	pod.Labels = map[string]string{
		"app.kubernetes.io/part-of":   "rabbitmq",
		"app.kubernetes.io/component": "rabbitmq",
	}
	return pod
}

func TestWave10RabbitMQAlarmFails(t *testing.T) {
	srv, _ := w10PromSrv(t, func(query string) []w10Sample {
		if strings.Contains(query, "file_descriptor_limit") {
			return []w10Sample{{
				labels: map[string]string{"namespace": "mq", "pod": "rabbitmq-server-0"},
				value:  1,
			}}
		}
		return nil
	})
	pods := []runtime.Object{}
	for _, n := range []string{"rabbitmq-server-0", "rabbitmq-server-1", "rabbitmq-server-2"} {
		pods = append(pods, w10RabbitPod("mq", n, true))
	}
	cs := fake.NewSimpleClientset(pods...)
	p := testProber(cs)
	p.cfg.httpURL = srv.URL
	p.httpClient = srv.Client()

	res := p.checkRabbitMQQuorumHealth(ctx)
	if res.pass {
		t.Fatalf("fd-limit alarm must fail: %+v", res)
	}
	if !strings.Contains(res.why, "rabbitmq-server-0") ||
		!strings.Contains(res.why, "fd_limit_alarm") {
		t.Fatalf("why missing diagnostics: %q", res.why)
	}
}

func TestWave10RabbitMQStuckUnreadyHeal(t *testing.T) {
	// Prometheus dead -> pod signature still heals: unready >10m
	// with >=2 Ready siblings.
	bad := w10RabbitPod("mq", "rabbitmq-server-0", false)
	bad.Status.Conditions[0].LastTransitionTime = metav1.NewTime(time.Now().Add(-15 * time.Minute))
	r1 := w10RabbitPod("mq", "rabbitmq-server-1", true)
	r2 := w10RabbitPod("mq", "rabbitmq-server-2", true)
	cs := fake.NewSimpleClientset(bad, r1, r2)
	p := testProber(cs)

	res := p.checkRabbitMQQuorumHealth(ctx)
	if res.pass {
		t.Fatalf("stuck-unready quorum member must fail: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("mq").Get(ctx, "rabbitmq-server-0", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("unready pod should be deleted with quorum intact, err=%v", err)
	}
}

func TestWave10RabbitMQHealthyPasses(t *testing.T) {
	pods := []runtime.Object{
		w10RabbitPod("mq", "rabbitmq-server-0", true),
		w10RabbitPod("mq", "rabbitmq-server-1", true),
		w10RabbitPod("mq", "rabbitmq-server-2", true),
	}
	cs := fake.NewSimpleClientset(pods...)
	p := testProber(cs)
	if res := p.checkRabbitMQQuorumHealth(ctx); !res.pass {
		t.Fatalf("healthy quorum must pass: %+v", res)
	}
}

// ---------------------------------------------------------------------------
// W10-ST4 — dragonfly-replica-sync-storm
// ---------------------------------------------------------------------------

func w10DragonflyPod(ns, name string, role string) *corev1.Pod {
	pod := w10Pod(ns, name, corev1.PodRunning, true, time.Hour)
	pod.Labels = map[string]string{
		"app.kubernetes.io/name": "dragonfly",
	}
	if role != "" {
		pod.Labels["app.kubernetes.io/role"] = role
	}
	return pod
}

// w10DragonflySrv answers the link-down query (BOTH the replica and
// the master report link down — the master must be flagged but never
// restarted) and the sync-storm query (non-empty -> storm active).
func w10DragonflySrv(t *testing.T) *httptest.Server {
	t.Helper()
	srv, _ := w10PromSrv(t, func(query string) []w10Sample {
		if strings.Contains(query, "master_link_status") {
			return []w10Sample{
				{
					labels: map[string]string{"namespace": "dragonfly", "pod": "dragonfly-replica-1"},
					value:  0,
				},
				{
					labels: map[string]string{"namespace": "dragonfly", "pod": "dragonfly-master-0"},
					value:  0,
				},
			}
		}
		return []w10Sample{{
			labels: map[string]string{"namespace": "dragonfly", "pod": "dragonfly-replica-1"},
			value:  4,
		}}
	})
	return srv
}

func TestWave10DragonflySyncStormRestartsReplicaNotMaster(t *testing.T) {
	srv := w10DragonflySrv(t)
	replica := w10DragonflyPod("dragonfly", "dragonfly-replica-1", "replica")
	master := w10DragonflyPod("dragonfly", "dragonfly-master-0", "master")
	cs := fake.NewSimpleClientset(replica, master)
	p := testProber(cs)
	p.cfg.httpURL = srv.URL
	p.httpClient = srv.Client()
	base := time.Now()
	p.now = func() time.Time { return base }

	// First sweep stamps the link-down first-seen; second (past the
	// 5m persistence window) confirms the storm.
	if res := p.checkDragonflyReplicaSyncStorm(ctx); !res.pass {
		t.Fatalf("first sighting inside window must pass: %+v", res)
	}
	base = base.Add(6 * time.Minute)
	res := p.checkDragonflyReplicaSyncStorm(ctx)
	if res.pass {
		t.Fatalf("sustained link-down + sync storm must fail: %+v", res)
	}
	if !strings.Contains(res.why, "dragonfly-replica-1") {
		t.Fatalf("why missing replica: %q", res.why)
	}
	if _, err := cs.CoreV1().Pods("dragonfly").Get(ctx, "dragonfly-replica-1", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("desynced replica should be restarted, err=%v", err)
	}
	if _, err := cs.CoreV1().Pods("dragonfly").Get(ctx, "dragonfly-master-0", metav1.GetOptions{}); err != nil {
		t.Fatalf("master must never be restarted: %v", err)
	}
}

func TestWave10DragonflyLinkDownAloneDoesNotRestart(t *testing.T) {
	// Storm query returns empty -> sustained link-down FAILs but no
	// restart.
	srv, _ := w10PromSrv(t, func(query string) []w10Sample {
		if strings.Contains(query, "master_link_status") {
			return []w10Sample{{
				labels: map[string]string{"namespace": "dragonfly", "pod": "dragonfly-replica-9"},
				value:  0,
			}}
		}
		return nil
	})
	replica := w10DragonflyPod("dragonfly", "dragonfly-replica-9", "replica")
	cs := fake.NewSimpleClientset(replica)
	p := testProber(cs)
	p.cfg.httpURL = srv.URL
	p.httpClient = srv.Client()
	base := time.Now()
	p.now = func() time.Time { return base }
	p.checkDragonflyReplicaSyncStorm(ctx)
	base = base.Add(6 * time.Minute)
	res := p.checkDragonflyReplicaSyncStorm(ctx)
	if res.pass {
		t.Fatalf("sustained link-down must still fail: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("dragonfly").Get(ctx, "dragonfly-replica-9", metav1.GetOptions{}); err != nil {
		t.Fatalf("unconfirmed storm must not restart the replica: %v", err)
	}
}

// ---------------------------------------------------------------------------
// W10-GI5 — image-pull-storm
// ---------------------------------------------------------------------------

// w10PullPod builds a Pending pod whose container waits in the given
// reason, created `age` ago.
func w10PullPod(ns, name, reason, message string, age time.Duration) *corev1.Pod {
	pod := w10Pod(ns, name, corev1.PodPending, false, age)
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
		Name: "app",
		State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
			Reason:  reason,
			Message: message,
		}},
	}}
	return pod
}

func TestWave10ImagePullStormSingleNamespace(t *testing.T) {
	pod := w10PullPod("team-a", "web-1", "ImagePullBackOff",
		"Back-off pulling image \"registry.example.com/app:v1\"", 15*time.Minute)
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	res := p.checkImagePullStorm(ctx)
	if res.pass {
		t.Fatalf("pull backoff must fail: %+v", res)
	}
	if !strings.Contains(res.why, "workload_image_pull_backoff") {
		t.Fatalf("why missing workload detail: %q", res.why)
	}
}

func TestWave10ImagePullStormMultiNamespaceIsOutage(t *testing.T) {
	p1 := w10PullPod("team-a", "web-1", "ImagePullBackOff", "not found", 15*time.Minute)
	p2 := w10PullPod("team-b", "api-1", "ErrImagePull", "manifest unknown", 20*time.Minute)
	cs := fake.NewSimpleClientset(p1, p2)
	p := testProber(cs)
	res := p.checkImagePullStorm(ctx)
	if res.pass {
		t.Fatalf("multi-namespace pull failures must fail: %+v", res)
	}
	if !strings.Contains(res.why, "cluster_registry_pull_outage") {
		t.Fatalf("why missing outage detail: %q", res.why)
	}
	if m := findMetric(t, "node_automation_registry_pull_outage", map[string]string{}); m == nil ||
		m.GetGauge().GetValue() != 1 {
		t.Fatalf("outage gauge absent/not 1")
	}
}

func TestWave10ImagePullStormRegistryMarkerIsOutage(t *testing.T) {
	// Single namespace but a 429 marker flips it to outage.
	pod := w10PullPod("team-a", "web-1", "ImagePullBackOff",
		"failed to pull: 429 Too Many Requests", 15*time.Minute)
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	res := p.checkImagePullStorm(ctx)
	if res.pass {
		t.Fatalf("registry-rate-limit message must fail: %+v", res)
	}
	if !strings.Contains(res.why, "cluster_registry_pull_outage") {
		t.Fatalf("why missing outage detail: %q", res.why)
	}
}

func TestWave10ImagePullStormFreshPodIgnored(t *testing.T) {
	pod := w10PullPod("team-a", "web-1", "ImagePullBackOff", "pulling", 2*time.Minute)
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	if res := p.checkImagePullStorm(ctx); !res.pass {
		t.Fatalf("fresh pull failure must pass: %+v", res)
	}
}

func TestWave10ImagePullStormHealthyPasses(t *testing.T) {
	pod := w10Pod("team-a", "web-1", corev1.PodRunning, true, time.Hour)
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
		Name:  "app",
		State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
	}}
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	if res := p.checkImagePullStorm(ctx); !res.pass {
		t.Fatalf("healthy pod must pass: %+v", res)
	}
}
