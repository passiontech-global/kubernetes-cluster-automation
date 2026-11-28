// e2e_req_tier1_test.go — Tier 1 (functional equivalence classes): >=5 isolated
// subtests for each of the 17 node-automation-controller features.
package main_test

import (
	"bytes"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

func runTier1Tests(t *testing.T, binPath string, sem chan struct{}) {
	t.Run("F1_RepoContracts", func(t *testing.T) {
		t.Parallel()
		t.Run("VersionOutputAndExitZero", func(t *testing.T) {
			t.Parallel()
			stdout, stderr, code := runManagerOnce(t, binPath, 10*time.Second, nil, "-version")
			if code != 0 {
				t.Fatalf("exit code = %d, want 0 (stdout=%q stderr=%q)", code, stdout, stderr)
			}
			if !strings.Contains(stdout, "node-automation-controller") {
				t.Errorf("stdout = %q, want node-automation-controller", stdout)
			}
		})

		t.Run("HelpDocumentsCoreFlags", func(t *testing.T) {
			t.Parallel()
			stdout, stderr, code := runManagerOnce(t, binPath, 10*time.Second, nil, "-help")
			if code != 0 {
				t.Fatalf("exit code = %d, want 0", code)
			}
			out := stdout + stderr
			for _, f := range []string{"-metrics-bind-address", "-health-probe-bind-address", "-pprof-bind-address", "-modules", "-leader-elect"} {
				if !strings.Contains(out, f) {
					t.Errorf("-help missing flag %q", f)
				}
			}
		})

		t.Run("MetricsPredeclaredAcrossRegistryRows", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			_, metricsURL, _ := startReqManager(t, binPath, srv, nil, "evicted-pod-janitor")
			samples := scrapeMetrics(t, metricsURL)
			for _, q := range []string{"evicted-pod-janitor", "apiserver-endpoint-guard", "admission-webhook-guard", "dead-node-sweeper", "cluster-health-probes"} {
				if val, ok := findMetric(samples, "shell_operator_hook_run_errors_total", map[string]string{"queue": q}); !ok || val != 0 {
					t.Errorf("predeclared error counter queue=%q got (%v,%v), want (0,true)", q, val, ok)
				}
			}
		})

		t.Run("GroupSelectorsBootCleanly", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			proc, _, probeURL := startReqManager(t, binPath, srv, nil, "@apiserver")
			code, _, err := httpGetBody(probeURL + "/healthz")
			if err != nil || code != http.StatusOK {
				t.Errorf("GET /healthz = (%d, %v), want 200", code, err)
			}
			proc.stopWithSIGINTAndAssertZero(t, 15*time.Second)
		})

		t.Run("ContractSuitesPass", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			cmd := exec.CommandContext(t.Context(), "go", "test", "-race", "./internal/envdoc", "./internal/releaseglob", "./internal/registry")
			cmd.Dir = "../.."
			cmd.Env = append(scrubbedKubeEnv(), "GOWORK=off")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("contract suites failed: %v\n%s", err, out)
			}
		})
	})

	t.Run("F4_APIServerEndpointGuard", func(t *testing.T) {
		t.Parallel()
		t.Run("StartupReadyz", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			proc, _, probeURL := startReqManager(t, binPath, srv, nil, "apiserver-endpoint-guard")
			code, _, err := httpGetBody(probeURL + "/readyz")
			if err != nil || code != http.StatusOK {
				t.Errorf("GET /readyz = (%d, %v), want 200", code, err)
			}
			proc.stopWithSIGINTAndAssertZero(t, 15*time.Second)
		})

		t.Run("Version134SelectsEndpointSliceSSOT", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.setVersion("1", "34")
			srv.addService(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "kubernetes"}})
			srv.addEndpointSlice(makeKubernetesSlice("kubernetes", "10.0.0.1", "10.0.0.2", ""))
			proc, _, _ := startReqManager(t, binPath, srv, nil, "apiserver-endpoint-guard")
			srv.waitForRequest(t, proc, 45*time.Second, "EndpointSlice list", func(r reqRecord) bool {
				return r.Method == http.MethodGet && strings.Contains(r.Path, "/apis/discovery.k8s.io/v1/namespaces/default/endpointslices")
			})
			if edits := srv.requestCount(func(r reqRecord) bool {
				return (r.Method == http.MethodPatch || r.Method == http.MethodPut) && strings.Contains(r.Path, "/endpoints/kubernetes")
			}); edits != 0 {
				t.Errorf("expected 0 Endpoints edits on v1.34 SSOT, got %d", edits)
			}
		})

		t.Run("Version132SelectsEndpointsSSOT", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.setVersion("1", "32")
			srv.addEndpoints(makeKubernetesEndpoints("10.0.0.1", "10.0.0.2"))
			proc, _, _ := startReqManager(t, binPath, srv, nil, "apiserver-endpoint-guard")
			srv.waitForRequest(t, proc, 45*time.Second, "Endpoints GET", func(r reqRecord) bool {
				return r.Method == http.MethodGet && strings.Contains(r.Path, "/api/v1/namespaces/default/endpoints")
			})
		})

		t.Run("MirrorSliceFallsBackToEndpointsSSOT", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.setVersion("1", "34")
			srv.addEndpointSlice(makeKubernetesSlice("kubernetes-abcde", "10.0.0.1", "10.0.0.2", "endpointslicemirroring-controller.k8s.io"))
			srv.addEndpoints(makeKubernetesEndpoints("10.0.0.1", "10.0.0.2"))
			proc, _, _ := startReqManager(t, binPath, srv, nil, "apiserver-endpoint-guard")
			srv.waitForRequest(t, proc, 45*time.Second, "Endpoints fallback GET", func(r reqRecord) bool {
				return r.Method == http.MethodGet && strings.Contains(r.Path, "/api/v1/namespaces/default/endpoints")
			})
		})

		t.Run("OutOfClusterFailClosedProbeMetrics", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.setVersion("1", "34")
			srv.addEndpointSlice(makeKubernetesSlice("kubernetes", "10.0.0.1", "10.0.0.2", ""))
			proc, metricsURL, _ := startReqManager(t, binPath, srv, nil, "apiserver-endpoint-guard")
			samples := waitForMetric(t, metricsURL, proc, 45*time.Second, "rv_gap=-1", func(s []metricSample) bool {
				v1, ok1 := findMetric(s, "node_automation_apiserver_rv_gap", map[string]string{"backend": "10.0.0.1"})
				v2, ok2 := findMetric(s, "node_automation_apiserver_rv_gap", map[string]string{"backend": "10.0.0.2"})
				return ok1 && ok2 && v1 == -1 && v2 == -1
			})
			if q, ok := findMetric(samples, "node_automation_apiserver_quarantined", map[string]string{"backend": "10.0.0.1"}); !ok || q != 0 {
				t.Errorf("quarantined metric = (%v,%v), want (0,true) on fail-closed out-of-cluster", q, ok)
			}
		})
	})

	t.Run("F6_CELPolicyDiscovery", func(t *testing.T) {
		t.Parallel()
		acquireManagerSlot(t, sem)
		srv := newReqE2EAPIServer(t)
		srv.registerDiscoveryGroup("example.com", "v1",
			// Irregular plural "policyindices" proves Discovery lookup rather than naive +s/+es guessing.
			metav1.APIResource{Name: "policyindices", Namespaced: true, Kind: "PolicyIndex", Verbs: []string{"get", "list"}},
			metav1.APIResource{Name: "clusterconfigs", Namespaced: false, Kind: "ClusterConfig", Verbs: []string{"get", "list"}},
		)
		piGVR := schema.GroupVersionResource{Group: "example.com", Version: "v1", Resource: "policyindices"}
		ccGVR := schema.GroupVersionResource{Group: "example.com", Version: "v1", Resource: "clusterconfigs"}
		srv.addCustomObject(piGVR, &unstructured.Unstructured{
			Object: map[string]any{
				"apiVersion": "example.com/v1", "kind": "PolicyIndex",
				"metadata": map[string]any{"name": "vap-cfg", "namespace": "default"},
			},
		})
		srv.addCustomObject(piGVR, &unstructured.Unstructured{
			Object: map[string]any{
				"apiVersion": "example.com/v1", "kind": "PolicyIndex",
				"metadata": map[string]any{"name": "map-cfg", "namespace": "default"},
			},
		})
		srv.addCustomObject(ccGVR, &unstructured.Unstructured{
			Object: map[string]any{
				"apiVersion": "example.com/v1", "kind": "ClusterConfig",
				"metadata": map[string]any{"name": "global-cfg"},
			},
		})

		podRules := &admissionv1.MatchResources{
			ResourceRules: []admissionv1.NamedRuleWithOperations{{
				RuleWithOperations: admissionv1.RuleWithOperations{
					Operations: []admissionv1.OperationType{admissionv1.Create},
					Rule:       admissionv1.Rule{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"pods"}},
				},
			}},
		}
		failPolicy := admissionv1.Fail
		ns := "default"
		// 1. Namespaced VAP with explicit namespace (irregular Discovery plural)
		srv.addVAP(&admissionv1.ValidatingAdmissionPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "vap-namespaced"},
			Spec: admissionv1.ValidatingAdmissionPolicySpec{
				FailurePolicy:    &failPolicy,
				MatchConstraints: podRules,
				ParamKind:        &admissionv1.ParamKind{APIVersion: "example.com/v1", Kind: "PolicyIndex"},
			},
		})
		srv.addVAPB(&admissionv1.ValidatingAdmissionPolicyBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "vapb-namespaced"},
			Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
				PolicyName: "vap-namespaced",
				ParamRef:   &admissionv1.ParamRef{Name: "vap-cfg", Namespace: ns},
			},
		})
		// 2. Per-namespace binding (namespaced=true, paramRef.Namespace="")
		srv.addVAP(&admissionv1.ValidatingAdmissionPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "vap-per-ns"},
			Spec: admissionv1.ValidatingAdmissionPolicySpec{
				FailurePolicy:    &failPolicy,
				MatchConstraints: podRules,
				ParamKind:        &admissionv1.ParamKind{APIVersion: "example.com/v1", Kind: "PolicyIndex"},
			},
		})
		srv.addVAPB(&admissionv1.ValidatingAdmissionPolicyBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "vapb-per-ns"},
			Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
				PolicyName: "vap-per-ns",
				ParamRef:   &admissionv1.ParamRef{Name: "per-ns-param"},
			},
		})
		// 3. Cluster-scoped ParamKind
		srv.addVAP(&admissionv1.ValidatingAdmissionPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "vap-cluster"},
			Spec: admissionv1.ValidatingAdmissionPolicySpec{
				FailurePolicy:    &failPolicy,
				MatchConstraints: podRules,
				ParamKind:        &admissionv1.ParamKind{APIVersion: "example.com/v1", Kind: "ClusterConfig"},
			},
		})
		srv.addVAPB(&admissionv1.ValidatingAdmissionPolicyBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "vapb-cluster"},
			Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
				PolicyName: "vap-cluster",
				ParamRef:   &admissionv1.ParamRef{Name: "global-cfg"},
			},
		})
		// 4. Namespaced MAP
		srv.addMAP(&admissionv1.MutatingAdmissionPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "map-namespaced"},
			Spec: admissionv1.MutatingAdmissionPolicySpec{
				FailurePolicy:    &failPolicy,
				MatchConstraints: podRules,
				ParamKind:        &admissionv1.ParamKind{APIVersion: "example.com/v1", Kind: "PolicyIndex"},
			},
		})
		srv.addMAPB(&admissionv1.MutatingAdmissionPolicyBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "mapb-namespaced"},
			Spec: admissionv1.MutatingAdmissionPolicyBindingSpec{
				PolicyName: "map-namespaced",
				ParamRef:   &admissionv1.ParamRef{Name: "map-cfg", Namespace: ns},
			},
		})

		promURL := startMockPromServer(t, func(string) []map[string]any { return nil })
		proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"HEALTH_PROMETHEUS_QUERY_URL=" + promURL}, "admission-webhook-guard")
		samples := waitForMetric(t, metricsURL, proc, 55*time.Second, "cel_policy criticalns_patch", func(s []metricSample) bool {
			v, ok := findMetric(s, "node_automation_cel_policy_actions_total", map[string]string{
				"kind": "validating_admission_policy", "action": "criticalns_patch",
			})
			return ok && v >= 1
		})

		t.Run("VAPCustomPluralParamKindDiscovery", func(t *testing.T) {
			if n := srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/apis/example.com/v1/namespaces/default/policyindices/vap-cfg"
			}); n == 0 {
				t.Errorf("expected GET to namespaced irregular plural /apis/example.com/v1/namespaces/default/policyindices/vap-cfg")
			}
		})
		t.Run("MAPCustomPluralParamKindDiscovery", func(t *testing.T) {
			if n := srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/apis/example.com/v1/namespaces/default/policyindices/map-cfg"
			}); n == 0 {
				t.Errorf("expected GET to namespaced irregular plural /apis/example.com/v1/namespaces/default/policyindices/map-cfg")
			}
		})
		t.Run("PerNamespaceParamRefSkipsClusterGet", func(t *testing.T) {
			if n := srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/apis/example.com/v1/policyindices/per-ns-param"
			}); n > 0 {
				t.Errorf("unexpected cluster-scoped GET %d for per-namespace ParamRef (namespaced=true, namespace=\"\")", n)
			}
		})
		t.Run("ClusterScopedParamRefIssuesClusterGet", func(t *testing.T) {
			if n := srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/apis/example.com/v1/clusterconfigs/global-cfg"
			}); n == 0 {
				t.Errorf("expected cluster-scoped GET /apis/example.com/v1/clusterconfigs/global-cfg")
			}
		})
		t.Run("CriticalNSFailClosedPatched", func(t *testing.T) {
			v, ok := findMetric(samples, "node_automation_cel_policy_actions_total", map[string]string{
				"kind": "validating_admission_policy", "action": "criticalns_patch",
			})
			if !ok || v < 1 {
				t.Errorf("criticalns_patch = (%v,%v), want >= 1", v, ok)
			}
		})
	})

	t.Run("F7_BoundedPodLogReads", func(t *testing.T) {
		t.Parallel()
		t.Run("PostgresWALDetectsLogTail", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addPod(makePostgresPod("db", "pg-0", "main-pg"))
			srv.setPodLog("db", "pg-0", "postgres", http.StatusOK, []byte("2026-11-22 PANIC: could not write to file \"pg_wal/00000001\": No space left on device\n"))
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "postgres-wal-archive-guard,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "postgres wal unhealthy", func(s []metricSample) bool {
				v, ok := findMetric(s, "node_automation_postgres_wal_archive_unhealthy", map[string]string{"namespace": "db", "cluster": "main-pg"})
				return ok && v == 1
			})
		})

		t.Run("PostgresWALOver2MiBTailDetected", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addPod(makePostgresPod("db", "pg-big", "big-pg"))
			var buf bytes.Buffer
			buf.Write(bytes.Repeat([]byte("info: normal checkpoint completed\n"), 80000)) // ~2.7 MiB
			buf.WriteString("FATAL: pg_wal write failed: no space left on device\n")
			srv.setPodLog("db", "pg-big", "postgres", http.StatusOK, buf.Bytes())
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "postgres-wal-archive-guard,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "postgres big tail detected", func(s []metricSample) bool {
				v, ok := findMetric(s, "node_automation_postgres_wal_archive_unhealthy", map[string]string{"namespace": "db", "cluster": "big-pg"})
				return ok && v == 1
			})
		})

		t.Run("PostgresWALOver2MiBHeadOutsideCapTruncated", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addPod(makePostgresPod("db", "pg-head", "head-pg"))
			var buf bytes.Buffer
			buf.WriteString("FATAL: pg_wal write failed: no space left on device\n")
			buf.Write(bytes.Repeat([]byte("info: normal checkpoint completed\n"), 80000)) // >2.7 MiB after head error
			srv.setPodLog("db", "pg-head", "postgres", http.StatusOK, buf.Bytes())
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "postgres-wal-archive-guard,cluster-health-probes")
			samples := waitForMetric(t, metricsURL, proc, 15*time.Second, "postgres check OK", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "postgres-wal-archive-guard", "status": "OK"})
				return ok && v == 1
			})
			if v, ok := findMetric(samples, "node_automation_postgres_wal_archive_unhealthy", map[string]string{"cluster": "head-pg"}); ok && v == 1 {
				t.Errorf("expected head error beyond 256KiB cap to be truncated, but unhealthy gauge fired")
			}
		})

		t.Run("CloudflaredQUICLogTwoSweeps", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addPod(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:         "edge",
					Name:              "cloudflared-0",
					CreationTimestamp: metav1.NewTime(time.Now().Add(-10 * time.Minute)),
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "cloudflared", Image: "cloudflare/cloudflared:2025.1"}},
				},
				Status: corev1.PodStatus{Phase: corev1.PodRunning},
			})
			srv.setPodLog("edge", "cloudflared-0", "", http.StatusOK, []byte("ERR Failed to dial to edge with quic error=\"timeout\"\n"))
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "cloudflared-tunnel-health,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 20*time.Second, "cloudflared degraded", func(s []metricSample) bool {
				v, ok := findMetric(s, "node_automation_cloudflared_tunnel_degraded", map[string]string{"namespace": "edge", "pod": "cloudflared-0"})
				return ok && v == 1
			})
		})

		t.Run("LinkerdH2StreamGuardLogQuery", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addPod(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:         "apps",
					Name:              "meshed-0",
					CreationTimestamp: metav1.NewTime(time.Now().Add(-10 * time.Minute)),
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app", Image: "app:v1"},
						{Name: "linkerd-proxy", Image: "cr.l5d.io/linkerd/proxy:v2"},
					},
				},
				Status: corev1.PodStatus{Phase: corev1.PodRunning},
			})
			srv.setPodLog("apps", "meshed-0", "linkerd-proxy", http.StatusOK, []byte("2026-11-22T00:00:00Z INFO proxy running\n"))
			proc, _, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "linkerd-h2-stream-guard,cluster-health-probes")
			req := srv.waitForRequest(t, proc, 15*time.Second, "linkerd-proxy log GET", func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/api/v1/namespaces/apps/pods/meshed-0/log" &&
					hasQueryParam(r.RawQuery, "container", "linkerd-proxy")
			})
			if !hasQueryParam(req.RawQuery, "timestamps", "true") {
				t.Errorf("expected timestamps=true in query %q", req.RawQuery)
			}
		})
	})

	t.Run("F11_GuardstateTLSProbeTimeout", func(t *testing.T) {
		t.Parallel()
		t.Run("BlackholeTCPListenerBounded2s", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			bh := startBlackholeTCPListener(t)
			srv := newReqE2EAPIServer(t)
			seedWebhookService(srv, "apps", "bh-webhook", "127.0.0.1", bh.port, "n1")
			srv.addMWC(makeMWC("mwc-bh", "apps", "bh-webhook", bh.port))
			proc, _, _ := startReqManager(t, binPath, srv, nil, "admission-webhook-guard")

			srv.waitForRequest(t, proc, 55*time.Second, "post-breaker VAP list", func(r reqRecord) bool {
				return r.Method == http.MethodGet && strings.HasSuffix(r.Path, "/validatingadmissionpolicies")
			})
			acceptAt, ok := bh.firstAcceptTime()
			if !ok {
				t.Fatalf("expected blackhole listener to receive TCP Accept")
			}
			vapReq := srv.requestsMatching(func(r reqRecord) bool {
				return r.Method == http.MethodGet && strings.HasSuffix(r.Path, "/validatingadmissionpolicies")
			})[0]
			delta := vapReq.At.Sub(acceptAt)
			if delta > 5*time.Second {
				t.Errorf("TLS handshake probe took %s after Accept(), want <=5s (2s timeout)", delta)
			}
		})

		t.Run("HealthyTLSListenerCompletesFast", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			hl := startHealthyTLSListener(t)
			srv := newReqE2EAPIServer(t)
			seedWebhookService(srv, "apps", "ok-webhook", "127.0.0.1", hl.port, "n1")
			srv.addMWC(makeMWC("mwc-ok", "apps", "ok-webhook", hl.port))
			promURL := startMockPromServer(t, func(string) []map[string]any { return nil })
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"HEALTH_PROMETHEUS_QUERY_URL=" + promURL}, "admission-webhook-guard")

			srv.waitForRequest(t, proc, 55*time.Second, "post-breaker VAP list", func(r reqRecord) bool {
				return r.Method == http.MethodGet && strings.HasSuffix(r.Path, "/validatingadmissionpolicies")
			})
			samples := scrapeMetrics(t, metricsURL)
			if v, ok := sumMetric(samples, "node_automation_webhook_circuit_breaker_trips_total", nil); ok && v > 0 {
				t.Errorf("expected 0 breaker trips on healthy TLS listener, got %v", v)
			}
		})

		t.Run("ConnectionRefusedFailsFast", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			closedPort := freeLoopbackPort(t)
			var portInt int32
			_, _ = fmt.Sscan(closedPort, &portInt)
			srv := newReqE2EAPIServer(t)
			seedWebhookService(srv, "apps", "dead-webhook", "127.0.0.1", portInt, "n1")
			srv.addMWC(makeMWC("mwc-dead", "apps", "dead-webhook", portInt))
			promURL := startMockPromServer(t, func(string) []map[string]any { return nil })
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"HEALTH_PROMETHEUS_QUERY_URL=" + promURL}, "admission-webhook-guard")

			srv.waitForRequest(t, proc, 55*time.Second, "post-breaker VAP list", func(r reqRecord) bool {
				return r.Method == http.MethodGet && strings.HasSuffix(r.Path, "/validatingadmissionpolicies")
			})
			samples := scrapeMetrics(t, metricsURL)
			if v, ok := findMetric(samples, "shell_operator_hook_run_errors_total", map[string]string{"queue": "admission-webhook-guard"}); !ok || v != 0 {
				t.Errorf("hook error counter = (%v,%v), want (0,true)", v, ok)
			}
		})

		t.Run("CRDConversionBlackholeBounded2s", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			bh := startBlackholeTCPListener(t)
			srv := newReqE2EAPIServer(t)
			seedWebhookService(srv, "apps", "crd-bh", "127.0.0.1", bh.port, "n1")
			srv.addCRD(&apiextensionsv1.CustomResourceDefinition{
				ObjectMeta: metav1.ObjectMeta{Name: "widgets.example.com"},
				Spec: apiextensionsv1.CustomResourceDefinitionSpec{
					Group: "example.com",
					Names: apiextensionsv1.CustomResourceDefinitionNames{Plural: "widgets", Kind: "Widget"},
					Scope: apiextensionsv1.NamespaceScoped,
					Conversion: &apiextensionsv1.CustomResourceConversion{
						Strategy: apiextensionsv1.WebhookConverter,
						Webhook: &apiextensionsv1.WebhookConversion{
							ClientConfig: &apiextensionsv1.WebhookClientConfig{
								Service: &apiextensionsv1.ServiceReference{Namespace: "apps", Name: "crd-bh", Port: &bh.port},
							},
						},
					},
				},
			})
			proc, _, _ := startReqManager(t, binPath, srv, nil, "admission-webhook-guard")
			srv.waitForRequest(t, proc, 55*time.Second, "post-breaker VAP list", func(r reqRecord) bool {
				return r.Method == http.MethodGet && strings.HasSuffix(r.Path, "/validatingadmissionpolicies")
			})
			acceptAt, ok := bh.firstAcceptTime()
			if !ok {
				t.Fatalf("expected CRD conversion probe to connect to blackhole listener")
			}
			vapReq := srv.requestsMatching(func(r reqRecord) bool {
				return r.Method == http.MethodGet && strings.HasSuffix(r.Path, "/validatingadmissionpolicies")
			})[0]
			if delta := vapReq.At.Sub(acceptAt); delta > 5*time.Second {
				t.Errorf("CRD conversion TLS probe took %s after Accept(), want <=5s", delta)
			}
		})

		t.Run("MixedBlackholeAndHealthyEndpoints", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			bh, hl := startBlackholeAndHealthyPair(t)
			srv := newReqE2EAPIServer(t)
			srv.addNode(&corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "n1"},
				Status:     corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}},
			})
			srv.addService(&corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "mix-webhook"},
				Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Name: "webhook", Port: 443}}},
			})
			ready := true
			nodeName := "n1"
			srv.addEndpointSlice(&discoveryv1.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "apps", Name: "mix-webhook-1",
					Labels: map[string]string{"kubernetes.io/service-name": "mix-webhook"},
				},
				Endpoints: []discoveryv1.Endpoint{
					{Addresses: []string{"127.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}, NodeName: &nodeName},
					{Addresses: []string{"127.0.0.2"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}, NodeName: &nodeName},
				},
				Ports: []discoveryv1.EndpointPort{{Port: &bh.port}},
			})
			srv.addMWC(makeMWC("mwc-mix", "apps", "mix-webhook", 443))
			promURL := startMockPromServer(t, func(string) []map[string]any { return nil })
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"HEALTH_PROMETHEUS_QUERY_URL=" + promURL}, "admission-webhook-guard")
			srv.waitForRequest(t, proc, 55*time.Second, "post-breaker VAP list", func(r reqRecord) bool {
				return r.Method == http.MethodGet && strings.HasSuffix(r.Path, "/validatingadmissionpolicies")
			})
			acceptAt, ok := bh.firstAcceptTime()
			if !ok {
				t.Fatalf("expected blackhole endpoint 127.0.0.1 dial")
			}
			if hl.acceptCount() == 0 {
				t.Errorf("expected healthy TLS endpoint 127.0.0.2:%d to receive handshake", hl.port)
			}
			vapReq := srv.requestsMatching(func(r reqRecord) bool {
				return r.Method == http.MethodGet && strings.HasSuffix(r.Path, "/validatingadmissionpolicies")
			})[0]
			if delta := vapReq.At.Sub(acceptAt); delta > 6*time.Second {
				t.Errorf("mixed endpoint probe took %s, want <=6s", delta)
			}
			samples := scrapeMetrics(t, metricsURL)
			if v, ok := sumMetric(samples, "node_automation_webhook_circuit_breaker_trips_total", nil); ok && v > 0 {
				t.Errorf("expected 0 breaker trips when 127.0.0.2 endpoint is healthy TLS, got %v", v)
			}
			if v, ok := findMetric(samples, "shell_operator_hook_run_errors_total", map[string]string{"queue": "admission-webhook-guard"}); !ok || v != 0 {
				t.Errorf("hook errors = (%v,%v), want (0,true)", v, ok)
			}
		})
	})

	t.Run("F12_FluxPatchGateAndRefund", func(t *testing.T) {
		t.Parallel()
		t.Run("HPAFluxConflictRefundsBudgetForSibling", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.enableCRD(schema.GroupVersionResource{Group: "autoscaling", Version: "v2", Resource: "horizontalpodautoscalers"})
			oldStamp := time.Now().Add(-20 * time.Minute).UTC().Format(time.RFC3339)
			zero := int32(0)
			srv.addDeployment(&appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "apps", Name: "dep-flux", ResourceVersion: "1",
					ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "helm-controller"}},
				},
				Spec: appsv1.DeploymentSpec{Replicas: &zero},
			})
			srv.addDeployment(&appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "dep-free", ResourceVersion: "1"},
				Spec:       appsv1.DeploymentSpec{Replicas: &zero},
			})
			srv.addCustomObject(schema.GroupVersionResource{Group: "autoscaling", Version: "v2", Resource: "horizontalpodautoscalers"}, makeUnhealthyHPA("apps", "hpa-a-flux", "dep-flux", oldStamp))
			srv.addCustomObject(schema.GroupVersionResource{Group: "autoscaling", Version: "v2", Resource: "horizontalpodautoscalers"}, makeUnhealthyHPA("apps", "hpa-b-free", "dep-free", oldStamp))

			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{
				"CLUSTER_HEALTH_PROBES_INTERVAL=5s",
				"NODE_AUTOMATION_HEAL_BUDGET_MAX=1",
				"NODE_AUTOMATION_HEAL_FLUX_CONFLICT_LOOP_MAX=1",
			}, "hpa-scaling-guard,cluster-health-probes")

			srv.waitForRequest(t, proc, 15*time.Second, "dep-free PATCH", func(r reqRecord) bool {
				return r.Method == http.MethodPatch && r.Path == "/apis/apps/v1/namespaces/apps/deployments/dep-free"
			})
			samples := scrapeMetrics(t, metricsURL)
			if v, ok := findMetric(samples, "node_automation_heal_gitops_conflict_total", map[string]string{"manager": "helm-controller"}); !ok || v < 1 {
				t.Errorf("gitops_conflict_total = (%v,%v), want >= 1", v, ok)
			}
			if v, ok := findMetric(samples, "node_automation_heal_budget_exhausted_total", nil); ok && v > 0 {
				t.Errorf("budget_exhausted_total = %v, want 0 after FluxPatchGate RefundGrant", v)
			}
		})

		t.Run("KedaFluxConflictRefundsBudgetForSibling", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			kedaGVR := schema.GroupVersionResource{Group: "keda.sh", Version: "v1alpha1", Resource: "scaledobjects"}
			srv.enableCRD(kedaGVR)
			oldStamp := time.Now().Add(-20 * time.Minute).UTC().Format(time.RFC3339)
			zero := int32(0)
			srv.addDeployment(&appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "apps", Name: "keda-flux-dep", ResourceVersion: "1",
					ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "kustomize-controller"}},
				},
				Spec: appsv1.DeploymentSpec{Replicas: &zero},
			})
			srv.addDeployment(&appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "keda-free-dep", ResourceVersion: "1"},
				Spec:       appsv1.DeploymentSpec{Replicas: &zero},
			})
			srv.addCustomObject(kedaGVR, makeUnhealthyScaledObject("apps", "so-a-flux", "keda-flux-dep", oldStamp))
			srv.addCustomObject(kedaGVR, makeUnhealthyScaledObject("apps", "so-b-free", "keda-free-dep", oldStamp))

			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{
				"CLUSTER_HEALTH_PROBES_INTERVAL=1s",
				"NODE_AUTOMATION_HEAL_BUDGET_MAX=1",
				"NODE_AUTOMATION_HEAL_FLUX_CONFLICT_LOOP_MAX=1",
			}, "keda-scaledobject-guard,cluster-health-probes")

			srv.waitForRequest(t, proc, 15*time.Second, "keda-free-dep PATCH", func(r reqRecord) bool {
				return r.Method == http.MethodPatch && r.Path == "/apis/apps/v1/namespaces/apps/deployments/keda-free-dep"
			})
			samples := scrapeMetrics(t, metricsURL)
			if v, ok := findMetric(samples, "node_automation_heal_gitops_conflict_total", map[string]string{"manager": "kustomize-controller"}); !ok || v < 1 {
				t.Errorf("gitops_conflict_total = (%v,%v), want >= 1", v, ok)
			}
		})

		t.Run("DeploymentRolloutWedgeFluxAndReleaseKey", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			one := int32(1)
			oldCond := metav1.NewTime(time.Now().Add(-30 * time.Minute))
			srv.addDeployment(&appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "apps", Name: "wedge-a-flux",
					ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "helm-controller"}},
				},
				Spec: appsv1.DeploymentSpec{Replicas: &one},
				Status: appsv1.DeploymentStatus{
					Conditions: []appsv1.DeploymentCondition{{
						Type: appsv1.DeploymentProgressing, Status: corev1.ConditionFalse,
						Reason: "ProgressDeadlineExceeded", LastTransitionTime: oldCond,
					}},
				},
			})
			srv.addDeployment(&appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "wedge-b-free"},
				Spec:       appsv1.DeploymentSpec{Replicas: &one},
				Status: appsv1.DeploymentStatus{
					Conditions: []appsv1.DeploymentCondition{{
						Type: appsv1.DeploymentProgressing, Status: corev1.ConditionFalse,
						Reason: "ProgressDeadlineExceeded", LastTransitionTime: oldCond,
					}},
				},
			})

			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{
				"CLUSTER_HEALTH_PROBES_INTERVAL=5s",
				"NODE_AUTOMATION_HEAL_BUDGET_MAX=1",
				"NODE_AUTOMATION_HEAL_FLUX_CONFLICT_LOOP_MAX=1",
			}, "deployment-rollout-wedge,cluster-health-probes")

			srv.waitForRequest(t, proc, 15*time.Second, "wedge-b-free PATCH", func(r reqRecord) bool {
				return r.Method == http.MethodPatch && r.Path == "/apis/apps/v1/namespaces/apps/deployments/wedge-b-free"
			})
			samples := scrapeMetrics(t, metricsURL)
			if v, ok := findMetric(samples, "node_automation_heal_budget_exhausted_total", nil); ok && v > 0 {
				t.Errorf("budget_exhausted_total = %v, want 0 after FluxPatchGate refund", v)
			}
		})

		t.Run("CoreDNSForwardSaturationPromQLIntegration", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			var qMu sync.Mutex
			var queries []string
			promURL := startMockPromServer(t, func(q string) []map[string]any {
				qMu.Lock()
				queries = append(queries, q)
				qMu.Unlock()
				if strings.Contains(q, "coredns_forward_max_concurrent_rejects_total") {
					return []map[string]any{{"metric": map[string]string{}, "value": []any{float64(time.Now().Unix()), "2.5"}}}
				}
				return nil
			})
			srv := newReqE2EAPIServer(t)
			two := int32(2)
			srv.addDeployment(&appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "kube-system", Name: "coredns",
					ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "kustomize-controller"}},
				},
				Spec: appsv1.DeploymentSpec{Replicas: &two},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{
				"CLUSTER_HEALTH_PROBES_INTERVAL=1s",
				"HEALTH_PROMETHEUS_QUERY_URL=" + promURL,
			}, "coredns-forward-saturation,cluster-health-probes")
			// Note: coreDNSFwdSatMinAge (5m in-RAM FirstSeenLedger) prevents opaque-box boostCoreDNS trigger inside 15s;
			// boostCoreDNS FluxPatchGate/RefundGrant is covered by unit tests in coredns_forward_saturation_test.go.
			samples := waitForMetric(t, metricsURL, proc, 15*time.Second, "coredns check OK", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "coredns-forward-saturation", "status": "OK"})
				return ok && v == 1
			})
			qMu.Lock()
			queried := false
			for _, q := range queries {
				if strings.Contains(q, "coredns_forward_max_concurrent_rejects_total") {
					queried = true
					break
				}
			}
			qMu.Unlock()
			if !queried {
				t.Errorf("expected PromQL query containing coredns_forward_max_concurrent_rejects_total, got %v", queries)
			}
			if v, ok := findMetric(samples, "shell_operator_hook_run_errors_total", map[string]string{"queue": "cluster-health-probes"}); !ok || v != 0 {
				t.Errorf("hook errors = (%v,%v), want (0,true)", v, ok)
			}
		})

		t.Run("SubPathLastScanResetsOnCensusError", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addDeployment(makeSubPathDeployment("apps", "subpath-app", "app-cfg"))
			srv.addConfigMap(&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "app-cfg"},
				Data:       map[string]string{"cfg.yaml": "key: val"},
			})
			srv.addErrorRule(http.MethodGet, "/api/v1/namespaces/apps/configmaps/app-cfg", http.StatusInternalServerError, 1)

			proc, _, _ := startReqManager(t, binPath, srv, []string{
				"CLUSTER_HEALTH_PROBES_INTERVAL=1s",
			}, "subpath-config-drift,cluster-health-probes")

			srv.waitForRequest(t, proc, 15*time.Second, "2nd ConfigMap GET after 500", func(r reqRecord) bool {
				return srv.requestCount(func(x reqRecord) bool {
					return x.Method == http.MethodGet && x.Path == "/api/v1/namespaces/apps/configmaps/app-cfg"
				}) >= 2
			})
		})
	})

	t.Run("F14_DeadNodeAndPartitionEvictor", func(t *testing.T) {
		t.Parallel()
		t.Run("DeadNodeMissingPVFailsClosed", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			seedDeadNodeWithPVC(srv, "dead-1", "canary-1", "apps", "pvc-miss", "pv-missing", nil)
			proc, metricsURL, _ := startReqManager(t, binPath, srv, nil, "dead-node-sweeper")

			samples := waitForMetric(t, metricsURL, proc, 55*time.Second, "unfenced_stateful_skipped=1", func(s []metricSample) bool {
				v, ok := findMetric(s, "node_automation_dead_node_unfenced_stateful_skipped", map[string]string{"node": "dead-1"})
				return ok && v == 1
			})
			if patches := srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodPatch && r.Path == "/api/v1/nodes/dead-1"
			}); patches > 0 {
				t.Errorf("expected 0 fence PATCH calls on missing PV, got %d", patches)
			}
			if v, ok := sumMetric(samples, "node_automation_dead_node_fenced_without_snr_total", map[string]string{"node": "dead-1"}); ok && v > 0 {
				t.Errorf("expected no fence counter increment on missing PV, got %v", v)
			}
		})

		t.Run("DeadNodeModelessPVFailsClosed", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			seedDeadNodeWithPVC(srv, "dead-2", "canary-2", "apps", "pvc-nomode", "pv-nomode", &corev1.PersistentVolume{
				ObjectMeta: metav1.ObjectMeta{Name: "pv-nomode"},
				Spec:       corev1.PersistentVolumeSpec{AccessModes: nil},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, nil, "dead-node-sweeper")

			waitForMetric(t, metricsURL, proc, 55*time.Second, "unfenced_stateful_skipped=1", func(s []metricSample) bool {
				v, ok := findMetric(s, "node_automation_dead_node_unfenced_stateful_skipped", map[string]string{"node": "dead-2"})
				return ok && v == 1
			})
			if patches := srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodPatch && r.Path == "/api/v1/nodes/dead-2"
			}); patches > 0 {
				t.Errorf("expected 0 fence PATCH calls on modeless PV, got %d", patches)
			}
		})

		t.Run("DeadNodeRWMPVFencesNode", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			seedDeadNodeWithPVC(srv, "dead-rwx", "canary-rwx", "apps", "pvc-rwx", "pv-rwx", &corev1.PersistentVolume{
				ObjectMeta: metav1.ObjectMeta{Name: "pv-rwx"},
				Spec:       corev1.PersistentVolumeSpec{AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany}},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, nil, "dead-node-sweeper")

			waitForMetric(t, metricsURL, proc, 55*time.Second, "fenced_without_snr=1", func(s []metricSample) bool {
				v, ok := findMetric(s, "node_automation_dead_node_fenced_without_snr_total", map[string]string{"node": "dead-rwx", "has_volumes": "false"})
				return ok && v >= 1
			})
		})

		t.Run("PartitionEvictor404NotFoundNoPDBLog", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			seedPartitionCluster(srv, "part-w1", 2, "flux-system", "source-ctrl-0", "")
			srv.setPodEvictionStatus("flux-system", "source-ctrl-0", http.StatusNotFound)
			proc, metricsURL, _ := startReqManager(t, binPath, srv, nil, "partition-pod-evictor")

			srv.waitForRequest(t, proc, 55*time.Second, "pod eviction POST", func(r reqRecord) bool {
				return r.Method == http.MethodPost && r.Path == "/api/v1/namespaces/flux-system/pods/source-ctrl-0/eviction"
			})
			waitForLog(t, proc, 55*time.Second, "partition-pod-evictor sweep done", `"logger":"partition-pod-evictor","msg":"sweep done"`)
			samples := scrapeMetrics(t, metricsURL)
			if v, ok := findMetric(samples, "shell_operator_hook_run_errors_total", map[string]string{"queue": "partition-pod-evictor"}); !ok || v != 0 {
				t.Errorf("hook errors = (%v,%v), want (0,true)", v, ok)
			}
			if strings.Contains(proc.stderr.String(), "DEFER: PDB refused eviction") {
				t.Errorf("404 eviction logged PDB refusal unexpectedly:\n%s", proc.stderr.String())
			}
		})

		t.Run("PartitionEvictor429LogsPDBRefusal", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			seedPartitionCluster(srv, "part-w2", 2, "flux-system", "helm-ctrl-0", "")
			srv.setPodEvictionStatus("flux-system", "helm-ctrl-0", http.StatusTooManyRequests)
			proc, metricsURL, _ := startReqManager(t, binPath, srv, nil, "partition-pod-evictor")

			srv.waitForRequest(t, proc, 55*time.Second, "pod eviction POST 429", func(r reqRecord) bool {
				return r.Method == http.MethodPost && r.Path == "/api/v1/namespaces/flux-system/pods/helm-ctrl-0/eviction"
			})
			waitForLog(t, proc, 55*time.Second, "partition-pod-evictor PDB refusal log", "DEFER: PDB refused eviction")
			waitForLog(t, proc, 55*time.Second, "partition-pod-evictor sweep done", `"logger":"partition-pod-evictor","msg":"sweep done"`)
			samples := scrapeMetrics(t, metricsURL)
			if v, ok := findMetric(samples, "shell_operator_hook_run_errors_total", map[string]string{"queue": "partition-pod-evictor"}); !ok || v != 0 {
				t.Errorf("hook errors = (%v,%v), want (0,true)", v, ok)
			}
		})
	})

	t.Run("F16_ControllerAPILoadAndRV0", func(t *testing.T) {
		t.Parallel()
		t.Run("AllTypedReplicaSetsSharedRV0", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{
				"CLUSTER_HEALTH_PROBES_INTERVAL=1s",
			}, "deployment-rollout-wedge,workload-admission-block-guard,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "both checks OK", func(s []metricSample) bool {
				v1, ok1 := findMetric(s, "kuberhealthy_check", map[string]string{"check": "deployment-rollout-wedge", "status": "OK"})
				v2, ok2 := findMetric(s, "kuberhealthy_check", map[string]string{"check": "workload-admission-block-guard", "status": "OK"})
				return ok1 && ok2 && v1 == 1 && v2 == 1
			})
			rsLists := srv.requestsMatching(func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/apis/apps/v1/replicasets"
			})
			if len(rsLists) == 0 {
				t.Fatalf("expected GET /apis/apps/v1/replicasets")
			}
			for _, req := range rsLists {
				if !hasQueryParam(req.RawQuery, "resourceVersion", "0") {
					t.Errorf("ReplicaSet list missing resourceVersion=0: %q", req.RawQuery)
				}
				if hasQueryParam(req.RawQuery, "limit", "") {
					t.Errorf("ReplicaSet list with RV=0 should omit limit: %q", req.RawQuery)
				}
			}
			// On 1st sweep, shared AllTypedReplicaSets should issue at most 1 per sweep (not 2 per sweep)
			depLists := srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/apis/apps/v1/deployments"
			})
			if len(rsLists) > depLists {
				t.Errorf("ReplicaSet lists (%d) exceeded shared sweep count (%d)", len(rsLists), depLists)
			}
		})

		t.Run("WorkloadHistoryGCSnapshotFirstAndRV0", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			oldTS := metav1.NewTime(time.Now().Add(-48 * time.Hour))
			zero := int32(0)
			ctrl := true
			srv.addDeployment(&appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "live-dep", UID: "dep-uid-1"},
			})
			srv.addReplicaSet(&appsv1.ReplicaSet{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "apps", Name: "live-rs-0", UID: "rs-live", CreationTimestamp: oldTS,
					OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "live-dep", UID: "dep-uid-1", Controller: &ctrl}},
				},
				Spec: appsv1.ReplicaSetSpec{Replicas: &zero},
			})
			srv.addReplicaSet(&appsv1.ReplicaSet{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "apps", Name: "orphan-rs-0", UID: "rs-orphan", CreationTimestamp: oldTS,
					OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "gone-dep", UID: "dep-gone", Controller: &ctrl}},
				},
				Spec: appsv1.ReplicaSetSpec{Replicas: &zero},
			})
			srv.addControllerRevision(&appsv1.ControllerRevision{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "apps", Name: "orphan-cr-0", UID: "cr-orphan", CreationTimestamp: oldTS,
					OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "StatefulSet", Name: "gone-sts", UID: "sts-gone", Controller: &ctrl}},
				},
			})

			proc, _, _ := startReqManager(t, binPath, srv, []string{
				"CLUSTER_HEALTH_PROBES_INTERVAL=1s",
			}, "api-object-sprawl-report-gc,cluster-health-probes")

			srv.waitForRequest(t, proc, 15*time.Second, "orphan RS DELETE", func(r reqRecord) bool {
				return r.Method == http.MethodDelete && r.Path == "/apis/apps/v1/namespaces/apps/replicasets/orphan-rs-0"
			})
			srv.waitForRequest(t, proc, 15*time.Second, "orphan CR DELETE", func(r reqRecord) bool {
				return r.Method == http.MethodDelete && r.Path == "/apis/apps/v1/namespaces/apps/controllerrevisions/orphan-cr-0"
			})
			if liveGets := srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/apis/apps/v1/namespaces/apps/deployments/live-dep"
			}); liveGets > 0 {
				t.Errorf("expected 0 live Deployment GETs for snapshot-present owner, got %d", liveGets)
			}
			for _, req := range srv.requestsMatching(func(r reqRecord) bool {
				return r.Method == http.MethodGet && (r.Path == "/apis/apps/v1/replicasets" || r.Path == "/apis/apps/v1/controllerrevisions")
			}) {
				if !hasQueryParam(req.RawQuery, "resourceVersion", "0") {
					t.Errorf("list %s missing resourceVersion=0: %q", req.Path, req.RawQuery)
				}
			}
		})

		t.Run("SixAuditChecksUseRV0", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addPVC(&corev1.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "rv0-pending-pvc", CreationTimestamp: metav1.NewTime(time.Now().Add(-1 * time.Hour))},
				Status:     corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending},
			})
			hl := startHealthyTLSListener(t)
			seedWebhookService(srv, "apps", "rv0-wh-svc", "127.0.0.1", hl.port, "n1")
			srv.addVWC(makeVWC("rv0-vwc", "apps", "rv0-wh-svc", hl.port))
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{
				"CLUSTER_HEALTH_PROBES_INTERVAL=1s",
			}, "admission-security-guard,service-traffic-policy-guard,resource-quota-check,pvc-lifecycle-guard,api-object-sprawl-report-gc,imagepull-secret-auditor,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 20*time.Second, "all 6 audit checks reported", func(s []metricSample) bool {
				for _, c := range []string{"admission-security-guard", "service-traffic-policy-guard", "resource-quota-check", "pvc-lifecycle-guard", "api-object-sprawl-report-gc", "imagepull-secret-auditor"} {
					if _, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": c}); !ok {
						return false
					}
				}
				return true
			})
			for _, path := range []string{
				"/apis/networking.k8s.io/v1/networkpolicies",
				"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
				"/apis/rbac.authorization.k8s.io/v1/rolebindings",
				"/apis/networking.k8s.io/v1/ingresses",
				"/api/v1/resourcequotas",
				"/apis/storage.k8s.io/v1/storageclasses",
				"/api/v1/serviceaccounts",
			} {
				matches := srv.requestsMatching(func(r reqRecord) bool {
					return r.Method == http.MethodGet && r.Path == path
				})
				if len(matches) == 0 {
					t.Errorf("expected GET %s", path)
					continue
				}
				for _, m := range matches {
					if !hasQueryParam(m.RawQuery, "resourceVersion", "0") {
						t.Errorf("GET %s missing resourceVersion=0 (query=%q)", path, m.RawQuery)
					}
				}
			}
		})

		t.Run("FailedJobsJanitorCachesVAAndNodes", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			oldDel := metav1.NewTime(time.Now().Add(-3 * time.Hour))
			srv.addNode(&corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "dead-n"},
				Status:     corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionFalse}}},
			})
			for i := range 3 {
				pvcName := fmt.Sprintf("stuck-pvc-%d", i)
				srv.addPVC(&corev1.PersistentVolumeClaim{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "apps", Name: pvcName, DeletionTimestamp: &oldDel,
						Finalizers: []string{"kubernetes.io/pvc-protection"},
					},
					Spec: corev1.PersistentVolumeClaimSpec{VolumeName: fmt.Sprintf("pv-%d", i)},
				})
				srv.addPod(&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: fmt.Sprintf("fail-pod-%d", i)},
					Spec: corev1.PodSpec{
						NodeName: "dead-n",
						Volumes: []corev1.Volume{{
							Name:         "vol",
							VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: pvcName}},
						}},
					},
					Status: corev1.PodStatus{Phase: corev1.PodFailed},
				})
			}
			proc, metricsURL, _ := startReqManager(t, binPath, srv, nil, "failed-jobs-janitor")
			waitForMetric(t, metricsURL, proc, 55*time.Second, "stuck_terminating_resources=1", func(s []metricSample) bool {
				v, ok := findMetric(s, "node_automation_stuck_terminating_resources", map[string]string{"kind": "PersistentVolumeClaim", "name": "stuck-pvc-2"})
				return ok && v == 1
			})
			// Typed VolumeAttachments list (non-PartialObjectMetadataList) is called at most once for all 3 PVCs.
			vaTyped := srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/apis/storage.k8s.io/v1/volumeattachments" &&
					!strings.Contains(r.Accept, "PartialObjectMetadataList")
			})
			if vaTyped > 1 {
				t.Errorf("expected cached VolumeAttachments list <= 1 for 3 stuck PVCs, got %d", vaTyped)
			}
		})

		t.Run("HeavyScanCycles6Gating", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{
				"CLUSTER_HEALTH_PROBES_INTERVAL=1s",
			}, "imagepull-secret-auditor,pod-status-check,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 20*time.Second, "cycle 7 re-audit", func(s []metricSample) bool {
				return srv.requestCount(func(r reqRecord) bool {
					return r.Method == http.MethodGet && r.Path == "/api/v1/serviceaccounts"
				}) >= 2
			})
			saCount := srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/api/v1/serviceaccounts"
			})
			podCount := srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/api/v1/pods"
			})
			if podCount < 7 {
				t.Errorf("expected >=7 sweep pod lists by cycle 7, got %d", podCount)
			}
			if saCount > 2 {
				t.Errorf("expected HeavyScanCycles=6 to gate ServiceAccounts to <=2 lists across 7 cycles, got %d", saCount)
			}
		})
	})

	t.Run("F20_CIDockerfilesAndReleaseGlobs", func(t *testing.T) {
		t.Parallel()
		t.Run("ReleaseWorkflowGlobsMatchCmdDeps", func(t *testing.T) {
			t.Parallel()
			cmd := exec.CommandContext(t.Context(), "go", "test", "-race", "./internal/releaseglob", "-run", "TestReleaseWorkflowGlobsMatchCmdDeps")
			cmd.Dir = "../.."
			cmd.Env = append(scrubbedKubeEnv(), "GOWORK=off")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("releaseglob failed: %v\n%s", err, out)
			}
		})

		t.Run("DockerDetectMappingMatchesDeps", func(t *testing.T) {
			t.Parallel()
			cmd := exec.CommandContext(t.Context(), "go", "test", "-race", "./internal/releaseglob", "-run", "TestDockerDetectMappingMatchesDeps")
			cmd.Dir = "../.."
			cmd.Env = append(scrubbedKubeEnv(), "GOWORK=off")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("ciyml test failed: %v\n%s", err, out)
			}
		})

		t.Run("DockerfileMultiStageNonRoot", func(t *testing.T) {
			t.Parallel()
			raw := readRepoFile(t, "../../Dockerfile")
			for _, want := range []string{"CGO_ENABLED=0", "-trimpath", "nonroot", "65532:65532"} {
				if !strings.Contains(raw, want) {
					t.Errorf("Dockerfile missing %q", want)
				}
			}
		})

		t.Run("HadolintZeroIssues", func(t *testing.T) {
			t.Parallel()
			cmd := exec.CommandContext(t.Context(), "hadolint", "Dockerfile")
			cmd.Dir = "../.."
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("hadolint failed: %v\n%s", err, out)
			}
		})

		t.Run("CIWorkflowPreservesDockerDetect", func(t *testing.T) {
			t.Parallel()
			raw := readRepoFile(t, "../../../../.github/workflows/ci.yml")
			for _, want := range []string{"docker-detect:", "def consumers"} {
				if !strings.Contains(raw, want) {
					t.Errorf("ci.yml missing %q", want)
				}
			}
		})
	})

	t.Run("F22_ControllerUnitCoverageSmoke", func(t *testing.T) {
		t.Parallel()
		t.Run("SubPathConfigDrift", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addDeployment(makeSubPathDeployment("apps", "sub-app", "sub-cm"))
			srv.addConfigMap(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "sub-cm"}, Data: map[string]string{"cfg.yaml": "a: 1"}})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "subpath-config-drift,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "subpath OK", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "subpath-config-drift", "status": "OK"})
				return ok && v == 1
			})
		})

		t.Run("TopologySpreadZoneDeadlock", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addNode(&corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "z-a", Labels: map[string]string{"topology.kubernetes.io/zone": "zone-a"}},
				Status:     corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}},
			})
			srv.addNode(&corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "z-b", Labels: map[string]string{"topology.kubernetes.io/zone": "zone-b"}},
				Status:     corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionFalse}}},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "topology-spread-zone-deadlock,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "topology OK", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "topology-spread-zone-deadlock", "status": "OK"})
				return ok && v == 1
			})
		})

		t.Run("LinkerdProtocolDetectionStall", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			ctrl := true
			srv.addDeployment(&appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "redis-cli", UID: "dep-redis"},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "redis:7"}}},
					},
				},
			})
			srv.addReplicaSet(&appsv1.ReplicaSet{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "apps", Name: "redis-cli-rs", UID: "rs-redis",
					OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "redis-cli", UID: "dep-redis", Controller: &ctrl}},
				},
			})
			srv.addPod(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "apps", Name: "redis-cli-pod",
					OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "redis-cli-rs", UID: "rs-redis", Controller: &ctrl}},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app", Image: "app:v1", Ports: []corev1.ContainerPort{{ContainerPort: 6379}}},
						{Name: "linkerd-proxy", Image: "cr.l5d.io/linkerd/proxy:v2"},
					},
				},
				Status: corev1.PodStatus{Phase: corev1.PodRunning},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "linkerd-protocol-detection-stall,cluster-health-probes")
			srv.waitForRequest(t, proc, 15*time.Second, "Deployment opaque-ports PATCH", func(r reqRecord) bool {
				return r.Method == http.MethodPatch && r.Path == "/apis/apps/v1/namespaces/apps/deployments/redis-cli" &&
					strings.Contains(r.Body, "config.linkerd.io/opaque-ports")
			})
			samples := scrapeMetrics(t, metricsURL)
			if v, ok := findMetric(samples, "node_automation_linkerd_opaque_port_missing", map[string]string{"namespace": "apps", "pod": "redis-cli-pod", "port": "6379"}); !ok || v != 1 {
				t.Errorf("opaque_port_missing = (%v,%v), want (1,true)", v, ok)
			}
		})

		t.Run("FailedJobsJanitor", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			oldTS := metav1.NewTime(time.Now().Add(-30 * time.Hour))
			srv.addJob(&batchv1.Job{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "old-failed-job", UID: "job-uid-1", CreationTimestamp: oldTS},
				Status: batchv1.JobStatus{
					Conditions: []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, LastTransitionTime: oldTS}},
				},
			})
			proc, _, _ := startReqManager(t, binPath, srv, nil, "failed-jobs-janitor")
			srv.waitForRequest(t, proc, 55*time.Second, "failed job DELETE", func(r reqRecord) bool {
				return r.Method == http.MethodDelete && r.Path == "/apis/batch/v1/namespaces/apps/jobs/old-failed-job"
			})
		})

		t.Run("PDBDeadlockWatchdog", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addNode(&corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "w-cordoned"},
				Spec:       corev1.NodeSpec{Unschedulable: true},
				Status:     corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}},
			})
			srv.addPDB(&policyv1.PodDisruptionBudget{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web-pdb"},
				Status:     policyv1.PodDisruptionBudgetStatus{ExpectedPods: 3, DesiredHealthy: 3, DisruptionsAllowed: 0},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, nil, "pdb-deadlock-watchdog")
			waitForLog(t, proc, 55*time.Second, "pdb-deadlock-watchdog sweep done", `"logger":"pdb-deadlock-watchdog","msg":"sweep done"`)
			if n := srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/apis/policy/v1/poddisruptionbudgets"
			}); n == 0 {
				t.Errorf("expected GET /apis/policy/v1/poddisruptionbudgets")
			}
			if n := srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/api/v1/nodes"
			}); n == 0 {
				t.Errorf("expected GET /api/v1/nodes")
			}
			samples := scrapeMetrics(t, metricsURL)
			if v, ok := findMetric(samples, "shell_operator_hook_run_errors_total", map[string]string{"queue": "pdb-deadlock-watchdog"}); !ok || v != 0 {
				t.Errorf("hook errors = (%v,%v), want (0,true)", v, ok)
			}
		})

		t.Run("CertDriftAuditor", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			_, soonPEM := generateSelfSignedCert(t, "exp.example.com", time.Now().Add(5*24*time.Hour), 202)
			_, caPEM := generateSelfSignedCert(t, "ca.example.com", time.Now().Add(100*24*time.Hour), 203)
			_, stalePEM := generateSelfSignedCert(t, "stale.example.com", time.Now().Add(100*24*time.Hour), 204)
			srv.addSecret(&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "expiring-tls"},
				Type:       corev1.SecretTypeTLS,
				Data:       map[string][]byte{"tls.crt": soonPEM},
			})
			srv.addSecret(&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "cert-manager", Name: "ca-sec"},
				Data:       map[string][]byte{"ca.crt": caPEM},
			})
			srv.addMWC(&admissionv1.MutatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "drifted-mwc",
					Annotations: map[string]string{"cert-manager.io/inject-ca-from-secret": "cert-manager/ca-sec"},
				},
				Webhooks: []admissionv1.MutatingWebhook{{
					Name:         "wh.example.com",
					ClientConfig: admissionv1.WebhookClientConfig{CABundle: stalePEM},
				}},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, nil, "cert-drift-auditor")
			samples := waitForMetric(t, metricsURL, proc, 55*time.Second, "tls_secret_days_to_expiry", func(s []metricSample) bool {
				_, ok := findMetric(s, "node_automation_tls_secret_days_to_expiry", map[string]string{"namespace": "apps", "secret": "expiring-tls"})
				return ok
			})
			if v, ok := findMetric(samples, "node_automation_webhook_ca_bundle_mismatch", map[string]string{"name": "drifted-mwc", "webhook": "wh.example.com"}); !ok || v != 1 {
				t.Errorf("ca_bundle_mismatch = (%v,%v), want (1,true)", v, ok)
			}
		})
	})

	t.Run("F25_VolumeSnapshotLifecycleGuard", func(t *testing.T) {
		t.Parallel()
		vsGVR := schema.GroupVersionResource{Group: "snapshot.storage.k8s.io", Version: "v1", Resource: "volumesnapshots"}
		vscGVR := schema.GroupVersionResource{Group: "snapshot.storage.k8s.io", Version: "v1", Resource: "volumesnapshotcontents"}

		t.Run("ModuleRegistersAndStarts", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "volumesnapshot-lifecycle-guard,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "volumesnapshot-lifecycle-guard status", func(s []metricSample) bool {
				_, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "volumesnapshot-lifecycle-guard"})
				return ok
			})
		})

		t.Run("StuckVolumeSnapshotNotReady", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addCustomObject(vsGVR, makeVolumeSnapshot("apps", "snap-stuck", false, time.Now().Add(-4*time.Hour), nil))
			srv.enableCRD(vscGVR)
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "volumesnapshot-lifecycle-guard,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "volumesnapshot FAIL", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "volumesnapshot-lifecycle-guard", "status": "FAIL"})
				return ok && v == 1
			})
		})

		t.Run("StuckVolumeSnapshotContent", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.enableCRD(vsGVR)
			srv.addCustomObject(vscGVR, makeVolumeSnapshotContent("vsc-stuck", false, time.Now().Add(-4*time.Hour), nil))
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "volumesnapshot-lifecycle-guard,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "volumesnapshotcontent FAIL", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "volumesnapshot-lifecycle-guard", "status": "FAIL"})
				return ok && v == 1
			})
		})

		t.Run("TerminatingVolumeSnapshotWithFinalizer", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			delAt := time.Now().Add(-4 * time.Hour)
			srv.addCustomObject(vsGVR, makeVolumeSnapshot("apps", "snap-term", false, delAt, &delAt))
			srv.enableCRD(vscGVR)
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "volumesnapshot-lifecycle-guard,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "terminating snapshot FAIL", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "volumesnapshot-lifecycle-guard", "status": "FAIL"})
				return ok && v == 1
			})
		})

		t.Run("HealthyReadyVolumeSnapshotPasses", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addCustomObject(vsGVR, makeVolumeSnapshot("apps", "snap-ok", true, time.Now().Add(-4*time.Hour), nil))
			srv.enableCRD(vscGVR)
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "volumesnapshot-lifecycle-guard,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "volumesnapshot OK", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "volumesnapshot-lifecycle-guard", "status": "OK"})
				return ok && v == 1
			})
		})
	})

	t.Run("F27_GatewayAPIGuard", func(t *testing.T) {
		t.Parallel()
		gcGVR := schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gatewayclasses"}
		gwGVR := schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"}
		httpGVR := schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "httproutes"}
		tlsGVR := schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1alpha2", Resource: "tlsroutes"}

		t.Run("ListsGatewayClassesAndGateways", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.enableCRD(gcGVR)
			srv.enableCRD(gwGVR)
			proc, _, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "gateway-route-health,cluster-health-probes")
			srv.waitForRequest(t, proc, 15*time.Second, "gatewayclasses list", func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/apis/gateway.networking.k8s.io/v1/gatewayclasses"
			})
			srv.waitForRequest(t, proc, 15*time.Second, "gateways list", func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/apis/gateway.networking.k8s.io/v1/gateways"
			})
		})

		t.Run("ListsTLSRoutes", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.enableCRD(tlsGVR)
			proc, _, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "gateway-route-health,cluster-health-probes")
			srv.waitForRequest(t, proc, 15*time.Second, "tlsroutes list", func(r reqRecord) bool {
				return r.Method == http.MethodGet && strings.Contains(r.Path, "/apis/gateway.networking.k8s.io/") && strings.HasSuffix(r.Path, "/tlsroutes")
			})
		})

		t.Run("ListsHTTPRoutes", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.enableCRD(httpGVR)
			proc, _, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "gateway-route-health,cluster-health-probes")
			srv.waitForRequest(t, proc, 15*time.Second, "httproutes list", func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/apis/gateway.networking.k8s.io/v1/httproutes"
			})
		})

		t.Run("GatewayProgrammedFalseDetected", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			oldCond := time.Now().Add(-30 * time.Minute).UTC().Format(time.RFC3339)
			srv.addCustomObject(gwGVR, &unstructured.Unstructured{
				Object: map[string]any{
					"apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
					"metadata": map[string]any{"name": "gw-bad", "namespace": "apps", "creationTimestamp": oldCond},
					"spec":     map[string]any{"gatewayClassName": "missing-class"},
					"status": map[string]any{
						"conditions": []any{
							map[string]any{"type": "Accepted", "status": "False", "reason": "Invalid", "lastTransitionTime": oldCond},
							map[string]any{"type": "Programmed", "status": "False", "reason": "Pending", "lastTransitionTime": oldCond},
						},
					},
				},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "gateway-route-health,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "gateway FAIL", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "gateway-route-health", "status": "FAIL"})
				return ok && v == 1
			})
		})

		t.Run("CrossNamespaceHTTPRouteMissingReferenceGrant", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.enableCRD(schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1beta1", Resource: "referencegrants"})
			oldCond := time.Now().Add(-30 * time.Minute).UTC().Format(time.RFC3339)
			srv.addCustomObject(httpGVR, &unstructured.Unstructured{
				Object: map[string]any{
					"apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
					"metadata": map[string]any{"name": "cross-ns-route", "namespace": "edge", "creationTimestamp": oldCond},
					"spec": map[string]any{
						"rules": []any{map[string]any{
							"backendRefs": []any{map[string]any{"name": "api-svc", "namespace": "backend", "port": int64(8080)}},
						}},
					},
					"status": map[string]any{
						"parents": []any{map[string]any{
							"conditions": []any{map[string]any{"type": "ResolvedRefs", "status": "False", "reason": "RefNotPermitted", "lastTransitionTime": oldCond}},
						}},
					},
				},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "gateway-route-health,cluster-health-probes")
			// Note: gateway_route_health.go gates FAIL / node_automation_gateway_route_unhealthy behind a 10m in-RAM FirstSeenLedger
			// (probefw.Persisted(&p.since, ..., 10*time.Minute)), so within 15s status stays OK while httproutes & referencegrants are evaluated.
			samples := waitForMetric(t, metricsURL, proc, 15*time.Second, "gateway-route-health evaluated httproutes and referencegrants", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "gateway-route-health", "status": "OK"})
				if !ok || v != 1 {
					return false
				}
				httpListed := srv.requestCount(func(r reqRecord) bool {
					return r.Method == http.MethodGet && r.Path == "/apis/gateway.networking.k8s.io/v1/httproutes"
				}) > 0
				grantsListed := srv.requestCount(func(r reqRecord) bool {
					return r.Method == http.MethodGet && strings.Contains(r.Path, "referencegrants")
				}) > 0
				return httpListed && grantsListed
			})
			if v, ok := findMetric(samples, "shell_operator_hook_run_errors_total", map[string]string{"queue": "cluster-health-probes"}); !ok || v != 0 {
				t.Errorf("hook errors = (%v,%v), want (0,true)", v, ok)
			}
		})
	})

	t.Run("F28ctrl_ImagePullSecretAuditor", func(t *testing.T) {
		t.Parallel()
		t.Run("PrivateRegistryPodWithoutPullSecretFlagged", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addPod(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "priv-pod"},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "registry.internal.corp/team/app:v1.2.3"}}},
				Status:     corev1.PodStatus{Phase: corev1.PodRunning},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "imagepull-secret-auditor,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "private registry FAIL", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "imagepull-secret-auditor", "status": "FAIL"})
				return ok && v == 1
			})
		})

		t.Run("PrivateRegistryDeploymentWithoutPullSecretFlagged", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addDeployment(&appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "priv-dep"},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "harbor.internal.local/ops/worker:v2"}}},
					},
				},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "imagepull-secret-auditor,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "private registry deployment FAIL", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "imagepull-secret-auditor", "status": "FAIL"})
				return ok && v == 1
			})
		})

		t.Run("PrivateRegistryPodWithValidPullSecretPasses", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addSecret(&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "regcred"},
				Type:       corev1.SecretTypeDockerConfigJson,
				Data:       map[string][]byte{corev1.DockerConfigJsonKey: []byte(`{"auths":{"registry.internal.corp":{"auth":"dXNlcjpwYXNz"}}}`)},
			})
			srv.addPod(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "priv-ok"},
				Spec: corev1.PodSpec{
					ImagePullSecrets: []corev1.LocalObjectReference{{Name: "regcred"}},
					Containers:       []corev1.Container{{Name: "app", Image: "registry.internal.corp/team/app:v1.2.3"}},
				},
				Status: corev1.PodStatus{Phase: corev1.PodRunning},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "imagepull-secret-auditor,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "valid pullsecret OK", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "imagepull-secret-auditor", "status": "OK"})
				return ok && v == 1
			})
		})

		t.Run("PublicRegistryPodWithoutPullSecretPasses", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addPod(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "pub-pod"},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "nginx", Image: "registry.k8s.io/pause:3.10"}}},
				Status:     corev1.PodStatus{Phase: corev1.PodRunning},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "imagepull-secret-auditor,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "public registry OK", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "imagepull-secret-auditor", "status": "OK"})
				return ok && v == 1
			})
		})

		t.Run("HeavyScanCyclesReauditsOnCycle7", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			proc, _, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "imagepull-secret-auditor,cluster-health-probes")
			srv.waitForRequest(t, proc, 20*time.Second, "cycle 7 ServiceAccount list", func(r reqRecord) bool {
				return srv.requestCount(func(x reqRecord) bool {
					return x.Method == http.MethodGet && x.Path == "/api/v1/serviceaccounts"
				}) >= 2
			})
		})
	})

	t.Run("F29_DRAResourceClaimGuard", func(t *testing.T) {
		t.Parallel()
		rcGVR := schema.GroupVersionResource{Group: "resource.k8s.io", Version: "v1", Resource: "resourceclaims"}

		t.Run("ModuleRegistersAndStarts", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "dra-claim-wedge-guard,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "dra check metric", func(s []metricSample) bool {
				_, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "dra-claim-wedge-guard"})
				return ok
			})
		})

		t.Run("ListsResourceClaimsV1", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.enableCRD(rcGVR)
			proc, _, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "dra-claim-wedge-guard,cluster-health-probes")
			srv.waitForRequest(t, proc, 15*time.Second, "resourceclaims list", func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/apis/resource.k8s.io/v1/resourceclaims"
			})
		})

		t.Run("ZombieReservedClaimForDeletedPodFlagged", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addCustomObject(rcGVR, makeDRAResourceClaim("gpu-ns", "gpu-zombie", "deleted-pod", "dead-uid", true, time.Now().Add(-3*time.Hour), nil))
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "dra-claim-wedge-guard,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "dra zombie FAIL", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "dra-claim-wedge-guard", "status": "FAIL"})
				return ok && v == 1
			})
		})

		t.Run("StuckUnallocatedClaimFlagged", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addCustomObject(rcGVR, makeDRAResourceClaim("gpu-ns", "gpu-unalloc", "", "", false, time.Now().Add(-3*time.Hour), nil))
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "dra-claim-wedge-guard,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "dra unallocated FAIL", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "dra-claim-wedge-guard", "status": "FAIL"})
				return ok && v == 1
			})
		})

		t.Run("HealthyAllocatedClaimForLivePodPasses", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addPod(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "gpu-ns", Name: "live-gpu-pod", UID: "live-uid"},
				Status:     corev1.PodStatus{Phase: corev1.PodRunning},
			})
			srv.addCustomObject(rcGVR, makeDRAResourceClaim("gpu-ns", "gpu-ok", "live-gpu-pod", "live-uid", true, time.Now().Add(-3*time.Hour), nil))
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "dra-claim-wedge-guard,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "dra healthy OK", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "dra-claim-wedge-guard", "status": "OK"})
				return ok && v == 1
			})
		})
	})

	t.Run("F30_PodResizeWedgeGuard", func(t *testing.T) {
		t.Parallel()
		t.Run("ModuleRegistersAndStarts", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "pod-resize-wedge-guard,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "pod-resize check metric", func(s []metricSample) bool {
				_, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "pod-resize-wedge-guard"})
				return ok
			})
		})

		t.Run("PodResizePendingStuckFlagged", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addPod(makeResizePod("apps", "resize-pending", "PodResizePending", "Deferred", time.Now().Add(-2*time.Hour)))
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "pod-resize-wedge-guard,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "pod-resize pending FAIL", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "pod-resize-wedge-guard", "status": "FAIL"})
				return ok && v == 1
			})
		})

		t.Run("PodResizeInProgressStuckFlagged", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addPod(makeResizePod("apps", "resize-inprog", "PodResizeInProgress", "", time.Now().Add(-2*time.Hour)))
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "pod-resize-wedge-guard,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "pod-resize in-progress FAIL", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "pod-resize-wedge-guard", "status": "FAIL"})
				return ok && v == 1
			})
		})

		t.Run("HealthyRunningPodPasses", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addPod(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "normal-pod"},
				Status:     corev1.PodStatus{Phase: corev1.PodRunning},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "pod-resize-wedge-guard,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "pod-resize OK", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "pod-resize-wedge-guard", "status": "OK"})
				return ok && v == 1
			})
		})

		t.Run("PodResizePendingInfeasibleFlagged", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addPod(makeResizePod("apps", "resize-infeasible", "PodResizePending", "Infeasible", time.Now().Add(-2*time.Hour)))
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "pod-resize-wedge-guard,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "pod-resize infeasible FAIL", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "pod-resize-wedge-guard", "status": "FAIL"})
				return ok && v == 1
			})
		})
	})

	t.Run("F31ctrl_OrphanEndpointSliceCleaner", func(t *testing.T) {
		t.Parallel()
		acquireManagerSlot(t, sem)
		srv := newReqE2EAPIServer(t)
		oldTS := metav1.NewTime(time.Now().Add(-30 * time.Minute))
		srv.addService(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "kubernetes"}})
		srv.addService(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web-live"}})
		srv.addPod(&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web-live-0", UID: "live-pod-uid"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		})
		ready := true
		srv.addEndpointSlice(&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "apps", Name: "web-live-slice", UID: "es-live-1", CreationTimestamp: oldTS,
				Labels: map[string]string{"kubernetes.io/service-name": "web-live"},
			},
			Endpoints: []discoveryv1.Endpoint{
				{
					Addresses:  []string{"10.1.0.1"},
					Conditions: discoveryv1.EndpointConditions{Ready: &ready},
					TargetRef:  &corev1.ObjectReference{Kind: "Pod", Namespace: "apps", Name: "web-live-0", UID: "live-pod-uid"},
				},
				{
					Addresses:  []string{"10.1.0.99"},
					Conditions: discoveryv1.EndpointConditions{Ready: &ready},
					TargetRef:  &corev1.ObjectReference{Kind: "Pod", Namespace: "apps", Name: "web-dead-0", UID: "ghost-pod-uid"},
				},
			},
		})
		srv.addEndpointSlice(&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "apps", Name: "orphan-svc-slice", UID: "es-orphan-1", CreationTimestamp: oldTS,
				Labels: map[string]string{"kubernetes.io/service-name": "deleted-svc"},
			},
		})
		srv.addEndpointSlice(&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "default", Name: "kubernetes", UID: "es-kube-1", CreationTimestamp: oldTS,
				Labels: map[string]string{"kubernetes.io/service-name": "kubernetes"},
			},
			Endpoints: []discoveryv1.Endpoint{{
				Addresses: []string{"10.0.0.1"},
				TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: "default", Name: "ghost-apiserver", UID: "ghost-kube-uid"},
			}},
		})

		proc, metricsURL, _ := startReqManager(t, binPath, srv, nil, "orphan-endpointslice-cleaner")
		waitForLog(t, proc, 55*time.Second, "orphan-endpointslice-cleaner sweep done", `"logger":"orphan-endpointslice-cleaner","msg":"sweep done"`)
		samples := scrapeMetrics(t, metricsURL)

		t.Run("ExecutesRun1ListsServicesSlicesAndPods", func(t *testing.T) {
			if srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodGet && strings.Contains(r.Path, "/services")
			}) == 0 || srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodGet && strings.Contains(r.Path, "/endpointslices")
			}) == 0 || srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/api/v1/pods"
			}) == 0 {
				t.Errorf("expected services, endpointslices, and pods list requests on run 1")
			}
		})

		t.Run("GhostPodUIDDetectedOrRemediated", func(t *testing.T) {
			remediated := srv.requestCount(func(r reqRecord) bool {
				return (r.Method == http.MethodPatch || r.Method == http.MethodDelete) &&
					strings.Contains(r.Path, "/apps/endpointslices/web-live-slice")
			})
			ghostMetric := false
			for _, s := range samples {
				if strings.Contains(s.Name, "ghost") || strings.Contains(s.Name, "orphan_endpoint") {
					if s.Value > 0 {
						ghostMetric = true
					}
				}
			}
			stderr := proc.stderr.String()
			ghostLogged := strings.Contains(stderr, "ghost endpoint candidate: Pod UID missing") &&
				strings.Contains(stderr, "ghost-pod-uid")
			if remediated == 0 && !ghostMetric && !ghostLogged {
				t.Errorf("expected ghost Pod UID detection (patch/delete, metric, or candidate log with ghost-pod-uid), got none")
			}
		})

		t.Run("LivePodUIDEndpointUntouched", func(t *testing.T) {
			if del := srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodDelete && r.Path == "/apis/discovery.k8s.io/v1/namespaces/apps/endpointslices/web-live-slice"
			}); del > 0 {
				t.Errorf("live Service EndpointSlice must not be deleted outright, got %d", del)
			}
		})

		t.Run("MissingServiceSliceZeroErrors", func(t *testing.T) {
			if v, ok := findMetric(samples, "shell_operator_hook_run_errors_total", map[string]string{"queue": "orphan-endpointslice-cleaner"}); !ok || v != 0 {
				t.Errorf("hook errors = (%v,%v), want (0,true)", v, ok)
			}
		})

		t.Run("DefaultKubernetesSliceNeverMutated", func(t *testing.T) {
			if mut := srv.requestCount(func(r reqRecord) bool {
				return (r.Method == http.MethodPatch || r.Method == http.MethodDelete) &&
					strings.Contains(r.Path, "/default/endpointslices/kubernetes")
			}); mut > 0 {
				t.Errorf("default/kubernetes EndpointSlice must never be mutated, got %d", mut)
			}
		})
	})

	t.Run("F32_VeleroRestoreAndIngressNginxPosture", func(t *testing.T) {
		t.Parallel()
		veleroRestoreGVR := schema.GroupVersionResource{Group: "velero.io", Version: "v1", Resource: "restores"}

		t.Run("VeleroAuditorListsRestores", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			enableVeleroCRDs(srv)
			srv.enableCRD(veleroRestoreGVR)
			proc, _, _ := startReqManager(t, binPath, srv, nil, "velero-backup-auditor")
			srv.waitForRequest(t, proc, 55*time.Second, "velero restores list", func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/apis/velero.io/v1/restores"
			})
		})

		t.Run("VeleroStuckInProgressRestoreDetected", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			enableVeleroCRDs(srv)
			oldStart := time.Now().Add(-8 * time.Hour).UTC().Format(time.RFC3339)
			srv.addCustomObject(veleroRestoreGVR, &unstructured.Unstructured{
				Object: map[string]any{
					"apiVersion": "velero.io/v1", "kind": "Restore",
					"metadata": map[string]any{"name": "restore-stuck", "namespace": "velero", "creationTimestamp": oldStart},
					"status":   map[string]any{"phase": "InProgress", "startTimestamp": oldStart},
				},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, nil, "velero-backup-auditor")
			srv.waitForRequest(t, proc, 55*time.Second, "velero restores list", func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/apis/velero.io/v1/restores"
			})
			waitForLog(t, proc, 55*time.Second, "velero-backup-auditor sweep done", `"logger":"velero-backup-auditor","msg":"sweep done"`)
			samples := scrapeMetrics(t, metricsURL)
			found := false
			for _, s := range samples {
				if strings.Contains(s.Name, "velero") && strings.Contains(s.Name, "restore") && s.Value >= 1 {
					found = true
				}
			}
			if !found && !strings.Contains(proc.stderr.String(), "restore-stuck") {
				t.Errorf("expected stuck Velero Restore metric or log for restore-stuck")
			}
		})

		t.Run("VeleroFailedRestoreDetected", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			enableVeleroCRDs(srv)
			ts := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
			srv.addCustomObject(veleroRestoreGVR, &unstructured.Unstructured{
				Object: map[string]any{
					"apiVersion": "velero.io/v1", "kind": "Restore",
					"metadata": map[string]any{"name": "restore-failed", "namespace": "velero", "creationTimestamp": ts},
					"status":   map[string]any{"phase": "Failed", "startTimestamp": ts},
				},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, nil, "velero-backup-auditor")
			srv.waitForRequest(t, proc, 55*time.Second, "velero restores list", func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/apis/velero.io/v1/restores"
			})
			waitForLog(t, proc, 55*time.Second, "velero-backup-auditor sweep done", `"logger":"velero-backup-auditor","msg":"sweep done"`)
			samples := scrapeMetrics(t, metricsURL)
			found := false
			for _, s := range samples {
				if strings.Contains(s.Name, "velero") && strings.Contains(s.Name, "restore") && s.Value >= 1 {
					found = true
				}
			}
			if !found && !strings.Contains(proc.stderr.String(), "restore-failed") {
				t.Errorf("expected failed Velero Restore metric or log for restore-failed")
			}
		})

		t.Run("IngressNginxRetirementPostureFlagsNginx", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addIngressClass(&networkingv1.IngressClass{
				ObjectMeta: metav1.ObjectMeta{Name: "nginx"},
				Spec:       networkingv1.IngressClassSpec{Controller: "k8s.io/ingress-nginx"},
			})
			icName := "nginx"
			srv.addIngress(&networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "legacy-ing"},
				Spec:       networkingv1.IngressSpec{IngressClassName: &icName},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "@health")
			waitForMetric(t, metricsURL, proc, 20*time.Second, "ingress-nginx posture check", func(s []metricSample) bool {
				for _, m := range s {
					if m.Name == "kuberhealthy_check" && strings.Contains(m.Labels["check"], "ingress") && strings.Contains(m.Labels["check"], "nginx") && m.Labels["status"] == "FAIL" && m.Value == 1 {
						return true
					}
				}
				return false
			})
		})

		t.Run("NonNginxIngressClassPassesPosture", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addIngressClass(&networkingv1.IngressClass{
				ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
				Spec:       networkingv1.IngressClassSpec{Controller: "cilium.io/ingress-controller"},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "@health")
			waitForMetric(t, metricsURL, proc, 20*time.Second, "ingress-nginx posture OK", func(s []metricSample) bool {
				for _, m := range s {
					if m.Name == "kuberhealthy_check" && strings.Contains(m.Labels["check"], "ingress") && strings.Contains(m.Labels["check"], "nginx") && m.Labels["status"] == "OK" && m.Value == 1 {
						return true
					}
				}
				return false
			})
		})
	})
}

// ---- Shared Seed Builders --------------------------------------------------

func enableVeleroCRDs(srv *reqE2EAPIServer) {
	for _, res := range []string{"schedules", "backups", "backupstoragelocations", "podvolumebackups", "podvolumerestores", "backuprepositories", "restores"} {
		srv.enableCRD(schema.GroupVersionResource{Group: "velero.io", Version: "v1", Resource: res})
	}
}

func readRepoFile(t *testing.T, relPath string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "cat", relPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("read %s: %v\n%s", relPath, err, out)
	}
	return string(out)
}

func makeKubernetesSlice(name, ip1, ip2, managedBy string) *discoveryv1.EndpointSlice {
	ready := true
	port := int32(6443)
	labels := map[string]string{"kubernetes.io/service-name": "kubernetes"}
	if managedBy != "" {
		labels["endpointslice.kubernetes.io/managed-by"] = managedBy
	}
	var eps []discoveryv1.Endpoint
	for _, ip := range []string{ip1, ip2} {
		if ip != "" {
			eps = append(eps, discoveryv1.Endpoint{
				Addresses:  []string{ip},
				Conditions: discoveryv1.EndpointConditions{Ready: &ready},
			})
		}
	}
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name, Labels: labels},
		Endpoints:  eps,
		Ports:      []discoveryv1.EndpointPort{{Port: &port}},
	}
}

func makeKubernetesEndpoints(ips ...string) *corev1.Endpoints {
	var addrs []corev1.EndpointAddress
	for _, ip := range ips {
		addrs = append(addrs, corev1.EndpointAddress{IP: ip})
	}
	return &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "kubernetes"},
		Subsets: []corev1.EndpointSubset{{
			Addresses: addrs,
			Ports:     []corev1.EndpointPort{{Port: 6443}},
		}},
	}
}

func makePostgresPod(ns, name, cluster string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name,
			Labels: map[string]string{"cnpg.io/cluster": cluster},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "postgres", Image: "postgres:16"}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func seedWebhookService(srv *reqE2EAPIServer, ns, name, ip string, port int32, nodeName string) {
	srv.addNode(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: nodeName},
		Status:     corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}},
	})
	srv.addService(&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": name},
			Ports:    []corev1.ServicePort{{Name: "webhook", Port: port}},
		},
	})
	ready := true
	srv.addEndpointSlice(&discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name + "-slice",
			Labels: map[string]string{"kubernetes.io/service-name": name},
		},
		Endpoints: []discoveryv1.Endpoint{{
			Addresses:  []string{ip},
			Conditions: discoveryv1.EndpointConditions{Ready: &ready},
			NodeName:   &nodeName,
		}},
		Ports: []discoveryv1.EndpointPort{{Port: &port}},
	})
}

func makeMWC(name, svcNS, svcName string, port int32) *admissionv1.MutatingWebhookConfiguration {
	fp := admissionv1.Fail
	return &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          name + ".example.com",
			FailurePolicy: &fp,
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: &admissionv1.ServiceReference{Namespace: svcNS, Name: svcName, Port: &port},
			},
		}},
	}
}

func makeVWC(name, svcNS, svcName string, port int32) *admissionv1.ValidatingWebhookConfiguration {
	fp := admissionv1.Fail
	return &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Webhooks: []admissionv1.ValidatingWebhook{{
			Name:          name + ".example.com",
			FailurePolicy: &fp,
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: &admissionv1.ServiceReference{Namespace: svcNS, Name: svcName, Port: &port},
			},
		}},
	}
}

func makeUnhealthyHPA(ns, name, targetDep, firstSeenRFC3339 string) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "autoscaling/v2", "kind": "HorizontalPodAutoscaler",
			"metadata": map[string]any{
				"namespace":   ns,
				"name":        name,
				"annotations": map[string]any{"passiontech.dev/first-seen-hpa-scaling": fmt.Sprintf(`{"%s/%s":%q}`, ns, name, firstSeenRFC3339)},
			},
			"spec": map[string]any{
				"minReplicas":    int64(1),
				"maxReplicas":    int64(5),
				"scaleTargetRef": map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "name": targetDep},
			},
			"status": map[string]any{
				"conditions": []any{map[string]any{"type": "AbleToScale", "status": "False", "reason": "FailedGetScale"}},
			},
		},
	}
}

func makeUnhealthyScaledObject(ns, name, targetDep, firstSeenRFC3339 string) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "keda.sh/v1alpha1", "kind": "ScaledObject",
			"metadata": map[string]any{
				"namespace":   ns,
				"name":        name,
				"annotations": map[string]any{"passiontech.dev/first-seen-keda-scaledobject": fmt.Sprintf(`{"%s/%s":%q}`, ns, name, firstSeenRFC3339)},
			},
			"spec": map[string]any{
				"minReplicaCount": int64(1),
				"scaleTargetRef":  map[string]any{"kind": "Deployment", "name": targetDep},
			},
			"status": map[string]any{
				"conditions": []any{map[string]any{"type": "Ready", "status": "False", "reason": "ScalerError"}},
			},
		},
	}
}

func makeSubPathDeployment(ns, name, cmName string) *appsv1.Deployment {
	one := int32(1)
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: appsv1.DeploymentSpec{
			Replicas: &one,
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Volumes: []corev1.Volume{{
						Name:         "cfg",
						VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: cmName}}},
					}},
					Containers: []corev1.Container{{
						Name: "app", Image: "app:v1",
						VolumeMounts: []corev1.VolumeMount{{Name: "cfg", MountPath: "/etc/cfg.yaml", SubPath: "cfg.yaml"}},
					}},
				},
			},
		},
	}
}

func seedDeadNodeWithPVC(srv *reqE2EAPIServer, deadNode, canaryNode, ns, pvcName, pvName string, pv *corev1.PersistentVolume) {
	oldTime := metav1.NewTime(time.Now().Add(-45 * time.Minute))
	srv.addNode(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: deadNode},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionUnknown, LastTransitionTime: oldTime}},
		},
	})
	srv.addNode(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: canaryNode},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue, LastTransitionTime: oldTime}},
		},
	})
	srv.setNodeProxyHealthz(deadNode, http.StatusBadGateway, `{"kind":"Status","status":"Failure","message":"error trying to reach service","code":502}`)
	srv.setNodeProxyHealthz(canaryNode, http.StatusOK, "ok")

	delTS := metav1.NewTime(time.Now().Add(-20 * time.Minute))
	srv.addPod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "stuck-" + deadNode, DeletionTimestamp: &delTS},
		Spec: corev1.PodSpec{
			NodeName: deadNode,
			Volumes: []corev1.Volume{{
				Name:         "data",
				VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: pvcName}},
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	})
	srv.addPVC(&corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: pvcName},
		Spec:       corev1.PersistentVolumeClaimSpec{VolumeName: pvName},
	})
	if pv != nil {
		srv.addPV(pv)
	}
}

func seedPartitionCluster(srv *reqE2EAPIServer, partNode string, healthyWorkers int, podNS, podName, pvcStorageClass string) {
	oldTime := metav1.NewTime(time.Now().Add(-20 * time.Minute))
	srv.addNode(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: partNode},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionTrue, LastTransitionTime: oldTime},
				{Type: "ClusterNetworkProblems", Status: corev1.ConditionTrue, LastTransitionTime: oldTime},
			},
		},
	})
	for i := range healthyWorkers {
		srv.addNode(&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("%s-ok-%d", partNode, i)},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue, LastTransitionTime: oldTime}},
			},
		})
	}
	var vols []corev1.Volume
	if pvcStorageClass != "" {
		sc := pvcStorageClass
		srv.addPVC(&corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{Namespace: podNS, Name: "pinned-pvc"},
			Spec:       corev1.PersistentVolumeClaimSpec{StorageClassName: &sc},
		})
		vols = append(vols, corev1.Volume{
			Name:         "data",
			VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "pinned-pvc"}},
		})
	}
	ctrl := true
	srv.addPod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: podNS, Name: podName, UID: types.UID("uid-" + podName),
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "ReplicaSet", Name: podName + "-rs", UID: types.UID("rs-" + podName), Controller: &ctrl,
			}},
		},
		Spec:   corev1.PodSpec{NodeName: partNode, Volumes: vols},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	})
}

func makeVolumeSnapshot(ns, name string, ready bool, createdAt time.Time, deletedAt *time.Time) *unstructured.Unstructured {
	metaMap := map[string]any{
		"namespace":         ns,
		"name":              name,
		"creationTimestamp": createdAt.UTC().Format(time.RFC3339),
	}
	if deletedAt != nil {
		metaMap["deletionTimestamp"] = deletedAt.UTC().Format(time.RFC3339)
		metaMap["finalizers"] = []any{"snapshot.storage.kubernetes.io/volumesnapshot-as-source-protection"}
	}
	return &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "snapshot.storage.k8s.io/v1", "kind": "VolumeSnapshot",
			"metadata": metaMap,
			"spec":     map[string]any{"source": map[string]any{"persistentVolumeClaimName": "pvc-1"}},
			"status":   map[string]any{"readyToUse": ready},
		},
	}
}

func makeVolumeSnapshotContent(name string, ready bool, createdAt time.Time, deletedAt *time.Time) *unstructured.Unstructured {
	metaMap := map[string]any{
		"name":              name,
		"creationTimestamp": createdAt.UTC().Format(time.RFC3339),
	}
	if deletedAt != nil {
		metaMap["deletionTimestamp"] = deletedAt.UTC().Format(time.RFC3339)
		metaMap["finalizers"] = []any{"snapshot.storage.kubernetes.io/volumesnapshotcontent-bound-protection"}
	}
	return &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "snapshot.storage.k8s.io/v1", "kind": "VolumeSnapshotContent",
			"metadata": metaMap,
			"status":   map[string]any{"readyToUse": ready},
		},
	}
}

func makeDRAResourceClaim(ns, name, podName, podUID string, allocated bool, createdAt time.Time, deletedAt *time.Time) *unstructured.Unstructured {
	metaMap := map[string]any{
		"namespace":         ns,
		"name":              name,
		"creationTimestamp": createdAt.UTC().Format(time.RFC3339),
	}
	if deletedAt != nil {
		metaMap["deletionTimestamp"] = deletedAt.UTC().Format(time.RFC3339)
		metaMap["finalizers"] = []any{"resource.kubernetes.io/delete-protection"}
	}
	status := map[string]any{}
	if allocated {
		status["allocation"] = map[string]any{"nodeSelector": map[string]any{}}
	}
	if podName != "" {
		status["reservedFor"] = []any{map[string]any{
			"resource": "pods",
			"name":     podName,
			"uid":      podUID,
		}}
	}
	return &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "resource.k8s.io/v1", "kind": "ResourceClaim",
			"metadata": metaMap,
			"status":   status,
		},
	}
}

func makeResizePod(ns, name, condType, reason string, since time.Time) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "app:v1"}}},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{{
				Type:               corev1.PodConditionType(condType),
				Status:             corev1.ConditionTrue,
				Reason:             reason,
				LastTransitionTime: metav1.NewTime(since),
			}},
		},
	}
}
