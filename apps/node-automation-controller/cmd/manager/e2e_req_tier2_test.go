// e2e_req_tier2_test.go — Tier 2 (boundary, corner, and negative cases): >=5
// isolated subtests for each of the 17 node-automation-controller features.
package main_test

import (
	"fmt"
	"net/http"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	yaml "go.yaml.in/yaml/v3"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	policyv1 "k8s.io/api/policy/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

func runTier2Tests(t *testing.T, binPath string, sem chan struct{}) {
	t.Run("F1_RepoContractsBoundary", func(t *testing.T) {
		t.Parallel()
		t.Run("UnknownModuleFailsFastWithLists", func(t *testing.T) {
			t.Parallel()
			_, stderr, code := runManagerOnce(t, binPath, 10*time.Second, scrubbedKubeEnv(), "-modules=no-such-module")
			if code != 1 || !strings.Contains(stderr, "valid names:") || !strings.Contains(stderr, "valid groups:") {
				t.Errorf("code=%d stderr=%q, want exit 1 listing valid names/groups", code, stderr)
			}
		})

		t.Run("InvalidGroupSelectorsFailFast", func(t *testing.T) {
			t.Parallel()
			for _, arg := range []string{"@bogus", "@"} {
				_, stderr, code := runManagerOnce(t, binPath, 10*time.Second, scrubbedKubeEnv(), "-modules="+arg)
				if code != 1 || !strings.Contains(stderr, "invalid -modules allowlist") {
					t.Errorf("arg=%q code=%d stderr=%q, want exit 1 invalid allowlist", arg, code, stderr)
				}
			}
		})

		t.Run("NonLoopbackPprofRejected", func(t *testing.T) {
			t.Parallel()
			srv := newReqE2EAPIServer(t)
			kc := writeE2EKubeconfig(t, srv.URL())
			_, stderr, code := runManagerOnce(t, binPath, 10*time.Second, scrubbedKubeEnv("KUBECONFIG="+kc),
				"-metrics-bind-address=127.0.0.1:0",
				"-health-probe-bind-address=127.0.0.1:0",
				"-pprof-bind-address=0.0.0.0:"+freeLoopbackPort(t),
				"-modules=evicted-pod-janitor",
			)
			if code != 1 {
				t.Errorf("expected non-zero exit for 0.0.0.0 pprof bind, got %d (stderr=%q)", code, stderr)
			}
		})

		t.Run("GofmtAndVetClean", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			fmtCmd := exec.Command("gofmt", "-l", "cmd/manager")
			fmtCmd.Dir = "../.."
			if out, err := fmtCmd.CombinedOutput(); err != nil || strings.TrimSpace(string(out)) != "" {
				t.Errorf("gofmt unformatted files (%v):\n%s", err, out)
			}
			vetCmd := exec.Command("go", "vet", "./cmd/manager")
			vetCmd.Dir = "../.."
			vetCmd.Env = append(scrubbedKubeEnv(), "GOWORK=off")
			if out, err := vetCmd.CombinedOutput(); err != nil {
				t.Errorf("go vet failed: %v\n%s", err, out)
			}
		})

		t.Run("SubSecondHealthIntervalClampedSafely", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			proc, _, probeURL := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=200ms"}, "pod-status-check,cluster-health-probes")
			code, _, err := httpGetBody(probeURL + "/readyz")
			if err != nil || code != http.StatusOK {
				t.Errorf("GET /readyz = (%d, %v), want 200", code, err)
			}
			proc.stopWithSIGINTAndAssertZero(t, 15*time.Second)
		})
	})

	t.Run("F4_APIServerEndpointGuardBoundary", func(t *testing.T) {
		t.Parallel()
		t.Run("SingleControllerNeverEditsEndpoints", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.setVersion("1", "34")
			srv.addEndpointSlice(makeKubernetesSlice("kubernetes", "10.0.0.1", "", ""))
			proc, _, _ := startReqManager(t, binPath, srv, nil, "apiserver-endpoint-guard")
			srv.waitForRequest(t, proc, 45*time.Second, "EndpointSlice list", func(r reqRecord) bool {
				return r.Method == http.MethodGet && strings.Contains(r.Path, "endpointslices")
			})
			if edits := srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodPatch || r.Method == http.MethodPut || r.Method == http.MethodDelete
			}); edits != 0 {
				t.Errorf("expected 0 writes on single-controller cluster, got %d", edits)
			}
		})

		t.Run("ZeroBackendsLogsWithoutErrorBump", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.setVersion("1", "32")
			srv.addEndpoints(makeKubernetesEndpoints())
			proc, metricsURL, _ := startReqManager(t, binPath, srv, nil, "apiserver-endpoint-guard")
			srv.waitForRequest(t, proc, 45*time.Second, "Endpoints GET", func(r reqRecord) bool {
				return r.Method == http.MethodGet && strings.Contains(r.Path, "/endpoints")
			})
			samples := scrapeMetrics(t, metricsURL)
			if v, ok := findMetric(samples, "shell_operator_hook_run_errors_total", map[string]string{"queue": "apiserver-endpoint-guard"}); !ok || v != 0 {
				t.Errorf("hook errors = (%v,%v), want (0,true)", v, ok)
			}
		})

		t.Run("UnparseableVersionFallsBackToEndpoints", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.setVersionRaw(`{"major":"1","minor":"not-a-num","gitVersion":"v1.x"}`)
			srv.addEndpoints(makeKubernetesEndpoints("10.0.0.1", "10.0.0.2"))
			proc, _, _ := startReqManager(t, binPath, srv, nil, "apiserver-endpoint-guard")
			srv.waitForRequest(t, proc, 45*time.Second, "Endpoints fallback GET", func(r reqRecord) bool {
				return r.Method == http.MethodGet && strings.Contains(r.Path, "/api/v1/namespaces/default/endpoints")
			})
		})

		t.Run("MissingBothEndpointsAndSliceIncrementsError", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.setVersion("1", "34")
			proc, metricsURL, _ := startReqManager(t, binPath, srv, nil, "apiserver-endpoint-guard")
			waitForMetric(t, metricsURL, proc, 45*time.Second, "hook error >= 1", func(s []metricSample) bool {
				v, ok := findMetric(s, "shell_operator_hook_run_errors_total", map[string]string{"queue": "apiserver-endpoint-guard"})
				return ok && v >= 1
			})
		})

		t.Run("GracefulShutdownZero", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			proc, _, _ := startReqManager(t, binPath, srv, nil, "apiserver-endpoint-guard")
			proc.stopWithSIGINTAndAssertZero(t, 15*time.Second)
		})
	})

	t.Run("F6_CELPolicyBoundary", func(t *testing.T) {
		t.Parallel()
		t.Run("UnresolvableParamKindOnBrokenPolicyStaysUnverifiable", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			ign := admissionv1.Ignore
			failPol := admissionv1.Fail
			srv.addVAP(&admissionv1.ValidatingAdmissionPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "vap-broken-unresolvable",
					Annotations: map[string]string{"passiontech.dev/circuit-broken-cel-policy": "2026-11-22T00:00:00Z missing_param_ref"},
				},
				Spec: admissionv1.ValidatingAdmissionPolicySpec{
					FailurePolicy: &ign,
					ParamKind:     &admissionv1.ParamKind{APIVersion: "missing.example.com/v1", Kind: "GhostParam"},
				},
			})
			srv.addVAPB(&admissionv1.ValidatingAdmissionPolicyBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "vapb-broken"},
				Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
					PolicyName: "vap-broken-unresolvable",
					ParamRef:   &admissionv1.ParamRef{Name: "p1", Namespace: "default"},
				},
			})
			// Fail-closed policy with unresolvable ParamKind must stay Fail (never tripped to Ignore).
			srv.addVAP(&admissionv1.ValidatingAdmissionPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "vap-fail-unresolvable"},
				Spec: admissionv1.ValidatingAdmissionPolicySpec{
					FailurePolicy: &failPol,
					ParamKind:     &admissionv1.ParamKind{APIVersion: "missing.example.com/v1", Kind: "GhostParam"},
				},
			})
			srv.addVAPB(&admissionv1.ValidatingAdmissionPolicyBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "vapb-fail-unresolvable"},
				Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
					PolicyName: "vap-fail-unresolvable",
					ParamRef:   &admissionv1.ParamRef{Name: "p2", Namespace: "default"},
				},
			})
			promURL := startMockPromServer(t, func(string) []map[string]any { return nil })
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"HEALTH_PROMETHEUS_QUERY_URL=" + promURL}, "admission-webhook-guard")
			samples := waitForMetric(t, metricsURL, proc, 55*time.Second, "circuit_broken=1", func(s []metricSample) bool {
				v, ok := findMetric(s, "node_automation_cel_policy_circuit_broken", map[string]string{"policy": "vap-broken-unresolvable"})
				return ok && v == 1
			})
			if n := srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/apis/missing.example.com/v1"
			}); n == 0 {
				t.Errorf("expected Discovery GET /apis/missing.example.com/v1 for unresolvable ParamKind")
			}
			if patches := srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodPatch && (strings.Contains(r.Path, "vap-broken-unresolvable") || strings.Contains(r.Path, "vap-fail-unresolvable"))
			}); patches > 0 {
				t.Errorf("expected 0 PATCHes on unverifiable ParamKind policies (must neither restore broken nor trip Fail policy), got %d", patches)
			}
			if v, ok := findMetric(samples, "shell_operator_hook_run_errors_total", map[string]string{"queue": "admission-webhook-guard"}); !ok || v != 0 {
				t.Errorf("expected 0 hook errors when Discovery returns 404 for ParamKind, got (%v,%v)", v, ok)
			}
		})

		t.Run("CELPolicy403ForbiddenSkipsGracefully", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addErrorRule(http.MethodGet, "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies", http.StatusForbidden, -1)
			promURL := startMockPromServer(t, func(string) []map[string]any { return nil })
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"HEALTH_PROMETHEUS_QUERY_URL=" + promURL}, "admission-webhook-guard")
			srv.waitForRequest(t, proc, 55*time.Second, "VAP 403 list", func(r reqRecord) bool {
				return r.Method == http.MethodGet && strings.HasSuffix(r.Path, "/validatingadmissionpolicies")
			})
			srv.waitForRequest(t, proc, 55*time.Second, "MAP list after VAP 403", func(r reqRecord) bool {
				return r.Method == http.MethodGet && strings.HasSuffix(r.Path, "/mutatingadmissionpolicies")
			})
			samples := waitForMetric(t, metricsURL, proc, 15*time.Second, "hook_run_errors_total == 0", func(s []metricSample) bool {
				v, ok := findMetric(s, "shell_operator_hook_run_errors_total", map[string]string{"queue": "admission-webhook-guard"})
				return ok && v == 0
			})
			if v, ok := findMetric(samples, "shell_operator_hook_run_errors_total", map[string]string{"queue": "admission-webhook-guard"}); !ok || v != 0 {
				t.Errorf("hook errors = (%v,%v), want (0,true) on 403", v, ok)
			}
		})

		t.Run("CriticalNSEnforceDisabledEmitsGaugeWithoutPatch", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			fp := admissionv1.Fail
			podRules := &admissionv1.MatchResources{
				ResourceRules: []admissionv1.NamedRuleWithOperations{{
					RuleWithOperations: admissionv1.RuleWithOperations{
						Operations: []admissionv1.OperationType{admissionv1.Create},
						Rule:       admissionv1.Rule{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"pods"}},
					},
				}},
			}
			srv.addVAP(&admissionv1.ValidatingAdmissionPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "vap-crit-audit"},
				Spec:       admissionv1.ValidatingAdmissionPolicySpec{FailurePolicy: &fp, MatchConstraints: podRules},
			})
			promURL := startMockPromServer(t, func(string) []map[string]any { return nil })
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{
				"CEL_POLICY_CRITICAL_NS_ENFORCE_ENABLED=false",
				"HEALTH_PROMETHEUS_QUERY_URL=" + promURL,
			}, "admission-webhook-guard")
			waitForMetric(t, metricsURL, proc, 55*time.Second, "critical_ns_exposed=1", func(s []metricSample) bool {
				v, ok := findMetric(s, "node_automation_cel_policy_critical_ns_exposed", map[string]string{"policy": "vap-crit-audit", "namespace": "kube-system"})
				return ok && v == 1
			})
			if patches := srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodPatch && strings.Contains(r.Path, "vap-crit-audit")
			}); patches > 0 {
				t.Errorf("expected 0 PATCHes when CEL_POLICY_CRITICAL_NS_ENFORCE_ENABLED=false, got %d", patches)
			}
		})

		t.Run("ParameterNotFoundActionAllowSkipsLookup", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			allowAct := admissionv1.AllowAction
			fp := admissionv1.Fail
			srv.registerDiscoveryGroup("example.com", "v1", metav1.APIResource{Name: "widgets", Namespaced: true, Kind: "Widget"})
			srv.addVAP(&admissionv1.ValidatingAdmissionPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "vap-allow-param"},
				Spec: admissionv1.ValidatingAdmissionPolicySpec{
					FailurePolicy: &fp,
					ParamKind:     &admissionv1.ParamKind{APIVersion: "example.com/v1", Kind: "Widget"},
				},
			})
			srv.addVAPB(&admissionv1.ValidatingAdmissionPolicyBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "vapb-allow-param"},
				Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
					PolicyName: "vap-allow-param",
					ParamRef: &admissionv1.ParamRef{
						Name:                    "missing-widget",
						Namespace:               "default",
						ParameterNotFoundAction: &allowAct,
					},
				},
			})
			proc, _, _ := startReqManager(t, binPath, srv, nil, "admission-webhook-guard")
			srv.waitForRequest(t, proc, 55*time.Second, "VAPB list", func(r reqRecord) bool {
				return r.Method == http.MethodGet && strings.HasSuffix(r.Path, "/validatingadmissionpolicybindings")
			})
			if gets := srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodGet && strings.Contains(r.Path, "/widgets/missing-widget")
			}); gets > 0 {
				t.Errorf("expected 0 widget GETs when ParameterNotFoundAction=Allow, got %d", gets)
			}
		})

		t.Run("MaintenanceHoldBlocksCriticalNSPatch", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addNode(&corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "cordoned-maint"},
				Spec: corev1.NodeSpec{
					Unschedulable: true,
					Taints:        []corev1.Taint{{Key: "node.kubernetes.io/unschedulable", Effect: corev1.TaintEffectNoSchedule, TimeAdded: &metav1.Time{Time: time.Now().Add(-5 * time.Minute)}}},
				},
				Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}},
			})
			fp := admissionv1.Fail
			podRules := &admissionv1.MatchResources{
				ResourceRules: []admissionv1.NamedRuleWithOperations{{
					RuleWithOperations: admissionv1.RuleWithOperations{
						Operations: []admissionv1.OperationType{admissionv1.Create},
						Rule:       admissionv1.Rule{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"pods"}},
					},
				}},
			}
			srv.addVAP(&admissionv1.ValidatingAdmissionPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "vap-hold"},
				Spec:       admissionv1.ValidatingAdmissionPolicySpec{FailurePolicy: &fp, MatchConstraints: podRules},
			})
			promURL := startMockPromServer(t, func(string) []map[string]any { return nil })
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"HEALTH_PROMETHEUS_QUERY_URL=" + promURL}, "admission-webhook-guard")
			samples := waitForMetric(t, metricsURL, proc, 55*time.Second, "critical_ns_exposed=1", func(s []metricSample) bool {
				v, ok := findMetric(s, "node_automation_cel_policy_critical_ns_exposed", map[string]string{"policy": "vap-hold", "namespace": "kube-system"})
				return ok && v == 1
			})
			if patches := srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodPatch && strings.Contains(r.Path, "vap-hold")
			}); patches > 0 {
				t.Errorf("expected 0 PATCHes during active cordon maintenance hold, got %d", patches)
			}
			if v, ok := findMetric(samples, "shell_operator_hook_run_errors_total", map[string]string{"queue": "admission-webhook-guard"}); !ok || v != 0 {
				t.Errorf("hook errors = (%v,%v), want (0,true)", v, ok)
			}
		})
	})

	t.Run("F7_BoundedPodLogReadsBoundary", func(t *testing.T) {
		t.Parallel()
		t.Run("MultiContainerWithoutPostgresContainerSkipped", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addPod(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "db", Name: "multi-0", Labels: map[string]string{"cnpg.io/cluster": "c1"}},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "sidecar-a", Image: "busybox"},
						{Name: "sidecar-b", Image: "busybox"},
					},
				},
				Status: corev1.PodStatus{Phase: corev1.PodRunning},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "postgres-wal-archive-guard,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "postgres OK", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "postgres-wal-archive-guard", "status": "OK"})
				return ok && v == 1
			})
			if logs := srv.requestCount(func(r reqRecord) bool { return strings.HasSuffix(r.Path, "/log") }); logs > 0 {
				t.Errorf("expected 0 log requests for non-postgres multi-container pod, got %d", logs)
			}
		})

		t.Run("PodLog500InconclusiveLogsWarnWithoutFalseFinding", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addPod(makePostgresPod("db", "pg-err", "pg-err-cluster"))
			srv.setPodLog("db", "pg-err", "postgres", http.StatusInternalServerError, []byte("err"))
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "postgres-wal-archive-guard,cluster-health-probes")
			samples := waitForMetric(t, metricsURL, proc, 15*time.Second, "postgres inconclusive completes sweep", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "postgres-wal-archive-guard", "status": "OK"})
				return ok && v == 1
			})
			if !strings.Contains(proc.stderr.String(), "WARN: postgres log fetch failed") {
				t.Errorf("expected WARN log for inconclusive 500 pod log, got stderr:\n%s", proc.stderr.String())
			}
			if v, ok := sumMetric(samples, "node_automation_postgres_wal_archive_unhealthy", map[string]string{"cluster": "pg-err-cluster"}); ok && v > 0 {
				t.Errorf("expected no false wal unhealthy gauge on 500 pod log, got %v", v)
			}
		})

		t.Run("YoungCloudflaredPodSkipsLogScan", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addPod(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "cf-young", CreationTimestamp: metav1.NewTime(time.Now().Add(-1 * time.Minute))},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "cloudflared", Image: "cloudflare/cloudflared:2025.1"}}},
				Status:     corev1.PodStatus{Phase: corev1.PodRunning},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "cloudflared-tunnel-health,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "cloudflared OK", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "cloudflared-tunnel-health", "status": "OK"})
				return ok && v == 1
			})
			if logs := srv.requestCount(func(r reqRecord) bool { return strings.HasSuffix(r.Path, "/log") }); logs > 0 {
				t.Errorf("expected 0 log requests for young <5m cloudflared pod, got %d", logs)
			}
		})

		t.Run("CloudflaredBenignBufferWarningIgnored", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addPod(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "cf-benign", CreationTimestamp: metav1.NewTime(time.Now().Add(-10 * time.Minute))},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "cloudflared", Image: "cloudflare/cloudflared:2025.1"}}},
				Status:     corev1.PodStatus{Phase: corev1.PodRunning},
			})
			srv.setPodLog("edge", "cf-benign", "", http.StatusOK, []byte("WRN failed to sufficiently increase receive buffer size\n"))
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "cloudflared-tunnel-health,cluster-health-probes")
			samples := waitForMetric(t, metricsURL, proc, 15*time.Second, "cloudflared log read + OK", func(s []metricSample) bool {
				if srv.requestCount(func(r reqRecord) bool {
					return strings.HasSuffix(r.Path, "/cf-benign/log")
				}) == 0 {
					return false
				}
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "cloudflared-tunnel-health", "status": "OK"})
				return ok && v == 1
			})
			if v, ok := findMetric(samples, "node_automation_cloudflared_tunnel_degraded", map[string]string{"pod": "cf-benign"}); ok && v == 1 {
				t.Errorf("benign UDP buffer warning must not trigger degraded gauge")
			}
		})

		t.Run("LinkerdH2LogErrorInconclusiveNoDelete", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addPod(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "meshed-err", CreationTimestamp: metav1.NewTime(time.Now().Add(-10 * time.Minute))},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app", Image: "app:v1"},
						{Name: "linkerd-proxy", Image: "cr.l5d.io/linkerd/proxy:v2"},
					},
				},
				Status: corev1.PodStatus{Phase: corev1.PodRunning},
			})
			srv.setPodLog("apps", "meshed-err", "linkerd-proxy", http.StatusInternalServerError, []byte("boom"))
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "linkerd-h2-stream-guard,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "linkerd log 500 + OK", func(s []metricSample) bool {
				if srv.requestCount(func(r reqRecord) bool {
					return strings.HasSuffix(r.Path, "/meshed-err/log")
				}) == 0 {
					return false
				}
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "linkerd-h2-stream-guard", "status": "OK"})
				return ok && v == 1
			})
			if dels := srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodDelete && strings.Contains(r.Path, "meshed-err")
			}); dels > 0 {
				t.Errorf("expected 0 pod deletes on log read error, got %d", dels)
			}
		})
	})

	t.Run("F11_GuardstateTLSProbeBoundary", func(t *testing.T) {
		t.Parallel()
		t.Run("SixWebhookServicesBoundedConcurrentPool", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			bh1 := startBlackholeTCPListener(t)
			bh2 := startBlackholeTCPListener(t)
			hl := startHealthyTLSListener(t)
			srv := newReqE2EAPIServer(t)
			seedWebhookService(srv, "apps", "svc-bh1", "127.0.0.1", bh1.port, "n1")
			seedWebhookService(srv, "apps", "svc-bh2", "127.0.0.1", bh2.port, "n1")
			for i := range 4 {
				name := fmt.Sprintf("svc-ok-%d", i)
				seedWebhookService(srv, "apps", name, "127.0.0.1", hl.port, "n1")
				srv.addMWC(makeMWC("mwc-ok-"+name, "apps", name, hl.port))
			}
			srv.addMWC(makeMWC("mwc-bh1", "apps", "svc-bh1", bh1.port))
			srv.addMWC(makeMWC("mwc-bh2", "apps", "svc-bh2", bh2.port))
			proc, _, _ := startReqManager(t, binPath, srv, nil, "admission-webhook-guard")
			srv.waitForRequest(t, proc, 55*time.Second, "post-breaker VAP list", func(r reqRecord) bool {
				return r.Method == http.MethodGet && strings.HasSuffix(r.Path, "/validatingadmissionpolicies")
			})
			acceptAt, ok := bh1.firstAcceptTime()
			if !ok {
				t.Fatalf("expected blackhole listener 1 Accept")
			}
			vapReq := srv.requestsMatching(func(r reqRecord) bool {
				return r.Method == http.MethodGet && strings.HasSuffix(r.Path, "/validatingadmissionpolicies")
			})[0]
			if delta := vapReq.At.Sub(acceptAt); delta > 6*time.Second {
				t.Errorf("concurrent pool with 2 blackholes took %s, want <=6s", delta)
			}
		})

		t.Run("EndpointOnUnhealthyNodeNotDialed", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			bh := startBlackholeTCPListener(t)
			srv := newReqE2EAPIServer(t)
			srv.addNode(&corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "bad-node"},
				Status:     corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionFalse}}},
			})
			srv.addService(&corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "badnode-wh"},
				Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Name: "webhook", Port: bh.port}}},
			})
			ready := true
			nn := "bad-node"
			srv.addEndpointSlice(&discoveryv1.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "apps", Name: "badnode-wh-1",
					Labels: map[string]string{"kubernetes.io/service-name": "badnode-wh"},
				},
				Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"127.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}, NodeName: &nn}},
				Ports:     []discoveryv1.EndpointPort{{Port: &bh.port}},
			})
			srv.addMWC(makeMWC("mwc-badnode", "apps", "badnode-wh", bh.port))
			proc, _, _ := startReqManager(t, binPath, srv, nil, "admission-webhook-guard")
			srv.waitForRequest(t, proc, 55*time.Second, "post-breaker VAP list", func(r reqRecord) bool {
				return r.Method == http.MethodGet && strings.HasSuffix(r.Path, "/validatingadmissionpolicies")
			})
			if c := bh.acceptCount(); c != 0 {
				t.Errorf("expected 0 dials to endpoint on NotReady node, got %d", c)
			}
		})

		t.Run("MultiPortEndpointSliceSelectsWebhookPort", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			metricsBH := startBlackholeTCPListener(t)
			webhookTLS := startHealthyTLSListener(t)
			srv := newReqE2EAPIServer(t)
			srv.addNode(&corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "n1"},
				Status:     corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}},
			})
			srv.addService(&corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "multiport-wh"},
				Spec: corev1.ServiceSpec{
					Ports: []corev1.ServicePort{
						{Name: "metrics", Port: metricsBH.port},
						{Name: "webhook", Port: webhookTLS.port},
					},
				},
			})
			ready := true
			nn := "n1"
			mName, wName := "metrics", "webhook"
			srv.addEndpointSlice(&discoveryv1.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "apps", Name: "multiport-wh-1",
					Labels: map[string]string{"kubernetes.io/service-name": "multiport-wh"},
				},
				Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"127.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}, NodeName: &nn}},
				Ports:     []discoveryv1.EndpointPort{{Name: &mName, Port: &metricsBH.port}, {Name: &wName, Port: &webhookTLS.port}},
			})
			srv.addMWC(makeMWC("mwc-multiport", "apps", "multiport-wh", webhookTLS.port))
			proc, _, _ := startReqManager(t, binPath, srv, nil, "admission-webhook-guard")
			srv.waitForRequest(t, proc, 55*time.Second, "post-breaker VAP list", func(r reqRecord) bool {
				return r.Method == http.MethodGet && strings.HasSuffix(r.Path, "/validatingadmissionpolicies")
			})
			if c := metricsBH.acceptCount(); c != 0 {
				t.Errorf("expected 0 dials to non-webhook metrics port, got %d", c)
			}
		})

		t.Run("ZeroReadyEndpointsSkipsTCPDial", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			bh := startBlackholeTCPListener(t)
			srv := newReqE2EAPIServer(t)
			srv.addService(&corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "zero-wh"},
				Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Name: "webhook", Port: bh.port}}},
			})
			notReady := false
			srv.addEndpointSlice(&discoveryv1.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "apps", Name: "zero-wh-1",
					Labels: map[string]string{"kubernetes.io/service-name": "zero-wh"},
				},
				Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"127.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: &notReady}}},
				Ports:     []discoveryv1.EndpointPort{{Port: &bh.port}},
			})
			srv.addMWC(makeMWC("mwc-zero", "apps", "zero-wh", bh.port))
			proc, _, _ := startReqManager(t, binPath, srv, nil, "admission-webhook-guard")
			srv.waitForRequest(t, proc, 55*time.Second, "post-breaker VAP list", func(r reqRecord) bool {
				return r.Method == http.MethodGet && strings.HasSuffix(r.Path, "/validatingadmissionpolicies")
			})
			if c := bh.acceptCount(); c != 0 {
				t.Errorf("expected 0 TCP dials for zero ready endpoints, got %d", c)
			}
		})

		t.Run("SIGINTMidBlackholeDialShutsDownCleanly", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			bh := startBlackholeTCPListener(t)
			srv := newReqE2EAPIServer(t)
			seedWebhookService(srv, "apps", "sigint-bh", "127.0.0.1", bh.port, "n1")
			srv.addMWC(makeMWC("mwc-sigint-bh", "apps", "sigint-bh", bh.port))
			proc, _, _ := startReqManager(t, binPath, srv, nil, "admission-webhook-guard")
			deadline := time.Now().Add(55 * time.Second)
			for time.Now().Before(deadline) && bh.acceptCount() == 0 {
				time.Sleep(50 * time.Millisecond)
			}
			if bh.acceptCount() == 0 {
				t.Fatalf("timed out waiting for blackhole dial")
			}
			proc.stopWithSIGINTAndAssertZero(t, 10*time.Second)
		})
	})

	t.Run("F12_FluxPatchGateBoundary", func(t *testing.T) {
		t.Parallel()
		t.Run("CooldownHeldFluxTargetDoesNotIncrementConflict", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			one := int32(1)
			oldCond := metav1.NewTime(time.Now().Add(-30 * time.Minute))
			freshCooldown := time.Now().Add(-5 * time.Minute).UTC().Format(time.RFC3339)
			srv.addDeployment(&appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:     "apps",
					Name:          "dep-cooled-flux",
					ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "helm-controller"}},
					Annotations:   map[string]string{"passiontech.dev/last-deployment-unstick": freshCooldown},
				},
				Spec: appsv1.DeploymentSpec{Replicas: &one},
				Status: appsv1.DeploymentStatus{
					Conditions: []appsv1.DeploymentCondition{{
						Type: appsv1.DeploymentProgressing, Status: corev1.ConditionFalse,
						Reason: "ProgressDeadlineExceeded", LastTransitionTime: oldCond,
					}},
				},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{
				"CLUSTER_HEALTH_PROBES_INTERVAL=1s",
				"NODE_AUTOMATION_HEAL_FLUX_CONFLICT_LOOP_MAX=1",
			}, "deployment-rollout-wedge,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "rollout wedge FAIL", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "deployment-rollout-wedge", "status": "FAIL"})
				return ok && v == 1
			})
			samples := scrapeMetrics(t, metricsURL)
			if v, ok := sumMetric(samples, "node_automation_heal_gitops_conflict_total", nil); ok && v > 0 {
				t.Errorf("cooldown-held Flux target incremented gitops_conflict_total=%v, want 0 (HealAllowed must run before FluxPatchGate)", v)
			}
		})

		t.Run("MaintenanceHoldBlocksFluxConflictCounter", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addDaemonSet(&appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:   "kube-system",
					Name:        "kured",
					Annotations: map[string]string{"weave.works/kured-node-lock": `{"nodeID":"w1"}`},
				},
			})
			srv.enableCRD(schema.GroupVersionResource{Group: "autoscaling", Version: "v2", Resource: "horizontalpodautoscalers"})
			oldStamp := time.Now().Add(-20 * time.Minute).UTC().Format(time.RFC3339)
			zero := int32(0)
			srv.addDeployment(&appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "apps", Name: "dep-maint-flux",
					ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "helm-controller"}},
				},
				Spec: appsv1.DeploymentSpec{Replicas: &zero},
			})
			srv.addCustomObject(schema.GroupVersionResource{Group: "autoscaling", Version: "v2", Resource: "horizontalpodautoscalers"}, makeUnhealthyHPA("apps", "hpa-maint", "dep-maint-flux", oldStamp))
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{
				"CLUSTER_HEALTH_PROBES_INTERVAL=1s",
				"NODE_AUTOMATION_HEAL_FLUX_CONFLICT_LOOP_MAX=1",
			}, "hpa-scaling-guard,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "hpa FAIL", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "hpa-scaling-guard", "status": "FAIL"})
				return ok && v == 1
			})
			samples := scrapeMetrics(t, metricsURL)
			if v, ok := sumMetric(samples, "node_automation_heal_gitops_conflict_total", nil); ok && v > 0 {
				t.Errorf("maintenance-held Flux target incremented gitops_conflict_total=%v, want 0", v)
			}
		})

		t.Run("FluxLoopMaxZeroDisablesGate", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.enableCRD(schema.GroupVersionResource{Group: "autoscaling", Version: "v2", Resource: "horizontalpodautoscalers"})
			oldStamp := time.Now().Add(-20 * time.Minute).UTC().Format(time.RFC3339)
			zero := int32(0)
			srv.addDeployment(&appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "apps", Name: "dep-loop0-flux", ResourceVersion: "1",
					ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "helm-controller"}},
				},
				Spec: appsv1.DeploymentSpec{Replicas: &zero},
			})
			srv.addCustomObject(schema.GroupVersionResource{Group: "autoscaling", Version: "v2", Resource: "horizontalpodautoscalers"}, makeUnhealthyHPA("apps", "hpa-loop0", "dep-loop0-flux", oldStamp))
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{
				"CLUSTER_HEALTH_PROBES_INTERVAL=1s",
				"NODE_AUTOMATION_HEAL_FLUX_CONFLICT_LOOP_MAX=0",
			}, "hpa-scaling-guard,cluster-health-probes")
			srv.waitForRequest(t, proc, 15*time.Second, "dep-loop0-flux PATCH", func(r reqRecord) bool {
				return r.Method == http.MethodPatch && r.Path == "/apis/apps/v1/namespaces/apps/deployments/dep-loop0-flux"
			})
			samples := scrapeMetrics(t, metricsURL)
			if v, ok := sumMetric(samples, "node_automation_heal_gitops_conflict_total", nil); ok && v > 0 {
				t.Errorf("expected 0 gitops conflicts when LOOP_MAX=0, got %v", v)
			}
		})

		t.Run("SubPathDeploymentList500RetriesNextSweep", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addErrorRule(http.MethodGet, "/apis/apps/v1/deployments", http.StatusInternalServerError, 1)
			proc, _, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "subpath-config-drift,cluster-health-probes")
			srv.waitForRequest(t, proc, 15*time.Second, "2nd deployments list after 500", func(r reqRecord) bool {
				return srv.requestCount(func(x reqRecord) bool {
					return x.Method == http.MethodGet && x.Path == "/apis/apps/v1/deployments"
				}) >= 2
			})
		})

		t.Run("RolloutWedgeConflictReleasesWorkloadReservation", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			one := int32(1)
			oldCond := metav1.NewTime(time.Now().Add(-30 * time.Minute))
			// Flux-managed wedged Deployment whose template already covers linkerd opaque-ports 6379.
			// When deployment-rollout-wedge hits FluxPatchGate at LOOP_MAX=1, it must call ReleaseWorkloadKey
			// AND RefundGrant so linkerd-protocol-detection-stall can reserve apps/Deployment/shared-workload
			// and delete the stale meshed pod in the SAME sweep.
			srv.addDeployment(&appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "apps", Name: "shared-workload", UID: "dep-shared",
					ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "helm-controller"}},
				},
				Spec: appsv1.DeploymentSpec{
					Replicas: &one,
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Annotations: map[string]string{"config.linkerd.io/opaque-ports": "6379"},
						},
					},
				},
				Status: appsv1.DeploymentStatus{
					Conditions: []appsv1.DeploymentCondition{{
						Type: appsv1.DeploymentProgressing, Status: corev1.ConditionFalse,
						Reason: "ProgressDeadlineExceeded", LastTransitionTime: oldCond,
					}},
				},
			})
			ctrl := true
			srv.addReplicaSet(&appsv1.ReplicaSet{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "apps", Name: "shared-workload-rs", UID: "rs-shared",
					OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "shared-workload", UID: "dep-shared", Controller: &ctrl}},
				},
			})
			srv.addPod(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "apps", Name: "shared-workload-rs-pod", UID: "pod-shared",
					OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "shared-workload-rs", UID: "rs-shared", Controller: &ctrl}},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app", Image: "redis:7", Ports: []corev1.ContainerPort{{ContainerPort: 6379}}},
						{Name: "linkerd-proxy", Image: "cr.l5d.io/linkerd/proxy:v2"},
					},
				},
				Status: corev1.PodStatus{Phase: corev1.PodRunning},
			})
			// Ensure linkerd-protocol-detection-stall (which uses metadata-only AllReplicaSets) finishes its
			// census after deployment-rollout-wedge (which uses typed AllTypedReplicaSets) hits FluxPatchGate
			// in the same sweep, so linkerd exercises the released workload reservation & refunded grant.
			srv.addDelayRule(http.MethodGet, "/apis/apps/v1/replicasets", "PartialObjectMetadataList", 150*time.Millisecond)
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{
				"CLUSTER_HEALTH_PROBES_INTERVAL=5s",
				"NODE_AUTOMATION_HEAL_BUDGET_MAX=1",
				"NODE_AUTOMATION_HEAL_FLUX_CONFLICT_LOOP_MAX=1",
			}, "linkerd-protocol-detection-stall,deployment-rollout-wedge,cluster-health-probes")
			srv.waitForRequest(t, proc, 15*time.Second, "linkerd pod DELETE using released workload reservation", func(r reqRecord) bool {
				return r.Method == http.MethodDelete && r.Path == "/api/v1/namespaces/apps/pods/shared-workload-rs-pod"
			})
			samples := waitForMetric(t, metricsURL, proc, 15*time.Second, "gitops conflict >= 1", func(s []metricSample) bool {
				v, ok := findMetric(s, "node_automation_heal_gitops_conflict_total", map[string]string{"manager": "helm-controller"})
				return ok && v >= 1
			})
			if patches := srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodPatch && r.Path == "/apis/apps/v1/namespaces/apps/deployments/shared-workload"
			}); patches > 0 {
				t.Errorf("Flux-gated Deployment must not be patched at LOOP_MAX=1, got %d", patches)
			}
			if v, ok := findMetric(samples, "node_automation_heal_budget_exhausted_total", nil); ok && v > 0 {
				t.Errorf("budget_exhausted_total = %v, want 0 after FluxPatchGate RefundGrant", v)
			}
			if strings.Contains(proc.stderr.String(), "DEFER: workload disruption already reserved this sweep") {
				t.Errorf("workload reservation leaked after deployment-rollout-wedge FluxPatchGate denial:\n%s", proc.stderr.String())
			}
			waitForLog(t, proc, 15*time.Second, "linkerd delete log", "DELETE: linkerd protocol-detection stall")
			stderrStr := proc.stderr.String()
			idxSkip := strings.Index(stderrStr, "SKIP: rollout wedge nudge — Flux Heal-Revert Loop")
			idxDel := strings.Index(stderrStr, "DELETE: linkerd protocol-detection stall")
			if idxSkip < 0 || idxDel < 0 || idxSkip > idxDel {
				t.Errorf("expected deployment-rollout-wedge FluxPatchGate denial (idx=%d) before linkerd delete (idx=%d) in same sweep:\n%s",
					idxSkip, idxDel, stderrStr)
			}
		})
	})

	t.Run("F14_DeadNodeAndPartitionEvictorBoundary", func(t *testing.T) {
		t.Parallel()
		t.Run("DeadNodeOverrideFenceUnfencedStatefulTrue", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			seedDeadNodeWithPVC(srv, "dead-ov", "canary-ov", "apps", "pvc-ov", "pv-missing-ov", nil)
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"DEAD_NODE_SWEEPER_FENCE_UNFENCED_STATEFUL=true"}, "dead-node-sweeper")
			waitForMetric(t, metricsURL, proc, 55*time.Second, "fenced has_volumes=true", func(s []metricSample) bool {
				v, ok := findMetric(s, "node_automation_dead_node_fenced_without_snr_total", map[string]string{"node": "dead-ov", "has_volumes": "true"})
				return ok && v >= 1
			})
		})

		t.Run("DeadNodeUnboundPVCFencesNode", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			seedDeadNodeWithPVC(srv, "dead-unb", "canary-unb", "apps", "pvc-unb", "", nil)
			proc, metricsURL, _ := startReqManager(t, binPath, srv, nil, "dead-node-sweeper")
			waitForMetric(t, metricsURL, proc, 55*time.Second, "fenced has_volumes=false", func(s []metricSample) bool {
				v, ok := findMetric(s, "node_automation_dead_node_fenced_without_snr_total", map[string]string{"node": "dead-unb", "has_volumes": "false"})
				return ok && v >= 1
			})
		})

		t.Run("DeadNodeVolumeAttachmentMissingPVFailsClosed", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			oldTime := metav1.NewTime(time.Now().Add(-45 * time.Minute))
			srv.addNode(&corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "dead-va"},
				Status:     corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionUnknown, LastTransitionTime: oldTime}}},
			})
			srv.addNode(&corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "canary-va"},
				Status:     corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue, LastTransitionTime: oldTime}}},
			})
			srv.setNodeProxyHealthz("dead-va", http.StatusBadGateway, "error trying to reach service")
			srv.setNodeProxyHealthz("canary-va", http.StatusOK, "ok")
			delTS := metav1.NewTime(time.Now().Add(-20 * time.Minute))
			srv.addPod(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "stuck-va", DeletionTimestamp: &delTS},
				Spec:       corev1.PodSpec{NodeName: "dead-va"},
				Status:     corev1.PodStatus{Phase: corev1.PodRunning},
			})
			pvName := "pv-va-missing"
			srv.addVolumeAttachment(&storagev1.VolumeAttachment{
				ObjectMeta: metav1.ObjectMeta{Name: "va-missing-pv"},
				Spec:       storagev1.VolumeAttachmentSpec{NodeName: "dead-va", Source: storagev1.VolumeAttachmentSource{PersistentVolumeName: &pvName}},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, nil, "dead-node-sweeper")
			waitForMetric(t, metricsURL, proc, 55*time.Second, "va missing pv skipped=1", func(s []metricSample) bool {
				v, ok := findMetric(s, "node_automation_dead_node_unfenced_stateful_skipped", map[string]string{"node": "dead-va"})
				return ok && v == 1
			})
		})

		t.Run("PartitionEvictorMeshWideAbortHalfFlagged", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			oldTime := metav1.NewTime(time.Now().Add(-20 * time.Minute))
			for _, name := range []string{"w-p1", "w-p2"} {
				srv.addNode(&corev1.Node{
					ObjectMeta: metav1.ObjectMeta{Name: name},
					Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{
						{Type: corev1.NodeReady, Status: corev1.ConditionTrue, LastTransitionTime: oldTime},
						{Type: "ClusterNetworkProblems", Status: corev1.ConditionTrue, LastTransitionTime: oldTime},
					}},
				})
			}
			for _, name := range []string{"w-ok1", "w-ok2"} {
				srv.addNode(&corev1.Node{
					ObjectMeta: metav1.ObjectMeta{Name: name},
					Status:     corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue, LastTransitionTime: oldTime}}},
				})
			}
			srv.addPod(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "flux-system", Name: "src-1"},
				Spec:       corev1.PodSpec{NodeName: "w-p1"},
				Status:     corev1.PodStatus{Phase: corev1.PodRunning},
			})
			proc, _, _ := startReqManager(t, binPath, srv, nil, "partition-pod-evictor")
			srv.waitForRequest(t, proc, 55*time.Second, "live node confirm", func(r reqRecord) bool {
				return r.Method == http.MethodGet && strings.HasPrefix(r.Path, "/api/v1/nodes/w-p")
			})
			if muts := srv.requestCount(func(r reqRecord) bool {
				return (r.Method == http.MethodPatch && strings.HasPrefix(r.Path, "/api/v1/nodes/")) ||
					(r.Method == http.MethodPost && strings.HasSuffix(r.Path, "/eviction"))
			}); muts > 0 {
				t.Errorf("expected 0 taints/evictions on >=50%% mesh-wide partition, got %d", muts)
			}
		})

		t.Run("PartitionEvictorSkipsLocalPathPinnedPod", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			seedPartitionCluster(srv, "part-pin", 2, "flux-system", "pinned-pod", "local-path")
			proc, _, _ := startReqManager(t, binPath, srv, nil, "partition-pod-evictor")
			srv.waitForRequest(t, proc, 55*time.Second, "node taint PATCH", func(r reqRecord) bool {
				return r.Method == http.MethodPatch && r.Path == "/api/v1/nodes/part-pin"
			})
			if evicts := srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodPost && strings.HasSuffix(r.Path, "/eviction")
			}); evicts > 0 {
				t.Errorf("expected 0 evictions for local-path pinned pod, got %d", evicts)
			}
		})
	})

	t.Run("F16_ControllerAPILoadBoundary", func(t *testing.T) {
		t.Parallel()
		t.Run("HeavyScanCyclesRetryImmediatelyOn500", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addErrorRule(http.MethodGet, "/api/v1/serviceaccounts", http.StatusInternalServerError, 1)
			proc, _, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "imagepull-secret-auditor,cluster-health-probes")
			srv.waitForRequest(t, proc, 5*time.Second, "immediate retry of ServiceAccounts on cycle 2", func(r reqRecord) bool {
				return srv.requestCount(func(x reqRecord) bool {
					return x.Method == http.MethodGet && x.Path == "/api/v1/serviceaccounts"
				}) >= 2
			})
		})

		t.Run("WorkloadHistoryGC403GracefulSkip", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addErrorRule(http.MethodGet, "/apis/apps/v1/controllerrevisions", http.StatusForbidden, -1)
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "api-object-sprawl-report-gc,cluster-health-probes")
			samples := waitForMetric(t, metricsURL, proc, 15*time.Second, "controllerrevisions 403 + OK", func(s []metricSample) bool {
				if srv.requestCount(func(r reqRecord) bool {
					return r.Method == http.MethodGet && r.Path == "/apis/apps/v1/controllerrevisions"
				}) == 0 {
					return false
				}
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "api-object-sprawl-report-gc", "status": "OK"})
				return ok && v == 1
			})
			if v, ok := findMetric(samples, "shell_operator_hook_run_errors_total", map[string]string{"queue": "cluster-health-probes"}); !ok || v != 0 {
				t.Errorf("hook errors = (%v,%v), want (0,true) on 403", v, ok)
			}
		})

		t.Run("WorkloadHistoryGCDeleteCap30", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			oldTS := metav1.NewTime(time.Now().Add(-48 * time.Hour))
			zero := int32(0)
			ctrl := true
			for i := range 35 {
				srv.addReplicaSet(&appsv1.ReplicaSet{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "apps", Name: fmt.Sprintf("orphan-cap-%02d", i), UID: types.UID(fmt.Sprintf("rs-cap-%02d", i)),
						CreationTimestamp: oldTS,
						OwnerReferences:   []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: fmt.Sprintf("gone-%02d", i), UID: "gone", Controller: &ctrl}},
					},
					Spec: appsv1.ReplicaSetSpec{Replicas: &zero},
				})
			}
			proc, _, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "api-object-sprawl-report-gc,cluster-health-probes")
			srv.waitForRequest(t, proc, 15*time.Second, "30th orphan RS DELETE", func(r reqRecord) bool {
				return srv.requestCount(func(x reqRecord) bool {
					return x.Method == http.MethodDelete && strings.Contains(x.Path, "/replicasets/orphan-cap-")
				}) >= 30
			})
			dels := srv.requestCount(func(x reqRecord) bool {
				return x.Method == http.MethodDelete && strings.Contains(x.Path, "/replicasets/orphan-cap-")
			})
			if dels > 30 {
				t.Errorf("expected cycle 1 delete cap <= 30, got %d", dels)
			}
		})

		t.Run("GuardstateTargetsWebhookServicesWithoutFleetList", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			hl := startHealthyTLSListener(t)
			seedWebhookService(srv, "apps", "idx-wh-shared", "127.0.0.1", hl.port, "n1")
			srv.addMWC(makeMWC("mwc-idx-a", "apps", "idx-wh-shared", hl.port))
			srv.addVWC(makeVWC("vwc-idx-b", "apps", "idx-wh-shared", hl.port))
			proc, _, _ := startReqManager(t, binPath, srv, nil, "admission-webhook-guard")
			srv.waitForRequest(t, proc, 55*time.Second, "post-breaker VAP list", func(r reqRecord) bool {
				return r.Method == http.MethodGet && strings.HasSuffix(r.Path, "/validatingadmissionpolicies")
			})
			if lists := srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/api/v1/services"
			}); lists > 0 {
				t.Errorf("expected 0 fleet /api/v1/services LIST calls, got %d", lists)
			}
			if gets := srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/api/v1/namespaces/apps/services/idx-wh-shared"
			}); gets != 1 {
				t.Errorf("expected 1 deduplicated targeted GET to /services/idx-wh-shared across MWC+VWC+all duties, got %d", gets)
			}
		})

		t.Run("WorkloadHistoryGCOrphanLiveGetSafety", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			oldTS := metav1.NewTime(time.Now().Add(-48 * time.Hour))
			zero := int32(0)
			ctrl := true
			srv.addReplicaSet(&appsv1.ReplicaSet{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "apps", Name: "rs-live-confirm", UID: "rs-live-c", CreationTimestamp: oldTS,
					OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "dep-live-only", UID: "dep-live-uid", Controller: &ctrl}},
				},
				Spec: appsv1.ReplicaSetSpec{Replicas: &zero},
			})
			// Add deployment AFTER list or return 404 on list while Get succeeds: easiest is addDeployment + inject 500? No, inject empty list?
			// Instead, addDeployment so Get succeeds, and verify live Get confirms existence and skips Delete!
			srv.addDeployment(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "dep-live-only", UID: "dep-live-uid"}})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "api-object-sprawl-report-gc,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "sprawl OK", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "api-object-sprawl-report-gc", "status": "OK"})
				return ok && v == 1
			})
			if dels := srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodDelete && strings.Contains(r.Path, "rs-live-confirm")
			}); dels > 0 {
				t.Errorf("expected 0 deletes for RS whose owner Deployment exists, got %d", dels)
			}
		})
	})

	t.Run("F20_CIDockerfilesBoundary", func(t *testing.T) {
		t.Parallel()
		t.Run("CIWorkflowChecksDoesNotNeedDockerDetect", func(t *testing.T) {
			t.Parallel()
			raw := readRepoFile(t, "../../../../.github/workflows/ci.yml")
			var wf struct {
				Jobs map[string]struct {
					Needs any `yaml:"needs"`
				} `yaml:"jobs"`
			}
			if err := yaml.Unmarshal([]byte(raw), &wf); err != nil {
				t.Fatalf("parse ci.yml: %v", err)
			}
			checksJob, ok := wf.Jobs["checks"]
			if !ok {
				t.Fatalf("ci.yml missing jobs.checks")
			}
			switch v := checksJob.Needs.(type) {
			case nil:
			case string:
				if v == "docker-detect" {
					t.Errorf("ci.yml jobs.checks.needs = %q, must not depend on docker-detect", v)
				}
			case []any:
				for _, item := range v {
					if s, ok := item.(string); ok && s == "docker-detect" {
						t.Errorf("ci.yml jobs.checks.needs %v must not include docker-detect", v)
					}
				}
			case []string:
				if slices.Contains(v, "docker-detect") {
					t.Errorf("ci.yml jobs.checks.needs %v must not include docker-detect", v)
				}
			default:
				t.Fatalf("ci.yml jobs.checks.needs has unexpected type %T (%v)", checksJob.Needs, checksJob.Needs)
			}
		})

		t.Run("CIWorkflowCacheKeysNoRunIDThrash", func(t *testing.T) {
			t.Parallel()
			raw := readRepoFile(t, "../../../../.github/workflows/ci.yml")
			if strings.Contains(raw, "github.run_id") {
				t.Errorf("ci.yml cache keys still embed github.run_id causing 100%% cache miss thrash")
			}
		})

		t.Run("DockerfileBuilderUsesGolang1274Alpine", func(t *testing.T) {
			t.Parallel()
			raw := readRepoFile(t, "../../Dockerfile")
			if !strings.Contains(raw, "golang:1.27.4-alpine") {
				t.Errorf("Dockerfile builder does not use golang:1.27.4-alpine")
			}
		})

		t.Run("MoonYmlDeclaresInputs", func(t *testing.T) {
			t.Parallel()
			raw := readRepoFile(t, "../../moon.yml")
			for _, want := range []string{
				"language: 'go'",
				"inputs:",
				"docs/env.md",
				"/libs/hostkit/**/*.go",
				"/.github/workflows/ci.yml",
				"/.github/workflows/release-app.yml",
				"/.github/workflows/release-node-automation-controller.yml",
			} {
				if !strings.Contains(raw, want) {
					t.Errorf("moon.yml missing expected task input/declaration %q", want)
				}
			}
		})

		t.Run("ReleaseWorkflowMatchesCmdDeps", func(t *testing.T) {
			t.Parallel()
			cmd := exec.Command("go", "list", "-deps", "./cmd/manager")
			cmd.Dir = "../.."
			cmd.Env = append(scrubbedKubeEnv(), "GOWORK=off")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("go list -deps failed: %v\n%s", err, out)
			}
			rel := readRepoFile(t, "../../../../.github/workflows/release-node-automation-controller.yml")
			if !strings.Contains(string(out), "libs/hostkit/envx") || !strings.Contains(rel, "libs/hostkit/envx") {
				t.Errorf("expected release workflow and cmd deps to both include libs/hostkit/envx")
			}
		})
	})

	t.Run("F22_ControllerUnitCoverageBoundary", func(t *testing.T) {
		t.Parallel()
		t.Run("SubPathOptOutSkipsConfigMapGet", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			dep := makeSubPathDeployment("apps", "sub-optout", "cm-optout")
			dep.Annotations = map[string]string{"passiontech.dev/subpath-reload-opt-out": "true"}
			srv.addDeployment(dep)
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "subpath-config-drift,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "subpath OK", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "subpath-config-drift", "status": "OK"})
				return ok && v == 1
			})
			if gets := srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodGet && strings.Contains(r.Path, "cm-optout")
			}); gets > 0 {
				t.Errorf("expected 0 ConfigMap GETs for opted-out workload, got %d", gets)
			}
		})

		t.Run("TopologyVirtualKubeletExcluded", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addNode(&corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "vk-node",
					Labels: map[string]string{"topology.kubernetes.io/zone": "vk-zone", "type": "virtual-kubelet"},
				},
				Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionFalse}}},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "topology-spread-zone-deadlock,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "topology OK", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "topology-spread-zone-deadlock", "status": "OK"})
				return ok && v == 1
			})
		})

		t.Run("LinkerdSkipOutboundPortsAlreadyCovered", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addPod(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:   "apps",
					Name:        "meshed-covered",
					Annotations: map[string]string{"config.linkerd.io/skip-outbound-ports": "6379"},
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
			waitForMetric(t, metricsURL, proc, 15*time.Second, "linkerd OK", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "linkerd-protocol-detection-stall", "status": "OK"})
				return ok && v == 1
			})
		})

		t.Run("FailedJobsJanitorPVCWithUnreferencedFinalizerUnstuck", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			oldDel := metav1.NewTime(time.Now().Add(-3 * time.Hour))
			srv.addPVC(&corev1.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "apps", Name: "pvc-unstick", DeletionTimestamp: &oldDel,
					Finalizers: []string{"kubernetes.io/pvc-protection"},
				},
			})
			proc, _, _ := startReqManager(t, binPath, srv, nil, "failed-jobs-janitor")
			srv.waitForRequest(t, proc, 55*time.Second, "PVC finalizer PATCH", func(r reqRecord) bool {
				return r.Method == http.MethodPatch && r.Path == "/api/v1/namespaces/apps/persistentvolumeclaims/pvc-unstick"
			})
		})

		t.Run("PDBWatchdogHealthyZeroErrors", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addPDB(&policyv1.PodDisruptionBudget{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "ok-pdb"},
				Status:     policyv1.PodDisruptionBudgetStatus{ExpectedPods: 3, DesiredHealthy: 2, DisruptionsAllowed: 1},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, nil, "pdb-deadlock-watchdog")
			waitForLog(t, proc, 55*time.Second, "pdb-deadlock-watchdog sweep done", `"logger":"pdb-deadlock-watchdog","msg":"sweep done"`)
			if n := srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/apis/policy/v1/poddisruptionbudgets"
			}); n == 0 {
				t.Errorf("expected GET /apis/policy/v1/poddisruptionbudgets")
			}
			samples := scrapeMetrics(t, metricsURL)
			if v, ok := sumMetric(samples, "node_automation_pdb_drain_blocked", nil); ok && v > 0 {
				t.Errorf("expected 0 pdb_drain_blocked on healthy PDB, got %v", v)
			}
			if v, ok := findMetric(samples, "shell_operator_hook_run_errors_total", map[string]string{"queue": "pdb-deadlock-watchdog"}); !ok || v != 0 {
				t.Errorf("hook errors = (%v,%v), want (0,true)", v, ok)
			}
		})

		t.Run("CertDriftInvalidPEMTolerated", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addSecret(&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "bad-pem"},
				Type:       corev1.SecretTypeTLS,
				Data:       map[string][]byte{"tls.crt": []byte("not-a-valid-pem")},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, nil, "cert-drift-auditor")
			waitForLog(t, proc, 55*time.Second, "cert-drift-auditor invalid PEM skip log", "skip: tls secret carries no decodable tls.crt PEM")
			samples := scrapeMetrics(t, metricsURL)
			if v, ok := findMetric(samples, "shell_operator_hook_run_errors_total", map[string]string{"queue": "cert-drift-auditor"}); !ok || v != 0 {
				t.Errorf("hook errors = (%v,%v), want (0,true) on malformed PEM", v, ok)
			}
		})
	})

	t.Run("F25_VolumeSnapshotBoundary", func(t *testing.T) {
		t.Parallel()
		vsGVR := schema.GroupVersionResource{Group: "snapshot.storage.k8s.io", Version: "v1", Resource: "volumesnapshots"}
		vscGVR := schema.GroupVersionResource{Group: "snapshot.storage.k8s.io", Version: "v1", Resource: "volumesnapshotcontents"}

		t.Run("CRDAbsent404AutoSkipsCleanly", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "volumesnapshot-lifecycle-guard,cluster-health-probes")
			samples := waitForMetric(t, metricsURL, proc, 15*time.Second, "volumesnapshot OK on 404", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "volumesnapshot-lifecycle-guard", "status": "OK"})
				return ok && v == 1
			})
			if v, ok := findMetric(samples, "shell_operator_hook_run_errors_total", map[string]string{"queue": "cluster-health-probes"}); !ok || v != 0 {
				t.Errorf("hook errors = (%v,%v), want (0,true)", v, ok)
			}
		})

		t.Run("FreshVolumeSnapshotPasses", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addCustomObject(vsGVR, makeVolumeSnapshot("apps", "snap-fresh", false, time.Now().Add(-1*time.Minute), nil))
			srv.enableCRD(vscGVR)
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "volumesnapshot-lifecycle-guard,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "fresh snapshot OK", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "volumesnapshot-lifecycle-guard", "status": "OK"})
				return ok && v == 1
			})
		})

		t.Run("VolumeSnapshot403HandledGracefully", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.enableCRD(vsGVR)
			srv.addErrorRule(http.MethodGet, "/apis/snapshot.storage.k8s.io/v1/volumesnapshots", http.StatusForbidden, -1)
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "volumesnapshot-lifecycle-guard,cluster-health-probes")
			srv.waitForRequest(t, proc, 15*time.Second, "403 volumesnapshots list", func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/apis/snapshot.storage.k8s.io/v1/volumesnapshots"
			})
			samples := waitForMetric(t, metricsURL, proc, 15*time.Second, "volumesnapshot OK on 403", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "volumesnapshot-lifecycle-guard", "status": "OK"})
				return ok && v == 1
			})
			if v, ok := findMetric(samples, "shell_operator_hook_run_errors_total", map[string]string{"queue": "cluster-health-probes"}); !ok || v != 0 {
				t.Errorf("hook errors = (%v,%v), want (0,true) on 403", v, ok)
			}
		})

		t.Run("VolumeSnapshotStatusErrorFlagged", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			obj := makeVolumeSnapshot("apps", "snap-err", false, time.Now().Add(-4*time.Hour), nil)
			obj.Object["status"] = map[string]any{"readyToUse": false, "error": map[string]any{"message": "snapshot failed"}}
			srv.addCustomObject(vsGVR, obj)
			srv.enableCRD(vscGVR)
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "volumesnapshot-lifecycle-guard,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "errored snapshot FAIL", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "volumesnapshot-lifecycle-guard", "status": "FAIL"})
				return ok && v == 1
			})
		})

		t.Run("GateEnvFalseDisablesVolumeSnapshotGuard", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addCustomObject(vsGVR, makeVolumeSnapshot("apps", "snap-dis", false, time.Now().Add(-4*time.Hour), nil))
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{
				"CLUSTER_HEALTH_PROBES_INTERVAL=1s",
				"NODE_AUTOMATION_VOLUMESNAPSHOT_LIFECYCLE_GUARD_ENABLED=false",
			}, "volumesnapshot-lifecycle-guard,pod-status-check,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "pod-status-check OK", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "pod-status-check", "status": "OK"})
				return ok && v == 1
			})
			if lists := srv.requestCount(func(r reqRecord) bool {
				return strings.Contains(r.Path, "volumesnapshots")
			}); lists > 0 {
				t.Errorf("expected 0 volumesnapshot calls when gated off, got %d", lists)
			}
		})
	})

	t.Run("F27_GatewayAPIBoundary", func(t *testing.T) {
		t.Parallel()
		gcGVR := schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gatewayclasses"}
		gwGVR := schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"}
		httpGVR := schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "httproutes"}

		t.Run("AllGatewayCRDsAbsentAutoSkipsOK", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "gateway-route-health,cluster-health-probes")
			samples := waitForMetric(t, metricsURL, proc, 15*time.Second, "gateway OK on 404", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "gateway-route-health", "status": "OK"})
				return ok && v == 1
			})
			if v, ok := findMetric(samples, "shell_operator_hook_run_errors_total", map[string]string{"queue": "cluster-health-probes"}); !ok || v != 0 {
				t.Errorf("hook errors = (%v,%v), want (0,true)", v, ok)
			}
		})

		t.Run("GatewayClassAcceptedFalseAudited", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			oldCond := time.Now().Add(-30 * time.Minute).UTC().Format(time.RFC3339)
			srv.addCustomObject(gcGVR, &unstructured.Unstructured{
				Object: map[string]any{
					"apiVersion": "gateway.networking.k8s.io/v1", "kind": "GatewayClass",
					"metadata": map[string]any{"name": "cilium-bad", "creationTimestamp": oldCond},
					"spec":     map[string]any{"controllerName": "io.cilium/gateway-controller"},
					"status": map[string]any{
						"conditions": []any{map[string]any{"type": "Accepted", "status": "False", "reason": "InvalidParameters", "lastTransitionTime": oldCond}},
					},
				},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "gateway-route-health,cluster-health-probes")
			srv.waitForRequest(t, proc, 15*time.Second, "gatewayclasses list", func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/apis/gateway.networking.k8s.io/v1/gatewayclasses"
			})
			samples := waitForMetric(t, metricsURL, proc, 15*time.Second, "gateway-route-health FAIL on GatewayClass Accepted=False", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "gateway-route-health", "status": "FAIL"})
				return ok && v == 1
			})
			if v, ok := findMetric(samples, "shell_operator_hook_run_errors_total", map[string]string{"queue": "cluster-health-probes"}); !ok || v != 0 {
				t.Errorf("hook errors = (%v,%v), want (0,true)", v, ok)
			}
		})

		t.Run("HealthyProgrammedGatewayPasses", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			oldCond := time.Now().Add(-30 * time.Minute).UTC().Format(time.RFC3339)
			srv.addCustomObject(gcGVR, &unstructured.Unstructured{
				Object: map[string]any{
					"apiVersion": "gateway.networking.k8s.io/v1", "kind": "GatewayClass",
					"metadata": map[string]any{"name": "cilium"},
					"status":   map[string]any{"conditions": []any{map[string]any{"type": "Accepted", "status": "True", "lastTransitionTime": oldCond}}},
				},
			})
			srv.addCustomObject(gwGVR, &unstructured.Unstructured{
				Object: map[string]any{
					"apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
					"metadata": map[string]any{"name": "gw-ok", "namespace": "apps"},
					"spec":     map[string]any{"gatewayClassName": "cilium"},
					"status": map[string]any{
						"conditions": []any{
							map[string]any{"type": "Accepted", "status": "True", "lastTransitionTime": oldCond},
							map[string]any{"type": "Programmed", "status": "True", "lastTransitionTime": oldCond},
						},
					},
				},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "gateway-route-health,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "healthy gateway OK", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "gateway-route-health", "status": "OK"})
				return ok && v == 1
			})
		})

		t.Run("TLSRoute404WhileHTTPRoutePresentSkipsGracefully", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.enableCRD(httpGVR)
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "gateway-route-health,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "gateway OK", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "gateway-route-health", "status": "OK"})
				return ok && v == 1
			})
		})

		t.Run("Gateway403ForbiddenGraceful", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.enableCRD(gwGVR)
			srv.addErrorRule(http.MethodGet, "/apis/gateway.networking.k8s.io/v1/gateways", http.StatusForbidden, -1)
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "gateway-route-health,cluster-health-probes")
			srv.waitForRequest(t, proc, 15*time.Second, "403 gateways list", func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/apis/gateway.networking.k8s.io/v1/gateways"
			})
			samples := waitForMetric(t, metricsURL, proc, 15*time.Second, "gateway OK on 403", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "gateway-route-health", "status": "OK"})
				return ok && v == 1
			})
			if v, ok := findMetric(samples, "shell_operator_hook_run_errors_total", map[string]string{"queue": "cluster-health-probes"}); !ok || v != 0 {
				t.Errorf("hook errors = (%v,%v), want (0,true) on 403", v, ok)
			}
		})
	})

	t.Run("F28ctrl_ImagePullSecretBoundary", func(t *testing.T) {
		t.Parallel()
		t.Run("MissingPullSecretFlagged", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addPod(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "pod-miss-sec"},
				Spec: corev1.PodSpec{
					ImagePullSecrets: []corev1.LocalObjectReference{{Name: "does-not-exist"}},
					Containers:       []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
				},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "imagepull-secret-auditor,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "missing pullsecret gauge", func(s []metricSample) bool {
				v, ok := findMetric(s, "node_automation_imagepull_secret_unhealthy", map[string]string{"secret": "does-not-exist", "reason": "missing"})
				return ok && v == 1
			})
		})

		t.Run("WrongSecretTypeFlagged", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addSecret(&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "wrong-type-sec"},
				Type:       corev1.SecretTypeOpaque,
			})
			srv.addPod(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "pod-wrong-type"},
				Spec: corev1.PodSpec{
					ImagePullSecrets: []corev1.LocalObjectReference{{Name: "wrong-type-sec"}},
					Containers:       []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
				},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "imagepull-secret-auditor,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "unexpected_type gauge", func(s []metricSample) bool {
				v, ok := findMetric(s, "node_automation_imagepull_secret_unhealthy", map[string]string{"secret": "wrong-type-sec", "reason": "unexpected_type"})
				return ok && v == 1
			})
		})

		t.Run("MalformedDockerConfigJSONFlagged", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addSecret(&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "bad-json-sec"},
				Type:       corev1.SecretTypeDockerConfigJson,
				Data:       map[string][]byte{corev1.DockerConfigJsonKey: []byte(`{not valid json`)},
			})
			srv.addPod(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "pod-bad-json"},
				Spec: corev1.PodSpec{
					ImagePullSecrets: []corev1.LocalObjectReference{{Name: "bad-json-sec"}},
					Containers:       []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
				},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "imagepull-secret-auditor,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "malformed gauge", func(s []metricSample) bool {
				v, ok := findMetric(s, "node_automation_imagepull_secret_unhealthy", map[string]string{"secret": "bad-json-sec"})
				return ok && v == 1
			})
		})

		t.Run("SAPullSecretCoversPrivateRegistryPod", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addSecret(&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "sa-regcred"},
				Type:       corev1.SecretTypeDockerConfigJson,
				Data:       map[string][]byte{corev1.DockerConfigJsonKey: []byte(`{"auths":{"registry.internal.corp":{"auth":"dXNlcjpwYXNz"}}}`)},
			})
			srv.addServiceAccount(&corev1.ServiceAccount{
				ObjectMeta:       metav1.ObjectMeta{Namespace: "apps", Name: "app-sa"},
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: "sa-regcred"}},
			})
			srv.addPod(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "sa-pod"},
				Spec: corev1.PodSpec{
					ServiceAccountName: "app-sa",
					Containers:         []corev1.Container{{Name: "app", Image: "registry.internal.corp/team/app:v1.2.3"}},
				},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "imagepull-secret-auditor,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "sa pullsecret OK", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "imagepull-secret-auditor", "status": "OK"})
				return ok && v == 1
			})
		})

		t.Run("DockerHubShortImageNameTreatedAsPublic", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addPod(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "short-pub"},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "nginx", Image: "nginx:1.25"}}},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "imagepull-secret-auditor,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "short image OK", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "imagepull-secret-auditor", "status": "OK"})
				return ok && v == 1
			})
		})
	})

	t.Run("F29_DRABoundary", func(t *testing.T) {
		t.Parallel()
		rcGVR := schema.GroupVersionResource{Group: "resource.k8s.io", Version: "v1", Resource: "resourceclaims"}

		t.Run("DRACRDAbsent404AutoSkipsCleanly", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "dra-claim-wedge-guard,cluster-health-probes")
			samples := waitForMetric(t, metricsURL, proc, 15*time.Second, "dra OK on 404", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "dra-claim-wedge-guard", "status": "OK"})
				return ok && v == 1
			})
			if v, ok := findMetric(samples, "shell_operator_hook_run_errors_total", map[string]string{"queue": "cluster-health-probes"}); !ok || v != 0 {
				t.Errorf("hook errors = (%v,%v), want (0,true)", v, ok)
			}
		})

		t.Run("FreshUnallocatedClaimPasses", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addCustomObject(rcGVR, makeDRAResourceClaim("gpu-ns", "gpu-fresh", "", "", false, time.Now().Add(-30*time.Second), nil))
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "dra-claim-wedge-guard,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "fresh dra OK", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "dra-claim-wedge-guard", "status": "OK"})
				return ok && v == 1
			})
		})

		t.Run("DRA403ForbiddenGraceful", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.enableCRD(rcGVR)
			srv.addErrorRule(http.MethodGet, "/apis/resource.k8s.io/v1/resourceclaims", http.StatusForbidden, -1)
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "dra-claim-wedge-guard,cluster-health-probes")
			srv.waitForRequest(t, proc, 15*time.Second, "403 resourceclaims list", func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/apis/resource.k8s.io/v1/resourceclaims"
			})
			samples := waitForMetric(t, metricsURL, proc, 15*time.Second, "dra OK on 403", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "dra-claim-wedge-guard", "status": "OK"})
				return ok && v == 1
			})
			if v, ok := findMetric(samples, "shell_operator_hook_run_errors_total", map[string]string{"queue": "cluster-health-probes"}); !ok || v != 0 {
				t.Errorf("hook errors = (%v,%v), want (0,true) on 403", v, ok)
			}
		})

		t.Run("TerminatingStuckResourceClaimFlagged", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			delAt := time.Now().Add(-3 * time.Hour)
			srv.addCustomObject(rcGVR, makeDRAResourceClaim("gpu-ns", "gpu-term", "", "", true, delAt, &delAt))
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "dra-claim-wedge-guard,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "terminating dra FAIL", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "dra-claim-wedge-guard", "status": "FAIL"})
				return ok && v == 1
			})
		})

		t.Run("SharedReservationWithLivePodHandled", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addPod(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "gpu-ns", Name: "live-p", UID: "live-u"},
				Status:     corev1.PodStatus{Phase: corev1.PodRunning},
			})
			claim := makeDRAResourceClaim("gpu-ns", "gpu-shared", "live-p", "live-u", true, time.Now().Add(-3*time.Hour), nil)
			status := claim.Object["status"].(map[string]any)
			status["reservedFor"] = []any{
				map[string]any{"resource": "pods", "name": "live-p", "uid": "live-u"},
				map[string]any{"resource": "pods", "name": "dead-p", "uid": "dead-u"},
			}
			srv.addCustomObject(rcGVR, claim)
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "dra-claim-wedge-guard,cluster-health-probes")
			srv.waitForRequest(t, proc, 15*time.Second, "resourceclaims list", func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/apis/resource.k8s.io/v1/resourceclaims"
			})
			samples := waitForMetric(t, metricsURL, proc, 15*time.Second, "dra OK with shared live-pod reservation", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "dra-claim-wedge-guard", "status": "OK"})
				return ok && v == 1
			})
			if v, ok := findMetric(samples, "shell_operator_hook_run_errors_total", map[string]string{"queue": "cluster-health-probes"}); !ok || v != 0 {
				t.Errorf("hook errors = (%v,%v), want (0,true)", v, ok)
			}
			if muts := srv.requestCount(func(r reqRecord) bool {
				return (r.Method == http.MethodDelete || r.Method == http.MethodPatch) && strings.Contains(r.Path, "gpu-shared")
			}); muts > 0 {
				t.Errorf("live-pod shared ResourceClaim gpu-shared must not be deleted/patched, got %d", muts)
			}
		})
	})

	t.Run("F30_PodResizeBoundary", func(t *testing.T) {
		t.Parallel()
		t.Run("FreshPodResizePendingPasses", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addPod(makeResizePod("apps", "resize-fresh", "PodResizePending", "Deferred", time.Now().Add(-15*time.Second)))
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "pod-resize-wedge-guard,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "fresh resize OK", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "pod-resize-wedge-guard", "status": "OK"})
				return ok && v == 1
			})
		})

		t.Run("ConditionFalseIgnored", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			pod := makeResizePod("apps", "resize-false", "PodResizePending", "", time.Now().Add(-2*time.Hour))
			pod.Status.Conditions[0].Status = corev1.ConditionFalse
			srv.addPod(pod)
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "pod-resize-wedge-guard,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "false condition OK", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "pod-resize-wedge-guard", "status": "OK"})
				return ok && v == 1
			})
		})

		t.Run("TerminatingPodIgnored", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			pod := makeResizePod("apps", "resize-term", "PodResizePending", "Deferred", time.Now().Add(-2*time.Hour))
			del := metav1.NewTime(time.Now().Add(-1 * time.Hour))
			pod.DeletionTimestamp = &del
			srv.addPod(pod)
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "pod-resize-wedge-guard,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "terminating resize OK", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "pod-resize-wedge-guard", "status": "OK"})
				return ok && v == 1
			})
		})

		t.Run("TerminalSucceededPodIgnored", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			pod := makeResizePod("apps", "resize-done", "PodResizeInProgress", "", time.Now().Add(-2*time.Hour))
			pod.Status.Phase = corev1.PodSucceeded
			srv.addPod(pod)
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "pod-resize-wedge-guard,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "succeeded resize OK", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "pod-resize-wedge-guard", "status": "OK"})
				return ok && v == 1
			})
		})

		t.Run("MultipleNamespacesIsolated", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addPod(makeResizePod("ns-a", "p-a", "PodResizePending", "Deferred", time.Now().Add(-2*time.Hour)))
			srv.addPod(makeResizePod("ns-b", "p-b", "PodResizeInProgress", "", time.Now().Add(-2*time.Hour)))
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "pod-resize-wedge-guard,cluster-health-probes")
			waitForMetric(t, metricsURL, proc, 15*time.Second, "multi-ns resize FAIL", func(s []metricSample) bool {
				v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "pod-resize-wedge-guard", "status": "FAIL"})
				return ok && v == 1
			})
		})
	})

	t.Run("F31ctrl_OrphanEndpointSliceBoundary", func(t *testing.T) {
		t.Parallel()
		t.Run("EmptyServiceListAbortsFailClosed", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			oldTS := metav1.NewTime(time.Now().Add(-30 * time.Minute))
			srv.addEndpointSlice(&discoveryv1.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "apps", Name: "slice-keep", CreationTimestamp: oldTS,
					Labels: map[string]string{"kubernetes.io/service-name": "svc-1"},
				},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, nil, "orphan-endpointslice-cleaner")
			waitForMetric(t, metricsURL, proc, 55*time.Second, "hook error >= 1 on empty svc list", func(s []metricSample) bool {
				v, ok := findMetric(s, "shell_operator_hook_run_errors_total", map[string]string{"queue": "orphan-endpointslice-cleaner"})
				return ok && v >= 1
			})
			if muts := srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodDelete || r.Method == http.MethodPatch
			}); muts > 0 {
				t.Errorf("expected 0 mutations on empty service list abort, got %d", muts)
			}
		})

		t.Run("CornerCasesOnLiveCluster", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addService(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "kubernetes"}})
			srv.addService(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "ext-svc"}})
			// Fresh slice (<15m)
			srv.addEndpointSlice(&discoveryv1.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "apps", Name: "fresh-slice", CreationTimestamp: metav1.NewTime(time.Now().Add(-2 * time.Minute)),
					Labels: map[string]string{"kubernetes.io/service-name": "missing-svc"},
				},
			})
			// Unlabeled slice
			srv.addEndpointSlice(&discoveryv1.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "unlabeled-slice", CreationTimestamp: metav1.NewTime(time.Now().Add(-30 * time.Minute))},
			})
			// External IP slice (no TargetRef)
			ready := true
			srv.addEndpointSlice(&discoveryv1.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "apps", Name: "ext-svc-slice", CreationTimestamp: metav1.NewTime(time.Now().Add(-30 * time.Minute)),
					Labels: map[string]string{"kubernetes.io/service-name": "ext-svc"},
				},
				Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"192.0.2.10"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}}},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, nil, "orphan-endpointslice-cleaner")
			waitForLog(t, proc, 55*time.Second, "orphan-endpointslice-cleaner sweep done", `"logger":"orphan-endpointslice-cleaner","msg":"sweep done"`)
			if lists := srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodGet && strings.Contains(r.Path, "/endpointslices")
			}); lists == 0 {
				t.Errorf("expected GET endpointslices before sweep done")
			}
			samples := scrapeMetrics(t, metricsURL)
			t.Run("FreshSliceNotReaped", func(t *testing.T) {
				if dels := srv.requestCount(func(r reqRecord) bool {
					return r.Method == http.MethodDelete && strings.Contains(r.Path, "fresh-slice")
				}); dels > 0 {
					t.Errorf("fresh slice must not be deleted, got %d", dels)
				}
			})
			t.Run("UnlabeledSliceIgnored", func(t *testing.T) {
				if dels := srv.requestCount(func(r reqRecord) bool {
					return r.Method == http.MethodDelete && strings.Contains(r.Path, "unlabeled-slice")
				}); dels > 0 {
					t.Errorf("unlabeled slice must not be deleted, got %d", dels)
				}
			})
			t.Run("ExternalIPWithoutTargetRefUntouched", func(t *testing.T) {
				if muts := srv.requestCount(func(r reqRecord) bool {
					return (r.Method == http.MethodPatch || r.Method == http.MethodDelete) && strings.Contains(r.Path, "ext-svc-slice")
				}); muts > 0 {
					t.Errorf("external-IP slice without TargetRef must not be treated as ghost Pod, got %d", muts)
				}
			})
			t.Run("ZeroRunErrorsOnCornerCluster", func(t *testing.T) {
				if v, ok := findMetric(samples, "shell_operator_hook_run_errors_total", map[string]string{"queue": "orphan-endpointslice-cleaner"}); !ok || v != 0 {
					t.Errorf("hook errors = (%v,%v), want (0,true)", v, ok)
				}
			})
		})
	})

	t.Run("F32_VeleroAndIngressNginxBoundary", func(t *testing.T) {
		t.Parallel()
		veleroRestoreGVR := schema.GroupVersionResource{Group: "velero.io", Version: "v1", Resource: "restores"}

		t.Run("VeleroCRDAbsent404ZeroErrors", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			proc, metricsURL, _ := startReqManager(t, binPath, srv, nil, "velero-backup-auditor")
			srv.waitForRequest(t, proc, 55*time.Second, "velero schedules 404 probe", func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/apis/velero.io/v1/schedules"
			})
			waitForLog(t, proc, 55*time.Second, "velero-backup-auditor CRD absent skip", `"logger":"velero-backup-auditor","msg":"skip: velero CRDs not installed"`)
			samples := scrapeMetrics(t, metricsURL)
			if v, ok := findMetric(samples, "shell_operator_hook_run_errors_total", map[string]string{"queue": "velero-backup-auditor"}); !ok || v != 0 {
				t.Errorf("hook errors = (%v,%v), want (0,true) on 404", v, ok)
			}
		})

		t.Run("FreshInProgressRestoreNotFlaggedStuck", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			enableVeleroCRDs(srv)
			fresh := time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339)
			srv.addCustomObject(veleroRestoreGVR, &unstructured.Unstructured{
				Object: map[string]any{
					"apiVersion": "velero.io/v1", "kind": "Restore",
					"metadata": map[string]any{"name": "restore-fresh", "namespace": "velero", "creationTimestamp": fresh},
					"status":   map[string]any{"phase": "InProgress", "startTimestamp": fresh},
				},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, nil, "velero-backup-auditor")
			srv.waitForRequest(t, proc, 55*time.Second, "velero restores list", func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/apis/velero.io/v1/restores"
			})
			waitForLog(t, proc, 55*time.Second, "velero-backup-auditor sweep done", `"logger":"velero-backup-auditor","msg":"sweep done"`)
			samples := scrapeMetrics(t, metricsURL)
			for _, s := range samples {
				if strings.Contains(s.Name, "velero") && strings.Contains(s.Name, "restore") && s.Value > 0 {
					t.Errorf("fresh <6h Restore must not trigger stuck metric %s=%v", s.Name, s.Value)
				}
			}
		})

		t.Run("CompletedRestoreHealthy", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			enableVeleroCRDs(srv)
			old := time.Now().Add(-10 * time.Hour).UTC().Format(time.RFC3339)
			srv.addCustomObject(veleroRestoreGVR, &unstructured.Unstructured{
				Object: map[string]any{
					"apiVersion": "velero.io/v1", "kind": "Restore",
					"metadata": map[string]any{"name": "restore-done", "namespace": "velero", "creationTimestamp": old},
					"status":   map[string]any{"phase": "Completed", "startTimestamp": old},
				},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, nil, "velero-backup-auditor")
			srv.waitForRequest(t, proc, 55*time.Second, "velero restores list", func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/apis/velero.io/v1/restores"
			})
			waitForLog(t, proc, 55*time.Second, "velero-backup-auditor sweep done", `"logger":"velero-backup-auditor","msg":"sweep done"`)
			samples := scrapeMetrics(t, metricsURL)
			if v, ok := findMetric(samples, "shell_operator_hook_run_errors_total", map[string]string{"queue": "velero-backup-auditor"}); !ok || v != 0 {
				t.Errorf("hook errors = (%v,%v), want (0,true)", v, ok)
			}
		})

		t.Run("EmptyIngressClusterPassesPosture", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "@health")
			waitForMetric(t, metricsURL, proc, 20*time.Second, "ingress-nginx posture OK on empty cluster", func(s []metricSample) bool {
				for _, m := range s {
					if m.Name == "kuberhealthy_check" && strings.Contains(m.Labels["check"], "ingress") && strings.Contains(m.Labels["check"], "nginx") && m.Labels["status"] == "OK" && m.Value == 1 {
						return true
					}
				}
				return false
			})
		})

		t.Run("IngressNginxControllerPodFlaggedEvenWithoutIngressClass", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addDeployment(&appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ingress-nginx", Name: "ingress-nginx-controller"},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "controller", Image: "registry.k8s.io/ingress-nginx/controller:v1.11.0"}}},
					},
				},
			})
			srv.addPod(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ingress-nginx", Name: "ingress-nginx-controller-0"},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "controller", Image: "registry.k8s.io/ingress-nginx/controller:v1.11.0"}}},
				Status:     corev1.PodStatus{Phase: corev1.PodRunning},
			})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "@health")
			waitForMetric(t, metricsURL, proc, 20*time.Second, "ingress-nginx posture FAIL", func(s []metricSample) bool {
				for _, m := range s {
					if m.Name == "kuberhealthy_check" && strings.Contains(m.Labels["check"], "ingress") && strings.Contains(m.Labels["check"], "nginx") && m.Labels["status"] == "FAIL" && m.Value == 1 {
						return true
					}
				}
				return false
			})
		})
	})
}
