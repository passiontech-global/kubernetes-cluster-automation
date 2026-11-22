// e2e_req_tier4_test.go — Tier 4 (real-world multi-fault cluster sweep scenarios
// from TEST_INFRA.md Scenarios 4, 5, and 6).
package main_test

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

func runTier4Tests(t *testing.T, binPath string, sem chan struct{}) {
	// Scenario 4: Multi-fault GitOps & Rollout sweep (F1, F12, F16, F22)
	t.Run("Scenario4_MultiFaultGitOpsAndRolloutSweep", func(t *testing.T) {
		t.Parallel()
		acquireManagerSlot(t, sem)
		srv := newReqE2EAPIServer(t)

		one := int32(1)
		zero := int32(0)
		oldCond := metav1.NewTime(time.Now().Add(-30 * time.Minute))
		oldTS := metav1.NewTime(time.Now().Add(-48 * time.Hour))
		oldStamp := time.Now().Add(-20 * time.Minute).UTC().Format(time.RFC3339)
		ctrl := true

		// Flux-managed wedged Deployment + non-Flux wedged Deployment
		srv.addDeployment(&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "apps", Name: "sc4-a-flux-wedge", UID: "dep-sc4-flux",
				ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "helm-controller"}},
			},
			Spec: appsv1.DeploymentSpec{Replicas: &one},
			Status: appsv1.DeploymentStatus{Conditions: []appsv1.DeploymentCondition{{
				Type: appsv1.DeploymentProgressing, Status: corev1.ConditionFalse, Reason: "ProgressDeadlineExceeded", LastTransitionTime: oldCond,
			}}},
		})
		srv.addDeployment(&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "sc4-b-free-wedge", UID: "dep-sc4-free"},
			Spec:       appsv1.DeploymentSpec{Replicas: &one},
			Status: appsv1.DeploymentStatus{Conditions: []appsv1.DeploymentCondition{{
				Type: appsv1.DeploymentProgressing, Status: corev1.ConditionFalse, Reason: "ProgressDeadlineExceeded", LastTransitionTime: oldCond,
			}}},
		})

		// HPA Flux target + SubPath ConfigMap transient 500 + Linkerd opaque port + Orphan RS
		srv.enableCRD(schema.GroupVersionResource{Group: "autoscaling", Version: "v2", Resource: "horizontalpodautoscalers"})
		srv.addDeployment(&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "apps", Name: "sc4-hpa-target",
				ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "kustomize-controller"}},
			},
			Spec: appsv1.DeploymentSpec{Replicas: &zero},
		})
		srv.addCustomObject(schema.GroupVersionResource{Group: "autoscaling", Version: "v2", Resource: "horizontalpodautoscalers"}, makeUnhealthyHPA("apps", "sc4-hpa", "sc4-hpa-target", oldStamp))

		srv.addDeployment(makeSubPathDeployment("apps", "sc4-subpath", "sc4-cm"))
		srv.addConfigMap(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "sc4-cm"}, Data: map[string]string{"cfg.yaml": "k: v"}})
		srv.addErrorRule(http.MethodGet, "/api/v1/namespaces/apps/configmaps/sc4-cm", http.StatusInternalServerError, 1)

		srv.addDeployment(&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "sc4-l5d", UID: "dep-sc4-l5d"},
			Spec:       appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "redis:7"}}}}},
		})
		srv.addReplicaSet(&appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "apps", Name: "sc4-l5d-rs", UID: "rs-sc4-l5d",
				OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "sc4-l5d", UID: "dep-sc4-l5d", Controller: &ctrl}},
			},
		})
		srv.addPod(&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "apps", Name: "sc4-l5d-pod",
				OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "sc4-l5d-rs", UID: "rs-sc4-l5d", Controller: &ctrl}},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "app", Image: "redis:7", Ports: []corev1.ContainerPort{{ContainerPort: 6379}}},
					{Name: "linkerd-proxy", Image: "cr.l5d.io/linkerd/proxy:v2"},
				},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		})

		srv.addReplicaSet(&appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "apps", Name: "sc4-orphan-rs", UID: "rs-sc4-orphan", CreationTimestamp: oldTS,
				OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "deleted-dep", UID: "gone", Controller: &ctrl}},
			},
			Spec: appsv1.ReplicaSetSpec{Replicas: &zero},
		})

		proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{
			"CLUSTER_HEALTH_PROBES_INTERVAL=1s",
			"NODE_AUTOMATION_HEAL_BUDGET_MAX=2",
			"NODE_AUTOMATION_HEAL_BUDGET_WINDOW=2s",
			"NODE_AUTOMATION_HEAL_FLUX_CONFLICT_LOOP_MAX=1",
		}, "deployment-rollout-wedge,workload-admission-block-guard,hpa-scaling-guard,subpath-config-drift,linkerd-protocol-detection-stall,api-object-sprawl-report-gc,imagepull-secret-auditor,cluster-health-probes")

		srv.waitForRequest(t, proc, 20*time.Second, "sc4-b-free-wedge PATCH after Flux refund", func(r reqRecord) bool {
			return r.Method == http.MethodPatch && r.Path == "/apis/apps/v1/namespaces/apps/deployments/sc4-b-free-wedge"
		})
		srv.waitForRequest(t, proc, 20*time.Second, "sc4-l5d opaque-ports PATCH", func(r reqRecord) bool {
			return r.Method == http.MethodPatch && r.Path == "/apis/apps/v1/namespaces/apps/deployments/sc4-l5d"
		})
		srv.waitForRequest(t, proc, 20*time.Second, "sc4-orphan-rs DELETE", func(r reqRecord) bool {
			return r.Method == http.MethodDelete && r.Path == "/apis/apps/v1/namespaces/apps/replicasets/sc4-orphan-rs"
		})
		srv.waitForRequest(t, proc, 20*time.Second, "sc4-cm retry GET", func(r reqRecord) bool {
			return srv.requestCount(func(x reqRecord) bool {
				return x.Method == http.MethodGet && x.Path == "/api/v1/namespaces/apps/configmaps/sc4-cm"
			}) >= 2
		})

		samples := waitForMetric(t, metricsURL, proc, 20*time.Second, "helm-controller and kustomize-controller gitops conflicts", func(s []metricSample) bool {
			v1, ok1 := findMetric(s, "node_automation_heal_gitops_conflict_total", map[string]string{"manager": "helm-controller"})
			v2, ok2 := findMetric(s, "node_automation_heal_gitops_conflict_total", map[string]string{"manager": "kustomize-controller"})
			return ok1 && v1 >= 1 && ok2 && v2 >= 1
		})
		if v, ok := findMetric(samples, "node_automation_heal_gitops_conflict_total", map[string]string{"manager": "helm-controller"}); !ok || v < 1 {
			t.Errorf("helm-controller gitops conflict = (%v,%v), want >= 1", v, ok)
		}
		if v, ok := findMetric(samples, "node_automation_heal_gitops_conflict_total", map[string]string{"manager": "kustomize-controller"}); !ok || v < 1 {
			t.Errorf("kustomize-controller gitops conflict = (%v,%v), want >= 1", v, ok)
		}
		for _, req := range srv.requestsMatching(func(r reqRecord) bool {
			return r.Method == http.MethodGet && r.Path == "/apis/apps/v1/replicasets"
		}) {
			if !hasQueryParam(req.RawQuery, "resourceVersion", "0") {
				t.Errorf("ReplicaSet list missing resourceVersion=0: %q", req.RawQuery)
			}
		}
	})

	// Scenario 5: Cloud-native Wave 5 mixed cluster sweep + CRD-absent fallback (F25, F27, F28-ctrl, F29, F30, F31-ctrl, F32)
	t.Run("Scenario5_Wave5MixedClusterAndCRDAbsentFallback", func(t *testing.T) {
		t.Run("PhaseA_AllWave5SignalsActive", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			enableVeleroCRDs(srv)

			vsGVR := schema.GroupVersionResource{Group: "snapshot.storage.k8s.io", Version: "v1", Resource: "volumesnapshots"}
			gwGVR := schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"}
			rcGVR := schema.GroupVersionResource{Group: "resource.k8s.io", Version: "v1", Resource: "resourceclaims"}
			velGVR := schema.GroupVersionResource{Group: "velero.io", Version: "v1", Resource: "restores"}

			oldCond := time.Now().Add(-30 * time.Minute).UTC().Format(time.RFC3339)
			srv.addCustomObject(vsGVR, makeVolumeSnapshot("apps", "sc5-snap", false, time.Now().Add(-4*time.Hour), nil))
			srv.addCustomObject(gwGVR, &unstructured.Unstructured{
				Object: map[string]any{
					"apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
					"metadata": map[string]any{"name": "sc5-gw", "namespace": "apps", "creationTimestamp": oldCond},
					"status":   map[string]any{"conditions": []any{map[string]any{"type": "Programmed", "status": "False", "lastTransitionTime": oldCond}}},
				},
			})
			srv.addCustomObject(rcGVR, makeDRAResourceClaim("gpu", "sc5-claim", "dead-pod", "dead-uid", true, time.Now().Add(-3*time.Hour), nil))
			oldVel := time.Now().Add(-8 * time.Hour).UTC().Format(time.RFC3339)
			srv.addCustomObject(velGVR, &unstructured.Unstructured{
				Object: map[string]any{
					"apiVersion": "velero.io/v1", "kind": "Restore",
					"metadata": map[string]any{"name": "sc5-restore", "namespace": "velero", "creationTimestamp": oldVel},
					"status":   map[string]any{"phase": "InProgress", "startTimestamp": oldVel},
				},
			})

			srv.addPod(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "sc5-priv"},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "registry.internal.corp/svc:v1"}}},
			})
			srv.addPod(makeResizePod("apps", "sc5-resize", "PodResizePending", "Deferred", time.Now().Add(-2*time.Hour)))
			srv.addService(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "kubernetes"}})
			srv.addService(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "sc5-svc"}})
			ready := true
			srv.addEndpointSlice(&discoveryv1.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "apps", Name: "sc5-svc-slice", CreationTimestamp: metav1.NewTime(time.Now().Add(-30 * time.Minute)),
					Labels: map[string]string{"kubernetes.io/service-name": "sc5-svc"},
				},
				Endpoints: []discoveryv1.Endpoint{{
					Addresses: []string{"10.3.0.10"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready},
					TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: "apps", Name: "ghost-sc5", UID: types.UID("ghost-uid-sc5")},
				}},
			})
			srv.addIngressClass(&networkingv1.IngressClass{
				ObjectMeta: metav1.ObjectMeta{Name: "nginx"},
				Spec:       networkingv1.IngressClassSpec{Controller: "k8s.io/ingress-nginx"},
			})

			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"},
				"velero-backup-auditor,orphan-endpointslice-cleaner,@health")
			samples := waitForMetric(t, metricsURL, proc, 55*time.Second, "Wave 5 checks FAIL + velero restores queried", func(s []metricSample) bool {
				if srv.requestCount(func(r reqRecord) bool {
					return r.Method == http.MethodGet && r.Path == "/apis/velero.io/v1/restores"
				}) == 0 {
					return false
				}
				for _, chk := range []string{"volumesnapshot-lifecycle-guard", "gateway-route-health", "imagepull-secret-auditor", "dra-claim-wedge-guard", "pod-resize-wedge-guard"} {
					v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": chk, "status": "FAIL"})
					if !ok || v != 1 {
						return false
					}
				}
				return true
			})
			ingFlagged := false
			for _, m := range samples {
				if m.Name == "kuberhealthy_check" && strings.Contains(m.Labels["check"], "ingress") && strings.Contains(m.Labels["check"], "nginx") && m.Labels["status"] == "FAIL" && m.Value == 1 {
					ingFlagged = true
				}
			}
			if !ingFlagged {
				t.Errorf("expected ingress-nginx retirement posture FAIL in Scenario 5 Phase A")
			}
		})

		t.Run("PhaseB_CRDAbsentAutoSkipFallback", func(t *testing.T) {
			t.Parallel()
			acquireManagerSlot(t, sem)
			srv := newReqE2EAPIServer(t)
			srv.addService(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "kubernetes"}})
			proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"},
				"velero-backup-auditor,orphan-endpointslice-cleaner,volumesnapshot-lifecycle-guard,gateway-route-health,dra-claim-wedge-guard,pod-resize-wedge-guard,imagepull-secret-auditor,cluster-health-probes")
			samples := waitForMetric(t, metricsURL, proc, 55*time.Second, "CRD-absent Wave 5 checks OK", func(s []metricSample) bool {
				for _, chk := range []string{"volumesnapshot-lifecycle-guard", "gateway-route-health", "dra-claim-wedge-guard", "pod-resize-wedge-guard", "imagepull-secret-auditor"} {
					v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": chk, "status": "OK"})
					if !ok || v != 1 {
						return false
					}
				}
				return srv.requestCount(func(r reqRecord) bool {
					return r.Method == http.MethodGet && r.Path == "/apis/velero.io/v1/schedules"
				}) > 0
			})
			for _, q := range []string{"cluster-health-probes", "velero-backup-auditor", "orphan-endpointslice-cleaner"} {
				if v, ok := findMetric(samples, "shell_operator_hook_run_errors_total", map[string]string{"queue": q}); !ok || v != 0 {
					t.Errorf("queue %q error counter = (%v,%v), want (0,true) on CRD-absent cluster", q, v, ok)
				}
			}
		})
	})

	// Scenario 6: Multi-policy admission & partition resilience sweep (F4, F6, F7, F11, F14)
	t.Run("Scenario6_MultiPolicyAdmissionAndPartitionResilience", func(t *testing.T) {
		t.Parallel()
		acquireManagerSlot(t, sem)
		bh := startBlackholeTCPListener(t)
		srv := newReqE2EAPIServer(t)

		// F4: v1.34 + 2-backend EndpointSlice
		srv.setVersion("1", "34")
		srv.addService(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "kubernetes"}})
		srv.addEndpointSlice(makeKubernetesSlice("kubernetes", "10.0.0.1", "10.0.0.2", ""))

		// F6: VAP + per-namespace ParamRef + critical-NS patch
		srv.registerDiscoveryGroup("example.com", "v1", metav1.APIResource{Name: "policystatuses", Namespaced: true, Kind: "PolicyStatus"})
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
			ObjectMeta: metav1.ObjectMeta{Name: "sc6-vap"},
			Spec: admissionv1.ValidatingAdmissionPolicySpec{
				FailurePolicy:    &fp,
				MatchConstraints: podRules,
				ParamKind:        &admissionv1.ParamKind{APIVersion: "example.com/v1", Kind: "PolicyStatus"},
			},
		})
		srv.addVAPB(&admissionv1.ValidatingAdmissionPolicyBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "sc6-vapb"},
			Spec:       admissionv1.ValidatingAdmissionPolicyBindingSpec{PolicyName: "sc6-vap", ParamRef: &admissionv1.ParamRef{Name: "sc6-param"}},
		})

		// F11: Blackhole MWC TLS webhook backend
		seedWebhookService(srv, "apps", "sc6-bh-wh", "127.0.0.1", bh.port, "sc6-canary")
		srv.addMWC(makeMWC("sc6-mwc", "apps", "sc6-bh-wh", bh.port))

		// F14: Dead node with missing PV + Partitioned node with 404 eviction pod
		seedDeadNodeWithPVC(srv, "sc6-dead", "sc6-canary", "apps", "sc6-pvc", "sc6-pv-missing", nil)
		oldTime := metav1.NewTime(time.Now().Add(-20 * time.Minute))
		srv.addNode(&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "sc6-part"},
			Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionTrue, LastTransitionTime: oldTime},
				{Type: "ClusterNetworkProblems", Status: corev1.ConditionTrue, LastTransitionTime: oldTime},
			}},
		})
		srv.addNode(&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "sc6-worker-2"},
			Status:     corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue, LastTransitionTime: oldTime}}},
		})
		sc6Ctrl := true
		srv.addPod(&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "flux-system", Name: "sc6-src-0", UID: "sc6-src-uid",
				OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "sc6-src-rs", UID: "sc6-src-rs", Controller: &sc6Ctrl}},
			},
			Spec:   corev1.PodSpec{NodeName: "sc6-part"},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		})
		srv.setPodEvictionStatus("flux-system", "sc6-src-0", http.StatusNotFound)

		// F7: >2.5 MiB Postgres log tail + cloudflared QUIC log fallback
		srv.addPod(makePostgresPod("db", "sc6-pg-0", "sc6-pg"))
		var logBuf bytes.Buffer
		logBuf.Write(bytes.Repeat([]byte("checkpoint normal\n"), 150000)) // ~2.7 MiB
		logBuf.WriteString("PANIC: pg_wal/00000001 write failed: No space left on device\n")
		srv.setPodLog("db", "sc6-pg-0", "postgres", http.StatusOK, logBuf.Bytes())

		srv.addPod(&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "sc6-cf-0", CreationTimestamp: metav1.NewTime(time.Now().Add(-10 * time.Minute))},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "cloudflared", Image: "cloudflare/cloudflared:2025.1"}}},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		})
		srv.setPodLog("edge", "sc6-cf-0", "", http.StatusOK, []byte("ERR Failed to dial to edge with quic\n"))

		promURL := startMockPromServer(t, func(string) []map[string]any { return nil })
		proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{
			"CLUSTER_HEALTH_PROBES_INTERVAL=1s",
			"HEALTH_PROMETHEUS_QUERY_URL=" + promURL,
		}, "apiserver-endpoint-guard,admission-webhook-guard,dead-node-sweeper,partition-pod-evictor,postgres-wal-archive-guard,cloudflared-tunnel-health,cluster-health-probes")

		waitForMetric(t, metricsURL, proc, 55*time.Second, "Scenario 6 all signals converged", func(s []metricSample) bool {
			v1, ok1 := findMetric(s, "node_automation_apiserver_rv_gap", map[string]string{"backend": "10.0.0.1"})
			v2, ok2 := findMetric(s, "node_automation_cel_policy_actions_total", map[string]string{"action": "criticalns_patch"})
			v3, ok3 := findMetric(s, "node_automation_dead_node_unfenced_stateful_skipped", map[string]string{"node": "sc6-dead"})
			v4, ok4 := findMetric(s, "node_automation_postgres_wal_archive_unhealthy", map[string]string{"cluster": "sc6-pg"})
			v5, ok5 := findMetric(s, "node_automation_cloudflared_tunnel_degraded", map[string]string{"pod": "sc6-cf-0"})
			evictSent := srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodPost && r.Path == "/api/v1/namespaces/flux-system/pods/sc6-src-0/eviction"
			}) > 0
			return ok1 && v1 == -1 && ok2 && v2 >= 1 && ok3 && v3 == 1 && ok4 && v4 == 1 && ok5 && v5 == 1 && evictSent
		})

		waitForLog(t, proc, 55*time.Second, "partition-pod-evictor sweep done", `"logger":"partition-pod-evictor","msg":"sweep done"`)
		samples := scrapeMetrics(t, metricsURL)
		if n := srv.requestCount(func(r reqRecord) bool {
			return r.Method == http.MethodGet && r.Path == "/apis/example.com/v1/policystatuses/sc6-param"
		}); n > 0 {
			t.Errorf("per-namespace ParamRef issued cluster-scoped GET (%d)", n)
		}
		if v, ok := findMetric(samples, "shell_operator_hook_run_errors_total", map[string]string{"queue": "partition-pod-evictor"}); !ok || v != 0 {
			t.Errorf("partition-pod-evictor hook errors = (%v,%v), want (0,true)", v, ok)
		}
		if strings.Contains(proc.stderr.String(), "DEFER: PDB refused eviction") {
			t.Errorf("404 eviction logged PDB refusal unexpectedly")
		}
		proc.stopWithSIGINTAndAssertZero(t, 15*time.Second)
	})
}
