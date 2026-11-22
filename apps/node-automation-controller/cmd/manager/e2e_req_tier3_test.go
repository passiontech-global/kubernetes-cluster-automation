// e2e_req_tier3_test.go — Tier 3 (cross-feature pairwise combinations): 17
// pairwise combinations covering all 17 node-automation-controller features.
package main_test

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

func runTier3Tests(t *testing.T, binPath string, sem chan struct{}) {
	t.Run("Pair01_F1_x_F4_ContractsAndEndpointSliceSSOT", func(t *testing.T) {
		t.Parallel()
		acquireManagerSlot(t, sem)
		srv := newReqE2EAPIServer(t)
		srv.setVersion("1", "34")
		srv.addEndpointSlice(makeKubernetesSlice("kubernetes", "10.0.0.1", "10.0.0.2", ""))
		proc, metricsURL, _ := startReqManager(t, binPath, srv, nil, "apiserver-endpoint-guard,evicted-pod-janitor")
		samples := waitForMetric(t, metricsURL, proc, 45*time.Second, "rv_gap=-1", func(s []metricSample) bool {
			v, ok := findMetric(s, "node_automation_apiserver_rv_gap", map[string]string{"backend": "10.0.0.1"})
			return ok && v == -1
		})
		if v, ok := findMetric(samples, "shell_operator_hook_run_errors_total", map[string]string{"queue": "evicted-pod-janitor"}); !ok || v != 0 {
			t.Errorf("evicted-pod-janitor predeclared counter = (%v,%v), want (0,true)", v, ok)
		}
		proc.stopWithSIGINTAndAssertZero(t, 15*time.Second)
	})

	t.Run("Pair02_F1_x_F7_ContractsAndBoundedLogTail", func(t *testing.T) {
		t.Parallel()
		acquireManagerSlot(t, sem)
		srv := newReqE2EAPIServer(t)
		srv.addPod(makePostgresPod("db", "pg-pair", "pair-cluster"))
		var buf bytes.Buffer
		buf.Write(bytes.Repeat([]byte("log line ok\n"), 200000)) // ~2.4 MiB
		buf.WriteString("PANIC: pg_wal/0001 write failed: No space left on device\n")
		srv.setPodLog("db", "pg-pair", "postgres", http.StatusOK, buf.Bytes())
		proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "postgres-wal-archive-guard,cluster-health-probes")
		samples := waitForMetric(t, metricsURL, proc, 15*time.Second, "postgres wal unhealthy", func(s []metricSample) bool {
			v, ok := findMetric(s, "node_automation_postgres_wal_archive_unhealthy", map[string]string{"cluster": "pair-cluster"})
			return ok && v == 1
		})
		if v, ok := findMetric(samples, "kuberhealthy_check", map[string]string{"check": "postgres-wal-archive-guard", "status": "FAIL"}); !ok || v != 1 {
			t.Errorf("kuberhealthy_check FAIL = (%v,%v), want (1,true)", v, ok)
		}
	})

	t.Run("Pair03_F4_x_F6_EndpointGuardAndCELPolicy", func(t *testing.T) {
		t.Parallel()
		acquireManagerSlot(t, sem)
		srv := newReqE2EAPIServer(t)
		srv.setVersion("1", "34")
		srv.addEndpointSlice(makeKubernetesSlice("kubernetes", "10.0.0.1", "10.0.0.2", ""))
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
			ObjectMeta: metav1.ObjectMeta{Name: "vap-pair"},
			Spec: admissionv1.ValidatingAdmissionPolicySpec{
				FailurePolicy:    &fp,
				MatchConstraints: podRules,
				ParamKind:        &admissionv1.ParamKind{APIVersion: "example.com/v1", Kind: "PolicyStatus"},
			},
		})
		srv.addVAPB(&admissionv1.ValidatingAdmissionPolicyBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "vapb-pair"},
			Spec:       admissionv1.ValidatingAdmissionPolicyBindingSpec{PolicyName: "vap-pair", ParamRef: &admissionv1.ParamRef{Name: "p1"}},
		})
		promURL := startMockPromServer(t, func(string) []map[string]any { return nil })
		proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"HEALTH_PROMETHEUS_QUERY_URL=" + promURL}, "apiserver-endpoint-guard,admission-webhook-guard")
		waitForMetric(t, metricsURL, proc, 55*time.Second, "both apiserver & cel metrics", func(s []metricSample) bool {
			_, ok1 := findMetric(s, "node_automation_apiserver_rv_gap", map[string]string{"backend": "10.0.0.1"})
			_, ok2 := findMetric(s, "node_automation_cel_policy_actions_total", map[string]string{"action": "criticalns_patch"})
			return ok1 && ok2
		})
		if gets := srv.requestCount(func(r reqRecord) bool {
			return r.Method == http.MethodGet && r.Path == "/apis/example.com/v1/policystatuses/p1"
		}); gets > 0 {
			t.Errorf("unexpected cluster-scoped GET for per-namespace ParamRef")
		}
	})

	t.Run("Pair04_F6_x_F11_CELPolicyAndTLSBlackholeTimeout", func(t *testing.T) {
		t.Parallel()
		acquireManagerSlot(t, sem)
		bh := startBlackholeTCPListener(t)
		srv := newReqE2EAPIServer(t)
		seedWebhookService(srv, "apps", "bh-pair", "127.0.0.1", bh.port, "n1")
		srv.addMWC(makeMWC("mwc-pair", "apps", "bh-pair", bh.port))
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
			ObjectMeta: metav1.ObjectMeta{Name: "vap-bh"},
			Spec: admissionv1.ValidatingAdmissionPolicySpec{
				FailurePolicy:    &fp,
				MatchConstraints: podRules,
				ParamKind:        &admissionv1.ParamKind{APIVersion: "example.com/v1", Kind: "PolicyStatus"},
			},
		})
		srv.addVAPB(&admissionv1.ValidatingAdmissionPolicyBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "vapb-bh"},
			Spec:       admissionv1.ValidatingAdmissionPolicyBindingSpec{PolicyName: "vap-bh", ParamRef: &admissionv1.ParamRef{Name: "p2"}},
		})
		promURL := startMockPromServer(t, func(string) []map[string]any { return nil })
		proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"HEALTH_PROMETHEUS_QUERY_URL=" + promURL}, "admission-webhook-guard")
		waitForMetric(t, metricsURL, proc, 55*time.Second, "criticalns_patch after blackhole timeout", func(s []metricSample) bool {
			v, ok := findMetric(s, "node_automation_cel_policy_actions_total", map[string]string{"action": "criticalns_patch"})
			return ok && v >= 1
		})
		acceptAt, ok := bh.firstAcceptTime()
		if !ok {
			t.Fatalf("expected blackhole TCP dial")
		}
		vapReq := srv.requestsMatching(func(r reqRecord) bool {
			return r.Method == http.MethodGet && strings.HasSuffix(r.Path, "/validatingadmissionpolicies")
		})[0]
		if delta := vapReq.At.Sub(acceptAt); delta > 5*time.Second {
			t.Errorf("CEL policy sweep delayed %s behind blackhole TLS dial, want <=5s", delta)
		}
	})

	t.Run("Pair05_F7_x_F12_BoundedLogAndFluxRefund", func(t *testing.T) {
		t.Parallel()
		acquireManagerSlot(t, sem)
		srv := newReqE2EAPIServer(t)
		srv.addPod(makePostgresPod("db", "pg-f7", "c-f7"))
		srv.setPodLog("db", "pg-f7", "postgres", http.StatusOK, []byte("pg_wal: no space left on device\n"))
		srv.enableCRD(schema.GroupVersionResource{Group: "autoscaling", Version: "v2", Resource: "horizontalpodautoscalers"})
		oldStamp := time.Now().Add(-20 * time.Minute).UTC().Format(time.RFC3339)
		zero := int32(0)
		srv.addDeployment(&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "f-dep", ResourceVersion: "1", ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "helm-controller"}}},
			Spec:       appsv1.DeploymentSpec{Replicas: &zero},
		})
		srv.addDeployment(&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "ok-dep", ResourceVersion: "1"},
			Spec:       appsv1.DeploymentSpec{Replicas: &zero},
		})
		srv.addCustomObject(schema.GroupVersionResource{Group: "autoscaling", Version: "v2", Resource: "horizontalpodautoscalers"}, makeUnhealthyHPA("apps", "hpa-a", "f-dep", oldStamp))
		srv.addCustomObject(schema.GroupVersionResource{Group: "autoscaling", Version: "v2", Resource: "horizontalpodautoscalers"}, makeUnhealthyHPA("apps", "hpa-b", "ok-dep", oldStamp))

		proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{
			"CLUSTER_HEALTH_PROBES_INTERVAL=1s",
			"NODE_AUTOMATION_HEAL_BUDGET_MAX=1",
			"NODE_AUTOMATION_HEAL_FLUX_CONFLICT_LOOP_MAX=1",
		}, "postgres-wal-archive-guard,hpa-scaling-guard,cluster-health-probes")
		waitForMetric(t, metricsURL, proc, 15*time.Second, "postgres wal + gitops conflict", func(s []metricSample) bool {
			v1, ok1 := findMetric(s, "node_automation_postgres_wal_archive_unhealthy", map[string]string{"cluster": "c-f7"})
			v2, ok2 := findMetric(s, "node_automation_heal_gitops_conflict_total", map[string]string{"manager": "helm-controller"})
			return ok1 && ok2 && v1 == 1 && v2 >= 1
		})
		srv.waitForRequest(t, proc, 15*time.Second, "ok-dep PATCH after Flux refund", func(r reqRecord) bool {
			return r.Method == http.MethodPatch && r.Path == "/apis/apps/v1/namespaces/apps/deployments/ok-dep"
		})
	})

	t.Run("Pair06_F11_x_F14_TLSBlackholeAndDeadNodePartition", func(t *testing.T) {
		t.Parallel()
		acquireManagerSlot(t, sem)
		bh := startBlackholeTCPListener(t)
		srv := newReqE2EAPIServer(t)
		seedWebhookService(srv, "apps", "bh-f11", "127.0.0.1", bh.port, "canary-n")
		srv.addMWC(makeMWC("mwc-f11", "apps", "bh-f11", bh.port))
		seedDeadNodeWithPVC(srv, "dead-f14", "canary-n", "apps", "pvc-f14", "pv-miss-f14", nil)

		proc, metricsURL, _ := startReqManager(t, binPath, srv, nil, "admission-webhook-guard,dead-node-sweeper")
		waitForMetric(t, metricsURL, proc, 55*time.Second, "dead node skipped=1", func(s []metricSample) bool {
			v, ok := findMetric(s, "node_automation_dead_node_unfenced_stateful_skipped", map[string]string{"node": "dead-f14"})
			return ok && v == 1
		})
		srv.waitForRequest(t, proc, 55*time.Second, "post-breaker VAP list", func(r reqRecord) bool {
			return r.Method == http.MethodGet && strings.HasSuffix(r.Path, "/validatingadmissionpolicies")
		})
	})

	t.Run("Pair07_F12_x_F16_FluxRefundAndSharedAllTypedReplicaSets", func(t *testing.T) {
		t.Parallel()
		acquireManagerSlot(t, sem)
		srv := newReqE2EAPIServer(t)
		one := int32(1)
		oldCond := metav1.NewTime(time.Now().Add(-30 * time.Minute))
		srv.addDeployment(&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "dep-flux-pair", ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "helm-controller"}}},
			Spec:       appsv1.DeploymentSpec{Replicas: &one},
			Status: appsv1.DeploymentStatus{Conditions: []appsv1.DeploymentCondition{{
				Type: appsv1.DeploymentProgressing, Status: corev1.ConditionFalse, Reason: "ProgressDeadlineExceeded", LastTransitionTime: oldCond,
			}}},
		})
		srv.addDeployment(&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "dep-free-pair"},
			Spec:       appsv1.DeploymentSpec{Replicas: &one},
			Status: appsv1.DeploymentStatus{Conditions: []appsv1.DeploymentCondition{{
				Type: appsv1.DeploymentProgressing, Status: corev1.ConditionFalse, Reason: "ProgressDeadlineExceeded", LastTransitionTime: oldCond,
			}}},
		})
		proc, _, _ := startReqManager(t, binPath, srv, []string{
			"CLUSTER_HEALTH_PROBES_INTERVAL=1s",
			"NODE_AUTOMATION_HEAL_BUDGET_MAX=1",
			"NODE_AUTOMATION_HEAL_FLUX_CONFLICT_LOOP_MAX=1",
		}, "deployment-rollout-wedge,workload-admission-block-guard,cluster-health-probes")
		srv.waitForRequest(t, proc, 15*time.Second, "dep-free-pair PATCH", func(r reqRecord) bool {
			return r.Method == http.MethodPatch && r.Path == "/apis/apps/v1/namespaces/apps/deployments/dep-free-pair"
		})
		for _, req := range srv.requestsMatching(func(r reqRecord) bool {
			return r.Method == http.MethodGet && r.Path == "/apis/apps/v1/replicasets"
		}) {
			if !hasQueryParam(req.RawQuery, "resourceVersion", "0") {
				t.Errorf("shared ReplicaSet list missing resourceVersion=0: %q", req.RawQuery)
			}
		}
	})

	t.Run("Pair08_F14_x_F1_DeadNodeAndPartitionEvictorWithBudget", func(t *testing.T) {
		t.Parallel()
		acquireManagerSlot(t, sem)
		srv := newReqE2EAPIServer(t)
		seedDeadNodeWithPVC(srv, "dead-p8", "ok-p8", "apps", "pvc-p8", "pv-miss-p8", nil)
		oldTime := metav1.NewTime(time.Now().Add(-20 * time.Minute))
		srv.addNode(&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "part-p8"},
			Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionTrue, LastTransitionTime: oldTime},
				{Type: "ClusterNetworkProblems", Status: corev1.ConditionTrue, LastTransitionTime: oldTime},
			}},
		})
		srv.addNode(&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "ok-p8-2"},
			Status:     corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue, LastTransitionTime: oldTime}}},
		})
		p8Ctrl := true
		srv.addPod(&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "flux-system", Name: "src-p8", UID: "src-p8-uid",
				OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "src-p8-rs", UID: "src-p8-rs", Controller: &p8Ctrl}},
			},
			Spec:   corev1.PodSpec{NodeName: "part-p8"},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		})
		srv.setPodEvictionStatus("flux-system", "src-p8", http.StatusNotFound)
		proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"NODE_AUTOMATION_HEAL_BUDGET_MAX=1"}, "dead-node-sweeper,partition-pod-evictor")
		waitForMetric(t, metricsURL, proc, 55*time.Second, "dead node skipped=1", func(s []metricSample) bool {
			v, ok := findMetric(s, "node_automation_dead_node_unfenced_stateful_skipped", map[string]string{"node": "dead-p8"})
			return ok && v == 1
		})
		srv.waitForRequest(t, proc, 55*time.Second, "eviction POST", func(r reqRecord) bool {
			return r.Method == http.MethodPost && r.Path == "/api/v1/namespaces/flux-system/pods/src-p8/eviction"
		})
		waitForLog(t, proc, 55*time.Second, "partition-pod-evictor sweep done", `"logger":"partition-pod-evictor","msg":"sweep done"`)
		samples := scrapeMetrics(t, metricsURL)
		if v, ok := findMetric(samples, "shell_operator_hook_run_errors_total", map[string]string{"queue": "partition-pod-evictor"}); !ok || v != 0 {
			t.Errorf("partition-pod-evictor hook errors = (%v,%v), want (0,true)", v, ok)
		}
	})

	t.Run("Pair09_F16_x_F22_FailedJobsJanitorCachingAndReap", func(t *testing.T) {
		t.Parallel()
		acquireManagerSlot(t, sem)
		srv := newReqE2EAPIServer(t)
		oldTS := metav1.NewTime(time.Now().Add(-30 * time.Hour))
		srv.addJob(&batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "job-pair9", UID: "job-p9", CreationTimestamp: oldTS},
			Status:     batchv1.JobStatus{Conditions: []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, LastTransitionTime: oldTS}}},
		})
		srv.addNode(&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "dead-p9"},
			Status:     corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionFalse}}},
		})
		for _, n := range []string{"pvc-p9-a", "pvc-p9-b"} {
			srv.addPVC(&corev1.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: n, DeletionTimestamp: &oldTS, Finalizers: []string{"kubernetes.io/pvc-protection"}},
				Spec:       corev1.PersistentVolumeClaimSpec{VolumeName: "pv-" + n},
			})
			srv.addPod(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "pod-" + n},
				Spec: corev1.PodSpec{
					NodeName: "dead-p9",
					Volumes:  []corev1.Volume{{Name: "v", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: n}}}},
				},
				Status: corev1.PodStatus{Phase: corev1.PodFailed},
			})
		}
		proc, _, _ := startReqManager(t, binPath, srv, nil, "failed-jobs-janitor")
		srv.waitForRequest(t, proc, 55*time.Second, "failed job DELETE", func(r reqRecord) bool {
			return r.Method == http.MethodDelete && r.Path == "/apis/batch/v1/namespaces/apps/jobs/job-pair9"
		})
		vaTyped := srv.requestCount(func(r reqRecord) bool {
			return r.Method == http.MethodGet && r.Path == "/apis/storage.k8s.io/v1/volumeattachments" &&
				!strings.Contains(r.Accept, "PartialObjectMetadataList")
		})
		if vaTyped > 1 {
			t.Errorf("expected cached VolumeAttachments list <= 1, got %d", vaTyped)
		}
	})

	t.Run("Pair10_F22_x_F12_SubPathRetryAndLinkerdPatch", func(t *testing.T) {
		t.Parallel()
		acquireManagerSlot(t, sem)
		srv := newReqE2EAPIServer(t)
		srv.addDeployment(makeSubPathDeployment("apps", "sub-p10", "cm-p10"))
		srv.addConfigMap(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "cm-p10"}, Data: map[string]string{"a": "b"}})
		srv.addErrorRule(http.MethodGet, "/api/v1/namespaces/apps/configmaps/cm-p10", http.StatusInternalServerError, 1)
		ctrl := true
		srv.addDeployment(&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "l5d-p10", UID: "dep-l5d"},
			Spec:       appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "redis:7"}}}}},
		})
		srv.addReplicaSet(&appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "apps", Name: "l5d-p10-rs", UID: "rs-l5d",
				OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "l5d-p10", UID: "dep-l5d", Controller: &ctrl}},
			},
		})
		srv.addPod(&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "apps", Name: "l5d-p10-pod",
				OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "l5d-p10-rs", UID: "rs-l5d", Controller: &ctrl}},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "app", Image: "redis:7", Ports: []corev1.ContainerPort{{ContainerPort: 6379}}},
					{Name: "linkerd-proxy", Image: "cr.l5d.io/linkerd/proxy:v2"},
				},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		})
		proc, _, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "subpath-config-drift,linkerd-protocol-detection-stall,cluster-health-probes")
		srv.waitForRequest(t, proc, 15*time.Second, "l5d-p10 PATCH", func(r reqRecord) bool {
			return r.Method == http.MethodPatch && r.Path == "/apis/apps/v1/namespaces/apps/deployments/l5d-p10"
		})
		srv.waitForRequest(t, proc, 15*time.Second, "cm-p10 retry GET", func(r reqRecord) bool {
			return srv.requestCount(func(x reqRecord) bool {
				return x.Method == http.MethodGet && x.Path == "/api/v1/namespaces/apps/configmaps/cm-p10"
			}) >= 2
		})
	})

	t.Run("Pair11_F25_x_F16_VolumeSnapshotAndPVCLifecycleRV0", func(t *testing.T) {
		t.Parallel()
		acquireManagerSlot(t, sem)
		srv := newReqE2EAPIServer(t)
		vsGVR := schema.GroupVersionResource{Group: "snapshot.storage.k8s.io", Version: "v1", Resource: "volumesnapshots"}
		srv.addCustomObject(vsGVR, makeVolumeSnapshot("apps", "snap-p11", false, time.Now().Add(-45*time.Minute), nil))
		proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "volumesnapshot-lifecycle-guard,pvc-lifecycle-guard,cluster-health-probes")
		waitForMetric(t, metricsURL, proc, 15*time.Second, "volumesnapshot FAIL + pvc OK", func(s []metricSample) bool {
			v1, ok1 := findMetric(s, "kuberhealthy_check", map[string]string{"check": "volumesnapshot-lifecycle-guard", "status": "FAIL"})
			v2, ok2 := findMetric(s, "kuberhealthy_check", map[string]string{"check": "pvc-lifecycle-guard", "status": "OK"})
			return ok1 && ok2 && v1 == 1 && v2 == 1
		})
		for _, req := range srv.requestsMatching(func(r reqRecord) bool {
			return r.Method == http.MethodGet && r.Path == "/apis/storage.k8s.io/v1/storageclasses"
		}) {
			if !hasQueryParam(req.RawQuery, "resourceVersion", "0") {
				t.Errorf("storageclasses list missing resourceVersion=0: %q", req.RawQuery)
			}
		}
	})

	t.Run("Pair12_F27_x_F11_GatewayAPIAndWebhookBlackhole", func(t *testing.T) {
		t.Parallel()
		acquireManagerSlot(t, sem)
		bh := startBlackholeTCPListener(t)
		srv := newReqE2EAPIServer(t)
		seedWebhookService(srv, "apps", "bh-p12", "127.0.0.1", bh.port, "n1")
		srv.addMWC(makeMWC("mwc-p12", "apps", "bh-p12", bh.port))
		gwGVR := schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"}
		oldCond := time.Now().Add(-30 * time.Minute).UTC().Format(time.RFC3339)
		srv.addCustomObject(gwGVR, &unstructured.Unstructured{
			Object: map[string]any{
				"apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
				"metadata": map[string]any{"name": "gw-p12", "namespace": "apps", "creationTimestamp": oldCond},
				"status": map[string]any{"conditions": []any{
					map[string]any{"type": "Programmed", "status": "False", "lastTransitionTime": oldCond},
				}},
			},
		})
		proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "gateway-route-health,cluster-health-probes,admission-webhook-guard")
		waitForMetric(t, metricsURL, proc, 55*time.Second, "gateway FAIL", func(s []metricSample) bool {
			v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "gateway-route-health", "status": "FAIL"})
			return ok && v == 1
		})
		srv.waitForRequest(t, proc, 55*time.Second, "post-breaker VAP list", func(r reqRecord) bool {
			return r.Method == http.MethodGet && strings.HasSuffix(r.Path, "/validatingadmissionpolicies")
		})
	})

	t.Run("Pair13_F28ctrl_x_F16_ImagePullSecretPrivateAndRV0", func(t *testing.T) {
		t.Parallel()
		acquireManagerSlot(t, sem)
		srv := newReqE2EAPIServer(t)
		srv.addPod(&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "priv-p13"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "registry.internal.corp/app:v1"}}},
		})
		proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "imagepull-secret-auditor,cluster-health-probes")
		waitForMetric(t, metricsURL, proc, 15*time.Second, "imagepull FAIL", func(s []metricSample) bool {
			v, ok := findMetric(s, "kuberhealthy_check", map[string]string{"check": "imagepull-secret-auditor", "status": "FAIL"})
			return ok && v == 1
		})
		for _, path := range []string{"/api/v1/secrets", "/api/v1/serviceaccounts"} {
			for _, req := range srv.requestsMatching(func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == path
			}) {
				if !hasQueryParam(req.RawQuery, "resourceVersion", "0") {
					t.Errorf("%s list missing resourceVersion=0: %q", path, req.RawQuery)
				}
			}
		}
	})

	t.Run("Pair14_F29_x_F25_DRAClaimAndVolumeSnapshotMixed", func(t *testing.T) {
		t.Parallel()
		acquireManagerSlot(t, sem)
		srv := newReqE2EAPIServer(t)
		rcGVR := schema.GroupVersionResource{Group: "resource.k8s.io", Version: "v1", Resource: "resourceclaims"}
		srv.addCustomObject(rcGVR, makeDRAResourceClaim("gpu", "claim-z", "dead-pod", "dead-uid", true, time.Now().Add(-3*time.Hour), nil))
		// VolumeSnapshot CRD intentionally absent (404 auto-skip)
		proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "dra-claim-wedge-guard,volumesnapshot-lifecycle-guard,cluster-health-probes")
		waitForMetric(t, metricsURL, proc, 15*time.Second, "dra FAIL and volumesnapshot OK", func(s []metricSample) bool {
			v1, ok1 := findMetric(s, "kuberhealthy_check", map[string]string{"check": "dra-claim-wedge-guard", "status": "FAIL"})
			v2, ok2 := findMetric(s, "kuberhealthy_check", map[string]string{"check": "volumesnapshot-lifecycle-guard", "status": "OK"})
			return ok1 && ok2 && v1 == 1 && v2 == 1
		})
	})

	t.Run("Pair15_F30_x_F22_PodResizeAndRolloutWedgeSharedSnapshot", func(t *testing.T) {
		t.Parallel()
		acquireManagerSlot(t, sem)
		srv := newReqE2EAPIServer(t)
		srv.addPod(makeResizePod("apps", "resize-p15", "PodResizePending", "Deferred", time.Now().Add(-2*time.Hour)))
		proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "pod-resize-wedge-guard,deployment-rollout-wedge,topology-spread-zone-deadlock,cluster-health-probes")
		waitForMetric(t, metricsURL, proc, 15*time.Second, "resize FAIL + others OK", func(s []metricSample) bool {
			v1, ok1 := findMetric(s, "kuberhealthy_check", map[string]string{"check": "pod-resize-wedge-guard", "status": "FAIL"})
			v2, ok2 := findMetric(s, "kuberhealthy_check", map[string]string{"check": "deployment-rollout-wedge", "status": "OK"})
			return ok1 && ok2 && v1 == 1 && v2 == 1
		})
		// Shared AllPods snapshot: pod list count <= deployment list count
		podLists := srv.requestCount(func(r reqRecord) bool { return r.Method == http.MethodGet && r.Path == "/api/v1/pods" })
		depLists := srv.requestCount(func(r reqRecord) bool { return r.Method == http.MethodGet && r.Path == "/apis/apps/v1/deployments" })
		if podLists > depLists {
			t.Errorf("expected shared AllPods snapshot (pods=%d <= deps=%d)", podLists, depLists)
		}
	})

	t.Run("Pair16_F31ctrl_x_F14_OrphanEndpointSliceAndPartitionEvictor", func(t *testing.T) {
		t.Parallel()
		acquireManagerSlot(t, sem)
		srv := newReqE2EAPIServer(t)
		seedPartitionCluster(srv, "part-p16", 2, "flux-system", "src-p16", "")
		srv.setPodEvictionStatus("flux-system", "src-p16", http.StatusNotFound)
		srv.addService(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "kubernetes"}})
		srv.addService(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web-p16"}})
		ready := true
		srv.addEndpointSlice(&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "apps", Name: "web-p16-slice", CreationTimestamp: metav1.NewTime(time.Now().Add(-30 * time.Minute)),
				Labels: map[string]string{"kubernetes.io/service-name": "web-p16"},
			},
			Endpoints: []discoveryv1.Endpoint{{
				Addresses: []string{"10.2.0.5"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready},
				TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: "apps", Name: "ghost-pod", UID: types.UID("ghost-uid-p16")},
			}},
		})
		proc, metricsURL, _ := startReqManager(t, binPath, srv, nil, "orphan-endpointslice-cleaner,partition-pod-evictor")
		waitForLog(t, proc, 55*time.Second, "orphan-endpointslice-cleaner sweep done", `"logger":"orphan-endpointslice-cleaner","msg":"sweep done"`)
		waitForLog(t, proc, 55*time.Second, "partition-pod-evictor sweep done", `"logger":"partition-pod-evictor","msg":"sweep done"`)
		if evictions := srv.requestCount(func(x reqRecord) bool {
			return x.Method == http.MethodPost && x.Path == "/api/v1/namespaces/flux-system/pods/src-p16/eviction"
		}); evictions == 0 {
			t.Errorf("expected partition-pod-evictor eviction POST for src-p16")
		}
		samples := scrapeMetrics(t, metricsURL)
		if v, ok := findMetric(samples, "shell_operator_hook_run_errors_total", map[string]string{"queue": "partition-pod-evictor"}); !ok || v != 0 {
			t.Errorf("partition-pod-evictor errors = (%v,%v), want (0,true)", v, ok)
		}
		if v, ok := findMetric(samples, "shell_operator_hook_run_errors_total", map[string]string{"queue": "orphan-endpointslice-cleaner"}); !ok || v != 0 {
			t.Errorf("orphan-endpointslice-cleaner errors = (%v,%v), want (0,true)", v, ok)
		}
		// Assert genuine F31-ctrl ghost Pod UID detection/remediation on web-p16-slice
		remediated := srv.requestCount(func(r reqRecord) bool {
			return (r.Method == http.MethodPatch || r.Method == http.MethodDelete) &&
				strings.Contains(r.Path, "/apps/endpointslices/web-p16-slice")
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
			strings.Contains(stderr, "ghost-uid-p16")
		if remediated == 0 && !ghostMetric && !ghostLogged {
			t.Errorf("expected F31-ctrl ghost Pod UID detection/remediation on web-p16-slice (patch/delete, metric, or candidate log with ghost-uid-p16), got none")
		}
	})

	t.Run("Pair17_F32_x_F20_VeleroRestoreIngressNginxAndContracts", func(t *testing.T) {
		t.Parallel()
		acquireManagerSlot(t, sem)
		srv := newReqE2EAPIServer(t)
		enableVeleroCRDs(srv)
		veleroRestoreGVR := schema.GroupVersionResource{Group: "velero.io", Version: "v1", Resource: "restores"}
		oldStart := time.Now().Add(-8 * time.Hour).UTC().Format(time.RFC3339)
		srv.addCustomObject(veleroRestoreGVR, &unstructured.Unstructured{
			Object: map[string]any{
				"apiVersion": "velero.io/v1", "kind": "Restore",
				"metadata": map[string]any{"name": "restore-p17", "namespace": "velero", "creationTimestamp": oldStart},
				"status":   map[string]any{"phase": "InProgress", "startTimestamp": oldStart},
			},
		})
		srv.addIngressClass(&networkingv1.IngressClass{
			ObjectMeta: metav1.ObjectMeta{Name: "nginx"},
			Spec:       networkingv1.IngressClassSpec{Controller: "k8s.io/ingress-nginx"},
		})
		proc, metricsURL, _ := startReqManager(t, binPath, srv, []string{"CLUSTER_HEALTH_PROBES_INTERVAL=1s"}, "velero-backup-auditor,@health")
		waitForMetric(t, metricsURL, proc, 55*time.Second, "ingress-nginx FAIL + velero restores list", func(s []metricSample) bool {
			if srv.requestCount(func(r reqRecord) bool {
				return r.Method == http.MethodGet && r.Path == "/apis/velero.io/v1/restores"
			}) == 0 {
				return false
			}
			for _, m := range s {
				if m.Name == "kuberhealthy_check" && strings.Contains(m.Labels["check"], "ingress") && strings.Contains(m.Labels["check"], "nginx") && m.Labels["status"] == "FAIL" && m.Value == 1 {
					return true
				}
			}
			return false
		})
	})
}
