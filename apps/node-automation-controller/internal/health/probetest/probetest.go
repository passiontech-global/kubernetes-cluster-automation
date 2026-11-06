// Package probetest holds the shared test builders every
// cluster-health check subpackage uses: the standard probefw.Deps
// wiring with deterministic seams, the fake dynamic client carrying
// every GVR the checks List, node/pod/EndpointSlice fixtures, the
// fake Prometheus query server, and the metric-registry lookup
// helpers. Functional names — no wave provenance.
package probetest

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/promq"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// NewDeps builds a probefw.Deps with the env-equivalent defaults but
// deterministic seams: DNS always resolves, and the HTTP check points
// at a dead address (fast connection-refused FAIL) unless the test
// overrides Cfg.HTTPContent.URL/HTTPClient.
func NewDeps(cs kubernetes.Interface, dyn dynamic.Interface) *probefw.Deps {
	d := &probefw.Deps{
		Name: "cluster-health-probes",
		CS:   cs,
		Dyn:  dyn,
		Cfg: probefw.Config{
			DNS: probefw.DNSConfig{Hostnames: []string{"svc-a.ns.svc", "svc-b.ns.svc"}},
			Timeouts: probefw.TimeoutsConfig{
				Check:    5 * time.Second,
				PerCheck: time.Minute,
			},
			HTTPContent: probefw.HTTPContentConfig{
				URL:      "http://127.0.0.1:1/",
				Expected: "Healthy",
			},
			Pods: probefw.PodsConfig{
				Namespace:    "kube-system",
				MaxRestarts:  10,
				SkipDuration: 10 * time.Minute,
			},
			Quota: probefw.QuotaConfig{Threshold: 0.9},
			KCM: probefw.KCMConfig{
				LeaseMaxAge:  30 * time.Second,
				FreezeMinAge: 10 * time.Minute,
			},
		},
		LookupHost: func(context.Context, string) ([]string, error) {
			return []string{"10.0.0.1"}, nil
		},
		HTTPClient: &http.Client{},
		Now:        time.Now,
	}
	// Same wiring the root prober applies: the Prometheus client
	// shares the HTTPClient seam tests swap post-construction and
	// bounds each query by the check timeout.
	d.Prom = promq.Client{HTTP: d.HTTPClient, Timeout: d.Cfg.Timeouts.Check}
	return d
}

// FreezeNow pins the Deps clock to base — the shared shape for the
// "p.Now = func() time.Time { return base }" every persistence-window
// test hand-rolls. Advance by calling again with a new base (the
// clock is the same plain func var production wires to time.Now).
func FreezeNow(d *probefw.Deps, base time.Time) {
	d.Now = func() time.Time { return base }
}

// OpDyn registers every GVR the sweep checks scan — the fake dynamic
// client PANICS on an unregistered GVR List, so every watched
// operator resource (W5.8 original five + the ten W7-C2 additions)
// plus the OLM/autopilot reads must be mapped.
func OpDyn(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return testutil.NewFakeDyn(map[schema.GroupVersionResource]string{
		kube.GVRGateway:   "GatewayList",
		kube.GVRHTTPRoute: "HTTPRouteList",
		kube.GVRGRPCRoute: "GRPCRouteList",
		// The owns filter LISTs classes once per stuck gateway-api
		// object — unregistered GVR panics the fake.
		kube.GVRGatewayClass:  "GatewayClassList",
		kube.GVRScyllaCluster: "ScyllaClusterList",
		kube.GVRDragonfly:     "DragonflyList",
		kube.GVRHelmReleaseV2: "HelmReleaseList",
		// The flux retry check falls back to the previous storage
		// version when v2 is unserved — register it too so that
		// probe order cannot panic the fake.
		kube.GVRHelmReleaseV2Beta2: "HelmReleaseList",
		kube.GVRFluxKustomization:  "KustomizationList",
		// W7-C2 — the ten additional watched operators' CRDs.
		kube.GVRFluxGitRepository:  "GitRepositoryList",
		kube.GVRFluxHelmRepository: "HelmRepositoryList",
		kube.GVRFluxHelmChart:      "HelmChartList",
		kube.GVRFluxOCIRepository:  "OCIRepositoryList",
		kube.GVRFluxBucket:         "BucketList",
		{Group: "notification.toolkit.fluxcd.io", Version: "v1beta3", Resource: "alerts"}:    "AlertList",
		{Group: "notification.toolkit.fluxcd.io", Version: "v1beta3", Resource: "providers"}: "ProviderList",
		{Group: "notification.toolkit.fluxcd.io", Version: "v1beta3", Resource: "receivers"}: "ReceiverList",
		kube.GVRCertificate:           "CertificateList",
		kube.GVRExternalSecretV1:      "ExternalSecretList",
		kube.GVRExternalSecretV1Beta1: "ExternalSecretList",
		kube.GVRRabbitMQCluster:       "RabbitmqClusterList",
		kube.GVRKedaScaledObject:      "ScaledObjectList",
		kube.GVRArgoCD:                "ArgoCDList",
		// argocd-app-stuck Lists Applications unconditionally every
		// sweep — same unregistered-GVR panic exposure as the
		// watchdog table.
		kube.GVRArgoCDApplication:      "ApplicationList",
		kube.GVRKargoStage:             "StageList",
		kube.GVRKargoWarehouse:         "WarehouseList",
		kube.GVREverestDatabaseCluster: "DatabaseClusterList",
		kube.GVRShipwrightBuild:        "BuildList",
		// W10-CP3 — the nine additional watched operators' CRDs.
		kube.GVRNodeHealthCheck:         "NodeHealthCheckList",
		kube.GVRSelfNodeRemediation:     "SelfNodeRemediationList",
		kube.GVRPerconaXtraDBCluster:    "PerconaXtraDBClusterList",
		kube.GVRPerconaPGCluster:        "PerconaPGClusterList",
		kube.GVRPerconaServerMongoDB:    "PerconaServerMongoDBList",
		kube.GVRTektonPipelineRun:       "PipelineRunList",
		kube.GVRShipwrightOperatorBuild: "ShipwrightBuildList",
		// W7-C5 — OLM reads.
		kube.GVROLMClusterServiceVersion: "ClusterServiceVersionList",
		kube.GVROLMSubscription:          "SubscriptionList",
		// api-object-sprawl-report-gc — trivy + policy reports.
		kube.GVRVulnerabilityReport: "VulnerabilityReportList",
		kube.GVRConfigAuditReport:   "ConfigAuditReportList",
		kube.GVRExposedSecretReport: "ExposedSecretReportList",
		kube.GVREphemeralReport:     "EphemeralReportList",
		kube.GVRPolicyReport:        "PolicyReportList",
		// cilium-missing-endpoint — the CEP census.
		kube.GVRCiliumEndpoint: "CiliumEndpointList",
		// liqo-tunnel-health — the peering CR family.
		kube.GVRLiqoConnection:    "ConnectionList",
		kube.GVRLiqoGatewayClient: "GatewayClientList",
		kube.GVRLiqoGatewayServer: "GatewayServerList",
		// postgres-wal-archive-guard — the CNPG cluster scan.
		kube.GVRCNPGCluster: "ClusterList",
		// Maintenance mutex read.
		kube.AutopilotPlanGVR: "PlanList",
	}, objs...)
}

// UnstructuredObj builds a CR object carrying a generation and an
// optional status.observedGeneration (og=0 leaves the field absent).
func UnstructuredObj(apiVersion, kind, ns, name string, gen, og int64) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata": map[string]any{
			"namespace": ns, "name": name, "generation": gen,
		},
	}}
	if og > 0 {
		_ = unstructured.SetNestedField(obj.Object, og, "status", "observedGeneration")
	}
	return obj
}

// FindMetric locates one series by exact label set inside a gathered
// family — returns nil when absent.
func FindMetric(t *testing.T, family string, want map[string]string) *dto.Metric {
	t.Helper()
	fams, err := ctrlmetrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range fams {
		if f.GetName() != family {
			continue
		}
		for _, m := range f.GetMetric() {
			if len(m.GetLabel()) != len(want) {
				continue
			}
			match := true
			for _, l := range m.GetLabel() {
				v, ok := want[l.GetName()]
				if !ok || v != l.GetValue() {
					match = false
					break
				}
			}
			if match {
				return m
			}
		}
	}
	return nil
}

// HealthGauge reads the kuberhealthy_check{check,status} gauge under
// the literal "kuberhealthy" namespace label.
func HealthGauge(t *testing.T, check, status string) (float64, bool) {
	t.Helper()
	m := FindMetric(t, "kuberhealthy_check",
		map[string]string{"check": check, "namespace": "kuberhealthy", "status": status})
	if m == nil {
		return 0, false
	}
	return m.GetGauge().GetValue(), true
}

// ---------------------------------------------------------------------------
// Node / pod / EndpointSlice builders
// ---------------------------------------------------------------------------

// ReadyWorkerNode builds a Ready, schedulable worker node with optional
// extra conditions (FilesystemReadOnly/KernelHungTasks latched `age`
// ago for the hang check).
func ReadyWorkerNode(name string, cond corev1.NodeConditionType, condAge time.Duration, unschedulable bool) *corev1.Node {
	n := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       corev1.NodeSpec{Unschedulable: unschedulable},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{
			{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}},
	}
	if cond != "" {
		n.Status.Conditions = append(n.Status.Conditions, corev1.NodeCondition{
			Type:               cond,
			Status:             corev1.ConditionTrue,
			LastTransitionTime: metav1.NewTime(time.Now().Add(-condAge)),
		})
	}
	return n
}

// PendingUnscheduledPod builds a Pending pod that was never assigned —
// no nodeName, and when scheduled=false no PodScheduled condition at
// all (the scheduler-freeze signature).
func PendingUnscheduledPod(ns, name string, age time.Duration, scheduled bool) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name,
			CreationTimestamp: metav1.NewTime(time.Now().Add(-age)),
		},
		Status: corev1.PodStatus{Phase: corev1.PodPending},
	}
	if scheduled {
		p.Status.Conditions = []corev1.PodCondition{{
			Type:   corev1.PodScheduled,
			Status: corev1.ConditionFalse}}
	}
	return p
}

// HeadlessService builds a headless Service with a pod selector — the
// shape linkerd-destination derives endpoints from.
func HeadlessService(ns, name string, selector map[string]string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: corev1.ServiceSpec{
			ClusterIP: corev1.ClusterIPNone,
			Selector:  selector,
		},
	}
}

// ReadyPodWithIP builds a Running+Ready pod carrying podIP and labels.
func ReadyPodWithIP(ns, name, ip string, lbls map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         ns,
			Name:              name,
			Labels:            lbls,
			CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour)),
			UID:               types.UID("uid-" + name),
		},
		Spec: corev1.PodSpec{NodeName: "w1"},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			PodIP: ip,
			Conditions: []corev1.PodCondition{{
				Type:   corev1.PodReady,
				Status: corev1.ConditionTrue,
			}},
		},
	}
}

// EndpointSliceForService builds an EndpointSlice bound to svc carrying
// the given addresses, all Ready.
func EndpointSliceForService(ns, svc string, addrs ...string) *discoveryv1.EndpointSlice {
	s := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      svc + "-abc",
			Labels:    map[string]string{discoveryv1.LabelServiceName: svc},
		},
	}
	for _, a := range addrs {
		s.Endpoints = append(s.Endpoints, discoveryv1.Endpoint{
			Addresses:  []string{a},
			Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
		})
	}
	return s
}

// PodWithPhase builds a pod with explicit phase, readiness and age.
func PodWithPhase(ns, name string, phase corev1.PodPhase, ready bool, age time.Duration) *corev1.Pod {
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

// ---------------------------------------------------------------------------
// Fake Prometheus query server
// ---------------------------------------------------------------------------

// PromTestSample is one Prometheus instant-vector sample for the fake
// query API.
type PromTestSample struct {
	Labels map[string]string
	Value  float64
}

// promTestBody renders a Prometheus /api/v1/query vector response.
func promTestBody(samples []PromTestSample) string {
	var b strings.Builder
	b.WriteString(`{"status":"success","data":{"resultType":"vector","result":[`)
	for i, s := range samples {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"metric":{`)
		first := true
		for k, v := range s.Labels {
			if !first {
				b.WriteString(",")
			}
			first = false
			fmt.Fprintf(&b, "%q:%q", k, v)
		}
		b.WriteString(`},"value":[1,"` +
			strconv.FormatFloat(s.Value, 'f', -1, 64) + `"]}`)
	}
	b.WriteString(`]}}`)
	return b.String()
}

// PromTestServer serves promTestBody(respond(query)) at /api/v1/query
// and returns the server plus the last query string seen (for
// assertion).
func PromTestServer(t *testing.T, respond func(query string) []PromTestSample) (*httptest.Server, *string) {
	t.Helper()
	var lastQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		lastQuery = r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, promTestBody(respond(lastQuery)))
	}))
	t.Cleanup(srv.Close)
	return srv, &lastQuery
}
