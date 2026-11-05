// probe_helpers_test.go — shared test builders for the
// cluster-health probe checks: node/pod fixtures, linkerd
// endpoint-sync fixtures, scylla fixtures, the fake Prometheus
// query server, and the ArgoCD/Application + workload-owner
// builders. Functional names — no wave provenance.
package clusterhealthprobes

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

// readyWorkerNode builds a Ready, schedulable worker node with optional
// extra conditions (FilesystemReadOnly/KernelHungTasks latched `age`
// ago for the hang check).
func readyWorkerNode(name string, cond corev1.NodeConditionType, condAge time.Duration, unschedulable bool) *corev1.Node {
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

// pendingUnscheduledPod builds a Pending pod that was never assigned — no
// nodeName, and when scheduled=false no PodScheduled condition at
// all (the scheduler-freeze signature).
func pendingUnscheduledPod(ns, name string, age time.Duration, scheduled bool) *corev1.Pod {
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

// ---------------------------------------------------------------------------
// Linkerd / scylla / node-hang builders
// ---------------------------------------------------------------------------

// precordonedWorkerNode builds a worker node carrying our pre-cordon stamp —
// unschedulable with node.ops/precordoned-by=node-hang-precordon and
// no active latch (the auto-uncordon shape).
func precordonedWorkerNode(name string, unschedulable bool) *corev1.Node {
	n := readyWorkerNode(name, "", 0, unschedulable)
	n.Annotations = map[string]string{
		nodeHangPreCordonAnno: nodeHangPreCordonValue,
	}
	return n
}

// linkerdInjectedNamespace builds a namespace opted into linkerd injection.
func linkerdInjectedNamespace(name string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name:   name,
		Labels: map[string]string{linkerdInjectLabel: "enabled"},
	}}
}

// headlessService builds a headless Service with a pod selector — the
// shape linkerd-destination derives endpoints from.
func headlessService(ns, name string, selector map[string]string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: corev1.ServiceSpec{
			ClusterIP: corev1.ClusterIPNone,
			Selector:  selector,
		},
	}
}

// readyPodWithIP builds a Running+Ready pod carrying podIP and labels.
func readyPodWithIP(ns, name, ip string, lbls map[string]string) *corev1.Pod {
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

// endpointSliceForService builds an EndpointSlice bound to svc carrying the
// given addresses, all Ready.
func endpointSliceForService(ns, svc string, addrs ...string) *discoveryv1.EndpointSlice {
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

// scyllaMemberPod builds a ScyllaDB member pod — Running+Ready by default;
// callers flip Ready/phase for the troubled shapes.
func scyllaMemberPod(ns, name, cluster, ip string, ready bool) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         ns,
			Name:              name,
			Labels:            map[string]string{scyllaClusterLabel: cluster},
			CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour)),
			UID:               types.UID("uid-" + name),
		},
		Spec: corev1.PodSpec{NodeName: "w1"},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			PodIP: ip,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:         scyllaContainerName,
				RestartCount: 3,
			}},
		},
	}
	if ready {
		p.Status.Conditions = []corev1.PodCondition{{
			Type:   corev1.PodReady,
			Status: corev1.ConditionTrue,
		}}
	}
	return p
}

// scyllaMemberService builds the per-member Service the scylla-operator
// creates for internode traffic — labeled with the pod it fronts.
func scyllaMemberService(ns, name, podName string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      name,
			Labels:    map[string]string{scyllaPodNameLabel: podName},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.96.0.10",
			Ports:     []corev1.ServicePort{{Port: 9042}},
		},
	}
}

// scyllaClusterCR builds a ScyllaCluster CR carrying one status condition
// whose lastTransitionTime is `age` old.
func scyllaClusterCR(ns, name, condType, condStatus string, age time.Duration) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "scylla.scylladb.com/v1",
		"kind":       "ScyllaCluster",
		"metadata":   map[string]any{"namespace": ns, "name": name},
		"status": map[string]any{
			"conditions": []any{map[string]any{
				"type":               condType,
				"status":             condStatus,
				"lastTransitionTime": time.Now().Add(-age).UTC().Format(time.RFC3339),
			}},
		},
	}}
}

// ---------------------------------------------------------------------------
// Pod fixtures + fake Prometheus server
// ---------------------------------------------------------------------------

// promTestSample is one Prometheus instant-vector sample for the fake
// query API.
type promTestSample struct {
	labels map[string]string
	value  float64
}

// promTestBody renders a Prometheus /api/v1/query vector response.
func promTestBody(samples []promTestSample) string {
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

// promTestServer serves promTestBody(respond(query)) at /api/v1/query and
// returns the server plus the last query string seen (for assertion).
func promTestServer(t *testing.T, respond func(query string) []promTestSample) (*httptest.Server, *string) {
	t.Helper()
	var lastQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		lastQuery = r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, promTestBody(respond(lastQuery)))
	}))
	t.Cleanup(srv.Close)
	return srv, &lastQuery
}

// podWithPhase builds a pod with explicit phase, readiness and age.
func podWithPhase(ns, name string, phase corev1.PodPhase, ready bool, age time.Duration) *corev1.Pod {
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

// meshedPodWithPorts builds a Running meshed pod exposing the given
// container ports, optionally carrying linkerd port annotations.
func meshedPodWithPorts(ns, name string, ports []int32, opaque, skip string) *corev1.Pod {
	pod := podWithPhase(ns, name, corev1.PodRunning, true, time.Hour)
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

// setPodOwnerStatefulSet gives the pod a controller ownerRef to a StatefulSet —
// the realistic shape for stateful meshed workloads.
func setPodOwnerStatefulSet(pod *corev1.Pod, stsName string) {
	pod.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: "apps/v1",
		Kind:       "StatefulSet",
		Name:       stsName,
		Controller: ptr.To(true),
	}}
}

// emptyStatefulSet builds a bare StatefulSet with an empty pod template —
// the heal target for the linkerd opaque-ports patch.
func emptyStatefulSet(ns, name string) *appsv1.StatefulSet {
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

// bareDeployment builds a bare Deployment — the live-owner fixture
// for the finalizer-sweep tests.
func bareDeployment(ns, name string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
	}
}

// argoCDApplication builds an ArgoCD Application unstructured carrying the
// given health status and conditions.
func argoCDApplication(ns, name, health string, conds ...map[string]any) *unstructured.Unstructured {
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

// coreDNSUpstreamPromServer answers the two coredns queries: the healthcheck
// query reports pod "bad" failing; the SERVFAIL query reports none.
func coreDNSUpstreamPromServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv, _ := promTestServer(t, func(query string) []promTestSample {
		if strings.Contains(query, "ForwardHealthcheckFailureCount") {
			return []promTestSample{{
				labels: map[string]string{"pod": "coredns-bad", "namespace": "kube-system"},
				value:  1.4,
			}}
		}
		return nil
	})
	return srv
}

func rabbitMQMemberPod(ns, name string, ready bool) *corev1.Pod {
	pod := podWithPhase(ns, name, corev1.PodRunning, ready, time.Hour)
	pod.Labels = map[string]string{
		"app.kubernetes.io/part-of":   "rabbitmq",
		"app.kubernetes.io/component": "rabbitmq",
	}
	return pod
}

func dragonflyMemberPod(ns, name string, role string) *corev1.Pod {
	pod := podWithPhase(ns, name, corev1.PodRunning, true, time.Hour)
	pod.Labels = map[string]string{
		"app.kubernetes.io/name": "dragonfly",
	}
	if role != "" {
		pod.Labels["app.kubernetes.io/role"] = role
	}
	return pod
}

// dragonflyPromServer answers the link-down query (BOTH the replica and
// the master report link down — the master must be flagged but never
// restarted) and the sync-storm query (non-empty -> storm active).
func dragonflyPromServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv, _ := promTestServer(t, func(query string) []promTestSample {
		if strings.Contains(query, "master_link_status") {
			return []promTestSample{
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
		return []promTestSample{{
			labels: map[string]string{"namespace": "dragonfly", "pod": "dragonfly-replica-1"},
			value:  4,
		}}
	})
	return srv
}

// imagePullWaitingPod builds a Pending pod whose container waits in the given
// reason, created `age` ago.
func imagePullWaitingPod(ns, name, reason, message string, age time.Duration) *corev1.Pod {
	pod := podWithPhase(ns, name, corev1.PodPending, false, age)
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
		Name: "app",
		State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
			Reason:  reason,
			Message: message,
		}},
	}}
	return pod
}

// ---------------------------------------------------------------------------
// EndpointSlice / linkerd-destination / desync-drive builders
// ---------------------------------------------------------------------------

// readyPodIPSince builds a Running+Ready pod whose PodReady
// LastTransitionTime is the explicit `readySince` — the EndpointSlice
// heal's missing-IP fuse (linkerdSliceHealMinAge) reads that clock,
// and tests need Ready ages both inside and outside it.
func readyPodIPSince(ns, name, ip string, lbls map[string]string,
	readySince time.Time) *corev1.Pod {
	p := readyPodWithIP(ns, name, ip, lbls)
	p.Status.Conditions[0].LastTransitionTime = metav1.NewTime(readySince)
	return p
}

// managedEndpointSlice builds an EndpointSlice carrying the
// managed-by=endpointslice-controller.k8s.io label — the only slice
// kind the desync heal deletes (KCM recreates those; mirror and
// third-party slices are left alone).
func managedEndpointSlice(ns, svc string, addrs ...string) *discoveryv1.EndpointSlice {
	s := endpointSliceForService(ns, svc, addrs...)
	s.Labels[discoveryv1.LabelManagedBy] = linkerdSliceManagedByESC
	return s
}

// linkerdDestinationPod builds a linkerd-destination pod — the bounce target
// the heal picks (oldest match wins; one per test suffices).
func linkerdDestinationPod(name string, age time.Duration) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace:         linkerdNS,
		Name:              name,
		UID:               types.UID("uid-" + name),
		CreationTimestamp: metav1.NewTime(time.Now().Add(-age)),
	}}
}

// driveEndpointDesync runs the check at base, inside the window, and
// past it — the same three-sweep shape as
// TestCheckLinkerdEndpointSyncDesyncHeal — returning the final
// probeResult.
func driveEndpointDesync(t *testing.T, p *clusterHealthProber, base time.Time) probeResult {
	t.Helper()
	p.now = func() time.Time { return base }
	p.checkLinkerdEndpointSync(ctx)
	p.now = func() time.Time { return base.Add(5 * time.Minute) }
	p.checkLinkerdEndpointSync(ctx)
	p.now = func() time.Time { return base.Add(linkerdEndpointDesyncMinAge + time.Minute) }
	return p.checkLinkerdEndpointSync(ctx)
}
