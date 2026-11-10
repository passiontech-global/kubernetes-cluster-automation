// stateful_masterless_cnpg_test.go — coverage for the CNPG half of
// the stateful-masterless-services check: CloudNativePG owns bare
// Pods (no StatefulSet), so cnpgMasterlessCandidates aggregates the
// pod census by cnpg.io/cluster, stampTarget persists the
// first-seen window on the Service itself, and healDue routes a
// CNPG candidate through dbOperatorForLabels — which resolves ""
// for the synthetic cluster label set, leaving the per-pod role
// diagnostics as the only action (never a pod delete).
package datastore

import (
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// Builders (cnpgML prefix — unique across sibling test files)
// ---------------------------------------------------------------------------

// cnpgMLPod builds a Ready pod of the named CloudNativePG cluster —
// cnpg.io/cluster is the grouping label cnpgMasterlessCandidates
// aggregates on; app=cluster keeps the pod selector-compatible with
// the fixtures' master-role Services.
func cnpgMLPod(ns, name, cluster string, ready bool) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name,
			Labels: map[string]string{
				cnpgClusterLabel:       cluster,
				"app":                  cluster,
				"cnpg.io/instanceName": name,
			},
		},
	}
	if ready {
		pod.Status.Conditions = []corev1.PodCondition{{
			Type:   corev1.PodReady,
			Status: corev1.ConditionTrue,
		}}
	}
	return pod
}

// cnpgMLMasterSvc builds the master-role ClusterIP Service routing
// to a CNPG cluster's pods — selector carries the cluster label plus
// a role key (stripped by selectorMatchesSTS before matching).
func cnpgMLMasterSvc(ns, name, cluster string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.96.0.20",
			Selector: map[string]string{
				cnpgClusterLabel: cluster,
				"role":           "master",
			},
		},
	}
}

// cnpgMLEndpointSlice builds an EndpointSlice for svc with one Ready
// endpoint — the "master reachable" fixture for the resolution half.
func cnpgMLEndpointSlice(ns, svc string) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: svc + "-zzz",
			Labels: map[string]string{discoveryv1.LabelServiceName: svc},
		},
		Endpoints: []discoveryv1.Endpoint{{
			Addresses:  []string{"10.0.0.50"},
			Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
		}},
	}
}

// ---------------------------------------------------------------------------
// cnpgMasterlessCandidates — the pure candidate pairing
// ---------------------------------------------------------------------------

// Ready CNPG pods aggregate into one candidate per (ns, cluster);
// pods that are unready, terminating, or unlabeled never pair, and
// only master-role ClusterIP Services whose non-role selector keys
// match the cluster's pod labels qualify.
func TestCNPGMasterlessCandidates(t *testing.T) {
	ready := cnpgMLPod("db", "pg-1-aaa", "pg", true)
	ready2 := cnpgMLPod("db", "pg-1-bbb", "pg", true)
	unready := cnpgMLPod("db", "pg-2-ccc", "pg", false)
	terminating := cnpgMLPod("db", "pg-3-ddd", "pg", true)
	termAt := metav1.NewTime(time.Now())
	terminating.DeletionTimestamp = &termAt
	plain := &corev1.Pod{ // no cnpg.io/cluster label at all
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "db", Name: "web-0",
			Labels: map[string]string{"app": "web"}},
		Status: corev1.PodStatus{Conditions: []corev1.PodCondition{{
			Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	}
	otherNS := cnpgMLPod("other", "pg-1-eee", "pg", true)

	svcs := []corev1.Service{
		*cnpgMLMasterSvc("db", "pg-ro", "pg"),        // matches cluster pg
		*cnpgMLMasterSvc("db", "pg-rw", "pg"),        // also matches — same cluster
		*cnpgMLMasterSvc("db", "other-svc", "other"), // no pods for "other" in db
		func() corev1.Service { // headless — deliberately per-pod
			s := cnpgMLMasterSvc("db", "pg-headless", "pg")
			s.Spec.ClusterIP = corev1.ClusterIPNone
			return *s
		}(),
		func() corev1.Service { // no master role anywhere
			s := cnpgMLMasterSvc("db", "pg-plain", "pg")
			s.Spec.Selector = map[string]string{cnpgClusterLabel: "pg"}
			return *s
		}(),
		func() corev1.Service { // selector misses the pod labels
			s := cnpgMLMasterSvc("db", "pg-miss", "pg")
			s.Spec.Selector[cnpgClusterLabel] = "different-cluster"
			return *s
		}(),
		*cnpgMLMasterSvc("other", "pg-ro", "pg"), // pairs with the other-ns pod
	}

	got := cnpgMasterlessCandidates(
		[]corev1.Pod{*ready, *ready2, *unready, *terminating, *plain, *otherNS}, svcs)

	// db/pg pairs with pg-ro + pg-rw; other/pg pairs with other/pg-ro.
	// pg-headless, pg-plain and pg-miss never qualify.
	if len(got) != 3 {
		t.Fatalf("candidates = %d, want 3: %+v", len(got), got)
	}
	byKey := map[string]masterSvc{}
	for _, c := range got {
		byKey[c.ns+"/"+c.svc] = c
		if c.sts != nil {
			t.Fatalf("cnpg candidate %s/%s carries a StatefulSet", c.ns, c.svc)
		}
		if c.svcObj == nil {
			t.Fatalf("cnpg candidate %s/%s missing svcObj stamp target", c.ns, c.svc)
		}
	}
	for _, k := range []string{"db/pg-ro", "db/pg-rw", "other/pg-ro"} {
		c, ok := byKey[k]
		if !ok {
			t.Fatalf("missing candidate %s", k)
		}
		wantCluster := "pg"
		if c.cnpg != wantCluster {
			t.Fatalf("%s cnpg=%q, want %q", k, c.cnpg, wantCluster)
		}
	}
	// The unready/terminating/unlabeled pods contributed nothing —
	// only the two Ready db pods + one Ready other pod seeded
	// clusters, and each cluster emits at most one candidate per
	// qualifying Service.
}

// ---------------------------------------------------------------------------
// workloadName / stampTarget — the CNPG identity + stamp plumbing
// ---------------------------------------------------------------------------

// workloadName is the StatefulSet name when one exists, else the
// CNPG cluster value — the gauge/key identity for both shapes.
func TestMasterSvcWorkloadName(t *testing.T) {
	sts := shSTS("db", "pg", 1, map[string]string{"app": "pg"})
	for _, tc := range []struct {
		name string
		c    masterSvc
		want string
	}{
		{"sts-backed", masterSvc{ns: "db", svc: "s", sts: sts}, "pg"},
		{"cnpg", masterSvc{ns: "db", svc: "s", cnpg: "pg"}, "pg"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.c.workloadName(); got != tc.want {
				t.Fatalf("workloadName = %q, want %q", got, tc.want)
			}
		})
	}
}

// stampTarget picks the stamp carrier per candidate shape: the
// StatefulSet for STS-backed workloads (patch lands on the STS), the
// Service itself for CNPG (patch lands on the Service — there is no
// STS to annotate).
func TestStampTarget(t *testing.T) {
	sts := shSTS("db", "pg", 1, map[string]string{"app": "pg"})
	svc := cnpgMLMasterSvc("db", "pg-ro", "pg")
	cs := fake.NewSimpleClientset(sts, svc)
	chk := NewStatefulMasterlessCheck(probetest.NewDeps(cs, probetest.OpDyn()))
	c := chk.(*statefulMasterlessCheck)

	patchData := func() []byte {
		data, err := kube.MergePatchAnnos(map[string]any{
			"test/stamp": "v1"})
		if err != nil {
			t.Fatalf("MergePatchAnnos: %v", err)
		}
		return data
	}

	// STS candidate → the returned object IS the StatefulSet and the
	// closure patches StatefulSets.
	obj, patch := c.stampTarget(masterSvc{
		ns: "db", svc: "pg-ro", sts: sts, svcObj: svc})
	if obj.GetName() != "pg" {
		t.Fatalf("sts stampTarget object = %q, want pg", obj.GetName())
	}
	if err := patch(ctx, patchData()); err != nil {
		t.Fatalf("sts stamp patch: %v", err)
	}
	gotSTS, err := cs.AppsV1().StatefulSets("db").
		Get(ctx, "pg", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if gotSTS.Annotations["test/stamp"] != "v1" {
		t.Fatal("sts stamp annotation missing")
	}

	// CNPG candidate → the returned object IS the Service and the
	// closure patches Services (never a nonexistent StatefulSet).
	obj, patch = c.stampTarget(masterSvc{
		ns: "db", svc: "pg-ro", svcObj: svc, cnpg: "pg"})
	if obj.GetName() != "pg-ro" {
		t.Fatalf("cnpg stampTarget object = %q, want pg-ro", obj.GetName())
	}
	if err := patch(ctx, patchData()); err != nil {
		t.Fatalf("svc stamp patch: %v", err)
	}
	gotSvc, err := cs.CoreV1().Services("db").
		Get(ctx, "pg-ro", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if gotSvc.Annotations["test/stamp"] != "v1" {
		t.Fatal("service stamp annotation missing")
	}
}

// ---------------------------------------------------------------------------
// End-to-end — a masterless CNPG service through Run
// ---------------------------------------------------------------------------

// A CNPG cluster whose master-role Service reports 0 Ready endpoints
// past the windows FAILs the check, emits the zero-endpoints gauge
// under the CLUSTER name, persists the first-seen stamp on the
// Service, and — because dbOperatorForLabels resolves no known db
// operator for the synthetic cluster label set — deletes nothing:
// the role diagnostics path is log-only.
func TestCNPGMasterlessZeroEndpoints(t *testing.T) {
	testutil.CleanupMetric(t, statefulServiceZeroEndpointsGauge,
		"db", "pg-ro", "pg")
	t.Cleanup(func() {
		statefulServiceZeroEndpointsGauge.DeleteLabelValues("db", "pg-ro", "pg")
	})
	base := time.Now()
	pod := cnpgMLPod("db", "pg-1-aaa", "pg", true)
	svc := cnpgMLMasterSvc("db", "pg-ro", "pg")
	cs := fake.NewSimpleClientset(pod, svc)
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	chk := probetest.MustCheck[*statefulMasterlessCheck](t, p)
	chk.stsZeroSince.Observe("db/pg-ro/pg", base.Add(-12*time.Minute))

	res := chk.Run(ctx)
	if res.Pass {
		t.Fatal("masterless CNPG service must FAIL")
	}
	m := probetest.FindMetric(t, "node_automation_stateful_service_zero_endpoints",
		map[string]string{"namespace": "db", "service": "pg-ro", "statefulset": "pg"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("zero-endpoints gauge = %v, want 1", m)
	}
	// The persisted first-seen stamp rides the Service — the CNPG
	// cluster has no StatefulSet to carry it.
	gotSvc, err := cs.CoreV1().Services("db").
		Get(ctx, "pg-ro", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	raw := gotSvc.Annotations[kube.AnnoFirstSeenStatefulMasterless]
	if !strings.Contains(raw, "db/pg-ro/pg") {
		t.Fatalf("first-seen stamp missing cluster key on the Service: %q", raw)
	}
	// Diagnostics-only heal path: no pod may be deleted for a CNPG
	// candidate — its election contract is the CNPG operator's, not
	// a generic ordinal kill.
	for _, a := range cs.Actions() {
		if a.GetResource().Resource == "pods" && a.GetVerb() == "delete" {
			t.Fatalf("cnpg pod delete must never fire, got %v", a)
		}
	}
	if _, err := cs.CoreV1().Pods("db").
		Get(ctx, "pg-1-aaa", metav1.GetOptions{}); err != nil {
		t.Fatal("cnpg pod wrongly deleted")
	}
}

// The resolution twin: once the master Service reports a Ready
// endpoint again, the Service's persisted stamp clears (a stale
// stamp would fast-trip the heal on the next wedge) and the gauge
// series is dropped.
func TestCNPGMasterlessResolutionClearsStamp(t *testing.T) {
	testutil.CleanupMetric(t, statefulServiceZeroEndpointsGauge,
		"db", "pg-ro", "pg")
	base := time.Now()
	pod := cnpgMLPod("db", "pg-1-aaa", "pg", true)
	svc := cnpgMLMasterSvc("db", "pg-ro", "pg")
	cs := fake.NewSimpleClientset(pod, svc)
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	chk := probetest.MustCheck[*statefulMasterlessCheck](t, p)
	chk.stsZeroSince.Observe("db/pg-ro/pg", base.Add(-12*time.Minute))

	if res := chk.Run(ctx); res.Pass {
		t.Fatal("first sweep must FAIL — 0 ready endpoints")
	}
	// The master comes back — one Ready endpoint on the Service.
	if _, err := cs.DiscoveryV1().EndpointSlices("db").Create(ctx,
		cnpgMLEndpointSlice("db", "pg-ro"), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if res := chk.Run(ctx); !res.Pass {
		t.Fatalf("resolved masterless service must pass: %+v", res)
	}
	gotSvc, err := cs.CoreV1().Services("db").
		Get(ctx, "pg-ro", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := gotSvc.Annotations[kube.AnnoFirstSeenStatefulMasterless]; ok {
		t.Fatal("first-seen stamp must clear once the master is reachable")
	}
	if m := probetest.FindMetric(t,
		"node_automation_stateful_service_zero_endpoints",
		map[string]string{"namespace": "db", "service": "pg-ro",
			"statefulset": "pg"}); m != nil {
		t.Fatal("zero-endpoints gauge must drop after resolution")
	}
}

// A CNPG cluster whose pods carry standard app.kubernetes.io/managed-by:
// cloudnative-pg attributes to "cloudnative-pg" via dbOperatorForLabels
// and bounces the cnpg-controller-manager operator pod (never the
// cluster's own data pod) to force primary re-election.
func TestCNPGMasterlessManagedByCloudNativePGBouncesOperator(t *testing.T) {
	testutil.CleanupMetric(t, statefulServiceZeroEndpointsGauge,
		"db", "pg-rw", "pg")
	t.Cleanup(func() {
		statefulServiceZeroEndpointsGauge.DeleteLabelValues("db", "pg-rw", "pg")
	})
	base := time.Now()
	pod := cnpgMLPod("db", "pg-1", "pg", true)
	pod.Labels["app.kubernetes.io/managed-by"] = "cloudnative-pg"
	opPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "cnpg-system",
			Name:      "cnpg-controller-manager-7f9c8-abc",
			UID:       "op-uid-1",
			CreationTimestamp: metav1.NewTime(
				base.Add(-1 * time.Hour)),
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	svc := cnpgMLMasterSvc("db", "pg-rw", "pg")
	cs := fake.NewSimpleClientset(pod, opPod, svc)
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	chk := probetest.MustCheck[*statefulMasterlessCheck](t, p)
	chk.stsZeroSince.Observe("db/pg-rw/pg", base.Add(-12*time.Minute))

	res := chk.Run(ctx)
	if res.Pass {
		t.Fatal("masterless CNPG service must FAIL")
	}
	if _, err := cs.CoreV1().Pods("cnpg-system").
		Get(ctx, opPod.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("expected cnpg-controller-manager pod to be bounced, err=%v", err)
	}
	if _, err := cs.CoreV1().Pods("db").
		Get(ctx, pod.Name, metav1.GetOptions{}); err != nil {
		t.Fatalf("cnpg data pod must never be deleted: %v", err)
	}
}

// A pod census failure is an infra error for the whole check — the
// CNPG candidate pairing reads AllPods and "0 ready" is
// indistinguishable from "no data" without it.
func TestCNPGMasterlessPodListErrorIsInfra(t *testing.T) {
	svc := cnpgMLMasterSvc("db", "pg-ro", "pg")
	cs := fake.NewSimpleClientset(svc)
	cs.PrependReactor("list", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewInternalError(
				fmt.Errorf("apiserver down"))
		})
	p := testProberDyn(cs, probetest.OpDyn())
	res := probetest.MustCheck[*statefulMasterlessCheck](t, p).Run(ctx)
	if res.Infra == nil {
		t.Fatalf("pod list failure must surface as infra error: %+v", res)
	}
}
