// stateful_masterless_services_test.go — coverage for the
// stateful-masterless-services check: the W7-C3 dragonfly
// dual-replica deadlock heal and the W4/W10-FIX4 db-operator pod
// prefix resolution.
package datastore

import (
	"fmt"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// W4 — dbOperatorFor matches a pod-template label carrying the
// operator name; a generic STS matches nothing.
func TestDBOperatorFor(t *testing.T) {
	sts := &appsv1.StatefulSet{
		Spec: appsv1.StatefulSetSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app.kubernetes.io/managed-by": "pxc-operator"}}}},
	}
	if got := dbOperatorFor(sts); got != "pxc-operator" {
		t.Fatalf("dbOperatorFor=%q, want pxc-operator", got)
	}
	if got := dbOperatorFor(&appsv1.StatefulSet{}); got != "" {
		t.Fatalf("dbOperatorFor=%q, want empty", got)
	}
}

// W10-FIX4 — dbOperatorPodPrefixes resolves BOTH spellings of a
// Percona operator to the same alias group: the long Deployment
// name AND the short chart alias must yield every pod-name prefix,
// whichever spelling dbOperatorFor matched.
func TestDBOperatorPodPrefixes(t *testing.T) {
	want := []string{"percona-xtradb-cluster-operator", "pxc-operator"}
	for _, in := range []string{
		"percona-xtradb-cluster-operator", "pxc-operator"} {
		got := dbOperatorPodPrefixes(in)
		if len(got) != len(want) {
			t.Fatalf("dbOperatorPodPrefixes(%q)=%v, want %v", in, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("dbOperatorPodPrefixes(%q)=%v, want %v", in, got, want)
			}
		}
	}
	// Non-aliased operator → bare name only.
	if got := dbOperatorPodPrefixes("scylla-operator"); len(got) != 1 ||
		got[0] != "scylla-operator" {
		t.Fatalf("dbOperatorPodPrefixes(scylla)=%v, want [scylla-operator]", got)
	}
}

// ---------------------------------------------------------------------------
// W7-C3 — dragonfly dual-replica deadlock heal
// ---------------------------------------------------------------------------

// dragonflyRolePod builds a Ready STS pod with the given role label
// ("" = no role label — the dual-replica wedge).
func dragonflyRolePod(ns, name, role string, ready bool) *corev1.Pod {
	labels := map[string]string{"app": "dragonfly", "app.kubernetes.io/part-of": "dragonfly"}
	if role != "" {
		labels["role"] = role
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name, UID: types.UID(name), Labels: labels,
		},
	}
	if ready {
		pod.Status.Conditions = []corev1.PodCondition{{
			Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	}
	return pod
}

// Deadlock end-to-end: 12m masterless streak, operator heal landed
// 4m ago, both pods Ready with role=replica → ordinal-0 deleted,
// counter bumped, stamp persisted on the STS.
func TestDeadlockDeletesLowestOrdinal(t *testing.T) {
	dragonflyMasterlessPodHealsTotal.DeleteLabelValues("db", "dragonfly")
	t.Cleanup(func() {
		dragonflyMasterlessPodHealsTotal.DeleteLabelValues("db", "dragonfly")
		statefulServiceZeroEndpointsGauge.DeleteLabelValues("db", "dragonfly-master", "dragonfly")
	})
	base := time.Now()
	sts := shSTS("db", "dragonfly", 2,
		map[string]string{"app": "dragonfly", "app.kubernetes.io/part-of": "dragonfly"})
	svc := shMasterSvc("db", "dragonfly-master",
		map[string]string{"app": "dragonfly", "role": "master"})
	cs := fake.NewSimpleClientset(sts, svc,
		dragonflyRolePod("db", "dragonfly-0", "replica", true),
		dragonflyRolePod("db", "dragonfly-1", "replica", true))
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	probetest.MustCheck[*statefulMasterlessCheck](t, p).stsZeroSince.
		Observe("db/dragonfly-master/dragonfly", base.Add(-12*time.Minute))
	probetest.MustCheck[*statefulMasterlessCheck](t, p).drOpHealAt = map[string]time.Time{"db/dragonfly": base.Add(-4 * time.Minute)}

	if res := probetest.MustCheck[*statefulMasterlessCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("deadlocked masterless service must FAIL")
	}
	if _, err := cs.CoreV1().Pods("db").
		Get(ctx, "dragonfly-0", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("ordinal-0 pod must be deleted, err=%v", err)
	}
	if _, err := cs.CoreV1().Pods("db").
		Get(ctx, "dragonfly-1", metav1.GetOptions{}); err != nil {
		t.Fatal("only the lowest ordinal may be reaped")
	}
	m := probetest.FindMetric(t, "node_automation_dragonfly_masterless_pod_heals_total",
		map[string]string{"namespace": "db", "statefulset": "dragonfly"})
	if m == nil || m.GetCounter().GetValue() != 1 {
		t.Fatal("deadlock heals counter = 0, want 1")
	}
	gotSTS, err := cs.AppsV1().StatefulSets("db").Get(ctx, "dragonfly", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if gotSTS.Annotations[dragonflyPodHealAnno] == "" {
		t.Fatal("pod-heal stamp annotation missing on the STS")
	}
}

// The step-2 heal must wait for the operator restart to settle — a
// 1m-old operator heal keeps ordinal-0 alive.
func TestDeadlockWaitsForOperatorSettle(t *testing.T) {
	base := time.Now()
	sts := shSTS("db", "dragonfly", 2,
		map[string]string{"app": "dragonfly", "app.kubernetes.io/part-of": "dragonfly"})
	svc := shMasterSvc("db", "dragonfly-master",
		map[string]string{"app": "dragonfly", "role": "master"})
	cs := fake.NewSimpleClientset(sts, svc,
		dragonflyRolePod("db", "dragonfly-0", "replica", true),
		dragonflyRolePod("db", "dragonfly-1", "replica", true))
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	probetest.MustCheck[*statefulMasterlessCheck](t, p).stsZeroSince.
		Observe("db/dragonfly-master/dragonfly", base.Add(-12*time.Minute))
	probetest.MustCheck[*statefulMasterlessCheck](t, p).drOpHealAt = map[string]time.Time{"db/dragonfly": base.Add(-time.Minute)}

	_ = probetest.MustCheck[*statefulMasterlessCheck](t, p).Run(ctx)
	if _, err := cs.CoreV1().Pods("db").
		Get(ctx, "dragonfly-0", metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted while the operator heal is still settling")
	}
}

// No operator heal on record at all — step 1 never landed, so the
// pod kill must not skip ahead.
func TestDeadlockRequiresOperatorHeal(t *testing.T) {
	base := time.Now()
	sts := shSTS("db", "dragonfly", 2,
		map[string]string{"app": "dragonfly", "app.kubernetes.io/part-of": "dragonfly"})
	svc := shMasterSvc("db", "dragonfly-master",
		map[string]string{"app": "dragonfly", "role": "master"})
	cs := fake.NewSimpleClientset(sts, svc,
		dragonflyRolePod("db", "dragonfly-0", "replica", true))
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	probetest.MustCheck[*statefulMasterlessCheck](t, p).stsZeroSince.
		Observe("db/dragonfly-master/dragonfly", base.Add(-12*time.Minute))

	_ = probetest.MustCheck[*statefulMasterlessCheck](t, p).Run(ctx)
	if _, err := cs.CoreV1().Pods("db").
		Get(ctx, "dragonfly-0", metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted with no operator heal on record")
	}
}

// A pod already carrying role=master is a live re-election — the
// kill would fight it.
func TestDeadlockSkipsWhenMasterPresent(t *testing.T) {
	base := time.Now()
	sts := shSTS("db", "dragonfly", 2,
		map[string]string{"app": "dragonfly", "app.kubernetes.io/part-of": "dragonfly"})
	svc := shMasterSvc("db", "dragonfly-master",
		map[string]string{"app": "dragonfly", "role": "master"})
	cs := fake.NewSimpleClientset(sts, svc,
		dragonflyRolePod("db", "dragonfly-0", "master", true),
		dragonflyRolePod("db", "dragonfly-1", "replica", true))
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	probetest.MustCheck[*statefulMasterlessCheck](t, p).stsZeroSince.
		Observe("db/dragonfly-master/dragonfly", base.Add(-12*time.Minute))
	probetest.MustCheck[*statefulMasterlessCheck](t, p).drOpHealAt = map[string]time.Time{"db/dragonfly": base.Add(-4 * time.Minute)}

	_ = probetest.MustCheck[*statefulMasterlessCheck](t, p).Run(ctx)
	if _, err := cs.CoreV1().Pods("db").
		Get(ctx, "dragonfly-0", metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted while a pod already holds the master role")
	}
}

// The 30m pod-heal cooldown (in-RAM half) keeps a second delete
// from firing.
func TestDeadlockHealCooldown(t *testing.T) {
	base := time.Now()
	sts := shSTS("db", "dragonfly", 2,
		map[string]string{"app": "dragonfly", "app.kubernetes.io/part-of": "dragonfly"})
	svc := shMasterSvc("db", "dragonfly-master",
		map[string]string{"app": "dragonfly", "role": "master"})
	cs := fake.NewSimpleClientset(sts, svc,
		dragonflyRolePod("db", "dragonfly-0", "replica", true))
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	probetest.MustCheck[*statefulMasterlessCheck](t, p).stsZeroSince.
		Observe("db/dragonfly-master/dragonfly", base.Add(-12*time.Minute))
	probetest.MustCheck[*statefulMasterlessCheck](t, p).drOpHealAt = map[string]time.Time{"db/dragonfly": base.Add(-4 * time.Minute)}
	probetest.MustCheck[*statefulMasterlessCheck](t, p).drPodHealed.
		Stamp("db/dragonfly", base.Add(-10*time.Minute))

	_ = probetest.MustCheck[*statefulMasterlessCheck](t, p).Run(ctx)
	if _, err := cs.CoreV1().Pods("db").
		Get(ctx, "dragonfly-0", metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted inside the 30m deadlock cooldown")
	}
}

// A StatefulSet the go-kube-downscaler parked at spec.replicas:0 —
// 0 ready endpoints on its master Service is sleep, never a
// masterless signature. (ReadyReplicas=1 proves the downscaler
// guard did the work — the ReadyReplicas gate alone would mask it.)
func TestMasterlessSkipsDownscaledSTS(t *testing.T) {
	base := time.Now()
	zero := int32(0)
	sts := shSTS("db", "dragonfly", 1,
		map[string]string{"app": "dragonfly", "app.kubernetes.io/part-of": "dragonfly"})
	sts.Spec.Replicas = &zero
	sts.Annotations = map[string]string{"downscaler/downtime-replicas": "0"}
	svc := shMasterSvc("db", "dragonfly-master",
		map[string]string{"app": "dragonfly", "role": "master"})
	cs := fake.NewSimpleClientset(sts, svc)
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	probetest.MustCheck[*statefulMasterlessCheck](t, p).stsZeroSince.
		Observe("db/dragonfly-master/dragonfly", base.Add(-12*time.Minute))
	probetest.MustCheck[*statefulMasterlessCheck](t, p).drOpHealAt = map[string]time.Time{"db/dragonfly": base.Add(-4 * time.Minute)}

	if res := probetest.MustCheck[*statefulMasterlessCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("downscaled statefulset must pass: %+v", res)
	}
}

// ---------------------------------------------------------------------------
// W12-SC2 — multi-master split brain + cross-DC site skew
// ---------------------------------------------------------------------------

// endpointSliceWithZones builds an EndpointSlice bound to svc whose
// endpoints carry the given zone values ("" = unset).
func endpointSliceWithZones(ns, svc string, zones ...string) *discoveryv1.EndpointSlice {
	s := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: svc + "-zzz",
			Labels: map[string]string{discoveryv1.LabelServiceName: svc},
		},
	}
	for i, z := range zones {
		ep := discoveryv1.Endpoint{
			Addresses:  []string{fmt.Sprintf("10.0.0.%d", i+1)},
			Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
		}
		if z != "" {
			ep.Zone = ptr.To(z)
		}
		s.Endpoints = append(s.Endpoints, ep)
	}
	return s
}

// zoneNode builds a Ready worker node carrying the topology zone.
func zoneNode(name, zone string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{corev1.LabelTopologyZone: zone}},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{
			{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}},
	}
}

// A master-role Service carrying 2 Ready endpoints is a live
// split-brain — but only after two consecutive sweeps (a relabeling
// flap settles inside one).
func TestMasterlessMultipleMastersSplitBrain(t *testing.T) {
	statefulServiceMultipleMastersGauge.DeleteLabelValues("db", "dragonfly-master", "dragonfly")
	t.Cleanup(func() {
		statefulServiceMultipleMastersGauge.DeleteLabelValues("db", "dragonfly-master", "dragonfly")
	})
	sts := shSTS("db", "dragonfly", 2,
		map[string]string{"app": "dragonfly", "app.kubernetes.io/part-of": "dragonfly"})
	svc := shMasterSvc("db", "dragonfly-master",
		map[string]string{"app": "dragonfly", "role": "master"})
	cs := fake.NewSimpleClientset(sts, svc,
		endpointSliceWithZones("db", "dragonfly-master", "", ""))
	p := testProberDyn(cs, probetest.OpDyn())

	if res := probetest.MustCheck[*statefulMasterlessCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("first multi-master sighting must pass: %+v", res)
	}
	res := probetest.MustCheck[*statefulMasterlessCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("multi-master for 2 sweeps did not fail the check")
	}
	m := probetest.FindMetric(t, "node_automation_stateful_service_multiple_masters",
		map[string]string{"namespace": "db", "service": "dragonfly-master",
			"statefulset": "dragonfly"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("multiple_masters gauge = %v, want 1", m)
	}
}

// Trigger A: the master's Ready endpoint lives in lanit while the
// STS still serves a Ready replica in datahub — reads/writes pay
// the inter-DC RTT.
func TestMasterlessSiteSkewTriggerA(t *testing.T) {
	statefulMasterSiteSkewGauge.DeleteLabelValues("db", "dragonfly-master", "dragonfly", "lanit")
	t.Cleanup(func() {
		statefulMasterSiteSkewGauge.DeleteLabelValues("db", "dragonfly-master", "dragonfly", "lanit")
	})
	sts := shSTS("db", "dragonfly", 2,
		map[string]string{"app": "dragonfly", "app.kubernetes.io/part-of": "dragonfly"})
	svc := shMasterSvc("db", "dragonfly-master",
		map[string]string{"app": "dragonfly", "role": "master"})
	// The master endpoint lives in lanit; a replica stays Ready in
	// datahub — the asymmetric pinning the skew detector exists for.
	replica := probetest.ReadyPodWithIP("db", "dragonfly-1", "10.0.0.9",
		map[string]string{"app": "dragonfly", "app.kubernetes.io/part-of": "dragonfly"})
	replica.Spec.NodeName = "dh-worker"
	cs := fake.NewSimpleClientset(sts, svc, replica,
		zoneNode("dh-worker", "datahub"),
		zoneNode("ln-worker", "lanit"),
		endpointSliceWithZones("db", "dragonfly-master", "lanit"))
	p := testProberDyn(cs, probetest.OpDyn())

	res := probetest.MustCheck[*statefulMasterlessCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("master pinned to lanit with datahub replicas must fail")
	}
	m := probetest.FindMetric(t, "node_automation_stateful_master_site_skew",
		map[string]string{"namespace": "db", "service": "dragonfly-master",
			"statefulset": "dragonfly", "zone": "lanit"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("site_skew gauge = %v, want 1", m)
	}
}

// Trigger B: every stateful master in the cluster pinned to lanit
// (100% >= 80%) is a cluster-level skew event — each pinned master
// gets the gauge even without a same-STS datahub replica.
func TestMasterlessSiteSkewPinRatio(t *testing.T) {
	statefulMasterSiteSkewGauge.DeleteLabelValues("db", "m1", "sts-a", "lanit")
	statefulMasterSiteSkewGauge.DeleteLabelValues("db", "m2", "sts-b", "lanit")
	t.Cleanup(func() {
		statefulMasterSiteSkewGauge.DeleteLabelValues("db", "m1", "sts-a", "lanit")
		statefulMasterSiteSkewGauge.DeleteLabelValues("db", "m2", "sts-b", "lanit")
	})
	stsA := shSTS("db", "sts-a", 2, map[string]string{"app": "a"})
	stsB := shSTS("db", "sts-b", 2, map[string]string{"app": "b"})
	svcA := shMasterSvc("db", "m1", map[string]string{"app": "a", "role": "master"})
	svcB := shMasterSvc("db", "m2", map[string]string{"app": "b", "role": "master"})
	cs := fake.NewSimpleClientset(stsA, stsB, svcA, svcB,
		zoneNode("dh-worker", "datahub"),
		zoneNode("ln-worker", "lanit"),
		endpointSliceWithZones("db", "m1", "lanit"),
		endpointSliceWithZones("db", "m2", "lanit"))
	p := testProberDyn(cs, probetest.OpDyn())

	res := probetest.MustCheck[*statefulMasterlessCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("100% masters pinned to lanit must fail")
	}
	for _, lv := range []map[string]string{
		{"namespace": "db", "service": "m1", "statefulset": "sts-a", "zone": "lanit"},
		{"namespace": "db", "service": "m2", "statefulset": "sts-b", "zone": "lanit"},
	} {
		m := probetest.FindMetric(t,
			"node_automation_stateful_master_site_skew", lv)
		if m == nil || m.GetGauge().GetValue() != 1 {
			t.Fatalf("site_skew gauge missing for %v", lv)
		}
	}
}

// A single-zone cluster (only lanit workers) can never skew — the
// signature is meaningless without a live main site.
func TestMasterlessSiteSkewSingleZoneSkips(t *testing.T) {
	sts := shSTS("db", "sts-a", 2, map[string]string{"app": "a"})
	svc := shMasterSvc("db", "m1", map[string]string{"app": "a", "role": "master"})
	cs := fake.NewSimpleClientset(sts, svc,
		zoneNode("ln-worker", "lanit"),
		endpointSliceWithZones("db", "m1", "lanit"))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*statefulMasterlessCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("single-zone cluster must pass: %+v", res)
	}
}

// Deliberate maintenance (a cordoned node) defers the pod kill.
func TestDeadlockMaintenanceDefers(t *testing.T) {
	base := time.Now()
	cordoned := testutil.Node("w1", corev1.ConditionTrue, nil)
	cordoned.Spec.Unschedulable = true
	sts := shSTS("db", "dragonfly", 2,
		map[string]string{"app": "dragonfly", "app.kubernetes.io/part-of": "dragonfly"})
	svc := shMasterSvc("db", "dragonfly-master",
		map[string]string{"app": "dragonfly", "role": "master"})
	cs := fake.NewSimpleClientset(cordoned, sts, svc,
		dragonflyRolePod("db", "dragonfly-0", "replica", true))
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	probetest.MustCheck[*statefulMasterlessCheck](t, p).stsZeroSince.
		Observe("db/dragonfly-master/dragonfly", base.Add(-12*time.Minute))
	probetest.MustCheck[*statefulMasterlessCheck](t, p).drOpHealAt = map[string]time.Time{"db/dragonfly": base.Add(-4 * time.Minute)}

	_ = probetest.MustCheck[*statefulMasterlessCheck](t, p).Run(ctx)
	if _, err := cs.CoreV1().Pods("db").
		Get(ctx, "dragonfly-0", metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted during maintenance")
	}
}
