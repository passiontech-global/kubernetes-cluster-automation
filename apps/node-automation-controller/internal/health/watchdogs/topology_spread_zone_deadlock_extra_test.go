// topology_spread_zone_deadlock_extra_test.go — Wave-5B regressions:
// cordon deadlock, minDomains 422 / exact restore, and a zone deleted
// out from under a relaxed workload.
package watchdogs

import (
	"context"
	json "encoding/json/v2"
	"testing"
	"time"

	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// The relax record must clear minDomains (ScheduleAnyway + minDomains
// is a 422 Invalid) and restore EXACTLY the recorded index with its
// original minDomains — a ScheduleAnyway constraint the user wrote
// themselves must survive both directions untouched.
func TestTopologyRelaxClearMinDomainsAndExactRestore(t *testing.T) {
	md := int32(2)
	tscs := []corev1.TopologySpreadConstraint{
		{TopologyKey: corev1.LabelTopologyZone, WhenUnsatisfiable: corev1.DoNotSchedule, MaxSkew: 1, MinDomains: &md},
		{TopologyKey: corev1.LabelTopologyZone, WhenUnsatisfiable: corev1.ScheduleAnyway, MaxSkew: 1}, // user's own
		{TopologyKey: "topology.kubernetes.io/region", WhenUnsatisfiable: corev1.DoNotSchedule, MaxSkew: 1},
	}
	payload, rec, ok := relaxZoneConstraintsPatch(tscs, []string{"az-b"})
	if !ok || len(rec.Relaxed) != 1 || rec.Relaxed[0].Index != 0 || *rec.Relaxed[0].MinDomains != 2 {
		t.Fatalf("unexpected relax record: ok=%v rec=%+v", ok, rec)
	}
	var relaxedDoc struct {
		Spec struct {
			Template struct {
				Spec struct {
					Constraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints"`
				} `json:"spec"`
			} `json:"template"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(payload, &relaxedDoc); err != nil {
		t.Fatalf("decode relax patch: %v", err)
	}
	got := relaxedDoc.Spec.Template.Spec.Constraints
	if len(got) != 3 {
		t.Fatalf("constraints = %d, want 3", len(got))
	}
	if got[0].WhenUnsatisfiable != corev1.ScheduleAnyway || got[0].MinDomains != nil {
		t.Fatalf("relaxed constraint = %+v, want ScheduleAnyway with minDomains cleared", got[0])
	}
	if got[1].WhenUnsatisfiable != corev1.ScheduleAnyway {
		t.Fatal("user's ScheduleAnyway constraint must be untouched by relax")
	}
	if got[2].WhenUnsatisfiable != corev1.DoNotSchedule {
		t.Fatal("non-zone constraint must be untouched by relax")
	}

	anno, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	restorePayload, ok := restoreZoneConstraintsPatch(got, string(anno), 2 /* healthy zones still cover minDomains=2 */)
	if !ok {
		t.Fatal("restore patch not produced")
	}
	var restoreDoc map[string]any
	if err := json.Unmarshal(restorePayload, &restoreDoc); err != nil {
		t.Fatalf("decode restore patch: %v", err)
	}
	meta := restoreDoc["metadata"].(map[string]any)
	annos := meta["annotations"].(map[string]any)
	if v, exists := annos[kube.AnnoTopologyRelaxedBy]; !exists || v != nil {
		t.Fatalf("restore must delete AnnoTopologyRelaxedBy, got %v (exists=%v)", v, exists)
	}
	var restored struct {
		Spec struct {
			Template struct {
				Spec struct {
					Constraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints"`
				} `json:"spec"`
			} `json:"template"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(restorePayload, &restored); err != nil {
		t.Fatalf("decode restore constraints: %v", err)
	}
	back := restored.Spec.Template.Spec.Constraints
	if back[0].WhenUnsatisfiable != corev1.DoNotSchedule || back[0].MinDomains == nil || *back[0].MinDomains != 2 {
		t.Fatalf("restored constraint = %+v, want original DoNotSchedule/minDomains=2", back[0])
	}
	if back[1].WhenUnsatisfiable != corev1.ScheduleAnyway {
		t.Fatalf("restore overwrote the user's ScheduleAnyway constraint: %+v", back[1])
	}
	if back[2].WhenUnsatisfiable != corev1.DoNotSchedule {
		t.Fatalf("restore touched a non-zone constraint: %+v", back[2])
	}
}

func topologyRelaxFixture(t *testing.T, nowp *time.Time, nB *corev1.Node) (*fake.Clientset, *topologySpreadZoneDeadlockCheck, *probetest.Prober) {
	t.Helper()
	now := *nowp
	md := int32(2)
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "api"},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					TopologySpreadConstraints: []corev1.TopologySpreadConstraint{
						{TopologyKey: corev1.LabelTopologyZone, WhenUnsatisfiable: corev1.DoNotSchedule, MaxSkew: 1, MinDomains: &md},
					},
				},
			},
		},
	}
	ctrl := true
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{
		Namespace: "apps", Name: "api-rs",
		OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "api", Controller: &ctrl}},
	}}
	pending := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "api-pod",
			OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "api-rs", Controller: &ctrl}},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodPending,
			Conditions: []corev1.PodCondition{{
				Type: corev1.PodScheduled, Status: corev1.ConditionFalse,
				Message:            "0/2 nodes are available: 2 node(s) didn't match pod topology spread constraints.",
				LastTransitionTime: metav1.NewTime(now.Add(-15 * time.Minute)),
			}},
		},
	}
	nA := zoneWorkerNode("worker-a", "az-a", true, false)
	cs := fake.NewSimpleClientset(nA, nB, dep, rs, pending)
	p := testProber(cs)
	p.Now = func() time.Time { return *nowp }
	return cs, probetest.MustCheck[*topologySpreadZoneDeadlockCheck](t, p), p
}

// A freshly cordoned worker is a NODE-SCOPED maintenance hold. The
// old HealAllowed let that very cordon defer the relax that exists to
// unblock the zone — HealAllowedClusterWideOnly must proceed.
func TestTopologyRelaxProceedsOnCordonedZone(t *testing.T) {
	topologyZoneDeadlockGauge.Reset()
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	taintAt := metav1.NewTime(now.Add(-10 * time.Minute))
	nB := zoneWorkerNode("worker-b", "az-b", true, true) // Ready but cordoned
	nB.Spec.Taints = []corev1.Taint{{
		Key: kube.UnschedulableTaintKey, Effect: corev1.TaintEffectNoSchedule,
		TimeAdded: &taintAt,
	}}
	cs, chk, _ := topologyRelaxFixture(t, &now, nB)

	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("T=0: %+v", res)
	}
	now = now.Add(10 * time.Minute)
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); res.Pass {
		t.Fatalf("expected deadlock once the cordoned zone persisted >=10m: %+v", res)
	}
	got, _ := cs.AppsV1().Deployments("apps").Get(context.Background(), "api", metav1.GetOptions{})
	c := got.Spec.Template.Spec.TopologySpreadConstraints[0]
	if c.WhenUnsatisfiable != corev1.ScheduleAnyway || c.MinDomains != nil {
		t.Fatalf("cordoned zone must be relaxed with minDomains cleared, got %+v", c)
	}
	if v := ptestutil.ToFloat64(topologyZoneDeadlockGauge.WithLabelValues("apps", "api", "az-b")); v != 1 {
		t.Fatalf("deadlock gauge = %v, want 1", v)
	}
}

// A zone deleted out from under a relaxed workload must drop out of
// the known set so the restore path fires. With minDomains=2 but only
// one surviving healthy zone, replaying the recorded minDomains would
// be a 422 Invalid — the constraint stays relaxed and the record is
// KEPT in the annotation so a later sweep with more zones can finish
// the restore. (The old sticky knownZones kept the deleted zone
// forever and pinned the relax even longer.)
func TestTopologyRestoreAfterZoneDeleted(t *testing.T) {
	topologyZoneDeadlockGauge.Reset()
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	nB := zoneWorkerNode("worker-b", "az-b", false, false) // dead zone
	cs, chk, p := topologyRelaxFixture(t, &now, nB)

	chk.Run(probetest.SweepCtx(ctx, chk.Deps)) // T=0 start window
	now = now.Add(10 * time.Minute)
	chk.Run(probetest.SweepCtx(ctx, chk.Deps)) // relax
	got, _ := cs.AppsV1().Deployments("apps").Get(context.Background(), "api", metav1.GetOptions{})
	if got.Spec.Template.Spec.TopologySpreadConstraints[0].WhenUnsatisfiable != corev1.ScheduleAnyway {
		t.Fatal("expected relaxed constraint before zone deletion")
	}

	// The whole zone disappears — no node objects left in az-b.
	_ = cs.CoreV1().Nodes().Delete(context.Background(), "worker-b", metav1.DeleteOptions{})
	p.InvalidateNodes(context.Background())
	p.InvalidateDeployments(context.Background())
	now = now.Add(10 * time.Minute)
	chk.Run(probetest.SweepCtx(ctx, chk.Deps)) // start the all-healthy window
	now = now.Add(30 * time.Minute)
	chk.Run(probetest.SweepCtx(ctx, chk.Deps)) // restore

	got, _ = cs.AppsV1().Deployments("apps").Get(context.Background(), "api", metav1.GetOptions{})
	c := got.Spec.Template.Spec.TopologySpreadConstraints[0]
	if c.WhenUnsatisfiable != corev1.ScheduleAnyway || c.MinDomains != nil {
		t.Fatalf("minDomains=2 with only one surviving zone is a 422 Invalid — constraint must stay relaxed, got %+v", c)
	}
	anno, ok := got.Annotations[kube.AnnoTopologyRelaxedBy]
	if !ok {
		t.Fatal("deferred restore must keep AnnoTopologyRelaxedBy for a later sweep")
	}
	rec, valid := parseTopologyRelaxRecord(anno)
	if !valid || len(rec.Relaxed) != 1 || rec.Relaxed[0].MinDomains == nil ||
		*rec.Relaxed[0].MinDomains != 2 {
		t.Fatalf("deferred record = %+v (valid=%v), want index 0 / minDomains 2", rec, valid)
	}
}

func TestIsVirtualWorkerNodeLabels(t *testing.T) {
	cases := []struct {
		name   string
		labels map[string]string
		want   bool
	}{
		{"liqo", map[string]string{"liqo.io/type": "virtual-node"}, true},
		{"provider", map[string]string{"virtual-kubelet.io/provider": "azure"}, true},
		{"type", map[string]string{"type": "virtual-kubelet"}, true},
		{"instance-type", map[string]string{corev1.LabelInstanceTypeStable: "external"}, true},
		{"legacy instance-type is not the stable label", map[string]string{"instance-type": "external"}, false},
		{"real worker", map[string]string{"type": "worker", corev1.LabelInstanceTypeStable: "m5.large"}, false},
	}
	for _, tc := range cases {
		n := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Labels: tc.labels}}
		if got := isVirtualWorkerNode(n); got != tc.want {
			t.Errorf("%s: isVirtualWorkerNode = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A recorded minDomains larger than the surviving healthy-zone count
// would be rejected with 422 Invalid on restore. When EVERY entry is
// deferred, nothing can change — no patch at all (the annotation and
// the relaxed constraint stay as they are for a later sweep).
func TestRestoreZoneConstraintsPatchDefersStaleMinDomains(t *testing.T) {
	md := int32(3)
	tscs := []corev1.TopologySpreadConstraint{
		{TopologyKey: corev1.LabelTopologyZone, WhenUnsatisfiable: corev1.ScheduleAnyway, MaxSkew: 1},
	}
	rec := topologyRelaxRecord{
		By:      topologyRelaxedMarkerValue,
		Zones:   []string{"az-b", "az-c"},
		Relaxed: []topologyRelaxEntry{{Index: 0, MinDomains: &md}},
	}
	anno, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	payload, ok := restoreZoneConstraintsPatch(tscs, string(anno), 2) // 2 surviving zones < minDomains=3
	if ok || payload != nil {
		t.Fatalf("fully deferred restore must emit no patch, got ok=%v payload=%s", ok, payload)
	}
}

// When only SOME entries are deferred, the rest must be restored and
// the deferred entries kept in AnnoTopologyRelaxedBy (with the dead
// zones still attributed) so a later sweep can finish the job.
func TestRestoreZoneConstraintsPatchKeepsDeferredEntries(t *testing.T) {
	mdOK, mdDeferred := int32(2), int32(3)
	tscs := []corev1.TopologySpreadConstraint{
		{TopologyKey: corev1.LabelTopologyZone, WhenUnsatisfiable: corev1.ScheduleAnyway, MaxSkew: 1},
		{TopologyKey: corev1.LabelTopologyZone, WhenUnsatisfiable: corev1.ScheduleAnyway, MaxSkew: 1},
	}
	rec := topologyRelaxRecord{
		By:    topologyRelaxedMarkerValue,
		Zones: []string{"az-b", "az-c"},
		Relaxed: []topologyRelaxEntry{
			{Index: 0, MinDomains: &mdOK},
			{Index: 1, MinDomains: &mdDeferred},
		},
	}
	anno, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	payload, ok := restoreZoneConstraintsPatch(tscs, string(anno), 2)
	if !ok || payload == nil {
		t.Fatal("partial restore patch not produced")
	}
	var doc struct {
		Metadata struct {
			Annotations map[string]*string `json:"annotations"`
		} `json:"metadata"`
		Spec struct {
			Template struct {
				Spec struct {
					Constraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints"`
				} `json:"spec"`
			} `json:"template"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(payload, &doc); err != nil {
		t.Fatal(err)
	}
	if c := doc.Spec.Template.Spec.Constraints[0]; c.WhenUnsatisfiable != corev1.DoNotSchedule ||
		c.MinDomains == nil || *c.MinDomains != 2 {
		t.Fatalf("restorable constraint not restored: %+v", c)
	}
	if c := doc.Spec.Template.Spec.Constraints[1]; c.WhenUnsatisfiable != corev1.ScheduleAnyway ||
		c.MinDomains != nil {
		t.Fatalf("deferred constraint must stay relaxed: %+v", c)
	}
	raw := doc.Metadata.Annotations[kube.AnnoTopologyRelaxedBy]
	if raw == nil || *raw == "" {
		t.Fatalf("deferred entry must stay recorded in the annotation, got %v", raw)
	}
	kept, valid := parseTopologyRelaxRecord(*raw)
	if !valid || len(kept.Relaxed) != 1 || kept.Relaxed[0].Index != 1 ||
		kept.Relaxed[0].MinDomains == nil || *kept.Relaxed[0].MinDomains != 3 {
		t.Fatalf("deferred record = %+v (valid=%v), want only index 1 / minDomains 3", kept, valid)
	}
	if len(kept.Zones) != 2 || kept.Zones[0] != "az-b" || kept.Zones[1] != "az-c" {
		t.Fatalf("deferred record lost zone attribution: %+v", kept.Zones)
	}
}

// An orphan AnnoTopologyRelaxedBy — unparseable record, or a record
// whose workload no longer carries a relaxed zone constraint — is
// cleaned up with an annotation-only patch instead of being left to
// pin topologyRecordedZones forever.
func TestRestorePatchForOrphanAnnotation(t *testing.T) {
	chk := &topologySpreadZoneDeadlockCheck{}
	assertAnnotationDropped := func(payload []byte, ok bool) {
		t.Helper()
		if !ok {
			t.Fatal("orphan cleanup patch not produced")
		}
		var doc struct {
			Metadata struct {
				Annotations map[string]*string `json:"annotations"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(payload, &doc); err != nil {
			t.Fatal(err)
		}
		if v, exists := doc.Metadata.Annotations[kube.AnnoTopologyRelaxedBy]; !exists || v != nil {
			t.Fatalf("orphan annotation must be deleted, got %v (exists=%v)", v, exists)
		}
	}

	assertAnnotationDropped(chk.restorePatchFor(nil, "not-json", 3))
	rec := topologyRelaxRecord{
		By:      topologyRelaxedMarkerValue,
		Relaxed: []topologyRelaxEntry{{Index: 0}},
	}
	anno, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	// The workload already restored its constraint — no ScheduleAnyway
	// left — so the marker is stale even though the record parses.
	alreadyRestored := []corev1.TopologySpreadConstraint{
		{TopologyKey: corev1.LabelTopologyZone, WhenUnsatisfiable: corev1.DoNotSchedule},
	}
	assertAnnotationDropped(chk.restorePatchFor(alreadyRestored, string(anno), 3))
}
