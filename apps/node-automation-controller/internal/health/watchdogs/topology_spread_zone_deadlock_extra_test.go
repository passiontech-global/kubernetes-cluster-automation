// topology_spread_zone_deadlock_extra_test.go — Wave-5B regressions:
// cordon deadlock, minDomains 422 / exact restore, and a zone deleted
// out from under a relaxed workload.
package watchdogs

import (
	"context"
	json "encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
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

func TestTopologyGateOrderingReservationReleaseAndRefundAcrossAllPaths(t *testing.T) {
	fluxManaged := []metav1.ManagedFieldsEntry{{
		Manager:    "kustomize-controller",
		Operation:  metav1.ManagedFieldsOperationApply,
		APIVersion: "apps/v1",
	}}
	md := int32(2)
	relaxAnno := func() string {
		raw, err := json.Marshal(topologyRelaxRecord{
			By:      topologyRelaxedMarkerValue,
			Zones:   []string{"az-b"},
			Relaxed: []topologyRelaxEntry{{Index: 0, MinDomains: &md}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}()

	makeDep := func(relaxed bool, withZoneDoNotSchedule bool) *appsv1.Deployment {
		when := corev1.DoNotSchedule
		minD := &md
		annos := map[string]string{}
		if relaxed {
			when = corev1.ScheduleAnyway
			minD = nil
			annos[kube.AnnoTopologyRelaxedBy] = relaxAnno
		}
		var tscs []corev1.TopologySpreadConstraint
		if withZoneDoNotSchedule || relaxed {
			tscs = []corev1.TopologySpreadConstraint{{
				TopologyKey:       corev1.LabelTopologyZone,
				WhenUnsatisfiable: when,
				MaxSkew:           1,
				MinDomains:        minD,
			}}
		}
		return &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "apps", Name: "api",
				Annotations:   annos,
				ManagedFields: fluxManaged,
			},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{TopologySpreadConstraints: tscs},
				},
			},
		}
	}
	makeSTS := func(relaxed bool, withZoneDoNotSchedule bool) *appsv1.StatefulSet {
		when := corev1.DoNotSchedule
		minD := &md
		annos := map[string]string{}
		if relaxed {
			when = corev1.ScheduleAnyway
			minD = nil
			annos[kube.AnnoTopologyRelaxedBy] = relaxAnno
		}
		var tscs []corev1.TopologySpreadConstraint
		if withZoneDoNotSchedule || relaxed {
			tscs = []corev1.TopologySpreadConstraint{{
				TopologyKey:       corev1.LabelTopologyZone,
				WhenUnsatisfiable: when,
				MaxSkew:           1,
				MinDomains:        minD,
			}}
		}
		return &appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "apps", Name: "db",
				Annotations:   annos,
				ManagedFields: fluxManaged,
			},
			Spec: appsv1.StatefulSetSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{TopologySpreadConstraints: tscs},
				},
			},
		}
	}

	type pathCase struct {
		name     string
		resource string
		wKey     string
		fluxKind string
		setup    func() (objs []runtime.Object, obj metav1.Object, invoke func(sctx context.Context, chk *topologySpreadZoneDeadlockCheck, rep *probefw.SweepReport, now time.Time))
	}

	paths := []pathCase{
		{
			name:     "relaxDeployment",
			resource: "deployments",
			wKey:     "apps/Deployment/api",
			fluxKind: "deployment",
			setup: func() ([]runtime.Object, metav1.Object, func(context.Context, *topologySpreadZoneDeadlockCheck, *probefw.SweepReport, time.Time)) {
				dep := makeDep(false, true)
				return []runtime.Object{dep}, dep, func(sctx context.Context, chk *topologySpreadZoneDeadlockCheck, rep *probefw.SweepReport, now time.Time) {
					chk.relaxDeployment(sctx, logr.Discard(), rep, dep, []string{"az-b"}, now)
				}
			},
		},
		{
			name:     "relaxStatefulSet",
			resource: "statefulsets",
			wKey:     "apps/StatefulSet/db",
			fluxKind: "statefulset",
			setup: func() ([]runtime.Object, metav1.Object, func(context.Context, *topologySpreadZoneDeadlockCheck, *probefw.SweepReport, time.Time)) {
				sts := makeSTS(false, true)
				return []runtime.Object{sts}, sts, func(sctx context.Context, chk *topologySpreadZoneDeadlockCheck, rep *probefw.SweepReport, now time.Time) {
					chk.relaxStatefulSet(sctx, logr.Discard(), rep, sts, []string{"az-b"}, now)
				}
			},
		},
		{
			name:     "restoreDeployment",
			resource: "deployments",
			wKey:     "apps/Deployment/api",
			fluxKind: "deployment",
			setup: func() ([]runtime.Object, metav1.Object, func(context.Context, *topologySpreadZoneDeadlockCheck, *probefw.SweepReport, time.Time)) {
				dep := makeDep(true, false)
				return []runtime.Object{dep}, dep, func(sctx context.Context, chk *topologySpreadZoneDeadlockCheck, rep *probefw.SweepReport, now time.Time) {
					chk.restoreRelaxedWorkloads(sctx, logr.Discard(), rep, []appsv1.Deployment{*dep}, nil, 2, now)
				}
			},
		},
		{
			name:     "restoreStatefulSet",
			resource: "statefulsets",
			wKey:     "apps/StatefulSet/db",
			fluxKind: "statefulset",
			setup: func() ([]runtime.Object, metav1.Object, func(context.Context, *topologySpreadZoneDeadlockCheck, *probefw.SweepReport, time.Time)) {
				sts := makeSTS(true, false)
				return []runtime.Object{sts}, sts, func(sctx context.Context, chk *topologySpreadZoneDeadlockCheck, rep *probefw.SweepReport, now time.Time) {
					chk.restoreRelaxedWorkloads(sctx, logr.Discard(), rep, nil, []appsv1.StatefulSet{*sts}, 2, now)
				}
			},
		},
	}

	for _, pc := range paths {
		t.Run(pc.name+"/FluxPatchGate denial releases key, refunds budget, and isolates key", func(t *testing.T) {
			heal.ConfigureBudget(1, time.Hour)
			heal.ConfigureFluxConflictLoop(2, 30*time.Minute)
			t.Cleanup(func() {
				heal.ConfigureBudget(0, 0)
				heal.ConfigureFluxConflictLoop(0, 0)
			})

			objs, obj, invoke := pc.setup()
			cs := fake.NewSimpleClientset(objs...)
			var patches int
			cs.PrependReactor("patch", pc.resource, func(ktesting.Action) (bool, runtime.Object, error) {
				patches++
				return false, nil, nil
			})
			p := testProber(cs)
			chk := probetest.MustCheck[*topologySpreadZoneDeadlockCheck](t, p)
			now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
			sctx := probetest.SweepCtx(ctx, chk.Deps)

			// Exhaust sibling/bare keys first -> must NOT block our duty-prefixed key.
			heal.FluxPatchGate(pc.fluxKind, obj, "other-duty:"+pc.wKey, now)
			heal.FluxPatchGate(pc.fluxKind, obj, "apps/"+obj.GetName(), now)

			// First real call uses hit #1 (max=2) -> succeeds.
			var rep probefw.SweepReport
			invoke(sctx, chk, &rep, now)
			if patches != 1 {
				t.Fatalf("first call patches=%d, want 1 (wrongly blocked by sibling/bare key)", patches)
			}

			// Reset cooldown/key/budget for second call which hits FluxPatchGate limit (#2 == max=2).
			heal.ConfigureBudget(1, time.Hour)
			chk.healCooldowns = state.CooldownSet{}
			sctx2 := probetest.SweepCtx(ctx, chk.Deps)
			invoke(sctx2, chk, &rep, now.Add(time.Minute))
			if patches != 1 {
				t.Fatalf("FluxPatchGate denial did not block second patch: patches=%d", patches)
			}
			if !kube.TryReserveWorkloadKey(sctx2, pc.wKey) {
				t.Fatalf("FluxPatchGate denial leaked workload key %q", pc.wKey)
			}
			if proceed, _ := chk.HealAllowedClusterWideOnly(sctx2, logr.Discard(), nil, "sibling", time.Minute, now.Add(time.Minute)); !proceed {
				t.Fatal("FluxPatchGate denial did not refund budget grant")
			}
		})

		t.Run(pc.name+"/TryReserveWorkloadKey denial refunds budget and does not stamp FluxPatchGate", func(t *testing.T) {
			heal.ConfigureBudget(1, time.Hour)
			heal.ConfigureFluxConflictLoop(2, 30*time.Minute)
			t.Cleanup(func() {
				heal.ConfigureBudget(0, 0)
				heal.ConfigureFluxConflictLoop(0, 0)
			})

			objs, _, invoke := pc.setup()
			cs := fake.NewSimpleClientset(objs...)
			var patches int
			cs.PrependReactor("patch", pc.resource, func(ktesting.Action) (bool, runtime.Object, error) {
				patches++
				return false, nil, nil
			})
			p := testProber(cs)
			chk := probetest.MustCheck[*topologySpreadZoneDeadlockCheck](t, p)
			now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
			sctx := probetest.SweepCtx(ctx, chk.Deps)

			if !kube.TryReserveWorkloadKey(sctx, pc.wKey) {
				t.Fatal("failed to pre-reserve key")
			}
			var rep probefw.SweepReport
			invoke(sctx, chk, &rep, now)
			if patches != 0 {
				t.Fatalf("pre-reserved workload got patched: patches=%d", patches)
			}
			if proceed, _ := chk.HealAllowedClusterWideOnly(sctx, logr.Discard(), nil, "sibling", time.Minute, now); !proceed {
				t.Fatal("TryReserveWorkloadKey denial did not refund budget grant")
			}

			// Verify FluxPatchGate was NOT stamped (next un-reserved call at max=2 succeeds).
			heal.ConfigureBudget(1, time.Hour)
			sctx2 := probetest.SweepCtx(ctx, chk.Deps)
			invoke(sctx2, chk, &rep, now.Add(time.Minute))
			if patches != 1 {
				t.Fatalf("expected 1 patch after reservation cleared, got %d (FluxPatchGate stamped during denial)", patches)
			}
		})

		t.Run(pc.name+"/Patch error releases workload key and records InfraErr", func(t *testing.T) {
			heal.ConfigureBudget(1, time.Hour)
			t.Cleanup(func() { heal.ConfigureBudget(0, 0) })

			objs, _, invoke := pc.setup()
			cs := fake.NewSimpleClientset(objs...)
			cs.PrependReactor("patch", pc.resource, func(ktesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("apiserver error")
			})
			p := testProber(cs)
			chk := probetest.MustCheck[*topologySpreadZoneDeadlockCheck](t, p)
			now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
			sctx := probetest.SweepCtx(ctx, chk.Deps)

			var rep probefw.SweepReport
			invoke(sctx, chk, &rep, now)
			if !kube.TryReserveWorkloadKey(sctx, pc.wKey) {
				t.Fatalf("Patch error leaked workload key %q", pc.wKey)
			}
			if res := rep.Verdict("topology: ", ", "); res.Infra == nil {
				t.Fatal("Patch error did not record InfraErr")
			}
		})
	}

	t.Run("relaxZoneConstraintsPatch !ok releases workload key and refunds budget", func(t *testing.T) {
		for _, kind := range []string{"Deployment", "StatefulSet"} {
			t.Run(kind, func(t *testing.T) {
				heal.ConfigureBudget(1, time.Hour)
				t.Cleanup(func() { heal.ConfigureBudget(0, 0) })

				dep := makeDep(false, false) // no DoNotSchedule zone constraint -> !ok
				sts := makeSTS(false, false)
				cs := fake.NewSimpleClientset(dep, sts)
				p := testProber(cs)
				chk := probetest.MustCheck[*topologySpreadZoneDeadlockCheck](t, p)
				now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
				sctx := probetest.SweepCtx(ctx, chk.Deps)
				var rep probefw.SweepReport

				wKey := "apps/Deployment/api"
				if kind == "Deployment" {
					chk.relaxDeployment(sctx, logr.Discard(), &rep, dep, []string{"az-b"}, now)
				} else {
					wKey = "apps/StatefulSet/db"
					chk.relaxStatefulSet(sctx, logr.Discard(), &rep, sts, []string{"az-b"}, now)
				}

				if !kube.TryReserveWorkloadKey(sctx, wKey) {
					t.Fatalf("!ok path leaked workload key %q", wKey)
				}
				if proceed, _ := chk.HealAllowedClusterWideOnly(sctx, logr.Discard(), nil, "sibling", time.Minute, now); !proceed {
					t.Fatal("!ok path did not refund budget grant")
				}
			})
		}
	})
}

func TestTopologyStatefulSetOptInAndRelax(t *testing.T) {
	base := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	ctrl := true
	md2 := int32(2)

	makeSTS := func(annos map[string]string, tscs []corev1.TopologySpreadConstraint) *appsv1.StatefulSet {
		return &appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "db", Annotations: annos},
			Spec: appsv1.StatefulSetSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{TopologySpreadConstraints: tscs},
				},
			},
		}
	}

	t.Run("Run opt-in gating", func(t *testing.T) {
		cases := []struct {
			name        string
			annos       map[string]string
			overlayOpt  bool
			wantRelaxed bool
			wantPatches int
		}{
			{
				name:        "without opt-in annotation stays DoNotSchedule",
				wantRelaxed: false,
				wantPatches: 0,
			},
			{
				name:        "opt-in=false stays DoNotSchedule",
				annos:       map[string]string{kube.AnnoTopologyRelaxOptIn: "false"},
				wantRelaxed: false,
				wantPatches: 0,
			},
			{
				name:        "opt-in=true directly on StatefulSet relaxes",
				annos:       map[string]string{kube.AnnoTopologyRelaxOptIn: "true"},
				wantRelaxed: true,
				wantPatches: 1,
			},
			{
				name:        "opt-in=true via SweepOverlay relaxes",
				overlayOpt:  true,
				wantRelaxed: true,
				wantPatches: 1,
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				topologyZoneDeadlockGauge.Reset()
				now := base
				sts := makeSTS(tc.annos, []corev1.TopologySpreadConstraint{{
					TopologyKey:       corev1.LabelTopologyZone,
					WhenUnsatisfiable: corev1.DoNotSchedule,
					MaxSkew:           1,
					MinDomains:        &md2,
				}})
				pending := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace:       "apps",
						Name:            "db-0",
						OwnerReferences: []metav1.OwnerReference{{Kind: "StatefulSet", Name: "db", Controller: &ctrl}},
					},
					Status: corev1.PodStatus{
						Phase: corev1.PodPending,
						Conditions: []corev1.PodCondition{{
							Type:               corev1.PodScheduled,
							Status:             corev1.ConditionFalse,
							Message:            "0/2 nodes are available: 2 node(s) didn't match pod topology spread constraints.",
							LastTransitionTime: metav1.NewTime(now.Add(-15 * time.Minute)),
						}},
					},
				}
				nA := zoneWorkerNode("worker-a", "az-a", true, false)
				nB := zoneWorkerNode("worker-b", "az-b", false, false)

				cs := fake.NewSimpleClientset(nA, nB, sts, pending)
				var patches int
				cs.PrependReactor("patch", "statefulsets", func(ktesting.Action) (bool, runtime.Object, error) {
					patches++
					return false, nil, nil
				})
				p := testProber(cs)
				p.Now = func() time.Time { return now }
				chk := probetest.MustCheck[*topologySpreadZoneDeadlockCheck](t, p)

				sctx1 := probetest.SweepCtx(ctx, chk.Deps)
				res1 := chk.Run(sctx1)
				probetest.VerifySweep(sctx1)
				if !res1.Pass {
					t.Fatalf("T=0 Run = %+v, want Pass", res1)
				}

				now = now.Add(10 * time.Minute)
				sctx2 := probetest.SweepCtx(ctx, chk.Deps)
				if tc.overlayOpt {
					cached, err := chk.AllStatefulSets(sctx2)
					if err != nil || len(cached) != 1 {
						t.Fatalf("AllStatefulSets = (%d, %v)", len(cached), err)
					}
					payload, err := kube.MergePatchAnnos(map[string]any{kube.AnnoTopologyRelaxOptIn: "true"})
					if err != nil {
						t.Fatal(err)
					}
					kube.RecordAnnoPatch(sctx2, &cached[0], payload)
				}
				res2 := chk.Run(sctx2)
				probetest.VerifySweep(sctx2)
				if res2.Pass {
					t.Fatalf("T+10m Run unexpectedly passed")
				}
				if v := ptestutil.ToFloat64(topologyZoneDeadlockGauge.WithLabelValues("apps", "db", "az-b")); v != 1 {
					t.Fatalf("deadlock gauge = %v, want 1", v)
				}
				if patches != tc.wantPatches {
					t.Fatalf("patches = %d, want %d", patches, tc.wantPatches)
				}

				got, err := cs.AppsV1().StatefulSets("apps").Get(ctx, "db", metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				c := got.Spec.Template.Spec.TopologySpreadConstraints[0]
				if tc.wantRelaxed {
					if c.WhenUnsatisfiable != corev1.ScheduleAnyway || c.MinDomains != nil {
						t.Fatalf("relaxed constraint = %+v, want ScheduleAnyway with nil MinDomains", c)
					}
					rec, valid := parseTopologyRelaxRecord(got.Annotations[kube.AnnoTopologyRelaxedBy])
					if !valid || rec.By != topologyRelaxedMarkerValue || len(rec.Zones) != 1 || rec.Zones[0] != "az-b" ||
						len(rec.Relaxed) != 1 || rec.Relaxed[0].Index != 0 || rec.Relaxed[0].MinDomains == nil || *rec.Relaxed[0].MinDomains != 2 {
						t.Fatalf("unexpected relax record: valid=%v rec=%+v", valid, rec)
					}
				} else {
					if c.WhenUnsatisfiable != corev1.DoNotSchedule {
						t.Fatalf("un-opted STS was mutated: %+v", c)
					}
					if _, exists := got.Annotations[kube.AnnoTopologyRelaxedBy]; exists {
						t.Fatal("un-opted STS must not carry AnnoTopologyRelaxedBy")
					}
				}
			})
		}
	})

	t.Run("relaxStatefulSet direct branches and HealAllowedClusterWideOnly", func(t *testing.T) {
		cases := []struct {
			name            string
			activeCooldown  bool
			kuredAnno       string
			nilDyn          bool
			nodeListErr     bool
			exhaustBudget   bool
			wantPatches     int
			wantInfraSubstr string
			wantCooldown    bool
		}{
			{
				name:         "happy path preserves non-zone and user ScheduleAnyway constraints",
				wantPatches:  1,
				wantCooldown: true,
			},
			{
				name:           "active cooldown skips patch without InfraErr",
				activeCooldown: true,
				wantPatches:    0,
				wantCooldown:   true,
			},
			{
				name:        "cluster-wide kured hold skips patch without InfraErr",
				kuredAnno:   "cluster-upgrade",
				wantPatches: 0,
			},
			{
				name:         "node-scoped kured hold allows relax patch",
				kuredAnno:    `{"nodeID":"worker-b"}`,
				wantPatches:  1,
				wantCooldown: true,
			},
			{
				name:            "unverifiable maintenance mutex (Dyn nil) records InfraErr",
				nilDyn:          true,
				wantPatches:     0,
				wantInfraSubstr: "maintenance mutex unverifiable — relax statefulset deferred",
			},
			{
				name:            "unverifiable maintenance mutex (nodes list error) records InfraErr",
				nodeListErr:     true,
				wantPatches:     0,
				wantInfraSubstr: "maintenance mutex unverifiable — relax statefulset deferred",
			},
			{
				name:          "exhausted budget skips patch without InfraErr",
				exhaustBudget: true,
				wantPatches:   0,
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if tc.exhaustBudget {
					heal.ConfigureBudget(1, time.Hour)
					t.Cleanup(func() { heal.ConfigureBudget(0, 0) })
				}
				sts := makeSTS(map[string]string{kube.AnnoTopologyRelaxOptIn: "true"}, []corev1.TopologySpreadConstraint{
					{TopologyKey: corev1.LabelTopologyZone, WhenUnsatisfiable: corev1.DoNotSchedule, MaxSkew: 1, MinDomains: &md2},
					{TopologyKey: corev1.LabelHostname, WhenUnsatisfiable: corev1.DoNotSchedule, MaxSkew: 1},
					{TopologyKey: corev1.LabelTopologyZone, WhenUnsatisfiable: corev1.ScheduleAnyway, MaxSkew: 1},
				})
				objs := []runtime.Object{
					sts,
					zoneWorkerNode("worker-a", "az-a", true, false),
					zoneWorkerNode("worker-b", "az-b", true, true),
				}
				if tc.kuredAnno != "" {
					objs = append(objs, &appsv1.DaemonSet{
						ObjectMeta: metav1.ObjectMeta{
							Namespace:   "kube-system",
							Name:        "kured",
							Annotations: map[string]string{"weave.works/kured-node-lock": tc.kuredAnno},
						},
					})
				}

				cs := fake.NewSimpleClientset(objs...)
				var patches int
				cs.PrependReactor("patch", "statefulsets", func(ktesting.Action) (bool, runtime.Object, error) {
					patches++
					return false, nil, nil
				})
				if tc.nodeListErr {
					cs.PrependReactor("list", "nodes", func(ktesting.Action) (bool, runtime.Object, error) {
						return true, nil, errors.New("nodes down")
					})
				}

				p := testProberDyn(cs, probetest.OpDyn())
				chk := probetest.MustCheck[*topologySpreadZoneDeadlockCheck](t, p)
				if tc.nilDyn {
					chk.Dyn = nil
				}
				sctx := probetest.SweepCtx(ctx, chk.Deps)
				defer probetest.VerifySweep(sctx)

				wKey := "apps/StatefulSet/db"
				if tc.activeCooldown {
					chk.healCooldowns.Stamp(wKey, base.Add(-5*time.Minute))
				}
				if tc.exhaustBudget {
					if proceed, _ := chk.HealAllowedClusterWideOnly(sctx, logr.Discard(), nil, "other/Deployment/sib", time.Minute, base); !proceed {
						t.Fatal("failed to pre-spend heal budget")
					}
				}

				var rep probefw.SweepReport
				chk.relaxStatefulSet(sctx, logr.Discard(), &rep, sts, []string{"az-b"}, base)

				if patches != tc.wantPatches {
					t.Fatalf("patches = %d, want %d", patches, tc.wantPatches)
				}
				res := rep.Verdict("topology: ", ", ")
				if tc.wantInfraSubstr != "" {
					if res.Infra == nil || !strings.Contains(res.Infra.Error(), tc.wantInfraSubstr) {
						t.Fatalf("Infra = %v, want substring %q", res.Infra, tc.wantInfraSubstr)
					}
				} else if res.Infra != nil {
					t.Fatalf("unexpected Infra error: %v", res.Infra)
				}
				if gotCool := chk.healCooldowns.CooledDown(wKey, topologyPatchCooldown, base); gotCool != tc.wantCooldown {
					t.Fatalf("healCooldowns stamped=%v, want %v", gotCool, tc.wantCooldown)
				}

				if tc.wantPatches == 1 {
					got, err := cs.AppsV1().StatefulSets("apps").Get(ctx, "db", metav1.GetOptions{})
					if err != nil {
						t.Fatal(err)
					}
					tscs := got.Spec.Template.Spec.TopologySpreadConstraints
					if tscs[0].WhenUnsatisfiable != corev1.ScheduleAnyway || tscs[0].MinDomains != nil ||
						tscs[1].WhenUnsatisfiable != corev1.DoNotSchedule || tscs[2].WhenUnsatisfiable != corev1.ScheduleAnyway {
						t.Fatalf("unexpected relaxed constraints: %+v", tscs)
					}
					list, err := chk.AllStatefulSets(sctx)
					if err != nil || len(list) == 0 || list[0].Spec.Template.Spec.TopologySpreadConstraints[0].WhenUnsatisfiable != corev1.ScheduleAnyway {
						t.Fatalf("InvalidateStatefulSets did not refresh snapshot: list=%+v err=%v", list, err)
					}
				}
			})
		}
	})
}

func TestTopologyRestoreRelaxedWorkloadsTable(t *testing.T) {
	base := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	md2, md3 := int32(2), int32(3)

	marshalRec := func(t *testing.T, rec topologyRelaxRecord) string {
		t.Helper()
		b, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	defaultRecAnno := func(t *testing.T) string {
		return marshalRec(t, topologyRelaxRecord{
			By:      topologyRelaxedMarkerValue,
			Zones:   []string{"az-b"},
			Relaxed: []topologyRelaxEntry{{Index: 0, MinDomains: &md2}},
		})
	}

	makeDep := func(name string, paused bool, annos map[string]string, tscs []corev1.TopologySpreadConstraint) appsv1.Deployment {
		return appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: name, Annotations: annos},
			Spec: appsv1.DeploymentSpec{
				Paused: paused,
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{TopologySpreadConstraints: tscs},
				},
			},
		}
	}
	makeSTS := func(name string, annos map[string]string, tscs []corev1.TopologySpreadConstraint) appsv1.StatefulSet {
		return appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: name, Annotations: annos},
			Spec: appsv1.StatefulSetSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{TopologySpreadConstraints: tscs},
				},
			},
		}
	}

	type restoreCase struct {
		name            string
		setup           func(t *testing.T) (deps []appsv1.Deployment, stss []appsv1.StatefulSet, objs []runtime.Object)
		healthyZones    int
		activeCooldown  string
		kuredAnno       string
		nilDyn          bool
		nodeListErr     bool
		exhaustBudget   bool
		overlaySetSTS   bool
		overlayDropSTS  bool
		patchErrName    string
		wantPatches     int
		wantInfraSubstr string
		verify          func(t *testing.T, cs *fake.Clientset, sctx context.Context, chk *topologySpreadZoneDeadlockCheck)
	}

	relaxedZoneTSC := []corev1.TopologySpreadConstraint{{
		TopologyKey:       corev1.LabelTopologyZone,
		WhenUnsatisfiable: corev1.ScheduleAnyway,
		MaxSkew:           1,
	}}

	cases := []restoreCase{
		{
			name:         "StatefulSet full restore clears anno, stamps cooldown, invalidates cache",
			healthyZones: 2,
			setup: func(t *testing.T) ([]appsv1.Deployment, []appsv1.StatefulSet, []runtime.Object) {
				sts := makeSTS("db", map[string]string{kube.AnnoTopologyRelaxedBy: defaultRecAnno(t)}, relaxedZoneTSC)
				return nil, []appsv1.StatefulSet{sts}, []runtime.Object{&sts}
			},
			wantPatches: 1,
			verify: func(t *testing.T, cs *fake.Clientset, sctx context.Context, chk *topologySpreadZoneDeadlockCheck) {
				got, err := cs.AppsV1().StatefulSets("apps").Get(ctx, "db", metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				c := got.Spec.Template.Spec.TopologySpreadConstraints[0]
				if c.WhenUnsatisfiable != corev1.DoNotSchedule || c.MinDomains == nil || *c.MinDomains != 2 {
					t.Fatalf("restored STS constraint = %+v", c)
				}
				if _, exists := got.Annotations[kube.AnnoTopologyRelaxedBy]; exists {
					t.Fatal("AnnoTopologyRelaxedBy still present on restored STS")
				}
				if !chk.healCooldowns.CooledDown("apps/StatefulSet/db", topologyPatchCooldown, base) {
					t.Fatal("healCooldowns not stamped for restored STS")
				}
				list, err := chk.AllStatefulSets(sctx)
				if err != nil || len(list) != 1 || list[0].Spec.Template.Spec.TopologySpreadConstraints[0].WhenUnsatisfiable != corev1.DoNotSchedule {
					t.Fatalf("InvalidateStatefulSets did not refresh snapshot: list=%+v err=%v", list, err)
				}
			},
		},
		{
			name:         "Deployment partial restore keeps deferred entry in AnnoTopologyRelaxedBy",
			healthyZones: 2,
			setup: func(t *testing.T) ([]appsv1.Deployment, []appsv1.StatefulSet, []runtime.Object) {
				anno := marshalRec(t, topologyRelaxRecord{
					By:    topologyRelaxedMarkerValue,
					Zones: []string{"az-b", "az-c"},
					Relaxed: []topologyRelaxEntry{
						{Index: 0, MinDomains: &md2},
						{Index: 1, MinDomains: &md3},
					},
				})
				tscs := []corev1.TopologySpreadConstraint{
					{TopologyKey: corev1.LabelTopologyZone, WhenUnsatisfiable: corev1.ScheduleAnyway, MaxSkew: 1},
					{TopologyKey: corev1.LabelTopologyZone, WhenUnsatisfiable: corev1.ScheduleAnyway, MaxSkew: 1},
				}
				dep := makeDep("api", false, map[string]string{kube.AnnoTopologyRelaxedBy: anno}, tscs)
				return []appsv1.Deployment{dep}, nil, []runtime.Object{&dep}
			},
			wantPatches: 1,
			verify: func(t *testing.T, cs *fake.Clientset, _ context.Context, _ *topologySpreadZoneDeadlockCheck) {
				got, err := cs.AppsV1().Deployments("apps").Get(ctx, "api", metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				tscs := got.Spec.Template.Spec.TopologySpreadConstraints
				if tscs[0].WhenUnsatisfiable != corev1.DoNotSchedule || tscs[0].MinDomains == nil || *tscs[0].MinDomains != 2 {
					t.Fatalf("index 0 not restored: %+v", tscs[0])
				}
				if tscs[1].WhenUnsatisfiable != corev1.ScheduleAnyway || tscs[1].MinDomains != nil {
					t.Fatalf("index 1 must stay relaxed: %+v", tscs[1])
				}
				kept, valid := parseTopologyRelaxRecord(got.Annotations[kube.AnnoTopologyRelaxedBy])
				if !valid || len(kept.Relaxed) != 1 || kept.Relaxed[0].Index != 1 || kept.Relaxed[0].MinDomains == nil || *kept.Relaxed[0].MinDomains != 3 {
					t.Fatalf("partial restore kept record = %+v (valid=%v)", kept, valid)
				}
			},
		},
		{
			name:         "paused Deployment skipped without reserving key or spending budget",
			healthyZones: 2,
			setup: func(t *testing.T) ([]appsv1.Deployment, []appsv1.StatefulSet, []runtime.Object) {
				dep := makeDep("api", true, map[string]string{kube.AnnoTopologyRelaxedBy: defaultRecAnno(t)}, relaxedZoneTSC)
				return []appsv1.Deployment{dep}, nil, []runtime.Object{&dep}
			},
			wantPatches: 0,
			verify: func(t *testing.T, _ *fake.Clientset, sctx context.Context, _ *topologySpreadZoneDeadlockCheck) {
				if !kube.TryReserveWorkloadKey(sctx, "apps/Deployment/api") {
					t.Fatal("paused Deployment reserved workload key")
				}
			},
		},
		{
			name:         "empty AnnoTopologyRelaxedBy on Deployment and StatefulSet is no-op",
			healthyZones: 2,
			setup: func(t *testing.T) ([]appsv1.Deployment, []appsv1.StatefulSet, []runtime.Object) {
				dep := makeDep("api", false, nil, relaxedZoneTSC)
				sts := makeSTS("db", nil, relaxedZoneTSC)
				return []appsv1.Deployment{dep}, []appsv1.StatefulSet{sts}, []runtime.Object{&dep, &sts}
			},
			wantPatches: 0,
		},
		{
			name:         "all-deferred !ok on Deployment and StatefulSet touches nothing",
			healthyZones: 1,
			setup: func(t *testing.T) ([]appsv1.Deployment, []appsv1.StatefulSet, []runtime.Object) {
				anno := defaultRecAnno(t)
				dep := makeDep("api", false, map[string]string{kube.AnnoTopologyRelaxedBy: anno}, relaxedZoneTSC)
				sts := makeSTS("db", map[string]string{kube.AnnoTopologyRelaxedBy: anno}, relaxedZoneTSC)
				return []appsv1.Deployment{dep}, []appsv1.StatefulSet{sts}, []runtime.Object{&dep, &sts}
			},
			wantPatches: 0,
			verify: func(t *testing.T, _ *fake.Clientset, sctx context.Context, chk *topologySpreadZoneDeadlockCheck) {
				if !kube.TryReserveWorkloadKey(sctx, "apps/Deployment/api") || !kube.TryReserveWorkloadKey(sctx, "apps/StatefulSet/db") {
					t.Fatal("all-deferred !ok reserved workload key")
				}
				if chk.healCooldowns.CooledDown("apps/Deployment/api", topologyPatchCooldown, base) ||
					chk.healCooldowns.CooledDown("apps/StatefulSet/db", topologyPatchCooldown, base) {
					t.Fatal("all-deferred !ok stamped healCooldowns")
				}
			},
		},
		{
			name:         "malformed JSON orphan cleanup drops annotation and keeps user ScheduleAnyway",
			healthyZones: 2,
			setup: func(t *testing.T) ([]appsv1.Deployment, []appsv1.StatefulSet, []runtime.Object) {
				dep := makeDep("api", false, map[string]string{kube.AnnoTopologyRelaxedBy: "not-json"}, relaxedZoneTSC)
				sts := makeSTS("db", map[string]string{kube.AnnoTopologyRelaxedBy: "not-json"}, relaxedZoneTSC)
				return []appsv1.Deployment{dep}, []appsv1.StatefulSet{sts}, []runtime.Object{&dep, &sts}
			},
			wantPatches: 2,
			verify: func(t *testing.T, cs *fake.Clientset, _ context.Context, _ *topologySpreadZoneDeadlockCheck) {
				dep, _ := cs.AppsV1().Deployments("apps").Get(ctx, "api", metav1.GetOptions{})
				sts, _ := cs.AppsV1().StatefulSets("apps").Get(ctx, "db", metav1.GetOptions{})
				if _, ok := dep.Annotations[kube.AnnoTopologyRelaxedBy]; ok {
					t.Fatal("malformed anno not deleted from Deployment")
				}
				if _, ok := sts.Annotations[kube.AnnoTopologyRelaxedBy]; ok {
					t.Fatal("malformed anno not deleted from StatefulSet")
				}
				if dep.Spec.Template.Spec.TopologySpreadConstraints[0].WhenUnsatisfiable != corev1.ScheduleAnyway ||
					sts.Spec.Template.Spec.TopologySpreadConstraints[0].WhenUnsatisfiable != corev1.ScheduleAnyway {
					t.Fatal("orphan cleanup mutated user ScheduleAnyway constraint")
				}
			},
		},
		{
			name:         "wrong By and empty Relaxed orphan annotations cleaned up",
			healthyZones: 2,
			setup: func(t *testing.T) ([]appsv1.Deployment, []appsv1.StatefulSet, []runtime.Object) {
				wrongBy := marshalRec(t, topologyRelaxRecord{By: "other", Relaxed: []topologyRelaxEntry{{Index: 0}}})
				emptyRel := marshalRec(t, topologyRelaxRecord{By: topologyRelaxedMarkerValue, Relaxed: []topologyRelaxEntry{}})
				dep := makeDep("api", false, map[string]string{kube.AnnoTopologyRelaxedBy: wrongBy}, relaxedZoneTSC)
				sts := makeSTS("db", map[string]string{kube.AnnoTopologyRelaxedBy: emptyRel}, relaxedZoneTSC)
				return []appsv1.Deployment{dep}, []appsv1.StatefulSet{sts}, []runtime.Object{&dep, &sts}
			},
			wantPatches: 2,
			verify: func(t *testing.T, cs *fake.Clientset, _ context.Context, _ *topologySpreadZoneDeadlockCheck) {
				dep, _ := cs.AppsV1().Deployments("apps").Get(ctx, "api", metav1.GetOptions{})
				sts, _ := cs.AppsV1().StatefulSets("apps").Get(ctx, "db", metav1.GetOptions{})
				if _, ok := dep.Annotations[kube.AnnoTopologyRelaxedBy]; ok {
					t.Fatal("wrong-By anno not deleted")
				}
				if _, ok := sts.Annotations[kube.AnnoTopologyRelaxedBy]; ok {
					t.Fatal("empty-Relaxed anno not deleted")
				}
			},
		},
		{
			name:         "already restored and stale-index orphan annotations cleaned up",
			healthyZones: 2,
			setup: func(t *testing.T) ([]appsv1.Deployment, []appsv1.StatefulSet, []runtime.Object) {
				anno := defaultRecAnno(t)
				staleIdx := marshalRec(t, topologyRelaxRecord{By: topologyRelaxedMarkerValue, Relaxed: []topologyRelaxEntry{{Index: 5}}})
				alreadyDoNotSched := []corev1.TopologySpreadConstraint{{
					TopologyKey: corev1.LabelTopologyZone, WhenUnsatisfiable: corev1.DoNotSchedule, MaxSkew: 1,
				}}
				dep := makeDep("api", false, map[string]string{kube.AnnoTopologyRelaxedBy: anno}, alreadyDoNotSched)
				sts := makeSTS("db", map[string]string{kube.AnnoTopologyRelaxedBy: staleIdx}, relaxedZoneTSC)
				return []appsv1.Deployment{dep}, []appsv1.StatefulSet{sts}, []runtime.Object{&dep, &sts}
			},
			wantPatches: 2,
			verify: func(t *testing.T, cs *fake.Clientset, _ context.Context, _ *topologySpreadZoneDeadlockCheck) {
				dep, _ := cs.AppsV1().Deployments("apps").Get(ctx, "api", metav1.GetOptions{})
				sts, _ := cs.AppsV1().StatefulSets("apps").Get(ctx, "db", metav1.GetOptions{})
				if _, ok := dep.Annotations[kube.AnnoTopologyRelaxedBy]; ok {
					t.Fatal("already-restored anno not deleted")
				}
				if _, ok := sts.Annotations[kube.AnnoTopologyRelaxedBy]; ok {
					t.Fatal("stale-index anno not deleted")
				}
				if sts.Spec.Template.Spec.TopologySpreadConstraints[0].WhenUnsatisfiable != corev1.ScheduleAnyway {
					t.Fatal("stale-index cleanup altered user ScheduleAnyway constraint")
				}
			},
		},
		{
			name:          "SweepOverlay adds AnnoTopologyRelaxedBy visibility to restore",
			healthyZones:  2,
			overlaySetSTS: true,
			setup: func(t *testing.T) ([]appsv1.Deployment, []appsv1.StatefulSet, []runtime.Object) {
				sts := makeSTS("db", nil, relaxedZoneTSC)
				return nil, []appsv1.StatefulSet{sts}, []runtime.Object{&sts}
			},
			wantPatches: 1,
			verify: func(t *testing.T, cs *fake.Clientset, _ context.Context, _ *topologySpreadZoneDeadlockCheck) {
				sts, _ := cs.AppsV1().StatefulSets("apps").Get(ctx, "db", metav1.GetOptions{})
				if sts.Spec.Template.Spec.TopologySpreadConstraints[0].WhenUnsatisfiable != corev1.DoNotSchedule {
					t.Fatal("SweepOverlay AnnoTopologyRelaxedBy did not trigger restore")
				}
			},
		},
		{
			name:           "SweepOverlay deletes AnnoTopologyRelaxedBy and skips restore",
			healthyZones:   2,
			overlayDropSTS: true,
			setup: func(t *testing.T) ([]appsv1.Deployment, []appsv1.StatefulSet, []runtime.Object) {
				sts := makeSTS("db", map[string]string{kube.AnnoTopologyRelaxedBy: defaultRecAnno(t)}, relaxedZoneTSC)
				return nil, []appsv1.StatefulSet{sts}, []runtime.Object{&sts}
			},
			wantPatches: 0,
		},
		{
			name:           "HealAllowedClusterWideOnly skips active cooldown for Deployment and StatefulSet",
			healthyZones:   2,
			activeCooldown: "both",
			setup: func(t *testing.T) ([]appsv1.Deployment, []appsv1.StatefulSet, []runtime.Object) {
				anno := defaultRecAnno(t)
				dep := makeDep("api", false, map[string]string{kube.AnnoTopologyRelaxedBy: anno}, relaxedZoneTSC)
				sts := makeSTS("db", map[string]string{kube.AnnoTopologyRelaxedBy: anno}, relaxedZoneTSC)
				return []appsv1.Deployment{dep}, []appsv1.StatefulSet{sts}, []runtime.Object{&dep, &sts}
			},
			wantPatches: 0,
		},
		{
			name:         "HealAllowedClusterWideOnly skips cluster-wide kured hold",
			healthyZones: 2,
			kuredAnno:    "cluster-upgrade",
			setup: func(t *testing.T) ([]appsv1.Deployment, []appsv1.StatefulSet, []runtime.Object) {
				anno := defaultRecAnno(t)
				dep := makeDep("api", false, map[string]string{kube.AnnoTopologyRelaxedBy: anno}, relaxedZoneTSC)
				sts := makeSTS("db", map[string]string{kube.AnnoTopologyRelaxedBy: anno}, relaxedZoneTSC)
				return []appsv1.Deployment{dep}, []appsv1.StatefulSet{sts}, []runtime.Object{&dep, &sts}
			},
			wantPatches: 0,
		},
		{
			name:         "HealAllowedClusterWideOnly proceeds under node-scoped kured hold",
			healthyZones: 2,
			kuredAnno:    `{"nodeID":"worker-b"}`,
			setup: func(t *testing.T) ([]appsv1.Deployment, []appsv1.StatefulSet, []runtime.Object) {
				anno := defaultRecAnno(t)
				dep := makeDep("api", false, map[string]string{kube.AnnoTopologyRelaxedBy: anno}, relaxedZoneTSC)
				sts := makeSTS("db", map[string]string{kube.AnnoTopologyRelaxedBy: anno}, relaxedZoneTSC)
				return []appsv1.Deployment{dep}, []appsv1.StatefulSet{sts}, []runtime.Object{&dep, &sts}
			},
			wantPatches: 2,
		},
		{
			name:         "HealAllowedClusterWideOnly unverifiable (Dyn nil) records InfraErr",
			healthyZones: 2,
			nilDyn:       true,
			setup: func(t *testing.T) ([]appsv1.Deployment, []appsv1.StatefulSet, []runtime.Object) {
				anno := defaultRecAnno(t)
				dep := makeDep("api", false, map[string]string{kube.AnnoTopologyRelaxedBy: anno}, relaxedZoneTSC)
				sts := makeSTS("db", map[string]string{kube.AnnoTopologyRelaxedBy: anno}, relaxedZoneTSC)
				return []appsv1.Deployment{dep}, []appsv1.StatefulSet{sts}, []runtime.Object{&dep, &sts}
			},
			wantPatches:     0,
			wantInfraSubstr: "maintenance mutex unverifiable — restore deployment deferred",
		},
		{
			name:         "HealAllowedClusterWideOnly unverifiable (nodes list error) records InfraErr",
			healthyZones: 2,
			nodeListErr:  true,
			setup: func(t *testing.T) ([]appsv1.Deployment, []appsv1.StatefulSet, []runtime.Object) {
				sts := makeSTS("db", map[string]string{kube.AnnoTopologyRelaxedBy: defaultRecAnno(t)}, relaxedZoneTSC)
				return nil, []appsv1.StatefulSet{sts}, []runtime.Object{&sts}
			},
			wantPatches:     0,
			wantInfraSubstr: "maintenance mutex unverifiable — restore statefulset deferred",
		},
		{
			name:          "HealAllowedClusterWideOnly skips when global budget exhausted",
			healthyZones:  2,
			exhaustBudget: true,
			setup: func(t *testing.T) ([]appsv1.Deployment, []appsv1.StatefulSet, []runtime.Object) {
				anno := defaultRecAnno(t)
				dep := makeDep("api", false, map[string]string{kube.AnnoTopologyRelaxedBy: anno}, relaxedZoneTSC)
				sts := makeSTS("db", map[string]string{kube.AnnoTopologyRelaxedBy: anno}, relaxedZoneTSC)
				return []appsv1.Deployment{dep}, []appsv1.StatefulSet{sts}, []runtime.Object{&dep, &sts}
			},
			wantPatches: 0,
		},
		{
			name:         "multi-workload continuation proceeds after paused/error workloads",
			healthyZones: 2,
			patchErrName: "api-err",
			setup: func(t *testing.T) ([]appsv1.Deployment, []appsv1.StatefulSet, []runtime.Object) {
				anno := defaultRecAnno(t)
				depPaused := makeDep("api-paused", true, map[string]string{kube.AnnoTopologyRelaxedBy: anno}, relaxedZoneTSC)
				depErr := makeDep("api-err", false, map[string]string{kube.AnnoTopologyRelaxedBy: anno}, relaxedZoneTSC)
				depOK := makeDep("api-ok", false, map[string]string{kube.AnnoTopologyRelaxedBy: anno}, relaxedZoneTSC)
				stsErr := makeSTS("api-err", map[string]string{kube.AnnoTopologyRelaxedBy: anno}, relaxedZoneTSC)
				stsOK := makeSTS("db-ok", map[string]string{kube.AnnoTopologyRelaxedBy: anno}, relaxedZoneTSC)
				return []appsv1.Deployment{depPaused, depErr, depOK}, []appsv1.StatefulSet{stsErr, stsOK},
					[]runtime.Object{&depPaused, &depErr, &depOK, &stsErr, &stsOK}
			},
			wantPatches:     4,
			wantInfraSubstr: "topology zone restore Deployment apps/Deployment/api-err",
			verify: func(t *testing.T, cs *fake.Clientset, _ context.Context, _ *topologySpreadZoneDeadlockCheck) {
				depOK, _ := cs.AppsV1().Deployments("apps").Get(ctx, "api-ok", metav1.GetOptions{})
				stsOK, _ := cs.AppsV1().StatefulSets("apps").Get(ctx, "db-ok", metav1.GetOptions{})
				if depOK.Spec.Template.Spec.TopologySpreadConstraints[0].WhenUnsatisfiable != corev1.DoNotSchedule {
					t.Fatal("api-ok Deployment not restored after earlier patch error")
				}
				if stsOK.Spec.Template.Spec.TopologySpreadConstraints[0].WhenUnsatisfiable != corev1.DoNotSchedule {
					t.Fatal("db-ok StatefulSet not restored after earlier patch error")
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.exhaustBudget {
				heal.ConfigureBudget(1, time.Hour)
				t.Cleanup(func() { heal.ConfigureBudget(0, 0) })
			}

			deps, stss, objs := tc.setup(t)
			objs = append(objs,
				zoneWorkerNode("worker-a", "az-a", true, false),
				zoneWorkerNode("worker-b", "az-b", true, false),
			)
			if tc.kuredAnno != "" {
				objs = append(objs, &appsv1.DaemonSet{
					ObjectMeta: metav1.ObjectMeta{
						Namespace:   "kube-system",
						Name:        "kured",
						Annotations: map[string]string{"weave.works/kured-node-lock": tc.kuredAnno},
					},
				})
			}

			cs := fake.NewSimpleClientset(objs...)
			var patches int
			cs.PrependReactor("patch", "*", func(action ktesting.Action) (bool, runtime.Object, error) {
				pa := action.(ktesting.PatchAction)
				res := pa.GetResource().Resource
				if res != "deployments" && res != "statefulsets" {
					return false, nil, nil
				}
				patches++
				if tc.patchErrName != "" && pa.GetName() == tc.patchErrName {
					return true, nil, errors.New("apiserver patch error")
				}
				return false, nil, nil
			})
			if tc.nodeListErr {
				cs.PrependReactor("list", "nodes", func(ktesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("nodes list failed")
				})
			}

			p := testProberDyn(cs, probetest.OpDyn())
			chk := probetest.MustCheck[*topologySpreadZoneDeadlockCheck](t, p)
			if tc.nilDyn {
				chk.Dyn = nil
			}
			sctx := probetest.SweepCtx(ctx, chk.Deps)
			defer probetest.VerifySweep(sctx)

			if tc.activeCooldown == "both" {
				chk.healCooldowns.Stamp("apps/Deployment/api", base.Add(-5*time.Minute))
				chk.healCooldowns.Stamp("apps/StatefulSet/db", base.Add(-5*time.Minute))
			}
			if tc.exhaustBudget {
				if proceed, _ := chk.HealAllowedClusterWideOnly(sctx, logr.Discard(), nil, "other/Deployment/sib", time.Minute, base); !proceed {
					t.Fatal("failed to pre-spend heal budget")
				}
			}
			if tc.overlaySetSTS {
				payload, err := kube.MergePatchAnnos(map[string]any{kube.AnnoTopologyRelaxedBy: defaultRecAnno(t)})
				if err != nil {
					t.Fatal(err)
				}
				kube.RecordAnnoPatch(sctx, &stss[0], payload)
			}
			if tc.overlayDropSTS {
				payload, err := kube.MergePatchAnnos(map[string]any{kube.AnnoTopologyRelaxedBy: nil})
				if err != nil {
					t.Fatal(err)
				}
				kube.RecordAnnoPatch(sctx, &stss[0], payload)
			}

			var rep probefw.SweepReport
			chk.restoreRelaxedWorkloads(sctx, logr.Discard(), &rep, deps, stss, tc.healthyZones, base)

			if patches != tc.wantPatches {
				t.Fatalf("patches = %d, want %d", patches, tc.wantPatches)
			}
			res := rep.Verdict("topology: ", ", ")
			if tc.wantInfraSubstr != "" {
				if res.Infra == nil || !strings.Contains(res.Infra.Error(), tc.wantInfraSubstr) {
					t.Fatalf("Infra = %v, want substring %q", res.Infra, tc.wantInfraSubstr)
				}
			} else if res.Infra != nil {
				t.Fatalf("unexpected Infra error: %v", res.Infra)
			}
			if tc.verify != nil {
				tc.verify(t, cs, sctx, chk)
			}
		})
	}
}
