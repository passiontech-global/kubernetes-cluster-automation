// workload_history_gc_test.go — coverage for Wave 4C #11 extended API
// object sprawl census + bounded auto-GC: 0-replica ReplicaSets,
// orphan ControllerRevisions, orphan SA-token Secrets, 24h age gate,
// revisionHistoryLimit floor of 10, cap=30 oldest-first, UID delete
// preconditions, 403 graceful skip, env gate, and GaugeLedger cleanup.
package sprawl

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func makeDeploy(ns, name string, uid types.UID, revLimit *int32) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: uid},
		Spec: appsv1.DeploymentSpec{
			RevisionHistoryLimit: revLimit,
		},
	}
}

func makeZeroRS(ns, name string, uid types.UID, depName string, depUID types.UID, createdAt time.Time, specReps, statusReps int32) *appsv1.ReplicaSet {
	return &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         ns,
			Name:              name,
			UID:               uid,
			CreationTimestamp: metav1.NewTime(createdAt),
			OwnerReferences: []metav1.OwnerReference{{
				Kind:       "Deployment",
				Name:       depName,
				UID:        depUID,
				Controller: ptr.To(true),
			}},
		},
		Spec:   appsv1.ReplicaSetSpec{Replicas: ptr.To(specReps)},
		Status: appsv1.ReplicaSetStatus{Replicas: statusReps},
	}
}

func makeCR(ns, name string, uid types.UID, ownerKind, ownerName string, ownerUID types.UID, createdAt time.Time) *appsv1.ControllerRevision {
	return &appsv1.ControllerRevision{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         ns,
			Name:              name,
			UID:               uid,
			CreationTimestamp: metav1.NewTime(createdAt),
			OwnerReferences: []metav1.OwnerReference{{
				Kind:       ownerKind,
				Name:       ownerName,
				UID:        ownerUID,
				Controller: ptr.To(true),
			}},
		},
	}
}

func makeSATokenSecret(ns, name string, uid types.UID, saName string, saUID types.UID, createdAt time.Time) *corev1.Secret {
	annos := map[string]string{
		corev1.ServiceAccountNameKey: saName,
	}
	if saUID != "" {
		annos[corev1.ServiceAccountUIDKey] = string(saUID)
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         ns,
			Name:              name,
			UID:               uid,
			Annotations:       annos,
			CreationTimestamp: metav1.NewTime(createdAt),
		},
		Type: corev1.SecretTypeServiceAccountToken,
	}
}

func TestWorkloadHistoryGC_ReplicaSetOrphanAndExcessHistory(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

	// Deployment with revisionHistoryLimit=2 -> effective keep floor is 10.
	dep := makeDeploy("apps", "web", "dep-uid-1", ptr.To(int32(2)))
	var objs []runtime.Object
	objs = append(objs, dep)

	// 12 zero-replica RSs for live dep:
	// - 11 older than 24h (rs-00 .. rs-10, rs-00 oldest)
	// - 1 newer than 24h (rs-11, age 2h)
	// Grouping all 12 first keeps newest 10 (rs-02..rs-11) and marks rs-00, rs-01 as excess (>24h).
	for i := range 11 {
		age := time.Duration(36-i) * time.Hour
		objs = append(objs, makeZeroRS("apps", fmt.Sprintf("web-rs-%02d", i),
			types.UID(fmt.Sprintf("uid-rs-%02d", i)), "web", "dep-uid-1", now.Add(-age), 0, 0))
	}
	objs = append(objs, makeZeroRS("apps", "web-rs-11", "uid-rs-11",
		"web", "dep-uid-1", now.Add(-2*time.Hour), 0, 0))

	// Active RS (status.replicas=1) must not be counted in 0-replica history or deleted.
	objs = append(objs, makeZeroRS("apps", "web-rs-active", "uid-rs-active",
		"web", "dep-uid-1", now.Add(-48*time.Hour), 0, 1))

	// Orphan RS (missing Deployment), >24h -> deleted.
	objs = append(objs, makeZeroRS("apps", "gone-rs-old", "uid-gone-old",
		"gone-dep", "gone-uid", now.Add(-25*time.Hour), 0, 0))
	// Orphan RS at exact 24h boundary -> must NOT be deleted (strictly > 24h).
	objs = append(objs, makeZeroRS("apps", "gone-rs-boundary", "uid-gone-boundary",
		"gone-dep", "gone-uid", now.Add(-24*time.Hour), 0, 0))
	// Orphan RS with UID mismatch vs live Deployment -> deleted.
	objs = append(objs, makeZeroRS("apps", "web-old-incarnation", "uid-old-inc",
		"web", "dep-uid-stale", now.Add(-26*time.Hour), 0, 0))

	cs := fake.NewSimpleClientset(objs...)
	var deletedWithUID []types.UID
	cs.PrependReactor("delete", "replicasets", func(action ktesting.Action) (bool, runtime.Object, error) {
		da := action.(ktesting.DeleteAction)
		if da.GetDeleteOptions().Preconditions != nil && da.GetDeleteOptions().Preconditions.UID != nil {
			deletedWithUID = append(deletedWithUID, *da.GetDeleteOptions().Preconditions.UID)
		}
		return false, nil, nil
	})

	p := testProberDyn(cs, sprawlDyn())
	probetest.FreezeNow(p.Deps, now)
	ch := probetest.MustCheck[*apiObjectSprawlReportGCCheck](t, p)
	res := ch.Run(probetest.SweepCtx(ctx, p.Deps))
	if res.Pass {
		t.Fatalf("expected failing verdict while sprawl exists: %+v", res)
	}
	if !strings.Contains(res.Why, "4 replicaset_zero sprawl") {
		t.Fatalf("unexpected Why: %q", res.Why)
	}
	if len(deletedWithUID) != 4 {
		t.Fatalf("expected 4 UID-preconditioned deletes, got %d (%v)", len(deletedWithUID), deletedWithUID)
	}

	// Verify expected deletions vs survivals.
	for _, gone := range []string{"web-rs-00", "web-rs-01", "gone-rs-old", "web-old-incarnation"} {
		if _, err := cs.AppsV1().ReplicaSets("apps").Get(ctx, gone, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Fatalf("expected %s to be deleted, err=%v", gone, err)
		}
	}
	for _, keep := range []string{"web-rs-02", "web-rs-10", "web-rs-11", "web-rs-active", "gone-rs-boundary"} {
		if _, err := cs.AppsV1().ReplicaSets("apps").Get(ctx, keep, metav1.GetOptions{}); err != nil {
			t.Fatalf("expected %s to survive: %v", keep, err)
		}
	}

	// Second sweep: all >24h targets are gone, gauge series must prune via GaugeLedger.
	res2 := ch.Run(probetest.SweepCtx(ctx, p.Deps))
	if !res2.Pass {
		t.Fatalf("expected PASS after sprawl cleared, got %+v", res2)
	}
	if _, ok := testutil.GaugeSeriesValue(t, "node_automation_api_object_sprawl_count",
		map[string]string{"kind": sprawlKindReplicaSetZero}); ok {
		t.Fatal("stale replicaset_zero gauge series not pruned on recovery")
	}
}

func TestWorkloadHistoryGC_ControllerRevisionsAndSATokens(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

	liveSTS := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Namespace: "db", Name: "pg", UID: "sts-live"}}
	liveDS := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "cilium", UID: "ds-live"}}
	liveSA := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "worker", UID: "sa-live"}}

	objs := []runtime.Object{
		liveSTS, liveDS, liveSA,
		// Live owner ControllerRevisions -> survive.
		makeCR("db", "pg-rev-live", "cr-1", "StatefulSet", "pg", "sts-live", now.Add(-48*time.Hour)),
		makeCR("kube-system", "cilium-rev-live", "cr-2", "DaemonSet", "cilium", "ds-live", now.Add(-48*time.Hour)),
		// Orphan CR (StatefulSet gone, >24h) -> deleted.
		makeCR("db", "old-sts-rev", "cr-orphan-1", "StatefulSet", "gone-sts", "sts-gone", now.Add(-30*time.Hour)),
		// Orphan CR (DaemonSet UID mismatch, >24h) -> deleted.
		makeCR("kube-system", "old-ds-rev", "cr-orphan-2", "DaemonSet", "cilium", "ds-stale", now.Add(-30*time.Hour)),
		// Orphan CR (<=24h) -> survive.
		makeCR("db", "young-orphan-rev", "cr-young", "StatefulSet", "gone-sts", "sts-gone", now.Add(-20*time.Hour)),

		// Live SA-token Secret -> survive.
		makeSATokenSecret("apps", "worker-token-live", "sec-1", "worker", "sa-live", now.Add(-72*time.Hour)),
		// Orphan SA-token Secret (missing SA, >24h) -> deleted.
		makeSATokenSecret("apps", "gone-sa-token", "sec-orphan-1", "deleted-sa", "sa-gone", now.Add(-48*time.Hour)),
		// Orphan SA-token Secret (SA UID mismatch, >24h) -> deleted.
		makeSATokenSecret("apps", "stale-uid-token", "sec-orphan-2", "worker", "sa-old-uid", now.Add(-48*time.Hour)),
		// Orphan SA-token Secret (<=24h) -> survive.
		makeSATokenSecret("apps", "young-sa-token", "sec-young", "deleted-sa", "sa-gone", now.Add(-12*time.Hour)),
		// Non-SA-token Opaque Secret even with SA annotation -> survive.
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:         "apps",
				Name:              "opaque-not-sa-token",
				UID:               "sec-opaque",
				Annotations:       map[string]string{corev1.ServiceAccountNameKey: "deleted-sa"},
				CreationTimestamp: metav1.NewTime(now.Add(-72 * time.Hour)),
			},
			Type: corev1.SecretTypeOpaque,
		},
	}

	cs := fake.NewSimpleClientset(objs...)
	p := testProberDyn(cs, sprawlDyn())
	probetest.FreezeNow(p.Deps, now)
	ch := probetest.MustCheck[*apiObjectSprawlReportGCCheck](t, p)
	res := ch.Run(probetest.SweepCtx(ctx, p.Deps))
	if res.Pass {
		t.Fatalf("expected sprawl findings, got PASS: %+v", res)
	}

	for _, name := range []string{"old-sts-rev"} {
		if _, err := cs.AppsV1().ControllerRevisions("db").Get(ctx, name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Fatalf("expected CR db/%s deleted, err=%v", name, err)
		}
	}
	if _, err := cs.AppsV1().ControllerRevisions("kube-system").Get(ctx, "old-ds-rev", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("expected CR kube-system/old-ds-rev deleted, err=%v", err)
	}
	for _, name := range []string{"pg-rev-live", "young-orphan-rev"} {
		if _, err := cs.AppsV1().ControllerRevisions("db").Get(ctx, name, metav1.GetOptions{}); err != nil {
			t.Fatalf("expected CR db/%s to survive: %v", name, err)
		}
	}
	for _, name := range []string{"gone-sa-token", "stale-uid-token"} {
		if _, err := cs.CoreV1().Secrets("apps").Get(ctx, name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Fatalf("expected Secret apps/%s deleted, err=%v", name, err)
		}
	}
	for _, name := range []string{"worker-token-live", "young-sa-token", "opaque-not-sa-token"} {
		if _, err := cs.CoreV1().Secrets("apps").Get(ctx, name, metav1.GetOptions{}); err != nil {
			t.Fatalf("expected Secret apps/%s to survive: %v", name, err)
		}
	}
}

func TestWorkloadHistoryGC_CapAndEnvGateAnd403(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

	t.Run("env gate false reports census without deleting", func(t *testing.T) {
		t.Setenv("NODE_AUTOMATION_SPRAWL_HISTORY_GC_ENABLED", "false")
		cs := fake.NewSimpleClientset(
			makeCR("db", "orphan-cr", "cr-1", "StatefulSet", "gone", "uid-gone", now.Add(-30*time.Hour)),
		)
		p := testProberDyn(cs, sprawlDyn())
		probetest.FreezeNow(p.Deps, now)
		ch := probetest.MustCheck[*apiObjectSprawlReportGCCheck](t, p)
		res := ch.Run(probetest.SweepCtx(ctx, p.Deps))
		if res.Pass {
			t.Fatal("expected failing finding when GC disabled and sprawl present")
		}
		if _, err := cs.AppsV1().ControllerRevisions("db").Get(ctx, "orphan-cr", metav1.GetOptions{}); err != nil {
			t.Fatalf("GC disabled must not delete: %v", err)
		}
		v, ok := testutil.GaugeSeriesValue(t, "node_automation_api_object_sprawl_count",
			map[string]string{"kind": sprawlKindControllerRevOrphan})
		if !ok || v != 1 {
			t.Fatalf("sprawl count gauge = %v, %v want 1", v, ok)
		}
	})

	t.Run("cap 30 deletes oldest first", func(t *testing.T) {
		var objs []runtime.Object
		for i := range 35 {
			age := time.Duration(60-i) * time.Hour // i=0 oldest (60h), i=34 newest (26h)
			objs = append(objs, makeZeroRS("apps", fmt.Sprintf("orphan-%02d", i),
				types.UID(fmt.Sprintf("uid-%02d", i)), "gone", "gone-uid", now.Add(-age), 0, 0))
		}
		cs := fake.NewSimpleClientset(objs...)
		p := testProberDyn(cs, sprawlDyn())
		probetest.FreezeNow(p.Deps, now)
		ch := probetest.MustCheck[*apiObjectSprawlReportGCCheck](t, p)
		ch.Run(probetest.SweepCtx(ctx, p.Deps))
		rem, err := cs.AppsV1().ReplicaSets("apps").List(ctx, metav1.ListOptions{})
		if err != nil {
			t.Fatalf("list rs: %v", err)
		}
		if len(rem.Items) != 5 {
			t.Fatalf("remaining replicasets = %d, want 5 (cap 30/35)", len(rem.Items))
		}
		for _, rs := range rem.Items {
			// Remaining 5 must be orphan-30 .. orphan-34.
			if rs.Name < "orphan-30" {
				t.Fatalf("expected oldest deleted first; unexpected survivor %s", rs.Name)
			}
		}
	})

	t.Run("403 forbidden on list carries series and skips without Infra error", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			makeCR("db", "orphan-cr", "cr-1", "StatefulSet", "gone", "uid-gone", now.Add(-30*time.Hour)),
		)
		p := testProberDyn(cs, sprawlDyn())
		probetest.FreezeNow(p.Deps, now)
		ch := probetest.MustCheck[*apiObjectSprawlReportGCCheck](t, p)

		// First sweep with GC disabled seeds emittedHistorySprawl with controllerrevision_orphan=1.
		ch.historyGCEnabled = false
		res1 := ch.Run(probetest.SweepCtx(ctx, p.Deps))
		if res1.Pass || res1.Infra != nil {
			t.Fatalf("unexpected sweep 1 result: %+v", res1)
		}

		// Inject 403 on list controllerrevisions for sweep 2.
		cs.PrependReactor("list", "controllerrevisions", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, &apierrors.StatusError{ErrStatus: metav1.Status{
				Status:  metav1.StatusFailure,
				Reason:  metav1.StatusReasonForbidden,
				Code:    http.StatusForbidden,
				Message: "forbidden",
			}}
		})
		res2 := ch.Run(probetest.SweepCtx(ctx, p.Deps))
		if res2.Infra != nil {
			t.Fatalf("403 must gracefully skip without Infra error, got %v", res2.Infra)
		}
		// Held series must still exist (carried forward on 403).
		if _, ok := testutil.GaugeSeriesValue(t, "node_automation_api_object_sprawl_count",
			map[string]string{"kind": sprawlKindControllerRevOrphan}); !ok {
			t.Fatal("403 list skip must carry held sprawl series forward")
		}
	})

	t.Run("403 forbidden on delete skips without IncError", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			makeCR("db", "orphan-cr-403", "cr-403", "StatefulSet", "gone", "uid-gone", now.Add(-30*time.Hour)),
		)
		cs.PrependReactor("delete", "controllerrevisions", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, &apierrors.StatusError{ErrStatus: metav1.Status{
				Status:  metav1.StatusFailure,
				Reason:  metav1.StatusReasonForbidden,
				Code:    http.StatusForbidden,
				Message: "forbidden",
			}}
		})
		p := testProberDyn(cs, sprawlDyn())
		probetest.FreezeNow(p.Deps, now)
		ch := probetest.MustCheck[*apiObjectSprawlReportGCCheck](t, p)
		beforeErrs := probetest.CounterSnapshot(t, p.Name)
		res := ch.Run(probetest.SweepCtx(ctx, p.Deps))
		if res.Infra != nil {
			t.Fatalf("403 on delete must not set Infra: %v", res.Infra)
		}
		probetest.AssertCounterDelta(t, p.Name, beforeErrs, 0)
	})
}
