// dragonfly_replica_sync_storm_test.go — coverage for the
// dragonfly-replica-sync-storm check (dragonfly-replica-sync-storm): replica restart
// (never the master) on confirmed storm, link-down alone FAILs
// without restart.
package datastore

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// Restart resume: a replica still carrying the persisted first-seen
// stamp past the 5m window restarts on the FIRST post-restart sweep —
// the in-RAM ledger is empty but the annotation proves the link-down
// held; the master is still never restarted.
func TestDragonflySyncStormResumeRestarts(t *testing.T) {
	srv := dragonflyPromServer(t)
	base := time.Now()
	replica := dragonflyMemberPod("dragonfly", "dragonfly-replica-1", "replica")
	replica.Annotations = map[string]string{
		kube.AnnoFirstSeenDragonflyLinkStorm: `{"link/dragonfly/dragonfly-replica-1":"` +
			base.Add(-6*time.Minute).UTC().Format(time.RFC3339) + `"}`}
	master := dragonflyMemberPod("dragonfly", "dragonfly-master-0", "master")
	cs := fake.NewSimpleClientset(replica, master)
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	p.Now = func() time.Time { return base }

	res := probetest.MustCheck[*dragonflyReplicaSyncStormCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("persisted link-storm window must FAIL on the first sweep")
	}
	if _, err := cs.CoreV1().Pods("dragonfly").
		Get(ctx, "dragonfly-replica-1", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("resumed window must restart the replica, err=%v", err)
	}
	if _, err := cs.CoreV1().Pods("dragonfly").
		Get(ctx, "dragonfly-master-0", metav1.GetOptions{}); err != nil {
		t.Fatal("master must never be restarted")
	}
}

func TestDragonflySyncStormRestartsReplicaNotMaster(t *testing.T) {
	srv := dragonflyPromServer(t)
	replica := dragonflyMemberPod("dragonfly", "dragonfly-replica-1", "replica")
	master := dragonflyMemberPod("dragonfly", "dragonfly-master-0", "master")
	cs := fake.NewSimpleClientset(replica, master)
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	base := time.Now()
	p.Now = func() time.Time { return base }

	// First sweep stamps the link-down first-seen; second (past the
	// 5m persistence window) confirms the storm.
	if res := probetest.MustCheck[*dragonflyReplicaSyncStormCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("first sighting inside window must pass: %+v", res)
	}
	base = base.Add(6 * time.Minute)
	res := probetest.MustCheck[*dragonflyReplicaSyncStormCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("sustained link-down + sync storm must fail: %+v", res)
	}
	if !strings.Contains(res.Why, "dragonfly-replica-1") {
		t.Fatalf("why missing replica: %q", res.Why)
	}
	if _, err := cs.CoreV1().Pods("dragonfly").Get(ctx, "dragonfly-replica-1", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("desynced replica should be restarted, err=%v", err)
	}
	if _, err := cs.CoreV1().Pods("dragonfly").Get(ctx, "dragonfly-master-0", metav1.GetOptions{}); err != nil {
		t.Fatalf("master must never be restarted: %v", err)
	}
}

// A Dragonfly CR parked at spec.replicas:0 by the
// go-kube-downscaler — a sustained link-down series for its member
// pod is never storm evidence and the pod is never restarted.
func TestDragonflySyncStormSkipsDownscaledCluster(t *testing.T) {
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, "master_link_status") {
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "dragonfly", "pod": "dragonfly-0"},
				Value:  0,
			}}
		}
		return nil
	})
	cr := probetest.UnstructuredObj("dragonflydb.io/v1alpha1", "Dragonfly",
		"dragonfly", "dragonfly", 1, 0)
	cr.SetAnnotations(map[string]string{"downscaler/uptime": "08:00-20:00"})
	cr.Object["spec"] = map[string]any{"replicas": int64(0)}
	replica := dragonflyMemberPod("dragonfly", "dragonfly-0", "replica")
	cs := fake.NewSimpleClientset(replica)
	p := testProberDyn(cs, probetest.OpDyn(cr))
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	base := time.Now()
	p.Now = func() time.Time { return base }

	probetest.MustCheck[*dragonflyReplicaSyncStormCheck](t, p).Run(ctx)
	base = base.Add(6 * time.Minute)
	res := probetest.MustCheck[*dragonflyReplicaSyncStormCheck](t, p).Run(ctx)
	if !res.Pass {
		t.Fatalf("downscaled dragonfly cluster must pass: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("dragonfly").Get(ctx, "dragonfly-0", metav1.GetOptions{}); err != nil {
		t.Fatalf("downscaled member must not be restarted: %v", err)
	}
}

func TestDragonflyLinkDownAloneDoesNotRestart(t *testing.T) {
	// Storm query returns empty -> sustained link-down FAILs but no
	// restart.
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, "master_link_status") {
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "dragonfly", "pod": "dragonfly-replica-9"},
				Value:  0,
			}}
		}
		return nil
	})
	replica := dragonflyMemberPod("dragonfly", "dragonfly-replica-9", "replica")
	cs := fake.NewSimpleClientset(replica)
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	base := time.Now()
	p.Now = func() time.Time { return base }
	probetest.MustCheck[*dragonflyReplicaSyncStormCheck](t, p).Run(ctx)
	base = base.Add(6 * time.Minute)
	res := probetest.MustCheck[*dragonflyReplicaSyncStormCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("sustained link-down must still fail: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("dragonfly").Get(ctx, "dragonfly-replica-9", metav1.GetOptions{}); err != nil {
		t.Fatalf("unconfirmed storm must not restart the replica: %v", err)
	}
}

func dragonflyMemberPod(ns, name string, role string) *corev1.Pod {
	pod := probetest.PodWithPhase(ns, name, corev1.PodRunning, true, time.Hour)
	pod.Labels = map[string]string{
		"app.kubernetes.io/name": "dragonfly",
	}
	if role != "" {
		pod.Labels["app.kubernetes.io/role"] = role
	}
	// Live members are StatefulSet-owned — the heal's candidate
	// filter requires a controller and its cooldown keys on one.
	pod.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: "apps/v1", Kind: "StatefulSet",
		Name: name + "-sts", Controller: ptr.To(true),
	}}
	return pod
}

// dragonflyPromServer answers the link-down query (BOTH the replica and
// the master report link down — the master must be flagged but never
// restarted) and the sync-storm query (non-empty -> storm active).
func dragonflyPromServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, "master_link_status") {
			return []probetest.PromTestSample{
				{
					Labels: map[string]string{"namespace": "dragonfly", "pod": "dragonfly-replica-1"},
					Value:  0,
				},
				{
					Labels: map[string]string{"namespace": "dragonfly", "pod": "dragonfly-master-0"},
					Value:  0,
				},
			}
		}
		return []probetest.PromTestSample{{
			Labels: map[string]string{"namespace": "dragonfly", "pod": "dragonfly-replica-1"},
			Value:  4,
		}}
	})
	return srv
}

// A desynced replica with NO controller owner is never restarted —
// the delete would be PERMANENT (nothing recreates the pod) and the
// cooldown keys on that very controller. The finding still FAILs the
// check; only the heal is withheld.
func TestDragonflySyncStormSkipsUnownedPod(t *testing.T) {
	srv := dragonflyPromServer(t)
	base := time.Now()
	lone := dragonflyMemberPod("dragonfly", "dragonfly-replica-1", "replica")
	lone.OwnerReferences = nil // controller-less — the skip shape
	lone.Annotations = map[string]string{
		kube.AnnoFirstSeenDragonflyLinkStorm: `{"link/dragonfly/dragonfly-replica-1":"` +
			base.Add(-6*time.Minute).UTC().Format(time.RFC3339) + `"}`}
	cs := fake.NewSimpleClientset(lone)
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	p.Now = func() time.Time { return base }

	res := probetest.MustCheck[*dragonflyReplicaSyncStormCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("sustained link-down must still FAIL: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("dragonfly").
		Get(ctx, "dragonfly-replica-1", metav1.GetOptions{}); err != nil {
		t.Fatalf("controller-less replica must not be restarted: %v", err)
	}
}

// heal-budget — a Prometheus outage must not leave the previous sweep's
// gauge series or first-seen windows dangling: the early return
// still prunes the seen ledger and reconciles the emitted ledger
// against an empty set (a stale 1 leaks otherwise).
func TestDragonflySyncStormPromOutageCleansLedgers(t *testing.T) {
	srv := dragonflyPromServer(t)
	base := time.Now()
	replica := dragonflyMemberPod("dragonfly", "dragonfly-replica-1", "replica")
	replica.Annotations = map[string]string{
		kube.AnnoFirstSeenDragonflyLinkStorm: `{"link/dragonfly/dragonfly-replica-1":"` +
			base.Add(-6*time.Minute).UTC().Format(time.RFC3339) + `"}`}
	master := dragonflyMemberPod("dragonfly", "dragonfly-master-0", "master")
	cs := fake.NewSimpleClientset(replica, master)
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	p.Now = func() time.Time { return base }

	chk := probetest.MustCheck[*dragonflyReplicaSyncStormCheck](t, p)
	if res := chk.Run(ctx); res.Pass {
		t.Fatal("first sweep must flag the storm replica")
	}
	if m := probetest.FindMetric(t, "node_automation_dragonfly_replica_sync_storm",
		map[string]string{"namespace": "dragonfly", "pod": "dragonfly-replica-1"}); m == nil {
		t.Fatal("storm gauge must emit on the first sweep")
	}

	// Prometheus dies — the check goes inconclusive-but-clean.
	p.Cfg.HTTPContent.URL = "http://127.0.0.1:1"
	res := chk.Run(ctx)
	if !res.Pass {
		t.Fatalf("a dead Prometheus reads pass-with-clean-ledgers: %+v", res)
	}
	if m := probetest.FindMetric(t, "node_automation_dragonfly_replica_sync_storm",
		map[string]string{"namespace": "dragonfly", "pod": "dragonfly-replica-1"}); m != nil {
		t.Fatal("stale storm series must be deleted when the sweep cannot verify")
	}
	if keys := probetest.LedgerKeys(&chk.seen); len(keys) != 0 {
		t.Fatalf("seen ledger must prune clean on the outage: %v", keys)
	}
}

// isDragonflyPod pure pins: each of the three well-known label paths
// qualifies, a dragonfly substring in any label value qualifies, and
// unrelated labels do not.
func TestIsDragonflyPodPredicate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		labels map[string]string
		want   bool
	}{
		{"app.kubernetes.io/name", map[string]string{"app.kubernetes.io/name": "dragonfly"}, true},
		{"part-of", map[string]string{"app.kubernetes.io/part-of": "dragonfly"}, true},
		{"created-by", map[string]string{"app.kubernetes.io/created-by": "dragonfly-operator"}, true},
		{"substring value", map[string]string{"app": "dragonfly-df-0"}, true},
		{"unrelated", map[string]string{"app": "redis-standalone"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
				Namespace: "db", Name: "df-0", Labels: tc.labels}}
			if got := isDragonflyPod(pod); got != tc.want {
				t.Fatalf("isDragonflyPod = %v, want %v", got, tc.want)
			}
		})
	}
}
