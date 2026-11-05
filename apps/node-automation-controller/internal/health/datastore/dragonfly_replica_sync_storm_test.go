// dragonfly_replica_sync_storm_test.go — coverage for the
// dragonfly-replica-sync-storm check (W10-ST4): replica restart
// (never the master) on confirmed storm, link-down alone FAILs
// without restart.
package datastore

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"net/http/httptest"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

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
	if res := mustCheck[*dragonflyReplicaSyncStormCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("first sighting inside window must pass: %+v", res)
	}
	base = base.Add(6 * time.Minute)
	res := mustCheck[*dragonflyReplicaSyncStormCheck](t, p).Run(ctx)
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
	mustCheck[*dragonflyReplicaSyncStormCheck](t, p).Run(ctx)
	base = base.Add(6 * time.Minute)
	res := mustCheck[*dragonflyReplicaSyncStormCheck](t, p).Run(ctx)
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
