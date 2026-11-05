// dragonfly_replica_sync_storm_test.go — coverage for the
// dragonfly-replica-sync-storm check (W10-ST4): replica restart
// (never the master) on confirmed storm, link-down alone FAILs
// without restart.
package clusterhealthprobes

import (
	"strings"
	"testing"
	"time"

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
	p.cfg.httpURL = srv.URL
	p.httpClient = srv.Client()
	base := time.Now()
	p.now = func() time.Time { return base }

	// First sweep stamps the link-down first-seen; second (past the
	// 5m persistence window) confirms the storm.
	if res := p.checkDragonflyReplicaSyncStorm(ctx); !res.pass {
		t.Fatalf("first sighting inside window must pass: %+v", res)
	}
	base = base.Add(6 * time.Minute)
	res := p.checkDragonflyReplicaSyncStorm(ctx)
	if res.pass {
		t.Fatalf("sustained link-down + sync storm must fail: %+v", res)
	}
	if !strings.Contains(res.why, "dragonfly-replica-1") {
		t.Fatalf("why missing replica: %q", res.why)
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
	srv, _ := promTestServer(t, func(query string) []promTestSample {
		if strings.Contains(query, "master_link_status") {
			return []promTestSample{{
				labels: map[string]string{"namespace": "dragonfly", "pod": "dragonfly-replica-9"},
				value:  0,
			}}
		}
		return nil
	})
	replica := dragonflyMemberPod("dragonfly", "dragonfly-replica-9", "replica")
	cs := fake.NewSimpleClientset(replica)
	p := testProber(cs)
	p.cfg.httpURL = srv.URL
	p.httpClient = srv.Client()
	base := time.Now()
	p.now = func() time.Time { return base }
	p.checkDragonflyReplicaSyncStorm(ctx)
	base = base.Add(6 * time.Minute)
	res := p.checkDragonflyReplicaSyncStorm(ctx)
	if res.pass {
		t.Fatalf("sustained link-down must still fail: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("dragonfly").Get(ctx, "dragonfly-replica-9", metav1.GetOptions{}); err != nil {
		t.Fatalf("unconfirmed storm must not restart the replica: %v", err)
	}
}
