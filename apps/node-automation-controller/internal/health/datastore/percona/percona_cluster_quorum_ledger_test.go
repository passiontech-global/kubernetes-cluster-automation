// percona_cluster_quorum_ledger_test.go — regression for the
// emitted-gauge ledger granularity bug: the degraded gauge declares
// (kind, namespace, name) but the ledger keyed per signature
// ("degraded/…", "wsrep/…/<detail>", "patroni/…"), so one signature
// resolving pruned the cluster's series even while a sibling
// signature still fired.
package percona

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
)

// A cluster flagged by BOTH the degraded-quorum branch and wsrep
// Prometheus evidence emits one (PerconaXtraDBCluster, ns, name)
// series; when the wsrep evidence clears but the degraded quorum
// still holds, the series must survive the ledger prune.
func TestPerconaDegradedGaugeSurvivesPartialSignatureRecovery(t *testing.T) {
	testutil.CleanupMetric(t, perconaClusterDegradedGauge, "PerconaXtraDBCluster", "db", "pxc-main")
	base := time.Now()

	// wsrep evidence starts ABSENT: it emits on first sight (no
	// persistence window), so the in-window run only passes with the
	// Prometheus side clean.
	wsrepOn := false
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if wsrepOn && strings.Contains(query, "wsrep_cluster_status") {
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "db",
					"wsrep_cluster_name": "pxc-main"},
				Value: 0,
			}}
		}
		return nil
	})
	cs := fake.NewSimpleClientset()
	p := testProberDyn(cs, probetest.OpDyn(pxcCluster("db", "pxc-main", 2, 3)))
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	chk := probetest.MustCheck[*perconaQuorumCheck](t, p)

	probetest.FreezeNow(p.Deps, base)
	if res := chk.Run(ctx); !res.Pass {
		t.Fatalf("first sighting inside the window must pass: %+v", res)
	}
	probetest.FreezeNow(p.Deps, base.Add(perconaDegradedMinAge+time.Minute))
	wsrepOn = true // both signatures now fire on the same tuple
	if res := chk.Run(ctx); res.Pass {
		t.Fatal("degraded quorum + wsrep evidence must fail past the window")
	}
	m := probetest.FindMetric(t, "node_automation_percona_cluster_degraded",
		map[string]string{"kind": "PerconaXtraDBCluster",
			"namespace": "db", "name": "pxc-main"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("degraded gauge = %v, want 1", m)
	}

	// The wsrep evidence clears but the degraded quorum still holds:
	// the cluster's series must NOT be pruned with the resolved
	// signature's ledger entry.
	wsrepOn = false
	if res := chk.Run(ctx); res.Pass {
		t.Fatal("still-degraded quorum must keep failing")
	}
	m = probetest.FindMetric(t, "node_automation_percona_cluster_degraded",
		map[string]string{"kind": "PerconaXtraDBCluster",
			"namespace": "db", "name": "pxc-main"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("degraded gauge = %v after wsrep cleared, want 1 "+
			"(ledger pruned the still-firing signature's series)", m)
	}
}
