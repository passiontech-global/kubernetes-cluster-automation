// percona_self_healing_test.go — the percona-cluster-quorum check's
// self-healing coverage, driven through the fake clientset + fake
// dynamic client (split from datastore's self_healing_test.go when
// the check moved into its own package).
package percona

import (
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
)

// ---------------------------------------------------------------------------
// percona-cluster-quorum — percona-cluster-quorum
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------

func TestCheckPerconaClusterQuorum(t *testing.T) {
	base := time.Now()
	errCluster := probetest.UnstructuredObj("pxc.percona.com/v1",
		"PerconaXtraDBCluster", "db", "pxc", 3, 3)
	_ = unstructured.SetNestedField(errCluster.Object, "error",
		"status", "state")
	paused := probetest.UnstructuredObj("psmdb.percona.com/v1",
		"PerconaServerMongoDB", "db", "mongo", 3, 3)
	_ = unstructured.SetNestedField(paused.Object, true, "spec", "pause")
	_ = unstructured.SetNestedField(paused.Object, "error",
		"status", "state")
	ready := probetest.UnstructuredObj("pgv2.percona.com/v2",
		"PerconaPGCluster", "db", "pg", 3, 3)
	_ = unstructured.SetNestedField(ready.Object, "ready",
		"status", "state")
	_ = unstructured.SetNestedField(ready.Object, int64(2),
		"status", "postgres", "ready")
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(
		errCluster, paused, ready))
	p.Now = func() time.Time { return base }

	res := probetest.MustCheck[*perconaQuorumCheck](t, p).Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatal("error-state cluster must FAIL")
	}
	if !strings.Contains(res.Why, "pxc") {
		t.Fatalf("offender must name the cluster: %q", res.Why)
	}
	if strings.Contains(res.Why, "mongo") {
		t.Fatalf("paused cluster must not be flagged: %q", res.Why)
	}
}

// ready<1 (top-level AND the nested status.postgres.ready PG shape)
// flags an unpaused cluster.
func TestCheckPerconaClusterQuorumReadyZero(t *testing.T) {
	base := time.Now()
	pxc := probetest.UnstructuredObj("pxc.percona.com/v1",
		"PerconaXtraDBCluster", "db", "pxc", 3, 3)
	_ = unstructured.SetNestedField(pxc.Object, "ready", "status", "state")
	_ = unstructured.SetNestedField(pxc.Object, int64(0), "status", "ready")
	pg := probetest.UnstructuredObj("pgv2.percona.com/v2",
		"PerconaPGCluster", "db", "pg", 3, 3)
	_ = unstructured.SetNestedField(pg.Object, "ready", "status", "state")
	_ = unstructured.SetNestedField(pg.Object, int64(0),
		"status", "postgres", "ready")
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(pxc, pg))
	p.Now = func() time.Time { return base }

	res := probetest.MustCheck[*perconaQuorumCheck](t, p).Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatal("ready<1 clusters must FAIL")
	}
	if !strings.Contains(res.Why, "pxc") || !strings.Contains(res.Why, "pg") {
		t.Fatalf("both clusters must be flagged: %q", res.Why)
	}
}

// "initializing" gets the 30m grace window: first sighting passes,
// past the window it FAILs; resolving clears the timer.
func TestCheckPerconaClusterQuorumInitializing(t *testing.T) {
	base := time.Now()
	init := probetest.UnstructuredObj("pxc.percona.com/v1",
		"PerconaXtraDBCluster", "db", "pxc", 3, 3)
	_ = unstructured.SetNestedField(init.Object, "initializing",
		"status", "state")
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(init))
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*perconaQuorumCheck](t, p).Run(probetest.SweepCtx(ctx)); !res.Pass {
		t.Fatalf("fresh initializing must pass: %+v", res)
	}
	// 31m later — still initializing → FAIL.
	p.Now = func() time.Time { return base.Add(31 * time.Minute) }
	if res := probetest.MustCheck[*perconaQuorumCheck](t, p).Run(probetest.SweepCtx(ctx)); res.Pass {
		t.Fatal("initializing >30m must FAIL")
	}
}
