// operator_stuck_signatures_test.go — coverage for the Percona
// deliberate-park brakes on the stale-generation signature
// (perconaUnpausedStaleGen): spec.pause=true and psmdb's
// spec.mode=paused both park reconciliation deliberately, so a
// paused cluster whose observedGeneration lags is parked work, not
// a stuck operator — the generic signature would flag every
// deliberately-paused cluster forever (the same false-positive
// class as the flux suspend and HelmRepository type=oci carve-outs
// the sibling predicates carry).
package watchdogs

import (
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// shPercona builds a Percona cluster CR carrying a generation and an
// optional status.observedGeneration (og=0 leaves it absent), plus
// the spec.pause / spec.mode brakes the predicate reads. kind picks
// the apiVersion/kind pair the three Percona watchdog rows watch.
func shPercona(name string, gen, og int64, pause bool, mode string) *unstructured.Unstructured {
	o := probetest.UnstructuredObj("pxc.percona.com/v1", "PerconaXtraDBCluster",
		"db", name, gen, og)
	if pause {
		_ = unstructured.SetNestedField(o.Object, true, "spec", "pause")
	}
	if mode != "" {
		_ = unstructured.SetNestedField(o.Object, mode, "spec", "mode")
	}
	return o
}

// The pause brakes and the underlying stale-generation verdict:
// paused objects are never stuck, unpaused stale ones always are,
// and a caught-up generation is healthy either way.
func TestPerconaUnpausedStaleGen(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cluster *unstructured.Unstructured
		stuck   bool
	}{
		// THE carve-out: a stale generation on a paused cluster is
		// the deliberate-park steady state — pxc's spec.pause brake.
		{"paused cluster with a stale generation is not stuck",
			shPercona("pxc", 5, 3, true, ""), false},
		{"paused cluster with no status is not stuck",
			shPercona("pxc", 1, 0, true, ""), false},
		// psmdb parks via spec.mode=paused instead of spec.pause.
		{"mode=paused cluster with a stale generation is not stuck",
			shPercona("psmdb", 5, 3, false, "paused"), false},
		{"unpaused stale generation is stuck",
			shPercona("pxc", 5, 3, false, ""), true},
		{"unpaused cluster with no status is stuck",
			shPercona("pxc", 1, 0, false, ""), true},
		{"mode=running stale generation is stuck",
			shPercona("psmdb", 5, 3, false, "running"), true},
		{"unpaused caught-up generation is healthy",
			shPercona("pxc", 5, 5, false, ""), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := perconaUnpausedStaleGen(tc.cluster); got != tc.stuck {
				t.Fatalf("perconaUnpausedStaleGen = %v, want %v", got, tc.stuck)
			}
		})
	}
}

// End-to-end on the xtradb watchdog row: a renewing
// percona-xtradb-cluster-operator lease beside a stale-but-paused
// PerconaXtraDBCluster keeps the check quiet and tracks nothing —
// while the same cluster UNpaused freezes under stale_gen once it
// outlives the window (the brake is scoped, not a blanket disable
// of the perconaxtradbclusters entry).
func TestCheckOperatorWorkqueuesPausedPerconaIgnored(t *testing.T) {
	testutil.CleanupMetric(t, operatorWorkqueueFrozenGauge, "percona-xtradb-cluster-operator", kcmReasonStaleGen)
	base := time.Now()
	cs := fake.NewSimpleClientset(
		shLease("everest", "percona-xtradb-cluster-operator-lock",
			"percona-xtradb-cluster-operator-aa_uid", 2*time.Second, base))
	paused := shPercona("parked", 5, 3, true, "")
	p := testProberDyn(cs, probetest.OpDyn(paused))
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*operatorWorkqueueCheck](t, p).Run(probetest.SweepCtx(ctx)); !res.Pass {
		t.Fatalf("paused PerconaXtraDBCluster must not freeze the check: %+v", res)
	}
	for _, k := range probetest.LedgerKeys(
		&probetest.MustCheck[*operatorWorkqueueCheck](t, p).opFirstSeen) {
		if k == "percona-xtradb-cluster-operator/perconaxtradbclusters/db/parked/"+kcmReasonStaleGen {
			t.Fatal("paused cluster must not be tracked")
		}
	}

	// Sanity — the row itself still works: unpaused + stale + a
	// first-seen already past the 20m window freezes the gauge.
	stale := shPercona("live", 5, 3, false, "")
	p2 := testProberDyn(cs, probetest.OpDyn(paused, stale))
	p2.Now = func() time.Time { return base }
	probetest.MustCheck[*operatorWorkqueueCheck](t, p2).opFirstSeen.
		Observe("percona-xtradb-cluster-operator/perconaxtradbclusters/db/live/"+kcmReasonStaleGen,
			base.Add(-time.Hour))
	if res := probetest.MustCheck[*operatorWorkqueueCheck](t, p2).Run(probetest.SweepCtx(ctx)); res.Pass {
		t.Fatal("unpaused stale PerconaXtraDBCluster must FAIL")
	}
	if v, _ := shOpFrozenGauge(t,
		"percona-xtradb-cluster-operator", kcmReasonStaleGen); v != 1 {
		t.Fatalf("frozen gauge = %v, want 1", v)
	}
}
