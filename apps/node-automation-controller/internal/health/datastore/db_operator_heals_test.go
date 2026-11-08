// db_operator_heals_test.go — end-to-end coverage for the W4
// generic db-operator heal (healDBOperator): the per-operator
// helpers are unit-tested in stateful_masterless_services_test.go
// but no fixture ever drove the heal itself — a masterless STS
// owned by a known db operator past the 5m streak must bounce the
// operator's oldest Running pod (across BOTH Deployment-name
// spellings the Percona operators answer to), honor the 30m
// per-operator cooldown, and defer quietly when no operator pod
// exists.
package datastore

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
)

// dbOpSTS builds a ready StatefulSet labeled as owned by the named
// db operator — the app.kubernetes.io/managed-by value is the
// label dbOperatorFor matches on (any label value containing the
// operator name attributes it).
func dbOpSTS(ns, name, operator string, ready int32) *appsv1.StatefulSet {
	return shSTS(ns, name, ready, map[string]string{
		"app": name, "app.kubernetes.io/managed-by": operator})
}

// dbOpPod builds a Running operator pod in ns — the name must carry
// "<prefix>-" for heal.OldestRunningPod's trailing-dash prefix match.
func dbOpPod(ns, name string, created time.Time) *corev1.Pod {
	pod := probetest.ReadyPodWithIP(ns, name, "10.0.0.21", nil)
	pod.CreationTimestamp = metav1.NewTime(created)
	pod.UID = types.UID("uid-" + name)
	return pod
}

// A pxc-operator-owned STS masterless past the heal window bounces
// the operator's oldest Running pod — the Deployment it was created
// from spelled the short chart alias.
func TestDBOperatorHealBouncesOperatorPod(t *testing.T) {
	testutil.CleanupMetric(t, statefulServiceZeroEndpointsGauge, "db", "pxc-master", "pxc-cluster")
	base := time.Now()
	sts := dbOpSTS("db", "pxc-cluster", "pxc-operator", 3)
	svc := shMasterSvc("db", "pxc-master",
		map[string]string{"app": "pxc-cluster", "role": "master"})
	opPod := dbOpPod("pxc-operator", "pxc-operator-7d9f4d5b8c-x1", base.Add(-time.Hour))
	cs := fake.NewSimpleClientset(sts, svc, opPod)
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	probetest.MustCheck[*statefulMasterlessCheck](t, p).stsZeroSince.
		Observe("db/pxc-master/pxc-cluster", base.Add(-12*time.Minute))

	if res := probetest.MustCheck[*statefulMasterlessCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("masterless pxc STS must FAIL")
	}
	if _, err := cs.CoreV1().Pods("pxc-operator").
		Get(ctx, opPod.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("db operator pod must be deleted, err=%v", err)
	}
}

// W10-FIX4: the STS attributes itself to the LONG Deployment name
// (percona-xtradb-cluster-operator) while its pods still run under
// the short chart alias (pxc-operator-*) — a heal keyed on the
// matched spelling alone would find no pod. The alias group must
// cover both directions.
func TestDBOperatorHealFindsAliasedPodNames(t *testing.T) {
	testutil.CleanupMetric(t, statefulServiceZeroEndpointsGauge, "db", "pxc-master", "pxc-cluster")
	base := time.Now()
	sts := dbOpSTS("db", "pxc-cluster", "percona-xtradb-cluster-operator", 3)
	svc := shMasterSvc("db", "pxc-master",
		map[string]string{"app": "pxc-cluster", "role": "master"})
	aliased := dbOpPod("everest", "pxc-operator-6f8bc5d7c9-y2", base.Add(-2*time.Hour))
	decoy := dbOpPod("everest", "mariadb-operator-5d4c3b2a-z3", base.Add(-3*time.Hour))
	cs := fake.NewSimpleClientset(sts, svc, decoy, aliased)
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	probetest.MustCheck[*statefulMasterlessCheck](t, p).stsZeroSince.
		Observe("db/pxc-master/pxc-cluster", base.Add(-12*time.Minute))

	if res := probetest.MustCheck[*statefulMasterlessCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("masterless STS must FAIL")
	}
	if _, err := cs.CoreV1().Pods("everest").
		Get(ctx, aliased.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("aliased operator pod must be deleted, err=%v", err)
	}
	if _, err := cs.CoreV1().Pods("everest").
		Get(ctx, decoy.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("another operator's pod must never be in blast radius")
	}
}

// The 30m per-operator cooldown suppresses a repeat bounce — the
// check still FAILs (detection is independent of remediation) but
// the replacement operator pod lives.
func TestDBOperatorHealCooldownSuppressesRepeat(t *testing.T) {
	testutil.CleanupMetric(t, statefulServiceZeroEndpointsGauge, "db", "pxc-master", "pxc-cluster")
	base := time.Now()
	sts := dbOpSTS("db", "pxc-cluster", "pxc-operator", 3)
	svc := shMasterSvc("db", "pxc-master",
		map[string]string{"app": "pxc-cluster", "role": "master"})
	replacement := dbOpPod("pxc-operator", "pxc-operator-88zz-q9", base.Add(-time.Minute))
	cs := fake.NewSimpleClientset(sts, svc, replacement)
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	ch := probetest.MustCheck[*statefulMasterlessCheck](t, p)
	ch.stsZeroSince.
		Observe("db/pxc-master/pxc-cluster", base.Add(-12*time.Minute))
	// The shared Deps heals ledger keys on the operator name — a
	// stamp 10m old sits inside the 30m cooldown.
	ch.Heals.Stamp("pxc-operator", base.Add(-10*time.Minute))

	if res := ch.Run(ctx); res.Pass {
		t.Fatal("still-masterless STS must keep FAILING")
	}
	if _, err := cs.CoreV1().Pods("pxc-operator").
		Get(ctx, replacement.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("operator pod deleted inside the 30m cooldown")
	}
}

// A masterless db-operator STS whose operator has NO Running pod
// defers the heal quietly — the gauge/FAIL still report the wedge
// (deleting nothing is the safe posture: the operator may simply
// be down, which is a different failure class than a wedged one).
func TestDBOperatorHealNoRunningPodDefers(t *testing.T) {
	testutil.CleanupMetric(t, statefulServiceZeroEndpointsGauge, "db", "pxc-master", "pxc-cluster")
	base := time.Now()
	sts := dbOpSTS("db", "pxc-cluster", "pxc-operator", 3)
	svc := shMasterSvc("db", "pxc-master",
		map[string]string{"app": "pxc-cluster", "role": "master"})
	// A Pending operator pod is not a delete target — OldestRunningPod
	// requires Phase=Running.
	pending := dbOpPod("pxc-operator", "pxc-operator-5d4c-p", base.Add(-time.Minute))
	pending.Status.Phase = corev1.PodPending
	pending.Status.Conditions = nil
	cs := fake.NewSimpleClientset(sts, svc, pending)
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	probetest.MustCheck[*statefulMasterlessCheck](t, p).stsZeroSince.
		Observe("db/pxc-master/pxc-cluster", base.Add(-12*time.Minute))

	if res := probetest.MustCheck[*statefulMasterlessCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("masterless STS must FAIL even with no heal target")
	}
	for _, a := range cs.Actions() {
		if a.GetVerb() == "delete" {
			t.Fatalf("no running operator pod must mean no delete, got %v",
				a.(ktesting.DeleteAction).GetName())
		}
	}
}
