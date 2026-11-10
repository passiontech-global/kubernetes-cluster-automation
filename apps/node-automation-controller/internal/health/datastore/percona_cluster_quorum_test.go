// percona_cluster_quorum_test.go — coverage for the
// percona-cluster-quorum check's percona-degraded-quorum signatures: degraded
// quorum (ready<size >=20m), the Galera wsrep Prometheus evidence
// (non-Primary / OFF / Donor-Desynced >=30m), and the
// PerconaPGCluster Patroni failover lock (vacant leader surfaces
// with Running pods, >=10m).
package datastore

import (
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// pxcCluster builds a PerconaXtraDBCluster CR with the given
// status.ready/size — a healthy state ("ready") exercises the
// percona-degraded-quorum degraded-quorum branch, which lives on the default path.
func pxcCluster(ns, name string, ready, size int64) *unstructured.Unstructured {
	return testutil.Unstructured(
		kube.GVRPerconaXtraDBCluster.GroupVersion().WithKind("PerconaXtraDBCluster"),
		ns, name,
		map[string]any{"status": map[string]any{
			"state": "ready",
			"ready": ready,
			"size":  size,
		}})
}

// pgCluster builds a PerconaPGCluster CR — the Patroni-lock branch
// only needs the object itself plus its member pods.
func pgCluster(ns, name string) *unstructured.Unstructured {
	return testutil.Unstructured(
		kube.GVRPerconaPGCluster.GroupVersion().WithKind("PerconaPGCluster"),
		ns, name,
		map[string]any{"status": map[string]any{
			"state": "ready",
			"postgres": map[string]any{
				"ready": int64(3),
				"size":  int64(3),
			},
		}})
}

// pgMember builds a Running PG member pod labeled with its cluster —
// the lock signature only counts while >=1 member pod runs.
func pgMember(ns, name, cluster string) *corev1.Pod {
	pod := probetest.PodWithPhase(ns, name, corev1.PodRunning, true, time.Hour)
	pod.Labels = map[string]string{"pgv2.percona.com/cluster": cluster}
	return pod
}

// A cluster reporting ready=2 of size=3 inside the 20m window only
// tracks first-seen; past the window the degraded gauge fires and
// the check fails.
func TestPerconaDegradedQuorumPersists(t *testing.T) {
	testutil.CleanupMetric(t, perconaClusterDegradedGauge, "PerconaXtraDBCluster", "db", "pxc-main")
	base := time.Now()
	cs := fake.NewSimpleClientset()
	p := testProberDyn(cs, probetest.OpDyn(pxcCluster("db", "pxc-main", 2, 3)))
	probetest.FreezeNow(p.Deps, base)

	if res := probetest.MustCheck[*perconaQuorumCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("first sighting inside the window must pass: %+v", res)
	}
	probetest.FreezeNow(p.Deps, base.Add(perconaDegradedMinAge+time.Minute))
	res := probetest.MustCheck[*perconaQuorumCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("degraded quorum past 20m did not fail the check")
	}
	m := probetest.FindMetric(t, "node_automation_percona_cluster_degraded",
		map[string]string{"kind": "PerconaXtraDBCluster",
			"namespace": "db", "name": "pxc-main"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("degraded gauge = %v, want 1", m)
	}
}

// A cluster back at full size is healthy — and the first-seen key is
// pruned so a later drop re-arms the whole window.
func TestPerconaFullSizePasses(t *testing.T) {
	base := time.Now()
	cs := fake.NewSimpleClientset()
	p := testProberDyn(cs, probetest.OpDyn(pxcCluster("db", "pxc-main", 3, 3)))
	probetest.FreezeNow(p.Deps, base)
	probetest.MustCheck[*perconaQuorumCheck](t, p).Run(ctx)
	probetest.FreezeNow(p.Deps, base.Add(perconaDegradedMinAge+time.Minute))
	if res := probetest.MustCheck[*perconaQuorumCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("full-size cluster must pass: %+v", res)
	}
}

// A single-member cluster (size=1) or a non-quorum size (size=2)
// never trips the degraded branch — "size" isn't a quorum statement
// below 3.
func TestPerconaSmallClusterSkipsDegraded(t *testing.T) {
	base := time.Now()
	cs := fake.NewSimpleClientset()
	p := testProberDyn(cs, probetest.OpDyn(
		pxcCluster("db", "pxc-two", 1, 2)))
	probetest.FreezeNow(p.Deps, base)
	probetest.MustCheck[*perconaQuorumCheck](t, p).Run(ctx)
	probetest.FreezeNow(p.Deps, base.Add(perconaDegradedMinAge+time.Minute))
	res := probetest.MustCheck[*perconaQuorumCheck](t, p).Run(ctx)
	// ready=1 of size=2 is degraded-by-count but below the size>=3
	// floor — and ready<1 doesn't apply (ready=1). Pass.
	if !res.Pass {
		t.Fatalf("size=2 cluster must not degrade-flag: %+v", res)
	}
}

// Prometheus wsrep evidence: a member holding Donor/Desynced for the
// whole 30m window fails the check and reports on the gauge under
// PerconaXtraDBCluster — wsrep only exists for Galera.
func TestPerconaWsrepDonorDesyncedFails(t *testing.T) {
	testutil.CleanupMetric(t, perconaClusterDegradedGauge, "PerconaXtraDBCluster", "db", "pxc-main")
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, "wsrep_local_state") {
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "db",
					"wsrep_cluster_name": "pxc-main"},
				Value: 2,
			}}
		}
		return nil
	})
	cs := fake.NewSimpleClientset()
	p := testProberDyn(cs, probetest.OpDyn(pxcCluster("db", "pxc-main", 3, 3)))
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()

	res := probetest.MustCheck[*perconaQuorumCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("Donor/Desynced member evidence must fail the check")
	}
	if !strings.Contains(res.Why, "Donor/Desynced") {
		t.Fatalf("why missing the wsrep detail: %q", res.Why)
	}
	m := probetest.FindMetric(t, "node_automation_percona_cluster_degraded",
		map[string]string{"kind": "PerconaXtraDBCluster",
			"namespace": "db", "name": "pxc-main"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("wsrep degraded gauge = %v, want 1", m)
	}
}

// Patroni failover lock: a PerconaPGCluster whose leader Lease
// EXISTS with an empty holder (leader absent) while a member pod
// still Runs — tracked first, FAIL + gauge past the 10m window.
func TestPerconaPatroniLeaderLock(t *testing.T) {
	testutil.CleanupMetric(t, perconaClusterDegradedGauge, "PerconaPGCluster", "db", "pg-main")
	base := time.Now()
	holderLease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Namespace: "db", Name: "pg-main-leader"},
		Spec:       coordinationv1.LeaseSpec{HolderIdentity: ptr.To("")},
	}
	cs := fake.NewSimpleClientset(pgMember("db", "pg-main-0", "pg-main"), holderLease)
	// No <cr>-leader Endpoints — the endpoints DCS surface is absent
	// (vacant-by-default), the Lease's empty holder is the evidence.
	p := testProberDyn(cs, probetest.OpDyn(pgCluster("db", "pg-main")))
	probetest.FreezeNow(p.Deps, base)

	if res := probetest.MustCheck[*perconaQuorumCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("first lock sighting inside the window must pass: %+v", res)
	}
	probetest.FreezeNow(p.Deps, base.Add(perconaPatroniLockMinAge+time.Minute))
	res := probetest.MustCheck[*perconaQuorumCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("patroni leader lock past 10m did not fail the check")
	}
	m := probetest.FindMetric(t, "node_automation_percona_cluster_degraded",
		map[string]string{"kind": "PerconaPGCluster",
			"namespace": "db", "name": "pg-main"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("patroni lock gauge = %v, want 1", m)
	}
}

// heal-budget — a 404 on BOTH the leader Lease and the leader Endpoints is
// absence of evidence, NOT leader loss: the CR could be mid-
// bootstrap with no DCS surface written yet. No lock, pass.
func TestPerconaPatroniBothSurfacesAbsentNoLock(t *testing.T) {
	base := time.Now()
	cs := fake.NewSimpleClientset(pgMember("db", "pg-main-0", "pg-main"))
	p := testProberDyn(cs, probetest.OpDyn(pgCluster("db", "pg-main")))
	probetest.FreezeNow(p.Deps, base)
	probetest.MustCheck[*perconaQuorumCheck](t, p).Run(ctx)
	probetest.FreezeNow(p.Deps, base.Add(perconaPatroniLockMinAge+time.Minute))
	if res := probetest.MustCheck[*perconaQuorumCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("404 on both DCS surfaces must not read as leader loss: %+v", res)
	}
}

// A held leader Lease is a live primary — no lock, pass.
func TestPerconaPatroniHeldLeasePasses(t *testing.T) {
	holder := "pg-main-0_abc123"
	renew := metav1.NewMicroTime(time.Now())
	lease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Namespace: "db", Name: "pg-main-leader"},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity: &holder,
			RenewTime:      &renew,
		},
	}
	cs := fake.NewSimpleClientset(pgMember("db", "pg-main-0", "pg-main"), lease)
	p := testProberDyn(cs, probetest.OpDyn(pgCluster("db", "pg-main")))
	if res := probetest.MustCheck[*perconaQuorumCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("a held patroni leader lease must pass: %+v", res)
	}
}

// Zero Running member pods is a different failure class — the lock
// signature needs live operand pods to mean anything.
func TestPerconaPatroniNoPodsNoLock(t *testing.T) {
	cs := fake.NewSimpleClientset() // no pods, no lease objects
	p := testProberDyn(cs, probetest.OpDyn(pgCluster("db", "pg-main")))
	base := time.Now()
	probetest.FreezeNow(p.Deps, base)
	probetest.MustCheck[*perconaQuorumCheck](t, p).Run(ctx)
	probetest.FreezeNow(p.Deps, base.Add(perconaPatroniLockMinAge+time.Minute))
	if res := probetest.MustCheck[*perconaQuorumCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("no running pods must not read as a patroni lock: %+v", res)
	}
}

// corev1EndpointsVacant — an Endpoints object routes nothing when
// every subset is address-less (notReadyAddresses still count as
// vacant: a not-ready backend serves no traffic).
func TestCorev1EndpointsVacant(t *testing.T) {
	ready := corev1.Endpoints{Subsets: []corev1.EndpointSubset{{
		Addresses: []corev1.EndpointAddress{{IP: "10.0.0.1"}},
	}}}
	notReadyOnly := corev1.Endpoints{Subsets: []corev1.EndpointSubset{{
		NotReadyAddresses: []corev1.EndpointAddress{{IP: "10.0.0.2"}},
	}}}
	mixed := corev1.Endpoints{Subsets: []corev1.EndpointSubset{
		{NotReadyAddresses: []corev1.EndpointAddress{{IP: "10.0.0.2"}}},
		{Addresses: []corev1.EndpointAddress{{IP: "10.0.0.1"}}},
	}}
	for _, tc := range []struct {
		name string
		ep   *corev1.Endpoints
		want bool
	}{
		{"no subsets", &corev1.Endpoints{}, true},
		{"empty subsets", &corev1.Endpoints{Subsets: []corev1.EndpointSubset{{}}}, true},
		{"routable address", &ready, false},
		{"not-ready only", &notReadyOnly, true},
		{"one routable among subsets", &mixed, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := corev1EndpointsVacant(tc.ep); got != tc.want {
				t.Fatalf("corev1EndpointsVacant = %v, want %v", got, tc.want)
			}
		})
	}
}

// patroniLeaderVacant is the Patroni failover-lock predicate: BOTH
// DCS surfaces (the <cr>-leader Lease and Endpoints) must exist-or-
// default-vacant with at least one actually seen, and both vacant —
// a held holder or a routing endpoints object is a live primary. A
// declared pgbouncer proxy adds the pooler path: empty pooler
// Endpoints means clients have no route even if a primary exists.
func TestPatroniLeaderVacant(t *testing.T) {
	lease := func(holder *string) *coordinationv1.Lease {
		return &coordinationv1.Lease{
			ObjectMeta: metav1.ObjectMeta{Namespace: "db", Name: "pg-main-leader"},
			Spec:       coordinationv1.LeaseSpec{HolderIdentity: holder},
		}
	}
	ep := func(name string, addrs ...string) *corev1.Endpoints {
		e := &corev1.Endpoints{
			ObjectMeta: metav1.ObjectMeta{Namespace: "db", Name: name}}
		if len(addrs) > 0 {
			sub := corev1.EndpointSubset{}
			for _, a := range addrs {
				sub.Addresses = append(sub.Addresses,
					corev1.EndpointAddress{IP: a})
			}
			e.Subsets = []corev1.EndpointSubset{sub}
		}
		return e
	}
	cr := func(pgBouncer bool) *unstructured.Unstructured {
		c := pgCluster("db", "pg-main")
		if pgBouncer {
			_ = unstructured.SetNestedField(c.Object, true,
				"spec", "proxy", "pgBouncer", "expose")
		}
		return c
	}
	check := func(objs ...runtime.Object) *perconaQuorumCheck {
		return &perconaQuorumCheck{Deps: &probefw.Deps{
			CS: fake.NewSimpleClientset(objs...)}}
	}
	cases := []struct {
		name string
		objs []runtime.Object
		cr   *unstructured.Unstructured
		want bool
	}{
		{"held lease is a live primary",
			[]runtime.Object{lease(ptr.To("pg-main-0")), ep("pg-main-leader")},
			cr(false), false},
		{"vacant lease + vacant endpoints",
			[]runtime.Object{lease(ptr.To("")), ep("pg-main-leader")},
			cr(false), true},
		{"lease absent, endpoints vacant",
			[]runtime.Object{ep("pg-main-leader")},
			cr(false), true},
		{"both surfaces absent is not evidence",
			nil, cr(false), false},
		{"vacant lease but endpoints route an address",
			[]runtime.Object{lease(ptr.To("")),
				ep("pg-main-leader", "10.0.0.1")},
			cr(false), false},
		{"pgbouncer declared, pooler endpoints vacant",
			[]runtime.Object{ep("pg-main-pgbouncer")},
			cr(true), true},
		{"pgbouncer declared, pooler endpoints absent",
			nil, cr(true), true},
		{"pgbouncer declared, pooler routes an address",
			[]runtime.Object{ep("pg-main-pgbouncer", "10.0.0.9")},
			cr(true), false},
		{"no pgbouncer — pooler never consulted",
			[]runtime.Object{ep("pg-main-pgbouncer", "10.0.0.9")},
			cr(false), false},
	}
	for _, tc := range cases {
		if got := check(tc.objs...).patroniLeaderVacant(ctx, logr.Discard(), tc.cr); got != tc.want {
			t.Errorf("%s: patroniLeaderVacant=%v, want %v", tc.name, got, tc.want)
		}
	}
}
