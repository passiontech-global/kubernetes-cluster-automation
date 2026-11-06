// percona_cluster_quorum.go — the W10-ST5 percona-cluster-quorum
// watchdog (stuck-initializing Percona clusters) plus the W12-ST2
// degraded-quorum / Patroni-lock gauge.
package datastore

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// perconaQuorumCheck is the W10-ST5 Percona cluster quorum watchdog.
type perconaQuorumCheck struct {
	*probefw.Deps

	//   - perconaInitSeen: "gvr/ns/name" → first sweep the Percona
	//     cluster read "initializing" — the 30m stuck-initializing
	//     window for checkPerconaClusterQuorum (W10-ST5). Pruned on
	//     resolve so a later re-init re-arms.
	//   - perconaDegradedSeen: "degraded/gvr/ns/name" |
	//     "patroni/ns/name" → first sweep the W12-ST2 degraded-quorum
	//     (ready<size) or Patroni-lock signature showed — each must
	//     hold its own window before it counts.
	//   - perconaDegradedEmitted: the emitted-gauge ledger for the
	//     percona_cluster_degraded tuples — a cluster that recovers
	//     loses its series via DeleteLabelValues, not a stale 1.
	perconaInitSeen        state.FirstSeenLedger
	perconaDegradedSeen    state.FirstSeenLedger
	perconaDegradedEmitted state.GaugeLedger[string]
}

// newPerconaQuorumCheck builds the W10-ST5 check — the first-seen
// ledger arms lazily on first use.
func NewPerconaQuorumCheck(d *probefw.Deps) probefw.Check {
	return &perconaQuorumCheck{Deps: d}
}

// ---------------------------------------------------------------------------
// W10-ST5 — percona-cluster-quorum.
// ---------------------------------------------------------------------------

const (
	// CheckNamePerconaQuorum is the check's kuberhealthy_check
	// label value — W10-ST5; not a ported HealthCheck but reports
	// under its own check name so the generic FAIL alerting path
	// covers it.
	CheckNamePerconaQuorum = "percona-cluster-quorum"
	// perconaInitMinAge bounds how long a Percona cluster may sit in
	// "initializing" before the quorum check calls it stuck — fresh
	// clusters legitimately take tens of minutes to bootstrap.
	perconaInitMinAge = 30 * time.Minute

	// W12-ST2 — perconaDegradedMinAge bounds a degraded quorum
	// (status.ready < status.size while ready >= 1 and size >= 3):
	// one member down still serves, so the signature must persist
	// 20m before it counts — longer than a node blip, shorter than
	// the real quorum-loss window a second failure opens.
	perconaDegradedMinAge = 20 * time.Minute
	// perconaPatroniLockMinAge bounds a PerconaPGCluster whose
	// Patroni DCS surfaces (<cr>-leader Lease/Endpoints) and the
	// <cr>-pgbouncer pooler Endpoints stay vacant while member pods
	// keep Running — Patroni refusing to promote is a live outage,
	// but a fresh bootstrap legitimately needs minutes to elect.
	perconaPatroniLockMinAge = 10 * time.Minute
	// perconaWsrepLocalStateDonor is the Galera local-state value
	// for Donor/Desynced — a member donating an SST is out of the
	// write path for the whole donation.
	perconaWsrepLocalStateDonor = 2
)

// perconaClusterDegradedGauge is the W12-ST2 signal: 1 while a
// Percona cluster reports fewer ready instances than its declared
// size for >=20m (degraded quorum — one failure short of losing
// writes), a Galera member sits non-Primary / OFF / Donor-Desynced
// in Prometheus wsrep state, or a PerconaPGCluster's Patroni leader
// surfaces stay vacant with Running pods (failover lock).
var perconaClusterDegradedGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_percona_cluster_degraded",
	Help: "1 while a Percona cluster reports ready<size >=20m, wsrep non-Primary/OFF/Donor member evidence, or a PerconaPGCluster Patroni leader stays vacant with Running pods.",
}, []string{"kind", "namespace", "name"})

func init() {
	ctrlmetrics.Registry.MustRegister(perconaClusterDegradedGauge)
}

// perconaClusterGVRs are the three Percona operator CRDs the quorum
// check sweeps cluster-wide; a cluster without a given operator
// simply has no objects (CRD absent → the List misses quietly).
var perconaClusterGVRs = kube.PerconaClusterGVRs

// perconaGVRKind maps each swept GVR to the CR kind the degraded
// gauge's kind label reports — wsrep metrics only ever exist for
// PXC, so Prometheus-sourced findings hardcode PerconaXtraDBCluster.
var perconaGVRKind = map[schema.GroupVersionResource]string{
	kube.GVRPerconaXtraDBCluster: "PerconaXtraDBCluster",
	kube.GVRPerconaPGCluster:     "PerconaPGCluster",
	kube.GVRPerconaServerMongoDB: "PerconaServerMongoDB",
}

// checkPerconaClusterQuorum flags Percona database clusters that
// report an error state, sit in "initializing" past
// perconaInitMinAge, or show fewer than one ready instance while not
// paused (W10-ST5). W12-ST2 adds the signatures a CR status hides:
// a degraded quorum (ready < size >= 20m while >=1 member still
// serves — one blip short of losing writes), Galera member state
// from Prometheus wsrep metrics (non-Primary / OFF / Donor-Desynced
// >=30m), and the PerconaPGCluster Patroni failover lock (vacant
// leader surfaces with Running pods, >=10m). Suggested run()
// registration name: "percona-cluster-quorum".
func (p *perconaQuorumCheck) Run(ctx context.Context) probefw.Result {
	if r := p.RequireDyn("percona quorum check"); r != nil {
		return *r
	}
	log := logf.FromContext(ctx)
	now := p.Now()

	var rep probefw.SweepReport
	live := map[string]bool{}         // every scanned CR — the init ledger's prune set
	degradedLive := map[string]bool{} // signatures observed THIS sweep — the degraded ledger's
	var pgClusters []*unstructured.Unstructured
	for _, gvr := range perconaClusterGVRs {
		list, err := p.Dyn.Resource(gvr).List(ctx, metav1.ListOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) || meta.IsNoMatchError(err) {
				continue // operator/CRD not installed on this cluster
			}
			rep.InfraErr(fmt.Errorf("list %s: %w", gvr.Resource, err))
			continue
		}
		for i := range list.Items {
			o := &list.Items[i]
			key := gvr.Resource + "/" + o.GetNamespace() + "/" + o.GetName()
			live[key] = true
			if gvr == kube.GVRPerconaPGCluster {
				pgClusters = append(pgClusters, o)
			}
			if perconaClusterPaused(o) {
				p.clearPerconaInit(key)
				continue
			}
			state, _ := kube.NestedString(o.Object, "status", "state")
			statusField, _ := kube.NestedString(o.Object, "status", "status")
			switch {
			case strings.EqualFold(state, "error") ||
				strings.EqualFold(statusField, "error"):
				rep.Find(fmt.Sprintf(
					"%s/%s state=%s", o.GetNamespace(), o.GetName(),
					perconaStateLabel(state, statusField)))
				p.clearPerconaInit(key)
			case strings.EqualFold(state, "initializing") ||
				strings.EqualFold(statusField, "initializing"):
				// Initializing is checked BEFORE ready<1: a fresh
				// cluster's operator writes status.ready:0 while
				// bootstrapping — flagging it here would bypass
				// the perconaInitMinAge grace and flap new
				// clusters (W10-ST5 review).
				if probefw.Persisted(&p.perconaInitSeen, key, now,
					perconaInitMinAge, logr.Discard()) {
					rep.Find(fmt.Sprintf(
						"%s/%s initializing>%s", o.GetNamespace(),
						o.GetName(), perconaInitMinAge))
				}
			case perconaReadyBelowOne(o):
				rep.Find(fmt.Sprintf(
					"%s/%s ready<1", o.GetNamespace(), o.GetName()))
				p.clearPerconaInit(key)
			default:
				p.clearPerconaInit(key)
				// W12-ST2 — degraded quorum: at least one member
				// serving but short of the declared size for >=20m.
				// ready>=1 keeps this disjoint from the ready<1
				// branch; size>=3 keeps single/dual-member clusters
				// (where "size" isn't a quorum statement) out of it.
				if ready, size, found := perconaReadySize(o); found &&
					ready >= 1 && size >= 3 && ready < size {
					dkey := "degraded/" + key
					degradedLive[dkey] = true
					if probefw.Persisted(&p.perconaDegradedSeen, dkey,
						now, perconaDegradedMinAge, log) {
						rep.Emit(perconaClusterDegradedGauge, dkey,
							[]string{perconaGVRKind[gvr],
								o.GetNamespace(), o.GetName()},
							fmt.Sprintf("%s/%s ready %d/%d degraded >=%s",
								o.GetNamespace(), o.GetName(), ready, size,
								perconaDegradedMinAge))
					}
				}
			}
		}
	}

	// W12-ST2 (b) — Patroni failover lock: a PerconaPGCluster whose
	// leader surfaces stay vacant while member pods still run.
	p.checkPatroniLeaderLock(ctx, log, &rep, pgClusters, degradedLive, now)

	// W12-ST2 (c) — Galera member state the CR status cannot see:
	// wsrep non-Primary, OFF, or a Donor/Desynced member stuck for
	// >=30m. Unresolvable endpoint skips the section; a query failure
	// is tolerated evidence loss, never a false FAIL.
	if _, err := p.PromEndpoint(); err == nil {
		for _, q := range []struct{ query, detail string }{
			{`mysql_global_status_wsrep_cluster_status != 1`,
				"wsrep_cluster_status!=Primary"},
			{`mysql_global_status_wsrep_ready == 0`,
				"wsrep_ready=OFF"},
			{fmt.Sprintf(`min_over_time(mysql_global_status_wsrep_local_state[30m]) == %d`,
				perconaWsrepLocalStateDonor),
				"wsrep_local_state=Donor/Desynced>=30m"},
		} {
			series, qerr := p.PromQuery(ctx, q.query)
			if qerr != nil {
				log.Info("WARN: wsrep query failed — Galera evidence incomplete",
					"error", qerr)
				continue
			}
			for _, s := range series {
				name := s.Label("wsrep_cluster_name", "cluster", "pod", "instance")
				if name == "" {
					name = "-"
				}
				ns := s.Label("namespace")
				rep.Emit(perconaClusterDegradedGauge,
					"wsrep/"+ns+"/"+name+"/"+q.detail,
					[]string{"PerconaXtraDBCluster", ns, name},
					fmt.Sprintf("%s/%s %s", ns, name, q.detail))
			}
		}
	}

	// Prune first-seen timers for signatures that resolved or whose
	// objects disappeared entirely.
	p.perconaInitSeen.Prune(func(k string) bool { return live[k] })
	p.perconaDegradedSeen.Prune(func(k string) bool { return degradedLive[k] })

	return rep.Result(&p.perconaDegradedEmitted,
		perconaClusterDegradedGauge.DeleteLabelValues,
		"percona cluster quorum: ", ", ")
}

// perconaReadySize reads the ready/size pair across the Percona
// status shapes: top-level status.ready + status.size (PXC, PSMDB)
// or the nested status.postgres.* (PGv2 keeps readiness under the
// postgres component). Absent pairs read as "unknown" — an operator
// that never wrote a size must not false-positive the degraded
// branch.
func perconaReadySize(o *unstructured.Unstructured) (ready, size int64, found bool) {
	if r, ok := kube.NestedInt64(o.Object, "status", "ready"); ok {
		s, sok := kube.NestedInt64(o.Object, "status", "size")
		return r, s, sok
	}
	if r, ok := kube.NestedInt64(o.Object, "status", "postgres", "ready"); ok {
		s, sok := kube.NestedInt64(o.Object, "status", "postgres", "size")
		return r, s, sok
	}
	return 0, 0, false
}

// checkPatroniLeaderLock sweeps the PerconaPGCluster CRs collected in
// the main loop for the W12-ST2 failover-lock signature: Patroni
// elects its primary through the <cr>-leader Lease (or Endpoints in
// the endpoints DCS mode) — both surfaces vacant means no primary
// holds; an empty <cr>-pgbouncer pooler Endpoints means clients have
// no path to one even if it exists. The signature only counts while
// >=1 member pod is Running: zero pods is a different failure class.
func (p *perconaQuorumCheck) checkPatroniLeaderLock(ctx context.Context,
	log logr.Logger, rep *probefw.SweepReport,
	pgClusters []*unstructured.Unstructured,
	degradedLive map[string]bool, now time.Time) {

	for _, cr := range pgClusters {
		if perconaClusterPaused(cr) {
			continue
		}
		ns, name := cr.GetNamespace(), cr.GetName()
		running, err := p.perconaPGRunningPods(ctx, ns, name)
		if err != nil {
			rep.InfraErr(err)
			continue
		}
		if running == 0 {
			continue
		}
		if !p.patroniLeaderVacant(ctx, log, cr) {
			continue
		}
		pkey := "patroni/" + ns + "/" + name
		degradedLive[pkey] = true
		if probefw.Persisted(&p.perconaDegradedSeen, pkey, now,
			perconaPatroniLockMinAge, log) {
			rep.Emit(perconaClusterDegradedGauge, pkey,
				[]string{"PerconaPGCluster", ns, name},
				fmt.Sprintf("%s/%s patroni leader lock >=%s",
					ns, name, perconaPatroniLockMinAge))
		}
	}
}

// perconaPGRunningPods counts the Running, non-terminating member
// pods of a PerconaPGCluster — the operator labels them
// pgv2.percona.com/cluster=<name>.
func (p *perconaQuorumCheck) perconaPGRunningPods(ctx context.Context,
	ns, cluster string) (int, error) {

	pods, err := p.CS.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
		LabelSelector: "pgv2.percona.com/cluster=" + cluster,
		Limit:         probefw.HealthListPageSize,
	})
	if err != nil {
		return 0, fmt.Errorf("list pg pods in %s: %w", ns, err)
	}
	running := 0
	for i := range pods.Items {
		if pods.Items[i].Status.Phase == corev1.PodRunning &&
			pods.Items[i].DeletionTimestamp == nil {
			running++
		}
	}
	return running, nil
}

// patroniLeaderVacant reports whether the cluster's Patroni surfaces
// say no primary is reachable: BOTH the <cr>-leader Lease and the
// <cr>-leader Endpoints vacant (covers whichever DCS mode the CR
// runs — a surface that simply doesn't exist in the active mode is
// not evidence), or — when the CR declares a pgbouncer proxy — the
// <cr>-pgbouncer Endpoints carrying no addresses (clients have no
// path even if a primary exists). A non-NotFound read error is
// "can't tell", not a lock — it is logged and reads clean.
func (p *perconaQuorumCheck) patroniLeaderVacant(ctx context.Context,
	log logr.Logger, cr *unstructured.Unstructured) bool {

	ns, name := cr.GetNamespace(), cr.GetName()

	// DCS surface A: the <cr>-leader Lease.
	leaseVacant, leaseSeen := false, false
	lease, err := p.CS.CoordinationV1().Leases(ns).Get(ctx,
		name+"-leader", metav1.GetOptions{})
	switch {
	case err == nil:
		leaseSeen = true
		leaseVacant = lease.Spec.HolderIdentity == nil ||
			*lease.Spec.HolderIdentity == ""
	case apierrors.IsNotFound(err):
		leaseSeen, leaseVacant = true, true
	default:
		log.Info("WARN: patroni leader lease fetch failed — lock evidence inconclusive",
			"lease", ns+"/"+name+"-leader", "error", err)
	}

	// DCS surface B: the <cr>-leader Endpoints (endpoints DCS mode).
	epVacant, epSeen := false, false
	ep, err := p.CS.CoreV1().Endpoints(ns).Get(ctx,
		name+"-leader", metav1.GetOptions{})
	switch {
	case err == nil:
		epSeen = true
		epVacant = corev1EndpointsVacant(ep)
	case apierrors.IsNotFound(err):
		epSeen, epVacant = true, true
	default:
		log.Info("WARN: patroni leader endpoints fetch failed — lock evidence inconclusive",
			"endpoints", ns+"/"+name+"-leader", "error", err)
	}

	if (leaseSeen || epSeen) && leaseVacant && epVacant {
		return true // no primary holder in either DCS mode
	}

	// Pooler path: when the CR deploys pgbouncer, an empty pooler
	// Endpoints leaves clients with no route to whatever primary
	// Patroni believes exists.
	if _, ok, _ := unstructured.NestedFieldNoCopy(cr.Object,
		"spec", "proxy", "pgBouncer"); !ok {
		return false
	}
	pooler, err := p.CS.CoreV1().Endpoints(ns).Get(ctx,
		name+"-pgbouncer", metav1.GetOptions{})
	switch {
	case err == nil:
		return corev1EndpointsVacant(pooler)
	case apierrors.IsNotFound(err):
		return true
	default:
		log.Info("WARN: pgbouncer endpoints fetch failed — lock evidence inconclusive",
			"endpoints", ns+"/"+name+"-pgbouncer", "error", err)
		return false
	}
}

// corev1EndpointsVacant reports whether an Endpoints object routes
// nothing — every subset empty or all addresses not-ready.
//
//nolint:staticcheck // SA1019: the object under test IS a corev1.Endpoints — Patroni's endpoints-DCS mode writes that kind directly; EndpointSlice cannot express it.
func corev1EndpointsVacant(ep *corev1.Endpoints) bool {
	for _, sub := range ep.Subsets {
		if len(sub.Addresses) > 0 {
			return false
		}
	}
	return true
}

// perconaClusterPaused reports spec.pause==true or spec.mode=="paused"
// — a deliberately parked cluster is not a quorum failure.
func perconaClusterPaused(o *unstructured.Unstructured) bool {
	if paused, _ := kube.NestedBool(o.Object, "spec", "pause"); paused {
		return true
	}
	if mode, _ := kube.NestedString(o.Object, "spec", "mode"); mode == "paused" {
		return true
	}
	return false
}

// perconaReadyBelowOne reads the ready-instance count across the
// Percona status shapes: top-level status.ready (PXC, PSMDB) or the
// nested status.postgres.ready (PGv2 keeps readiness under the
// postgres component). Absent fields read as "unknown", not zero —
// an operator that never wrote a count must not false-positive.
func perconaReadyBelowOne(o *unstructured.Unstructured) bool {
	if ready, found := kube.NestedInt64(o.Object, "status", "ready"); found {
		return ready < 1
	}
	if ready, found := kube.NestedInt64(o.Object, "status", "postgres", "ready"); found {
		return ready < 1
	}
	return false
}

// perconaStateLabel picks the non-empty state/status string for the
// offender message.
func perconaStateLabel(state, statusField string) string {
	if state != "" {
		return state
	}
	return statusField
}

// clearPerconaInit drops a cluster's initializing timer — resolved,
// errored or otherwise no longer initializing.
func (p *perconaQuorumCheck) clearPerconaInit(key string) {
	p.perconaInitSeen.Forget(key)
}
