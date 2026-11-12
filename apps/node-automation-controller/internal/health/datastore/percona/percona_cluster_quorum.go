// percona_cluster_quorum.go — the percona-cluster-quorum percona-cluster-quorum
// watchdog (stuck-initializing Percona clusters) plus the percona-degraded-quorum
// degraded-quorum / Patroni-lock gauge.
package percona

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

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// perconaQuorumCheck is the percona-cluster-quorum Percona cluster quorum watchdog.
type perconaQuorumCheck struct {
	*probefw.Deps

	//   - perconaInitSeen: "gvr/ns/name" → first sweep the Percona
	//     cluster read "initializing" — the 30m stuck-initializing
	//     window for checkPerconaClusterQuorum (percona-cluster-quorum). Pruned on
	//     resolve so a later re-init re-arms.
	//   - perconaDegradedSeen: "degraded/gvr/ns/name" |
	//     "patroni/ns/name" → first sweep the percona-degraded-quorum degraded-quorum
	//     (ready<size) or Patroni-lock signature showed — each must
	//     hold its own window before it counts.
	//   - perconaDegradedEmitted: the emitted-gauge ledger for the
	//     percona_cluster_degraded tuples — a cluster that recovers
	//     loses its series via DeleteLabelValues, not a stale 1.
	perconaInitSeen        state.FirstSeenLedger
	perconaDegradedSeen    state.FirstSeenLedger
	perconaDegradedEmitted state.GaugeLedger[string]
	// wsrepLast maps each wsrep-sourced emitted ledger key
	// ("PerconaXtraDBCluster/ns/name") to its finding detail — the
	// carry source for a Prometheus flap: the three wsrep queries
	// share the one gauge kind, so a failed query cannot tell which
	// live tuples it owned; wsrepLast remembers exactly the tuples
	// the wsrep section emitted or carried last sweep.
	wsrepLast map[string]string
}

// newPerconaQuorumCheck builds the percona-cluster-quorum check — the first-seen
// ledger arms lazily on first use.
func NewPerconaQuorumCheck(d *probefw.Deps) probefw.Check {
	return &perconaQuorumCheck{Deps: d}
}

// ---------------------------------------------------------------------------
// percona-cluster-quorum — percona-cluster-quorum.
// ---------------------------------------------------------------------------

const (
	// CheckNamePerconaQuorum is the check's kuberhealthy_check
	// label value — percona-cluster-quorum; not a ported HealthCheck but reports
	// under its own check name so the generic FAIL alerting path
	// covers it.
	CheckNamePerconaQuorum = "percona-cluster-quorum"
	// perconaInitMinAge bounds how long a Percona cluster may sit in
	// "initializing" before the quorum check calls it stuck — fresh
	// clusters legitimately take tens of minutes to bootstrap.
	perconaInitMinAge = 30 * time.Minute

	// percona-degraded-quorum — perconaDegradedMinAge bounds a degraded quorum
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

// perconaClusterDegradedGauge is the percona-degraded-quorum signal: 1 while a
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
// paused (percona-cluster-quorum). percona-degraded-quorum adds the signatures a CR status hides:
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
	// failedGVRs tracks CRDs whose LIST errored this sweep — their
	// clusters' first-seen windows and gauge series must survive the
	// transient failure instead of pruning as "resolved".
	failedGVRs := map[schema.GroupVersionResource]bool{}
	for _, gvr := range perconaClusterGVRs {
		list, err := p.AllUnstructured(ctx, gvr)
		if err != nil {
			if apierrors.IsNotFound(err) || meta.IsNoMatchError(err) {
				continue // operator/CRD not installed on this cluster
			}
			rep.InfraErr(fmt.Errorf("list %s: %w", gvr.Resource, err))
			failedGVRs[gvr] = true
			continue
		}
		for i := range list {
			o := &list[i]
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
				// clusters (percona-cluster-quorum review).
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
				// percona-degraded-quorum — degraded quorum: at least one member
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
						// The emitted ledger keys one entry per
						// LABEL TUPLE (kind/ns/name) — the gauge
						// declares no signature label, so a
						// signature-qualified key would make
						// Reconcile delete the cluster's still-
						// firing series when any sibling signature
						// (wsrep, patroni) resolved first.
						rep.Emit(perconaClusterDegradedGauge,
							perconaGVRKind[gvr]+"/"+
								o.GetNamespace()+"/"+o.GetName(),
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

	// percona-degraded-quorum (b) — Patroni failover lock: a PerconaPGCluster whose
	// leader surfaces stay vacant while member pods still run.
	p.checkPatroniLeaderLock(ctx, log, &rep, pgClusters, degradedLive, now)

	// percona-degraded-quorum (c) — Galera member state the CR status cannot see:
	// wsrep non-Primary, OFF, or a Donor/Desynced member stuck for
	// >=30m. Unresolvable endpoint skips the section; a query failure
	// is tolerated evidence loss, never a false FAIL — but the tuples
	// wsrepLast vouches for still Carry + re-Find, or one Prometheus
	// flap would prune live Galera series and drop their findings.
	carryWsrep := func(carried map[string]string) {
		for k, detail := range p.wsrepLast {
			if lv, held := p.perconaDegradedEmitted.Last()[k]; held {
				rep.Carry(k, lv)
				rep.Find(detail)
				carried[k] = detail
			}
		}
	}
	wsrepThis := map[string]string{} // fresh wsrep emits this sweep
	carriedWsrep := map[string]string{}
	wsrepOK := true
	if _, err := p.PromEndpoint(); err != nil {
		wsrepOK = false
		carryWsrep(carriedWsrep)
	} else {
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
				wsrepOK = false
				log.Info("WARN: wsrep query failed — Galera evidence incomplete",
					"error", qerr)
				carryWsrep(carriedWsrep)
				continue
			}
			for _, s := range series {
				name := s.Label("wsrep_cluster_name", "cluster", "pod", "instance")
				if name == "" {
					name = "-"
				}
				ns := s.Label("namespace")
				// Ledger key is the LABEL TUPLE, not the
				// signature — see the degraded branch above.
				key := "PerconaXtraDBCluster/" + ns + "/" + name
				detail := fmt.Sprintf("%s/%s %s", ns, name, q.detail)
				rep.Emit(perconaClusterDegradedGauge, key,
					[]string{"PerconaXtraDBCluster", ns, name}, detail)
				wsrepThis[key] = detail
			}
		}
	}
	// wsrepLast tracks what the section currently vouches for: a
	// fully clean sweep replaces it with the fresh emits; a partial
	// failure merges fresh emits with the carried survivors so the
	// next flap still knows every tuple it must preserve.
	if wsrepOK {
		p.wsrepLast = wsrepThis
	} else {
		merged := map[string]string{}
		for k, d := range wsrepThis {
			merged[k] = d
		}
		for k, d := range carriedWsrep {
			merged[k] = d
		}
		p.wsrepLast = merged
	}

	// Prune first-seen timers for signatures that resolved or whose
	// objects disappeared entirely — but NOT for objects whose GVR
	// failed to list: an unverifiable census is "can't tell", and
	// dropping their windows would re-arm the persistence clock on
	// every API flap.
	p.perconaInitSeen.Prune(func(k string) bool {
		if live[k] {
			return true
		}
		for gvr := range failedGVRs {
			if strings.HasPrefix(k, gvr.Resource+"/") {
				return true
			}
		}
		return false
	})
	p.perconaDegradedSeen.Prune(func(k string) bool {
		if degradedLive[k] {
			return true
		}
		for gvr := range failedGVRs {
			if strings.HasPrefix(k, "degraded/"+gvr.Resource+"/") {
				return true
			}
		}
		// patroni/* windows key off the PGC census — same failure.
		return failedGVRs[kube.GVRPerconaPGCluster] &&
			strings.HasPrefix(k, "patroni/")
	})

	// Carry last sweep's gauge series for kinds whose census failed —
	// Reconcile would otherwise DeleteLabelValues a still-firing
	// alert on a transient list error.
	for gvr := range failedGVRs {
		kind, ok := perconaGVRKind[gvr]
		if !ok {
			continue
		}
		for k, lv := range p.perconaDegradedEmitted.Last() {
			if len(lv) > 0 && lv[0] == kind {
				rep.Carry(k, lv)
			}
		}
	}

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
// the main loop for the percona-degraded-quorum failover-lock signature: Patroni
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
			// Can't tell — the pod census failed so the lock verdict
			// is unverifiable, not resolved: keep the patroni
			// first-seen stamp and carry any emitted tuple, or one
			// LIST flap would prune a live series and re-arm the
			// 10m window.
			degradedLive["patroni/"+ns+"/"+name] = true
			gkey := "PerconaPGCluster/" + ns + "/" + name
			if lv, held := p.perconaDegradedEmitted.Last()[gkey]; held {
				rep.Carry(gkey, lv)
				rep.Find(fmt.Sprintf("%s/%s patroni leader lock >=%s "+
					"(carried — pod census failed)",
					ns, name, perconaPatroniLockMinAge))
			}
			continue
		}
		if running == 0 {
			continue
		}
		vacant, inconclusive := p.patroniLeaderVacant(ctx, log, rep, cr)
		switch {
		case inconclusive:
			// Can't tell — a Lease/Endpoints read failed, so the
			// lock verdict is unverifiable, not vacant: keep the
			// patroni first-seen stamp and carry any emitted tuple,
			// or one API flap would BOTH read as "leader vacant"
			// evidence AND prune a live series / re-arm the 10m
			// window (the same contract the pod-census failure
			// above follows).
			degradedLive["patroni/"+ns+"/"+name] = true
			gkey := "PerconaPGCluster/" + ns + "/" + name
			if lv, held := p.perconaDegradedEmitted.Last()[gkey]; held {
				rep.Carry(gkey, lv)
				rep.Find(fmt.Sprintf("%s/%s patroni leader lock >=%s "+
					"(carried — patroni surface read failed)",
					ns, name, perconaPatroniLockMinAge))
			}
		case !vacant:
			continue
		default:
			pkey := "patroni/" + ns + "/" + name
			degradedLive[pkey] = true
			if probefw.Persisted(&p.perconaDegradedSeen, pkey, now,
				perconaPatroniLockMinAge, log) {
				// Ledger key is the LABEL TUPLE — see the degraded
				// branch in Run.
				rep.Emit(perconaClusterDegradedGauge,
					"PerconaPGCluster/"+ns+"/"+name,
					[]string{"PerconaPGCluster", ns, name},
					fmt.Sprintf("%s/%s patroni leader lock >=%s",
						ns, name, perconaPatroniLockMinAge))
			}
		}
	}
}

// perconaPGRunningPods counts the Running, non-terminating member
// pods of a PerconaPGCluster — the operator labels them
// pgv2.percona.com/cluster=<name>.
func (p *perconaQuorumCheck) perconaPGRunningPods(ctx context.Context,
	ns, cluster string) (int, error) {

	pods, err := p.PodsMatching(ctx, ns, "pgv2.percona.com/cluster="+cluster)
	if err != nil {
		return 0, fmt.Errorf("list pg pods in %s: %w", ns, err)
	}
	running := 0
	for i := range pods {
		if pods[i].Status.Phase == corev1.PodRunning &&
			pods[i].DeletionTimestamp == nil {
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
// path even if it exists). A 404 is absence of evidence, not
// vacancy; a non-NotFound read error is "can't tell" — reported as
// inconclusive=true so the caller carries the last verdict instead
// of letting an API flap fence a healthy failover (the old shape
// read a failed Lease GET as leaseVacant=false only for the BOTH-
// vacant branch, while a vacant pgbouncer Endpoints could still
// return vacant=true off the failed read).
func (p *perconaQuorumCheck) patroniLeaderVacant(ctx context.Context,
	log logr.Logger, rep *probefw.SweepReport,
	cr *unstructured.Unstructured) (vacant, inconclusive bool) {

	ns, name := cr.GetNamespace(), cr.GetName()

	// DCS surface A: the <cr>-leader Lease. seen=true ONLY when the
	// object actually exists — a 404 means the surface is absent
	// (or the CRD mode never writes it), which is absence of
	// evidence, NOT evidence the leader is gone (heal-budget: a 404 on BOTH
	// the Lease and the Endpoints must never read as leader loss —
	// the whole cluster CR could be mid-bootstrap). Vacancy defaults
	// true: a surface that does not exist cannot hold a lock.
	leaseVacant, leaseSeen := true, false
	lease, err := p.Lease(ctx, ns, name+"-leader")
	if err != nil {
		log.Info("WARN: patroni leader lease fetch failed — lock verdict inconclusive",
			"lease", ns+"/"+name+"-leader", "error", err)
		rep.InfraErr(fmt.Errorf("get patroni leader lease %s/%s: %w",
			ns, name+"-leader", err))
		return false, true
	} else if lease != nil {
		leaseSeen = true
		leaseVacant = lease.Spec.HolderIdentity == nil ||
			*lease.Spec.HolderIdentity == ""
	}
	// lease == nil is the absent case — stays unseen, vacancy stays
	// default-true, same as the old IsNotFound branch.

	// DCS surface B: the <cr>-leader Endpoints (endpoints DCS mode) —
	// same seen/vacant contract as the Lease.
	epVacant, epSeen := true, false
	ep, err := p.CS.CoreV1().Endpoints(ns).Get(ctx,
		name+"-leader", metav1.GetOptions{})
	switch {
	case err == nil:
		epSeen = true
		epVacant = corev1EndpointsVacant(ep)
	case apierrors.IsNotFound(err):
	default:
		log.Info("WARN: patroni leader endpoints fetch failed — lock verdict inconclusive",
			"endpoints", ns+"/"+name+"-leader", "error", err)
		rep.InfraErr(fmt.Errorf("get patroni leader endpoints %s/%s: %w",
			ns, name+"-leader", err))
		return false, true
	}

	// At least one surface must ACTUALLY exist (seen), and both must
	// be vacant, before the absence of a primary holder is evidence.
	if (leaseSeen || epSeen) && leaseVacant && epVacant {
		return true, false // no primary holder in either DCS mode
	}

	// Pooler path: when the CR deploys pgbouncer, an empty pooler
	// Endpoints leaves clients with no route to whatever primary
	// Patroni believes exists.
	if _, ok := kube.NestedMap(cr.Object,
		"spec", "proxy", "pgBouncer"); !ok {
		return false, false
	}
	pooler, err := p.CS.CoreV1().Endpoints(ns).Get(ctx,
		name+"-pgbouncer", metav1.GetOptions{})
	switch {
	case err == nil:
		return corev1EndpointsVacant(pooler), false
	case apierrors.IsNotFound(err):
		return true, false
	default:
		log.Info("WARN: pgbouncer endpoints fetch failed — lock verdict inconclusive",
			"endpoints", ns+"/"+name+"-pgbouncer", "error", err)
		rep.InfraErr(fmt.Errorf("get patroni pgbouncer endpoints %s/%s: %w",
			ns, name+"-pgbouncer", err))
		return false, true
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
