// percona_patroni_leader.go — the Patroni leader-lock half of the
// percona-cluster-quorum check: the DCS lock Endpoints vacancy probe,
// the pg pod census and the leader-vacancy verdict. Split from
// percona_cluster_quorum.go (the CR-status quorum half) to keep both
// under ~500 LOC.
package percona

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

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
