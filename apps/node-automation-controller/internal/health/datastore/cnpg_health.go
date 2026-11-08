// cnpg_health.go — the cnpg-health sub-check of the
// postgres-wal-archive-guard check: the CloudNativePG cluster
// liveness guard (stuck failover phase, ready<instances shortfall,
// disabled continuous archiving) folded into the WAL guard's CNPG CR
// scan. Pure move out of postgres_wal_archive_guard.go — see that
// file for the check, its knobs and the WAL signatures.
package datastore

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// ---------------------------------------------------------------------------
// cnpg-health — CloudNativePG cluster health.
// ---------------------------------------------------------------------------

// cnpgStuckPhases are the CloudNativePG status.phase values that mark
// a failover/restart which never lands — normalized (lower-cased,
// spaces stripped) so the CRD's spaced spellings ("Failing over",
// "Waiting for the instances to become active") and the CamelCase
// enum names the cnpg-health incident cites ("FailingOver",
// "WaitingForInstancesToBecomeActive") all match.
var cnpgStuckPhases = map[string]bool{
	"failingover":                          true,
	"waitingforinstancestobecomeactive":    true,
	"waitingfortheinstancestobecomeactive": true,
}

// cnpgPhaseKey normalizes a status.phase for the stuck-phase lookup —
// spaces removed, lower-cased.
func cnpgPhaseKey(phase string) string {
	return strings.ToLower(strings.ReplaceAll(phase, " ", ""))
}

// checkCNPGClusterHealth is the cnpg-health CloudNativePG guard folded
// into this check's CNPG CR scan — the WAL signatures above watch the
// archiver, these three watch the cluster's failover/quorum liveness
// the archiver sits on top of:
//
//   - stuck_phase: status.phase held Failing over / Waiting for the
//     instances to become active past CNPGUnhealthyMinAge — a
//     failover that never lands. status.phaseTimestamp is the honest
//     clock when the operator stamps one; the first-seen ledger is
//     the fallback when it doesn't (and NEVER mixed with a parseable
//     timestamp — trusting the operator's own transition time beats
//     an in-RAM observation that can be older than the transition).
//   - under_replicated: status.readyInstances short of
//     status.instances past the same window — one member down still
//     serves, a second failure loses the write quorum.
//   - archiving_disabled: the ContinuousArchiving condition False —
//     PITR silently dead while scheduled snapshots keep "succeeding".
//
// Detection-only like the rest of the file — the
// node_automation_cnpg_cluster_unhealthy gauge is the alert contract.
func (p *postgresWALArchiveGuardCheck) checkCNPGClusterHealth(
	ctx context.Context, log logr.Logger, rep *probefw.SweepReport,
	clusters []*unstructured.Unstructured, now time.Time) {

	minAge := p.Cfg.Datastore.CNPGUnhealthyMinAge
	var cnpgRep probefw.SweepReport
	live := map[string]bool{} // first-seen keys still holding this sweep
	emit := func(cr *unstructured.Unstructured, reason, detail string) {
		ns, name := cr.GetNamespace(), cr.GetName()
		cnpgRep.Flag(cnpgClusterUnhealthyGauge, ns+"/"+name+"/"+reason,
			[]string{ns, name, reason})
		rep.Find(detail)
	}

	for _, cr := range clusters {
		ns, name := cr.GetNamespace(), cr.GetName()
		key := ns + "/" + name

		// (1) wedged failover/restart phase.
		phase, _ := kube.NestedString(cr.Object, "status", "phase")
		if cnpgStuckPhases[cnpgPhaseKey(phase)] {
			lk := "phase/" + key
			live[lk] = true
			persisted := false
			if ts, ok := kube.NestedString(
				cr.Object, "status", "phaseTimestamp"); ok {
				if t, err := time.Parse(time.RFC3339, ts); err == nil {
					persisted = now.Sub(t) >= minAge
				} else {
					persisted = probefw.Persisted(
						&p.cnpgSeen, lk, now, minAge, log)
				}
			} else {
				persisted = probefw.Persisted(
					&p.cnpgSeen, lk, now, minAge, log)
			}
			if persisted {
				emit(cr, "stuck_phase", fmt.Sprintf(
					"%s/%s cnpg phase %q held >=%s",
					ns, name, phase, minAge))
			}
		}

		// (2) ready instances short of the declared count.
		instances, iok := kube.NestedNumber(cr.Object, "status", "instances")
		ready, rok := kube.NestedNumber(cr.Object, "status", "readyInstances")
		if iok && rok && ready < instances {
			lk := "replicas/" + key
			live[lk] = true
			if probefw.Persisted(&p.cnpgSeen, lk, now, minAge, log) {
				emit(cr, "under_replicated", fmt.Sprintf(
					"%s/%s cnpg ready %d/%d held >=%s",
					ns, name, ready, instances, minAge))
			}
		}

		// (3) continuous archiving switched off — PITR dead while
		// scheduled snapshots keep looking green.
		if c, ok := kube.ConditionOf(cr.Object, "ContinuousArchiving"); ok &&
			c.Status == "False" {
			emit(cr, "archiving_disabled", fmt.Sprintf(
				"%s/%s cnpg ContinuousArchiving=False", ns, name))
		}
	}

	// Resolved signatures re-arm: a phase that lands or a count that
	// catches up drops its first-seen entry so a later flap measures
	// a fresh window, and the emitted ledger prunes the series.
	p.cnpgSeen.Prune(func(k string) bool { return live[k] })
	cnpgRep.Close(&p.emittedCNPG, cnpgClusterUnhealthyGauge.DeleteLabelValues)
}
