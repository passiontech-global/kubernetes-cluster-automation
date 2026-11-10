// cnpg_health.go — the cnpg-health sub-check of the
// postgres-wal-archive-guard check: the CloudNativePG cluster
// liveness guard (stuck failover phase, ready<instances shortfall,
// disabled continuous archiving) folded into the WAL guard's CNPG CR
// scan. Pure move out of postgres_wal_archive_guard.go — see that
// file for the check, its knobs and the WAL signatures.
package datastore

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
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
//   - primary_mismatch (W19-ST1): with status.instances > 0, an
//     empty status.currentPrimary (no elected primary) or a
//     current/target disagreement — a switchover that never lands
//     or a split-brain the operator is still reconciling.
//   - fenced_instances (W19-ST1): the cnpg.io/fencedInstances
//     annotation non-empty — instances the operator fenced after
//     losing contact. Detection persists minAge via the
//     first-seen ledger; the heal half below auto-unfences an
//     instance whose pod verifiably sits on a healthy node.
//
// Detection-only like the rest of the file — the
// node_automation_cnpg_cluster_unhealthy gauge is the alert contract;
// the ONLY write is the fenced-instance annotation unfence below,
// gated on the shared heal preamble.
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
			// Same minAge gate as the sibling branches: the
			// condition can flap during a backup-window restart, and
			// an unpersisted emit pins a stale gauge forever.
			lk := "arch/" + key
			live[lk] = true
			if probefw.Persisted(&p.cnpgSeen, lk, now, minAge, log) {
				emit(cr, "archiving_disabled", fmt.Sprintf(
					"%s/%s cnpg ContinuousArchiving=False held >=%s",
					ns, name, minAge))
			}
		}

		// (4) W19-ST1 primary_mismatch: with instances declared, an
		// empty currentPrimary (no elected primary — read-only or
		// stuck init) or a current/target disagreement (a switchover
		// that never lands, split-brain still reconciling) held past
		// the window. A zero-instance cluster is still bootstrapping
		// — exempt.
		curPrimary, _ := kube.NestedString(cr.Object, "status", "currentPrimary")
		tgtPrimary, _ := kube.NestedString(cr.Object, "status", "targetPrimary")
		primaryBad := iok && instances > 0 &&
			(curPrimary == "" ||
				(tgtPrimary != "" && curPrimary != tgtPrimary))
		if primaryBad {
			lk := "primary/" + key
			live[lk] = true
			if probefw.Persisted(&p.cnpgSeen, lk, now, minAge, log) {
				emit(cr, "primary_mismatch", fmt.Sprintf(
					"%s/%s cnpg currentPrimary=%q targetPrimary=%q held >=%s",
					ns, name, curPrimary, tgtPrimary, minAge))
			}
		}
	}

	// (5) W19-ST1 fenced_instances: detect + safe auto-unfence. The
	// pod/node census is fetched lazily — only when at least one
	// cluster carries the annotation.
	p.checkCNPGFencedInstances(ctx, log, clusters, now, minAge,
		emit, live)

	// Resolved signatures re-arm: a phase that lands or a count that
	// catches up drops its first-seen entry so a later flap measures
	// a fresh window, and the emitted ledger prunes the series.
	p.cnpgSeen.Prune(func(k string) bool { return live[k] })
	cnpgRep.Close(&p.emittedCNPG, cnpgClusterUnhealthyGauge.DeleteLabelValues)
}

// ---------------------------------------------------------------------------
// cnpg fenced_instances — detect + safe auto-unfence (W19-ST1)
// ---------------------------------------------------------------------------

// cnpgFencedInstancesAnno is the CNPG operator's fenced-instance
// list — comma-separated instance names ("*" fences the whole
// cluster) the operator wrote after losing contact with them.
const cnpgFencedInstancesAnno = "cnpg.io/fencedInstances"

// cnpgUnfenceCooldown bounds auto-unfence churn per cluster+instance
// — an unfenced instance that re-fences immediately must not flap
// the annotation every sweep.
const cnpgUnfenceCooldown = 30 * time.Minute

// checkCNPGFencedInstances detects the fenced_instances signature
// (annotation non-empty past minAge) and runs the safe auto-unfence:
// an instance whose pod verifiably sits on a Ready, schedulable node
// carrying NO remediation/out-of-service taint is a fence the
// operator never needed — the instance is alive and reachable, the
// fence is stale. Removing it from the annotation lets the instance
// rejoin; "*" (whole-cluster fence) is never auto-cleared.
func (p *postgresWALArchiveGuardCheck) checkCNPGFencedInstances(
	ctx context.Context, log logr.Logger,
	clusters []*unstructured.Unstructured, now time.Time,
	minAge time.Duration,
	emit func(cr *unstructured.Unstructured, reason, detail string),
	live map[string]bool) {

	// Cheap pass first: any cluster carrying the annotation at all?
	var fenced []*unstructured.Unstructured
	for _, cr := range clusters {
		if instances := cnpgFencedInstanceList(cr); len(instances) > 0 {
			fenced = append(fenced, cr)
		}
	}
	if len(fenced) == 0 {
		// No fences anywhere — every first-seen entry is stale;
		// clear the ledger so a later re-fence measures fresh.
		p.cnpgFenceSeen.Prune(func(string) bool { return false })
		return
	}

	// The pod/node census is fetched once per sweep and only when a
	// fence exists — unfence needs it, detection does not.
	pods, err := p.AllPods(ctx)
	if err != nil {
		log.Info("cnpg fenced_instances: pod census failed — detection only",
			"error", err)
		pods = nil
	}
	nodes, err := p.AllNodes(ctx)
	if err != nil {
		log.Info("cnpg fenced_instances: node census failed — detection only",
			"error", err)
		nodes = nil
	}
	nodeByName := map[string]*corev1.Node{}
	for i := range nodes {
		nodeByName[nodes[i].Name] = &nodes[i]
	}

	// canUnfence requires the dynamic client — without it the patch
	// half cannot run; detection above is unaffected.
	canUnfence := p.Dyn != nil

	// fenceLive tracks every "fence/ns/name/inst" key still present
	// in an annotation this sweep — the ledger prune below drops
	// entries whose instance left the list (unfenced, annotation
	// cleared) so a re-fence measures a fresh window.
	fenceLive := map[string]bool{}

	for _, cr := range fenced {
		ns, name := cr.GetNamespace(), cr.GetName()
		instances := cnpgFencedInstanceList(cr)

		// Detection: the signature is the annotation itself —
		// persist minAge like the other reason keys.
		lk := "fenced/" + ns + "/" + name
		live[lk] = true
		if probefw.Persisted(&p.cnpgSeen, lk, now, minAge, log) {
			emit(cr, "fenced_instances", fmt.Sprintf(
				"%s/%s cnpg fencedInstances=%s held >=%s",
				ns, name, strings.Join(instances, ","), minAge))
		}

		// Auto-unfence, per named instance ("*" is excluded inside
		// the loop). The fence must itself have persisted minAge —
		// a fence the operator stamped seconds ago may be a live
		// failover, not a stale mark. removed tracks every instance
		// already unfenced THIS sweep so a second patch cannot
		// resurrect the first removal.
		removed := map[string]bool{}
		for _, inst := range instances {
			if inst == "*" {
				continue
			}
			fk := "fence/" + ns + "/" + name + "/" + inst
			fenceLive[fk] = true
			if !probefw.Persisted(&p.cnpgFenceSeen, fk, now, minAge, log) {
				continue
			}
			if !cnpgInstanceOnHealthyNode(pods, nodeByName, ns, name, inst) ||
				!canUnfence {
				continue
			}
			key := probefw.SelfHealKey(
				CheckNamePostgresWALArchiveGuard, "cnpg-unfence/"+fk)
			proceed, unverifiable := p.HealAllowed(ctx, log,
				&p.Heals, key, cnpgUnfenceCooldown, now)
			if unverifiable {
				metrics.IncError(p.Name)
				continue
			}
			if !proceed {
				continue
			}
			if err := p.unfenceCNPGInstance(ctx, cr, inst,
				instances, removed); err != nil {
				metrics.IncError(p.Name)
				log.Error(err, "cnpg unfence patch failed",
					"cluster", ns+"/"+name, "instance", inst)
				continue
			}
			removed[inst] = true
			p.Heals.Stamp(key, now)
			log.Info("ACTION: cnpg unfence — instance pod verified on healthy node",
				"cluster", ns+"/"+name, "instance", inst)
		}
	}
	p.cnpgFenceSeen.Prune(func(k string) bool { return fenceLive[k] })
}

// cnpgFencedInstanceList parses the fencedInstances annotation into
// instance names — empty list when absent or blank.
func cnpgFencedInstanceList(cr *unstructured.Unstructured) []string {
	raw, _, _ := unstructured.NestedString(
		cr.Object, "metadata", "annotations", cnpgFencedInstancesAnno)
	var out []string
	for _, s := range strings.Split(raw, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// cnpgInstanceOnHealthyNode reports whether the fenced instance's
// pod is Running on a node that is Ready, schedulable and free of
// every remediation/out-of-service taint — the evidence that the
// fence is stale rather than protective. A missing pod or node
// census, a non-Running pod, or an unverifiable node all read false
// (fail closed — never unfence on partial evidence).
func cnpgInstanceOnHealthyNode(pods []corev1.Pod,
	nodeByName map[string]*corev1.Node, ns, cluster, inst string) bool {

	var pod *corev1.Pod
	for i := range pods {
		p := &pods[i]
		if p.Namespace != ns {
			continue
		}
		// CNPG stamps cnpg.io/instanceName on instance pods; the
		// pod name also equals the instance name in the standard
		// <cluster>-<ordinal> layout — either match counts.
		if p.Labels["cnpg.io/instanceName"] == inst || p.Name == inst ||
			(p.Labels["cnpg.io/cluster"] == cluster && p.Name == inst) {
			pod = p
			break
		}
	}
	if pod == nil || pod.Spec.NodeName == "" ||
		pod.Status.Phase != corev1.PodRunning {
		return false
	}
	node := nodeByName[pod.Spec.NodeName]
	if node == nil || node.Spec.Unschedulable {
		return false
	}
	ready := false
	for _, c := range node.Status.Conditions {
		if c.Type == corev1.NodeReady && c.Status == corev1.ConditionTrue {
			ready = true
		}
	}
	if !ready {
		return false
	}
	return !kube.HasRemediationOrOutOfServiceTaint(node)
}

// unfenceCNPGInstance removes `inst` (plus every entry in `removed`
// already unfenced this sweep) from the cluster's fencedInstances
// annotation via a merge patch — the remaining list (or key
// deletion when empty) is computed from the SAME parse the detection
// used so a second unfence in one sweep cannot resurrect the first
// removal, and concurrent annotation drift cannot resurrect a
// just-cleared instance either. The patch pins the List snapshot's
// resourceVersion (same shape stripFinalizers uses for
// VolumeAttachments) so a fence the CNPG operator added between List
// and Patch turns this into a conflict — skipped this cycle, the
// operator's protective write survives — instead of being silently
// dropped by the merge. Returns the patch error; the caller stamps
// the cooldown only on success.
func (p *postgresWALArchiveGuardCheck) unfenceCNPGInstance(
	ctx context.Context, cr *unstructured.Unstructured, inst string,
	all []string, removed map[string]bool) error {

	var next []string
	for _, s := range all {
		if s == inst || removed[s] {
			continue
		}
		next = append(next, s)
	}
	patch := map[string]any{
		"metadata": map[string]any{
			"resourceVersion": cr.GetResourceVersion(),
			"annotations": map[string]any{
				cnpgFencedInstancesAnno: nil,
			},
		},
	}
	if len(next) > 0 {
		patch["metadata"].(map[string]any)["annotations"].(map[string]any)[cnpgFencedInstancesAnno] = strings.Join(next, ",")
	}
	data, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	if _, err := p.Dyn.Resource(kube.GVRCNPGCluster).
		Namespace(cr.GetNamespace()).Patch(
		ctx, cr.GetName(), types.MergePatchType, data,
		metav1.PatchOptions{}); err != nil {
		return err
	}
	return nil
}
