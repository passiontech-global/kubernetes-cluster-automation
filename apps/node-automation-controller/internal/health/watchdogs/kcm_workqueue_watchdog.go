package watchdogs

import (
	"context"
	"fmt"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/health/probefw"
	"sort"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// kcmWorkqueueCheck is the C6 kube-controller-manager workqueue
// watchdog — a frozen KCM whose leader Lease still renews while its
// object controllers stop reconciling.
type kcmWorkqueueCheck struct {
	*probefw.Deps

	// C6 watchdog state (serial sweep — unguarded):
	//   - kcmFirstSeen: signature key "<reason>/<kind>/<name>" → the
	//     first sweep that observed it; a signature must persist
	//     kcmFreezeMinAge before the gauge fires. Pruned when the
	//     signature resolves — a later stall re-arms the window.
	//   - kcmFrozenReasons: reason labels currently held at 1, so a
	//     resolved signature flips its series back to 0 instead of
	//     leaking a stale 1 forever.
	kcmFirstSeen     map[string]time.Time
	kcmFrozenReasons map[string]bool
}

// newKcmWorkqueueCheck builds the C6 watchdog with fresh tracking
// maps — the state-map initialization that used to live in the
// monolithic newClusterHealthProber literal.
func NewKcmWorkqueueCheck(d *probefw.Deps) probefw.Check {
	return &kcmWorkqueueCheck{Deps: d,
		kcmFirstSeen:     map[string]time.Time{},
		kcmFrozenReasons: map[string]bool{},
	}
}

// C6 watchdog knobs — the KCM leader Lease name and the
// node_automation_kcm_workqueue_frozen{reason} label values.
const (
	// CheckNameKCMWorkqueue is the check's kuberhealthy_check label
	// value: not a ported HealthCheck but the C6 watchdog — it
	// still reports on the same series under its own check name so
	// the generic FAIL alerting path covers it too.
	CheckNameKCMWorkqueue = "kcm-workqueue-watchdog"
	kcmLeaseName          = "kube-controller-manager"
	kcmReasonDesiredZero  = "daemonset_desired_zero"
	kcmReasonStaleGen     = "stale_observed_generation"
)

// ---------------------------------------------------------------------------
// kcm-workqueue-watchdog (C6)
// ---------------------------------------------------------------------------

// checkKCMWorkqueue detects a kube-controller-manager workqueue
// freeze: the leader still renews its coordination.k8s.io Lease but
// the object controllers stop reconciling — a "gray" failure where
// /healthz and the leader lock stay green while cluster objects go
// stale (the incident class behind this watchdog).
//
// Preconditions, quiet on miss — the frozen-but-leader case is the
// ONLY thing this check flags:
//   - at least one Ready Node (the storm gate: with no Ready node a
//     desiredNumberScheduled==0 reading is ambiguous, and a dead
//     cluster is covered by other checks);
//   - the kube-system/kube-controller-manager Lease is still renewing
//     (renewTime no older than kcmLeaseMaxAge — KCM leader-election
//     renews every ~2s inside a 15s LeaseDuration). A stale or absent
//     Lease means the holder is GONE: a dead KCM is a different
//     failure pod-status/dead-node checks already cover, and flagging
//     it here would double-alert the wrong diagnosis.
//
// Freeze signatures (kube-system objects), each required to persist
// continuously for kcmFreezeMinAge via a per-object first-seen map:
//   - daemonset_desired_zero: a DaemonSet reports
//     status.desiredNumberScheduled==0 while pods are still
//     scheduled/ready — the DS controller stopped recomputing desired
//     from live nodes. desired==0 with zero pods anywhere is a
//     legitimately-empty selector, not a freeze, so it is excluded.
//   - stale_observed_generation: a Deployment or DaemonSet whose
//     status.observedGeneration lags metadata.generation — its
//     controller never processed the last spec write.
//
// On freeze the dedicated gauge
// node_automation_kcm_workqueue_frozen{reason} goes to 1; it flips
// back to 0 when the signature resolves (or when the preconditions
// stop holding — resetKCMWorkqueue re-arms tracking from scratch).
func (p *kcmWorkqueueCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()

	nodes, err := shared.ListNodes(ctx, p.CS)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list nodes: %w", err)}
	}
	ready := false
	for i := range nodes {
		if shared.NodeReady(&nodes[i]) {
			ready = true
			break
		}
	}
	if !ready {
		p.resetKCMWorkqueue()
		return probefw.Result{Pass: true}
	}

	lease, err := p.CS.CoordinationV1().Leases(metav1.NamespaceSystem).
		Get(ctx, kcmLeaseName, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		// No leader Lease at all — no elected KCM to judge.
		p.resetKCMWorkqueue()
		return probefw.Result{Pass: true}
	case err != nil:
		return probefw.Result{Infra: fmt.Errorf("get lease %s/%s: %w",
			metav1.NamespaceSystem, kcmLeaseName, err)}
	case lease.Spec.RenewTime == nil ||
		now.Sub(lease.Spec.RenewTime.Time) > p.Cfg.KCM.LeaseMaxAge:
		// Stale renewTime = the holder is gone — a dead KCM, not a
		// frozen one. Stay quiet.
		p.resetKCMWorkqueue()
		return probefw.Result{Pass: true}
	}

	dss, err := p.CS.AppsV1().DaemonSets(metav1.NamespaceSystem).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list daemonsets in %s: %w",
			metav1.NamespaceSystem, err)}
	}
	deps, err := p.CS.AppsV1().Deployments(metav1.NamespaceSystem).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list deployments in %s: %w",
			metav1.NamespaceSystem, err)}
	}

	// Candidate signatures keyed "<reason>/<kind>/<name>" so each
	// object's persistence window is tracked independently.
	sigs := map[string]string{}
	for i := range dss.Items {
		ds := &dss.Items[i]
		if ds.Status.DesiredNumberScheduled == 0 &&
			(ds.Status.CurrentNumberScheduled+
				ds.Status.UpdatedNumberScheduled+
				ds.Status.NumberReady+
				ds.Status.NumberMisscheduled) > 0 {
			sigs[kcmReasonDesiredZero+"/daemonset/"+ds.Name] = kcmReasonDesiredZero
		}
		if ds.Status.ObservedGeneration < ds.Generation {
			sigs[kcmReasonStaleGen+"/daemonset/"+ds.Name] = kcmReasonStaleGen
		}
	}
	for i := range deps.Items {
		dep := &deps.Items[i]
		if dep.Status.ObservedGeneration < dep.Generation {
			sigs[kcmReasonStaleGen+"/deployment/"+dep.Name] = kcmReasonStaleGen
		}
	}

	frozen := map[string]bool{}
	for sig, reason := range sigs {
		if _, ok := p.kcmFirstSeen[sig]; !ok {
			p.kcmFirstSeen[sig] = now
			log.Info("KCM freeze signature — tracking first-seen",
				"signature", sig)
			continue
		}
		if now.Sub(p.kcmFirstSeen[sig]) >= p.Cfg.KCM.FreezeMinAge {
			frozen[reason] = true
		}
	}
	for sig := range p.kcmFirstSeen {
		if _, ok := sigs[sig]; !ok {
			delete(p.kcmFirstSeen, sig)
		}
	}
	for reason := range p.kcmFrozenReasons {
		if !frozen[reason] {
			metrics.KCMWorkqueueFrozen.WithLabelValues(reason).Set(0)
			delete(p.kcmFrozenReasons, reason)
		}
	}
	for reason := range frozen {
		metrics.KCMWorkqueueFrozen.WithLabelValues(reason).Set(1)
		p.kcmFrozenReasons[reason] = true
	}

	if len(frozen) == 0 {
		return probefw.Result{Pass: true}
	}
	reasons := make([]string, 0, len(frozen))
	for r := range frozen {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	return probefw.Result{Why: fmt.Sprintf(
		"KCM lease renews but kube-system objects unreconciled >=%s: %s",
		p.Cfg.KCM.FreezeMinAge, strings.Join(reasons, ", "))}
}

// resetKCMWorkqueue clears freeze tracking and drops any held gauge —
// called when the frozen-but-leader diagnosis cannot apply (no Ready
// nodes, absent/stale KCM Lease) so a signature that flaps around a
// precondition edge re-arms its persistence window from scratch.
func (p *kcmWorkqueueCheck) resetKCMWorkqueue() {
	clear(p.kcmFirstSeen)
	for reason := range p.kcmFrozenReasons {
		metrics.KCMWorkqueueFrozen.WithLabelValues(reason).Set(0)
		delete(p.kcmFrozenReasons, reason)
	}
}
