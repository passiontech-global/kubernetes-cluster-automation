// operator_workqueue_watchdog.go — the operator-workqueue-watchdog
// check (operator-workqueue-watchdog): the lease-holding zombie detector generalized to
// third-party operators — a controller renewing its leader-election
// Lease while its target CRs sit unreconciled past the stuck
// threshold, auto-healed by a leader-pod delete once the signature
// outlives its persistence window.
package watchdogs

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// operatorWorkqueueCheck is the operator-workqueue-watchdog lease-holding zombie detector
// generalized to third-party operators — a controller holding a
// renewing Lease while its target CRs stay unreconciled past the
// stuck threshold, with leader-pod-delete auto-heal.
type operatorWorkqueueCheck struct {
	*probefw.Deps

	// operator-workqueue-watchdog watchdog state (serial sweep — unguarded):
	//   - opFirstSeen: "operator/<gvr>/<ns>/<name>" → first sweep
	//     that saw the stuck signature; it must persist the
	//     operator's stuckMinAge before the gauge fires. The window
	//     gates the leader-pod delete, so it runs the persisted
	//     variant: the first-seen also rides the stuck CR as an
	//     annotation (kube.AnnoFirstSeenOperatorWorkqueue) and a
	//     restart resumes the window instead of re-arming it.
	//     Cleared when the object reconciles — a later stall
	//     re-arms the window.
	//   - opFrozen: the emitted-gauge ledger for "operator/reason"
	//     series held at 1 — a tuple not re-emitted flips back to 0.
	//   - opHealed: operator → last leader-pod delete — the in-RAM
	//     half of the 1h heal cooldown (the Lease annotation is the
	//     durable half).
	opFirstSeen state.FirstSeenLedger
	opFrozen    state.GaugeLedger[string]
	opHealed    state.CooldownSet

	// gwClassCtlr caches GatewayClass name → spec.controllerName for
	// ~a minute so the gateway-API ownership filter doesn't LIST the
	// class set once per stuck object (serial sweep — unguarded).
	gwClassCtlr map[string]string
	gwClassAt   time.Time
}

// newOperatorWorkqueueCheck builds the operator-workqueue-watchdog watchdog — the ledgers
// arm lazily on first use (gwClassCtlr stays lazily populated on
// first resolve).
func NewOperatorWorkqueueCheck(d *probefw.Deps) probefw.Check {
	return &operatorWorkqueueCheck{Deps: d}
}

// operator-workqueue-watchdog — operator-workqueue-watchdog knobs. The signature-side
// knobs (stuck windows, reason labels) live with the table in
// operator_watchdog_targets.go; the heal cooldown lives with the
// heal path in operator_leader_heal.go.
const (
	// CheckNameOperatorWorkqueue is the check's kuberhealthy_check
	// label value — operator-workqueue-watchdog; like the KCM watchdog it is not a ported
	// HealthCheck but reports under its own check name so the
	// generic FAIL alerting path covers it.
	CheckNameOperatorWorkqueue = "operator-workqueue-watchdog"
	// operatorLeaseMaxAge bounds "still renewing": operator
	// leader-election renews every ~2s inside a ~15s duration, so a
	// renewTime older than 2m means the holder is GONE — a dead
	// operator, not a frozen one (pod-status checks cover that
	// failure class).
	operatorLeaseMaxAge = 2 * time.Minute
)

var (
	// operator-workqueue-watchdog — the stuck-operator signal: 1 while the operator renews
	// its Lease but its CRs stay unreconciled past the stuck
	// threshold. operator/reason identify the stall.
	operatorWorkqueueFrozenGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_operator_workqueue_frozen",
		Help: "1 while the operator renews its Lease but its CRs stay unreconciled past the stuck threshold.",
	}, []string{"operator", "reason"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		operatorWorkqueueFrozenGauge)
}

// checkOperatorWorkqueues detects a lease-holding zombie operator:
// the leader still renews its coordination.k8s.io Lease while its
// target CRs sit unreconciled — the C6 gray-failure shape, but for
// the third-party operators whose stuck queues the flux/gitops stack
// depends on. Quiet on miss in the same cases as the KCM watchdog:
// no Lease or a stale renewTime means the holder is gone (a dead
// operator is a different failure pod-status checks already cover).
//
// Dual mechanism per stuck operator:
//
//	a) AUTO-HEAL — past the stuck window and outside maintenance,
//	   healOperatorLeader resolves the holderIdentity to the leader
//	   pod and deletes it (1h cooldown, persisted on the Lease),
//	   forcing re-election onto a fresh replica.
//	b) ALERTING — operatorWorkqueueFrozenGauge{operator,reason}=1 stays
//	   set while the CRs remain unreconciled, so a PrometheusRule
//	   fires if healing did not unstick the queue.
func (p *operatorWorkqueueCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	// The CR scans and the maintenance mutex both need dyn — a
	// missing client is a wiring bug, not "no signal".
	if r := p.RequireDyn("operator workqueue check"); r != nil {
		return *r
	}
	now := p.Now()
	// opHealed keys on operator pod controllers that can be
	// recreated under fresh names — prune expired stamps each sweep.
	p.opHealed.PruneExpired(now, operatorHealCooldown)

	var rep probefw.SweepReport
	for _, op := range operatorTargets {
		// Leader-election precondition — infra failures carry the
		// held tuples forward, "no leader to judge" resets the
		// operator's in-RAM first-seen.
		lease, carry, reset := p.operatorLiveness(ctx, op, now, &rep)
		switch {
		case carry:
			// Never evaluated — carry the held tuples forward.
			p.carryFrozen(&rep, op.name)
			continue
		case reset:
			p.resetOperator(op.name)
			continue
		}

		scan := p.scanOperatorResources(ctx, log, op, now, &rep)
		if scan.evalFailed {
			// An incomplete scan must not prune first-seen nor
			// clear held series or persisted stamps — carry this
			// operator's held tuples forward so the sweep-end
			// prune keeps them (they were never re-evaluated, not
			// proven resolved).
			p.carryFrozen(&rep, op.name)
			continue
		}

		p.settleOperatorWindows(ctx, log, op, &scan, &rep)

		if len(scan.reasonsFrozen) > 0 {
			reasons := make([]string, 0, len(scan.reasonsFrozen))
			for r := range scan.reasonsFrozen {
				reasons = append(reasons, r)
			}
			slices.Sort(reasons)
			p.healOperatorLeader(ctx, log, op, lease, reasons, now)
		}
	}

	// Sweep-end gauge hygiene: every "operator/reason" tuple held at
	// 1 last sweep that no operator re-emitted this sweep flips back
	// to 0 — this covers both resolved signatures and the
	// resetOperator paths (absent/stale Lease, dead pod), while
	// evalFailed operators carried theirs forward above.
	return rep.Result(&p.opFrozen, opFrozenFlipZero,
		"operator lease renews but target CRs unreconciled: ", ", ")
}

// operatorLease fetches the operator's leader-election Lease,
// trying each candidate name in op.leaseNames order — upstream
// ships more than one election id across versions, so a single
// hardcoded name would silently disable the watch on the others.
// Returns (nil, nil) when every candidate is absent; a non-NotFound
// error on any candidate is returned (errors are per-request, not
// per-name — RBAC/network failures hit all names equally).
func (p *operatorWorkqueueCheck) operatorLease(ctx context.Context, op operatorTarget) (*coordinationv1.Lease, error) {
	// Name order is preserved: the first candidate present in the
	// indexed lease census wins.
	for _, name := range op.leaseNames {
		l, err := p.Lease(ctx, op.leaseNS, name)
		if err != nil {
			return nil, fmt.Errorf("list leases for %s: %w", op.name, err)
		}
		if l != nil {
			return l, nil
		}
	}
	return nil, nil
}

// operatorPodRunning is the leaseOptional liveness fallback: at
// least one pod in the operator's pod namespace matching podSelector
// is Running — a live pod whose CRs sit unreconciled is the same
// zombie signature a renewing-lease zombie leader presents.
func (p *operatorWorkqueueCheck) operatorPodRunning(ctx context.Context, op operatorTarget) (bool, error) {
	pods, err := p.PodsMatching(ctx, targetPodNS(op), op.podSelector)
	if err != nil {
		return false, err
	}
	for i := range pods {
		if pods[i].Status.Phase == corev1.PodRunning &&
			pods[i].DeletionTimestamp == nil {
			return true, nil
		}
	}
	return false, nil
}

// opFrozenFlipZero is the emitted-ledger's prune action: an
// "operator/reason" series that stopped being emitted flips to 0
// rather than disappearing — the resolved edge stays visible.
func opFrozenFlipZero(labelValues ...string) bool {
	operatorWorkqueueFrozenGauge.WithLabelValues(labelValues...).Set(0)
	return true
}

// carryFrozen re-registers one operator's held frozen tuples on the
// sweep report so the sweep-end prune keeps them — the skip paths
// where the operator's signatures were never evaluated (lease read
// error, pod list error, incomplete CR scan) must not read as
// "resolved" and flap the series to 0.
func (p *operatorWorkqueueCheck) carryFrozen(rep *probefw.SweepReport, name string) {
	for k, lv := range p.opFrozen.Last() {
		if strings.HasPrefix(k, name+"/") {
			rep.Carry(k, lv)
		}
	}
}

// resetOperator clears one operator's in-RAM first-seen tracking —
// called when the frozen-but-leader diagnosis cannot apply
// (absent/stale Lease, dead pod) so a signature that flaps around a
// precondition edge re-arms from scratch. RAM-only by design: the
// persisted annotation on objects not evaluated this sweep
// deliberately lingers — a missing Lease disproves the leader
// diagnosis, not the CR's stuck signature, so the durable window
// resumes when evaluation restarts. The operator's held frozen
// series flip at the sweep-end opFrozen prune — nothing re-emitted
// them.
func (p *operatorWorkqueueCheck) resetOperator(name string) {
	p.opFirstSeen.Prune(func(k string) bool {
		return !strings.HasPrefix(k, name+"/")
	})
}

// opCRPatch closes over the stuck CR the persisted first-seen stamp
// rides — the durable half of the stuck window lives on the object
// itself, delivered as a merge patch on its own GVR. A landed patch
// is mirrored into the LISTED copy: resource rows that share a GVR
// (BUG-C5) stamp the same key under sibling predicates, and a stale
// local read would make the second stamp re-issue from pre-patch
// state (a wasted write per sweep — the values are identical, so
// correctness doesn't depend on the mirror, only the write count).
func (p *operatorWorkqueueCheck) opCRPatch(gvr schema.GroupVersionResource,
	o *unstructured.Unstructured) func(context.Context, []byte) error {

	return func(ctx context.Context, data []byte) error {
		if _, err := p.Dyn.Resource(gvr).Namespace(o.GetNamespace()).
			Patch(ctx, o.GetName(), types.MergePatchType, data,
				metav1.PatchOptions{}); err != nil {
			return err
		}
		probefw.MergeAnnoPatchLocally(ctx, o, data)
		return nil
	}
}
