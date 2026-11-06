package watchdogs

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	coordinationv1 "k8s.io/api/coordination/v1"
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

// operatorWorkqueueCheck is the W5.8 lease-holding zombie detector
// generalized to third-party operators — a controller holding a
// renewing Lease while its target CRs stay unreconciled past the
// stuck threshold, with leader-pod-delete auto-heal.
type operatorWorkqueueCheck struct {
	*probefw.Deps

	// W5.8 watchdog state (serial sweep — unguarded):
	//   - opFirstSeen: "operator/<gvr>/<ns>/<name>" → first sweep
	//     that saw the stuck signature; it must persist the
	//     operator's stuckMinAge before the gauge fires. Pruned when
	//     the object reconciles — a later stall re-arms the window.
	//   - opFrozen: the emitted-gauge ledger for "operator/reason"
	//     series held at 1 — a tuple not re-emitted flips back to 0.
	//   - opHealed: operator → last leader-pod delete — the in-RAM
	//     half of the 1h heal cooldown (the Lease annotation is the
	//     durable half).
	opFirstSeen state.FirstSeenLedger
	opFrozen    state.GaugeLedger[string]
	opHealed    state.CooldownSet
	// verdict memoizes the maintenance-mutex evaluation the
	// per-operator heal preambles share — one evaluation per
	// Verdict TTL instead of three API reads per stuck operator.
	verdict kube.Verdict

	// gwClassCtlr caches GatewayClass name → spec.controllerName for
	// ~a minute so the gateway-API ownership filter doesn't LIST the
	// class set once per stuck object (serial sweep — unguarded).
	gwClassCtlr map[string]string
	gwClassAt   time.Time
}

// newOperatorWorkqueueCheck builds the W5.8 watchdog — the ledgers
// arm lazily on first use (gwClassCtlr stays lazily populated on
// first resolve).
func NewOperatorWorkqueueCheck(d *probefw.Deps) probefw.Check {
	return &operatorWorkqueueCheck{Deps: d}
}

// W5.8 — operator-workqueue-watchdog knobs. The signature-side
// knobs (stuck windows, reason labels) live with the table in
// operator_watchdog_targets.go; the heal cooldown lives with the
// heal path in operator_leader_heal.go.
const (
	// CheckNameOperatorWorkqueue is the check's kuberhealthy_check
	// label value — W5.8; like the KCM watchdog it is not a ported
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
	// W5.8 — the stuck-operator signal: 1 while the operator renews
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

	var rep probefw.SweepReport
	for _, op := range operatorTargets {
		lease, lerr := p.operatorLease(ctx, op)
		switch {
		case lerr != nil:
			rep.InfraErr(lerr)
			// Never evaluated — carry the held tuples forward.
			p.carryFrozen(&rep, op.name)
			continue
		case lease == nil && op.leaseOptional:
			// No candidate Lease by design (replicas:1 or
			// leader-elect patched out) — a Running pod under the
			// selector is the liveness proof a renewing Lease
			// provides elsewhere. lease stays nil:
			// healOperatorLeader/leaderPods both tolerate it
			// (selector fallback, no stamp persist).
			alive, aerr := p.operatorPodRunning(ctx, op)
			switch {
			case aerr != nil:
				rep.InfraErr(fmt.Errorf("list pods %s selector %q (%s): %w",
					targetPodNS(op), op.podSelector, op.name, aerr))
				// Never evaluated — carry the held tuples forward.
				p.carryFrozen(&rep, op.name)
				continue
			case !alive:
				p.resetOperator(op.name)
				continue
			}
		case lease == nil:
			// No leader Lease — no elected operator to judge.
			p.resetOperator(op.name)
			continue
		case lease.Spec.RenewTime == nil ||
			now.Sub(lease.Spec.RenewTime.Time) > operatorLeaseMaxAge:
			// Stale renewTime = the holder is gone — a dead
			// operator, not a frozen one. Stay quiet.
			p.resetOperator(op.name)
			continue
		}

		// Collect this operator's live stuck signatures — keyed
		// "operator/<gvr>/<ns>/<name>" so each object's persistence
		// window is tracked independently. The list cache shares
		// one List across the resource entries that watch the same
		// GVR for different signatures (no_status_conditions +
		// stale_observed_generation, BUG-C5).
		live := map[string]bool{}
		reasonsFrozen := map[string]bool{}
		evalFailed := false
		lists := map[schema.GroupVersionResource]*unstructured.UnstructuredList{}
		for _, res := range op.resources {
			list, listed := lists[res.gvr]
			if !listed {
				l, err := p.Dyn.Resource(res.gvr).List(ctx, metav1.ListOptions{})
				switch {
				case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
					lists[res.gvr] = &unstructured.UnstructuredList{}
					list = lists[res.gvr]
				case err != nil:
					evalFailed = true
					rep.InfraErr(fmt.Errorf("list %s (%s): %w",
						res.gvr.Resource, op.name, err))
					lists[res.gvr] = &unstructured.UnstructuredList{}
					list = lists[res.gvr]
				default:
					lists[res.gvr] = l
					list = l
				}
			}
			for i := range list.Items {
				o := &list.Items[i]
				if !res.stuck(o) {
					continue
				}
				// Shared-resource types: skip objects provably owned
				// by a different controller so the signature — and
				// the heal — lands on the right operator only.
				if res.owns != nil && !res.owns(ctx, p, o) {
					continue
				}
				key := op.name + "/" + res.gvr.Resource + "/" +
					o.GetNamespace() + "/" + o.GetName()
				live[key] = true
				if probefw.Persisted(&p.opFirstSeen, key, now,
					op.stuckMinAge, log) {
					reasonsFrozen[res.reason] = true
				}
			}
		}
		if evalFailed {
			// An incomplete scan must not prune first-seen nor
			// clear held series — carry this operator's held tuples
			// forward so the sweep-end prune keeps them (they were
			// never re-evaluated, not proven resolved).
			p.carryFrozen(&rep, op.name)
			continue
		}

		p.opFirstSeen.Prune(func(k string) bool {
			return !strings.HasPrefix(k, op.name+"/") || live[k]
		})
		for r := range reasonsFrozen {
			rep.Emit(operatorWorkqueueFrozenGauge, op.name+"/"+r,
				[]string{op.name, r}, op.name+"/"+r)
		}

		if len(reasonsFrozen) > 0 {
			reasons := make([]string, 0, len(reasonsFrozen))
			for r := range reasonsFrozen {
				reasons = append(reasons, r)
			}
			sort.Strings(reasons)
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
	var firstErr error
	for _, name := range op.leaseNames {
		lease, err := p.CS.CoordinationV1().Leases(op.leaseNS).
			Get(ctx, name, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			continue
		case err != nil:
			if firstErr == nil {
				firstErr = fmt.Errorf("get lease %s/%s (%s): %w",
					op.leaseNS, name, op.name, err)
			}
			continue
		default:
			return lease, nil
		}
	}
	return nil, firstErr
}

// operatorPodRunning is the leaseOptional liveness fallback: at
// least one pod in the operator's pod namespace matching podSelector
// is Running — a live pod whose CRs sit unreconciled is the same
// zombie signature a renewing-lease zombie leader presents.
func (p *operatorWorkqueueCheck) operatorPodRunning(ctx context.Context, op operatorTarget) (bool, error) {
	pods, err := p.CS.CoreV1().Pods(targetPodNS(op)).List(ctx,
		metav1.ListOptions{LabelSelector: op.podSelector})
	if err != nil {
		return false, err
	}
	for i := range pods.Items {
		if pods.Items[i].Status.Phase == corev1.PodRunning &&
			pods.Items[i].DeletionTimestamp == nil {
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

// resetOperator clears one operator's first-seen tracking — called
// when the frozen-but-leader diagnosis cannot apply (absent/stale
// Lease, dead pod) so a signature that flaps around a precondition
// edge re-arms from scratch. The operator's held frozen series flip
// at the sweep-end opFrozen prune — nothing re-emitted them.
func (p *operatorWorkqueueCheck) resetOperator(name string) {
	p.opFirstSeen.Prune(func(k string) bool {
		return !strings.HasPrefix(k, name+"/")
	})
}
