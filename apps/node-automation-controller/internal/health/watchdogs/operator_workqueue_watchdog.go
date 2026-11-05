package watchdogs

import (
	"context"
	"fmt"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/health/probefw"
	"sort"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
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
	//   - opFrozen: "operator/reason" currently held at 1, so a
	//     resolved signature flips the series back to 0.
	//   - opHealed: operator → last leader-pod delete — the in-RAM
	//     half of the 1h heal cooldown (the Lease annotation is the
	//     durable half).
	opFirstSeen map[string]time.Time
	opFrozen    map[string]bool
	opHealed    map[string]time.Time

	// gwClassCtlr caches GatewayClass name → spec.controllerName for
	// ~a minute so the gateway-API ownership filter doesn't LIST the
	// class set once per stuck object (serial sweep — unguarded).
	gwClassCtlr map[string]string
	gwClassAt   time.Time
}

// newOperatorWorkqueueCheck builds the W5.8 watchdog with fresh
// tracking maps — the state-map initialization that used to live in
// the monolithic newClusterHealthProber literal (gwClassCtlr stays
// lazily populated on first resolve).
func NewOperatorWorkqueueCheck(d *probefw.Deps) probefw.Check {
	return &operatorWorkqueueCheck{Deps: d,
		opFirstSeen: map[string]time.Time{},
		opFrozen:    map[string]bool{},
		opHealed:    map[string]time.Time{},
	}
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
//	b) ALERTING — OperatorWorkqueueFrozen{operator,reason}=1 stays
//	   set while the CRs remain unreconciled, so a PrometheusRule
//	   fires if healing did not unstick the queue.
func (p *operatorWorkqueueCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	// The CR scans and the maintenance mutex both need dyn — a
	// missing client is a wiring bug, not "no signal".
	if p.Dyn == nil {
		return probefw.Result{Infra: fmt.Errorf(
			"no dynamic client — operator workqueue check unverifiable")}
	}
	now := p.Now()
	if p.opFirstSeen == nil {
		p.opFirstSeen = map[string]time.Time{}
	}
	if p.opFrozen == nil {
		p.opFrozen = map[string]bool{}
	}
	if p.opHealed == nil {
		p.opHealed = map[string]time.Time{}
	}

	frozen := map[string]string{} // "operator/reason" → reason, for the why line
	var firstErr error
	for _, op := range operatorTargets {
		lease, lerr := p.operatorLease(ctx, op)
		switch {
		case lerr != nil:
			if firstErr == nil {
				firstErr = lerr
			}
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
				if firstErr == nil {
					firstErr = fmt.Errorf("list pods %s selector %q (%s): %w",
						targetPodNS(op), op.podSelector, op.name, aerr)
				}
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
					if firstErr == nil {
						firstErr = fmt.Errorf("list %s (%s): %w",
							res.gvr.Resource, op.name, err)
					}
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
				first, ok := p.opFirstSeen[key]
				if !ok {
					p.opFirstSeen[key] = now
				}
				if !ok {
					log.Info("operator stuck signature — tracking first-seen",
						"operator", op.name, "resource", res.gvr.Resource,
						"object", o.GetNamespace()+"/"+o.GetName())
					continue
				}
				if now.Sub(first) >= op.stuckMinAge {
					reasonsFrozen[res.reason] = true
				}
			}
		}
		if evalFailed {
			// An incomplete scan must not prune first-seen nor
			// clear held series — leave this operator's state as-is.
			continue
		}

		for k := range p.opFirstSeen {
			if strings.HasPrefix(k, op.name+"/") && !live[k] {
				delete(p.opFirstSeen, k)
			}
		}
		for k := range p.opFrozen {
			if !strings.HasPrefix(k, op.name+"/") {
				continue
			}
			if reasonsFrozen[strings.TrimPrefix(k, op.name+"/")] {
				continue
			}
			metrics.OperatorWorkqueueFrozen.WithLabelValues(
				op.name, strings.TrimPrefix(k, op.name+"/")).Set(0)
			delete(p.opFrozen, k)
		}
		for r := range reasonsFrozen {
			metrics.OperatorWorkqueueFrozen.WithLabelValues(op.name, r).Set(1)
			p.opFrozen[op.name+"/"+r] = true
			frozen[op.name+"/"+r] = r
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

	if len(frozen) == 0 {
		if firstErr != nil {
			return probefw.Result{Infra: firstErr}
		}
		return probefw.Result{Pass: true}
	}
	keys := make([]string, 0, len(frozen))
	for k := range frozen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return probefw.Result{Infra: firstErr, Why: fmt.Sprintf(
		"operator lease renews but target CRs unreconciled: %s",
		strings.Join(keys, ", "))}
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

// resetOperator clears one operator's tracking and flips its held
// frozen series back to 0 — called when the frozen-but-leader
// diagnosis cannot apply (absent/stale Lease) so a signature that
// flaps around a precondition edge re-arms from scratch.
func (p *operatorWorkqueueCheck) resetOperator(name string) {
	for k := range p.opFirstSeen {
		if strings.HasPrefix(k, name+"/") {
			delete(p.opFirstSeen, k)
		}
	}
	for k := range p.opFrozen {
		if !strings.HasPrefix(k, name+"/") {
			continue
		}
		metrics.OperatorWorkqueueFrozen.WithLabelValues(
			name, strings.TrimPrefix(k, name+"/")).Set(0)
		delete(p.opFrozen, k)
	}
}
