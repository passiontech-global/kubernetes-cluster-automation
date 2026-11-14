// operator_workqueue_scan.go — the per-operator sweep core of the
// operator-workqueue-watchdog check (operator-workqueue-watchdog): the leader-election
// liveness precondition, the CR stuck-signature scan (collect +
// persist first-seen), and the post-scan window maintenance (prune +
// resolved clears + gauge emit). Split out of
// operator_workqueue_watchdog.go — see that file for the check, its
// Run orchestration and the sweep verdict.
package watchdogs

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	coordinationv1 "k8s.io/api/coordination/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// opResolvedObj is one CR evaluated non-stuck this sweep, held for
// the post-scan persisted first-seen clear — see the resolved map in
// scanOperatorResources for why the clear is deferred (shared-GVR
// sibling signatures under BUG-C5).
type opResolvedObj struct {
	o   *unstructured.Unstructured
	gvr schema.GroupVersionResource
}

// opScan is one operator's CR signature scan result: the live stuck
// keys, the resolved objects held for the post-scan stamp clear, the
// frozen reasons whose persistence windows landed, and whether the
// scan was incomplete — an incomplete scan must not prune first-seen
// nor clear held series, the caller carries the operator's held
// tuples forward instead.
type opScan struct {
	live          map[string]bool
	resolved      map[string]opResolvedObj
	reasonsFrozen map[string]bool
	evalFailed    bool
}

// operatorLiveness resolves the leader-election precondition for one
// target — the operator failure classes that end the target's sweep
// before any CR is read:
//
//   - carry: an infra failure (Lease read, pod-list read) — the
//     operator's signatures were never evaluated, so the caller
//     carries its held frozen tuples forward;
//   - reset: no leader to judge (no candidate Lease, no Running pod
//     under the leaseOptional fallback, stale renewTime = dead
//     holder — a dead operator, not a frozen one, so stay quiet) —
//     the caller resets the operator's in-RAM first-seen;
//   - otherwise the caller proceeds to the CR scan; lease is the
//     renewing Lease, nil only for the leaseOptional pod-running
//     fallback (no candidate Lease by design — replicas:1 or
//     leader-elect patched out; a Running pod under the selector is
//     the liveness proof a renewing Lease provides elsewhere;
//     healOperatorLeader/leaderPods both tolerate a nil Lease:
//     selector fallback, no stamp persist).
func (p *operatorWorkqueueCheck) operatorLiveness(ctx context.Context,
	op operatorTarget, now time.Time, rep *probefw.SweepReport) (
	lease *coordinationv1.Lease, carry, reset bool) {

	lease, lerr := p.operatorLease(ctx, op)
	switch {
	case lerr != nil:
		rep.InfraErr(lerr)
		return nil, true, false
	case lease == nil && op.leaseOptional:
		alive, aerr := p.operatorPodRunning(ctx, op)
		switch {
		case aerr != nil:
			rep.InfraErr(fmt.Errorf("list pods %s selector %q (%s): %w",
				targetPodNS(op), op.podSelector, op.name, aerr))
			return nil, true, false
		case !alive:
			return nil, false, true
		}
	case lease == nil:
		// No leader Lease — no elected operator to judge.
		return nil, false, true
	case lease.Spec.RenewTime == nil ||
		now.Sub(lease.Spec.RenewTime.Time) > operatorLeaseMaxAge:
		// Stale renewTime = the holder is gone — a dead
		// operator, not a frozen one. Stay quiet.
		return nil, false, true
	}
	return lease, false, false
}

// scanOperatorResources is one operator's CR stuck-signature scan:
// every watched resource is listed once per sweep (the cache shares
// one List across resource entries that watch the same GVR for
// different signatures — no_status_conditions +
// stale_observed_generation, BUG-C5), every object is evaluated
// under each row's predicate, and each stuck object's first-seen
// window is persisted. Live signatures are keyed
// "operator/<gvr>/<ns>/<name>" so each object's persistence window
// is tracked independently.
//
// resolved collects objects evaluated non-stuck under a watched
// predicate for the persisted first-seen clear that runs AFTER the
// resource loop (settleOperatorWindows): two resource rows can watch
// the SAME GVR under different predicates (BUG-C5) and share one
// first-seen key, so a not-stuck verdict under one predicate must
// not wipe the stamp while its sibling signature still reads stuck —
// the clear only fires for keys no row marked live.
//
// List errors land on the sweep report as infra errors and set
// evalFailed — the caller must carry the operator's held tuples
// forward rather than settle the windows.
func (p *operatorWorkqueueCheck) scanOperatorResources(ctx context.Context,
	log logr.Logger, op operatorTarget, now time.Time,
	rep *probefw.SweepReport) opScan {

	scan := opScan{
		live:          map[string]bool{},
		resolved:      map[string]opResolvedObj{},
		reasonsFrozen: map[string]bool{},
	}
	// The per-GVR item cache: sibling rows sharing the GVR reuse the
	// one fetch (BUG-C5) — the fetch itself goes through the
	// sweep-wide snapshot (Deps.AllUnstructured), so the whole
	// roster's read of a GVR memoizes per sweep; errors cache the
	// empty slice the same way. v1Items counts the ExternalSecret
	// v1 census: when v1 objects exist, the legacy v1beta1 rows are
	// skipped — the same object served under two API versions would
	// otherwise carry two first-seen keys (and two windows) for one
	// stuck CR.
	lists := map[schema.GroupVersionResource][]unstructured.Unstructured{}
	v1Items := -1
	for _, res := range op.resources {
		if res.gvr == kube.GVRExternalSecretV1Beta1 && v1Items > 0 {
			continue
		}
		items, listed := lists[res.gvr]
		if !listed {
			l, err := p.AllUnstructured(ctx, res.gvr)
			switch {
			case kube.IsCRDAbsent(err):
				// CRD absent / not yet served — nothing to scan;
				// the empty cache serves the sibling row too.
			case err != nil:
				scan.evalFailed = true
				rep.InfraErr(fmt.Errorf("list %s (%s): %w",
					res.gvr.Resource, op.name, err))
			default:
				items = l
			}
			lists[res.gvr] = items
			if res.gvr == kube.GVRExternalSecretV1 {
				v1Items = len(items)
			}
		}
		for i := range items {
			o := &items[i]
			key := op.name + "/" + res.gvr.Resource + "/" +
				o.GetNamespace() + "/" + o.GetName() + "/" + res.reason
			if !res.stuck(o) {
				if _, ok := scan.resolved[key]; !ok {
					scan.resolved[key] = opResolvedObj{o: o, gvr: res.gvr}
				}
				continue
			}
			// Shared-resource types: skip objects provably owned
			// by a different controller so the signature — and
			// the heal — lands on the right operator only. A
			// stuck-but-foreign object keeps any stamp it
			// carries: it evaluated stuck, not resolved — the
			// window should resume intact if ownership ever
			// flips back.
			if res.owns != nil && !res.owns(ctx, p, o) {
				continue
			}
			scan.live[key] = true
			// The window gates healOperatorLeader's leader-pod
			// delete — an operator restart must not re-arm it
			// from zero, so the first-seen rides the stuck CR
			// itself as a durable annotation (wider of ledger
			// vs annotation).
			if heal.FirstSeenPersisted(ctx, log,
				&p.opFirstSeen, o,
				kube.AnnoFirstSeenOperatorWorkqueue, key,
				op.stuckMinAge, now,
				p.opCRPatch(res.gvr, o)) {
				scan.reasonsFrozen[res.reason] = true
			}
		}
	}
	return scan
}

// settleOperatorWindows is the post-scan persistence maintenance for
// one operator: prune first-seen keys that are neither this
// operator's nor live this sweep, clear the persisted stamp for
// resolved signatures, and re-emit one gauge tuple per landed frozen
// reason.
func (p *operatorWorkqueueCheck) settleOperatorWindows(ctx context.Context,
	log logr.Logger, op operatorTarget, scan *opScan,
	rep *probefw.SweepReport) {

	p.opFirstSeen.Prune(func(k string) bool {
		return !strings.HasPrefix(k, op.name+"/") || scan.live[k]
	})
	// Resolution clears — objects healthy under EVERY watched
	// signature drop the persisted stamp (both clocks) so a
	// later stall re-arms the full window. Tolerated
	// sub-failure: a clear whose patch never lands is Warn'd
	// and absorbed (the ledger half was already Forgotten);
	// the stamp retries next sweep.
	for k, ro := range scan.resolved {
		if scan.live[k] {
			continue
		}
		if err := heal.ClearPersistedFirstSeen(ctx, log,
			&p.opFirstSeen, ro.o,
			kube.AnnoFirstSeenOperatorWorkqueue, k,
			p.opCRPatch(ro.gvr, ro.o)); err != nil {
			log.Info("WARN: persisted first-seen clear failed — "+
				"a stale stamp could fast-trip the next stall",
				"key", k, "error", err)
		}
	}
	for r := range scan.reasonsFrozen {
		rep.Emit(operatorWorkqueueFrozenGauge, op.name+"/"+r,
			[]string{op.name, r}, op.name+"/"+r)
	}
}
