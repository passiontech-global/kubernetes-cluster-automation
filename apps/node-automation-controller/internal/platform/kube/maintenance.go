// maintenance.go — the Cluster Maintenance Mutex (2.7): the single
// canonical implementation of the check the deferring modules used
// to each carry a copy of (descheduler-storm-gate,
// concourse-workdir-janitor, admission-webhook-guard's nil-dyn
// degraded path — all removed in favour of these helpers).
// Remediation that could disturb a drain/upgrade in flight defers
// while ANY signal holds.
//
// The consumption shape is MaintenanceActive — the (held, why,
// error) verdict every deferring module wants: the first active
// signal's evidence, evaluated in order with the historical
// short-circuit (a held signal means the later API calls never
// run). The per-signal *Evidence helpers stay package-private:
// they exist to be composed here, not called directly.
package kube

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

const (
	// kuredDaemonSetNS/Name is where the kured reboot lock lives.
	kuredDaemonSetNS   = "kube-system"
	kuredDaemonSetName = "kured"
	// KuredLockAnno is the reboot-coordination annotation kured holds
	// while a node drains for its reboot window.
	KuredLockAnno = "weave.works/kured-node-lock"
)

// AutopilotPlanGVR moved to gvr.go — the named GVR registry — same
// package, same exported identifier, unchanged value (its original
// doc comment moved with it).

// nodeCordonEvidence returns the evidence strings for mutex signal
// (a) — "node <name> actively cordoned" for every node inside the
// active-cordon window: spec.unschedulable with the unschedulable
// taint younger than 45m. A statically-cordoned node (>45m, no kured
// lock, no live Plan) is deliberate state, not maintenance: counting
// it would freeze every deferring remediation forever. A node
// LIST failure is an error — "cannot verify" must never read as
// "clear". now is the clock the 45m freshness window is evaluated on
// — plumbed from Verdict.Active's own `now` so the window and the
// verdict memo age on ONE clock (fake-clock tests pin both).
func nodeCordonEvidence(ctx context.Context, cs kubernetes.Interface,
	now time.Time) ([]string, error) {
	// A node cordoned for longer than the active window with no
	// other maintenance signal is a static cordon, not a drain.
	// maintenanceNodeList prefers the sweep's memoized census when
	// a MaintenanceSnapshotProvider rides the ctx — the mutex's
	// per-TTL re-evaluation then costs zero extra reads.
	nodes, err := maintenanceNodeList(ctx, cs)
	if err != nil {
		return nil, fmt.Errorf("list nodes (maintenance mutex): %w", err)
	}
	var ev []string
	for i := range nodes {
		if NodeActivelyCordoned(&nodes[i], now) {
			ev = append(ev, "node "+nodes[i].Name+" actively cordoned")
		}
	}
	return ev, nil
}

// KuredLockEvidence returns the evidence string for mutex signal
// (b) — "kured lock held by <value>" while DaemonSet
// kube-system/kured holds weave.works/kured-node-lock (a reboot
// drain is in progress right now). A missing kured DaemonSet is not
// evidence — kured is not installed on every cluster; a real API
// failure is an error.
func KuredLockEvidence(ctx context.Context, cs kubernetes.Interface) ([]string, error) {
	holder, err := kuredLockHolder(ctx, cs)
	if err != nil {
		return nil, err
	}
	if holder != "" {
		return []string{"kured lock held by " + holder}, nil
	}
	return nil, nil
}

// kuredLockHolder returns the node a kured reboot lock targets —
// "" means no lock (or kured not installed). kured writes
// weave.works/kured-node-lock as a JSON object
// ({"nodeID":"<node>"}), so the raw annotation value is NOT the
// node name: resolving it through kuredLockNodeID keeps a
// one-node reboot lock scoped to that node instead of degrading
// every lock to the cluster-wide hold. The read prefers the sweep
// census via maintenanceDaemonSet when a MaintenanceSnapshotProvider
// rides ctx; every other caller gets the direct namespaced GET.
func kuredLockHolder(ctx context.Context, cs kubernetes.Interface) (string, error) {
	ds, err := maintenanceDaemonSet(ctx, cs, kuredDaemonSetNS, kuredDaemonSetName)
	switch {
	case err != nil:
		return "", fmt.Errorf("get daemonset %s/%s (maintenance mutex): %w",
			kuredDaemonSetNS, kuredDaemonSetName, err)
	case ds == nil:
		// kured not installed on this cluster — no signal.
		return "", nil
	}
	return kuredLockNodeID(ds.Annotations[KuredLockAnno]), nil
}

// kuredLockNodeID extracts the node name from a kured lock
// annotation value. The documented kured format is a JSON object
// carrying nodeID; a value that is not that JSON falls back to the
// raw string (older writers stamped the node name directly). A JSON
// document WITHOUT a usable nodeID returns the raw value unchanged —
// it cannot resolve to a live node, so callers degrade to the
// conservative cluster-wide hold rather than silently dropping the
// lock signal.
func kuredLockNodeID(raw string) string {
	if raw == "" {
		return ""
	}
	var lock struct {
		NodeID string `json:"nodeID"`
	}
	if err := json.Unmarshal([]byte(raw), &lock); err == nil &&
		lock.NodeID != "" {
		return lock.NodeID
	}
	return raw
}

// AutopilotPlanEvidence returns the evidence strings for mutex
// signal (c) — "autopilot plan <name> state=<state>" for every Plan
// whose status.state is neither Schedulable nor Completed (a k0s
// upgrade in flight). An absent CRD is not evidence. A missing
// dynamic client is a wiring bug, not "no signal" — unverifiable
// fails closed like every other check here.
func AutopilotPlanEvidence(ctx context.Context, dyn dynamic.Interface) ([]string, error) {
	if dyn == nil {
		return nil, errors.New("no dynamic client — autopilot plan check unverifiable (maintenance mutex)")
	}
	plans, err := ListAllUnstructured(ctx, dyn.Resource(AutopilotPlanGVR),
		metav1.ListOptions{Limit: DefaultListPageSize})
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		// autopilot CRD not installed — no signal.
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("list autopilot plans (maintenance mutex): %w", err)
	}
	var ev []string
	for i := range plans.Items {
		state, _ := NestedString(
			plans.Items[i].Object, "status", "state")
		if state != "Schedulable" && state != "Completed" {
			ev = append(ev, fmt.Sprintf("autopilot plan %s state=%s",
				plans.Items[i].GetName(), state))
		}
	}
	return ev, nil
}

// Medik8sRemediationEvidence returns the evidence strings for mutex
// signal (d) — "medik8s remediation <kind> <ns>/<name>" for every
// SelfNodeRemediation, FenceAgentsRemediation and NodeMaintenance
// object still live on the cluster. The remediation CRs are created
// when a fencing/cordon+drain starts and deleted when it completes,
// so any live object is a remediation actively working a node —
// rebooting or rebalancing on top of an in-flight medik8s remediation
// double-books the node (the same overlap class the kured lock
// covers). Absent CRDs are not evidence; a NodeMaintenance whose
// status.phase already reads Succeeded is a finished (soon-deleted)
// record, not a live one. A real list failure is an error, and a nil
// dynamic client is unverifiable — the mutex never reads "cannot
// verify" as "clear".
func Medik8sRemediationEvidence(ctx context.Context, dyn dynamic.Interface) ([]string, error) {
	if dyn == nil {
		return nil, errors.New("no dynamic client — medik8s remediation check unverifiable (maintenance mutex)")
	}
	var ev []string
	for _, gvr := range Medik8sRemediationGVRs {
		items, err := ListAllUnstructured(ctx, dyn.Resource(gvr),
			metav1.ListOptions{Limit: DefaultListPageSize})
		switch {
		case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
			continue // CRD absent on this cluster — no signal
		case err != nil:
			return nil, fmt.Errorf("list %s (maintenance mutex): %w", gvr.Resource, err)
		}
		for i := range items.Items {
			obj := &items.Items[i]
			// A NodeMaintenance reporting Succeeded is the completed
			// record awaiting deletion — the cordon+drain already
			// finished, so it is not live evidence.
			if gvr == GVRNodeMaintenance {
				if phase, _ := NestedString(
					obj.Object, "status", "phase"); phase == "Succeeded" {
					continue
				}
			}
			kind := obj.GetKind()
			if kind == "" {
				kind = gvr.Resource
			}
			ev = append(ev, fmt.Sprintf("medik8s remediation %s %s in flight",
				kind, obj.GetNamespace()+"/"+obj.GetName()))
		}
	}
	return ev, nil
}

// MaintenanceActive reports whether deliberate cluster maintenance is
// in flight — destructive remediation (pod deletes, leader kills)
// defers while any signal holds:
//
//	a) any node ACTIVELY cordoned — spec.unschedulable with the
//	   unschedulable taint younger than 45m. A statically-cordoned
//	   node (>45m, no kured lock, no live Plan) is deliberate
//	   state, not maintenance: counting it would freeze every
//	   deferring remediation forever.
//	b) DaemonSet kube-system/kured holding weave.works/kured-node-lock;
//	c) an autopilot Plan whose status.state is neither Schedulable
//	   nor Completed — a k0s upgrade in flight;
//	d) a live medik8s remediation object — SelfNodeRemediation,
//	   FenceAgentsRemediation or a non-Succeeded NodeMaintenance —
//	   a fencing/cordon+drain already in flight.
//
// Returns (held, human-readable why, error). A missing kured
// DaemonSet or absent autopilot/medik8s CRD is not evidence; real API
// failures are errors — "cannot verify" must never read as "clear".
// A nil dynamic client makes the Plan and remediation checks
// unverifiable and is reported as an error, never silently skipped.
//
// The historical contract is the SHORT-CIRCUIT — the first held
// signal answers the verdict without paying for (or failing on)
// the later API reads. Signals evaluate in the canonical
// a → b → c → d order and `why` is the first signal's first evidence.
func MaintenanceActive(ctx context.Context, cs kubernetes.Interface, dyn dynamic.Interface) (bool, string, error) {
	return MaintenanceActiveWithClock(ctx, cs, dyn, time.Now())
}

// MaintenanceActiveWithClock is MaintenanceActive with the wall
// clock injected: Verdict.Active plumbs its own `now` down so the
// 45m cordon window and the verdict memo age on ONE clock, and
// fake-clock tests can pin the freshness verdict instead of racing
// time.Now (a cordoned node is only evidence for 45m — a test built
// around wall-clock time.Now flakes at exactly that boundary).
func MaintenanceActiveWithClock(ctx context.Context, cs kubernetes.Interface,
	dyn dynamic.Interface, now time.Time) (bool, string, error) {
	for _, signal := range []func() ([]string, error){
		func() ([]string, error) { return nodeCordonEvidence(ctx, cs, now) },
		func() ([]string, error) { return KuredLockEvidence(ctx, cs) },
		func() ([]string, error) { return AutopilotPlanEvidence(ctx, dyn) },
		func() ([]string, error) { return Medik8sRemediationEvidence(ctx, dyn) },
	} {
		ev, err := signal()
		if err != nil {
			return false, "", err
		}
		if len(ev) > 0 {
			return true, ev[0], nil
		}
	}
	return false, "", nil
}

// maintenanceStampCordonMaxAge is the cordon-freshness horizon the
// STAMP path applies — wider than the verdict's nodeCordonActiveMaxAge
// (45m) because the stamp is a hold-hint for node-host-agents, not
// the mutex itself: over-holding a static cordon costs agents a few
// deferred local actions, under-holding resumes them mid-drain.
const maintenanceStampCordonMaxAge = 2 * time.Hour

// maintenanceStampTTL is how far out the cluster-maintenance-until
// annotation reaches — refreshed on every held verdict (the Verdict
// memo bounds that to ~1/min), self-expiring if the controller
// dies mid-maintenance. 15m covers the agent's ~30s annotation
// cache with generous slack for a missed refresh.
const maintenanceStampTTL = 15 * time.Minute

// maintenanceStampRefreshFloor skips the node patch when the node's
// existing stamp already reaches past now+10m — the eval runs ~1/min
// while held, so without the floor every stamped node would take a
// merge patch every minute for the whole drain.
const maintenanceStampRefreshFloor = 10 * time.Minute

// remediationNodeNameAnno is the annotation medik8s NHC (>= v0.6)
// stamps on remediation CRs it names "<nodeName>-<templateName>" —
// the CR name no longer equals the node name, so the annotation
// carries the fencing target (same key deadnodesweeper reads; kept
// private here because platform cannot import the domain package).
const remediationNodeNameAnno = "remediation.medik8s.io/node-name"

// StampMaintenanceTargets is the L1↔L3 coordination WRITE half of
// the maintenance mutex — deliberately separate from the read-only
// MaintenanceActive verdict so a "does maintenance hold?" query can
// never patch Nodes as a side effect. Each pass converges every
// node's cluster-maintenance-until annotation toward the active
// target set:
//
//   - actively-cordoned nodes and nodes named by live medik8s
//     remediation CRs stamp INDIVIDUALLY — a single-node SNR must
//     not freeze every node's L1 self-heal;
//   - a live autopilot Plan or kured lock is cluster-wide by
//     nature (upgrade / reboot drain) — every node takes the stamp;
//   - a node OUTSIDE the target set has its stamp REMOVED when the
//     value is one this controller could have written — maintenance
//     ending must not leave agents paused on a stale window, and
//     waiting out the 15m TTL would extend every drain's tail by
//     that much. The unstamp keys off the STAMP target computation
//     (2h cordon horizon), never the 45m verdict window: a node
//     cordoned 90m is still mid-drain for stamping purposes.
//
// Best-effort by contract: per-node patch errors are swallowed (a
// failed stamp costs one agent cache window, never a wrong verdict)
// and target-collection read failures degrade to fewer STAMP
// targets — but a degraded read also disables the unstamp half:
// removing a hold on a signal we failed to observe is the one
// direction that must fail closed.
func StampMaintenanceTargets(ctx context.Context, cs kubernetes.Interface,
	dyn dynamic.Interface, now time.Time) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	all, names, complete := maintenanceStampTargets(ctx, cs, dyn, now)
	if !all && len(names) == 0 && !complete {
		return // degraded read, nothing to stamp, unstamp unsafe
	}
	nodes, err := ListNodes(ctx, cs)
	if err != nil {
		return
	}
	stamp := now.Add(maintenanceStampTTL).UTC().Format(time.RFC3339)
	floor := now.Add(maintenanceStampRefreshFloor)
	for i := range nodes {
		n := &nodes[i]
		if all || names[n.Name] {
			if t, ok := ParseAnnoTime(n.Annotations[nodecond.AnnoClusterMaintenanceUntil]); ok &&
				t.After(floor) {
				continue // stamp fresh enough — skip the write
			}
			data, err := MergePatchAnnos(map[string]any{
				nodecond.AnnoClusterMaintenanceUntil: stamp,
			})
			if err != nil {
				return
			}
			_, _ = cs.CoreV1().Nodes().Patch(ctx, n.Name,
				types.MergePatchType, data, metav1.PatchOptions{})
			continue
		}
		if !complete {
			continue // a signal read failed — never drop a hold blind
		}
		v, ok := n.Annotations[nodecond.AnnoClusterMaintenanceUntil]
		if !ok || !controllerOwnedStamp(v, now) {
			continue // absent, or a value this controller did not write
		}
		data, err := MergePatchAnnos(map[string]any{
			nodecond.AnnoClusterMaintenanceUntil: nil,
		})
		if err != nil {
			return
		}
		_, _ = cs.CoreV1().Nodes().Patch(ctx, n.Name,
			types.MergePatchType, data, metav1.PatchOptions{})
	}
}

// controllerOwnedStamp reports whether an annotation value has the
// shape THIS controller writes: an RFC3339 timestamp no further out
// than the stamp TTL plus a minute of slack. The stamp
// carries no owner field, so ownership is the value domain — a
// parseable timestamp inside the writable window is a stamp we (or
// a previous replica of us) could have written; anything else (a
// hand-set sentinel, another tool's format, a far-future "forever"
// mark) is left untouched. Past timestamps pass: an expired stamp
// is dead weight regardless of which replica wrote it, and removing
// it cannot extend a hold. The one-minute slack covers write/read
// clock skew between replicas — a live stamp's value is always
// <= its write time + TTL, so now+TTL+1m is the widest value this
// controller can legitimately have on a node.
func controllerOwnedStamp(value string, now time.Time) bool {
	t, ok := ParseAnnoTime(value)
	if !ok {
		return false
	}
	return !t.After(now.Add(maintenanceStampTTL + time.Minute))
}

// maintenanceStampTargets resolves which nodes the active
// maintenance signals cover, plus whether every consulted signal
// read succeeded. Read failures degrade to "no targets" per source —
// stamping is a hint, and the held verdict that triggered this call
// already proved maintenance is real — but they also clear `complete`
// so the caller skips the unstamp half: dropping a hold on a signal
// we could not observe is the unsafe direction.
func maintenanceStampTargets(ctx context.Context, cs kubernetes.Interface,
	dyn dynamic.Interface, now time.Time) (all bool, names map[string]bool,
	complete bool) {
	names = map[string]bool{}
	complete = true
	nodeNames := map[string]bool{}
	if nodes, err := maintenanceNodeList(ctx, cs); err == nil {
		for i := range nodes {
			nodeNames[nodes[i].Name] = true
			// The stamp horizon is wider than the verdict's 45m:
			// a node cordoned for up to 2h is still inside its
			// drain window for stamping purposes — agents holding
			// local remediation longer than the verdict needs is
			// cheap, resuming it mid-drain is not.
			if nodeCordonedFresh(&nodes[i], now, maintenanceStampCordonMaxAge) {
				names[nodes[i].Name] = true
			}
		}
	} else {
		complete = false
	}
	if dyn == nil {
		// The Plan and medik8s signals are unverifiable without a
		// dynamic client — same fail-closed rule as the verdict.
		complete = false
	} else {
		for _, gvr := range Medik8sRemediationGVRs {
			items, err := ListAllUnstructured(ctx, dyn.Resource(gvr),
				metav1.ListOptions{Limit: DefaultListPageSize})
			switch {
			case err == nil:
			case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
				continue // absent CRD — no targets, still complete
			default:
				complete = false
				continue // list failure — no targets from it
			}
			for i := range items.Items {
				obj := &items.Items[i]
				if gvr == GVRNodeMaintenance {
					if phase, _ := NestedString(
						obj.Object, "status", "phase"); phase == "Succeeded" {
						continue
					}
				}
				if n := medik8sTargetNode(obj, nodeNames); n != "" {
					names[n] = true
				}
			}
		}
		plans, err := ListAllUnstructured(ctx,
			dyn.Resource(AutopilotPlanGVR),
			metav1.ListOptions{Limit: DefaultListPageSize})
		switch {
		case err == nil:
			for i := range plans.Items {
				state, _ := NestedString(
					plans.Items[i].Object, "status", "state")
				if state != "Schedulable" && state != "Completed" {
					all = true // cluster upgrade — every node holds
					break
				}
			}
		case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
			// autopilot CRD absent — no targets, still complete
		default:
			complete = false
		}
	}
	if holder, err := kuredLockHolder(ctx, cs); err == nil {
		if holder != "" {
			// kured's lock names the node it is draining when the
			// value resolves to a live node — stamp only that
			// target instead of holding the whole cluster for one
			// node's reboot window. An unresolvable value
			// (timestamp/identity, or the node already deleted)
			// cannot be scoped, so it degrades to the conservative
			// cluster-wide hold the verdict already uses.
			if nodeNames[holder] {
				names[holder] = true
			} else {
				all = true
			}
		}
	} else {
		complete = false
	}
	return all, names, complete
}

// medik8sTargetNode extracts the node a remediation CR works on:
// the remediation.medik8s.io/node-name annotation first (NHC >=
// v0.6 names CRs "<node>-<template>"), then the CR name itself —
// exact node-name match, or the LONGEST "<node>-<suffix>" prefix
// for older named-template setups ("worker-1-gpu-x" resolves to
// node "worker-1-gpu", not the shorter "worker-1").
func medik8sTargetNode(obj *unstructured.Unstructured,
	nodeNames map[string]bool) string {
	if n := obj.GetAnnotations()[remediationNodeNameAnno]; n != "" {
		return n
	}
	name := obj.GetName()
	if nodeNames[name] {
		return name
	}
	// Longest matching "<node>-<suffix>" prefix wins: map iteration
	// order is random, so returning the FIRST prefix hit could pick
	// "worker-1" for CR "worker-1-gpu-reboot" when node "worker-1-gpu"
	// also exists — stamping/holding the wrong node. The longest
	// prefix is the most specific node name the CR name can encode.
	best := ""
	for nn := range nodeNames {
		if strings.HasPrefix(name, nn+"-") && len(nn) > len(best) {
			best = nn
		}
	}
	return best
}

// verdictTTL is how long a Verdict reuses one MaintenanceActive
// evaluation — sized to cover a sweep's per-target heal preambles
// without letting a drain that starts mid-incident go unseen past
// the next cycle.
const verdictTTL = time.Minute

// Verdict memoizes one MaintenanceActive evaluation for the verdict
// TTL — heal loops that run the mutex once per target would otherwise pay
// three API reads (node list, kured DS get, autopilot plan list) per
// pod. Zero value is ready (expired — evaluates on first call); an
// error verdict is sticky for the window too, matching the
// fail-closed contract of a fresh check.
type Verdict struct {
	// mu guards the memo fields — several module goroutines share
	// one Verdict (Deps.verdict) and may evaluate Active
	// concurrently; an unguarded read-modify-write could tear the
	// (at, held, why, err) tuple mid-sweep.
	mu   sync.Mutex
	at   time.Time
	held bool
	why  string
	err  error
}

// Active returns the maintenance verdict, evaluating
// MaintenanceActiveWithClock (with THIS call's `now` — the memo and
// the cordon window age on one clock) only when the memo is older
// than the verdict TTL. The evaluation runs under a DETACHED ctx —
// context.WithoutCancel keeps the sweep snapshot/overlay values but
// drops the caller's deadline: a check whose PerCheck ctx expires
// mid-eval must not cache its DeadlineExceeded into the 60s memo
// (every later gate would fail closed on a poisoned verdict), and
// the 15s bound keeps a wedged apiserver read from stalling the
// caller past its own budget.
func (v *Verdict) Active(ctx context.Context, cs kubernetes.Interface,
	dyn dynamic.Interface, now time.Time) (bool, string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if now.Sub(v.at) < verdictTTL {
		return v.held, v.why, v.err
	}
	mctx, cancel := context.WithTimeout(
		context.WithoutCancel(ctx), maintenanceEvalTimeout)
	defer cancel()
	v.held, v.why, v.err = MaintenanceActiveWithClock(mctx, cs, dyn, now)
	v.at = now
	// READ-ONLY by contract: a "does maintenance hold?" query must
	// never patch Nodes as a side effect — heal gates call Active
	// dozens of times per sweep and an unexpected write inside a
	// verdict read is exactly the kind of hidden mutation the
	// snapshot/fingerprint work exists to catch. Stamping is the
	// dedicated cluster-maintenance-stamper runnable's job
	// (cmd/manager/maintenancestamper.go) on its own 30s cadence.
	return v.held, v.why, v.err
}

// maintenanceEvalTimeout bounds one mutex evaluation — the four
// signal reads are small LISTs/GETs; 15s is generous headroom that
// still lands well inside a check's PerCheck budget.
const maintenanceEvalTimeout = 15 * time.Second
