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
	"errors"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
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
	nodes, err := ListNodes(ctx, cs)
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
	ds, err := cs.AppsV1().DaemonSets(kuredDaemonSetNS).
		Get(ctx, kuredDaemonSetName, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		// kured not installed on this cluster — no signal.
	case err != nil:
		return nil, fmt.Errorf("get daemonset %s/%s (maintenance mutex): %w",
			kuredDaemonSetNS, kuredDaemonSetName, err)
	default:
		if v := ds.Annotations[KuredLockAnno]; v != "" {
			return []string{"kured lock held by " + v}, nil
		}
	}
	return nil, nil
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
		state, _, _ := unstructured.NestedString(
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
				if phase, _, _ := unstructured.NestedString(
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
	at   time.Time
	held bool
	why  string
	err  error
}

// Active returns the maintenance verdict, evaluating
// MaintenanceActiveWithClock (with THIS call's `now` — the memo and
// the cordon window age on one clock) only when the memo is older
// than the verdict TTL.
func (v *Verdict) Active(ctx context.Context, cs kubernetes.Interface,
	dyn dynamic.Interface, now time.Time) (bool, string, error) {
	if now.Sub(v.at) < verdictTTL {
		return v.held, v.why, v.err
	}
	v.held, v.why, v.err = MaintenanceActiveWithClock(ctx, cs, dyn, now)
	v.at = now
	return v.held, v.why, v.err
}
