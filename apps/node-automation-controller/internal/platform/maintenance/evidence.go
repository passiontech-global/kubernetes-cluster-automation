// evidence.go — the Cluster Maintenance Mutex (2.7) READ half: the
// four maintenance signals (active cordon, kured lock, autopilot
// Plan, live medik8s remediation) and the MaintenanceActive verdict
// every deferring module consults. Remediation that could disturb a
// drain/upgrade in flight defers while ANY signal holds; the
// per-signal *Evidence helpers stay package-private — they exist to
// be composed inside MaintenanceActiveWithClock, not called
// directly.
package maintenance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

const (
	// kuredDaemonSetNS/Name is where the kured reboot lock lives.
	kuredDaemonSetNS   = "kube-system"
	kuredDaemonSetName = "kured"
	// KuredLockAnno is the reboot-coordination annotation kured holds
	// while a node drains for its reboot window.
	KuredLockAnno = "weave.works/kured-node-lock"
)

// kube.AutopilotPlanGVR moved to gvr.go — the named GVR registry — same
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
	nodeReader kube.CachedNodeReader, now time.Time) ([]string, error) {
	// A node cordoned for longer than the active window with no
	// other maintenance signal is a static cordon, not a drain.
	// maintenanceNodeList prefers the sweep's memoized census when
	// a MaintenanceSnapshotProvider rides the ctx, then the
	// Verdict's informer-backed reader when wired — the mutex's
	// per-TTL re-evaluation then costs zero apiserver reads.
	nodes, err := maintenanceNodeList(ctx, cs, nodeReader)
	if err != nil {
		return nil, fmt.Errorf("list nodes (maintenance mutex): %w", err)
	}
	var ev []string
	for i := range nodes {
		if kube.NodeActivelyCordoned(&nodes[i], now) {
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
	plans, err := kube.ListAllUnstructured(ctx, dyn.Resource(kube.AutopilotPlanGVR),
		metav1.ListOptions{Limit: kube.DefaultListPageSize})
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		// autopilot CRD not installed — no signal.
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("list autopilot plans (maintenance mutex): %w", err)
	}
	var ev []string
	for i := range plans.Items {
		state, _ := kube.NestedString(
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
	for _, gvr := range kube.Medik8sRemediationGVRs {
		items, err := kube.ListAllUnstructured(ctx, dyn.Resource(gvr),
			metav1.ListOptions{Limit: kube.DefaultListPageSize})
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
			if gvr == kube.GVRNodeMaintenance {
				if phase, _ := kube.NestedString(
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
// around wall-clock time.Now flakes at exactly that boundary). It is
// the reader-less shape: the node census takes the direct
// clientset path.
func MaintenanceActiveWithClock(ctx context.Context, cs kubernetes.Interface,
	dyn dynamic.Interface, now time.Time) (bool, string, error) {
	return maintenanceActive(ctx, cs, dyn, nil, now)
}

// maintenanceActive is MaintenanceActiveWithClock plus the optional
// informer-backed node reader Verdict.Active threads down from its
// NodeReader field — nil keeps the direct read.
func maintenanceActive(ctx context.Context, cs kubernetes.Interface,
	dyn dynamic.Interface, nodeReader kube.CachedNodeReader,
	now time.Time) (bool, string, error) {
	for _, signal := range []func() ([]string, error){
		func() ([]string, error) { return nodeCordonEvidence(ctx, cs, nodeReader, now) },
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
