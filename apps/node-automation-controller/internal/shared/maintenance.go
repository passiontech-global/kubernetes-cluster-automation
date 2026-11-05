// maintenance.go — the Cluster Maintenance Mutex (2.7): the shared
// form of the check the descheduler-storm-gate and
// concourse-workdir-janitor each carry a copy of — remediation that
// could disturb a drain/upgrade in flight defers while ANY signal
// holds.
package shared

import (
	"context"
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
	// KuredDaemonSetNS/Name is where the kured reboot lock lives.
	KuredDaemonSetNS   = "kube-system"
	KuredDaemonSetName = "kured"
	// KuredLockAnno is the reboot-coordination annotation kured holds
	// while a node drains for its reboot window.
	KuredLockAnno = "weave.works/kured-node-lock"
)

// AutopilotPlanGVR moved to gvr.go — the named GVR registry — same
// package, same exported identifier, unchanged value (its original
// doc comment moved with it).

// MaintenanceActive reports whether deliberate cluster maintenance is
// in flight — destructive remediation (pod deletes, leader kills)
// defers while any signal holds:
//
//	a) any node ACTIVELY cordoned — spec.unschedulable with the
//	   unschedulable taint younger than 45m. A statically-cordoned
//	   node (>45m, no kured lock, no live Plan) is deliberate
//	   state, not maintenance: counting it would freeze every
//	   deferring remediation forever (W8).
//	b) DaemonSet kube-system/kured holding weave.works/kured-node-lock;
//	c) an autopilot Plan whose status.state is neither Schedulable
//	   nor Completed — a k0s upgrade in flight.
//
// Returns (held, human-readable why, error). A missing kured
// DaemonSet or absent autopilot CRD is not evidence; real API
// failures are errors — "cannot verify" must never read as "clear".
// A nil dynamic client makes the Plan check unverifiable and is
// reported as an error, never silently skipped.
func MaintenanceActive(ctx context.Context, cs kubernetes.Interface, dyn dynamic.Interface) (bool, string, error) {
	// (a) cordon/drain in progress — a node cordoned for longer
	// than the active window with no other maintenance signal is a
	// static cordon, not a drain.
	now := time.Now()
	nodes, err := ListNodes(ctx, cs)
	if err != nil {
		return false, "", fmt.Errorf("list nodes (maintenance mutex): %w", err)
	}
	for i := range nodes {
		if NodeActivelyCordoned(&nodes[i], now) {
			return true, "node " + nodes[i].Name + " actively cordoned", nil
		}
	}

	// (b) kured holding its node-lock annotation means a reboot
	// drain is in progress right now.
	ds, err := cs.AppsV1().DaemonSets(KuredDaemonSetNS).
		Get(ctx, KuredDaemonSetName, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		// kured not installed on this cluster — no signal.
	case err != nil:
		return false, "", fmt.Errorf("get daemonset %s/%s (maintenance mutex): %w",
			KuredDaemonSetNS, KuredDaemonSetName, err)
	default:
		if v := ds.Annotations[KuredLockAnno]; v != "" {
			return true, "kured lock held by " + v, nil
		}
	}

	// (c) Any autopilot Plan outside its terminal states means a
	// k0s upgrade is in flight. An absent CRD is not evidence. A
	// missing dynamic client is a wiring bug, not "no signal" —
	// unverifiable fails closed like every other check here.
	if dyn == nil {
		return false, "", fmt.Errorf("no dynamic client — autopilot plan check unverifiable (maintenance mutex)")
	}
	plans, err := dyn.Resource(AutopilotPlanGVR).
		List(ctx, metav1.ListOptions{})
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		// autopilot CRD not installed — no signal.
	case err != nil:
		return false, "", fmt.Errorf("list autopilot plans (maintenance mutex): %w", err)
	default:
		for i := range plans.Items {
			state, _, _ := unstructured.NestedString(
				plans.Items[i].Object, "status", "state")
			if state != "Schedulable" && state != "Completed" {
				return true, fmt.Sprintf("autopilot plan %s state=%s",
					plans.Items[i].GetName(), state), nil
			}
		}
	}
	return false, "", nil
}
