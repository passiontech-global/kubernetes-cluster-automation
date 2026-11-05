// Package shared holds the machinery every node-automation module
// (the sibling module packages under internal/<domain>/) is built on —
// ported 1:1 from the shell-operator bash hooks in passiontech-fluxcd
// (infrastructure/base/node-ops/node-ops-operator/hooks/*.sh).
//
// Contract shared by every module:
//   - Reads go through the kubernetes.Interface clientset (cs) — the
//     operator's RBAC intentionally has NO watch verb on most types
//     (pods, services, jobs, webhookconfigs, ...), so a cached client
//     would deadlock the informer. Only types with an explicit
//     informer (Node, DaemonSet/konnectivity-agent, Deployments and
//     k8s-app=cilium Pods in kube-system, Secret/passiontech-pipeline)
//     may be watched.
//   - `name` everywhere is the legacy shell-operator queue name so
//     metrics.IncError(name) keeps the alert contract.
//   - Error-metric ownership: Periodic.Start IncErrors the queue for
//     any error fn RETURNS, so a module must never IncError an error
//     it returns — that double-counts. IncError inside a module is
//     reserved for tolerated sub-operation failures the run absorbs
//     (logs, continues, and ultimately returns nil) — without it
//     those failures would go uncounted.
//   - Periodic modules register through AddPeriodic; event-driven
//     modules register a reconciler and use Result.RequeueAfter as the
//     old crontab safety-net.
package shared

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
)

// ---------------------------------------------------------------------------
// periodic — replaces a shell-operator `schedule:` binding.
// ---------------------------------------------------------------------------

// Periodic replaces a shell-operator `schedule:` binding — a
// manager.Runnable that ticks fn on interval. Start owns run-level
// error accounting: every non-nil fn return IncErrors p.Name exactly
// once, so fn must NOT IncError errors it returns (double-count) —
// only tolerated sub-operation failures that the run absorbs (log +
// continue, nil return) may IncError from inside fn.
type Periodic struct {
	Name     string
	Interval time.Duration
	Fn       func(ctx context.Context) error
	Log      logr.Logger
}

func (p *Periodic) Start(ctx context.Context) error {
	// A non-positive interval would panic in rand.N / time.NewTicker.
	// AddPeriodic validates at registration, but a Periodic built by
	// hand must still fail here — as a runnable error that stops the
	// manager cleanly, not a panic inside a goroutine that
	// crash-loops the pod.
	if p.Interval <= 0 {
		return fmt.Errorf("periodic %q: interval must be > 0, got %s",
			p.Name, p.Interval)
	}
	// Inject the named logger into the ctx fn sees: modules log via
	// logf.FromContext(ctx), which on the raw manager ctx returns the
	// UNNAMED root logger — every run log line would lack the
	// "logger":"<queue>" field reconcilers get for free. A Periodic
	// built by hand (not via AddPeriodic) may carry a zero-value Log;
	// fall back to naming whatever the ctx already has so the run log
	// and the error log below stay named rather than silently
	// discarding.
	log := p.Log
	if log.GetSink() == nil {
		log = logf.FromContext(ctx).WithName(p.Name)
	}
	runCtx := logf.IntoContext(ctx, log)
	// De-phase the sweep modules: every AddPeriodic caller begins at
	// the same startup moment, so identical NewTicker intervals would
	// fire all modules on the same wall-clock minute — a thundering
	// herd of LIST calls (heap burst) at every common multiple of
	// 5/10/15/30/60m. A one-shot random phase offset uniform in
	// [0, interval) spreads them; the first run lands in
	// [interval, 2*interval), acceptable for crontab-equivalent
	// sweeps. ctx is honored so shutdown is never delayed.
	timer := time.NewTimer(rand.N(p.Interval))
	select {
	case <-ctx.Done():
		timer.Stop()
		return nil
	case <-timer.C:
	}
	t := time.NewTicker(p.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := p.Fn(runCtx); err != nil {
				metrics.IncError(p.Name)
				log.Error(err, "periodic run failed")
			}
		}
	}
}

// AddPeriodic registers fn to run every interval (equivalent to the
// old crontab entry). name is the legacy queue name for metrics
// compat. interval must be >= 1s: a non-positive interval (e.g. an
// env-derived *_INTERVAL knob set to "0s") would panic time.NewTicker
// inside the runnable, and a sub-second interval would hot-loop the
// sweep — returning an error here instead lets setupModules abort
// boot with the module name attached.
func AddPeriodic(mgr manager.Manager, name string, interval time.Duration, fn func(ctx context.Context) error) error {
	if interval < time.Second {
		return fmt.Errorf("periodic %q: interval must be >= 1s, got %s",
			name, interval)
	}
	return mgr.Add(&Periodic{
		Name:     name,
		Interval: interval,
		Fn:       fn,
		Log:      mgr.GetLogger().WithName(name),
	})
}

// ---------------------------------------------------------------------------
// Fixed-key watch fan-in — for full-cluster sweep reconcilers.
// ---------------------------------------------------------------------------

// FixedSweepRequest builds the single reconcile.Request for key.
func FixedSweepRequest(key string) []reconcile.Request {
	return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: key}}}
}

// SweepRequests returns a handler.MapFunc that collapses every watched
// object to one fixed workqueue key. The sweep modules ignore
// reconcile.Request.Name entirely (a trigger only says "go sweep the
// cluster"), so per-node For() keys fanned one informer sync into N
// queued requests AND N independent RequeueAfter timers — every timer
// re-running the same cluster-wide Nodes().List. One fixed key lets
// the workqueue set-collapse the duplicate enqueues and leaves a
// single RequeueAfter timer: 1 sweep per interval regardless of the
// node count.
func SweepRequests(key string) handler.MapFunc {
	return func(context.Context, client.Object) []reconcile.Request {
		return FixedSweepRequest(key)
	}
}

// ---------------------------------------------------------------------------
// Node helpers — taints/conditions/labels shared by several modules.
// ---------------------------------------------------------------------------

// NodeCondition returns the node's condition of type t, or nil.
func NodeCondition(n *corev1.Node, t corev1.NodeConditionType) *corev1.NodeCondition {
	for i := range n.Status.Conditions {
		if n.Status.Conditions[i].Type == t {
			return &n.Status.Conditions[i]
		}
	}
	return nil
}

// NodeReady reports whether the node's Ready condition is True.
func NodeReady(n *corev1.Node) bool {
	c := NodeCondition(n, corev1.NodeReady)
	return c != nil && c.Status == corev1.ConditionTrue
}

// IsControlPlane reports whether the node carries a control-plane role
// label (k0s control planes run no kubelet workload).
func IsControlPlane(n *corev1.Node) bool {
	_, cp := n.Labels["node-role.kubernetes.io/control-plane"]
	_, m := n.Labels["node-role.kubernetes.io/master"]
	return cp || m
}

// HasTaint reports whether taints contains an entry with the given key
// (any effect — `kubectl taint node <n> <key>-` removes all effects).
func HasTaint(taints []corev1.Taint, key string) bool {
	for _, t := range taints {
		if t.Key == key {
			return true
		}
	}
	return false
}

// UnschedulableTaintKey is the taint the cordon path stamps alongside
// spec.unschedulable — its TimeAdded is the only clock for "how long
// has this cordon been live".
const UnschedulableTaintKey = "node.kubernetes.io/unschedulable"

// NodeCordonActiveMaxAge is how old a cordon may be before it reads as
// deliberate static state rather than a drain in flight.
const NodeCordonActiveMaxAge = 45 * time.Minute

// NodeActivelyCordoned reports whether the node is cordoned AND the
// cordon looks like a drain in flight — spec.unschedulable plus the
// node.kubernetes.io/unschedulable taint younger than
// NodeCordonActiveMaxAge (or timestamp-less: unverifiable fails
// closed). A statically-cordoned node — unschedulable held past the
// window — does NOT count: long-cordoned nodes are an operator
// decision (decommissioned capacity, quarantined hardware), not a
// drain, and treating them as "maintenance in flight" freezes every
// remediation that defers to it forever.
func NodeActivelyCordoned(n *corev1.Node, now time.Time) bool {
	if !n.Spec.Unschedulable {
		return false
	}
	for _, t := range n.Spec.Taints {
		if t.Key != UnschedulableTaintKey {
			continue
		}
		if t.TimeAdded == nil {
			return true // cordon timestamp unverifiable — fail closed
		}
		return now.Sub(t.TimeAdded.Time) < NodeCordonActiveMaxAge
	}
	// unschedulable without the companion taint — the age cannot be
	// verified, so it counts (fail closed, same as a nil TimeAdded).
	return true
}

// DropTaintsByKey returns taints with every entry matching key
// removed. It filters IN PLACE — the result aliases and shortens the
// caller's backing array, so the input must not be shared or
// informer-cache-owned. Callers must pass a slice they own (today
// every call site hands over .spec.taints of a fresh Get, which the
// apiserver decodes per call).
func DropTaintsByKey(taints []corev1.Taint, key string) []corev1.Taint {
	out := taints[:0]
	changed := false
	for _, t := range taints {
		if t.Key != key {
			out = append(out, t)
		} else {
			changed = true
		}
	}
	if changed {
		// Zero the tail — the filtered entries would otherwise stay
		// reachable (and their strings uncollectable) through the
		// shared backing array.
		clear(taints[len(out):])
	}
	return out
}

// PatchNodeTaints replaces .spec.taints on a node via JSON Merge Patch
// — the merge semantics create the key when absent (a never-tainted
// node has no "taints" field, so a JSONPatch "replace" would be
// rejected) and arrays are replaced wholesale, which is exactly what
// callers pass (the full desired taint list).
func PatchNodeTaints(ctx context.Context, cs kubernetes.Interface, name string, taints []corev1.Taint) error {
	if taints == nil {
		taints = []corev1.Taint{} // merge patch [] clears, nil would marshal "taints":null
	}
	payload, err := json.Marshal(map[string]any{
		"spec": map[string]any{"taints": taints},
	})
	if err != nil {
		return err
	}
	_, err = cs.CoreV1().Nodes().Patch(ctx, name, types.MergePatchType, payload, metav1.PatchOptions{})
	return err
}

// TaintNode adds key=value:effect unless the key is already present.
// The node is re-fetched inside (kubectl taint's get-modify-patch
// pattern) so a taint added after the caller's snapshot is not lost.
func TaintNode(ctx context.Context, cs kubernetes.Interface, name, key, value string, effect corev1.TaintEffect) error {
	node, err := cs.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if HasTaint(node.Spec.Taints, key) {
		return nil
	}
	taints := append(append([]corev1.Taint{}, node.Spec.Taints...),
		corev1.Taint{Key: key, Value: value, Effect: effect})
	return PatchNodeTaints(ctx, cs, name, taints)
}

// UntaintNode removes every taint with the given key (all effects).
func UntaintNode(ctx context.Context, cs kubernetes.Interface, name, key string) error {
	node, err := cs.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if !HasTaint(node.Spec.Taints, key) {
		return nil
	}
	return PatchNodeTaints(ctx, cs, name, DropTaintsByKey(node.Spec.Taints, key))
}

// PatchNodeLabels merges labels onto a node (kubectl label --overwrite).
func PatchNodeLabels(ctx context.Context, cs kubernetes.Interface, name string, labels map[string]string) error {
	payload, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"labels": labels},
	})
	if err != nil {
		return err
	}
	_, err = cs.CoreV1().Nodes().Patch(ctx, name, types.StrategicMergePatchType, payload, metav1.PatchOptions{})
	return err
}

// ListNodes is the single place node listing happens (RBAC: cluster
// get/list/watch on nodes).
func ListNodes(ctx context.Context, cs kubernetes.Interface) ([]corev1.Node, error) {
	nl, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return nl.Items, nil
}

// CountNotReadyNodes returns how many nodes are not Ready=True —
// the shared "storm-gate" check used by several modules.
func CountNotReadyNodes(ctx context.Context, cs kubernetes.Interface) (int, error) {
	nodes, err := ListNodes(ctx, cs)
	if err != nil {
		return 0, err
	}
	n := 0
	for i := range nodes {
		if !NodeReady(&nodes[i]) {
			n++
		}
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// DaemonSet helpers.
// ---------------------------------------------------------------------------

// DaemonSetSettled mirrors the bash "rollout settled" check:
// observedGeneration == generation, updatedNumberScheduled ==
// desiredNumberScheduled and numberReady == desiredNumberScheduled.
func DaemonSetSettled(ds *appsv1.DaemonSet) bool {
	return ds.Status.ObservedGeneration == ds.Generation &&
		ds.Status.UpdatedNumberScheduled == ds.Status.DesiredNumberScheduled &&
		ds.Status.NumberReady == ds.Status.DesiredNumberScheduled
}

// PodReadyCond reports whether the pod's Ready condition is True.
func PodReadyCond(p *corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// PodSpecHasContainer reports whether the pod spec carries a container
// named name. The pinned patchers' strategic-merge patches merge
// containers by name and cannot create one (a name-only entry has no
// image and the apiserver rejects the pod spec), so a missing
// container must be a skip, not a patch.
func PodSpecHasContainer(ps *corev1.PodSpec, name string) bool {
	for i := range ps.Containers {
		if ps.Containers[i].Name == name {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Replica math.
// ---------------------------------------------------------------------------

// ProportionalReplicas is the cluster-proportional-autoscaler
// "linear" formula with includeUnschedulableNodes=true — every Node
// object counts, cordoned or not:
//
//	replicas = max(minReplicas, ceil(totalNodes / nodesPerReplica))
//
// nodesPerReplica<=0 is clamped to 1 — a 0 divisor would otherwise
// mean "one replica per node" anyway under the CPA semantics.
func ProportionalReplicas(totalNodes, minReplicas, nodesPerReplica int) int32 {
	if nodesPerReplica <= 0 {
		nodesPerReplica = 1
	}
	n := (totalNodes + nodesPerReplica - 1) / nodesPerReplica
	if n < minReplicas {
		n = minReplicas
	}
	return int32(n)
}

// ---------------------------------------------------------------------------
// Unstructured Ready-condition helpers (CRD objects read via the
// dynamic client — helmrelease-unlocker, externalsecret-nudge,
// certmanager-reaper).
// ---------------------------------------------------------------------------

// ReadyCond returns the Ready condition's status and message for an
// unstructured object ("", "" when absent or malformed).
func ReadyCond(obj *unstructured.Unstructured) (status, message string) {
	for _, c := range ReadyConds(obj) {
		if c["type"] != "Ready" {
			continue
		}
		s, _ := c["status"].(string)
		m, _ := c["message"].(string)
		return s, m
	}
	return "", ""
}

// ReadySince returns the Ready condition's lastTransitionTime —
// how long the object has been in its current Ready state.
func ReadySince(obj *unstructured.Unstructured) (time.Time, bool) {
	for _, c := range ReadyConds(obj) {
		if c["type"] != "Ready" {
			continue
		}
		ts, _ := c["lastTransitionTime"].(string)
		t, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			return time.Time{}, false
		}
		return t, true
	}
	return time.Time{}, false
}

// ReadyConds extracts .status.conditions as maps (empty on absence).
func ReadyConds(obj *unstructured.Unstructured) []map[string]any {
	raw, found, err := unstructured.NestedSlice(obj.Object, "status", "conditions")
	if err != nil || !found {
		return nil
	}
	out := make([]map[string]any, 0, len(raw))
	for _, c := range raw {
		if m, ok := c.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Cluster Maintenance Mutex (2.7) — the shared form of the check the
// descheduler-storm-gate and concourse-workdir-janitor each carry a
// copy of: remediation that could disturb a drain/upgrade in flight
// defers while ANY signal holds.
// ---------------------------------------------------------------------------

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
