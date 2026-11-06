// node-labeler — port of hooks/25-node-labeler-workload.sh.
//
// Re-asserts node labels that silently drift after redeploys
// (original incident: passiontech.dev/workload=app vanished and
// nodeSelector pods pended en masse). Each run does a full sweep:
//  1. node-role.kubernetes.io/worker on every non-control-plane node —
//     SelfNodeRemediation peer election needs it (medik8s #268).
//  2. Labels listed in configPath (mounted from CM
//     node-labeler-workload): "<key=val> <node1> <node2> ..." per line.
//
// Per-node failures only WARN — bash exits 0 deliberately so a deleted
// node still listed in labels.txt cannot hot-loop the queue; the 30m
// sweep retries.
package nodelabeler

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/envx"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

const workerRoleLabel = "node-role.kubernetes.io/worker"

type nodeLabeler struct {
	cs kubernetes.Interface
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the controller name, the registration log and
	// every IncError label come from one place.
	queue      string
	configPath string
}

// The watch wiring below installs these package-level units
// verbatim — tests exercise the exact predicate/mapfunc the
// controller runs instead of introspecting controller-runtime
// internals.

// nodeSweepRequests collapses every Node event onto the single fixed
// sweep key (see shared.SweepRequests).
var nodeSweepRequests = shared.SweepRequests("node-labeler-sweep")

// nodeLabelChanges is the Node watch predicate — the bash
// jqFilter='.metadata.labels': only label drift fires, everything
// else is dropped.
var nodeLabelChanges = predicate.Funcs{
	CreateFunc:  func(event.CreateEvent) bool { return true },
	DeleteFunc:  func(event.DeleteEvent) bool { return true },
	GenericFunc: func(event.GenericEvent) bool { return true },
	UpdateFunc: func(e event.UpdateEvent) bool {
		// client.Object is an interface: == nil cannot
		// catch a typed-nil pointer (GetLabels would
		// panic on it). The ok-comma assert siblings use
		// covers both — a nil interface fails the assert,
		// a typed nil lands in oldN/newN.
		oldN, ok1 := e.ObjectOld.(*corev1.Node)
		newN, ok2 := e.ObjectNew.(*corev1.Node)
		if !ok1 || !ok2 || oldN == nil || newN == nil {
			return false // missing objects never fire
		}
		return !reflect.DeepEqual(oldN.GetLabels(), newN.GetLabels())
	},
}

// Setup wires the node-labeler reconciler. configPath is the
// labels.txt file (default /etc/node-labeler/labels.txt).
func Setup(d shared.Deps) error {
	configPath := envx.Getenv("NODE_LABELER_CONFIG_PATH",
		"/etc/node-labeler/labels.txt")
	logf.Log.WithName(d.Name).Info("registered", "configPath", configPath)
	r := &nodeLabeler{cs: d.CS, queue: d.Name, configPath: configPath}
	return ctrl.NewControllerManagedBy(d.Mgr).
		Named(d.Name).
		// Watches with a single fixed workqueue key, not For(): the
		// reconcile ignores req.Name and always sweeps the whole
		// cluster, so per-node keys only produced N duplicate queued
		// requests + N independent RequeueAfter timers per informer
		// sync. One key collapses both to a single sweep (see
		// shared.SweepRequests). Predicate semantics are unchanged.
		Watches(&corev1.Node{},
			handler.EnqueueRequestsFromMapFunc(nodeSweepRequests),
			builder.WithPredicates(nodeLabelChanges)).
		Complete(shared.CountReconcile(d.Name, r.Reconcile))
}

func (r *nodeLabeler) Reconcile(ctx context.Context, _ reconcile.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	res := ctrl.Result{RequeueAfter: 30 * time.Minute}

	// (a) worker role on every non-control-plane node lacking it.
	nodes, err := kube.ListNodes(ctx, r.cs)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("list nodes: %w", err)
	}
	// The listed snapshot doubles as the labels.txt lookup index —
	// a per-entry Nodes().Get would N+1 the apiserver for a file
	// that names every node in the cluster.
	byName := make(map[string]*corev1.Node, len(nodes))
	labeled := 0
	for i := range nodes {
		n := &nodes[i]
		byName[n.Name] = n
		if kube.IsControlPlane(n) {
			continue
		}
		if _, ok := n.Labels[workerRoleLabel]; ok {
			continue
		}
		if err := kube.PatchNodeLabels(ctx, r.cs, n.Name, map[string]string{workerRoleLabel: ""}); err != nil {
			// bash exit "$failed" here — the metric must surface a
			// persistent patch failure even though the sweep continues.
			metrics.IncError(r.queue)
			log.Info("WARN: cannot label worker role on node", "node", n.Name, "error", err)
			continue
		}
		labeled++
		log.Info("labeled worker role", "node", n.Name, "label", workerRoleLabel+"=")
	}

	// (b) labels.txt — re-read every run: the ConfigMap volume refreshes
	// without a pod restart. Missing or empty file => nothing to do.
	data, err := os.ReadFile(r.configPath)
	if err != nil {
		// A missing file just means no ConfigMap is mounted on this
		// cluster — anything else (permissions, dangling symlink,
		// volume failure) silently disables file labels, so say so.
		if !os.IsNotExist(err) {
			log.Info("WARN: cannot read labels file — skipping file labels",
				"path", r.configPath, "error", err)
		}
		log.Info("sweep done", "labeled", labeled)
		return res, nil
	}
	if len(data) == 0 {
		log.Info("sweep done", "labeled", labeled)
		return res, nil
	}
	// (c) each line: <key=val> <node1> <node2> ...
	for _, line := range strings.Split(string(data), "\n") {
		// '#' starts a comment anywhere on the line — full-line
		// comments and trailing "n1 n2 # why" notes alike. Neither a
		// label key=value nor a node name can contain '#', so cutting
		// at the first one is unambiguous.
		line, _, _ = strings.Cut(line, "#")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		label := fields[0]
		key, val, hasEq := strings.Cut(label, "=")
		if !hasEq {
			// A bare "<token> <nodes>" line applies an empty-valued
			// label — almost always a ConfigMap typo, so flag it.
			log.Info("WARN: labels.txt line has no key=value — applying empty value",
				"line", line, "path", r.configPath)
		}
		for _, name := range fields[1:] {
			node, ok := byName[name]
			if !ok {
				// Likely a deleted node still listed in labels.txt —
				// warn and move on, never hot-loop (bash exit 0).
				// The run absorbs the miss (returns nil), so count it
				// here: a ghost entry that lingers for weeks would
				// otherwise stay invisible to alerting.
				metrics.IncError(r.queue)
				log.Info("WARN: node in labels.txt not found", "node", name, "label", label)
				continue
			}
			if node.Labels[key] == val {
				continue
			}
			if err := kube.PatchNodeLabels(ctx, r.cs, name, map[string]string{key: val}); err != nil {
				metrics.IncError(r.queue)
				log.Info("WARN: cannot label node", "node", name, "label", label, "error", err)
				continue
			}
			labeled++
			log.Info("labeled", "node", name, "label", label)
		}
	}
	log.Info("sweep done", "labeled", labeled)
	return res, nil
}
