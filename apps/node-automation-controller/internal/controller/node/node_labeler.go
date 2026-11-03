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
package node

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/controller/shared"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
)

const workerRoleLabel = "node-role.kubernetes.io/worker"

type nodeLabeler struct {
	cs         kubernetes.Interface
	configPath string
}

// SetupNodeLabeler wires the node-labeler reconciler. configPath is the
// labels.txt file (default /etc/node-labeler/labels.txt).
func SetupNodeLabeler(mgr ctrl.Manager, cs kubernetes.Interface, configPath string) error {
	r := &nodeLabeler{cs: cs, configPath: configPath}
	return ctrl.NewControllerManagedBy(mgr).
		Named("node-labeler").
		// Watches with a single fixed workqueue key, not For(): the
		// reconcile ignores req.Name and always sweeps the whole
		// cluster, so per-node keys only produced N duplicate queued
		// requests + N independent RequeueAfter timers per informer
		// sync. One key collapses both to a single sweep (see
		// shared.SweepRequests). Predicate semantics are unchanged.
		Watches(&corev1.Node{},
			handler.EnqueueRequestsFromMapFunc(shared.SweepRequests("node-labeler-sweep")),
			builder.WithPredicates(predicate.Funcs{
				CreateFunc:  func(event.CreateEvent) bool { return true },
				DeleteFunc:  func(event.DeleteEvent) bool { return true },
				GenericFunc: func(event.GenericEvent) bool { return true },
				// bash jqFilter='.metadata.labels' — only label drift fires.
				UpdateFunc: func(e event.UpdateEvent) bool {
					if e.ObjectOld == nil || e.ObjectNew == nil {
						return false
					}
					return !reflect.DeepEqual(e.ObjectOld.GetLabels(), e.ObjectNew.GetLabels())
				},
			})).
		Complete(r)
}

func (r *nodeLabeler) Reconcile(ctx context.Context, _ reconcile.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	res := ctrl.Result{RequeueAfter: 30 * time.Minute}

	// (a) worker role on every non-control-plane node lacking it.
	nodes, err := shared.ListNodes(ctx, r.cs)
	if err != nil {
		metrics.IncError("node-labeler")
		return ctrl.Result{}, fmt.Errorf("list nodes: %w", err)
	}
	labeled := 0
	for i := range nodes {
		n := &nodes[i]
		if shared.IsControlPlane(n) {
			continue
		}
		if _, ok := n.Labels[workerRoleLabel]; ok {
			continue
		}
		if err := shared.PatchNodeLabels(ctx, r.cs, n.Name, map[string]string{workerRoleLabel: ""}); err != nil {
			// bash exit "$failed" here — the metric must surface a
			// persistent patch failure even though the sweep continues.
			metrics.IncError("node-labeler")
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
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
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
			node, err := r.cs.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				// Likely a deleted node still listed in labels.txt —
				// warn and move on, never hot-loop (bash exit 0).
				log.Info("WARN: cannot get node", "node", name, "label", label, "error", err)
				continue
			}
			if node.Labels[key] == val {
				continue
			}
			if err := shared.PatchNodeLabels(ctx, r.cs, name, map[string]string{key: val}); err != nil {
				metrics.IncError("node-labeler")
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
