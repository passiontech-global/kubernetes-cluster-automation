// setup.go — the deadNodeSweeper wiring: the module struct (clients,
// seams, ledgers) and the registry Setup row. Pure extraction from
// dead_node_sweeper.go — the sweep driver and its safety story live in
// dead_node_sweeper.go / doc.go.
package deadnodesweeper

import (
	"context"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

type deadNodeSweeper struct {
	cs  kubernetes.Interface
	dyn dynamic.Interface
	// nodeReader backs ListNodesCached — the informer-backed node
	// census; the destructive confirm (UntaintNode/TaintNode re-Get)
	// stays on the direct clientset. Nil (test fixtures) falls back
	// to ListNodes.
	nodeReader kube.CachedNodeReader
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the periodic's name and every IncError label
	// come from one place.
	queue string
	// now is the wall-clock seam so tests can pin the stuck-pod and
	// Unknown-window verdicts. nil reads as system time — the
	// standard unarmed-seam convention.
	now shared.Clock
	// Probe seam — same trick as kubeletReaper: the node/proxy REST
	// path cannot be served by the fake clientset, so tests stub the
	// healthz outcome per node.
	probeFn func(ctx context.Context, nodeName string) (bool, error)
	// statefulSkipEmitted is the GaugeLedger for
	// DeadNodeUnfencedStatefulSkipped: a node Set(1)'d by the
	// split-brain gate is re-emitted every sweep it still holds
	// stateful volumes/pods, and the tuple leaves the ledger when the
	// fence or the recovery untaint DeleteLabelValues's it — so a
	// resolved skip flag cannot pin a stale 1 past the sweep that
	// last verified it. Zero value ready (same lazy-arm convention as
	// the now seam).
	statefulSkipEmitted state.GaugeLedger[string]
	// fencedWithoutSNREmitted is the same carry-forward ledger for
	// the DeadNodeFencedWithoutSNRTotal counter (key
	// node\x00has_volumes): fenceNode Emits the tuple it Inc'd, each
	// sweep re-emits the tuples whose node the census still lists,
	// and the sweep's Prune retires the series once the node is gone
	// — a counter Inc is never undone by its own code path, so
	// without this the vec grows monotonically on node-pool rotation.
	// Zero value ready.
	fencedWithoutSNREmitted state.GaugeLedger[string]
}

// Setup registers the 5-minute sweep.
func Setup(d shared.Deps) error {
	return shared.SetupNoConfig(d, func() error {
		s := &deadNodeSweeper{cs: d.CS, dyn: d.Dyn, queue: d.Name,
			nodeReader: d.CachedClient(), now: shared.SystemClock}
		s.probeFn = s.probe
		return shared.AddPeriodic(d.Mgr, s.queue, 5*time.Minute, s.run)
	})
}
