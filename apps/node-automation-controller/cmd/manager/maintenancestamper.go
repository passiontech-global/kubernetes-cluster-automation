// maintenancestamper.go — the cluster-maintenance-stamper runnable:
// the dedicated WRITE half of the L1↔L3 maintenance coordination.
//
// kube.Verdict.Active is READ-ONLY — heal gates consult it dozens
// of times per sweep and a verdict query must never patch Nodes.
// This runnable is therefore the ONLY writer of
// passiontech.dev/cluster-maintenance-until: every 30s it resolves
// the active maintenance targets and converges each node's stamp
// toward that set — stamping covered nodes (cluster upgrade → all
// nodes; fresh cordon / kured lock / SNR-NHC-FAR target → that
// node only) and removing controller-owned stamps from nodes whose
// maintenance ended, so node-host-agents never sit paused on a
// stale window.
//
// It is a plain Runnable: NeedLeaderElection defaults to true, so it
// only runs on the lease holder under --leader-elect, and runs
// unconditionally in single-replica mode (no election = always
// leader). The first pass runs IMMEDIATELY on Start — waiting one
// full interval after leader acquisition would leave a maintenance
// window that opened during failover unstamped for up to 30s, and
// the agent's ~30s annotation cache would not see it until the
// second pass. Stamping is best-effort — StampMaintenanceTargets
// swallows per-source read failures and the refresh floor suppresses
// rewrite churn, so a transient apiserver flap costs one skipped
// pass, never a crash.
package main

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/maintenance"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

// maintenanceStampInterval is the stamper cadence — half the agent's
// ~60s annotation-cache horizon, so a stamp written this pass is
// still fresh when the agent's next read lands.
const maintenanceStampInterval = 30 * time.Second

// maintenanceStamperRunnable periodically resolves the active
// maintenance targets and converges each node's
// cluster-maintenance-until annotation toward that set.
type maintenanceStamperRunnable struct {
	cs  kubernetes.Interface
	dyn dynamic.Interface
	// nodeReader is the manager's cache-backed client for the node
	// census (kube.ListNodesCached) — nil in tests falls back to the
	// direct clientset read.
	nodeReader kube.CachedNodeReader
	// now is the clock seam — zero value is system time; tests pin
	// it instead of sleeping through the ticker.
	now shared.Clock
	log logr.Logger
}

func (r *maintenanceStamperRunnable) Start(ctx context.Context) error {
	ticker := time.NewTicker(maintenanceStampInterval)
	defer ticker.Stop()
	// First pass before the first tick: leader acquisition itself
	// can be the moment maintenance state changed (the old leader
	// may have held the only stamp writer), so the window must not
	// wait a full interval to converge.
	r.stamp(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			r.stamp(ctx)
		}
	}
}

// stamp runs one convergence pass. Live reads on purpose — NOT the
// sweep census: this runnable is the freshness backstop for exactly
// the mid-sweep changes a memoized census cannot see.
func (r *maintenanceStamperRunnable) stamp(ctx context.Context) {
	maintenance.StampMaintenanceTargets(ctx, r.cs, r.dyn, r.nodeReader, r.now.Now())
}
