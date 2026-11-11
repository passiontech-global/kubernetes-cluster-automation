// GC delete path for the cilium identity auditor: the four stacked
// v2 gates (gcEnabled handled by the caller, grace period, min age,
// node storm-gate) and the capped, UID-preconditioned deletes.
// split from cilium_identity_auditor.go (see its header for the module contract).
package ciliumidentityauditor

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/reap"
)

// gcOrphans is the v2 delete path: only orphans that satisfy BOTH the
// grace-period (orphaned across ≥2 sweeps) and min-age (object itself
// old enough to have had a fair chance at an endpoint) gates are
// eligible, and even then deletion only proceeds while every node is
// Ready — capped at ciliumGCMaxDelete per sweep.
func (a *ciliumIdentityAuditor) gcOrphans(ctx context.Context,
	orphans []string, idCreated map[string]time.Time,
	idUIDs map[string]types.UID, now time.Time) error {
	log := logf.FromContext(ctx)

	var eligible []string
	for _, name := range orphans {
		orphanedFor, _ := a.orphanFirstSeen.Seen(name, now)
		if orphanedFor < ciliumOrphanGracePeriod {
			continue // first seen this sweep or still inside grace
		}
		if created, ok := idCreated[name]; !ok || now.Sub(created) < ciliumOrphanMinAge {
			continue // too young — endpoint may not exist yet
		}
		eligible = append(eligible, name)
	}
	if len(eligible) == 0 {
		log.Info("GC: no orphans past grace+age gates yet",
			"orphans", len(orphans))
		return nil
	}

	// Storm gate: a NotReady (or absent) node can still be running
	// pods whose CiliumEndpoints are unsynced — deleting "orphans"
	// underneath them strips live workloads of network policy. No
	// nodes at all means the cluster is too broken to judge, so an
	// empty list aborts too rather than vacuously passing "all
	// Ready".
	nodes, err := kube.ListNodesCached(ctx, a.nodeReader, a.cs)
	if err != nil {
		return fmt.Errorf("list nodes: %w", err) // propagates to run()'s return — wrapper IncErrors
	}
	if len(nodes) == 0 {
		log.Info("GC SKIP: no nodes listed — cannot verify cluster health",
			"eligible", len(eligible))
		return nil
	}
	for i := range nodes {
		if !kube.NodeReady(&nodes[i]) {
			log.Info("GC SKIP: node not Ready — identities may still be live on it",
				"node", nodes[i].Name, "eligible", len(eligible))
			return nil
		}
	}

	// The cap bounds delete ATTEMPTS (failed deletes churn the
	// apiserver the same way) — leftover identities drain next sweep.
	deleted, failed, capped := reap.Sweep(ctx, log, eligible,
		reap.Options[string]{
			Cap: ciliumGCMaxDelete,
			LogTarget: func(log logr.Logger, name string) {
				orphanedFor, _ := a.orphanFirstSeen.Seen(name, now)
				log.Info("ACTION: GC orphaned CiliumIdentity",
					"identity", name,
					"orphanedFor", orphanedFor.Truncate(time.Minute))
			},
			Delete: func(ctx context.Context, name string) error {
				// UID precondition closes the list→delete TOCTOU: a
				// same-named identity recreated between the List above
				// and this Delete is not the orphan this sweep vetted
				// — the apiserver rejects it with a Conflict, reported
				// through OnError like the NotFound race below.
				uid := idUIDs[name]
				if err := a.dyn.Resource(ciliumIdentityGVR).
					Delete(ctx, name, kube.UIDDeleteOptions(uid, "")); err != nil {
					return err
				}
				metrics.CiliumIdentitiesCollectedTotal.Inc()
				return nil
			},
			OnError: func(log logr.Logger, name string, err error) {
				switch {
				case apierrors.IsNotFound(err):
					log.Info("SKIP: identity already gone — raced with cilium's own GC",
						"identity", name)
				case apierrors.IsConflict(err):
					log.Info("SKIP: identity recreated since the list — UID precondition fired",
						"identity", name)
				default:
					metrics.IncError(a.queue)
					log.Error(err, "identity delete failed", "identity", name)
				}
			},
		})
	if capped {
		log.Info("GC capped — remaining orphans drain next sweep",
			"cap", ciliumGCMaxDelete,
			"remaining", len(eligible)-deleted-failed)
	}
	log.Info("GC done", "eligible", len(eligible), "deleted", deleted)
	return nil
}
