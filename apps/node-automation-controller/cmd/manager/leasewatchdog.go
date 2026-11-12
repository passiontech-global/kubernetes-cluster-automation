// leasewatchdog.go — the LeaseLossWatchdog: a leader-gated runnable
// that polls the election Lease directly and, the moment a FOREIGN
// holder appears, stops the whole manager instead of waiting for
// client-go's renew loop to notice.
//
// Why this exists: with the deployment-sized leases
// (180s/120s/5s) a replica that lost the Lease — e.g. the standby's
// LeaseLossWatchdog preemptor shortened a "dead" holder's lease and
// Standby B acquired it while the old leader was only partitioned,
// not dead — would otherwise keep running all 32 leader-gated
// modules until its own renew conflict surfaced, an
// Active-Active Split-Brain window measured in tens of seconds.
// A direct GET every 5s with a 3s timeout bounds that window to one
// poll interval: foreign holder → leaseStolen.Store(true) (the
// releaseGuardedLock then refuses the deferred tryRelease write) +
// cancel() on the manager's work context, which drains every
// runnable group and exits the process so the replica rejoins as a
// standby.
//
// NeedLeaderElection stays true (the default for a plain Runnable):
// only the replica that believes it leads may run this — on a
// standby the lease holder is legitimately "foreign" and would trip
// the watchdog instantly.
package main

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	// leaseWatchInterval is the poll cadence — plan-sized to catch a
	// stolen lease well inside the smallest sane LeaseDuration while
	// staying a trivial read rate (one GET per 5s per leader).
	leaseWatchInterval = 5 * time.Second
	// leaseWatchTimeout bounds each GET on probeCS so a hung
	// apiserver cannot stall the watchdog past its own interval.
	leaseWatchTimeout = 3 * time.Second
)

// leaseLossWatchdog polls the leader-election Lease and cancels the
// manager's work context when another identity holds it.
type leaseLossWatchdog struct {
	cs        kubernetes.Interface
	namespace string
	// selfID is the resource lock's Identity() — the hostname_uuid
	// the leader writes into HolderIdentity on every renew.
	selfID string
	// stolen is shared with releaseGuardedLock — set BEFORE cancel so
	// the deferred release write is already refused when the
	// elector's tryRelease runs during shutdown.
	stolen *atomic.Bool
	// cancel stops the whole manager (work context wrapping
	// SetupSignalHandler) — every runnable group drains on ctx.Done.
	cancel context.CancelFunc
	log    logr.Logger
}

// NeedLeaderElection reports true explicitly: this runnable must
// only run while THIS replica holds the lease — on a standby the
// foreign holder is the legitimate leader, not a theft.
func (w *leaseLossWatchdog) NeedLeaderElection() bool { return true }

func (w *leaseLossWatchdog) Start(ctx context.Context) error {
	ticker := time.NewTicker(leaseWatchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if w.lostToForeignHolder(ctx) {
				w.log.Info("leader lease held by another identity — "+
					"stopping manager work (split-brain guard)",
					"self", w.selfID)
				w.stolen.Store(true)
				w.cancel()
				return nil
			}
		}
	}
}

// lostToForeignHolder reports whether the Lease's current holder is
// a non-empty identity other than ours. Read failures are NOT loss
// evidence — an unreachable apiserver already fails the renew path
// on its own schedule, and cancelling on a transient GET error
// would needlessly bounce a healthy leader. Only a definitive
// foreign HolderIdentity trips the watchdog; a missing Lease or an
// empty holder is "not stolen" (our next renew re-acquires).
func (w *leaseLossWatchdog) lostToForeignHolder(ctx context.Context) bool {
	gctx, cancel := context.WithTimeout(ctx, leaseWatchTimeout)
	defer cancel()
	lease, err := w.cs.CoordinationV1().Leases(w.namespace).Get(
		gctx, leaderElectionID, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		return false
	case err != nil:
		w.log.V(1).Info("lease watchdog read failed — not loss evidence",
			"error", err.Error())
		return false
	}
	// HolderIdentity is *string — nil and "" both mean "no holder".
	if lease.Spec.HolderIdentity == nil {
		return false
	}
	holder := *lease.Spec.HolderIdentity
	return holder != "" && holder != w.selfID
}

// compile-time shape check: the watchdog is a leader-gated runnable.
var _ interface {
	Start(context.Context) error
	NeedLeaderElection() bool
} = (*leaseLossWatchdog)(nil)
