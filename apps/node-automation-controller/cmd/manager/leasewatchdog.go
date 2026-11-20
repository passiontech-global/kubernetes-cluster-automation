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
// Self-fencing: the same GET stream also bounds the OTHER split-
// brain shape — an apiserver partition where the leader can neither
// renew NOR read the Lease. lastVerified only advances on a read
// confirming holder == selfID; after selfFenceDuration(renewDeadline)
// (3/4 of RenewDeadline, e.g. 90s for 120s RenewDeadline or 7.5s for
// the 10s default) of inconclusive reads the leader fences itself
// rather than ride out an unverifiable hold indefinitely. On
// inconclusive self-fence, stolen stays false so releaseGuardedLock
// still checks the live Lease during drain and releases cleanly if
// still self-held (avoiding a 180s blackout when connectivity recovers
// mid-shutdown), while refusing release if a foreign holder took over.
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
	// defaultRenewDeadline mirrors controller-runtime's 10s default
	// when -leader-elect-renew-deadline is unset (0).
	defaultRenewDeadline = 10 * time.Second
	// leaseRenewStaleAfter bounds how old a self-held Lease's
	// RenewTime may be before the hold stops counting as
	// verified. HolderIdentity alone is not proof of a LIVE hold:
	// a replica whose renew WRITES fail keeps reading
	// holder==self until LeaseDuration expiry while every standby
	// waits out the full 180s. The deployment renews every
	// RetryPeriod=5s, so 30s of RenewTime staleness is six missed
	// renews — far past jitter, far inside the lease term.
	leaseRenewStaleAfter = 30 * time.Second
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
	// interval overrides leaseWatchInterval when > 0 (tests).
	interval time.Duration
	// fenceAfter overrides selfFenceDuration(renewDeadline) when > 0 (tests).
	fenceAfter time.Duration
	// renewDeadline sizes the inconclusive self-fence window
	// proportionally (3/4 of RenewDeadline, preserving Nebula blip
	// tolerance when configured with e.g. 120s).
	renewDeadline time.Duration
}

// selfFenceDuration scales the inconclusive self-fence horizon to
// 3/4 of renewDeadline (normalizing <=0 to defaultRenewDeadline=10s,
// floored at 1s). At the deployment's 120s RenewDeadline this yields
// 90s (worst-case 98s detection + 5s drain < 120s), preserving Nebula
// dataplane blip tolerance while still stepping down before
// RenewDeadline/LeaseDuration expire.
func selfFenceDuration(renewDeadline time.Duration) time.Duration {
	if renewDeadline <= 0 {
		renewDeadline = defaultRenewDeadline
	}
	return max(renewDeadline*3/4, time.Second)
}

// NeedLeaderElection reports true explicitly: this runnable must
// only run while THIS replica holds the lease — on a standby the
// foreign holder is the legitimate leader, not a theft.
func (w *leaseLossWatchdog) NeedLeaderElection() bool { return true }

func (w *leaseLossWatchdog) Start(ctx context.Context) error {
	iv := w.interval
	if iv <= 0 {
		iv = leaseWatchInterval
	}
	fence := w.fenceAfter
	if fence <= 0 {
		fence = selfFenceDuration(w.renewDeadline)
	}
	// lastVerified is the self-fencing clock: the last poll that
	// read the Lease AND confirmed holder == selfID. It starts
	// "now" — this runnable only runs once the replica holds the
	// lease, so the first fence window is a full fenceAfter of
	// grace for the apiserver to answer.
	lastVerified := time.Now()
	ticker := time.NewTicker(iv)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			switch w.pollLease(ctx) {
			case leaseForeign:
				w.log.Info("leader lease held by another identity — "+
					"stopping manager work (split-brain guard)",
					"self", w.selfID)
				if w.stolen != nil {
					w.stolen.Store(true)
				}
				w.cancel()
				return nil
			case leaseSelf:
				lastVerified = time.Now()
			default: // leaseInconclusive — unverifiable, not proven theft
				if elapsed := time.Since(lastVerified); elapsed >= fence {
					w.log.Info("leader lease unverifiable for "+
						fence.String()+" — self-fencing "+
						"(split-brain guard)",
						"self", w.selfID,
						"unverified_for", elapsed.String())
					// Do NOT set w.stolen here: leaseInconclusive
					// has not proven a foreign holder. Leaving
					// stolen=false lets releaseGuardedLock perform
					// a live Get during shutdown drain — releasing
					// if still self-held (avoiding a 180s blackout)
					// and refusing if someone else took over.
					w.cancel()
					return nil
				}
			}
		}
	}
}

// leaseState classifies one Lease GET for the watchdog loop.
type leaseState int

const (
	// leaseInconclusive: the read failed, the Lease is missing, or
	// the holder is empty — never loss evidence by itself, but it
	// does not refresh the self-fencing clock either.
	leaseInconclusive leaseState = iota
	// leaseSelf: holder == selfID — this replica's hold is verified.
	leaseSelf
	// leaseForeign: a non-empty holder other than ours.
	leaseForeign
)

// pollLease reads the election Lease once and classifies the
// result. Read failures and empty/missing holders are
// leaseInconclusive — an unreachable apiserver already fails the
// renew path on its own schedule, so a transient GET error must
// not bounce a healthy leader; the self-fence clock bounds how
// long inconclusive reads may persist before the leader steps
// down anyway. Only a definitive foreign HolderIdentity is
// immediate loss evidence.
func (w *leaseLossWatchdog) pollLease(ctx context.Context) leaseState {
	gctx, cancel := context.WithTimeout(ctx, leaseWatchTimeout)
	defer cancel()
	lease, err := w.cs.CoordinationV1().Leases(w.namespace).Get(
		gctx, leaderElectionID, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		return leaseInconclusive
	case err != nil:
		w.log.V(1).Info("lease watchdog read failed — not loss evidence",
			"error", err.Error())
		return leaseInconclusive
	}
	// HolderIdentity is *string — nil and "" both mean "no holder".
	if lease.Spec.HolderIdentity == nil {
		return leaseInconclusive
	}
	holder := *lease.Spec.HolderIdentity
	switch {
	case holder == "":
		return leaseInconclusive
	case holder == w.selfID:
		// A stale RenewTime means our renew writes are not
		// landing — the recorded identity is coasting on the
		// lease term, not on live renewals. Classify
		// inconclusive so the self-fence clock bounds it
		// instead of refreshing lastVerified on a dead hold.
		if lease.Spec.RenewTime == nil ||
			time.Since(lease.Spec.RenewTime.Time) > leaseRenewStaleAfter {
			return leaseInconclusive
		}
		return leaseSelf
	default:
		return leaseForeign
	}
}

// compile-time shape check: the watchdog is a leader-gated runnable.
var _ interface {
	Start(context.Context) error
	NeedLeaderElection() bool
} = (*leaseLossWatchdog)(nil)
