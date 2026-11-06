package hubsync

import (
	"context"
	"fmt"
	"time"

	coordv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coordclient "k8s.io/client-go/kubernetes/typed/coordination/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

// lease is a minimal coordinationv1 Lease acquire/renew loop —
// deliberately not client-go's leaderelection package: hubsync needs
// only "am I the holder" gating, not callback-driven leader lifecycle.
// Conventions follow client-go: LeaseDurationSeconds advertises how
// long a dead holder's claim is honoured, RenewTime is the last
// holder heartbeat, LeaseTransitions counts handoffs.
type lease struct {
	leases   coordclient.LeaseInterface
	name     string
	identity string
	duration time.Duration
	now      timex.Clock
}

// leaseOpTimeout bounds every single Lease API call. Without it a
// hung apiserver TCP connection (conntrack-blackhole, apiserver
// wedge) parks renew on the bare supervisor ctx — s.held stays true
// while the real Lease lapses and a second pod takes over, leaving
// two holders converging the same targets (split-brain).
const leaseOpTimeout = 10 * time.Second

// leaseGet/leaseCreate/leaseUpdate run one Lease call under
// leaseOpTimeout — a cancelled parent ctx still passes through.
func (l *lease) leaseGet(ctx context.Context) (*coordv1.Lease, error) {
	octx, cancel := context.WithTimeout(ctx, leaseOpTimeout)
	defer cancel()
	return l.leases.Get(octx, l.name, metav1.GetOptions{})
}

func (l *lease) leaseCreate(ctx context.Context, lease *coordv1.Lease) error {
	octx, cancel := context.WithTimeout(ctx, leaseOpTimeout)
	defer cancel()
	_, err := l.leases.Create(octx, lease, metav1.CreateOptions{})
	return err
}

func (l *lease) leaseUpdate(ctx context.Context, lease *coordv1.Lease) error {
	octx, cancel := context.WithTimeout(ctx, leaseOpTimeout)
	defer cancel()
	_, err := l.leases.Update(octx, lease, metav1.UpdateOptions{})
	return err
}

// renew performs one acquire/renew step and reports whether the
// caller holds the lease after it, plus the moment the claim lapses
// (our fresh RenewTime + the advertised duration — the same window a
// competing pod waits before takeover). API errors and Update
// conflicts are logged by the caller and simply yield "not held" —
// the next RenewInterval tick retries.
func (l *lease) renew(ctx context.Context) (bool, time.Time, error) {
	now := l.now()
	durSec := int32(l.duration.Round(time.Second).Seconds())
	if durSec <= 0 {
		durSec = 1
	}

	cur, err := l.leaseGet(ctx)
	switch {
	case apierrors.IsNotFound(err):
		mt := metav1.NewMicroTime(now)
		err = l.leaseCreate(ctx, &coordv1.Lease{
			ObjectMeta: metav1.ObjectMeta{Name: l.name},
			Spec: coordv1.LeaseSpec{
				HolderIdentity:       &l.identity,
				LeaseDurationSeconds: &durSec,
				AcquireTime:          &mt,
				RenewTime:            &mt,
			},
		})
		if err != nil {
			// Another pod won the create race — we're not the holder.
			return false, time.Time{}, err
		}
		return true, mt.Time.Add(time.Duration(durSec) * time.Second), nil
	case err != nil:
		return false, time.Time{}, err
	}

	holder := ""
	if cur.Spec.HolderIdentity != nil {
		holder = *cur.Spec.HolderIdentity
	}
	expired := true
	if cur.Spec.RenewTime != nil && cur.Spec.LeaseDurationSeconds != nil {
		expired = now.After(cur.Spec.RenewTime.Time.Add(
			time.Duration(*cur.Spec.LeaseDurationSeconds) * time.Second))
	}

	mt := metav1.NewMicroTime(now)
	expiresAt := mt.Time.Add(time.Duration(durSec) * time.Second)
	switch {
	case holder == l.identity:
		// Heartbeat — also adopt a changed configured duration,
		// which would otherwise only take effect on takeover.
		cur.Spec.RenewTime = &mt
		if cur.Spec.LeaseDurationSeconds == nil ||
			*cur.Spec.LeaseDurationSeconds != durSec {
			cur.Spec.LeaseDurationSeconds = &durSec
		}
		if err := l.leaseUpdate(ctx, cur); err != nil {
			return false, time.Time{}, fmt.Errorf("renew lease: %w", err)
		}
		return true, expiresAt, nil
	case expired || holder == "":
		// Take over a dead/absent holder — optimistic concurrency on
		// resourceVersion arbitrates simultaneous takeovers.
		trans := int32(1)
		if cur.Spec.LeaseTransitions != nil {
			trans = *cur.Spec.LeaseTransitions + 1
		}
		cur.Spec.HolderIdentity = &l.identity
		cur.Spec.LeaseDurationSeconds = &durSec
		cur.Spec.AcquireTime = &mt
		cur.Spec.RenewTime = &mt
		cur.Spec.LeaseTransitions = &trans
		if err := l.leaseUpdate(ctx, cur); err != nil {
			return false, time.Time{}, fmt.Errorf("acquire lease: %w", err)
		}
		return true, expiresAt, nil
	default:
		return false, time.Time{}, nil
	}
}

// renewLease wraps lease.renew: keeps s.held state + the claim's
// expiry, clears the synced-once latch on loss, logs transient errors.
func (s *Syncer) renewLease(ctx context.Context) bool {
	held, expiresAt, err := s.lease.renew(ctx)
	if err != nil {
		s.cfg.Log.Warn("hubsync: lease renew failed — retrying next tick",
			"lease", s.cfg.LeaseNamespace+"/"+s.cfg.LeaseName, "error", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.held && held {
		s.cfg.Log.Info("hubsync: lease acquired",
			"lease", s.cfg.LeaseNamespace+"/"+s.cfg.LeaseName)
	}
	if s.held && !held {
		s.cfg.Log.Warn("hubsync: lost lease",
			"lease", s.cfg.LeaseNamespace+"/"+s.cfg.LeaseName)
	}
	if !held {
		s.syncedWhileHeld = false
		s.leaseExpiresAt = time.Time{}
	} else {
		s.leaseExpiresAt = expiresAt
	}
	s.held = held
	return held
}
