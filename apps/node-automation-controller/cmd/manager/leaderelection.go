// leaderelection.go — the leader-election resource lock main()
// hands to ctrl.Options.LeaderElectionResourceLockInterface: the
// stock LeaseLock plus a release guard.
//
// The bug this closes: ReleaseOnCancel=true makes the OLD leader's
// deferred release() run tryRelease → Lock.Update with a
// LeaseDurationSeconds=1, empty-HolderIdentity record. When the
// LeaseLossWatchdog (leaderelect.Preemptor) has already shortened
// the dead leader's Lease and Standby B acquired it, the old
// leader's observed record is still stale-self — IsLeader() returns
// true and the release Update lands ON B's lease, wiping B's
// HolderIdentity. The lease then looks free, a third replica (or
// the same old leader) re-acquires, and the fleet flaps leaders.
// client-go's tryRelease re-Gets on conflict but IsLeader() reads
// the elector's own observedRecord — never refreshed by that Get —
// so the retry loop cannot see the new holder.
//
// The guard intercepts Update: a record with empty HolderIdentity
// is the release signature (renew always carries our identity), so
// before letting it through we re-Get the lease and skip the write
// when the current holder is someone else. The residual Get→Update
// window still exists, but a lost race now surfaces as a conflict
// on the fresh resourceVersion — and the retry's guard Get sees the
// new holder and stops instead of clobbering it.
package main

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/client-go/kubernetes"
	coordinationv1client "k8s.io/client-go/kubernetes/typed/coordination/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/tools/record"
)

// leaderElectionID is the Lease object name — shared by the resource
// lock, the LeaseLossWatchdog's GET, and ctrl.Options'
// LeaderElectionID so the three can never drift apart.
const leaderElectionID = "node-automation-controller.passiontech.dev"

// leaderClientConfig mirrors leaderelection.NewResourceLock's
// election-dedicated config: a copy carrying the "leader-election"
// user agent and a client timeout capped at
// max(effectiveRenewDeadline/2, 1s) so one hung request cannot eat
// the whole renew window. A non-positive deadline is the
// unset/zero case — it normalizes to the 10s default BEFORE the
// timeout math: the pre-fix `if renewDeadline > 0` guard left a
// zero deadline with an UNBOUNDED client timeout, so one hung
// apiserver request could wedge the renew loop instead of losing
// the lease and failing over. Split out so the normalization and
// the max() floor are unit-testable without building clients.
func leaderClientConfig(cfg *rest.Config,
	renewDeadline time.Duration) *rest.Config {

	elCfg := rest.AddUserAgent(rest.CopyConfig(cfg), "leader-election")
	if renewDeadline <= 0 {
		renewDeadline = 10 * time.Second
	}
	elCfg.Timeout = max(renewDeadline/2, time.Second)
	return elCfg
}

// buildLeaderLock constructs the Lease resource lock controller-
// runtime would have built internally (same leases type, same
// hostname_uuid identity convention, same RenewDeadline-derived
// client timeout), wrapped in releaseGuardedLock. Only called when
// leader election is on — the returned interface is ignored by
// ctrl.Options otherwise. stolen is the LeaseLossWatchdog's flag:
// once it observes a foreign holder it sets the flag and the guard
// refuses release writes unconditionally (the live-Get check stays
// as the fallback for the window before the watchdog's first pass).
func buildLeaderLock(cfg *rest.Config, scheme *runtime.Scheme,
	namespace string, renewDeadline time.Duration,
	stolen *atomic.Bool, done <-chan struct{}) (resourcelock.Interface, error) {

	elCfg := leaderClientConfig(cfg, renewDeadline)
	coreClient, err := corev1client.NewForConfig(elCfg)
	if err != nil {
		return nil, fmt.Errorf("leader-election core client: %w", err)
	}
	coordClient, err := coordinationv1client.NewForConfig(elCfg)
	if err != nil {
		return nil, fmt.Errorf("leader-election coordination client: %w", err)
	}
	cs, err := kubernetes.NewForConfig(elCfg)
	if err != nil {
		return nil, fmt.Errorf("leader-election clientset: %w", err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("leader-election identity: %w", err)
	}
	identity := hostname + "_" + string(uuid.NewUUID())

	// LeaderElection events on the Lease object stay live: the
	// broadcaster sink writes through the same clientset, bound per
	// event namespace (the Lease's).
	broadcaster := record.NewBroadcaster()
	broadcaster.StartRecordingToSink(leaseEventSink{cs: cs})
	// The broadcaster's writer goroutine outlives the lock otherwise —
	// Shutdown drains it when the work context cancels (manager stop /
	// leader loss), so a stopped manager never leaks the sink writer.
	go func() {
		<-done
		broadcaster.Shutdown()
	}()

	lock, err := resourcelock.New(resourcelock.LeasesResourceLock,
		namespace, leaderElectionID,
		coreClient, coordClient,
		resourcelock.ResourceLockConfig{
			Identity:      identity,
			EventRecorder: broadcaster.NewRecorder(scheme, corev1.EventSource{Component: "leader-election"}),
		})
	if err != nil {
		return nil, fmt.Errorf("leader-election resource lock: %w", err)
	}
	return &releaseGuardedLock{Interface: lock, stolen: stolen}, nil
}

// releaseGuardedLock wraps resourcelock.Interface with the
// release-write guard described in the file header.
type releaseGuardedLock struct {
	resourcelock.Interface
	// stolen mirrors the LeaseLossWatchdog's observation — when set,
	// a foreign holder is already proven and the release write is
	// refused without paying the guard Get.
	stolen *atomic.Bool
}

// Update intercepts release-shaped records (empty HolderIdentity —
// renew writes always carry ours) and refuses to write when the
// lease's current holder is a different identity.
func (l *releaseGuardedLock) Update(ctx context.Context,
	rec resourcelock.LeaderElectionRecord) error {
	if rec.HolderIdentity == "" {
		if l.stolen != nil && l.stolen.Load() {
			return nil // watchdog proved a foreign holder — never release-write
		}
		cur, _, err := l.Interface.Get(ctx)
		switch {
		case apierrors.IsNotFound(err):
			return nil // lease already gone — nothing to release
		case err != nil:
			return err
		case cur.HolderIdentity != "" && cur.HolderIdentity != l.Interface.Identity():
			return nil // someone else leads now — do NOT clobber their record
		}
	}
	return l.Interface.Update(ctx, rec)
}

// leaseEventSink adapts a clientset to record.EventSink — events
// land in the namespace the event object itself carries (the
// Lease's), so no namespace is bound at construction. Update and
// Patch delegate to Create semantics: leader-election events are
// fire-and-forget hints, and client-go's broadcaster only Calls
// them for aggregation edge cases the LeaseLock never triggers.
// Every write carries a 5s timeout: the sink is invoked on the
// broadcaster's goroutine with no caller ctx, and an unbounded
// apiserver stall here would leak a goroutine per event — the same
// hung-request class the lease client's max(RenewDeadline/2, 1s)
// timeout exists to bound.
type leaseEventSink struct {
	cs kubernetes.Interface
}

// leaseEventSinkTimeout bounds every sink write — a var (not a
// const) so tests can shrink it instead of sleeping 5s.
var leaseEventSinkTimeout = 5 * time.Second

func (s leaseEventSink) Create(e *corev1.Event) (*corev1.Event, error) {
	ctx, cancel := context.WithTimeout(context.Background(), leaseEventSinkTimeout)
	defer cancel()
	return s.cs.CoreV1().Events(e.Namespace).Create(
		ctx, e, metav1.CreateOptions{})
}

func (s leaseEventSink) Update(e *corev1.Event) (*corev1.Event, error) {
	ctx, cancel := context.WithTimeout(context.Background(), leaseEventSinkTimeout)
	defer cancel()
	return s.cs.CoreV1().Events(e.Namespace).Update(
		ctx, e, metav1.UpdateOptions{})
}

func (s leaseEventSink) Patch(oldEvent *corev1.Event, data []byte) (*corev1.Event, error) {
	ctx, cancel := context.WithTimeout(context.Background(), leaseEventSinkTimeout)
	defer cancel()
	return s.cs.CoreV1().Events(oldEvent.Namespace).Patch(
		ctx, oldEvent.Name, types.MergePatchType, data,
		metav1.PatchOptions{})
}
