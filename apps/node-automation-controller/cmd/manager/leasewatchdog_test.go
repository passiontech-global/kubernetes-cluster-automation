// leasewatchdog_test.go — the LeaseLossWatchdog contract: only a
// definitive FOREIGN HolderIdentity trips the cancel immediately;
// self, empty, missing, and unreadable leases are inconclusive —
// never instant loss — but they DO run the self-fence clock, so a
// sustained unverifiable window cancels the leader before a
// standby's lease hand-off can overlap.
package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

func leaseObj(holder string) *coordinationv1.Lease {
	l := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Name:      leaderElectionID,
			Namespace: "kube-system",
		},
	}
	if holder != "" {
		l.Spec.HolderIdentity = ptrTo(holder)
	}
	// A verified self-hold requires a FRESH RenewTime — the
	// watchdog treats holder==self with a stale/missing renew
	// stamp as inconclusive (dead hold coasting on the lease term).
	l.Spec.RenewTime = &metav1.MicroTime{Time: time.Now()}
	return l
}

func ptrTo(s string) *string { return &s }

func newWatchdog(t *testing.T, objs ...runtime.Object) (*leaseLossWatchdog,
	*atomic.Bool, chan struct{}) {
	t.Helper()
	cs := fake.NewSimpleClientset(objs...)
	stolen := &atomic.Bool{}
	cancelled := make(chan struct{})
	var once atomic.Bool
	cancel := func() {
		if once.CompareAndSwap(false, true) {
			close(cancelled)
		}
	}
	w := &leaseLossWatchdog{
		cs:        cs,
		namespace: "kube-system",
		selfID:    "pod-a_1234",
		stolen:    stolen,
		cancel:    cancel,
		log:       logr.Discard(),
		interval:  15 * time.Millisecond,
	}
	return w, stolen, cancelled
}

func TestWatchdogForeignHolderCancels(t *testing.T) {
	w, stolen, cancelled := newWatchdog(t, leaseObj("pod-b_5678"))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.Start(ctx) }()
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("watchdog did not cancel on foreign holder")
	}
	if !stolen.Load() {
		t.Fatal("stolen flag not set before cancel")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after cancel")
	}
}

func TestWatchdogSelfHolderKeepsRunning(t *testing.T) {
	w, stolen, cancelled := newWatchdog(t, leaseObj("pod-a_1234"))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.Start(ctx) }()
	// Let several poll intervals pass — self holder must never trip.
	time.Sleep(2*w.interval + 15*time.Millisecond)
	select {
	case <-cancelled:
		t.Fatal("watchdog cancelled on own holder")
	default:
	}
	if stolen.Load() {
		t.Fatal("stolen flag set on own holder")
	}
	cancel()
	<-done
}

func TestWatchdogEmptyAndMissingLeaseSafe(t *testing.T) {
	for _, tc := range []struct {
		name string
		objs []runtime.Object
	}{
		{"empty holder", []runtime.Object{leaseObj("")}},
		{"no lease object", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, _, cancelled := newWatchdog(t, tc.objs...)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- w.Start(ctx) }()
			time.Sleep(2*w.interval + 15*time.Millisecond)
			select {
			case <-cancelled:
				t.Fatal("watchdog cancelled on non-theft state")
			default:
			}
			cancel()
			<-done
		})
	}
}

// TestWatchdogSelfFencesOnSustainedReadFailure: an apiserver
// partition leaves the leader unable to verify its hold — after
// fenceAfter of inconclusive reads it must fence itself (the
// split-brain guard's other half: no foreign holder is ever
// observed, so only the unverifiable clock can stop it).
func TestWatchdogSelfFencesOnSustainedReadFailure(t *testing.T) {
	w, stolen, cancelled := newWatchdog(t, leaseObj("pod-a_1234"))
	w.fenceAfter = 40 * time.Millisecond
	w.cs.(*fake.Clientset).PrependReactor("get", "leases",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, context.DeadlineExceeded
		})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.Start(ctx) }()
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("watchdog did not self-fence on sustained read failure")
	}
	if stolen.Load() {
		t.Fatal("stolen flag must remain false on inconclusive self-fence")
	}
	<-done
}

// TestWatchdogSelfFencesOnEmptyHolder: a lease that never names a
// holder is just as unverifiable as a failed read — the fence must
// cover it (our renews are not landing, so the hold is unproven).
func TestWatchdogSelfFencesOnEmptyHolder(t *testing.T) {
	w, stolen, cancelled := newWatchdog(t, leaseObj(""))
	w.fenceAfter = 40 * time.Millisecond
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.Start(ctx) }()
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("watchdog did not self-fence on persistent empty holder")
	}
	if stolen.Load() {
		t.Fatal("stolen flag must remain false on inconclusive self-fence")
	}
	<-done
}

// TestWatchdogVerifiedReadsHoldOffFence: confirmed self-holder
// reads refresh lastVerified — a leader whose apiserver answers
// keeps running however long it likes (the fence only fires on
// UNVERIFIED time, never on verified time).
func TestWatchdogVerifiedReadsHoldOffFence(t *testing.T) {
	w, _, cancelled := newWatchdog(t, leaseObj("pod-a_1234"))
	w.fenceAfter = 30 * time.Millisecond // far below the sleep below
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.Start(ctx) }()
	time.Sleep(10 * w.fenceAfter)
	select {
	case <-cancelled:
		t.Fatal("watchdog fenced despite verified self-holder reads")
	default:
	}
	cancel()
	<-done
}

// TestWatchdogReadErrorIsNotLoss pins the INSTANT-loss contract:
// within the fence window a read error must not cancel — the
// self-fence (tested above) owns the sustained-outage case.
func TestWatchdogReadErrorIsNotLoss(t *testing.T) {
	w, _, cancelled := newWatchdog(t, leaseObj("pod-b_5678"))
	// Force every GET to fail — a transient apiserver error must
	// never bounce the leader.
	w.cs.(*fake.Clientset).PrependReactor("get", "leases",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, context.DeadlineExceeded
		})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.Start(ctx) }()
	time.Sleep(2*w.interval + 15*time.Millisecond)
	select {
	case <-cancelled:
		t.Fatal("watchdog cancelled on read error")
	default:
	}
	cancel()
	<-done
}

func TestWatchdogNeedLeaderElection(t *testing.T) {
	var w leaseLossWatchdog
	if !w.NeedLeaderElection() {
		t.Fatal("leaseLossWatchdog.NeedLeaderElection() = false, want true")
	}
}

func TestSelfFenceDuration(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"unset zero defaults to 10s", 0, 7500 * time.Millisecond},
		{"negative defaults to 10s", -5 * time.Second, 7500 * time.Millisecond},
		{"floor at 1s", time.Second, time.Second},
		{"default 10s", 10 * time.Second, 7500 * time.Millisecond},
		{"e2e 15s", 15 * time.Second, 11250 * time.Millisecond},
		{"deployment 120s", 120 * time.Second, 90 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := selfFenceDuration(tc.in); got != tc.want {
				t.Fatalf("selfFenceDuration(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestWatchdogRenewDeadlineTolerance verifies that a 120s RenewDeadline
// scales the self-fence horizon proportionally (~90s) rather than using
// a hardcoded 20s constant — sustained read errors past 50ms must not
// fence prematurely.
func TestWatchdogRenewDeadlineTolerance(t *testing.T) {
	w, stolen, cancelled := newWatchdog(t, leaseObj("pod-a_1234"))
	w.renewDeadline = 120 * time.Second
	w.cs.(*fake.Clientset).PrependReactor("get", "leases",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, context.DeadlineExceeded
		})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.Start(ctx) }()
	time.Sleep(60 * time.Millisecond)
	select {
	case <-cancelled:
		t.Fatal("watchdog fenced prematurely under 120s renewDeadline")
	default:
	}
	if stolen.Load() {
		t.Fatal("stolen flag set on inconclusive reads")
	}
	cancel()
	<-done
}

// TestWatchdogInconclusiveSelfFenceAllowsGuardedRelease verifies the full
// inconclusive-self-fence + releaseGuardedLock contract: after self-fencing
// on inconclusive reads, stolen stays false so releaseGuardedLock performs a
// live Get — releasing immediately when still self-held (avoiding a 180s
// blackout) and refusing release if a foreign holder took over.
func TestWatchdogInconclusiveSelfFenceAllowsGuardedRelease(t *testing.T) {
	for _, tc := range []struct {
		name       string
		liveHolder string
		wantWrites int
	}{
		{"still self-held releases cleanly", "pod-a_1234", 1},
		{"foreign holder refuses release", "pod-b_5678", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, stolen, cancelled := newWatchdog(t, leaseObj("pod-a_1234"))
			w.fenceAfter = 40 * time.Millisecond
			w.cs.(*fake.Clientset).PrependReactor("get", "leases",
				func(clienttesting.Action) (bool, runtime.Object, error) {
					return true, nil, context.DeadlineExceeded
				})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- w.Start(ctx) }()
			select {
			case <-cancelled:
			case <-time.After(5 * time.Second):
				t.Fatal("watchdog did not self-fence")
			}
			<-done

			inner := &fakeLock{holder: tc.liveHolder}
			guard := &releaseGuardedLock{Interface: inner, stolen: stolen}
			if err := guard.Update(t.Context(), releaseRec()); err != nil {
				t.Fatalf("guarded release error: %v", err)
			}
			if len(inner.updates) != tc.wantWrites {
				t.Fatalf("release writes = %d, want %d (holder=%q, stolen=%v)",
					len(inner.updates), tc.wantWrites, tc.liveHolder, stolen.Load())
			}
		})
	}
}
