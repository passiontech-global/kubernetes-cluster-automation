package hubsync

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	coordv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

func newTestSyncer(cs *fake.Clientset, now func() time.Time) *Syncer {
	cfg := Config{
		Client:   cs,
		Identity: "pod-a",
		Clock:    timex.NewCell(now),
		// Dialer left nil is not allowed by New (it would read the
		// real key path) — inject the fake.
		Dialer: newFakeDialer(),
	}
	s, err := New(cfg, nil)
	if err != nil {
		panic(err)
	}
	return s
}

// TestLeaseAcquireRenewTakeover walks the lease lifecycle: create on
// absence, renew while holder, refusal while another pod holds a
// fresh lease, takeover after expiry with LeaseTransitions bump.
func TestLeaseAcquireRenewTakeover(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	clock := &now
	cs := testutil.FakeKube()
	s := newTestSyncer(cs, func() time.Time { return *clock })
	ctx := context.Background()

	// 1. No lease → created + held.
	if !s.renewLease(ctx) || !s.held {
		t.Fatal("expected acquire on empty store")
	}
	l, err := cs.CoordinationV1().Leases("node-ops").
		Get(ctx, "node-host-agent-hubsync", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get lease: %v", err)
	}
	if *l.Spec.HolderIdentity != "pod-a" || *l.Spec.LeaseDurationSeconds != 60 {
		t.Fatalf("lease spec: %+v", l.Spec)
	}
	firstRenew := l.Spec.RenewTime.Time

	// 2. Still holder → renew advances RenewTime.
	*clock = now.Add(10 * time.Second)
	if !s.renewLease(ctx) || !s.held {
		t.Fatal("expected held renew")
	}
	l, _ = cs.CoordinationV1().Leases("node-ops").
		Get(ctx, "node-host-agent-hubsync", metav1.GetOptions{})
	if !l.Spec.RenewTime.Time.After(firstRenew) {
		t.Fatal("RenewTime not advanced")
	}
	if l.Spec.LeaseTransitions != nil && *l.Spec.LeaseTransitions != 0 {
		t.Fatalf("transitions on own renew: %v", *l.Spec.LeaseTransitions)
	}
}

// TestLeaseOtherHolderFresh: a live foreign holder gates us out.
func TestLeaseOtherHolderFresh(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	clock := &now
	other := "pod-b"
	dur := int32(60)
	rt := metav1.NewMicroTime(now)
	cs := testutil.FakeKube(&coordv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "node-ops", Name: "node-host-agent-hubsync",
		},
		Spec: coordv1.LeaseSpec{
			HolderIdentity:       &other,
			LeaseDurationSeconds: &dur,
			RenewTime:            &rt,
		},
	})
	s := newTestSyncer(cs, func() time.Time { return *clock })
	ctx := context.Background()

	*clock = now.Add(30 * time.Second) // inside the 60s window
	if s.renewLease(ctx) {
		t.Fatal("fresh foreign lease must gate us out")
	}
	if s.held {
		t.Fatal("held flag must stay false")
	}

	// Expiry → takeover with transitions bump.
	*clock = now.Add(61 * time.Second)
	if !s.renewLease(ctx) {
		t.Fatal("expired foreign lease must be taken over")
	}
	l, _ := cs.CoordinationV1().Leases("node-ops").
		Get(ctx, "node-host-agent-hubsync", metav1.GetOptions{})
	if *l.Spec.HolderIdentity != "pod-a" {
		t.Fatalf("holder %q", *l.Spec.HolderIdentity)
	}
	if l.Spec.LeaseTransitions == nil || *l.Spec.LeaseTransitions != 1 {
		t.Fatalf("transitions %v", l.Spec.LeaseTransitions)
	}
}

// TestLeaseLossClearsSyncedLatch: losing the lease resets the
// converge-once latch so re-acquiring converges immediately.
func TestLeaseLossClearsSyncedLatch(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	clock := &now
	cs := testutil.FakeKube()
	s := newTestSyncer(cs, func() time.Time { return *clock })
	ctx := context.Background()

	if !s.renewLease(ctx) {
		t.Fatal("acquire")
	}
	s.syncedWhileHeld = true

	// Another pod steals the lease via the API directly.
	other := "pod-b"
	dur := int32(60)
	rt := metav1.NewMicroTime(now.Add(time.Minute))
	_, err := cs.CoordinationV1().Leases("node-ops").Update(ctx, &coordv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "node-ops", Name: "node-host-agent-hubsync",
		},
		Spec: coordv1.LeaseSpec{
			HolderIdentity:       &other,
			LeaseDurationSeconds: &dur,
			RenewTime:            &rt,
		},
	}, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("steal lease: %v", err)
	}

	if s.renewLease(ctx) {
		t.Fatal("foreign fresh lease must not be held")
	}
	if s.syncedWhileHeld {
		t.Fatal("loss must clear the synced latch")
	}
}

// --- API-error injection + spec corners ---

// leaseWith builds a bare lease against cs with a fixed clock — the
// error-injection tests work below the Syncer wrapper.
func leaseWith(cs *fake.Clientset, now func() time.Time, dur time.Duration) *lease {
	return &lease{
		leases:   cs.CoordinationV1().Leases("node-ops"),
		name:     "node-host-agent-hubsync",
		identity: "pod-a",
		duration: dur,
		now:      now, // timex.Clock is func() time.Time
	}
}

// seedLease plants a Lease object directly in the fake store; age is
// relative to now (the test's fixed clock), so expiry math is
// deterministic.
func seedLease(t *testing.T, cs *fake.Clientset, holder string,
	now time.Time, age time.Duration, durSec, transitions *int32) {
	t.Helper()
	rt := metav1.NewMicroTime(now.Add(-age))
	l := &coordv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Namespace: "node-ops",
			Name: "node-host-agent-hubsync"},
		Spec: coordv1.LeaseSpec{HolderIdentity: &holder, RenewTime: &rt},
	}
	if durSec != nil {
		l.Spec.LeaseDurationSeconds = durSec
	}
	if transitions != nil {
		l.Spec.LeaseTransitions = transitions
	}
	if _, err := cs.CoordinationV1().Leases("node-ops").Create(
		context.Background(), l, metav1.CreateOptions{}); err != nil {
		t.Fatalf("seed lease: %v", err)
	}
}

// TestLeaseSubSecondDurationClamps: a configured duration under a
// second rounds to zero — clamped to 1s so the advertised claim never
// lapses instantly.
func TestLeaseSubSecondDurationClamps(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	clock := &now
	cs := testutil.FakeKube()
	l := leaseWith(cs, func() time.Time { return *clock }, 400*time.Millisecond)
	ctx := context.Background()

	held, _, err := l.renew(ctx)
	if err != nil || !held {
		t.Fatalf("renew err=%v held=%v", err, held)
	}
	stored, err := cs.CoordinationV1().Leases("node-ops").
		Get(ctx, "node-host-agent-hubsync", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if stored.Spec.LeaseDurationSeconds == nil ||
		*stored.Spec.LeaseDurationSeconds != 1 {
		t.Fatalf("duration=%v want clamped 1", stored.Spec.LeaseDurationSeconds)
	}
}

// TestLeaseRenewTransportErrors: every Lease API failure mode maps to
// "not held + error" — a get failure, a lost create race, and update
// conflicts on both the heartbeat and the takeover paths.
func TestLeaseRenewTransportErrors(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	notFound := apierrors.NewNotFound(
		schema.GroupResource{Group: "coordination.k8s.io", Resource: "leases"},
		"node-host-agent-hubsync")

	t.Run("get fails", func(t *testing.T) {
		cs := testutil.FakeKube()
		cs.PrependReactor("get", "leases",
			func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("etcd lost")
			})
		held, _, err := leaseWith(cs, func() time.Time { return now },
			time.Minute).renew(context.Background())
		if held || err == nil || err.Error() != "etcd lost" {
			t.Fatalf("held=%v err=%v", held, err)
		}
	})

	t.Run("create race lost", func(t *testing.T) {
		cs := testutil.FakeKube()
		cs.PrependReactor("get", "leases",
			func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, notFound
			})
		cs.PrependReactor("create", "leases",
			func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("another pod won")
			})
		held, _, err := leaseWith(cs, func() time.Time { return now },
			time.Minute).renew(context.Background())
		if held || err == nil || err.Error() != "another pod won" {
			t.Fatalf("held=%v err=%v", held, err)
		}
	})

	t.Run("heartbeat update conflict", func(t *testing.T) {
		cs := testutil.FakeKube()
		dur := int32(60)
		seedLease(t, cs, "pod-a", now, 0, &dur, nil)
		cs.PrependReactor("update", "leases",
			func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("resourceVersion conflict")
			})
		held, _, err := leaseWith(cs, func() time.Time { return now },
			time.Minute).renew(context.Background())
		if held || err == nil || !strings.Contains(err.Error(), "renew lease") {
			t.Fatalf("held=%v err=%v", held, err)
		}
	})

	t.Run("takeover update conflict", func(t *testing.T) {
		cs := testutil.FakeKube()
		dur := int32(60)
		seedLease(t, cs, "pod-b", now, 2*time.Minute, &dur, nil)
		cs.PrependReactor("update", "leases",
			func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("resourceVersion conflict")
			})
		held, _, err := leaseWith(cs, func() time.Time { return now },
			time.Minute).renew(context.Background())
		if held || err == nil || !strings.Contains(err.Error(), "acquire lease") {
			t.Fatalf("held=%v err=%v", held, err)
		}
	})
}

// TestLeaseHeartbeatAdoptsDuration: a lease written without
// LeaseDurationSeconds adopts the configured duration on the next
// heartbeat instead of waiting for a takeover.
func TestLeaseHeartbeatAdoptsDuration(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	clock := &now
	cs := testutil.FakeKube()
	seedLease(t, cs, "pod-a", now, 0, nil, nil)
	l := leaseWith(cs, func() time.Time { return *clock }, time.Minute)

	held, _, err := l.renew(context.Background())
	if err != nil || !held {
		t.Fatalf("renew err=%v held=%v", err, held)
	}
	stored, _ := cs.CoordinationV1().Leases("node-ops").
		Get(context.Background(), "node-host-agent-hubsync", metav1.GetOptions{})
	if stored.Spec.LeaseDurationSeconds == nil ||
		*stored.Spec.LeaseDurationSeconds != 60 {
		t.Fatalf("adopted duration=%v want 60", stored.Spec.LeaseDurationSeconds)
	}
}

// TestLeaseTakeoverBumpsTransitions: taking over an expired foreign
// claim increments an existing LeaseTransitions counter.
func TestLeaseTakeoverBumpsTransitions(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	clock := &now
	cs := testutil.FakeKube()
	dur := int32(60)
	trans := int32(3)
	seedLease(t, cs, "pod-b", now, 2*time.Minute, &dur, &trans)
	l := leaseWith(cs, func() time.Time { return *clock }, time.Minute)

	held, _, err := l.renew(context.Background())
	if err != nil || !held {
		t.Fatalf("renew err=%v held=%v", err, held)
	}
	stored, _ := cs.CoordinationV1().Leases("node-ops").
		Get(context.Background(), "node-host-agent-hubsync", metav1.GetOptions{})
	if stored.Spec.LeaseTransitions == nil ||
		*stored.Spec.LeaseTransitions != 4 ||
		*stored.Spec.HolderIdentity != "pod-a" {
		t.Fatalf("stored=%+v want pod-a holding, transitions 4", stored.Spec)
	}
}

// TestRenewLeaseLogsTransientError: the Syncer wrapper reports a
// failed renew tick as not-held while keeping its state consistent
// for the next tick.
func TestRenewLeaseLogsTransientError(t *testing.T) {
	cs := testutil.FakeKube()
	cs.PrependReactor("get", "leases",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("apiserver 500")
		})
	s := newTestSyncer(cs, func() time.Time { return time.Now() })
	if s.renewLease(context.Background()) {
		t.Fatal("failed renew must not report held")
	}
	if s.held || s.leaseExpiresAt.IsZero() == false {
		t.Fatalf("held=%v expiry=%v want cleared", s.held, s.leaseExpiresAt)
	}
}
