package hubsync

import (
	"context"
	"testing"
	"time"

	coordv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

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
