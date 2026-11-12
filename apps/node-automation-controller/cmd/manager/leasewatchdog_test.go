// leasewatchdog_test.go — the LeaseLossWatchdog contract: only a
// definitive FOREIGN HolderIdentity trips the cancel; self, empty,
// missing, and unreadable leases must never bounce a healthy leader.
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.Start(ctx) }()
	select {
	case <-cancelled:
	case <-time.After(10 * w.interval):
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
	ctx, cancel := context.WithCancel(context.Background())
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
			ctx, cancel := context.WithCancel(context.Background())
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

func TestWatchdogReadErrorIsNotLoss(t *testing.T) {
	w, _, cancelled := newWatchdog(t, leaseObj("pod-b_5678"))
	// Force every GET to fail — a transient apiserver error must
	// never bounce the leader.
	w.cs.(*fake.Clientset).PrependReactor("get", "leases",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, context.DeadlineExceeded
		})
	ctx, cancel := context.WithCancel(context.Background())
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
