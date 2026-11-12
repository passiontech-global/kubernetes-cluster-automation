// leaderelection_test.go — the releaseGuardedLock contract: a
// release-shaped Update (empty HolderIdentity) must never land on a
// lease another replica now holds.
package main

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

// fakeLock is a minimal resourcelock.Interface for guard tests —
// Get returns a scripted record, Update records what was written.
type fakeLock struct {
	holder   string
	updates  []resourcelock.LeaderElectionRecord
	getErr   error
	updateEr error
}

func (f *fakeLock) TryAcquire(context.Context) error { return nil }
func (f *fakeLock) Create(context.Context, resourcelock.LeaderElectionRecord) error {
	return nil
}
func (f *fakeLock) Get(context.Context) (*resourcelock.LeaderElectionRecord, []byte, error) {
	if f.getErr != nil {
		return nil, nil, f.getErr
	}
	return &resourcelock.LeaderElectionRecord{HolderIdentity: f.holder}, nil, nil
}
func (f *fakeLock) Update(_ context.Context, rec resourcelock.LeaderElectionRecord) error {
	if f.updateEr != nil {
		return f.updateEr
	}
	f.updates = append(f.updates, rec)
	return nil
}
func (f *fakeLock) RecordEvent(string) {}
func (f *fakeLock) WaitForLeaderRelease(context.Context, time.Duration) error {
	return nil
}
func (f *fakeLock) Describe() string { return "test/lease" }
func (f *fakeLock) Identity() string { return "pod-a_1234" }

var _ resourcelock.Interface = (*fakeLock)(nil)

func releaseRec() resourcelock.LeaderElectionRecord {
	// The shape client-go's tryRelease writes: LeaseDurationSeconds
	// collapsed to 1, no HolderIdentity.
	return resourcelock.LeaderElectionRecord{LeaseDurationSeconds: 1}
}

func renewRec() resourcelock.LeaderElectionRecord {
	return resourcelock.LeaderElectionRecord{
		HolderIdentity:       "pod-a_1234",
		LeaseDurationSeconds: 15,
	}
}

func TestReleaseGuardSkipsForeignHolder(t *testing.T) {
	inner := &fakeLock{holder: "pod-b_5678"}
	l := &releaseGuardedLock{Interface: inner}
	if err := l.Update(context.Background(), releaseRec()); err != nil {
		t.Fatalf("guarded release returned error: %v", err)
	}
	if len(inner.updates) != 0 {
		t.Fatalf("release landed on foreign-held lease: %+v", inner.updates)
	}
}

func TestReleaseGuardAllowsOwnHolder(t *testing.T) {
	inner := &fakeLock{holder: "pod-a_1234"}
	l := &releaseGuardedLock{Interface: inner}
	if err := l.Update(context.Background(), releaseRec()); err != nil {
		t.Fatalf("guarded release returned error: %v", err)
	}
	if len(inner.updates) != 1 {
		t.Fatalf("own-holder release blocked: %+v", inner.updates)
	}
}

func TestReleaseGuardAllowsFreeLease(t *testing.T) {
	inner := &fakeLock{holder: ""}
	l := &releaseGuardedLock{Interface: inner}
	if err := l.Update(context.Background(), releaseRec()); err != nil {
		t.Fatalf("guarded release on free lease returned error: %v", err)
	}
	if len(inner.updates) != 1 {
		t.Fatalf("free-lease release blocked: %+v", inner.updates)
	}
}

func TestReleaseGuardNeverTouchesRenew(t *testing.T) {
	// Renew writes carry our HolderIdentity — the guard must not
	// even pay the extra Get for them (foreign holder + renew must
	// pass through untouched).
	inner := &fakeLock{holder: "pod-b_5678"}
	l := &releaseGuardedLock{Interface: inner}
	if err := l.Update(context.Background(), renewRec()); err != nil {
		t.Fatalf("renew returned error: %v", err)
	}
	if len(inner.updates) != 1 {
		t.Fatalf("renew blocked: %+v", inner.updates)
	}
}

// The election client timeout must be max(effectiveRenewDeadline/2,
// 1s) with a NON-POSITIVE deadline normalized to the 10s default
// BEFORE the math — the pre-fix `if renewDeadline > 0` guard left a
// zero deadline with an unbounded client timeout, so one hung
// apiserver request could wedge the renew loop instead of losing
// the lease.
func TestLeaderClientConfigNormalizesDeadline(t *testing.T) {
	cfg := &rest.Config{Host: "https://127.0.0.1:6443"}
	for _, tc := range []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"unset zero", 0, 5 * time.Second},
		{"negative", -time.Second, 5 * time.Second},
		{"floor at 1s", time.Second, time.Second},
		{"half of 4s", 4 * time.Second, 2 * time.Second},
		{"half of 30s", 30 * time.Second, 15 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			el := leaderClientConfig(cfg, tc.in)
			if el.Timeout != tc.want {
				t.Fatalf("Timeout = %v, want %v", el.Timeout, tc.want)
			}
			if !strings.Contains(el.UserAgent, "leader-election") {
				t.Fatalf("UserAgent %q missing leader-election tag",
					el.UserAgent)
			}
		})
	}
	if cfg.Timeout != 0 {
		t.Fatal("leaderClientConfig mutated the caller's config")
	}
}

// roundTripperFunc adapts a func to http.RoundTripper for the
// hanging-transport sink test.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// Every leaseEventSink write carries the bounded timeout — the
// broadcaster calls the sink on its own goroutine with no caller
// ctx, so an unbounded apiserver stall would leak a goroutine per
// event. The transport below never answers on its own; only the
// sink's ctx deadline can end the call.
func TestLeaseEventSinkWriteIsBounded(t *testing.T) {
	old := leaseEventSinkTimeout
	leaseEventSinkTimeout = 50 * time.Millisecond
	defer func() { leaseEventSinkTimeout = old }()

	cs, err := kubernetes.NewForConfig(&rest.Config{
		Host: "http://127.0.0.1:1",
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			<-req.Context().Done()
			return nil, req.Context().Err()
		}),
	})
	if err != nil {
		t.Fatalf("clientset: %v", err)
	}
	sink := leaseEventSink{cs: cs}
	ev := &corev1.Event{ObjectMeta: metav1.ObjectMeta{
		Namespace: "kube-system", Name: "leader-election-test"}}

	for name, write := range map[string]func() error{
		"Create": func() error {
			_, err := sink.Create(ev)
			return err
		},
		"Update": func() error {
			_, err := sink.Update(ev)
			return err
		},
		"Patch": func() error {
			_, err := sink.Patch(ev, []byte(`{}`))
			return err
		},
	} {
		start := time.Now()
		err := write()
		if err == nil {
			t.Fatalf("%s: hanging transport returned nil error", name)
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("%s: sink write unbounded — took %v", name, elapsed)
		}
	}
}
