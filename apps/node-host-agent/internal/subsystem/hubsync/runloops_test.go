// runloops_test.go — the Syncer construction and loop-driving edges
// the lease/sync suites skip: New validation, the real-dialer splice,
// duplicate metric registration, the Enabled key gate, the Run
// ticker/watch select branches and the leaseLoop panic + signal
// backpressure guards.
package hubsync

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ssh"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// TestNewValidation: the two required Config fields.
func TestNewValidation(t *testing.T) {
	if _, err := New(Config{}, nil); err == nil ||
		err.Error() != "hubsync: Client is required" {
		t.Fatalf("nil client err=%v", err)
	}
	cs := testutil.FakeKube()
	if _, err := New(Config{Client: cs}, nil); err == nil ||
		err.Error() != "hubsync: Identity is required" {
		t.Fatalf("empty identity err=%v", err)
	}
}

// TestNewBuildsRealDialer: without an injected Dialer, New splices
// the sshclient config from the key path — construction still
// succeeds (the key loads per dial, not here).
func TestNewBuildsRealDialer(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "test")
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(key, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{Client: testutil.FakeKube(), Identity: "pod-a",
		SSHKeyPath: key}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	d, ok := s.dialer.(*sshDialer)
	if !ok {
		t.Fatalf("dialer=%T want *sshDialer", s.dialer)
	}
	if d.cfg.KeyPath != key || d.cfg.Port != defaultSSHPort {
		t.Fatalf("dialer cfg=%+v", d.cfg)
	}
}

// TestNewDuplicateRegistration: registering the same metric names on
// one registry twice fails New with the register error.
func TestNewDuplicateRegistration(t *testing.T) {
	reg := prometheus.NewRegistry()
	cfg := func() Config {
		return Config{Client: testutil.FakeKube(), Identity: "pod-a",
			Dialer: newFakeDialer()}
	}
	if _, err := New(cfg(), reg); err != nil {
		t.Fatalf("first New: %v", err)
	}
	if _, err := New(cfg(), reg); err == nil ||
		!strings.Contains(err.Error(), "register hubsync metrics") {
		t.Fatalf("second New err=%v", err)
	}
}

// TestEnabledKeyGate: a regular file is live, a directory and an
// absent path are not, and "" falls back to the default key path
// (absent in the test env).
func TestEnabledKeyGate(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(key, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !Enabled(key) {
		t.Fatal("key file want enabled")
	}
	if Enabled(dir) {
		t.Fatal("directory want disabled")
	}
	if Enabled("") {
		t.Fatal("default key path want disabled in test env")
	}
	if Enabled(filepath.Join(dir, "missing")) {
		t.Fatal("missing path want disabled")
	}
}

// scriptedWatcher fires Changed() exactly once: call 1 is Run's seed
// (swallowed), call 2 is the first watch tick that must converge.
type scriptedWatcher struct{ n atomic.Int32 }

func (w *scriptedWatcher) Changed() bool { return w.n.Add(1) == 2 }

// waitDials waits on the fake dialer's dial-notification channel
// until at least one dial lands.
func waitDials(t *testing.T, d *fakeDialer) {
	t.Helper()
	select {
	case <-d.dialCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("no dials within deadline: %v", d.dials())
	}
}

// TestRunSyncTickerDrivesCycle: with the lease held and the
// fresh-hold signal pre-consumed, only the SyncInterval ticker
// triggers converge cycles.
func TestRunSyncTickerDrivesCycle(t *testing.T) {
	dialer := newFakeDialer()
	cfg := testConfig(t, newClientsetWithSecret(), dialer, []byte("bin"))
	cfg.SyncInterval = 3 * time.Millisecond
	cfg.WatchInterval = time.Hour
	cfg.RenewInterval = 5 * time.Millisecond
	cfg.Watcher = neverWatcher{} // never fires — sync ticker is the only trigger
	s, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	holdLease(s)
	// Pre-consume the fresh-hold latch so leaseLoop's cycleCh never
	// fires — every cycle below comes from the sync ticker.
	s.mu.Lock()
	s.syncedWhileHeld = true
	s.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.Run(ctx) }()
	waitDials(t, dialer)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

// neverWatcher never reports an edge — the sync-ticker branch's
// control group.
type neverWatcher struct{}

func (neverWatcher) Changed() bool { return false }

// TestRunWatcherEdgeDrivesCycle: a vars/nebula-certs change edge
// converges immediately even when the sync ticker is far away.
func TestRunWatcherEdgeDrivesCycle(t *testing.T) {
	dialer := newFakeDialer()
	cfg := testConfig(t, newClientsetWithSecret(), dialer, []byte("bin"))
	cfg.SyncInterval = time.Hour
	cfg.WatchInterval = 3 * time.Millisecond
	cfg.RenewInterval = 5 * time.Millisecond
	cfg.Watcher = &scriptedWatcher{}
	s, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	holdLease(s)
	s.mu.Lock()
	s.syncedWhileHeld = true
	s.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.Run(ctx) }()
	waitDials(t, dialer)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

// TestLeaseLoopRecoversPanic: a panicking Lease API call is contained
// by the renewer's recover — the heartbeater exits instead of taking
// the daemon down (the lease then lapses, which fails safe).
func TestLeaseLoopRecoversPanic(t *testing.T) {
	cs := testutil.FakeKube()
	cs.PrependReactor("get", "leases",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			panic("apiserver exploded")
		})
	s, err := New(testConfig(t, cs, newFakeDialer(), []byte("bin")), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	done := make(chan struct{})
	go func() { defer close(done); s.leaseLoop(ctx) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("leaseLoop did not return after panic")
	}
}

// TestLeaseLoopDropsFullCycleSignal: when the buffered cycle signal
// is still full (a prior fresh hold unconsumed), the renewer's send
// falls to the drop branch instead of blocking the heartbeat.
func TestLeaseLoopDropsFullCycleSignal(t *testing.T) {
	cs := testutil.FakeKube()
	s, err := New(testConfig(t, cs, newFakeDialer(), []byte("bin")), nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := s.cfg
	cfg.RenewInterval = 10 * time.Millisecond
	s.cfg.RenewInterval = cfg.RenewInterval
	s.cycleCh <- struct{}{} // fill the 1-slot buffer

	// The first iteration renews (creating the lease) and hits the
	// drop branch — the create reactor's signal proves the lease
	// exists, so no polling on the fake clientset. The reactor arms
	// BEFORE the loop starts: PrependReactor is not synchronized
	// against concurrent fake-clientset calls.
	created := leaseTouchCh(cs, "create")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.leaseLoop(ctx) }()

	select {
	case <-created:
	case <-time.After(2 * time.Second):
		t.Fatal("leaseLoop never created the lease")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("leaseLoop did not return after cancel")
	}
}
