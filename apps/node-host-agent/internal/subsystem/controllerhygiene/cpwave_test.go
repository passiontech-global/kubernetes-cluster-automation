package controllerhygiene

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestKCMLeaderIdle(t *testing.T) {
	// leader + all queues empty → frozen signature.
	leader, idle, ok := kcmLeaderIdle(
		"leader_election_master_status 1\nworkqueue_depth{name=\"a\"} 0\nworkqueue_depth{name=\"b\"} 0\n")
	if !ok || !leader || !idle {
		t.Fatalf("leader=%v idle=%v ok=%v", leader, idle, ok)
	}
	// leader with queued work → healthy.
	if _, idle, _ = kcmLeaderIdle(
		"leader_election_master_status 1\nworkqueue_depth{name=\"a\"} 3\n"); idle {
		t.Fatal("idle=true with queued work")
	}
	// not leader → not the frozen signature (idle may still read
	// true; the caller ANDs leader&&idle).
	if leader, _, _ = kcmLeaderIdle(
		"leader_election_master_status 0\nworkqueue_depth{name=\"a\"} 0\n"); leader {
		t.Fatal("leader=true on status 0")
	}
	// no leader metric → inconclusive.
	if _, _, ok = kcmLeaderIdle("workqueue_depth{name=\"a\"} 0\n"); ok {
		t.Fatal("parsed=true without leader metric")
	}
	// no depth samples → inconclusive idle.
	if _, idle, _ = kcmLeaderIdle("leader_election_master_status 1\n"); idle {
		t.Fatal("idle=true with no depth samples")
	}
}

func mkCert(serial int64, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		NotAfter:     notAfter,
		Subject:      pkix.Name{CommonName: "x"},
	}
}

func TestCertNewerThan(t *testing.T) {
	old := mkCert(1, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	newer := mkCert(2, time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
	if !certNewerThan(newer, old) {
		t.Fatal("rotated-newer disk cert not flagged")
	}
	if certNewerThan(old, newer) {
		t.Fatal("older disk cert flagged as drift")
	}
	if certNewerThan(old, old) {
		t.Fatal("identical cert flagged as drift")
	}
	// Same window, different serial (re-issue keeping dates) → drift.
	same := mkCert(3, old.NotAfter)
	if !certNewerThan(same, old) {
		t.Fatal("re-issued cert (new serial, same window) not flagged")
	}
}

// --- checkCPFreeze ---

func TestCPFreezeRestartsAfterThreeDeadCycles(t *testing.T) {
	e := fixture(t)
	e.h.cfg.cpHealthFn = func(context.Context, string) bool { return false }
	e.h.cfg.kcmMetricsFn = func(context.Context, string) (string, error) {
		return "leader_election_master_status 1\nworkqueue_depth{name=\"a\"} 1\n", nil
	}
	e.alive["https://10.0.0.2:6443/readyz"] = true // peer healthy
	for i := 0; i < 3; i++ {
		e.h.Cycle(context.Background())
	}
	if e.rstN() == 0 {
		t.Fatal("no restart after 3 dead healthz cycles")
	}
	if !e.hasState("cp-component-frozen") {
		t.Fatal("cp-component-frozen latch missing")
	}
}

func TestCPFreezeGatedByDeadPeer(t *testing.T) {
	e := fixture(t)
	e.h.cfg.cpHealthFn = func(context.Context, string) bool { return false }
	e.h.cfg.kcmMetricsFn = func(context.Context, string) (string, error) {
		return "", nil
	}
	// PeerAPI default is alive[...] → false: peer dead → no restart.
	for i := 0; i < 4; i++ {
		e.h.Cycle(context.Background())
	}
	if e.rstN() != 0 {
		t.Fatal("restart fired while peer apiserver dead")
	}
	if !e.hasState("cp-component-frozen") {
		t.Fatal("latch should still record the freeze evidence")
	}
}

func TestCPFreezeLeaderIdlePastGrace(t *testing.T) {
	e := fixture(t)
	e.h.cfg.cpHealthFn = func(context.Context, string) bool { return true }
	e.h.cfg.kcmMetricsFn = func(context.Context, string) (string, error) {
		return "leader_election_master_status 1\nworkqueue_depth{name=\"a\"} 0\n", nil
	}
	e.alive["https://10.0.0.2:6443/readyz"] = true
	e.h.Cycle(context.Background()) // stamps quiet-since
	if e.rstN() != 0 {
		t.Fatal("restart before the quiet grace")
	}
	e.now = e.now.Add(11 * time.Minute)
	e.h.Cycle(context.Background())
	if e.rstN() == 0 {
		t.Fatal("no restart after leader+idle >10m")
	}
}
