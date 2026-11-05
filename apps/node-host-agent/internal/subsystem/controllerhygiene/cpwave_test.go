package controllerhygiene

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// textfileSample reads <dir>/<file> and returns the value of the
// `metric value` sample line (HELP/TYPE lines never match — they
// start with '#').
func textfileSample(t *testing.T, dir, file, metric string) (float64, bool) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, file))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, metric+" ") {
			continue
		}
		v, err := strconv.ParseFloat(
			strings.TrimSpace(strings.TrimPrefix(line, metric)), 64)
		if err != nil {
			t.Fatalf("unparseable sample %q: %v", line, err)
		}
		return v, true
	}
	return 0, false
}

// --- W10-FIX1: kcmQueueSnapshot / kcmQueueStalled ---

func TestParseKCMQueueSnapshot(t *testing.T) {
	body := "leader_election_master_status 1\n" +
		"workqueue_depth{name=\"a\"} 3\n" +
		"workqueue_depth{name=\"b\"} 0\n" +
		"workqueue_adds_total{name=\"a\"} 100\n" +
		"workqueue_adds_total{name=\"b\"} 50\n" +
		"workqueue_retries_total{name=\"a\"} 7\n"
	snap, ok := parseKCMQueueSnapshot(body, 1234)
	if !ok {
		t.Fatal("parsed=false with leader metric present")
	}
	if !snap.Leader || snap.At != 1234 {
		t.Fatalf("leader=%v at=%d", snap.Leader, snap.At)
	}
	if snap.DepthSum != 3 {
		t.Fatalf("depthSum=%v want 3", snap.DepthSum)
	}
	if snap.Depths["a"] != 3 || snap.Adds["a"] != 100 || snap.Retries["a"] != 7 {
		t.Fatalf("bad per-queue maps: %+v", snap)
	}
	// No leader metric → inconclusive.
	if _, ok = parseKCMQueueSnapshot(
		"workqueue_depth{name=\"a\"} 0\n", 1); ok {
		t.Fatal("parsed=true without leader metric")
	}
}

func kcmSnap(at int64, leader bool, depths, adds, retries map[string]float64) *kcmQueueSnapshot {
	s := &kcmQueueSnapshot{
		At: at, Leader: leader,
		Depths: map[string]float64{}, Adds: map[string]float64{},
		Retries: map[string]float64{},
	}
	for k, v := range depths {
		s.Depths[k] = v
		s.DepthSum += v
	}
	for k, v := range adds {
		s.Adds[k] = v
	}
	for k, v := range retries {
		s.Retries[k] = v
	}
	return s
}

func TestKCMQueueStalled(t *testing.T) {
	// (a) THE regression: healthy idle — leader, every queue depth 0,
	// counters flat — must NEVER fire, no matter how many scrapes.
	idle1 := kcmSnap(100, true,
		map[string]float64{"a": 0, "b": 0},
		map[string]float64{"a": 10, "b": 20},
		map[string]float64{"a": 1, "b": 2})
	idle2 := kcmSnap(160, true,
		map[string]float64{"a": 0, "b": 0},
		map[string]float64{"a": 10, "b": 20},
		map[string]float64{"a": 1, "b": 2})
	if kcmQueueStalled(idle1, idle2) {
		t.Fatal("stalled=true on healthy idle depthSum==0")
	}

	// (a) fires: depthSum > 50, adds flat across two scrapes.
	prev := kcmSnap(100, true,
		map[string]float64{"a": 60},
		map[string]float64{"a": 500},
		map[string]float64{"a": 30})
	cur := kcmSnap(160, true,
		map[string]float64{"a": 60},
		map[string]float64{"a": 500}, // +0 adds
		map[string]float64{"a": 30})
	if !kcmQueueStalled(prev, cur) {
		t.Fatal("stalled=false on depth>50 with adds delta 0")
	}

	// Same backlog but adds still flowing → workers/informers alive.
	curFlow := kcmSnap(160, true,
		map[string]float64{"a": 60},
		map[string]float64{"a": 530},
		map[string]float64{"a": 30})
	if kcmQueueStalled(prev, curFlow) {
		t.Fatal("stalled=true while adds_total still increasing")
	}

	// Shallow backlog → below the arm-(a) threshold.
	shallow := kcmSnap(160, true,
		map[string]float64{"a": 30},
		map[string]float64{"a": 500},
		map[string]float64{"a": 30})
	prevShallow := kcmSnap(100, true,
		map[string]float64{"a": 30},
		map[string]float64{"a": 500},
		map[string]float64{"a": 30})
	if kcmQueueStalled(prevShallow, shallow) {
		t.Fatal("stalled=true on depthSum 30 < 50")
	}

	// (b) fires: one queue depth>20, retries +>200, depth not draining.
	prevR := kcmSnap(100, true,
		map[string]float64{"q": 25},
		map[string]float64{"q": 10},
		map[string]float64{"q": 100})
	curR := kcmSnap(160, true,
		map[string]float64{"q": 25}, // no drain
		map[string]float64{"q": 10},
		map[string]float64{"q": 350}) // +250 retries
	if !kcmQueueStalled(prevR, curR) {
		t.Fatal("stalled=false on retry storm with no depth drain")
	}

	// (b) does NOT fire when the queue is draining.
	curDrain := kcmSnap(160, true,
		map[string]float64{"q": 10},
		map[string]float64{"q": 10},
		map[string]float64{"q": 350})
	if kcmQueueStalled(prevR, curDrain) {
		t.Fatal("stalled=true while queue depth is draining")
	}

	// Counter reset (KCM restart mid-window) → inconclusive.
	reset := kcmSnap(160, true,
		map[string]float64{"a": 5},
		map[string]float64{"a": 3}, // adds went backwards
		map[string]float64{"a": 1})
	if kcmQueueStalled(prev, reset) {
		t.Fatal("stalled=true across a counter reset")
	}

	// Not leader → never fires.
	notLeader := kcmSnap(160, false,
		map[string]float64{"a": 60},
		map[string]float64{"a": 500},
		map[string]float64{"a": 30})
	if kcmQueueStalled(prev, notLeader) {
		t.Fatal("stalled=true on non-leader scrape")
	}

	// Stale prev snapshot (>15m) → inconclusive.
	stale := kcmSnap(100+2000, true,
		map[string]float64{"a": 60},
		map[string]float64{"a": 500},
		map[string]float64{"a": 30})
	if kcmQueueStalled(prev, stale) {
		t.Fatal("stalled=true on a >15m snapshot gap")
	}

	// No baseline → first scrape never fires.
	if kcmQueueStalled(nil, cur) {
		t.Fatal("stalled=true with nil prev")
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

// stalledKCMBody is a metrics body that reads leader + a deep,
// flat-adds backlog — the W10-FIX1 stall signature (never the old
// leader+zero-depth idle false-positive).
const stalledKCMBody = "leader_election_master_status 1\n" +
	"workqueue_depth{name=\"a\"} 60\n" +
	"workqueue_adds_total{name=\"a\"} 500\n" +
	"workqueue_retries_total{name=\"a\"} 30\n"

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

func TestCPFreezeWorkqueueStalledPastGrace(t *testing.T) {
	e := fixture(t)
	e.h.cfg.cpHealthFn = func(context.Context, string) bool { return true }
	e.h.cfg.kcmMetricsFn = func(context.Context, string) (string, error) {
		return stalledKCMBody, nil
	}
	e.alive["https://10.0.0.2:6443/readyz"] = true
	e.h.Cycle(context.Background()) // snapshot 1 — no baseline yet
	e.now = e.now.Add(61 * time.Second)
	e.h.Cycle(context.Background()) // snapshot 2 → stalled, stamps quiet-since
	if e.rstN() != 0 {
		t.Fatal("restart before the quiet grace")
	}
	e.now = e.now.Add(11 * time.Minute)
	e.h.Cycle(context.Background())
	if e.rstN() == 0 {
		t.Fatal("no restart after workqueue stalled >10m")
	}
}

// TestCPFreezeHealthyIdleNeverRestarts is the W10-FIX1 regression:
// leader + depthSum==0 across many cycles and well past the old
// quiet grace must produce ZERO restarts — the old kcmLeaderIdle
// fired on exactly this body every hour.
func TestCPFreezeHealthyIdleNeverRestarts(t *testing.T) {
	e := fixture(t)
	e.h.cfg.cpHealthFn = func(context.Context, string) bool { return true }
	e.h.cfg.kcmMetricsFn = func(context.Context, string) (string, error) {
		return "leader_election_master_status 1\n" +
			"workqueue_depth{name=\"a\"} 0\n" +
			"workqueue_depth{name=\"b\"} 0\n" +
			"workqueue_adds_total{name=\"a\"} 10\n" +
			"workqueue_adds_total{name=\"b\"} 20\n", nil
	}
	e.alive["https://10.0.0.2:6443/readyz"] = true
	for i := 0; i < 15; i++ {
		e.h.Cycle(context.Background())
		e.now = e.now.Add(61 * time.Second)
	}
	if e.rstN() != 0 {
		t.Fatal("restart fired on healthy idle cluster (W10-FIX1 regression)")
	}
	if e.hasState("cp-component-frozen") {
		t.Fatal("cp-component-frozen latched on healthy idle cluster")
	}
}

// --- W10-CP2: checkKineStorageHealth ---

// setupKineStore points K0sDir at a tempdir carrying db/state.db +
// state.db-wal of the given sizes, shrinks the checkpoint threshold,
// diverts the textfile dir, and returns a call counter for the
// injected checkpoint fn.
func setupKineStore(t *testing.T, e *env, dbSize, walSize int64) *int {
	t.Helper()
	root := t.TempDir()
	k0s := filepath.Join(root, "k0s")
	dbDir := filepath.Join(k0s, "db")
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if dbSize >= 0 {
		writeFile(t, filepath.Join(dbDir, "state.db"),
			strings.Repeat("x", int(dbSize)))
	}
	if walSize >= 0 {
		writeFile(t, filepath.Join(dbDir, "state.db-wal"),
			strings.Repeat("y", int(walSize)))
	}
	e.h.cfg.K0sDir = k0s

	oldMin := kineWALCheckpointMinBytes
	kineWALCheckpointMinBytes = 100
	t.Cleanup(func() { kineWALCheckpointMinBytes = oldMin })
	oldTD := kineTextfileDirOverride
	kineTextfileDirOverride = filepath.Join(root, "textfile")
	t.Cleanup(func() { kineTextfileDirOverride = oldTD })

	calls := new(int)
	oldFn := kineCheckpointFn
	kineCheckpointFn = func(_ context.Context, dbPath string) error {
		*calls++
		if dbPath != filepath.Join(dbDir, "state.db") {
			t.Errorf("checkpoint db path %q", dbPath)
		}
		return nil
	}
	t.Cleanup(func() { kineCheckpointFn = oldFn })
	return calls
}

func TestKineStorageHealthCheckpointGating(t *testing.T) {
	e := fixture(t)
	calls := setupKineStore(t, e, 50, 200) // wal 200 > 100 threshold

	e.h.checkKineStorageHealth(context.Background())
	if *calls != 1 {
		t.Fatalf("checkpoint calls=%d want 1", *calls)
	}
	// Metrics landed in the textfile.
	prom, err := os.ReadFile(filepath.Join(
		kineTextfileDirOverride, "node-agent-kine-storage.prom"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"node_agent_kine_db_bytes 50",
		"node_agent_kine_wal_bytes 200",
	} {
		if !strings.Contains(string(prom), want) {
			t.Fatalf("textfile missing %q:\n%s", want, prom)
		}
	}

	// Second run inside the 30m cooldown → no checkpoint.
	e.h.checkKineStorageHealth(context.Background())
	if *calls != 1 {
		t.Fatalf("checkpoint calls=%d want 1 (cooldown)", *calls)
	}

	// Past the cooldown → checkpoint again.
	e.now = e.now.Add(31 * time.Minute)
	e.h.checkKineStorageHealth(context.Background())
	if *calls != 2 {
		t.Fatalf("checkpoint calls=%d want 2", *calls)
	}
}

func TestKineStorageHealthSmallWALNoCheckpoint(t *testing.T) {
	e := fixture(t)
	calls := setupKineStore(t, e, 50, 50) // wal 50 <= 100 threshold
	e.h.checkKineStorageHealth(context.Background())
	if *calls != 0 {
		t.Fatalf("checkpoint fired on small WAL: calls=%d", *calls)
	}
}

func TestKineStorageHealthNoSQLite3KeepsCooldown(t *testing.T) {
	e := fixture(t)
	calls := setupKineStore(t, e, 50, 200)
	oldFn := kineCheckpointFn
	kineCheckpointFn = func(context.Context, string) error {
		*calls++
		return errKineNoSQLite3
	}
	defer func() { kineCheckpointFn = oldFn }()

	e.h.checkKineStorageHealth(context.Background())
	e.h.checkKineStorageHealth(context.Background())
	if *calls != 2 {
		t.Fatalf("no-sqlite3 should not spend cooldown: calls=%d want 2",
			*calls)
	}
}

func TestKineStorageHealthAbsentStore(t *testing.T) {
	e := fixture(t)
	root := t.TempDir()
	e.h.cfg.K0sDir = filepath.Join(root, "k0s") // nothing inside
	oldTD := kineTextfileDirOverride
	kineTextfileDirOverride = filepath.Join(root, "textfile")
	defer func() { kineTextfileDirOverride = oldTD }()

	e.h.checkKineStorageHealth(context.Background()) // must not panic
	prom, err := os.ReadFile(filepath.Join(
		kineTextfileDirOverride, "node-agent-kine-storage.prom"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(prom), "\nnode_agent_kine_db_bytes ") {
		t.Fatalf("absent store emitted a size sample:\n%s", prom)
	}
}

// --- W10-CP5: checkKubeconfigCertExpiry ---

// testClientCertPEM mints a self-signed ECDSA cert PEM with the
// given NotAfter — fast enough for tests (P256, no RSA).
func testClientCertPEM(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl,
		&key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// kubeconfigWithCert renders a minimal valid kubeconfig embedding
// the cert PEM as client-certificate-data.
func kubeconfigWithCert(t *testing.T, certPEM []byte) string {
	t.Helper()
	return "apiVersion: v1\nkind: Config\n" +
		"clusters:\n- name: c\n  cluster:\n" +
		"    server: https://127.0.0.1:6443\n" +
		"    insecure-skip-tls-verify: true\n" +
		"users:\n- name: u\n  user:\n" +
		"    client-certificate-data: " +
		base64.StdEncoding.EncodeToString(certPEM) + "\n"
}

func TestKubeconfigCertExpiry(t *testing.T) {
	e := fixture(t)
	root := t.TempDir()
	k0s := filepath.Join(root, "k0s")
	pki := filepath.Join(k0s, "pki")
	if err := os.MkdirAll(pki, 0o755); err != nil {
		t.Fatal(err)
	}
	e.h.cfg.K0sDir = k0s
	oldTD := kineTextfileDirOverride
	kineTextfileDirOverride = filepath.Join(root, "textfile")
	defer func() { kineTextfileDirOverride = oldTD }()

	// admin.conf cert expiring in 5 days → inside the 14d window.
	writeFile(t, filepath.Join(pki, "admin.conf"),
		kubeconfigWithCert(t, testClientCertPEM(t,
			e.now.Add(5*24*time.Hour))))
	// scheduler.conf cert healthy at 60 days — min stays 5d.
	writeFile(t, filepath.Join(pki, "scheduler.conf"),
		kubeconfigWithCert(t, testClientCertPEM(t,
			e.now.Add(60*24*time.Hour))))
	// Garbage file → skipped gracefully.
	writeFile(t, filepath.Join(k0s, "kubelet.conf"), "not yaml: [")

	e.h.checkKubeconfigCertExpiry(context.Background())
	if !e.hasState(stateKubeCertExpiring) {
		t.Fatal("kubeconfig-cert-expiring latch missing")
	}
	// x509 truncates NotAfter to seconds — allow sub-day slop.
	v, ok := textfileSample(t, kineTextfileDirOverride,
		"node-agent-kubeconfig-cert.prom", certDaysMetric)
	if !ok || v <= 4.9 || v > 5.0 {
		t.Fatalf("min-days=%v ok=%v want ~5", v, ok)
	}

	// Rotate to a healthy cert → latch clears, sample ~60d.
	writeFile(t, filepath.Join(pki, "admin.conf"),
		kubeconfigWithCert(t, testClientCertPEM(t,
			e.now.Add(60*24*time.Hour))))
	e.h.checkKubeconfigCertExpiry(context.Background())
	if e.hasState(stateKubeCertExpiring) {
		t.Fatal("latch still held on healthy certs")
	}
	v, ok = textfileSample(t, kineTextfileDirOverride,
		"node-agent-kubeconfig-cert.prom", certDaysMetric)
	if !ok || v <= 59.9 || v > 60.0 {
		t.Fatalf("min-days=%v ok=%v want ~60", v, ok)
	}
}

func TestKubeconfigCertExpiryNoCerts(t *testing.T) {
	e := fixture(t)
	root := t.TempDir()
	e.h.cfg.K0sDir = filepath.Join(root, "k0s") // no kubeconfigs at all
	oldTD := kineTextfileDirOverride
	kineTextfileDirOverride = filepath.Join(root, "textfile")
	defer func() { kineTextfileDirOverride = oldTD }()

	e.h.checkKubeconfigCertExpiry(context.Background()) // no panic
	if e.hasState(stateKubeCertExpiring) {
		t.Fatal("latch on a host with no kubeconfigs")
	}
	prom, err := os.ReadFile(filepath.Join(
		kineTextfileDirOverride, "node-agent-kubeconfig-cert.prom"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(prom),
		"\nnode_agent_kubeconfig_cert_min_days_remaining ") {
		t.Fatalf("no-cert host emitted a days sample:\n%s", prom)
	}
}
