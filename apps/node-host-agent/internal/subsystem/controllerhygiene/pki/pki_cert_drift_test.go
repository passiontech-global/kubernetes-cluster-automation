package pki_test

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdepstest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/pki"

	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"
)

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
	if !pki.CertNewerThan(newer, old) {
		t.Fatal("rotated-newer disk cert not flagged")
	}
	if pki.CertNewerThan(old, newer) {
		t.Fatal("older disk cert flagged as drift")
	}
	if pki.CertNewerThan(old, old) {
		t.Fatal("identical cert flagged as drift")
	}
	// Same window, different serial (re-issue keeping dates) → drift.
	same := mkCert(3, old.NotAfter)
	if !pki.CertNewerThan(same, old) {
		t.Fatal("re-issued cert (new serial, same window) not flagged")
	}
}

// --- sa-pub-key-fingerprint: sa.pub ServiceAccount signer-key fingerprint ---

func TestSAPubFingerprintTextfile(t *testing.T) {
	e := fixture(t)
	root := t.TempDir()
	k0s := filepath.Join(root, "k0s")
	e.H.Cfg.K0sDir = k0s
	oldTD := cdeps.TextfileDirOverride
	cdeps.TextfileDirOverride = filepath.Join(root, "textfile")
	defer func() { cdeps.TextfileDirOverride = oldTD }()
	testutil.WriteFile(t, filepath.Join(k0s, "pki", "sa.pub"), "PUBKEY-BYTES")

	cdepstest.Check[*pki.DriftCheck](e.H, cdeps.CheckPKIDrift).Run(context.Background())
	data, err := os.ReadFile(filepath.Join(cdeps.TextfileDirOverride, pki.SAPubPromFile))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("PUBKEY-BYTES"))
	want := pki.SAPubMetric + `{sha256="` + hex.EncodeToString(sum[:]) + `"} 1`
	if !strings.Contains(string(data), want) {
		t.Fatalf("textfile missing %q:\n%s", want, data)
	}

	// A drifted sa.pub rewrites the series with the new hash.
	testutil.WriteFile(t, filepath.Join(k0s, "pki", "sa.pub"), "PUBKEY-BYTES-2")
	cdepstest.Check[*pki.DriftCheck](e.H, cdeps.CheckPKIDrift).Run(context.Background())
	data, err = os.ReadFile(filepath.Join(cdeps.TextfileDirOverride, pki.SAPubPromFile))
	if err != nil {
		t.Fatal(err)
	}
	sum2 := sha256.Sum256([]byte("PUBKEY-BYTES-2"))
	want2 := pki.SAPubMetric + `{sha256="` + hex.EncodeToString(sum2[:]) + `"} 1`
	if !strings.Contains(string(data), want2) {
		t.Fatalf("drifted fingerprint not exported:\n%s", data)
	}
}

// A missing sa.pub emits headers-only — the series goes absent,
// never a fabricated hash.
func TestSAPubFingerprintMissingFile(t *testing.T) {
	e := fixture(t)
	root := t.TempDir()
	e.H.Cfg.K0sDir = filepath.Join(root, "k0s") // no sa.pub
	oldTD := cdeps.TextfileDirOverride
	cdeps.TextfileDirOverride = filepath.Join(root, "textfile")
	defer func() { cdeps.TextfileDirOverride = oldTD }()

	cdepstest.Check[*pki.DriftCheck](e.H, cdeps.CheckPKIDrift).Run(context.Background())
	data, err := os.ReadFile(filepath.Join(cdeps.TextfileDirOverride, pki.SAPubPromFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "# TYPE "+pki.SAPubMetric) {
		t.Fatalf("header missing:\n%s", data)
	}
	for _, l := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(l, pki.SAPubMetric+"{") ||
			strings.HasPrefix(l, pki.SAPubMetric+" ") {
			t.Fatalf("fake sample emitted for a missing sa.pub:\n%s", data)
		}
	}
}

// --- pki-cert-drift Run: the per-pair state machine ---

// mintLeafPEM mints a self-signed non-CA leaf PEM with the given
// serial + NotAfter (P256 — fast) and returns the parsed cert (the
// socket-presented side) and the PEM bytes (the disk side).
func mintLeafPEM(t *testing.T, serial int64, notAfter time.Time) (*x509.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "drift-test"},
		NotBefore:    notAfter.Add(-24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl,
		&key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	crt, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return crt, string(pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// driftEnv wires a fixture whose single pair serves disk cert
// certPEM with sock presented by the stubbed TLSCertFn (sockErr
// simulates a dead socket). The SA textfile override is set like in
// every DriftCheck Run test — the fingerprint export rides the same
// cycle.
func driftEnv(t *testing.T, sock *x509.Certificate, sockErr error,
	certPEM string) *env {
	t.Helper()
	e := fixture(t)
	disk := filepath.Join(t.TempDir(), "apiserver.crt")
	testutil.WriteFile(t, disk, certPEM)
	e.H.Cfg.PKIDrift.Pairs = []cdeps.PKIDriftPair{{
		CertFile: disk,
		Addr:     "127.0.0.1:6443",
		Unit:     "k0scontroller.service",
	}}
	e.H.Cfg.TLSCertFn = func(context.Context, string) (*x509.Certificate, error) {
		return sock, sockErr
	}
	root := t.TempDir()
	oldTD := cdeps.TextfileDirOverride
	cdeps.TextfileDirOverride = filepath.Join(root, "textfile")
	t.Cleanup(func() { cdeps.TextfileDirOverride = oldTD })
	return e
}

// The socket being down is inconclusive evidence: the streak resets
// instead of accumulating toward a restart.
func TestDriftRunSocketDown(t *testing.T) {
	_, certPEM := mintLeafPEM(t, 1, time.Now().Add(24*time.Hour))
	e := driftEnv(t, nil, errors.New("dial: connection refused"), certPEM)

	cdepstest.Check[*pki.DriftCheck](e.H, cdeps.CheckPKIDrift).Run(context.Background())

	if got := e.H.State.Counter(cdeps.FileCtrPKIDriftPre + "0"); got != 0 {
		t.Fatalf("streak counter=%d want 0 (reset on socket error)", got)
	}
	if e.HasState(cdeps.StatePKIReloadStale) {
		t.Fatal("socket-down run latched state-cp-cert-reload-stale")
	}
}

// Disk cert identical to the served one — no drift, streak resets,
// a stale latch from a previous episode is released.
func TestDriftRunNoDrift(t *testing.T) {
	sock, certPEM := mintLeafPEM(t, 1, time.Now().Add(24*time.Hour))
	e := driftEnv(t, sock, nil, certPEM)
	// A previous episode left the latch held: a clean cycle must exit it.
	testutil.WriteFile(t, e.StateFile("cp-cert-reload-stale"), "1")

	cdepstest.Check[*pki.DriftCheck](e.H, cdeps.CheckPKIDrift).Run(context.Background())

	if got := e.H.State.Counter(cdeps.FileCtrPKIDriftPre + "0"); got != 0 {
		t.Fatalf("streak counter=%d want 0 (reset on no-drift)", got)
	}
	if e.HasState(cdeps.StatePKIReloadStale) {
		t.Fatal("clean cycle left state-cp-cert-reload-stale latched")
	}
	if v := promtest.ToFloat64(e.H.Cycles.WithLabelValues(cdeps.CheckPKIDrift, "ok")); v != 1 {
		t.Fatalf("ok counter=%v want 1", v)
	}
}

// Drift held for the streak length latches
// state-cp-cert-reload-stale and restarts the owning unit under the
// last-cp-cert-restart budget; the streak resets after the restart.
func TestDriftRunLatchesAndRestarts(t *testing.T) {
	sock, _ := mintLeafPEM(t, 1, time.Now().Add(24*time.Hour))
	_, diskPEM := mintLeafPEM(t, 2, time.Now().Add(48*time.Hour))
	e := driftEnv(t, sock, nil, diskPEM)
	streak := e.H.StreakCycles(e.H.Cfg.PKIDrift.Cycles)

	for range streak - 1 {
		cdepstest.Check[*pki.DriftCheck](e.H, cdeps.CheckPKIDrift).Run(context.Background())
		if e.HasState(cdeps.StatePKIReloadStale) {
			t.Fatal("latched before the streak was reached")
		}
	}
	if got := e.H.State.Counter(cdeps.FileCtrPKIDriftPre + "0"); got != streak-1 {
		t.Fatalf("streak counter=%d want %d below the gate", got, streak-1)
	}
	cdepstest.Check[*pki.DriftCheck](e.H, cdeps.CheckPKIDrift).Run(context.Background())

	if !e.HasState(cdeps.StatePKIReloadStale) {
		t.Fatal("drift streak did not latch state-cp-cert-reload-stale")
	}
	if e.RstN() != 1 || e.RstAt(0) != "k0scontroller.service" {
		t.Fatalf("restarts=%d first=%q want k0scontroller.service",
			e.RstN(), e.RstAt(0))
	}
	if n := e.CountLogLines("ACTION: restarting k0scontroller.service"); n != 1 {
		t.Fatalf("ACTION log lines=%d want 1:\n%s", n, e.LogLines())
	}
	if got := e.H.State.Counter(cdeps.FileCtrPKIDriftPre + "0"); got != 0 {
		t.Fatalf("streak counter=%d want 0 (reset after restart)", got)
	}
	if e.H.State.RateOK(cdeps.FileRatePKIRestart,
		e.H.Cfg.PKIDrift.RestartInterval) {
		t.Fatal("restart budget not spent")
	}
	if v := promtest.ToFloat64(e.H.Actions.WithLabelValues(
		cdeps.CheckPKIDrift, "restart_unit")); v != 1 {
		t.Fatalf("restart_unit counter=%v want 1", v)
	}
	if v := promtest.ToFloat64(e.H.Cycles.WithLabelValues(cdeps.CheckPKIDrift, "ok")); v != float64(streak) {
		t.Fatalf("ok counter=%v want %d", v, streak)
	}
}

// A restart that fails is surfaced as a suspect log line — the
// action was attempted and the budget spent either way.
func TestDriftRunRestartFails(t *testing.T) {
	sock, _ := mintLeafPEM(t, 1, time.Now().Add(24*time.Hour))
	_, diskPEM := mintLeafPEM(t, 2, time.Now().Add(48*time.Hour))
	e := driftEnv(t, sock, nil, diskPEM)
	base := e.H.Cfg.HostExecFn
	e.H.Cfg.HostExecFn = func(ctx context.Context, host bool, d time.Duration,
		name string, args ...string) (string, error) {
		if name == "systemctl" && len(args) >= 2 && args[0] == "restart" {
			return "", errors.New("systemd unreachable")
		}
		return base(ctx, host, d, name, args...)
	}

	for range e.H.StreakCycles(e.H.Cfg.PKIDrift.Cycles) {
		cdepstest.Check[*pki.DriftCheck](e.H, cdeps.CheckPKIDrift).Run(context.Background())
	}

	if n := e.CountLogLines("suspect: restart k0scontroller.service failed"); n == 0 {
		t.Fatalf("failed restart not suspect-logged:\n%s", e.LogLines())
	}
	if !e.HasState(cdeps.StatePKIReloadStale) {
		t.Fatal("failed-restart episode lost its latch")
	}
	if v := promtest.ToFloat64(e.H.Actions.WithLabelValues(
		cdeps.CheckPKIDrift, "restart_unit")); v != 1 {
		t.Fatalf("restart_unit counter=%v want 1 (attempt counts)", v)
	}
	if e.H.State.RateOK(cdeps.FileRatePKIRestart,
		e.H.Cfg.PKIDrift.RestartInterval) {
		t.Fatal("failed restart did not spend the budget")
	}
}

// Inside the restart cooldown the drift still latches but the
// restart is skipped with a suspect line and the streak survives.
func TestDriftRunCooldownSkipsRestart(t *testing.T) {
	sock, _ := mintLeafPEM(t, 1, time.Now().Add(24*time.Hour))
	_, diskPEM := mintLeafPEM(t, 2, time.Now().Add(48*time.Hour))
	e := driftEnv(t, sock, nil, diskPEM)
	e.H.State.RateSpend(cdeps.FileRatePKIRestart) // budget just spent
	streak := e.H.StreakCycles(e.H.Cfg.PKIDrift.Cycles)

	for range streak {
		cdepstest.Check[*pki.DriftCheck](e.H, cdeps.CheckPKIDrift).Run(context.Background())
	}

	if !e.HasState(cdeps.StatePKIReloadStale) {
		t.Fatal("cooldown drift did not latch state-cp-cert-reload-stale")
	}
	if e.RstN() != 0 {
		t.Fatalf("restart performed inside the cooldown: %v", e.RstAt(0))
	}
	if n := e.CountLogLines("suspect: cp-cert-reload-stale"); n == 0 {
		t.Fatalf("cooldown skip not suspect-logged:\n%s", e.LogLines())
	}
	if got := e.H.State.Counter(cdeps.FileCtrPKIDriftPre + "0"); got != streak {
		t.Fatalf("streak counter=%d want %d (kept while in cooldown)", got, streak)
	}
	if v := promtest.ToFloat64(e.H.Actions.WithLabelValues(
		cdeps.CheckPKIDrift, "restart_unit")); v != 0 {
		t.Fatalf("restart_unit counter=%v want 0", v)
	}
}

// Dry-run mode logs the action it would take and counts the metric,
// but never restarts, never spends the budget and never resets the
// streak.
func TestDriftRunDryRun(t *testing.T) {
	sock, _ := mintLeafPEM(t, 1, time.Now().Add(24*time.Hour))
	_, diskPEM := mintLeafPEM(t, 2, time.Now().Add(48*time.Hour))
	e := driftEnv(t, sock, nil, diskPEM)
	e.H.Cfg.Sig13.Mode = cdeps.ModeDryRun
	streak := e.H.StreakCycles(e.H.Cfg.PKIDrift.Cycles)

	for range streak {
		cdepstest.Check[*pki.DriftCheck](e.H, cdeps.CheckPKIDrift).Run(context.Background())
	}

	if n := e.CountLogLines("DRY-RUN: would restart k0scontroller.service"); n != 1 {
		t.Fatalf("DRY-RUN log lines=%d want 1:\n%s", n, e.LogLines())
	}
	if e.RstN() != 0 {
		t.Fatalf("dry-run restarted a unit: %v", e.RstAt(0))
	}
	if v := promtest.ToFloat64(e.H.Actions.WithLabelValues(
		cdeps.CheckPKIDrift, "dryrun_restart")); v != 1 {
		t.Fatalf("dryrun_restart counter=%v want 1", v)
	}
	if got := e.H.State.Counter(cdeps.FileCtrPKIDriftPre + "0"); got != streak {
		t.Fatalf("streak counter=%d want %d (dry-run keeps the streak)", got, streak)
	}
	if !e.H.State.RateOK(cdeps.FileRatePKIRestart,
		e.H.Cfg.PKIDrift.RestartInterval) {
		t.Fatal("dry-run spent the restart budget")
	}
	if v := promtest.ToFloat64(e.H.Actions.WithLabelValues(
		cdeps.CheckPKIDrift, "restart_unit")); v != 0 {
		t.Fatalf("restart_unit counter=%v want 0 in dry-run", v)
	}
}
