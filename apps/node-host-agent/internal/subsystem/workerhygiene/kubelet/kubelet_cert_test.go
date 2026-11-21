// kubelet_cert_test.go — external tests for #4 worker kubelet serving cert
// expiry & :10250 reload-drift guard (package kubelet_test).
package kubelet_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/nodecoord"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/kubelet"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

func makeTestCertPEM(t *testing.T, serial int64, notBefore, notAfter time.Time, isCA bool) (*x509.Certificate, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	crt, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return crt, pemBytes
}

func writePKIFile(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestKubeletCertMissingPKISkipsCleanly(t *testing.T) {
	e := fixture(t)
	dialed := false
	e.H.Cfg.Seams.Probe.TLSPeerCertFn = func(context.Context, string) (*x509.Certificate, error) {
		dialed = true
		return nil, errors.New("must not dial")
	}
	// Seed a stale latch to verify empty PKIDir clears it cleanly.
	e.H.State.Enter(latchdefs.LatchWorkerKubeletCertExpiring, "stale")

	e.H.Cycle(context.Background())

	if dialed {
		t.Fatal("TLSPeerCertFn called when both PKI PEMs are absent")
	}
	if e.H.State.Exists(latchdefs.LatchWorkerKubeletCertExpiring) {
		t.Fatal("expected stale LatchWorkerKubeletCertExpiring to clear on empty PKI dir")
	}
	if e.SDRan("restart k0sworker.service") {
		t.Fatal("unexpected k0sworker restart")
	}
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckKubeletCert, "ok")); got != 1 {
		t.Fatalf("ok cycles=%v want 1", got)
	}
}

func TestKubeletCertHealthy(t *testing.T) {
	e := fixture(t)
	_, clientPEM := makeTestCertPEM(t, 10, e.Now.Add(-time.Hour), e.Now.Add(30*24*time.Hour), false)
	srvCert, srvPEM := makeTestCertPEM(t, 20, e.Now.Add(-time.Hour), e.Now.Add(45*24*time.Hour), false)
	_, caPEM := makeTestCertPEM(t, 1, e.Now.Add(-time.Hour), e.Now.Add(365*24*time.Hour), true)

	writePKIFile(t, e.KubeletPKIDir, "kubelet-client-current.pem", clientPEM)
	writePKIFile(t, e.KubeletPKIDir, "kubelet-server-current.pem", append(srvPEM, caPEM...))
	e.TLSPeerCert = srvCert

	e.H.State.Enter(latchdefs.LatchWorkerKubeletCertExpiring, "stale")
	e.H.Cycle(context.Background())

	if e.H.State.Exists(latchdefs.LatchWorkerKubeletCertExpiring) {
		t.Fatal("healthy certs must clear LatchWorkerKubeletCertExpiring")
	}
	if e.SDRan("restart k0sworker.service") {
		t.Fatal("healthy certs must not restart k0sworker")
	}
}

func TestKubeletCertExpiringClientOrServerNoRestart(t *testing.T) {
	t.Run("client cert < 14d", func(t *testing.T) {
		e := fixture(t)
		_, clientPEM := makeTestCertPEM(t, 11, e.Now.Add(-time.Hour), e.Now.Add(5*24*time.Hour), false)
		srvCert, srvPEM := makeTestCertPEM(t, 21, e.Now.Add(-time.Hour), e.Now.Add(60*24*time.Hour), false)
		writePKIFile(t, e.KubeletPKIDir, "kubelet-client-current.pem", clientPEM)
		writePKIFile(t, e.KubeletPKIDir, "kubelet-server-current.pem", srvPEM)
		e.TLSPeerCert = srvCert

		for range 3 {
			e.H.Cycle(context.Background())
		}
		if !e.H.State.Exists(latchdefs.LatchWorkerKubeletCertExpiring) {
			t.Fatal("expected LatchWorkerKubeletCertExpiring for <14d client cert")
		}
		if e.SDRan("restart k0sworker.service") {
			t.Fatal("must NEVER restart k0sworker on expiry alone")
		}
		if !strings.Contains(e.LogLines(t), "suspect: kubelet-cert expiring") {
			t.Fatalf("missing suspect log:\n%s", e.LogLines(t))
		}
	})

	t.Run("server cert < 14d", func(t *testing.T) {
		e := fixture(t)
		_, clientPEM := makeTestCertPEM(t, 12, e.Now.Add(-time.Hour), e.Now.Add(60*24*time.Hour), false)
		srvCert, srvPEM := makeTestCertPEM(t, 22, e.Now.Add(-time.Hour), e.Now.Add(3*24*time.Hour), false)
		writePKIFile(t, e.KubeletPKIDir, "kubelet-client-current.pem", clientPEM)
		writePKIFile(t, e.KubeletPKIDir, "kubelet-server-current.pem", srvPEM)
		e.TLSPeerCert = srvCert

		for range 3 {
			e.H.Cycle(context.Background())
		}
		if !e.H.State.Exists(latchdefs.LatchWorkerKubeletCertExpiring) {
			t.Fatal("expected LatchWorkerKubeletCertExpiring for <14d server cert")
		}
		if e.SDRan("restart k0sworker.service") {
			t.Fatal("must NEVER restart k0sworker on expiry alone")
		}
	})
}

func TestKubeletCertReloadDriftTwoCycleConfirmAndRecover(t *testing.T) {
	e := fixture(t)
	e.SDReply["systemctl restart k0sworker.service"] = ""
	_, clientPEM := makeTestCertPEM(t, 13, e.Now.Add(-time.Hour), e.Now.Add(90*24*time.Hour), false)
	oldLive, _ := makeTestCertPEM(t, 100, e.Now.Add(-24*time.Hour), e.Now.Add(30*24*time.Hour), false)
	newDisk, newDiskPEM := makeTestCertPEM(t, 200, e.Now.Add(-time.Minute), e.Now.Add(90*24*time.Hour), false)

	writePKIFile(t, e.KubeletPKIDir, "kubelet-client-current.pem", clientPEM)
	writePKIFile(t, e.KubeletPKIDir, "kubelet-server-current.pem", newDiskPEM)
	e.TLSPeerCert = oldLive

	chk := wdepstest.Check[*kubelet.CertCheck](e.H, wdeps.CheckKubeletCert)

	// Cycle 1: pending — no latch, no restart.
	e.H.Cycle(context.Background())
	if chk.DriftFails != 1 {
		t.Fatalf("DriftFails=%d want 1 after cycle 1", chk.DriftFails)
	}
	if e.H.State.Exists(latchdefs.LatchWorkerKubeletCertExpiring) {
		t.Fatal("must not latch on 1st drift cycle")
	}
	if e.SDRan("restart k0sworker.service") {
		t.Fatal("must not restart on 1st drift cycle")
	}

	// Cycle 2: confirmed -> latch + restart + 1h budget.
	e.H.Cycle(context.Background())
	if !e.H.State.Exists(latchdefs.LatchWorkerKubeletCertExpiring) {
		t.Fatal("expected LatchWorkerKubeletCertExpiring after 2 drift cycles")
	}
	if !e.SDRan("systemctl restart k0sworker.service") {
		t.Fatalf("expected k0sworker restart, cmds=%v", e.SDCmds)
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "last-kubelet-cert-reload")); err != nil {
		t.Fatalf("last-kubelet-cert-reload budget not stamped: %v", err)
	}
	if got := testutil.ToFloat64(e.H.Actions.WithLabelValues(wdeps.CheckKubeletCert, "restart")); got != 1 {
		t.Fatalf("restart action counter=%v want 1", got)
	}
	if !strings.Contains(e.LogLines(t), latchdefs.ActionK0sworkerRestart) {
		t.Fatalf("missing ACTION log:\n%s", e.LogLines(t))
	}
	if chk.DriftFails != 0 {
		t.Fatalf("DriftFails=%d want 0 after restart", chk.DriftFails)
	}

	// Cycle 3: k0sworker reloaded -> live cert matches disk -> latch clears.
	e.TLSPeerCert = newDisk
	e.H.Cycle(context.Background())
	if e.H.State.Exists(latchdefs.LatchWorkerKubeletCertExpiring) {
		t.Fatal("expected LatchWorkerKubeletCertExpiring to clear after reload")
	}
}

func TestKubeletCertOlderDiskCertNoDrift(t *testing.T) {
	e := fixture(t)
	_, clientPEM := makeTestCertPEM(t, 14, e.Now.Add(-time.Hour), e.Now.Add(90*24*time.Hour), false)
	liveNew, _ := makeTestCertPEM(t, 201, e.Now.Add(-time.Minute), e.Now.Add(90*24*time.Hour), false)
	_, diskOldPEM := makeTestCertPEM(t, 101, e.Now.Add(-24*time.Hour), e.Now.Add(30*24*time.Hour), false)

	writePKIFile(t, e.KubeletPKIDir, "kubelet-client-current.pem", clientPEM)
	writePKIFile(t, e.KubeletPKIDir, "kubelet-server-current.pem", diskOldPEM)
	e.TLSPeerCert = liveNew

	for range 3 {
		e.H.Cycle(context.Background())
	}
	if e.H.State.Exists(latchdefs.LatchWorkerKubeletCertExpiring) {
		t.Fatal("older disk cert must not trigger reload drift")
	}
	if e.SDRan("restart k0sworker.service") {
		t.Fatal("older disk cert must not restart k0sworker")
	}
}

func TestKubeletCertReloadDriftRateLimit(t *testing.T) {
	e := fixture(t)
	_, clientPEM := makeTestCertPEM(t, 15, e.Now.Add(-time.Hour), e.Now.Add(90*24*time.Hour), false)
	oldLive, _ := makeTestCertPEM(t, 102, e.Now.Add(-24*time.Hour), e.Now.Add(30*24*time.Hour), false)
	_, newDiskPEM := makeTestCertPEM(t, 202, e.Now.Add(-time.Minute), e.Now.Add(90*24*time.Hour), false)

	writePKIFile(t, e.KubeletPKIDir, "kubelet-client-current.pem", clientPEM)
	writePKIFile(t, e.KubeletPKIDir, "kubelet-server-current.pem", newDiskPEM)
	e.TLSPeerCert = oldLive

	// Pre-stamp last-kubelet-cert-reload at e.Now.
	wdepstest.WriteFile(t, filepath.Join(e.StateDir, "last-kubelet-cert-reload"),
		fmt.Sprintf("%d\n", e.Now.Unix()))

	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if e.SDRan("restart k0sworker.service") {
		t.Fatal("restart must be blocked inside 1h cooldown")
	}
	if !strings.Contains(e.LogLines(t), "in restart cooldown (<60m)") {
		t.Fatalf("missing <60m cooldown log:\n%s", e.LogLines(t))
	}

	// Advance past 1h -> next cycle restarts.
	e.Now = e.Now.Add(61 * time.Minute)
	e.H.Cycle(context.Background())
	if !e.SDRan("restart k0sworker.service") {
		t.Fatal("expected restart after 1h cooldown elapsed")
	}
}

func TestKubeletCertReloadDriftSettleGate(t *testing.T) {
	e := fixture(t)
	_, clientPEM := makeTestCertPEM(t, 16, e.Now.Add(-time.Hour), e.Now.Add(90*24*time.Hour), false)
	oldLive, _ := makeTestCertPEM(t, 103, e.Now.Add(-24*time.Hour), e.Now.Add(30*24*time.Hour), false)
	_, newDiskPEM := makeTestCertPEM(t, 203, e.Now.Add(-time.Minute), e.Now.Add(90*24*time.Hour), false)

	writePKIFile(t, e.KubeletPKIDir, "kubelet-client-current.pem", clientPEM)
	writePKIFile(t, e.KubeletPKIDir, "kubelet-server-current.pem", newDiskPEM)
	e.TLSPeerCert = oldLive

	// uptime=7200.5s; ActiveEnter=7140.5s -> active age 60s < 180s.
	e.SDReply["ActiveEnterTimestampMonotonic --value k0sworker.service"] = "7140500000\n"

	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())

	if e.SDRan("restart k0sworker.service") {
		t.Fatal("must not restart when k0sworker active < 180s")
	}
	if !strings.Contains(e.LogLines(t), "not settled (<180s)") {
		t.Fatalf("missing settle log:\n%s", e.LogLines(t))
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "last-kubelet-cert-reload")); !os.IsNotExist(err) {
		t.Fatal("last-kubelet-cert-reload budget must NOT be spent when blocked by settle gate")
	}
}

func TestKubeletCertReloadDriftMaintenanceHold(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-a",
			Annotations: map[string]string{
				nodecond.AnnoClusterMaintenanceUntil: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			},
		},
	}
	e := fixture(t, node)
	e.H.Cfg.Coord = nodecoord.NewKube("node-a", e.CS)
	e.H.Cfg.Coord.Now = func() time.Time { return e.Now }
	// Align annotation with e.Now.
	node.Annotations[nodecond.AnnoClusterMaintenanceUntil] = e.Now.Add(time.Hour).UTC().Format(time.RFC3339)
	if _, err := e.CS.CoreV1().Nodes().Update(context.Background(), node, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}

	_, clientPEM := makeTestCertPEM(t, 17, e.Now.Add(-time.Hour), e.Now.Add(90*24*time.Hour), false)
	oldLive, _ := makeTestCertPEM(t, 104, e.Now.Add(-24*time.Hour), e.Now.Add(30*24*time.Hour), false)
	_, newDiskPEM := makeTestCertPEM(t, 204, e.Now.Add(-time.Minute), e.Now.Add(90*24*time.Hour), false)

	writePKIFile(t, e.KubeletPKIDir, "kubelet-client-current.pem", clientPEM)
	writePKIFile(t, e.KubeletPKIDir, "kubelet-server-current.pem", newDiskPEM)
	e.TLSPeerCert = oldLive

	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())

	if e.SDRan("restart k0sworker.service") {
		t.Fatal("maintenance hold must block k0sworker restart")
	}
	if !strings.Contains(e.LogLines(t), "held by maintenance window") {
		t.Fatalf("missing maintenance hold log:\n%s", e.LogLines(t))
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "last-kubelet-cert-reload")); !os.IsNotExist(err) {
		t.Fatal("last-kubelet-cert-reload budget must NOT be spent when held by maintenance")
	}

	// Clear maintenance hold and advance past Coord CacheTTL (30s) -> restart fires.
	delete(node.Annotations, nodecond.AnnoClusterMaintenanceUntil)
	if _, err := e.CS.CoreV1().Nodes().Update(context.Background(), node, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.Now = e.Now.Add(time.Minute)
	e.H.Cycle(context.Background())
	if !e.SDRan("restart k0sworker.service") {
		t.Fatal("expected restart once maintenance hold cleared")
	}
}

func TestKubeletCertDialErrorAndCorruptPEM(t *testing.T) {
	e := fixture(t)
	_, clientPEM := makeTestCertPEM(t, 18, e.Now.Add(-time.Hour), e.Now.Add(90*24*time.Hour), false)
	oldLive, _ := makeTestCertPEM(t, 105, e.Now.Add(-24*time.Hour), e.Now.Add(30*24*time.Hour), false)
	_, newDiskPEM := makeTestCertPEM(t, 205, e.Now.Add(-time.Minute), e.Now.Add(90*24*time.Hour), false)

	writePKIFile(t, e.KubeletPKIDir, "kubelet-client-current.pem", clientPEM)
	writePKIFile(t, e.KubeletPKIDir, "kubelet-server-current.pem", newDiskPEM)
	e.TLSPeerCert = oldLive

	chk := wdepstest.Check[*kubelet.CertCheck](e.H, wdeps.CheckKubeletCert)

	// Cycle 1: 1st drift cycle.
	e.H.Cycle(context.Background())
	if chk.DriftFails != 1 {
		t.Fatalf("DriftFails=%d want 1", chk.DriftFails)
	}

	// Cycle 2: dial error -> resets DriftFails to 0, preserves existing latch, inconclusive.
	e.H.State.Enter(latchdefs.LatchWorkerKubeletCertExpiring, "prior")
	e.TLSPeerCertErr = errors.New("connection refused")
	e.H.Cycle(context.Background())
	if chk.DriftFails != 0 {
		t.Fatalf("DriftFails=%d want 0 on dial error", chk.DriftFails)
	}
	if !e.H.State.Exists(latchdefs.LatchWorkerKubeletCertExpiring) {
		t.Fatal("inconclusive dial error must preserve existing latch")
	}
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckKubeletCert, "inconclusive")); got != 1 {
		t.Fatalf("inconclusive cycles=%v want 1", got)
	}

	// Corrupt PEM -> abort, preserves latch & DriftFails.
	chk.DriftFails = 1
	writePKIFile(t, e.KubeletPKIDir, "kubelet-server-current.pem", []byte("not-a-pem"))
	e.H.Cycle(context.Background())
	if chk.DriftFails != 1 {
		t.Fatalf("DriftFails=%d want 1 preserved on abort", chk.DriftFails)
	}
	if !e.H.State.Exists(latchdefs.LatchWorkerKubeletCertExpiring) {
		t.Fatal("abort must preserve existing latch")
	}
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckKubeletCert, "abort")); got != 1 {
		t.Fatalf("abort cycles=%v want 1", got)
	}
}
