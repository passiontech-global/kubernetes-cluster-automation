// pki_cert_drift.go — W8-CP4 PKI reload drift detection:
//
//	After cert rotation the on-disk cert can be newer than the one
//	a live socket still presents (the daemon never reloaded).
//	Compare SerialNumber + NotAfter of the on-disk file vs the
//	socket-presented leaf for each PKIDriftPair; drift for
//	PKIDriftCycles consecutive cycles latches
//	state-cp-cert-reload-stale and restarts the owning unit under
//	the last-cp-cert-restart budget.
//
//	W12-CP4a: the same Run also exports the SHA-256 fingerprint of
//	the k0s ServiceAccount token signer public key (sa.pub) to the
//	textfile channel — a signer key drifted between control-plane
//	nodes means TokenRequest tokens minted on this node randomly
//	401 on the other apiservers.
package pki

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
)

// SAPubMetric/SAPubPromFile — the W12-CP4a ServiceAccount signer-key
// fingerprint export: same series the hostmetrics collector exports
// on pods ({sha256} only here — the textfile is already node-local).
// saPubHashHelp is the identical sentence hostmetrics carries in
// its desc: the textfile collector rejects a family whose HELP
// lines disagree across .prom files, so keep them in lockstep.
const (
	SAPubMetric   = "node_k0s_sa_pub_fingerprint_hash"
	SAPubPromFile = "node-agent-sa-pub-fp.prom"
	saPubHashHelp = "SHA-256 fingerprint of the k0s ServiceAccount " +
		"token signer public key (sa.pub) — a differing hash across " +
		"control-plane nodes is signer key skew (TokenRequest 401s)."
)

// sha256FileHex returns the hex SHA-256 of a file's raw bytes —
// sa.pub is hashed whole (not parsed): a drifted file must change
// the fingerprint even when the drift is a stray byte, not a
// different key.
func sha256FileHex(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// emitSAPubFingerprint — W12-CP4a: write
// node_k0s_sa_pub_fingerprint_hash{sha256=...} to the textfile
// channel every cycle. The whole subsystem only runs on
// k0scontroller hosts (unit-file gate in Cycle/ShouldRun), so no
// extra control-plane gate is needed. A missing/unreadable sa.pub
// emits headers-only — the series goes absent, never a fake hash.
func (c *DriftCheck) emitSAPubFingerprint() {
	var p promfile.Builder
	sum, err := sha256FileHex(filepath.Join(c.d.Cfg.K0sDir, "pki", "sa.pub"))
	if err != nil {
		p.Header(SAPubMetric, saPubHashHelp)
	} else {
		p.GaugeLabels(SAPubMetric, saPubHashHelp,
			fmt.Sprintf("sha256=%q", sum), 1)
	}
	c.d.WriteTextfileProm(SAPubPromFile, p.String())
}

// DriftCheck is the W8-CP4 PKI reload drift detector as a
// Check — stateless: per-pair streaks live in the
// consecutive-cp-cert-stale-<i> counters.
type DriftCheck struct {
	d *cdeps.Deps
}

// Name returns the check label / log context.
func (c *DriftCheck) Name() string { return cdeps.CheckPKIDrift }

// Run — W8-CP4. For each pair: read the on-disk leaf and the
// socket-presented leaf; drift means the file describes a NEWER cert
// (later NotAfter, or different serial with a not-older NotAfter)
// than the socket serves. Drift held for PKIDriftCycles consecutive
// cycles latches the state and restarts the owning unit under the
// last-cp-cert-restart budget. W12-CP4a rides the same cycle: the
// sa.pub signer-key fingerprint export runs first so it lands even
// when a pair fails early.
func (c *DriftCheck) Run(ctx context.Context) {
	c.emitSAPubFingerprint()
	anyDrift := false
	for i, pair := range c.d.Cfg.PKIDrift.Pairs {
		ctr := cdeps.FileCtrPKIDriftPre + strconv.Itoa(i)
		disk, err := readLeafCert(pair.CertFile)
		if err != nil {
			// Cert absent — not a controller / pair not deployed on
			// this host. Reset rather than carry a stale count.
			c.d.State.ResetCounter(ctr)
			continue
		}
		sock, err := c.d.Cfg.TLSCertFn(ctx, pair.Addr)
		if err != nil {
			// Socket down is someone else's check — the drift
			// comparison is inconclusive, not evidence.
			c.d.State.ResetCounter(ctr)
			continue
		}
		if !CertNewerThan(disk, sock) {
			c.d.State.ResetCounter(ctr)
			continue
		}
		anyDrift = true
		n := c.d.State.Incr(ctr)
		if n < c.d.StreakCycles(c.d.Cfg.PKIDrift.Cycles) {
			continue
		}
		c.d.State.Enter(cdeps.StatePKIReloadStale, fmt.Sprintf(
			"%s newer than %s (disk notAfter=%s socket=%s)",
			pair.CertFile, pair.Addr,
			disk.NotAfter.UTC().Format(time.RFC3339),
			sock.NotAfter.UTC().Format(time.RFC3339)))
		if !c.d.State.RateOK(cdeps.FileRatePKIRestart,
			c.d.Cfg.PKIDrift.RestartInterval) {
			c.d.State.SuspectLog(cdeps.StatePKIReloadStale, fmt.Sprintf(
				"suspect: cp-cert-reload-stale %s but in restart cooldown (<%dm), skip",
				pair.CertFile, int(c.d.Cfg.PKIDrift.RestartInterval.Minutes())),
				c.d.Cfg.SuspectLogCadence)
			continue
		}
		switch c.d.Cfg.Sig13.Mode {
		case cdeps.ModeEnforce:
			c.d.State.AppendLog(fmt.Sprintf(
				"ACTION: restarting %s - cp-cert-reload-stale %s newer than %s",
				pair.Unit, pair.CertFile, pair.Addr))
			c.d.State.RateSpend(cdeps.FileRatePKIRestart)
			c.d.State.ResetCounter(ctr)
			if err := c.d.Restart(ctx, pair.Unit); err != nil {
				c.d.State.AppendLogWarn(fmt.Sprintf(
					"suspect: restart %s failed: %v", pair.Unit, err))
			}
			c.d.Actions.WithLabelValues(cdeps.CheckPKIDrift, "restart_unit").Inc()
		case cdeps.ModeDryRun:
			c.d.State.AppendLog(fmt.Sprintf(
				"DRY-RUN: would restart %s - cp-cert-reload-stale %s",
				pair.Unit, pair.CertFile))
			c.d.Actions.WithLabelValues(cdeps.CheckPKIDrift, "dryrun_restart").Inc()
		}
	}
	if !anyDrift {
		c.d.StateExit(cdeps.StatePKIReloadStale)
	}
	c.d.Cycles.WithLabelValues(cdeps.CheckPKIDrift, "ok").Inc()
}

// CertNewerThan reports whether disk is a rotated-newer cert the
// socket has not loaded: a later NotAfter, or a different serial
// while NotAfter is not older (rotation that keeps the same window).
// An OLDER disk cert (rollback, stale file) is not drift.
func CertNewerThan(disk, sock *x509.Certificate) bool {
	switch {
	case disk.SerialNumber.Cmp(sock.SerialNumber) == 0 &&
		disk.NotAfter.Equal(sock.NotAfter):
		return false // identical cert — loaded
	case disk.NotAfter.After(sock.NotAfter):
		return true
	case disk.SerialNumber.Cmp(sock.SerialNumber) != 0 &&
		disk.NotAfter.Equal(sock.NotAfter):
		return true
	}
	return false
}

// readLeafCert parses the first PEM cert block of a file.
func readLeafCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	return x509.ParseCertificate(block.Bytes)
}
