// pki_cert_drift.go — pki-cert-drift PKI reload drift detection:
//
//	After cert rotation the on-disk cert can be newer than the one
//	a live socket still presents (the daemon never reloaded).
//	Compare SerialNumber + NotAfter of the on-disk file vs the
//	socket-presented leaf for each PKIDriftPair; drift for
//	PKIDriftCycles consecutive cycles latches
//	state-cp-cert-reload-stale and restarts the owning unit under
//	the last-cp-cert-restart budget.
//
//	sa-pub-key-fingerprint: the same Run also exports the SHA-256 fingerprint of
//	the k0s ServiceAccount token signer public key (sa.pub) to the
//	textfile channel — a signer key drifted between control-plane
//	nodes means TokenRequest tokens minted on this node randomly
//	401 on the other apiservers.
package pki

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/pagecache"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
)

// SAPubMetric/SAPubPromFile — the sa-pub-key-fingerprint ServiceAccount signer-key
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

// emitSAPubFingerprint — sa-pub-key-fingerprint: write
// node_k0s_sa_pub_fingerprint_hash{sha256=...} to the textfile
// channel every cycle. The whole subsystem only runs on
// k0scontroller hosts (unit-file gate in Cycle/ShouldRun), so no
// extra control-plane gate is needed. A missing/unreadable sa.pub
// emits headers-only — the series goes absent, never a fake hash.
func (c *DriftCheck) emitSAPubFingerprint() {
	var p promfile.Builder
	// sa.pub is hashed whole (not parsed): a drifted file must
	// change the fingerprint even when the drift is a stray byte,
	// not a different key.
	sum, err := pagecache.Sha256File(filepath.Join(c.d.Cfg.K0sDir, "pki", "sa.pub"))
	if err != nil {
		p.Header(SAPubMetric, saPubHashHelp)
	} else {
		p.GaugeLabels(SAPubMetric, saPubHashHelp,
			fmt.Sprintf("sha256=%q", sum), 1)
	}
	c.d.WriteTextfileProm(SAPubPromFile, p.String())
}

// DriftCheck is the pki-cert-drift PKI reload drift detector as a
// Check — stateless: per-pair streaks live in the
// consecutive-cp-cert-stale-<i> counters.
type DriftCheck struct {
	d *cdeps.Deps
}

// Name returns the check label / log context.
func (c *DriftCheck) Name() string { return cdeps.CheckPKIDrift }

// Run — pki-cert-drift. For each pair: read the on-disk leaf and the
// socket-presented leaf; drift means the file describes a NEWER cert
// (later NotAfter, or different serial with a not-older NotAfter)
// than the socket serves. Drift held for PKIDriftCycles consecutive
// cycles latches the state and restarts the owning unit under the
// last-cp-cert-restart budget. sa-pub-key-fingerprint rides the same cycle: the
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
		// Budget file follows the unit being restarted: pairs that
		// bounce RestartUnit share the controller-wide
		// FileRateRestart budget with the sig13/cp-freeze heals;
		// other units (kine.service) keep the pki-private file.
		budget := cdeps.FileRatePKIRestart
		if pair.Unit == c.d.Cfg.RestartUnit {
			budget = cdeps.FileRateRestart
		}
		c.d.RestartWithGates(ctx, cdeps.RestartGateSpec{
			Check:         cdeps.CheckPKIDrift,
			State:         cdeps.StatePKIReloadStale,
			Budget:        budget,
			Cooldown:      c.d.Cfg.PKIDrift.RestartInterval,
			NeedQuorum:    pair.Unit == c.d.Cfg.RestartUnit,
			HoldPrefix:    "cp-cert-reload-stale " + pair.CertFile,
			Unit:          pair.Unit,
			ActionLine:    fmt.Sprintf("ACTION: restarting %s - cp-cert-reload-stale %s newer than %s", pair.Unit, pair.CertFile, pair.Addr),
			DryRunLine:    fmt.Sprintf("DRY-RUN: would restart %s - cp-cert-reload-stale %s", pair.Unit, pair.CertFile),
			ActionLabel:   "restart_unit",
			DryRunLabel:   "dryrun_restart",
			BeforeRestart: func() { c.d.State.ResetCounter(ctr) },
		})
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

// readLeafCert parses the leaf certificate of a file: the first PEM
// block whose cert is NOT a CA (IsCA == false) — bundles carry the
// chain after the leaf, and comparing the socket cert against an
// intermediate would flag phantom drift. Falls back to the first
// block when the file only holds CA certs.
func readLeafCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var first *x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		crt, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		if first == nil {
			first = crt
		}
		if !crt.IsCA {
			return crt, nil
		}
	}
	if first != nil {
		return first, nil
	}
	return nil, fmt.Errorf("no PEM certificate in %s", path)
}
