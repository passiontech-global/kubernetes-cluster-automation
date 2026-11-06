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
package controllerhygiene

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
)

// checkPKIDrift is the prometheus `check` label + log context for
// the PKI reload drift check.
const checkPKIDrift = "cp-cert-drift"

// saPubMetric/saPubPromFile — the W12-CP4a ServiceAccount signer-key
// fingerprint export: same series the hostmetrics collector exports
// on pods ({sha256} only here — the textfile is already node-local).
// saPubHashHelp is the identical sentence hostmetrics carries in
// its desc: the textfile collector rejects a family whose HELP
// lines disagree across .prom files, so keep them in lockstep.
const (
	saPubMetric   = "node_k0s_sa_pub_fingerprint_hash"
	saPubPromFile = "node-agent-sa-pub-fp.prom"
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
func (c *pkiDriftCheck) emitSAPubFingerprint() {
	var p promfile.Builder
	sum, err := sha256FileHex(filepath.Join(c.d.cfg.K0sDir, "pki", "sa.pub"))
	if err != nil {
		p.Header(saPubMetric, saPubHashHelp)
	} else {
		p.GaugeLabels(saPubMetric, saPubHashHelp,
			fmt.Sprintf("sha256=%q", sum), 1)
	}
	c.d.writeTextfileProm(saPubPromFile, p.String())
}

// tlsDialCert returns the leaf certificate addr presents — drift is
// judged on the presented cert, not on chain trust, so the dial is
// insecure by design.
func tlsDialCert(ctx context.Context, addr string) (*x509.Certificate, error) {
	d := &net.Dialer{Timeout: 8 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", addr,
		&tls.Config{InsecureSkipVerify: true}) // drift check wants the presented cert
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, errors.New("no peer certificate")
	}
	return state.PeerCertificates[0], nil
}

// pkiDriftCheck is the W8-CP4 PKI reload drift detector as a
// Check — stateless: per-pair streaks live in the
// consecutive-cp-cert-stale-<i> counters.
type pkiDriftCheck struct {
	d *deps
}

// Name returns the check label / log context.
func (c *pkiDriftCheck) Name() string { return checkPKIDrift }

// Run — W8-CP4. For each pair: read the on-disk leaf and the
// socket-presented leaf; drift means the file describes a NEWER cert
// (later NotAfter, or different serial with a not-older NotAfter)
// than the socket serves. Drift held for PKIDriftCycles consecutive
// cycles latches the state and restarts the owning unit under the
// last-cp-cert-restart budget. W12-CP4a rides the same cycle: the
// sa.pub signer-key fingerprint export runs first so it lands even
// when a pair fails early.
func (c *pkiDriftCheck) Run(ctx context.Context) {
	c.emitSAPubFingerprint()
	anyDrift := false
	for i, pair := range c.d.cfg.PKIDrift.Pairs {
		ctr := fileCtrPKIDriftPre + strconv.Itoa(i)
		disk, err := readLeafCert(pair.CertFile)
		if err != nil {
			// Cert absent — not a controller / pair not deployed on
			// this host. Reset rather than carry a stale count.
			c.d.state.ResetCounter(ctr)
			continue
		}
		sock, err := c.d.cfg.tlsCertFn(ctx, pair.Addr)
		if err != nil {
			// Socket down is someone else's check — the drift
			// comparison is inconclusive, not evidence.
			c.d.state.ResetCounter(ctr)
			continue
		}
		if !certNewerThan(disk, sock) {
			c.d.state.ResetCounter(ctr)
			continue
		}
		anyDrift = true
		n := c.d.state.Incr(ctr)
		if n < c.d.cfg.PKIDrift.Cycles {
			continue
		}
		c.d.state.Enter(statePKIReloadStale, fmt.Sprintf(
			"%s newer than %s (disk notAfter=%s socket=%s)",
			pair.CertFile, pair.Addr,
			disk.NotAfter.UTC().Format(time.RFC3339),
			sock.NotAfter.UTC().Format(time.RFC3339)))
		if !c.d.state.RateOK(fileRatePKIRestart,
			c.d.cfg.PKIDrift.RestartInterval) {
			c.d.state.SuspectLog(statePKIReloadStale, fmt.Sprintf(
				"suspect: cp-cert-reload-stale %s but in restart cooldown (<%dm), skip",
				pair.CertFile, int(c.d.cfg.PKIDrift.RestartInterval.Minutes())),
				c.d.cfg.SuspectLogCadence)
			continue
		}
		switch c.d.cfg.Sig13.Mode {
		case ModeEnforce:
			c.d.state.AppendLog(fmt.Sprintf(
				"ACTION: restarting %s - cp-cert-reload-stale %s newer than %s",
				pair.Unit, pair.CertFile, pair.Addr))
			c.d.state.RateSpend(fileRatePKIRestart)
			c.d.state.ResetCounter(ctr)
			if err := c.d.cfg.restartFn(ctx, pair.Unit); err != nil {
				c.d.state.AppendLogWarn(fmt.Sprintf(
					"suspect: restart %s failed: %v", pair.Unit, err))
			}
			c.d.actions.WithLabelValues(checkPKIDrift, "restart_unit").Inc()
		case ModeDryRun:
			c.d.state.AppendLog(fmt.Sprintf(
				"DRY-RUN: would restart %s - cp-cert-reload-stale %s",
				pair.Unit, pair.CertFile))
			c.d.actions.WithLabelValues(checkPKIDrift, "dryrun_restart").Inc()
		}
	}
	if !anyDrift {
		c.d.stateExit(statePKIReloadStale)
	}
	c.d.cycles.WithLabelValues(checkPKIDrift, "ok").Inc()
}

// certNewerThan reports whether disk is a rotated-newer cert the
// socket has not loaded: a later NotAfter, or a different serial
// while NotAfter is not older (rotation that keeps the same window).
// An OLDER disk cert (rollback, stale file) is not drift.
func certNewerThan(disk, sock *x509.Certificate) bool {
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
