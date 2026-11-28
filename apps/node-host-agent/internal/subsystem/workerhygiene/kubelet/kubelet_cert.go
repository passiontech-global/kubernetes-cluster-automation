// kubelet_cert.go — #4 worker kubelet serving cert expiry & :10250 reload-drift guard:
// reads kubelet-client-current.pem and kubelet-server-current.pem from PKIDir,
// dials ServeAddr via TLSPeerCertFn, latches worker-kubelet-cert-expiring on
// expiry (< CertMinDays) without restarting k0sworker, and restarts k0sworker
// (180s settle + HoldEmergencyHeal + 1h last-kubelet-cert-reload budget) only
// when on-disk serving cert is newer and differs from :10250 for >= 2 cycles.
package kubelet

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/checkkit"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
)

const (
	kubeletCertReloadBudget   = "last-kubelet-cert-reload"
	kubeletCertReloadCooldown = time.Hour
	kubeletCertSuspectCadence = 30 * time.Minute
	kubeletClientCertName     = "kubelet-client-current.pem"
	kubeletServerCertName     = "kubelet-server-current.pem"
	kubeletCertDefaultMinDays = 14
)

var errNoPEMCert = errors.New("no PEM certificate in bundle")

type cachedCertBundle struct {
	statKey     string
	leaf        *x509.Certificate
	minNotAfter time.Time
	err         error
}

// CertCheck monitors kubelet client/server certs on disk and the live
// serving cert presented on :10250 for imminent expiry and reload drift.
type CertCheck struct {
	d          *wdeps.Deps
	DriftFails int
	certMu     sync.Mutex
	certCache  map[string]cachedCertBundle
}

// Name returns the check label / WD_SIG key.
func (c *CertCheck) Name() string { return wdeps.CheckKubeletCert }

// Run executes one kubelet-cert check round.
func (c *CertCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckKubeletCert) {
		return
	}
	if ctx.Err() != nil {
		c.d.CycleResult(wdeps.CheckKubeletCert, "abort")
		return
	}
	if c.d.Cfg.Kubelet.PKIDir == "" {
		c.DriftFails = 0
		c.d.State.ExitClearSuspect(latchdefs.LatchWorkerKubeletCertExpiring)
		c.d.CycleResult(wdeps.CheckKubeletCert, "ok")
		return
	}

	clientPath := filepath.Join(c.d.Cfg.Kubelet.PKIDir, kubeletClientCertName)
	serverPath := filepath.Join(c.d.Cfg.Kubelet.PKIDir, kubeletServerCertName)
	_, clientNotAfter, clientErr := c.readCertBundleCached(clientPath)
	serverLeaf, serverNotAfter, serverErr := c.readCertBundleCached(serverPath)

	clientAbsent := errors.Is(clientErr, os.ErrNotExist)
	serverAbsent := errors.Is(serverErr, os.ErrNotExist)
	if (clientErr != nil && !clientAbsent) || (serverErr != nil && !serverAbsent) {
		if clientErr != nil && !clientAbsent {
			c.d.State.SuspectLog(wdeps.CheckKubeletCert+"-read",
				fmt.Sprintf("suspect: kubelet-cert read %s failed: %v — aborting", clientPath, clientErr),
				kubeletCertSuspectCadence)
		}
		if serverErr != nil && !serverAbsent {
			c.d.State.SuspectLog(wdeps.CheckKubeletCert+"-read",
				fmt.Sprintf("suspect: kubelet-cert read %s failed: %v — aborting", serverPath, serverErr),
				kubeletCertSuspectCadence)
		}
		c.d.CycleResult(wdeps.CheckKubeletCert, "abort")
		return
	}
	if clientAbsent && serverAbsent {
		c.DriftFails = 0
		c.d.State.ExitClearSuspect(latchdefs.LatchWorkerKubeletCertExpiring)
		c.d.CycleResult(wdeps.CheckKubeletCert, "ok")
		return
	}

	now := c.d.Cfg.Seams.Host.Clock.Now()
	minDays := float64(c.d.Cfg.Kubelet.CertMinDays)
	if minDays <= 0 {
		minDays = kubeletCertDefaultMinDays
	}
	var (
		diskExpiring   bool
		liveExpiring   bool
		worstDays      float64
		expireEvidence string
	)
	recordExpiry := func(label string, notAfter time.Time, flag *bool) {
		days := notAfter.Sub(now).Hours() / 24
		if days < minDays {
			if expireEvidence == "" || days < worstDays {
				worstDays = days
				expireEvidence = fmt.Sprintf("%s expires in %.1fd (<%.0fd, notAfter=%s)",
					label, days, minDays, notAfter.UTC().Format(time.RFC3339))
			}
			*flag = true
		}
	}
	if clientErr == nil {
		recordExpiry(kubeletClientCertName, clientNotAfter, &diskExpiring)
	}
	if serverErr == nil {
		recordExpiry(kubeletServerCertName, serverNotAfter, &diskExpiring)
	}

	var (
		liveCert *x509.Certificate
		liveErr  error
	)
	if c.d.Cfg.Seams.Probe.TLSPeerCertFn != nil {
		liveCert, liveErr = c.d.Cfg.Seams.Probe.TLSPeerCertFn(ctx, c.d.Cfg.Kubelet.ServeAddr)
	} else {
		liveErr = errors.New("no TLSPeerCertFn wired")
	}
	if ctx.Err() != nil {
		c.d.CycleResult(wdeps.CheckKubeletCert, "abort")
		return
	}

	driftNow := false
	driftEvidence := ""
	if liveErr == nil && liveCert != nil {
		recordExpiry("live "+c.d.Cfg.Kubelet.ServeAddr, liveCert.NotAfter, &liveExpiring)
		if serverLeaf != nil && serverCertDrift(serverLeaf, liveCert) {
			driftNow = true
			driftEvidence = fmt.Sprintf("disk notAfter=%s serial=%v != live %s notAfter=%s serial=%v",
				serverLeaf.NotAfter.UTC().Format(time.RFC3339), serverLeaf.SerialNumber,
				c.d.Cfg.Kubelet.ServeAddr, liveCert.NotAfter.UTC().Format(time.RFC3339), liveCert.SerialNumber)
		}
	} else {
		if liveErr == nil {
			liveErr = errors.New("empty tls peer cert")
		}
		c.DriftFails = 0
	}

	expiring := diskExpiring || liveExpiring
	if expiring {
		c.d.State.Enter(latchdefs.LatchWorkerKubeletCertExpiring, expireEvidence)
		c.d.State.SuspectLog(latchdefs.LatchWorkerKubeletCertExpiring,
			"suspect: kubelet-cert expiring - "+expireEvidence, kubeletCertSuspectCadence)
	}

	if driftNow {
		needed := max(c.d.Cfg.ConsecNeeded, 2)
		if checkkit.Pending(needed, &c.DriftFails,
			"suspect: kubelet-cert reload drift - "+driftEvidence, c.d.State.AppendLog) {
			c.d.CycleResult(wdeps.CheckKubeletCert, "ok")
			return
		}
		c.d.State.Enter(latchdefs.LatchWorkerKubeletCertExpiring, "reload-drift: "+driftEvidence)
		if restartK0sWorkerGated(c.d, ctx, k0sWorkerRestartGate{
			check:        wdeps.CheckKubeletCert,
			suspectTag:   "kubelet-cert reload drift",
			actionDetail: fmt.Sprintf("kubelet-cert-reload-drift (%s, persisted %dx)", driftEvidence, c.DriftFails),
			budget:       kubeletCertReloadBudget,
			cooldown:     kubeletCertReloadCooldown,
		}) {
			c.DriftFails = 0
		}
		c.d.CycleResult(wdeps.CheckKubeletCert, "ok")
		return
	}

	c.DriftFails = 0
	if expiring {
		c.d.CycleResult(wdeps.CheckKubeletCert, "ok")
		return
	}
	if liveErr != nil {
		c.d.State.SuspectLog(wdeps.CheckKubeletCert+"-dial",
			fmt.Sprintf("suspect: kubelet-cert TLS dial %s failed: %v — inconclusive, keeping state",
				c.d.Cfg.Kubelet.ServeAddr, liveErr),
			kubeletCertSuspectCadence)
		c.d.CycleResult(wdeps.CheckKubeletCert, "inconclusive")
		return
	}
	c.d.State.ExitClearSuspect(latchdefs.LatchWorkerKubeletCertExpiring)
	c.d.CycleResult(wdeps.CheckKubeletCert, "ok")
}

func (c *CertCheck) readCertBundleCached(path string) (*x509.Certificate, time.Time, error) {
	key, err := fsx.FileStatKey(path)
	if err != nil {
		c.certMu.Lock()
		delete(c.certCache, path)
		c.certMu.Unlock()
		return nil, time.Time{}, err
	}
	c.certMu.Lock()
	if ent, ok := c.certCache[path]; ok && ent.statKey == key {
		c.certMu.Unlock()
		return ent.leaf, ent.minNotAfter, ent.err
	}
	c.certMu.Unlock()

	leaf, minNotAfter, err := readCertBundle(path)
	if err == nil || errors.Is(err, errNoPEMCert) {
		c.certMu.Lock()
		if c.certCache == nil {
			c.certCache = make(map[string]cachedCertBundle)
		}
		c.certCache[path] = cachedCertBundle{
			statKey:     key,
			leaf:        leaf,
			minNotAfter: minNotAfter,
			err:         err,
		}
		c.certMu.Unlock()
	}
	return leaf, minNotAfter, err
}

// readCertBundle parses a PEM certificate bundle, returning the first
// non-CA leaf cert (falling back to the first cert if only CAs exist)
// and the earliest NotAfter across all certificates in the bundle.
func readCertBundle(path string) (leaf *x509.Certificate, minNotAfter time.Time, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	var first *x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		crt, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			continue
		}
		if first == nil {
			first = crt
			minNotAfter = crt.NotAfter
		} else if crt.NotAfter.Before(minNotAfter) {
			minNotAfter = crt.NotAfter
		}
		if leaf == nil && !crt.IsCA {
			leaf = crt
		}
	}
	if first == nil {
		return nil, time.Time{}, errNoPEMCert
	}
	if leaf == nil {
		leaf = first
	}
	return leaf, minNotAfter, nil
}

// serverCertDrift reports whether the on-disk serving leaf cert is
// newer than the live :10250 leaf cert and differs by serial or SHA-256.
func serverCertDrift(disk, live *x509.Certificate) bool {
	if disk == nil || live == nil || !disk.NotAfter.After(live.NotAfter) {
		return false
	}
	var serialDiffers bool
	if disk.SerialNumber != nil && live.SerialNumber != nil {
		serialDiffers = disk.SerialNumber.Cmp(live.SerialNumber) != 0
	} else {
		serialDiffers = (disk.SerialNumber == nil) != (live.SerialNumber == nil)
	}
	sha256Differs := sha256.Sum256(disk.Raw) != sha256.Sum256(live.Raw)
	return serialDiffers || sha256Differs
}
