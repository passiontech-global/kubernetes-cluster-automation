// cpwave.go — Wave 8 control-plane additions:
//
//	W8-CP3  KCM/scheduler freeze auto-heal. k0s hosts
//	        kube-controller-manager (:10257) and kube-scheduler
//	        (:10259) inside k0scontroller — when either /healthz
//	        stays dead for CPFreezeCycles consecutive cycles, or the
//	        KCM reports leader + zero queued work for longer than
//	        CPFreezeQuietFor, while the peer apiserver still answers,
//	        the component (not the apiserver) is frozen → restart
//	        k0scontroller.service under the last-cp-restart budget.
//	W8-CP4  PKI reload drift. After cert rotation the on-disk cert
//	        can be newer than the one a live socket still presents
//	        (the daemon never reloaded). Compare SerialNumber +
//	        NotAfter of the on-disk file vs the socket-presented
//	        leaf for each PKIDriftPair; drift for PKIDriftCycles
//	        consecutive cycles latches state-cp-cert-reload-stale
//	        and restarts the owning unit under the
//	        last-cp-cert-restart budget.
package controllerhygiene

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"
)

const checkCPFreeze = "cp-freeze"
const checkPKIDrift = "cp-cert-drift"

// probeHTTP2xx is cpHealthFn's default: GET url, true on a 2xx — the
// KCM/scheduler healthz contract (500 = component wedged, any other
// failure = unreachable). KCM/scheduler serve self-signed certs, so
// the shared insecure transport is used.
func probeHTTP2xx(ctx context.Context, url string, timeout time.Duration) bool {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := probeClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// httpGetInsecure is kcmMetricsFn's default — body or error.
func httpGetInsecure(ctx context.Context, url string, timeout time.Duration) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := probeClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// tlsDialCert returns the leaf certificate addr presents — drift is
// judged on the presented cert, not on chain trust, so the dial is
// insecure by design.
func tlsDialCert(ctx context.Context, addr string) (*x509.Certificate, error) {
	d := &net.Dialer{Timeout: 8 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", addr,
		&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // drift check wants the presented cert
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificate")
	}
	return state.PeerCertificates[0], nil
}

// kcmLeaderIdle parses the KCM /metrics body: leader_election_master
// ==1 while every workqueue_depth sample reads 0 — the leader holds
// the lease yet no controller workers are scheduling, the classic
// KCM-freeze signature.
func kcmLeaderIdle(body string) (leader, idle, parsed bool) {
	leaderRe := regexp.MustCompile(`(?m)^leader_election_master_status(?:\{[^}]*\})?\s+([0-9.]+)`)
	depthRe := regexp.MustCompile(`(?m)^workqueue_depth(?:\{[^}]*\})?\s+([0-9.]+)`)
	lm := leaderRe.FindStringSubmatch(body)
	if lm == nil {
		return false, false, false
	}
	lv, _ := strconv.ParseFloat(lm[1], 64)
	leader = lv >= 1
	var depthSum float64
	seen := 0
	for _, m := range depthRe.FindAllStringSubmatch(body, -1) {
		if v, err := strconv.ParseFloat(m[1], 64); err == nil {
			depthSum += v
			seen++
		}
	}
	// No depth samples at all is inconclusive, not idle.
	idle = seen > 0 && depthSum == 0
	return leader, idle, true
}

// peerHealthy reports whether the OTHER apiserver answers — the W8-CP3
// gate that proves only the controller components froze, not the whole
// control plane. Falls back to the local apiserver when no peer is
// configured (single-hub).
func (h *Hygiene) peerHealthy(ctx context.Context) bool {
	ep := h.cfg.PeerAPI
	if ep == "" {
		ep = h.cfg.SelfEndpoint
	}
	// ANY HTTP code = the apiserver event loop is alive (probeAnyCode
	// parity — a wedged apiserver is the wedge guard's problem, not
	// this check's).
	return h.cfg.probeFn(ctx, "https://"+ep+"/readyz")
}

// checkCPFreeze — W8-CP3. Restart evidence is (a) KCM or scheduler
// healthz dead for CPFreezeCycles consecutive cycles, or (b) KCM
// leader+idle persisting past CPFreezeQuietFor. The restart only
// fires while the peer apiserver stays healthy and honors Sig13Mode.
func (h *Hygiene) checkCPFreeze(ctx context.Context) {
	kcmOK := h.cfg.cpHealthFn(ctx, h.cfg.KCMHealthURL)
	schedOK := h.cfg.cpHealthFn(ctx, h.cfg.SchedHealthURL)

	frozen := false
	reason := ""
	switch {
	case !kcmOK || !schedOK:
		n := h.ctrInc(fileCtrCPFreeze)
		if n >= h.cfg.CPFreezeCycles {
			frozen = true
			reason = fmt.Sprintf("healthz dead %dx (kcm=%v sched=%v)",
				n, kcmOK, schedOK)
		} else {
			h.cycles.WithLabelValues(checkCPFreeze, "suspect").Inc()
			return
		}
	default:
		h.ctrReset(fileCtrCPFreeze)
	}

	// Leader-without-workers is an OR-condition: even with a healthy
	// healthz a frozen KCM scheduler loop shows up as leader + zero
	// depth. Only evaluated when the fast path didn't already fire.
	if !frozen {
		body, err := h.cfg.kcmMetricsFn(ctx, h.cfg.KCMMetricsURL)
		quiet := false
		if err == nil {
			leader, idle, parsed := kcmLeaderIdle(body)
			quiet = parsed && leader && idle
		}
		if quiet {
			if h.kcmQuietSince.IsZero() {
				h.kcmQuietSince = h.cfg.nowFn()
				h.ctrInc(fileCtrKCMQuiet)
			}
			if h.cfg.nowFn().Sub(h.kcmQuietSince) >= h.cfg.CPFreezeQuietFor {
				frozen = true
				reason = fmt.Sprintf("kcm leader+idle >%s",
					h.cfg.CPFreezeQuietFor)
			}
		} else {
			h.kcmQuietSince = time.Time{}
			h.ctrReset(fileCtrKCMQuiet)
		}
	}

	if !frozen {
		h.stateExit(stateCPComponentFrozen)
		h.cycles.WithLabelValues(checkCPFreeze, "ok").Inc()
		return
	}
	h.stateEnter(stateCPComponentFrozen, reason)
	// Gate: the peer apiserver must still answer — otherwise the
	// outage is bigger than a frozen component and the wedge guard
	// owns the restart story.
	if !h.peerHealthy(ctx) {
		h.suspectLog(stateCPComponentFrozen, fmt.Sprintf(
			"suspect: cp-component-frozen %s but peer apiserver unhealthy — wedge guard owns this, skip",
			reason))
		h.cycles.WithLabelValues(checkCPFreeze, "gated").Inc()
		return
	}
	if !h.rateOK(h.cfg.WatchdogStateDir, fileRateCPRestart,
		h.cfg.CPFreezeMinRestart) {
		h.suspectLog(stateCPComponentFrozen, fmt.Sprintf(
			"suspect: cp-component-frozen %s but in restart cooldown (<%dm), skip",
			reason, int(h.cfg.CPFreezeMinRestart.Minutes())))
		h.cycles.WithLabelValues(checkCPFreeze, "cooldown").Inc()
		return
	}
	switch h.cfg.Sig13Mode {
	case ModeEnforce:
		h.appendLog(fmt.Sprintf(
			"ACTION: restarting k0scontroller - cp-component-frozen %s",
			reason))
		h.rateSpend(h.cfg.WatchdogStateDir, fileRateCPRestart)
		h.ctrReset(fileCtrCPFreeze)
		h.ctrReset(fileCtrKCMQuiet)
		h.kcmQuietSince = time.Time{}
		if err := h.cfg.restartFn(ctx, h.cfg.RestartUnit); err != nil {
			h.appendLogWarn(fmt.Sprintf(
				"suspect: restart %s failed: %v", h.cfg.RestartUnit, err))
		}
		h.actions.WithLabelValues(checkCPFreeze, "restart_controller").Inc()
	case ModeDryRun:
		h.appendLog(fmt.Sprintf(
			"DRY-RUN: would restart k0scontroller - cp-component-frozen %s",
			reason))
		h.actions.WithLabelValues(checkCPFreeze, "dryrun_restart").Inc()
	}
	h.cycles.WithLabelValues(checkCPFreeze, "ok").Inc()
}

// checkPKIReloadDrift — W8-CP4. For each pair: read the on-disk leaf
// and the socket-presented leaf; drift means the file describes a
// NEWER cert (later NotAfter, or different serial with a not-older
// NotAfter) than the socket serves. Drift held for PKIDriftCycles
// consecutive cycles latches the state and restarts the owning unit
// under the last-cp-cert-restart budget.
func (h *Hygiene) checkPKIReloadDrift(ctx context.Context) {
	anyDrift := false
	for i, pair := range h.cfg.PKIDriftPairs {
		ctr := fileCtrPKIDriftPre + strconv.Itoa(i)
		disk, err := readLeafCert(pair.CertFile)
		if err != nil {
			// Cert absent — not a controller / pair not deployed on
			// this host. Reset rather than carry a stale count.
			h.ctrReset(ctr)
			continue
		}
		sock, err := h.cfg.tlsCertFn(ctx, pair.Addr)
		if err != nil {
			// Socket down is someone else's check — the drift
			// comparison is inconclusive, not evidence.
			h.ctrReset(ctr)
			continue
		}
		if !certNewerThan(disk, sock) {
			h.ctrReset(ctr)
			continue
		}
		anyDrift = true
		n := h.ctrInc(ctr)
		if n < h.cfg.PKIDriftCycles {
			continue
		}
		h.stateEnter(statePKIReloadStale, fmt.Sprintf(
			"%s newer than %s (disk notAfter=%s socket=%s)",
			pair.CertFile, pair.Addr,
			disk.NotAfter.UTC().Format(time.RFC3339),
			sock.NotAfter.UTC().Format(time.RFC3339)))
		if !h.rateOK(h.cfg.WatchdogStateDir, fileRatePKIRestart,
			h.cfg.PKIRestartInterval) {
			h.suspectLog(statePKIReloadStale, fmt.Sprintf(
				"suspect: cp-cert-reload-stale %s but in restart cooldown (<%dm), skip",
				pair.CertFile, int(h.cfg.PKIRestartInterval.Minutes())))
			continue
		}
		switch h.cfg.Sig13Mode {
		case ModeEnforce:
			h.appendLog(fmt.Sprintf(
				"ACTION: restarting %s - cp-cert-reload-stale %s newer than %s",
				pair.Unit, pair.CertFile, pair.Addr))
			h.rateSpend(h.cfg.WatchdogStateDir, fileRatePKIRestart)
			h.ctrReset(ctr)
			if err := h.cfg.restartFn(ctx, pair.Unit); err != nil {
				h.appendLogWarn(fmt.Sprintf(
					"suspect: restart %s failed: %v", pair.Unit, err))
			}
			h.actions.WithLabelValues(checkPKIDrift, "restart_unit").Inc()
		case ModeDryRun:
			h.appendLog(fmt.Sprintf(
				"DRY-RUN: would restart %s - cp-cert-reload-stale %s",
				pair.Unit, pair.CertFile))
			h.actions.WithLabelValues(checkPKIDrift, "dryrun_restart").Inc()
		}
	}
	if !anyDrift {
		h.stateExit(statePKIReloadStale)
	}
	h.cycles.WithLabelValues(checkPKIDrift, "ok").Inc()
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
