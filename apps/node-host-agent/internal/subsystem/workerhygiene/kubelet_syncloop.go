// kubelet_syncloop.go — the A4 PLEG probes the :10250 healthz check
// cannot see: /healthz/syncloop (kubelet sync-loop freeze) and the
// containerd unix socket hang check, plus the SA bearer reader the
// authenticated kubelet probes share.
package workerhygiene

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
)

// --- Check: kubelet syncloop / containerd socket (A4) ---
// 05's :10250 /healthz probe can stay green through a PLEG freeze —
// kubelet exposes /healthz/syncloop specifically for the sync loop
// (returns 500 the moment PLEG dies). The containerd unix socket is
// the other half: a hung containerd wedges PLEG while every HTTP
// endpoint still answers. Both latches now self-heal (BUG-H4): at
// ConsecNeeded fails they run the shared k0sworker restart gates
// (overload / settle / last-restart budget) instead of waiting for
// 05/T15 to notice.

// syncloopCheck is the A4 PLEG probe as a Check; it owns the
// consecutive-fail streak and the unauth-logged flag (ex-Hygiene
// .syncloopFails/.syncloopUnauth).
type syncloopCheck struct {
	h      *Hygiene
	fails  int
	unauth bool // last probe was 401/403 — log the streak once
}

// Name returns the check label / WD_SIG key.
func (c *syncloopCheck) Name() string { return checkSyncloop }

// Run executes one kubelet-syncloop round.
func (c *syncloopCheck) Run(ctx context.Context, e *cycleEnv) {
	if !e.workerActive {
		c.h.cycles.WithLabelValues(checkSyncloop, "gated").Inc()
		return
	}
	var lastErr error
	alive := false
	unauth := false
	// The bearer token is re-read every cycle — the file is small
	// and bound SA tokens rotate.
	bearer := c.h.kubeletBearer()
	for i := 0; i < probeAttempts; i++ {
		code, err := c.h.cfg.Seams.probeHTTPStatus(ctx,
			c.h.cfg.Kubelet.SyncloopURL, bearer, probeTimeout)
		if err == nil {
			switch {
			case code == http.StatusOK:
				alive = true
			case code == http.StatusUnauthorized || code == http.StatusForbidden:
				// Kubelet answered but won't divulge the verdict —
				// retrying the same credentials won't help.
				unauth = true
			default:
				lastErr = fmt.Errorf("syncloop status %d", code)
			}
		} else {
			lastErr = err
		}
		if alive || unauth {
			break
		}
		if i+1 < probeAttempts {
			select {
			case <-ctx.Done():
				c.h.cycles.WithLabelValues(checkSyncloop, "abort").Inc()
				return
			case <-time.After(c.h.cfg.ProbeGap):
			}
		}
	}
	if unauth {
		// The verdict is unknowable without working credentials —
		// inconclusive like the other keep-state paths, NOT a down
		// signal. Logged once per unauth streak so a permanently
		// unauthenticated deployment doesn't spam every cycle.
		if !c.unauth {
			c.h.state.AppendLog("suspect: kubelet-syncloop-down probe unauthorized " +
				"(401/403 — token missing or RBAC nonResourceURL /healthz/* not " +
				"granted) — inconclusive, keeping state")
			c.unauth = true
		}
		c.h.cycles.WithLabelValues(checkSyncloop, "inconclusive").Inc()
		return
	}
	c.unauth = false
	if alive {
		c.fails = 0
		c.h.state.Exit(hoststate.LatchKubeletSyncloopDown, nil)
		c.h.cycles.WithLabelValues(checkSyncloop, "ok").Inc()
		return
	}
	c.fails++
	if c.fails < c.h.cfg.ConsecNeeded {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: kubelet-syncloop-down /healthz/syncloop fail (PLEG?) err=%v (check %d/%d)",
			lastErr, c.fails, c.h.cfg.ConsecNeeded))
		c.h.cycles.WithLabelValues(checkSyncloop, "ok").Inc()
		return
	}
	// BUG-H4: a frozen PLEG is a kubelet stall the 05 probe can't
	// see — confirmed consecutive fails now self-heal through the
	// shared k0sworker restart gates (overload / settle /
	// last-restart budget), checkKubeletStall parity.
	overloaded := c.h.state.Exists(hoststate.LatchNodeOverloaded)
	if !overloaded {
		c.h.state.Enter(hoststate.LatchKubeletSyncloopDown,
			fmt.Sprintf("pleg-frozen last_err=%v", lastErr))
	} else if !c.h.state.Exists(hoststate.LatchKubeletSyncloopDown) {
		// A stall under CPU starvation is a symptom — latching
		// would escalate to NHC→SNR and dump 100% of the load
		// onto the survivors (amplifier). Log-only.
		c.h.state.AppendLog(fmt.Sprintf(
			"kubelet-syncloop-down suppressed-overloaded - pleg-frozen last_err=%v", lastErr))
	}
	switch {
	case overloaded:
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: kubelet-syncloop-down - node overloaded, skip restart k0sworker (err=%v)", lastErr))
	case !c.h.k0sWorkerSettled(ctx):
		c.h.state.AppendLog("suspect: kubelet-syncloop-down - k0sworker not settled (<180s), skip restart")
	case !c.h.state.RateTrySpend("last-restart", c.h.cfg.MinRestartInterval):
		c.h.state.AppendLog("suspect: kubelet-syncloop-down - in restart cooldown (<30m), skip")
	default:
		// Budget already spent atomically by the rateTrySpend
		// case — the feeder goroutine competes for the same file.
		c.h.state.AppendLog(fmt.Sprintf(
			"ACTION: restarting k0sworker - kubelet-syncloop-down pleg-frozen (persisted %dx)",
			c.fails))
		c.fails = 0
		if err := c.h.restartK0sWorker(ctx); err != nil {
			c.h.state.AppendLog(fmt.Sprintf("k0sworker restart failed: %v", err))
		} else {
			c.h.actions.WithLabelValues(checkSyncloop, "restart").Inc()
		}
	}
	c.h.cycles.WithLabelValues(checkSyncloop, "ok").Inc()
}

// kubeletBearer reads the service-account token kubelet's :10250
// webhook auth accepts — re-read every call so bound-token rotation
// needs no caching logic. Missing/unreadable file → "" (the probe
// runs unauthenticated and 401/403 marks the check inconclusive).
func (h *Hygiene) kubeletBearer() string {
	b, err := os.ReadFile(h.cfg.Kubelet.TokenPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// ctrsockCheck is the A4 containerd-socket hang probe as a Check;
// it owns the consecutive-fail streak (ex-Hygiene.ctrsockFails).
type ctrsockCheck struct {
	h     *Hygiene
	fails int
}

// Name returns the check label / WD_SIG key.
func (c *ctrsockCheck) Name() string { return checkCtrSock }

// Run executes one containerd-sock round.
func (c *ctrsockCheck) Run(ctx context.Context, e *cycleEnv) {
	if !e.workerActive {
		c.h.cycles.WithLabelValues(checkCtrSock, "gated").Inc()
		return
	}
	err := c.h.cfg.Seams.probeUnixSock(ctx, c.h.cfg.Ctr.Socket, unixSockProbeTimeout)
	if err == nil {
		c.fails = 0
		c.h.state.Exit(hoststate.LatchContainerdSockDown, nil)
		c.h.cycles.WithLabelValues(checkCtrSock, "ok").Inc()
		return
	}
	c.fails++
	if c.fails < c.h.cfg.ConsecNeeded {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: containerd-sock-down %s probe fail: %v (check %d/%d)",
			c.h.cfg.Ctr.Socket, err, c.fails, c.h.cfg.ConsecNeeded))
		c.h.cycles.WithLabelValues(checkCtrSock, "ok").Inc()
		return
	}
	// BUG-H4: a hung containerd socket wedges PLEG and every pod
	// lifecycle op — confirmed consecutive fails self-heal through
	// the shared k0sworker restart gates, checkKubeletSyncloop
	// parity.
	overloaded := c.h.state.Exists(hoststate.LatchNodeOverloaded)
	if !overloaded {
		c.h.state.Enter(hoststate.LatchContainerdSockDown,
			fmt.Sprintf("probe_err=%v", err))
	} else if !c.h.state.Exists(hoststate.LatchContainerdSockDown) {
		c.h.state.AppendLog(fmt.Sprintf(
			"containerd-sock-down suppressed-overloaded - probe_err=%v", err))
	}
	switch {
	case overloaded:
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: containerd-sock-down - node overloaded, skip restart k0sworker (err=%v)", err))
	case !c.h.k0sWorkerSettled(ctx):
		c.h.state.AppendLog("suspect: containerd-sock-down - k0sworker not settled (<180s), skip restart")
	case !c.h.state.RateTrySpend("last-restart", c.h.cfg.MinRestartInterval):
		c.h.state.AppendLog("suspect: containerd-sock-down - in restart cooldown (<30m), skip")
	default:
		// Budget already spent atomically by the rateTrySpend
		// case — the feeder goroutine competes for the same file.
		c.h.state.AppendLog(fmt.Sprintf(
			"ACTION: restarting k0sworker - containerd-sock-down %s (persisted %dx)",
			c.h.cfg.Ctr.Socket, c.fails))
		c.fails = 0
		if err := c.h.restartK0sWorker(ctx); err != nil {
			c.h.state.AppendLog(fmt.Sprintf("k0sworker restart failed: %v", err))
		} else {
			c.h.actions.WithLabelValues(checkCtrSock, "restart").Inc()
		}
	}
	c.h.cycles.WithLabelValues(checkCtrSock, "ok").Inc()
}

// --- Check: containerd stale ingest GC (A3 — 39-ctr-ingest-gc) ---
// A hard-reboot or OOM mid-pull leaves ingest dirs containerd never
// reaps; kubelet's ImageGC can't see them because the lease is
// orphaned. Runs when /var/lib/k0s is >75% full OR every 6h; ingest
// dirs with mtime >3h (no legitimate pull survives that) are removed
// via `ctr content ingest rm`, with a direct dir rm as fallback.
