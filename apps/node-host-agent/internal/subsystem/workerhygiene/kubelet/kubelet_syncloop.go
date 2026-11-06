// kubelet_syncloop.go — the A4 PLEG probes the :10250 healthz check
// cannot see: /healthz/syncloop (kubelet sync-loop freeze) and the
// containerd unix socket hang check, plus the SA bearer reader the
// authenticated kubelet probes share.
package kubelet

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// A4 (PLEG/containerd probes) wiring defaults — same /host mount
// convention as the other seams.
const (
	unixSockProbeTimeout = 5 * time.Second
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

// SyncloopCheck is the A4 PLEG probe as a Check; it owns the
// consecutive-fail streak and the unauth-logged flag (ex-Hygiene
// .syncloopFails/.syncloopUnauth).
type SyncloopCheck struct {
	d      *wdeps.Deps
	fails  int
	unauth bool // last probe was 401/403 — log the streak once
}

// Name returns the check label / WD_SIG key.
func (c *SyncloopCheck) Name() string { return wdeps.CheckSyncloop }

// Run executes one kubelet-syncloop round.
func (c *SyncloopCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if !e.WorkerActive {
		c.d.Cycles.WithLabelValues(wdeps.CheckSyncloop, "gated").Inc()
		return
	}
	var lastErr error
	alive := false
	unauth := false
	// The bearer token is re-read every cycle — the file is small
	// and bound SA tokens rotate.
	bearer := kubeletBearer(c.d)
	for i := 0; i < wdeps.ProbeAttempts; i++ {
		code, err := c.d.Cfg.Seams.ProbeHTTPStatus(ctx,
			c.d.Cfg.Kubelet.SyncloopURL, bearer, wdeps.ProbeTimeout)
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
		if i+1 < wdeps.ProbeAttempts {
			select {
			case <-ctx.Done():
				c.d.Cycles.WithLabelValues(wdeps.CheckSyncloop, "abort").Inc()
				return
			case <-time.After(c.d.Cfg.ProbeGap):
			}
		}
	}
	if unauth {
		// The verdict is unknowable without working credentials —
		// inconclusive like the other keep-state paths, NOT a down
		// signal. Logged once per unauth streak so a permanently
		// unauthenticated deployment doesn't spam every cycle.
		if !c.unauth {
			c.d.State.AppendLog("suspect: kubelet-syncloop-down probe unauthorized " +
				"(401/403 — token missing or RBAC nonResourceURL /healthz/* not " +
				"granted) — inconclusive, keeping state")
			c.unauth = true
		}
		c.d.Cycles.WithLabelValues(wdeps.CheckSyncloop, "inconclusive").Inc()
		return
	}
	c.unauth = false
	if alive {
		c.fails = 0
		c.d.State.Exit(hoststate.LatchKubeletSyncloopDown, nil)
		c.d.Cycles.WithLabelValues(wdeps.CheckSyncloop, "ok").Inc()
		return
	}
	c.fails++
	if c.fails < c.d.Cfg.ConsecNeeded {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: kubelet-syncloop-down /healthz/syncloop fail (PLEG?) err=%v (check %d/%d)",
			lastErr, c.fails, c.d.Cfg.ConsecNeeded))
		c.d.Cycles.WithLabelValues(wdeps.CheckSyncloop, "ok").Inc()
		return
	}
	// BUG-H4: a frozen PLEG is a kubelet stall the 05 probe can't
	// see — confirmed consecutive fails now self-heal through the
	// shared k0sworker restart gates (overload / settle /
	// last-restart budget), checkKubeletStall parity.
	overloaded := c.d.State.Exists(hoststate.LatchNodeOverloaded)
	if !overloaded {
		c.d.State.Enter(hoststate.LatchKubeletSyncloopDown,
			fmt.Sprintf("pleg-frozen last_err=%v", lastErr))
	} else if !c.d.State.Exists(hoststate.LatchKubeletSyncloopDown) {
		// A stall under CPU starvation is a symptom — latching
		// would escalate to NHC→SNR and dump 100% of the load
		// onto the survivors (amplifier). Log-only.
		c.d.State.AppendLog(fmt.Sprintf(
			"kubelet-syncloop-down suppressed-overloaded - pleg-frozen last_err=%v", lastErr))
	}
	switch {
	case overloaded:
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: kubelet-syncloop-down - node overloaded, skip restart k0sworker (err=%v)", lastErr))
	case !k0sWorkerSettled(c.d, ctx):
		c.d.State.AppendLog("suspect: kubelet-syncloop-down - k0sworker not settled (<180s), skip restart")
	case !c.d.State.RateTrySpend("last-restart", c.d.Cfg.MinRestartInterval):
		c.d.State.AppendLog("suspect: kubelet-syncloop-down - in restart cooldown (<30m), skip")
	default:
		// Budget already spent atomically by the rateTrySpend
		// case — the feeder goroutine competes for the same file.
		c.d.State.AppendLog(fmt.Sprintf(
			"ACTION: restarting k0sworker - kubelet-syncloop-down pleg-frozen (persisted %dx)",
			c.fails))
		c.fails = 0
		if err := restartK0sWorker(c.d, ctx); err != nil {
			c.d.State.AppendLog(fmt.Sprintf("k0sworker restart failed: %v", err))
		} else {
			c.d.Actions.WithLabelValues(wdeps.CheckSyncloop, "restart").Inc()
		}
	}
	c.d.Cycles.WithLabelValues(wdeps.CheckSyncloop, "ok").Inc()
}

// kubeletBearer reads the service-account token kubelet's :10250
// webhook auth accepts — re-read every call so bound-token rotation
// needs no caching logic. Missing/unreadable file → "" (the probe
// runs unauthenticated and 401/403 marks the check inconclusive).
func kubeletBearer(d *wdeps.Deps) string {
	b, err := os.ReadFile(d.Cfg.Kubelet.TokenPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// CtrsockCheck is the A4 containerd-socket hang probe as a Check;
// it owns the consecutive-fail streak (ex-Hygiene.ctrsockFails).
type CtrsockCheck struct {
	d     *wdeps.Deps
	fails int
}

// Name returns the check label / WD_SIG key.
func (c *CtrsockCheck) Name() string { return wdeps.CheckCtrSock }

// Run executes one containerd-sock round.
func (c *CtrsockCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if !e.WorkerActive {
		c.d.Cycles.WithLabelValues(wdeps.CheckCtrSock, "gated").Inc()
		return
	}
	err := c.d.Cfg.Seams.ProbeUnixSock(ctx, c.d.Cfg.Ctr.Socket, unixSockProbeTimeout)
	if err == nil {
		c.fails = 0
		c.d.State.Exit(hoststate.LatchContainerdSockDown, nil)
		c.d.Cycles.WithLabelValues(wdeps.CheckCtrSock, "ok").Inc()
		return
	}
	c.fails++
	if c.fails < c.d.Cfg.ConsecNeeded {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: containerd-sock-down %s probe fail: %v (check %d/%d)",
			c.d.Cfg.Ctr.Socket, err, c.fails, c.d.Cfg.ConsecNeeded))
		c.d.Cycles.WithLabelValues(wdeps.CheckCtrSock, "ok").Inc()
		return
	}
	// BUG-H4: a hung containerd socket wedges PLEG and every pod
	// lifecycle op — confirmed consecutive fails self-heal through
	// the shared k0sworker restart gates, checkKubeletSyncloop
	// parity.
	overloaded := c.d.State.Exists(hoststate.LatchNodeOverloaded)
	if !overloaded {
		c.d.State.Enter(hoststate.LatchContainerdSockDown,
			fmt.Sprintf("probe_err=%v", err))
	} else if !c.d.State.Exists(hoststate.LatchContainerdSockDown) {
		c.d.State.AppendLog(fmt.Sprintf(
			"containerd-sock-down suppressed-overloaded - probe_err=%v", err))
	}
	switch {
	case overloaded:
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: containerd-sock-down - node overloaded, skip restart k0sworker (err=%v)", err))
	case !k0sWorkerSettled(c.d, ctx):
		c.d.State.AppendLog("suspect: containerd-sock-down - k0sworker not settled (<180s), skip restart")
	case !c.d.State.RateTrySpend("last-restart", c.d.Cfg.MinRestartInterval):
		c.d.State.AppendLog("suspect: containerd-sock-down - in restart cooldown (<30m), skip")
	default:
		// Budget already spent atomically by the rateTrySpend
		// case — the feeder goroutine competes for the same file.
		c.d.State.AppendLog(fmt.Sprintf(
			"ACTION: restarting k0sworker - containerd-sock-down %s (persisted %dx)",
			c.d.Cfg.Ctr.Socket, c.fails))
		c.fails = 0
		if err := restartK0sWorker(c.d, ctx); err != nil {
			c.d.State.AppendLog(fmt.Sprintf("k0sworker restart failed: %v", err))
		} else {
			c.d.Actions.WithLabelValues(wdeps.CheckCtrSock, "restart").Inc()
		}
	}
	c.d.Cycles.WithLabelValues(wdeps.CheckCtrSock, "ok").Inc()
}

// --- Check: containerd stale ingest GC (A3 — 39-ctr-ingest-gc) ---
// A hard-reboot or OOM mid-pull leaves ingest dirs containerd never
// reaps; kubelet's ImageGC can't see them because the lease is
// orphaned. Runs when /var/lib/k0s is >75% full OR every 6h; ingest
// dirs with mtime >3h (no legitimate pull survives that) are removed
// via `ctr content ingest rm`, with a direct dir rm as fallback.
