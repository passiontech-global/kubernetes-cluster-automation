// cycle.go — the prober cycle driver (Cycle). The phases live in same-package
// files: cycle_probe.go (probeBackends/probeOne), cycle_drain.go
// (reapplyDrains/drainStale), cycle_vip.go (syncVIP/exportEnabled).

package apiprober

import (
	"context"
	"os"
	"time"
)

// Cycle runs one detection+guard round — the shell script body.
func (p *Prober) Cycle(ctx context.Context) {
	start := time.Now()
	defer func() { p.duration.Set(time.Since(start).Seconds()) }()

	// Re-read the guard conf every cycle — a conf written or edited
	// by hostconfig mid-run applies NOW, not after a restart.
	p.refreshGuard()
	// Read the SA bearer token ONCE per cycle — the projected token
	// only rotates on pod restart, and listRV used to os.ReadFile it
	// per query (2 reads × every backend × every cycle).
	p.cycleToken, p.cycleTokenErr = p.readTokenFile()
	p.cycleTokenLoaded = true
	defer func() {
		p.cycleToken, p.cycleTokenErr, p.cycleTokenLoaded = "", nil, false
	}()
	// Resolve the merged static set once for the whole cycle:
	// statics() re-reads node-watchdog.conf on every call and
	// discover needs it once per empty-addr `show stat` row — an
	// N-row table would otherwise cost N conf re-parses per cycle.
	p.cycleStatics = p.statics()
	// The snapshot is Cycle-scoped by contract: out-of-Cycle
	// staticAddr callers must resolve fresh via statics(), never
	// read the last cycle's (possibly conf-edited-away) snapshot.
	// Clear on EVERY return path — Cycle exits early at the socket
	// gate, on discover failure, and on ctx cancel.
	defer func() { p.cycleStatics = nil }()

	// Missing-socket gate: api-local-lb is worker-only (hostconfig
	// groupAPILB returns early on non-k0sworker hosts), so the
	// admin socket legitimately NEVER exists on controllers — a
	// missing socket is a quiet gated cycle, not a discovery
	// error. Stat-then-skip keeps the real failures loud: a socket
	// that exists but is unreadable/refused still reaches the dial
	// below and counts discover_fail. Other stat errors fall
	// through to the dial for the same reason. The DialSocket
	// seam bypasses the stat — the injected dialer IS the socket
	// contract in tests.
	if p.cfg.DialSocket == nil {
		if _, err := os.Stat(p.eff.socket); os.IsNotExist(err) {
			if !p.socketAbsent {
				logger().Info("HAProxy admin socket absent — backend discovery gated (api-local-lb is worker-only)",
					"socket", p.eff.socket)
				p.socketAbsent = true
			}
			p.cycles.WithLabelValues("no_socket").Inc()
			return
		}
		if p.socketAbsent {
			logger().Info("HAProxy admin socket present — resuming backend discovery",
				"socket", p.eff.socket)
			p.socketAbsent = false
		}
	}

	discovered, err := p.discover(ctx)
	if err != nil {
		logger().Error("cannot discover backends from HAProxy socket",
			"socket", p.eff.socket, "error", err)
		p.cycles.WithLabelValues("discover_fail").Inc()
		return
	}
	// Merge API_BACKENDS-style static entries — covers backends whose
	// `show stat` addr column is empty (external API LB VMs) and
	// apiservers the local HAProxy does not list.
	backends := mergeStatic(discovered, p.cycleStatics)
	// svnameByAddr maps a discovered addr to its HAProxy svname —
	// the socket action target must be the svname, never an addr key
	// (incident: `disable server api_local_back/147.93.159.255:6443`
	// → "No such server" retried every cycle).
	svnameByAddr := make(map[string]string, len(discovered))
	for _, d := range discovered {
		addr := withDefaultPort(d.Addr)
		if _, ok := svnameByAddr[addr]; !ok {
			svnameByAddr[addr] = d.Name
		}
	}
	p.backendCount.Set(float64(len(backends)))
	p.cycles.WithLabelValues("ok").Inc()

	// Resolved once per cycle: "" disables every watchdog file op.
	wdir := p.watchdogDir()
	// Persist every backend state at cycle end — deferred so the
	// mid-loop ctx.Err() return and every other early path still
	// flush the partial round's counters: a shutdown must not drop
	// a wedge streak that was one cycle from firing (the files are
	// the restart witness, see loadState).
	defer func() {
		if wdir != "" {
			p.flushStates(wdir)
		}
	}()

	fresh, stale, statusByName, vips, aborted := p.probeBackends(ctx,
		backends, wdir, svnameByAddr)
	if aborted {
		return
	}

	// Re-apply drains HAProxy forgot — runtime disables are not
	// persistent, so after a HAProxy restart a previously-drained
	// wedged backend shows UP again. Runs before the drain phase:
	// the stale loop below owns re-apply for its own entries (skip
	// duplicates). Only discovered rows can show UP again — statics
	// are constants with no HAProxy state to forget.
	p.reapplyDrains(ctx, stale, statusByName, svnameByAddr, fresh)

	// Drain phase — after the fresh count for this cycle is final.
	// usableFresh snapshots the pre-drain count: every backend in it
	// stays enabled through the drain (drains only remove stale
	// backends), so it is the RIGHT basis for the VIP bypass decision
	// — unlike the decremented fence budget below.
	usableFresh := fresh
	p.drainStale(ctx, stale, statusByName, svnameByAddr, wdir, &fresh)

	// VIP phase (sig14b): *_lb entries round-robin across controllers,
	// so when any direct controller is wedged/drained AND >=1 direct
	// controller is fresh, disable the VIP entry so traffic goes
	// straight to the healthy controller(s). Re-enable when all direct
	// controllers are healthy again, or when fresh == 0 (least-bad).
	p.syncVIP(ctx, backends, vips, stale, usableFresh, fresh)

	// Export per-backend enabled state after all transitions.
	p.exportEnabled(backends)

	// Prune state for backends that left discovery — only when
	// discover returned rows (never on discover_fail/empty: a failed
	// or empty scan must not wipe latches/counters/metric series the
	// next good scan still needs).
	if len(backends) > 0 {
		p.pruneStaleBackends(wdir, backends)
		if wdir != "" {
			p.pruneWatchdogFiles(wdir, backends)
		}
	}
}
