package controllerhygiene

// apiserverhub.go — sig13 port: local apiserver watch-cache wedge
// guard + kine TTL dead/rewedge loop (watchdog/modules/22-apiserver-
// hub.sh, merged with the k0s-apiserver-wedge-probe.sh accelerator).
//
// Signals (1:1):
//   apiserver-cache-stale    journal errors >= StaleMinErrs/6min —
//                            early warning only.
//   apiserver-cache-wedged   rv_now - rv_cache > GapMin for GapCycles
//                            consecutive cycles, OR rv_cache bit-
//                            identical while rv_now advances for
//                            FrozenCycles consecutive cycles (frozen
//                            bypasses the gap gate — sustained
//                            evidence with no plausible false
//                            positive).
//   kine-backend-unreachable both self+peer API queries dead AND the
//                            pg-wire probe fails — the outage sits in
//                            Postgres/PgBouncer, restarting
//                            k0scontroller is useless.
//   kine-ttl-dead            "TTL initial list failed|TTL event watch
//                            (failed|error)" in the journal since the
//                            CURRENT kine pid booted — workqueue
//                            ShutDown forever, kine never retries.
//   kine-ttl-loop            KineTTLRewedgeCycles DISTINCT kine pids
//                            each wedged since their own boot —
//                            deterministic seed race (WAN DB +
//                            large seed list); fast-kill suppressed,
//                            only a low-cadence recovery-probe kill.
//
// Restart fence (identical to the shell): restart k0scontroller only
// when the peer is FRESH, or — peer unreachable/stale — when self is
// the deterministic first hub AND SoloCycles wedge cycles elapsed.
// One restart per MinRestartInterval via the shared
// last-sig13-restart budget file.

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"syscall"
	"time"
)

// countMatches mirrors `grep -cE '<re>'` — matching line count.
func countMatches(re *regexp.Regexp, text string) int {
	n := 0
	for _, line := range splitLines(text) {
		if re.MatchString(line) {
			n++
		}
	}
	return n
}

// checkApiserverHub runs the journal early-warning plus the rv probe
// wedge logic — one merged 60s pass over module 22's sig13 body.
func (h *Hygiene) checkApiserverHub(ctx context.Context) {
	now := h.cfg.nowFn()

	// --- early warning: apiserver-cache-stale ---
	cacheErrs := countMatches(cacheErrRe,
		h.journalText(ctx, now.Add(-6*time.Minute)))
	if cacheErrs >= h.cfg.StaleMinErrs {
		h.stateEnter(stateCacheStale,
			fmt.Sprintf("errors=%d/6min", cacheErrs))
		h.appendLog(fmt.Sprintf(
			"suspect: apiserver-cache-stale - k0scontroller journal has %d watch-cache/consistency errors in 6 minutes",
			cacheErrs))
	} else {
		h.stateExit(stateCacheStale)
	}

	// --- functional wedge confirm ---
	// The shell gates the whole rv probe on the admin cert existing;
	// ensureClient()==nil is the equivalent "not a controller / k0s
	// not initialised" no-op.
	if h.ensureClient() == nil && h.cfg.listRVFn == nil {
		h.cycles.WithLabelValues(checkHub, "no_creds").Inc()
		return
	}

	rvC, okC := h.listRV(ctx, h.cfg.SelfEndpoint, true)
	rvN, okN := h.listRV(ctx, h.cfg.SelfEndpoint, false)
	// Consistent read via self failed (apiserver too wedged) → fall
	// back to the peer: every consistent read goes to the storage
	// backend so the rv is equivalent.
	if !okN && h.cfg.PeerAPI != "" {
		rvN, okN = h.listRV(ctx, h.cfg.PeerAPI, false)
	}
	gapKnown := okC && okN
	var gap int64
	if gapKnown {
		gap = rvN - rvC
		h.rvGap.Set(float64(gap))
	}

	// Frozen signal: rv_cache bit-identical to the previous cycle
	// while rv_now keeps advancing. Counter resets when rv_cache
	// moves (healthy), rv_now <= rv_cache (idle cluster — standing
	// still is not wedge evidence) or rv_now is unmeasurable.
	frn := 0
	frozen := false
	if okC {
		prev := h.readState(fileLastRVC)
		h.writeState(fileLastRVC, strconv.FormatInt(rvC, 10))
		if gapKnown && prev == strconv.FormatInt(rvC, 10) && rvN > rvC {
			frn = h.ctrInc(fileCtrFrozen)
			if frn >= h.cfg.FrozenCycles {
				frozen = true
			}
		} else {
			h.ctrReset(fileCtrFrozen)
		}
	}

	// Peer tracking: probe the peer's rv_cache EVERY cycle so the
	// fence distinguishes "peer genuinely fresh" (cache advancing)
	// from "peer also wedged" — a gap-only check misses a fresh peer
	// wedge (gap stays < GapMin for the first hours).
	prv := ""
	prvOK := false
	var prvRV int64
	pfn := 0
	peerFrozen := false
	if h.cfg.PeerAPI != "" {
		prvRV, prvOK = h.listRV(ctx, h.cfg.PeerAPI, true)
		if prvOK {
			prv = strconv.FormatInt(prvRV, 10)
			prevP := h.readState(fileLastPRVC)
			h.writeState(fileLastPRVC, prv)
			if prevP != "" && prevP == prv && gapKnown && rvN > prvRV {
				pfn = h.ctrInc(fileCtrPeerFrozen)
				if pfn >= h.cfg.FrozenCycles {
					peerFrozen = true
				}
			} else {
				h.ctrReset(fileCtrPeerFrozen)
			}
		}
	}

	wedged := false
	wreason := ""
	if gapKnown && gap > h.cfg.GapMin {
		wedged = true
		wreason = fmt.Sprintf("gap=%d", gap)
	} else if frozen {
		wedged = true
		wreason = fmt.Sprintf("frozen=%dx gap=%d", frn, gap)
	}
	// A measurable gap means the API answered → kine backend is
	// alive → clear the DB-dead latch (the alert must not outlive
	// the outage it describes).
	if gapKnown {
		h.stateExit(stateKineUnreachable)
	}

	if !wedged {
		h.ctrReset(fileCtrGap)
		h.stateExit(stateCacheWedged)
		// rv measurable again → reset the dead counter (it only
		// covers the both-APIs-mute window; left alone it would
		// carry into the next incident).
		if gapKnown {
			h.ctrReset(fileCtrDead)
		}
		if !gapKnown && cacheErrs > 0 {
			h.deadFallback(ctx)
		}
		h.cycles.WithLabelValues(checkHub, "ok").Inc()
		return
	}

	// --- wedge evidence present ---
	gn := h.ctrInc(fileCtrGap)
	h.stateEnter(stateCacheWedged,
		fmt.Sprintf("%s rv_cache=%d rv_now=%d", wreason, rvC, rvN))
	// Frozen is already sustained evidence — bypass the second
	// GAP_CYCLES gate (a big one-off gap can be transient lag; a
	// bit-identical rv_cache cannot).
	if !frozen && gn < h.cfg.GapCycles {
		h.appendLog(fmt.Sprintf(
			"suspect: apiserver cache %s — wedge evidence (check %d/%d)",
			wreason, gn, h.cfg.GapCycles))
		h.cycles.WithLabelValues(checkHub, "ok").Inc()
		return
	}

	// --- peer fence ---
	peerFresh := false
	peerNote := "no-api-peer-conf"
	if h.cfg.PeerAPI != "" {
		switch {
		case !prvOK:
			peerNote = "peer-unreachable-or-unreadable"
		case peerFrozen:
			peerNote = fmt.Sprintf("peer-frozen prv=%s (%dx)", prv, pfn)
		case rvN-prvRV < h.cfg.GapMin:
			peerFresh = true
			peerNote = fmt.Sprintf("peer-fresh gap=%d", rvN-prvRV)
		default:
			peerNote = fmt.Sprintf("peer-stale gap=%d", rvN-prvRV)
		}
	}
	soloOK := false
	if !peerFresh && h.cfg.SelfAPI != "" {
		if (h.cfg.PeerAPI == "" || h.cfg.SelfAPI < h.cfg.PeerAPI) &&
			gn >= h.cfg.SoloCycles {
			soloOK = true
		}
	}

	switch {
	case !h.rateOK(h.cfg.WatchdogStateDir, fileRateRestart, h.cfg.MinRestartInterval):
		h.appendLog(fmt.Sprintf(
			"suspect: apiserver-cache-wedged %s (%dx) - in restart cooldown (<%dm), skip",
			wreason, gn, int(h.cfg.MinRestartInterval.Minutes())))
		h.actions.WithLabelValues(checkHub, "fence_cooldown").Inc()
	case peerFresh || soloOK:
		switch h.cfg.Sig13Mode {
		case ModeEnforce:
			h.appendLog(fmt.Sprintf(
				"ACTION: restarting k0scontroller - apiserver-cache-wedged %s (%dx) %s solo=%v",
				wreason, gn, peerNote, soloOK))
			h.rateSpend(h.cfg.WatchdogStateDir, fileRateRestart)
			h.ctrReset(fileCtrGap)
			if err := h.cfg.restartFn(ctx, h.cfg.RestartUnit); err != nil {
				h.appendLog(fmt.Sprintf(
					"suspect: restart %s failed: %v", h.cfg.RestartUnit, err))
			}
			h.actions.WithLabelValues(checkHub, "restart_controller").Inc()
		case ModeDryRun:
			h.appendLog(fmt.Sprintf(
				"DRY-RUN: would restart k0scontroller - apiserver-cache-wedged %s (%dx) %s solo=%v",
				wreason, gn, peerNote, soloOK))
			h.actions.WithLabelValues(checkHub, "dryrun_restart").Inc()
		}
	default:
		h.appendLog(fmt.Sprintf(
			"suspect: apiserver-cache-wedged %s (%dx) but %s and self is not first-hub (or <%d cycles not reached) — holding",
			wreason, gn, peerNote, h.cfg.SoloCycles))
		h.actions.WithLabelValues(checkHub, "fence_skip").Inc()
	}
	h.cycles.WithLabelValues(checkHub, "ok").Inc()
}

// deadFallback is the rv-unmeasurable path (incident 2026-09-25: both
// apiservers mute on kine backend auth failure — the old veto kept the
// wedge running forever). When the pg-wire probe says the DB is alive
// the outage is in the apiserver → the "dead" restart path is allowed
// (first-hub + SoloCycles + rate-limit). When the probe fails the
// outage is DB-side → latch kine-backend-unreachable instead.
func (h *Hygiene) deadFallback(ctx context.Context) {
	h.appendLog("suspect: apiserver-cache-stale but rv-gap unmeasurable " +
		"(self+peer query fail) — wedged/autofix skipped")
	if h.cfg.KineDBProbe == "" {
		return
	}
	// Two probes 3s apart — one blip must not latch DB-dead.
	if !h.cfg.pgWireFn(ctx, h.cfg.KineDBProbe) {
		h.cfg.sleepFn(3 * time.Second)
		if !h.cfg.pgWireFn(ctx, h.cfg.KineDBProbe) {
			h.ctrReset(fileCtrDead)
			h.stateEnter(stateKineUnreachable,
				fmt.Sprintf("%s pg-wire fail", h.cfg.KineDBProbe))
			h.appendLog(fmt.Sprintf(
				"suspect: kine-backend-unreachable %s — apiserver fail is a consequence of DB/pgbouncer, restarting the controller is useless",
				h.cfg.KineDBProbe))
			return
		}
	}
	h.stateExit(stateKineUnreachable)
	dn := h.ctrInc(fileCtrDead)
	deadFirst := h.cfg.SelfAPI != "" &&
		(h.cfg.PeerAPI == "" || h.cfg.SelfAPI < h.cfg.PeerAPI)
	if dn < h.cfg.SoloCycles || !deadFirst {
		h.appendLog(fmt.Sprintf(
			"suspect: apiserver dead, kine db ok — dead-fallback needs %d cycles + first-hub (dn=%d first=%v)",
			h.cfg.SoloCycles, dn, deadFirst))
		return
	}
	if !h.rateOK(h.cfg.WatchdogStateDir, fileRateRestart, h.cfg.MinRestartInterval) {
		h.appendLog(fmt.Sprintf(
			"suspect: apiserver dead + kine db ok but in restart cooldown (<%dm), skip",
			int(h.cfg.MinRestartInterval.Minutes())))
		return
	}
	switch h.cfg.Sig13Mode {
	case ModeEnforce:
		h.appendLog(fmt.Sprintf(
			"ACTION: restarting k0scontroller - apiserver unresponsive, kine db %s healthy (dead-fallback %dx)",
			h.cfg.KineDBProbe, dn))
		h.rateSpend(h.cfg.WatchdogStateDir, fileRateRestart)
		h.ctrReset(fileCtrDead)
		if err := h.cfg.restartFn(ctx, h.cfg.RestartUnit); err != nil {
			h.appendLog(fmt.Sprintf(
				"suspect: restart %s failed: %v", h.cfg.RestartUnit, err))
		}
		h.actions.WithLabelValues(checkHub, "restart_controller").Inc()
	case ModeDryRun:
		h.appendLog(fmt.Sprintf(
			"DRY-RUN: would restart k0scontroller - apiserver dead, kine db ok (dead-fallback %dx)", dn))
		h.actions.WithLabelValues(checkHub, "dryrun_restart").Inc()
	}
}

// checkKineTTL is the module-22 tail: detect a kine process whose TTL
// workqueue died at boot and kill it so the supervisor respawns a
// clean one — escalating to the kine-ttl-loop latch (fast-kill
// suppressed, low-cadence probe kill only) when every respawned pid
// re-wedges from boot (deterministic environment race, not chance).
func (h *Hygiene) checkKineTTL(ctx context.Context) {
	kpid := h.findProcByComm("kine")
	if kpid == 0 {
		h.stateExit(stateKineTTLDead)
		h.stateExit(stateKineTTLLoop)
		h.cycles.WithLabelValues(checkKineTTL, "ok").Inc()
		return
	}
	now := h.cfg.nowFn()
	kage, err := h.pidAgeSeconds(kpid)
	if err != nil {
		kage = 0
	}
	since := now.Add(-time.Duration(kage) * time.Second)
	ttlDead := countMatches(ttlErrRe, h.journalText(ctx, since)) > 0
	if !ttlDead {
		// Pid living clean past the seed window → loop broken:
		// reset the counter and clear both latches.
		h.ctrReset(fileCtrTTLRewedge)
		_ = removeStateFile(h.cfg.WatchdogStateDir, fileTTLWedgedPID)
		h.stateExit(stateKineTTLDead)
		h.stateExit(stateKineTTLLoop)
		h.cycles.WithLabelValues(checkKineTTL, "ok").Inc()
		return
	}

	h.stateEnter(stateKineTTLDead,
		fmt.Sprintf("pid=%d age=%ds", kpid, int(kage)))
	// Each wedged pid counts once (dedupe ttl-last-wedged-pid); a pid
	// change = respawn after kill/crash — re-wedging on the new pid
	// is "kill cannot cure" evidence → accumulate rewedge.
	rew := 0
	if strconv.Itoa(kpid) != h.readState(fileTTLWedgedPID) {
		h.writeState(fileTTLWedgedPID, strconv.Itoa(kpid))
		rew = h.ctrInc(fileCtrTTLRewedge)
	} else {
		rew = h.ctrRead(fileCtrTTLRewedge)
	}

	switch {
	case rew >= h.cfg.KineTTLRewedgeCycles:
		h.stateEnter(stateKineTTLLoop,
			fmt.Sprintf("rewedge=%dx pid=%d", rew, kpid))
		h.appendLog(fmt.Sprintf(
			"suspect: kine-ttl-loop — %d consecutive kine pids wedged from boot; deterministic env (WAN DB + seed race), fast-kill suppressed",
			rew))
		// Loop path: one recovery-probe kill per KineTTLCtlRestart —
		// faster remediation is pointless and just flaps.
		if !h.rateOK(h.cfg.WatchdogStateDir, fileRateTTLKill, h.cfg.KineTTLCtlRestart) {
			break // low cadence not reached — stay silent
		}
		switch h.cfg.KineTTLMode {
		case ModeEnforce:
			h.appendLog(fmt.Sprintf(
				"ACTION: kill kine pid=%d — recovery probe kine-ttl-loop (rewedge=%dx, cadence %ds)",
				kpid, rew, int(h.cfg.KineTTLCtlRestart.Seconds())))
			h.rateSpend(h.cfg.WatchdogStateDir, fileRateTTLKill)
			_ = h.cfg.killFn(kpid, syscall.SIGTERM) //nolint:errcheck // shell `kill` — SIGTERM best-effort
			h.actions.WithLabelValues(checkKineTTL, "kill_kine").Inc()
		case ModeDryRun:
			h.appendLog(fmt.Sprintf(
				"DRY-RUN: would kill kine pid=%d — kine-ttl-loop rewedge=%dx", kpid, rew))
			h.actions.WithLabelValues(checkKineTTL, "dryrun_kill").Inc()
		}
	case kage > h.cfg.KineTTLMinProcAge.Seconds():
		// Tier 1 (chance wedge): only remediate once the instance
		// survived the seed window — never restart INTO the storm.
		if !h.rateOK(h.cfg.WatchdogStateDir, fileRateTTLKill, h.cfg.KineTTLMinRestart) {
			h.appendLog(fmt.Sprintf(
				"suspect: kine-ttl-dead but in restart cooldown (<%dm), skip",
				int(h.cfg.KineTTLMinRestart.Minutes())))
			break
		}
		switch h.cfg.KineTTLMode {
		case ModeEnforce:
			h.appendLog(fmt.Sprintf(
				"ACTION: kill kine pid=%d — TTL workqueue dead — k0s supervisor respawns",
				kpid))
			h.rateSpend(h.cfg.WatchdogStateDir, fileRateTTLKill)
			_ = h.cfg.killFn(kpid, syscall.SIGTERM) //nolint:errcheck // shell `kill` — SIGTERM best-effort
			h.actions.WithLabelValues(checkKineTTL, "kill_kine").Inc()
		case ModeDryRun:
			h.appendLog(fmt.Sprintf(
				"DRY-RUN: would kill kine pid=%d — TTL dead", kpid))
			h.actions.WithLabelValues(checkKineTTL, "dryrun_kill").Inc()
		}
	}
	h.cycles.WithLabelValues(checkKineTTL, "ok").Inc()
}
