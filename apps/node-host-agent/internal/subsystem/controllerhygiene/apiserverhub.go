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
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// countMatches mirrors `grep -cE '<re>'` — matching line count.
// strings.Cut iterates in place — no giant []string allocation on a
// multi-MiB journal snapshot.
func countMatches(re *regexp.Regexp, text string) int {
	n := 0
	for rest := text; rest != ""; {
		line, after, _ := strings.Cut(rest, "\n")
		rest = after
		if re.MatchString(line) {
			n++
		}
	}
	return n
}

// apiserverHubCheck is the module-22 sig13 wedge guard as a Check
// — stateless: gap/frozen/dead streaks and the last-rvc/last-prvc
// stamps live in the bookkeeping files.
type apiserverHubCheck struct {
	d *deps
}

// Name returns the check label / log context.
func (c *apiserverHubCheck) Name() string { return checkHub }

// Run executes the journal early-warning plus the rv probe wedge
// logic — one merged 60s pass over module 22's sig13 body.
func (c *apiserverHubCheck) Run(ctx context.Context) {
	now := c.d.cfg.nowFn()

	// --- early warning: apiserver-cache-stale ---
	cacheErrs := countMatches(cacheErrRe,
		c.d.journalText(ctx, now.Add(-6*time.Minute)))
	if cacheErrs >= c.d.cfg.Sig13.StaleMinErrs {
		c.d.state.Enter(stateCacheStale,
			fmt.Sprintf("errors=%d/6min", cacheErrs))
		c.d.state.SuspectLog(stateCacheStale, fmt.Sprintf(
			"suspect: apiserver-cache-stale - k0scontroller journal has %d watch-cache/consistency errors in 6 minutes",
			cacheErrs), c.d.cfg.SuspectLogCadence)
	} else {
		c.d.stateExit(stateCacheStale)
	}

	// --- functional wedge confirm ---
	// The shell gates the whole rv probe on the admin cert existing;
	// ensureClient()==nil is the equivalent "not a controller / k0s
	// not initialised" no-op.
	if c.d.ensureClient() == nil && c.d.cfg.listRVFn == nil {
		c.d.cycles.WithLabelValues(checkHub, "no_creds").Inc()
		return
	}

	rvC, okC := c.d.listRV(ctx, c.d.cfg.Hub.SelfEndpoint, true)
	rvN, okN := c.d.listRV(ctx, c.d.cfg.Hub.SelfEndpoint, false)
	// Consistent read via self failed (apiserver too wedged) → fall
	// back to the peer: every consistent read goes to the storage
	// backend so the rv is equivalent.
	if !okN && c.d.cfg.Hub.PeerAPI != "" {
		rvN, okN = c.d.listRV(ctx, c.d.cfg.Hub.PeerAPI, false)
	}
	gapKnown := okC && okN
	var gap int64
	if gapKnown {
		gap = rvN - rvC
		c.d.rvGap.Set(float64(gap))
	}

	// Frozen signal: rv_cache bit-identical to the previous cycle
	// while rv_now keeps advancing. Counter resets when rv_cache
	// moves (healthy), rv_now <= rv_cache (idle cluster — standing
	// still is not wedge evidence) or rv_now is unmeasurable.
	frn := 0
	frozen := false
	if okC {
		prev := c.d.readState(fileLastRVC)
		c.d.state.WriteEpochFile(filepath.Join(c.d.state.Dir, fileLastRVC), rvC)
		if gapKnown && prev == strconv.FormatInt(rvC, 10) && rvN > rvC {
			frn = c.d.state.Incr(fileCtrFrozen)
			if frn >= c.d.streakCycles(c.d.cfg.Sig13.FrozenCycles) {
				frozen = true
			}
		} else {
			c.d.state.ResetCounter(fileCtrFrozen)
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
	if c.d.cfg.Hub.PeerAPI != "" {
		prvRV, prvOK = c.d.listRV(ctx, c.d.cfg.Hub.PeerAPI, true)
		if prvOK {
			prv = strconv.FormatInt(prvRV, 10)
			prevP := c.d.readState(fileLastPRVC)
			c.d.state.WriteEpochFile(filepath.Join(c.d.state.Dir, fileLastPRVC), prvRV)
			if prevP != "" && prevP == prv && gapKnown && rvN > prvRV {
				pfn = c.d.state.Incr(fileCtrPeerFrozen)
				if pfn >= c.d.streakCycles(c.d.cfg.Sig13.FrozenCycles) {
					peerFrozen = true
				}
			} else {
				c.d.state.ResetCounter(fileCtrPeerFrozen)
			}
		}
	}

	wedged := false
	wreason := ""
	if gapKnown && gap > c.d.cfg.Sig13.GapMin {
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
		c.d.stateExit(stateKineUnreachable)
	}

	if !wedged {
		c.d.state.ResetCounter(fileCtrGap)
		c.d.stateExit(stateCacheWedged)
		// rv measurable again → reset the dead counter (it only
		// covers the both-APIs-mute window; left alone it would
		// carry into the next incident).
		if gapKnown {
			c.d.state.ResetCounter(fileCtrDead)
		}
		if !gapKnown && cacheErrs > 0 {
			c.deadFallback(ctx)
		}
		c.d.cycles.WithLabelValues(checkHub, "ok").Inc()
		return
	}

	// --- wedge evidence present ---
	gn := c.d.state.Incr(fileCtrGap)
	c.d.state.Enter(stateCacheWedged,
		fmt.Sprintf("%s rv_cache=%d rv_now=%d", wreason, rvC, rvN))
	// Frozen is already sustained evidence — bypass the second
	// GAP_CYCLES gate (a big one-off gap can be transient lag; a
	// bit-identical rv_cache cannot).
	if !frozen && gn < c.d.streakCycles(c.d.cfg.Sig13.GapCycles) {
		c.d.state.AppendLog(fmt.Sprintf(
			"suspect: apiserver cache %s — wedge evidence (check %d/%d)",
			wreason, gn, c.d.streakCycles(c.d.cfg.Sig13.GapCycles)))
		c.d.cycles.WithLabelValues(checkHub, "ok").Inc()
		return
	}

	// --- peer fence ---
	peerFresh := false
	peerNote := "no-api-peer-conf"
	if c.d.cfg.Hub.PeerAPI != "" {
		switch {
		case !prvOK:
			peerNote = "peer-unreachable-or-unreadable"
		case peerFrozen:
			peerNote = fmt.Sprintf("peer-frozen prv=%s (%dx)", prv, pfn)
		case rvN-prvRV < c.d.cfg.Sig13.GapMin:
			peerFresh = true
			peerNote = fmt.Sprintf("peer-fresh gap=%d", rvN-prvRV)
		default:
			peerNote = fmt.Sprintf("peer-stale gap=%d", rvN-prvRV)
		}
	}
	soloOK := false
	if !peerFresh && c.d.cfg.Hub.SelfAPI != "" {
		if (c.d.cfg.Hub.PeerAPI == "" || c.d.cfg.Hub.SelfAPI < c.d.cfg.Hub.PeerAPI) &&
			gn >= c.d.streakCycles(c.d.cfg.Sig13.SoloCycles) {
			soloOK = true
		}
	}

	switch {
	case !c.d.state.RateOK(fileRateRestart, c.d.cfg.Sig13.MinRestart):
		c.d.state.SuspectLog(stateCacheWedged, fmt.Sprintf(
			"suspect: apiserver-cache-wedged %s (%dx) - in restart cooldown (<%dm), skip",
			wreason, gn, int(c.d.cfg.Sig13.MinRestart.Minutes())),
			c.d.cfg.SuspectLogCadence)
		c.d.actions.WithLabelValues(checkHub, "fence_cooldown").Inc()
	case peerFresh || soloOK:
		switch c.d.cfg.Sig13.Mode {
		case ModeEnforce:
			c.d.state.AppendLog(fmt.Sprintf(
				"ACTION: restarting k0scontroller - apiserver-cache-wedged %s (%dx) %s solo=%v",
				wreason, gn, peerNote, soloOK))
			c.d.state.RateSpend(fileRateRestart)
			c.d.state.ResetCounter(fileCtrGap)
			// W8-CP1: hung HTTP/2 watch streams can survive past the
			// wedge decision and pin the apiserver's watch cache —
			// ss -K drops the zombie sockets so the restart (and the
			// post-restart reconnect) starts clean.
			if err := c.d.cfg.ssKillFn(ctx); err != nil {
				c.d.state.AppendLogWarn(fmt.Sprintf(
					"ss -K sport = :6443 failed (zombie watch streams left): %v", err))
			}
			if err := c.d.cfg.restartFn(ctx, c.d.cfg.RestartUnit); err != nil {
				c.d.state.AppendLogWarn(fmt.Sprintf(
					"suspect: restart %s failed: %v", c.d.cfg.RestartUnit, err))
			}
			c.d.actions.WithLabelValues(checkHub, "restart_controller").Inc()
		case ModeDryRun:
			c.d.state.AppendLog(fmt.Sprintf(
				"DRY-RUN: would restart k0scontroller - apiserver-cache-wedged %s (%dx) %s solo=%v",
				wreason, gn, peerNote, soloOK))
			c.d.actions.WithLabelValues(checkHub, "dryrun_restart").Inc()
		}
	default:
		c.d.state.SuspectLog(stateCacheWedged, fmt.Sprintf(
			"suspect: apiserver-cache-wedged %s (%dx) but %s and self is not first-hub (or <%d cycles not reached) — holding",
			wreason, gn, peerNote, c.d.streakCycles(c.d.cfg.Sig13.SoloCycles)), c.d.cfg.SuspectLogCadence)
		c.d.actions.WithLabelValues(checkHub, "fence_skip").Inc()
	}
	c.d.cycles.WithLabelValues(checkHub, "ok").Inc()
}

// deadFallback is the rv-unmeasurable path (incident 2026-09-25: both
// apiservers mute on kine backend auth failure — the old veto kept the
// wedge running forever). When the pg-wire probe says the DB is alive
// the outage is in the apiserver → the "dead" restart path is allowed
// (first-hub + SoloCycles + rate-limit). When the probe fails the
// outage is DB-side → latch kine-backend-unreachable instead.
func (c *apiserverHubCheck) deadFallback(ctx context.Context) {
	// Own key, not stateCacheStale: sharing the cache-stale key meant
	// the :73 cache-stale line spent the slot first every cadence and
	// this "autofix is blind" signal stayed suppressed permanently.
	c.d.state.SuspectLog(logKeyDeadFallbk,
		"suspect: apiserver-cache-stale but rv-gap unmeasurable "+
			"(self+peer query fail) — wedged/autofix skipped",
		c.d.cfg.SuspectLogCadence)
	if c.d.cfg.Hub.KineDBProbe == "" {
		return
	}
	// Two probes 3s apart — one blip must not latch DB-dead.
	if !c.d.cfg.pgWireFn(ctx, c.d.cfg.Hub.KineDBProbe) {
		c.d.cfg.sleepFn(3 * time.Second)
		if !c.d.cfg.pgWireFn(ctx, c.d.cfg.Hub.KineDBProbe) {
			c.d.state.ResetCounter(fileCtrDead)
			c.d.state.Enter(stateKineUnreachable,
				c.d.cfg.Hub.KineDBProbe+" pg-wire fail")
			c.d.state.SuspectLog(stateKineUnreachable, fmt.Sprintf(
				"suspect: kine-backend-unreachable %s — apiserver fail is a consequence of DB/pgbouncer, restarting the controller is useless",
				c.d.cfg.Hub.KineDBProbe), c.d.cfg.SuspectLogCadence)
			return
		}
	}
	c.d.stateExit(stateKineUnreachable)
	dn := c.d.state.Incr(fileCtrDead)
	deadFirst := c.d.cfg.Hub.SelfAPI != "" &&
		(c.d.cfg.Hub.PeerAPI == "" || c.d.cfg.Hub.SelfAPI < c.d.cfg.Hub.PeerAPI)
	if dn < c.d.streakCycles(c.d.cfg.Sig13.SoloCycles) || !deadFirst {
		c.d.state.SuspectLog(logKeyDeadFallbk, fmt.Sprintf(
			"suspect: apiserver dead, kine db ok — dead-fallback needs %d cycles + first-hub (dn=%d first=%v)",
			c.d.streakCycles(c.d.cfg.Sig13.SoloCycles), dn, deadFirst), c.d.cfg.SuspectLogCadence)
		return
	}
	if !c.d.state.RateOK(fileRateRestart, c.d.cfg.Sig13.MinRestart) {
		c.d.state.SuspectLog(logKeyDeadFallbk, fmt.Sprintf(
			"suspect: apiserver dead + kine db ok but in restart cooldown (<%dm), skip",
			int(c.d.cfg.Sig13.MinRestart.Minutes())), c.d.cfg.SuspectLogCadence)
		return
	}
	switch c.d.cfg.Sig13.Mode {
	case ModeEnforce:
		c.d.state.AppendLog(fmt.Sprintf(
			"ACTION: restarting k0scontroller - apiserver unresponsive, kine db %s healthy (dead-fallback %dx)",
			c.d.cfg.Hub.KineDBProbe, dn))
		c.d.state.RateSpend(fileRateRestart)
		c.d.state.ResetCounter(fileCtrDead)
		if err := c.d.cfg.restartFn(ctx, c.d.cfg.RestartUnit); err != nil {
			c.d.state.AppendLogWarn(fmt.Sprintf(
				"suspect: restart %s failed: %v", c.d.cfg.RestartUnit, err))
		}
		c.d.actions.WithLabelValues(checkHub, "restart_controller").Inc()
	case ModeDryRun:
		c.d.state.AppendLog(fmt.Sprintf(
			"DRY-RUN: would restart k0scontroller - apiserver dead, kine db ok (dead-fallback %dx)", dn))
		c.d.actions.WithLabelValues(checkHub, "dryrun_restart").Inc()
	}
}

// kineTTLCheck is the module-22 tail as a Check — stateless: the
// rewedge streak and wedged-pid dedupe live in consecutive-ttl-
// rewedge / ttl-last-wedged-pid.
type kineTTLCheck struct {
	d *deps
}

// Name returns the check label / log context.
func (c *kineTTLCheck) Name() string { return checkKineTTL }

// Run detects a kine process whose TTL workqueue died at boot and
// kills it so the supervisor respawns a clean one — escalating to
// the kine-ttl-loop latch (fast-kill suppressed, low-cadence probe
// kill only) when every respawned pid re-wedges from boot
// (deterministic environment race, not chance).
func (c *kineTTLCheck) Run(ctx context.Context) {
	kpid := c.d.proc.FindByComm("kine")
	if kpid == 0 {
		c.d.stateExit(stateKineTTLDead)
		c.d.stateExit(stateKineTTLLoop)
		c.d.cycles.WithLabelValues(checkKineTTL, "ok").Inc()
		return
	}
	now := c.d.cfg.nowFn()
	kage, err := c.d.proc.PIDAgeSeconds(kpid, clkTck)
	if err != nil {
		// Age unreadable → the journal window collapses to "now"
		// and a dead TTL goes undetected — surface it.
		c.d.state.AppendLogWarn(fmt.Sprintf(
			"suspect: kine pid=%d age unreadable: %v — TTL journal window degenerates",
			kpid, err))
		kage = 0
	}
	since := now.Add(-time.Duration(kage) * time.Second)
	ttlDead := countMatches(ttlErrRe, c.d.journalText(ctx, since)) > 0
	if !ttlDead {
		// Pid living clean past the seed window → loop broken:
		// reset the counter and clear both latches.
		c.d.state.ResetCounter(fileCtrTTLRewedge)
		c.d.state.ResetCounter(fileTTLWedgedPID)
		c.d.stateExit(stateKineTTLDead)
		c.d.stateExit(stateKineTTLLoop)
		c.d.cycles.WithLabelValues(checkKineTTL, "ok").Inc()
		return
	}

	c.d.state.Enter(stateKineTTLDead,
		fmt.Sprintf("pid=%d age=%ds", kpid, int(kage)))
	// Each wedged pid counts once (dedupe ttl-last-wedged-pid); a pid
	// change = respawn after kill/crash — re-wedging on the new pid
	// is "kill cannot cure" evidence → accumulate rewedge.
	rew := 0
	if strconv.Itoa(kpid) != c.d.readState(fileTTLWedgedPID) {
		c.d.state.WriteEpochFile(filepath.Join(c.d.state.Dir, fileTTLWedgedPID),
			int64(kpid))
		rew = c.d.state.Incr(fileCtrTTLRewedge)
	} else {
		rew = c.d.state.Counter(fileCtrTTLRewedge)
	}

	switch {
	case rew >= c.d.cfg.KineTTL.RewedgeCycles:
		c.d.state.Enter(stateKineTTLLoop,
			fmt.Sprintf("rewedge=%dx pid=%d", rew, kpid))
		// Held-latch dedupe (nonprod 2026-10: this line logged every
		// 60s cycle for weeks, 1600+ mentions) — first line on latch
		// entry, then one re-reminder per SuspectLogCadence. The rew
		// counter above still updates every cycle.
		c.d.state.SuspectLog(stateKineTTLLoop, fmt.Sprintf(
			"suspect: kine-ttl-loop — %d consecutive kine pids wedged from boot; deterministic env (WAN DB + seed race), fast-kill suppressed",
			rew), c.d.cfg.SuspectLogCadence)
		// Loop path: one recovery-probe kill per KineTTLCtlRestart —
		// faster remediation is pointless and just flaps.
		if !c.d.state.RateOK(fileRateTTLKill, c.d.cfg.KineTTL.CtlRestart) {
			break // low cadence not reached — stay silent
		}
		switch c.d.cfg.KineTTL.Mode {
		case ModeEnforce:
			c.d.state.AppendLog(fmt.Sprintf(
				"ACTION: kill kine pid=%d — recovery probe kine-ttl-loop (rewedge=%dx, cadence %ds)",
				kpid, rew, int(c.d.cfg.KineTTL.CtlRestart.Seconds())))
			c.d.state.RateSpend(fileRateTTLKill)
			if err := c.d.cfg.killFn(kpid, syscall.SIGTERM); err != nil {
				c.d.state.AppendLogWarn(fmt.Sprintf(
					"suspect: kill kine pid=%d failed: %v", kpid, err))
			}
			c.d.actions.WithLabelValues(checkKineTTL, "kill_kine").Inc()
		case ModeDryRun:
			c.d.state.AppendLog(fmt.Sprintf(
				"DRY-RUN: would kill kine pid=%d — kine-ttl-loop rewedge=%dx", kpid, rew))
			c.d.actions.WithLabelValues(checkKineTTL, "dryrun_kill").Inc()
		}
	case kage > c.d.cfg.KineTTL.MinProcAge.Seconds():
		// Tier 1 (chance wedge): only remediate once the instance
		// survived the seed window — never restart INTO the storm.
		if !c.d.state.RateOK(fileRateTTLKill, c.d.cfg.KineTTL.MinRestart) {
			c.d.state.SuspectLog(stateKineTTLDead, fmt.Sprintf(
				"suspect: kine-ttl-dead but in restart cooldown (<%dm), skip",
				int(c.d.cfg.KineTTL.MinRestart.Minutes())), c.d.cfg.SuspectLogCadence)
			break
		}
		switch c.d.cfg.KineTTL.Mode {
		case ModeEnforce:
			c.d.state.AppendLog(fmt.Sprintf(
				"ACTION: kill kine pid=%d — TTL workqueue dead — k0s supervisor respawns",
				kpid))
			c.d.state.RateSpend(fileRateTTLKill)
			if err := c.d.cfg.killFn(kpid, syscall.SIGTERM); err != nil {
				c.d.state.AppendLogWarn(fmt.Sprintf(
					"suspect: kill kine pid=%d failed: %v", kpid, err))
			}
			c.d.actions.WithLabelValues(checkKineTTL, "kill_kine").Inc()
		case ModeDryRun:
			c.d.state.AppendLog(fmt.Sprintf(
				"DRY-RUN: would kill kine pid=%d — TTL dead", kpid))
			c.d.actions.WithLabelValues(checkKineTTL, "dryrun_kill").Inc()
		}
	}
	c.d.cycles.WithLabelValues(checkKineTTL, "ok").Inc()
}
