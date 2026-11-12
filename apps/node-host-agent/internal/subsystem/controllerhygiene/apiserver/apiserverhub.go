package apiserver

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
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/checkkit"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
)

// cacheErrRe is the module-22 early-warning journal grep.
var cacheErrRe = regexp.MustCompile(
	`Cache consistency check error|required revision has been compacted|error while range on /registry`)

// HubCheck is the module-22 sig13 wedge guard as a Check
// — stateless: gap/frozen/dead streaks and the last-rvc/last-prvc
// stamps live in the bookkeeping files.
type HubCheck struct {
	d *cdeps.Deps
}

// Name returns the check label / log context.
func (c *HubCheck) Name() string { return cdeps.CheckHub }

// Run executes the journal early-warning plus the rv probe wedge
// logic — one merged 60s pass over module 22's sig13 body.
func (c *HubCheck) Run(ctx context.Context) {
	now := c.d.Cfg.Clock.Now()

	// --- early warning: apiserver-cache-stale ---
	cacheErrs := cdeps.CountMatches(cacheErrRe,
		c.d.JournalText(ctx, now.Add(-6*time.Minute)))
	if cacheErrs >= c.d.Cfg.Sig13.StaleMinErrs {
		c.d.State.Enter(cdeps.StateCacheStale,
			fmt.Sprintf("errors=%d/6min", cacheErrs))
		c.d.State.SuspectLog(cdeps.StateCacheStale, fmt.Sprintf(
			"suspect: apiserver-cache-stale - k0scontroller journal has %d watch-cache/consistency errors in 6 minutes",
			cacheErrs), c.d.Cfg.SuspectLogCadence)
	} else {
		c.d.StateExit(cdeps.StateCacheStale)
	}

	// --- functional wedge confirm ---
	// The shell gates the whole rv probe on the admin cert existing;
	// ensureClient()==nil is the equivalent "not a controller / k0s
	// not initialised" no-op.
	if c.d.EnsureClient() == nil {
		c.d.Cycles.WithLabelValues(cdeps.CheckHub, "no_creds").Inc()
		return
	}

	rvC, okC := c.d.ListRV(ctx, c.d.Cfg.Hub.SelfEndpoint, true)
	rvN, okN := c.d.ListRV(ctx, c.d.Cfg.Hub.SelfEndpoint, false)
	// Consistent read via self failed (apiserver too wedged) → fall
	// back to the peer: every consistent read goes to the storage
	// backend so the rv is equivalent.
	if !okN && c.d.Cfg.Hub.PeerAPI != "" {
		rvN, okN = c.d.ListRV(ctx, c.d.Cfg.Hub.PeerAPI, false)
	}
	gapKnown := okC && okN
	var gap int64
	if gapKnown {
		gap = rvN - rvC
		c.d.RVGap.Set(float64(gap))
	}

	// Frozen signal: rv_cache bit-identical to the previous cycle
	// while rv_now keeps advancing. Counter resets when rv_cache
	// moves (healthy), rv_now <= rv_cache (idle cluster — standing
	// still is not wedge evidence) or rv_now is unmeasurable.
	frn := 0
	frozen := false
	if okC {
		prev := c.d.ReadState(cdeps.FileLastRVC)
		c.d.State.WriteEpochFile(filepath.Join(c.d.State.Dir, cdeps.FileLastRVC), rvC)
		if gapKnown && prev == strconv.FormatInt(rvC, 10) && rvN > rvC {
			frn = c.d.State.Incr(cdeps.FileCtrFrozen)
			if frn >= c.d.StreakCycles(c.d.Cfg.Sig13.FrozenCycles) {
				frozen = true
			}
		} else {
			c.d.State.ResetCounter(cdeps.FileCtrFrozen)
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
	if c.d.Cfg.Hub.PeerAPI != "" {
		prvRV, prvOK = c.d.ListRV(ctx, c.d.Cfg.Hub.PeerAPI, true)
		if prvOK {
			prv = strconv.FormatInt(prvRV, 10)
			prevP := c.d.ReadState(cdeps.FileLastPRVC)
			c.d.State.WriteEpochFile(filepath.Join(c.d.State.Dir, cdeps.FileLastPRVC), prvRV)
			if prevP != "" && prevP == prv && gapKnown && rvN > prvRV {
				pfn = c.d.State.Incr(cdeps.FileCtrPeerFrozen)
				if pfn >= c.d.StreakCycles(c.d.Cfg.Sig13.FrozenCycles) {
					peerFrozen = true
				}
			} else {
				c.d.State.ResetCounter(cdeps.FileCtrPeerFrozen)
			}
		}
	}

	wedged := false
	wreason := ""
	if gapKnown && gap > c.d.Cfg.Sig13.GapMin {
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
		c.d.StateExit(cdeps.StateKineUnreachable)
	}

	if !wedged {
		c.d.State.ResetCounter(cdeps.FileCtrGap)
		c.d.StateExit(cdeps.StateCacheWedged)
		// rv measurable again → reset the dead counter (it only
		// covers the both-APIs-mute window; left alone it would
		// carry into the next incident).
		if gapKnown {
			c.d.State.ResetCounter(cdeps.FileCtrDead)
		}
		if !gapKnown && cacheErrs > 0 {
			c.deadFallback(ctx)
		}
		c.d.Cycles.WithLabelValues(cdeps.CheckHub, "ok").Inc()
		return
	}

	// --- wedge evidence present ---
	gn := c.d.State.Incr(cdeps.FileCtrGap)
	c.d.State.Enter(cdeps.StateCacheWedged,
		fmt.Sprintf("%s rv_cache=%d rv_now=%d", wreason, rvC, rvN))
	// Frozen is already sustained evidence — bypass the second
	// GAP_CYCLES gate (a big one-off gap can be transient lag; a
	// bit-identical rv_cache cannot).
	if !frozen && gn < c.d.StreakCycles(c.d.Cfg.Sig13.GapCycles) {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: apiserver cache %s — wedge evidence%s",
			wreason,
			checkkit.Progress(gn, c.d.StreakCycles(c.d.Cfg.Sig13.GapCycles))))
		c.d.Cycles.WithLabelValues(cdeps.CheckHub, "ok").Inc()
		return
	}

	// --- peer fence ---
	peerFresh := false
	peerNote := "no-api-peer-conf"
	if c.d.Cfg.Hub.PeerAPI != "" {
		switch {
		case !prvOK:
			peerNote = "peer-unreachable-or-unreadable"
		case peerFrozen:
			peerNote = fmt.Sprintf("peer-frozen prv=%s (%dx)", prv, pfn)
		case rvN-prvRV < c.d.Cfg.Sig13.GapMin:
			peerFresh = true
			peerNote = fmt.Sprintf("peer-fresh gap=%d", rvN-prvRV)
		default:
			peerNote = fmt.Sprintf("peer-stale gap=%d", rvN-prvRV)
		}
	}
	soloOK := false
	if !peerFresh && c.d.Cfg.Hub.SelfAPI != "" {
		if (c.d.Cfg.Hub.PeerAPI == "" || c.d.Cfg.Hub.SelfAPI < c.d.Cfg.Hub.PeerAPI) &&
			gn >= c.d.StreakCycles(c.d.Cfg.Sig13.SoloCycles) {
			soloOK = true
		}
	}

	switch {
	case !c.d.State.RateOK(cdeps.FileRateRestart, c.d.Cfg.Sig13.MinRestart):
		c.d.State.SuspectLog(cdeps.StateCacheWedged, fmt.Sprintf(
			"suspect: apiserver-cache-wedged %s (%dx) - in restart cooldown (<%dm), skip",
			wreason, gn, int(c.d.Cfg.Sig13.MinRestart.Minutes())),
			c.d.Cfg.SuspectLogCadence)
		c.d.Actions.WithLabelValues(cdeps.CheckHub, "fence_cooldown").Inc()
	case peerFresh || soloOK:
		// L1↔L3 maintenance hold outranks every other gate: a
		// kured drain or control-plane upgrade is already bouncing
		// this node — restarting the controller on top adds churn
		// the drain did not budget for. Checked before the quorum
		// probe so an unverifiable maintenance state fails closed
		// without spending an API call.
		if c.d.HoldLocalAction(ctx) {
			c.d.State.SuspectLog(cdeps.StateCacheWedged, fmt.Sprintf(
				"suspect: apiserver-cache-wedged %s (%dx) but cluster maintenance in progress — holding restart",
				wreason, gn), c.d.Cfg.SuspectLogCadence)
			c.d.Actions.WithLabelValues(cdeps.CheckHub, "maint_hold").Inc()
			break
		}
		// Peer-quorum gate on the peer-fresh path: the kubernetes
		// service must still report >=2 ready apiserver endpoints —
		// bouncing the controller below quorum takes the last
		// serving apiserver down with it. soloOK (first-hub, peer
		// stale) is the degraded-cluster escape: no quorum evidence
		// exists to check, restart anyway.
		if peerFresh && !c.d.ControllerQuorumReady(ctx) {
			c.d.State.SuspectLog(cdeps.StateCacheWedged, fmt.Sprintf(
				"suspect: apiserver-cache-wedged %s (%dx) but default/kubernetes reports <2 ready endpoints — holding restart",
				wreason, gn), c.d.Cfg.SuspectLogCadence)
			c.d.Actions.WithLabelValues(cdeps.CheckHub, "quorum_hold").Inc()
			break
		}
		switch c.d.Cfg.Sig13.Mode {
		case cdeps.ModeEnforce:
			c.d.State.AppendLog(fmt.Sprintf(
				"ACTION: restarting k0scontroller - apiserver-cache-wedged %s (%dx) %s solo=%v",
				wreason, gn, peerNote, soloOK))
			c.d.State.RateSpend(cdeps.FileRateRestart)
			c.d.State.ResetCounter(cdeps.FileCtrGap)
			// cp-component-restart: hung HTTP/2 watch streams can survive past the
			// wedge decision and pin the apiserver's watch cache —
			// ss -K drops the zombie sockets so the restart (and the
			// post-restart reconnect) starts clean.
			if err := c.d.SSKill(ctx); err != nil {
				c.d.State.AppendLogWarn(fmt.Sprintf(
					"ss -K sport = :6443 failed (zombie watch streams left): %v", err))
			}
			if err := c.d.Restart(ctx, c.d.Cfg.RestartUnit); err != nil {
				c.d.State.AppendLogWarn(fmt.Sprintf(
					"suspect: restart %s failed: %v", c.d.Cfg.RestartUnit, err))
			}
			c.d.Actions.WithLabelValues(cdeps.CheckHub, "restart_controller").Inc()
		case cdeps.ModeDryRun:
			c.d.State.AppendLog(fmt.Sprintf(
				"DRY-RUN: would restart k0scontroller - apiserver-cache-wedged %s (%dx) %s solo=%v",
				wreason, gn, peerNote, soloOK))
			c.d.Actions.WithLabelValues(cdeps.CheckHub, "dryrun_restart").Inc()
		}
	default:
		c.d.State.SuspectLog(cdeps.StateCacheWedged, fmt.Sprintf(
			"suspect: apiserver-cache-wedged %s (%dx) but %s and self is not first-hub (or <%d cycles not reached) — holding",
			wreason, gn, peerNote, c.d.StreakCycles(c.d.Cfg.Sig13.SoloCycles)), c.d.Cfg.SuspectLogCadence)
		c.d.Actions.WithLabelValues(cdeps.CheckHub, "fence_skip").Inc()
	}
	c.d.Cycles.WithLabelValues(cdeps.CheckHub, "ok").Inc()
}

// deadFallback is the rv-unmeasurable path (incident 2026-09-25: both
// apiservers mute on kine backend auth failure — the old veto kept the
// wedge running forever). When the pg-wire probe says the DB is alive
// the outage is in the apiserver → the "dead" restart path is allowed
// (first-hub + SoloCycles + rate-limit). When the probe fails the
// outage is DB-side → latch kine-backend-unreachable instead.
func (c *HubCheck) deadFallback(ctx context.Context) {
	// Own key, not cdeps.StateCacheStale: sharing the cache-stale key meant
	// the :73 cache-stale line spent the slot first every cadence and
	// this "autofix is blind" signal stayed suppressed permanently.
	c.d.State.SuspectLog(cdeps.LogKeyDeadFallbk,
		"suspect: apiserver-cache-stale but rv-gap unmeasurable "+
			"(self+peer query fail) — wedged/autofix skipped",
		c.d.Cfg.SuspectLogCadence)
	if c.d.Cfg.Hub.KineDBProbe == "" {
		return
	}
	// Two probes 3s apart — one blip must not latch DB-dead.
	if !c.d.Cfg.PgWireFn(ctx, c.d.Cfg.Hub.KineDBProbe) {
		c.d.Cfg.SleepFn(3 * time.Second)
		if !c.d.Cfg.PgWireFn(ctx, c.d.Cfg.Hub.KineDBProbe) {
			c.d.State.ResetCounter(cdeps.FileCtrDead)
			c.d.State.Enter(cdeps.StateKineUnreachable,
				c.d.Cfg.Hub.KineDBProbe+" pg-wire fail")
			c.d.State.SuspectLog(cdeps.StateKineUnreachable, fmt.Sprintf(
				"suspect: kine-backend-unreachable %s — apiserver fail is a consequence of DB/pgbouncer, restarting the controller is useless",
				c.d.Cfg.Hub.KineDBProbe), c.d.Cfg.SuspectLogCadence)
			return
		}
	}
	c.d.StateExit(cdeps.StateKineUnreachable)
	dn := c.d.State.Incr(cdeps.FileCtrDead)
	deadFirst := c.d.Cfg.Hub.SelfAPI != "" &&
		(c.d.Cfg.Hub.PeerAPI == "" || c.d.Cfg.Hub.SelfAPI < c.d.Cfg.Hub.PeerAPI)
	if dn < c.d.StreakCycles(c.d.Cfg.Sig13.SoloCycles) || !deadFirst {
		c.d.State.SuspectLog(cdeps.LogKeyDeadFallbkStreak, fmt.Sprintf(
			"suspect: apiserver dead, kine db ok — dead-fallback needs %d cycles + first-hub (dn=%d first=%v)",
			c.d.StreakCycles(c.d.Cfg.Sig13.SoloCycles), dn, deadFirst), c.d.Cfg.SuspectLogCadence)
		return
	}
	if c.d.HoldLocalAction(ctx) {
		c.d.State.SuspectLog(cdeps.LogKeyDeadFallbkCool,
			"suspect: apiserver dead + kine db ok but cluster maintenance in progress — holding restart",
			c.d.Cfg.SuspectLogCadence)
		return
	}
	if !c.d.State.RateOK(cdeps.FileRateRestart, c.d.Cfg.Sig13.MinRestart) {
		c.d.State.SuspectLog(cdeps.LogKeyDeadFallbkCool, fmt.Sprintf(
			"suspect: apiserver dead + kine db ok but in restart cooldown (<%dm), skip",
			int(c.d.Cfg.Sig13.MinRestart.Minutes())), c.d.Cfg.SuspectLogCadence)
		return
	}
	switch c.d.Cfg.Sig13.Mode {
	case cdeps.ModeEnforce:
		c.d.State.AppendLog(fmt.Sprintf(
			"ACTION: restarting k0scontroller - apiserver unresponsive, kine db %s healthy (dead-fallback %dx)",
			c.d.Cfg.Hub.KineDBProbe, dn))
		c.d.State.RateSpend(cdeps.FileRateRestart)
		c.d.State.ResetCounter(cdeps.FileCtrDead)
		if err := c.d.Restart(ctx, c.d.Cfg.RestartUnit); err != nil {
			c.d.State.AppendLogWarn(fmt.Sprintf(
				"suspect: restart %s failed: %v", c.d.Cfg.RestartUnit, err))
		}
		c.d.Actions.WithLabelValues(cdeps.CheckHub, "restart_controller").Inc()
	case cdeps.ModeDryRun:
		c.d.State.AppendLog(fmt.Sprintf(
			"DRY-RUN: would restart k0scontroller - apiserver dead, kine db ok (dead-fallback %dx)", dn))
		// Spend the same budget enforce would — a dry-run that
		// ignores the restart cooldown logs an action every cycle
		// and misrepresents what enforce would actually do.
		c.d.State.RateSpend(cdeps.FileRateRestart)
		c.d.State.ResetCounter(cdeps.FileCtrDead)
		c.d.Actions.WithLabelValues(cdeps.CheckHub, "dryrun_restart").Inc()
	}
}
