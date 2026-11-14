// Backend probe phase: verdict type, probe loop and per-backend probe round.
// Split out of cycle.go (pure move).

package apiprober

import (
	"context"
)

// probeVerdict is one backend's probe-round outcome — the two
// counters Cycle's phases consume: stale marks a wedged/dead
// backend (drain candidate), fresh marks a usable one (fence
// budget). Both false = inconclusive — the cycle counts the
// backend neither way.
type probeVerdict struct {
	stale bool
	fresh bool
}

// probeBackends runs the per-backend probe loop and returns the
// cycle's aggregate: the fresh count, the stale set, the status
// snapshot every later phase reads, the VIP entries held out of
// probing, and aborted — true when ctx died mid-loop (the caller
// returns early, same as the old inline ctx.Err() check).
func (p *Prober) probeBackends(ctx context.Context, backends []backend,
	wdir string, svnameByAddr map[string]string) (fresh int,
	stale map[string]bool, statusByName map[string]backend,
	vips []backend, aborted bool) {

	stale = map[string]bool{}
	statusByName = make(map[string]backend, len(backends))
	for _, b := range backends {
		if ctx.Err() != nil {
			return 0, nil, nil, nil, true
		}
		statusByName[b.Name] = b
		st := p.stateFor(b.Name)
		if wdir != "" && !st.loaded {
			// Restart witness: fold the persisted apibe-* counters
			// in once per backend per process lifetime — BEFORE the
			// vip() continue so a *_lb entry's drained marker
			// restores too.
			p.loadState(wdir, b.Name, st)
		}
		if b.vip() {
			vips = append(vips, b)
			continue
		}
		v := p.probeOne(ctx, b, st, wdir, svnameByAddr)
		if v.stale {
			stale[b.Name] = true
		}
		if v.fresh {
			fresh++
		}
	}
	return fresh, stale, statusByName, vips, false
}

// probeOne runs one backend's probe round: TCP preflight, the
// cache+live RV pair, the fail-class verdict and the streak
// bookkeeping. The recovery tail may re-enable a drained/maint
// backend through the HAProxy socket — the only action this phase
// takes; drains belong to drainStale.
func (p *Prober) probeOne(ctx context.Context, b backend,
	st *backendState, wdir string,
	svnameByAddr map[string]string) probeVerdict {

	log := logger()
	var v probeVerdict

	// TCP preflight: unreachable → HAProxy tcp-check owns the
	// verdict; we neither count it fresh nor stale.
	if err := p.tcpPreflight(ctx, b.Addr); err != nil {
		log.Info("probe: unreachable — skip (haproxy health-check owns it)",
			"backend", b.Name, "addr", b.Addr, "error", err)
		p.probeFailures.WithLabelValues(b.Name, "tcp").Inc()
		return v
	}

	rvCache, fcC, errC := p.listRV(ctx, b.Addr, p.cfg.CachePath)
	rvNow, fcN, errN := p.listRV(ctx, b.Addr, p.cfg.LivePath)
	okC, okN := fcC == failNone, fcN == failNone
	if !okC || !okN {
		// Split the verdict: a probe-side fault (credential
		// unreadable/rejected, TLS trust, request build) carries
		// ZERO evidence about the apiserver, so a cycle whose
		// failures are ALL probe-side is inconclusive — counts
		// neither fresh nor stale. But EITHER query failing on
		// an apiserver-side class (timeout, refused, dropped,
		// bad status, unreadable/unparseable response) feeds
		// the DEAD counter even when the other query succeeded:
		// a watch-cache read that still answers while the
		// consistent read stalls IS the wedge signature — the
		// cache serves stale hits over a dead storage path.
		apiserverSide := (!okC && !fcC.probeSide()) ||
			(!okN && !fcN.probeSide())
		if !apiserverSide {
			// Inconclusive — same treatment as TCP-unreachable:
			// counts neither fresh nor stale, never qfails
			// toward DEAD, never latches the stale file
			// (incident: a stale guard token 401ing for ~12h
			// masqueraded as a dead apiserver while HAProxy and
			// kubectl saw the backend healthy).
			key := string(fcC) + "|" + string(fcN)
			if st.probeErr != key {
				st.probeErr = key
				log.Warn("PROBE-ERR: backend queries failing probe-side — credential/TLS fault, verdict withheld (NOT apiserver evidence)",
					"backend", b.Name, "addr", b.Addr,
					"cacheErr", failDetail(fcC, errC),
					"liveErr", failDetail(fcN, errN),
					"tokenFile", p.eff.tokenFile,
					"caFile", p.eff.caFile)
			}
			p.probeFailures.WithLabelValues(b.Name, "probe_error").Inc()
			return v
		}
		if st.probeErr != "" {
			st.probeErr = ""
			log.Info("probe: probe-side errors cleared — failures are apiserver-side now",
				"backend", b.Name, "addr", b.Addr)
		}
		// TCP alive but queries fail = apiserver stall/wedge —
		// worse than DOWN (L7 /readyz may still pass while
		// storage is wedged, incident 2026-10-07).
		st.qfail++
		// Streaks must not span an outage: the gap counter and
		// the frozen baseline belong to the pre-outage episode —
		// carried across, a gap streak would merge two separate
		// incidents and the stale prevCache is no comparable.
		st.frozen = 0
		st.fail = 0
		st.ok = 0
		st.hasPrev = false
		p.probeFailures.WithLabelValues(b.Name, "query").Inc()
		if st.qfail >= p.eff.failCycles {
			v.stale = true
			log.Info("DEAD: API queries failing — apiserver stall/wedge, drain from VIP",
				"backend", b.Name, "addr", b.Addr,
				"cacheOK", okC, "liveOK", okN,
				"cacheErr", failDetail(fcC, errC),
				"liveErr", failDetail(fcN, errN),
				"qfail", st.qfail)
		} else {
			log.Info("probe: query failed — not draining yet",
				"backend", b.Name,
				"cacheOK", okC, "liveOK", okN,
				"cacheErr", failDetail(fcC, errC),
				"liveErr", failDetail(fcN, errN),
				"qfail", st.qfail,
				"failCycles", p.eff.failCycles)
		}
		return v
	}
	if st.probeErr != "" {
		st.probeErr = ""
		log.Info("probe: probe-side errors cleared — backend queries healthy again",
			"backend", b.Name, "addr", b.Addr)
	}
	st.qfail = 0
	gap := rvNow - rvCache
	p.rvGap.WithLabelValues(b.Name).Set(float64(gap))
	if wdir != "" {
		p.writeGapFile(wdir, b, gap)
	}

	// Frozen signal: rv_cache bit-identical while rv_now advances
	// → watch-cache stopped updating (early wedge signature).
	// rv_cache advancing (cache alive) or rv_now <= rv_cache
	// (cluster idle) resets the counter.
	if st.hasPrev && rvCache == st.prevCache && rvNow > rvCache {
		st.frozen++
	} else {
		st.frozen = 0
	}
	st.prevCache = rvCache
	st.hasPrev = true

	// Gap signal: rv_now - rv_cache > GapMin accumulates.
	if gap > p.eff.gapMin {
		st.fail++
	} else {
		st.fail = 0
	}

	switch {
	case st.frozen >= p.eff.frozen || st.fail >= p.eff.failCycles:
		v.stale = true
		st.ok = 0
		if st.frozen >= p.eff.frozen {
			log.Info("FROZEN: rv_cache unchanged while rv_now advances — watch-cache wedge",
				"backend", b.Name, "rvCache", rvCache, "rvNow", rvNow,
				"frozen", st.frozen)
		} else {
			log.Info("STALE: backend serving old watch-cache",
				"backend", b.Name, "gap", gap, "fail", st.fail)
		}
	case gap > p.eff.gapMin:
		st.ok = 0
		log.Info("probe: gap above threshold — not draining yet",
			"backend", b.Name, "gap", gap, "fail", st.fail,
			"failCycles", p.eff.failCycles)
	case st.frozen > 0:
		st.ok = 0
		log.Info("probe: rv_cache frozen while rv_now advances — accumulating",
			"backend", b.Name, "rvCache", rvCache, "rvNow", rvNow,
			"frozen", st.frozen, "frozenCycles", p.eff.frozen)
	default:
		// st.ok is a RECOVERY counter — it only runs while a
		// verdict still has something to prove: a backend we
		// drained (or the admin disabled — maint is reconciled
		// the same way) earns re-enable after RecoverCycles
		// consecutive fresh probes, and a backend still
		// carrying the stale latch (FENCE kept it enabled, or
		// dry-run never drained it) earns the state_exit the
		// same way. A healthy backend with nothing to recover
		// holds ok=0 — saveState's zero-means-absent rule then
		// leaves no apibe-ok file to rewrite every cycle.
		latched := wdir != "" && p.staleLatched(wdir, b)
		if st.drained || b.maint() || latched {
			st.ok++
		} else {
			st.ok = 0
		}
		if latched && st.ok >= p.eff.recoverC {
			// state_exit parity: the shell needed RECOVER_CYCLES
			// consecutive fully-fresh runs before clearing the
			// latch — one lucky probe must not unblock
			// 06-kubelet-watch-wedge's upstream gate. The
			// inconclusive paths above (TCP-unreachable,
			// under-threshold qfail/frozen/gap) keep whatever
			// latch exists.
			p.clearStale(wdir, b)
		}
		if st.drained || b.maint() {
			// Re-enable only after RecoverCycles consecutive
			// fresh cycles (drained by us, or admin-disabled
			// externally — reconciled the same way).
			if st.ok >= p.eff.recoverC {
				if p.eff.mode == ModeEnforce {
					svname, inPrimary := actionTarget(b, svnameByAddr)
					if err := p.haproxyServer(ctx, "enable",
						svname, !inPrimary); err != nil {
						log.Error("enable via HAProxy socket failed",
							"backend", b.Name, "server", svname, "error", err)
					} else {
						st.drained = false
						st.ok = 0
						p.actions.WithLabelValues(b.Name, "enable").Inc()
						if b.up() {
							v.fresh = true
						}
						log.Info("ACTION: enabled backend — fresh again",
							"backend", b.Name, "haproxyBackend", p.eff.backend,
							"ok", p.eff.recoverC, "gap", gap)
					}
				} else {
					log.Info("DRY-RUN: would enable backend",
						"backend", b.Name, "ok", st.ok, "gap", gap)
					p.actions.WithLabelValues(b.Name, "dryrun_enable").Inc()
				}
			}
		} else if b.up() {
			v.fresh = true
		}
	}
	return v
}
