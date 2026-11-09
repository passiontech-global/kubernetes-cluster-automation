package apiprober

import (
	"context"
	"os"
	"sort"
	"time"
)

// Cycle runs one detection+guard round — the shell script body.
func (p *Prober) Cycle(ctx context.Context) {
	log := logger()
	start := time.Now()
	defer func() { p.duration.Set(time.Since(start).Seconds()) }()

	// Re-read the guard conf every cycle — a conf written or edited
	// by hostconfig mid-run applies NOW, not after a restart.
	p.refreshGuard()
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
				log.Info("HAProxy admin socket absent — backend discovery gated (api-local-lb is worker-only)",
					"socket", p.eff.socket)
				p.socketAbsent = true
			}
			p.cycles.WithLabelValues("no_socket").Inc()
			return
		}
		if p.socketAbsent {
			log.Info("HAProxy admin socket present — resuming backend discovery",
				"socket", p.eff.socket)
			p.socketAbsent = false
		}
	}

	discovered, err := p.discover(ctx)
	if err != nil {
		log.Error("cannot discover backends from HAProxy socket",
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

	fresh := 0                 // direct backends fresh AND usable this cycle (drain fence)
	stale := map[string]bool{} // name → wedged/dead this cycle
	statusByName := make(map[string]backend, len(backends))
	var vips []backend

	for _, b := range backends {
		if ctx.Err() != nil {
			return
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

		// TCP preflight: unreachable → HAProxy tcp-check owns the
		// verdict; we neither count it fresh nor stale.
		if err := p.tcpPreflight(ctx, b.Addr); err != nil {
			log.Info("probe: unreachable — skip (haproxy health-check owns it)",
				"backend", b.Name, "addr", b.Addr, "error", err)
			p.probeFailures.WithLabelValues(b.Name, "tcp").Inc()
			continue
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
				continue
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
				stale[b.Name] = true
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
			continue
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
			stale[b.Name] = true
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
								fresh++
							}
							log.Info("ACTION: enabled backend — fresh again",
								"backend", b.Name, "backend", p.eff.backend,
								"ok", p.eff.recoverC, "gap", gap)
						}
					} else {
						log.Info("DRY-RUN: would enable backend",
							"backend", b.Name, "ok", st.ok, "gap", gap)
						p.actions.WithLabelValues(b.Name, "dryrun_enable").Inc()
					}
				}
			} else if b.up() {
				fresh++
			}
		}
	}

	// Re-apply drains HAProxy forgot — runtime disables are not
	// persistent, so after a HAProxy restart a previously-drained
	// wedged backend shows UP again. This pass covers ALL drained
	// backends, not just ones flagged stale: a probe-side outage
	// keeps a wedged backend out of `stale`, and without it the
	// backend silently rejoins traffic for the whole outage. The
	// stale loop below owns re-apply for its own entries (skip
	// duplicates). Only discovered rows can show UP again — statics
	// are constants with no HAProxy state to forget.
	for _, name := range func() []string {
		ns := make([]string, 0, len(p.states))
		for n := range p.states {
			ns = append(ns, n)
		}
		sort.Strings(ns)
		return ns
	}() {
		st := p.states[name]
		if !st.drained {
			continue
		}
		if _, inStale := stale[name]; inStale {
			continue // the stale loop below re-applies these
		}
		b := statusByName[name]
		if !b.discovered || !b.up() {
			continue
		}
		svname, inPrimary := actionTarget(b, svnameByAddr)
		// W19-PI1: same last-standing fence as the drain phase —
		// when fresh < 1 a HAProxy restart may have resurrected
		// this server as the ONLY usable backend; re-disabling it
		// would take the VIP down with it.
		if fresh < 1 {
			continue
		}
		if p.eff.mode == ModeEnforce {
			if err := p.haproxyServer(ctx, "disable",
				svname, !inPrimary); err != nil {
				log.Error("re-apply disable failed",
					"backend", name, "server", svname, "error", err)
			} else {
				log.Info("ACTION: re-applied disable — HAProxy forgot drained server",
					"backend", name)
				p.actions.WithLabelValues(name, "disable").Inc()
			}
		}
	}

	// Drain phase — after the fresh count for this cycle is final.
	// usableFresh snapshots the pre-drain count: every backend in it
	// stays enabled through the drain (drains only remove stale
	// backends), so it is the RIGHT basis for the VIP bypass decision
	// — unlike the decremented fence budget below.
	usableFresh := fresh
	names := make([]string, 0, len(stale))
	for n := range stale {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		st := p.states[name]
		b := statusByName[name]
		svname, inPrimary := actionTarget(b, svnameByAddr)
		if wdir != "" {
			// Wedged/dead this cycle → state_enter parity (the latch
			// gates 06-kubelet-watch-wedge's k0sworker restart).
			p.latchStale(wdir, b)
		}
		if st.drained {
			// Already drained — but a HAProxy restart forgets runtime
			// disables (socket state is not persistent). Re-apply
			// while HAProxy reports the server usable again; the
			// recovery path above re-enables via the drained flag.
			// Only discovered rows can show UP again — a static-only
			// backend is a constant "UP" with no HAProxy state to
			// forget, so re-applying would just repeat the socket
			// command every cycle.
			// W19-PI1: fence on fresh < 1 — same last-standing
			// protection as the drain phase below.
			if p.eff.mode == ModeEnforce && b.discovered && b.up() &&
				fresh >= 1 {
				if err := p.haproxyServer(ctx, "disable",
					svname, !inPrimary); err != nil {
					log.Error("re-apply disable failed",
						"backend", name, "server", svname, "error", err)
				} else {
					log.Info("ACTION: re-applied disable — HAProxy forgot drained server",
						"backend", name)
					p.actions.WithLabelValues(name, "disable").Inc()
				}
			}
			continue
		}
		// FENCE: never disable the last usable backend. If every other
		// backend is stale/unreachable this cycle, draining more only
		// takes the VIP down with them — keep it, escalate via log.
		if fresh < 1 {
			log.Info("FENCE: backend wedged but no fresh backend remains — not draining, manual action needed",
				"backend", name)
			p.actions.WithLabelValues(name, "fence_skip").Inc()
			continue
		}
		if p.eff.mode == ModeEnforce {
			if err := p.haproxyServer(ctx, "disable",
				svname, !inPrimary); err != nil {
				log.Error("disable via HAProxy socket failed",
					"backend", name, "server", svname, "error", err)
				continue
			}
			st.drained = true
			// Staged drain (shell `fresh=$((fresh - 1))` parity):
			// every successful disable spends one fresh slot, so a
			// run drains at most `fresh` stale backends — the fence
			// above then still has a usable backend to protect.
			fresh--
			p.actions.WithLabelValues(name, "disable").Inc()
			log.Info("ACTION: disabled backend — watch-cache wedge",
				"backend", name, "server", svname,
				"haproxyBackend", p.eff.backend,
				"freshRemaining", fresh)
			if !inPrimary {
				// The name is not a svname of the primary backend
				// (static-only API_BACKENDS entry): the action was
				// issued to every configured backend but only a
				// companion could have carried it — the primary
				// "No such server" was a no-op, not a drain.
				log.Warn("backend is not a server of the primary HAProxy backend — drain reached companion backends only",
					"backend", name, "haproxyBackend", p.eff.backend)
			}
		} else {
			log.Info("DRY-RUN: would disable backend — watch-cache wedge",
				"backend", name, "freshRemaining", fresh)
			p.actions.WithLabelValues(name, "dryrun_disable").Inc()
		}
	}

	// VIP phase (sig14b): *_lb entries round-robin across controllers,
	// so when any direct controller is wedged/drained AND >=1 direct
	// controller is fresh, disable the VIP entry so traffic goes
	// straight to the healthy controller(s). Re-enable when all direct
	// controllers are healthy again, or when fresh == 0 (least-bad).
	staleCtrlCount := 0
	for _, b := range backends {
		if b.vip() {
			continue
		}
		if stale[b.Name] || p.states[b.Name].drained {
			staleCtrlCount++
		}
	}
	wantVIPDisable := staleCtrlCount > 0 && usableFresh > 0
	for _, vip := range vips {
		st := p.states[vip.Name]
		if wantVIPDisable {
			if p.eff.mode == ModeEnforce {
				if !st.drained || vip.up() {
					if err := p.haproxyServer(ctx, "disable",
						vip.Name, false); err != nil {
						log.Error("disable VIP via HAProxy socket failed",
							"backend", vip.Name, "error", err)
						continue
					}
					st.drained = true
					p.actions.WithLabelValues(vip.Name, "disable").Inc()
					log.Info("ACTION: disabled VIP backend — direct controller wedged while fresh controller available",
						"backend", vip.Name, "staleCtrls", staleCtrlCount, "freshCtrls", fresh)
				}
			} else if !st.drained {
				st.drained = true
				log.Info("DRY-RUN: would disable VIP backend — direct controller wedged",
					"backend", vip.Name, "staleCtrls", staleCtrlCount, "freshCtrls", fresh)
				p.actions.WithLabelValues(vip.Name, "dryrun_disable").Inc()
			}
		} else if st.drained || vip.maint() {
			if p.eff.mode == ModeEnforce {
				if err := p.haproxyServer(ctx, "enable",
					vip.Name, false); err != nil {
					log.Error("enable VIP via HAProxy socket failed",
						"backend", vip.Name, "error", err)
					continue
				}
				st.drained = false
				p.actions.WithLabelValues(vip.Name, "enable").Inc()
				log.Info("ACTION: enabled VIP backend",
					"backend", vip.Name, "staleCtrls", staleCtrlCount, "freshCtrls", fresh)
			} else {
				st.drained = false
				log.Info("DRY-RUN: would enable VIP backend",
					"backend", vip.Name, "staleCtrls", staleCtrlCount, "freshCtrls", fresh)
				p.actions.WithLabelValues(vip.Name, "dryrun_enable").Inc()
			}
		}
	}

	// Export per-backend enabled state after all transitions.
	for _, b := range backends {
		v := 0.0
		if b.up() && !p.states[b.Name].drained {
			v = 1
		}
		p.enabled.WithLabelValues(b.Name).Set(v)
	}

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
