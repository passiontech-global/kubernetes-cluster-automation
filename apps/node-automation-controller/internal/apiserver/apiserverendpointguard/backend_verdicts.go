// backend_verdicts.go — the per-cycle verdicts of
// apiserver-endpoint-guard: folding each backend's probe result into
// its wedge streaks, the JWKS census, quarantine expiry and the
// quarantine/recover decisions run() persists (split out of
// backend_probe.go — see its header for the probe machinery and the
// transport these verdicts score).
package apiserverendpointguard

import (
	"context"
	"errors"
	"maps"
	"slices"
	"sync"

	"github.com/go-logr/logr"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
)

// ---------------------------------------------------------------------------
// Per-cycle verdicts — fold each backend's probe result into the
// streaks above, then turn the streaks into this cycle's
// quarantine/recover decisions (run() persists them).
// ---------------------------------------------------------------------------

// backendOutcome is one backend's verdict this cycle: wedged marks a
// quarantine candidate, healthy lets it vouch as a peer for the
// last-healthy guard in decideQuarantine.
type backendOutcome struct {
	wedged  bool
	healthy bool
}

// foldStreaks folds one backend's probe result into its streak state
// and returns this cycle's verdict — wedge signals only after
// endpointGuardErrCycles consecutive failures and the frozen-cache
// streak, and the ok-streak healthy backends accumulate.
// A run budget that expired mid-probe defers the verdict without
// touching the streaks (a starved or cancelled request is not
// evidence the backend is wedged). All state passed in — no globals,
// no receiver.
func foldStreaks(log logr.Logger, st *backendProbeState, res apiProbeResult,
	runCtx context.Context, quarantined bool) backendOutcome {
	var o backendOutcome
	if res.err != nil && runCtx.Err() != nil {
		// The run's own budget expired mid-probe — a starved or
		// cancelled request is not evidence the backend is
		// wedged: no errStreak bump, streaks untouched, verdict
		// deferred to the next cycle.
		log.Info("backend probe cut short by the run budget — verdict deferred", "ip", st.ip)
		return o
	}
	if res.err != nil {
		// Timeout / non-2xx: wedge signal only after
		// endpointGuardErrCycles consecutive failures — a single
		// WAN/TLS blip must not pull a healthy backend. Streaks
		// reset so a flap doesn't resume mid-count on recovery.
		st.errStreak++
		o.wedged = st.errStreak >= endpointGuardErrCycles
		st.frozenStreak, st.okStreak = 0, 0
		st.haveLast = false
		log.Error(res.err, "backend probe failed — wedge signal", "ip", st.ip)
		metrics.ObserveAPIBackend(st.ip, -1, quarantined)
		return o
	}
	st.errStreak = 0
	gap := res.liveRV - res.cacheRV
	// Frozen-cache wedge — the ONLY rv-based signal. cache_rv is the
	// watch cache's synced RV for the SAME LeaseList the quorum read
	// hit, and node-lease renewals (~10s/node) guarantee it advances
	// every sweep on a healthy backend: cache_rv flat across
	// consecutive cycles while live_rv keeps growing is the wedge
	// signature. The instantaneous gap is NOT a signal — it counts
	// every unrelated cluster write since the last lease renewal, so
	// it false-positived under ordinary write storms (P0-3).
	if st.haveLast && res.cacheRV == st.lastCacheRV && res.liveRV > st.lastLiveRV {
		st.frozenStreak++
	} else if res.cacheRV == st.lastCacheRV && res.liveRV > res.cacheRV {
		// cp-component-restart: the cache still trails the quorum RV — a
		// quiet cycle (cache advanced a little, or nothing
		// changed) must KEEP the frozen streak instead of
		// re-arming it, or a slowly-lagging cache never
		// reaches the wedge threshold. A cacheRV that ADVANCED
		// (res.cacheRV != st.lastCacheRV) is a fresh watch revision,
		// not a frozen cache — reset regardless of the liveRV gap.
	} else {
		st.frozenStreak = 0
	}
	st.lastLiveRV, st.lastCacheRV, st.haveLast = res.liveRV, res.cacheRV, true
	st.lastKIDs = res.jwksKIDs
	o.wedged = st.frozenStreak >= endpointGuardFrozenCyc
	o.healthy = st.frozenStreak < endpointGuardFrozenCyc
	if o.healthy {
		st.okStreak++
	} else {
		st.okStreak = 0
	}
	metrics.ObserveAPIBackend(st.ip, float64(gap), quarantined)
	return o
}

// jwksCensus runs the jwks-kid-skew JWKS kid-set skew census: majority vote
// across backends that returned a kid set — the most common set wins,
// a dissenting backend accumulates kidSkewStreak and >=3 cycles means
// its sa.pub/sa.key pair is out of rotation step (random 401s through
// the LB pool). Empty sets (unfetchable JWKS) neither vote nor accuse.
func jwksCensus(log logr.Logger, allIPs []string, backends map[string]*backendProbeState) {
	kidVotes := map[string]int{}
	for _, ip := range allIPs {
		if st := backends[ip]; st != nil && st.lastKIDs != "" {
			kidVotes[st.lastKIDs]++
		}
	}
	majorityKIDs, majorityN := "", 0
	for k, n := range kidVotes {
		if n > majorityN || (n == majorityN && k < majorityKIDs) {
			majorityKIDs, majorityN = k, n
		}
	}
	for _, ip := range allIPs {
		st := backends[ip]
		if st == nil {
			continue
		}
		// Skew needs >=2 voters (a one-backend cluster can't
		// disagree) and a dissenting non-empty set.
		skew := len(kidVotes) > 0 && majorityN >= 2 &&
			st.lastKIDs != "" && st.lastKIDs != majorityKIDs
		if skew {
			st.kidSkewStreak++
		} else {
			st.kidSkewStreak = 0
		}
		flagged := st.kidSkewStreak >= endpointGuardKidSkewCycles
		metrics.ObserveAPIBackendJWKSSkew(ip, flagged)
		if flagged {
			log.Error(errors.New("JWKS kid set skew"), "backend serves a different ServiceAccount signer kid set than the control-plane majority — random 401s through the LB pool (sa.pub/sa.key rotation skew)",
				"ip", ip, "cycles", st.kidSkewStreak)
		}
	}
}

// expireQuarantine drops quarantined IPs whose backend is never coming
// back: absent from the current address sets while probe-erring
// continuously for endpointGuardExpireCyc cycles means the backend is
// permanently decommissioned — the endpoints reconciler stopped
// re-adding it — so it leaves the quarantine set (annotation rewrite
// + memQuarantine, done by the caller) instead of pinning a dead IP —
// and the 10s re-apply cadence — forever. Mutates quarantinedIPs and
// backends in place; returns the expired IPs.
func expireQuarantine(log logr.Logger, backends map[string]*backendProbeState,
	activeIPs []string, quarantinedIPs map[string]bool) []string {
	var toExpire []string
	for _, ip := range slices.Sorted(maps.Keys(quarantinedIPs)) {
		if slices.Contains(activeIPs, ip) {
			continue // the reconciler re-added it — still a live backend
		}
		if st := backends[ip]; st != nil && st.errStreak >= endpointGuardExpireCyc {
			toExpire = append(toExpire, ip)
		}
	}
	for _, ip := range toExpire {
		delete(quarantinedIPs, ip)
		delete(backends, ip)
		metrics.ForgetAPIBackend(ip)
		log.Info("EXPIRE-QUARANTINE: backend absent from endpoints and unreachable — dropping quarantine",
			"ip", ip, "errCycles", endpointGuardExpireCyc)
	}
	return toExpire
}

// evaluateBackends probes every backend (active + quarantined) and
// folds the outcome into the per-backend streaks (foldStreaks), prunes
// streak state for IPs that left the controller set, runs the
// JWKS skew census (jwksCensus), then expires quarantined IPs whose
// backend is never coming back (expireQuarantine). Returns the per-IP
// verdicts and the expired IPs; quarantinedIPs shrinks in place for
// the expiries.
func (g *apiServerEndpointGuard) evaluateBackends(ctx context.Context,
	allIPs, activeIPs []string, quarantinedIPs map[string]bool) (map[string]backendOutcome, []string) {
	log := logf.FromContext(ctx)
	results := make(map[string]backendOutcome, len(allIPs))

	// Probe every backend in parallel, each against its OWN budget:
	// sequential probing let one slow/dead backend eat the whole 25s
	// runCtx, starving the healthy backends queued behind it — their
	// starved requests then read as transport failures and inflated
	// THEIR errStreaks toward a false wedge verdict. The streak fold
	// below stays sequential and deterministic in allIPs order.
	probed := make([]apiProbeResult, len(allIPs))
	var wg sync.WaitGroup
	for i, ip := range allIPs {
		wg.Add(1)
		go func(i int, ip string) {
			defer wg.Done()
			probeCtx, cancel := context.WithTimeout(ctx, endpointGuardProbeBudget)
			defer cancel()
			probed[i] = g.probeFn(probeCtx, ip)
		}(i, ip)
	}
	wg.Wait()

	for i, ip := range allIPs {
		st := g.backends[ip]
		if st == nil {
			st = &backendProbeState{ip: ip}
			g.backends[ip] = st
		}
		results[ip] = foldStreaks(log, st, probed[i], ctx, quarantinedIPs[ip])
	}

	// ---- JWKS kid-set skew census (jwks-kid-skew) -------------------------
	jwksCensus(log, allIPs, g.backends)

	// Prune streak STATE for IPs that left the controller set — the
	// verdict-facing hygiene: a removed backend's wedge streaks must
	// not resurface as stale evidence on re-add. The per-IP METRIC
	// series deliberately stay: absence from one cycle's address
	// snapshot is not proof of decommissioning — the endpoints
	// reconciler rebuilds default/kubernetes every ~10s and drops a
	// backend exactly when its lease lapses (the dead/wedged
	// signature this guard exists to catch), so forgetting the series
	// here would churn the ops evidence in and out mid-incident.
	// Series retirement happens in expireQuarantine only, the path
	// with actual decommission evidence (absence + endpointGuardExpireCyc
	// probe-error cycles).
	for ip := range g.backends {
		if !slices.Contains(allIPs, ip) {
			delete(g.backends, ip)
		}
	}

	// ---- Quarantine expiry ------------------------------------------
	// Decided BEFORE the min-backends gate: the expiry only shrinks
	// the annotation, a write that can never empty the endpoint set,
	// so it stays legal where address edits are banned — and its
	// bookkeeping can never deadlock behind the early return.
	toExpire := expireQuarantine(log, g.backends, activeIPs, quarantinedIPs)
	if len(toExpire) > 0 {
		g.memQuarantine = maps.Clone(quarantinedIPs)
		g.quarantineActive = len(quarantinedIPs) > 0
	}
	return results, toExpire
}

// decideQuarantine turns the per-backend verdicts into this cycle's
// removal/re-add lists. It runs only after run()'s min-backends gate:
// the SKIP/recovering logs below exist to explain edit decisions, so
// on probe-only clusters they must stay silent. reconcilerDriven tells
// whether the apiserver's own endpoint reconciler owns the SSOT
// objects (self-hosted planes — it re-lists live backends every ~10s);
// peerIPs is the independently discovered control-plane peer set used
// only when no such reconciler exists (hosted planes — P0-3).
func (g *apiServerEndpointGuard) decideQuarantine(log logr.Logger,
	results map[string]backendOutcome, activeIPs []string,
	routableIPs, quarantinedIPs map[string]bool,
	reconcilerDriven bool, peerIPs map[string]bool) (toRemove, toAdd []string, healthyActive int) {
	// ---- Decide removals -------------------------------------------------
	// A wedged active IP may be quarantined only while at least one
	// OTHER ROUTABLE IP is healthy this cycle — processed in sorted
	// order so a multi-wedge cycle can never remove the last healthy
	// backend. "Routable" excludes notReadyAddresses / Ready=false
	// slice endpoints: kube-proxy never routes to them, so a notReady
	// backend that happens to probe fine must not vouch for pulling
	// the last Ready endpoint — that would flap kubernetes.default to
	// zero routable addresses (notReady suspects are still probed and
	// quarantined above; only the healthy-peer accounting changes).
	for ip := range routableIPs {
		// An IP already under quarantine must not count as a healthy
		// active backend — the apiserver may transiently re-list it
		// (okStreak 1 < 2) but the reconcile pass pulls it right
		// back out, so vouching with it could quarantine the last
		// genuinely healthy backend.
		if results[ip].healthy && !quarantinedIPs[ip] {
			healthyActive++
		}
	}
	for _, ip := range activeIPs { // activeIPs is sorted
		if !results[ip].wedged {
			continue
		}
		if healthyActive < 1 {
			log.Info("SKIP-QUARANTINE: no healthy backend would remain — fail closed",
				"ip", ip)
			continue
		}
		toRemove = append(toRemove, ip)
		// A routable IP that was counted healthy but is now being
		// pulled must not keep vouching for later removals in the
		// same sweep.
		if results[ip].healthy && !quarantinedIPs[ip] {
			healthyActive--
		}
	}
	if len(toRemove) > 0 {
		// cp-component-restart: quarantining the IP only protects NEW dials —
		// pooled keep-alive connections to the wedged backend stay
		// pinned until they break. Drop them so the very next probe
		// (and anything sharing this transport) re-dials onto a
		// healthy backend. The mutex read keeps the field access
		// paired with probeClient's writes.
		g.clientMu.Lock()
		client := g.client
		g.clientMu.Unlock()
		if client != nil {
			client.CloseIdleConnections()
		}
	}

	// ---- Decide re-adds --------------------------------------------------
	// okStreak proves the HOST answers :6443, not that the backend is
	// still a member of default/kubernetes: a decommissioned backend
	// whose node keeps serving TLS passes every probe (okStreak climbs
	// forever, errStreak stays 0) — re-adding on streak alone made the
	// guard re-write the IP every cycle against whatever authority
	// dropped it, and kube-proxy flapped kubernetes.default. The
	// membership verdict therefore depends on who owns the objects:
	//
	//   - reconcilerDriven (self-hosted): the apiserver's endpoint
	//     reconciler re-lists live backends every ~10s, so activeIPs
	//     IS the authoritative membership answer — an absent IP is
	//     being deliberately dropped and stays quarantined (it leaves
	//     via expireQuarantine's decommission evidence instead).
	//   - hosted planes: NO reconciler exists — nothing re-lists a
	//     pulled IP, so activeIPs can never contain it again and the
	//     old check deadlocked every recovered backend out of the set
	//     forever (P0-3 SKIP-RE-ADD). Membership is instead proven
	//     against ssotPeerIPs, the control-plane node InternalIPs
	//     discovered independently of the mutated objects; a nil
	//     peer set (discovery failed) keeps the strict rule.
	for _, ip := range slices.Sorted(maps.Keys(quarantinedIPs)) {
		if g.backends[ip].okStreak < endpointGuardRecoverCyc {
			log.Info("quarantined backend still recovering",
				"ip", ip, "okStreak", g.backends[ip].okStreak, "need", endpointGuardRecoverCyc)
			continue
		}
		listed := slices.Contains(activeIPs, ip)
		peer := !reconcilerDriven && peerIPs[ip]
		if !listed && !peer {
			log.Info("SKIP-RE-ADD: recovered backend not vouched by endpoints or peer discovery — not re-added",
				"ip", ip, "okStreak", g.backends[ip].okStreak,
				"reconcilerDriven", reconcilerDriven)
			continue
		}
		toAdd = append(toAdd, ip)
	}
	return toRemove, toAdd, healthyActive
}
