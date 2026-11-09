// backend_probe.go — the live-vs-cached resourceVersion probe
// machinery of apiserver-endpoint-guard: raw HTTPS to
// https://<ip>:6443 with the pod's SA credentials (bypasses the
// 10.96.0.1 Service path on purpose: probing "the cluster IP" would
// only measure whichever backend iptables picked), the shared
// keep-alive transport/client, and the consecutive-cycle wedge
// streaks each backend accumulates.
package apiserverendpointguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/go-logr/logr"
	"k8s.io/client-go/rest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
)

// endpointGuardProbeBudget is the per-backend probe budget under
// parallel probing — the probe issues up to three sequential
// requests (live_rv, cache_rv, jwks) each bounded by the shared
// client's endpointGuardProbeTO, so one hung backend can never
// outlive the runCtx it used to share with healthy siblings.
const endpointGuardProbeBudget = 3 * endpointGuardProbeTO

// apiProbeResult is one backend probe outcome: the quorum (etcd) list
// RV, the watch-cache list RV, the sorted JWKS kid set, or the
// transport/HTTP error.
type apiProbeResult struct {
	liveRV   int64
	cacheRV  int64
	jwksKIDs string // sorted,space-joined keys[].kid; "" when unfetchable
	err      error
}

// backendProbeState carries the consecutive-cycle streaks a single
// backend must accumulate before the guard acts — wedges are never a
// one-sample verdict (same convention as kubeletReaperProbes).
type backendProbeState struct {
	ip            string // the backend this streak state belongs to
	gapStreak     int    // consecutive cycles with live_rv-cache_rv >= threshold
	frozenStreak  int    // consecutive cycles cache_rv flat while live_rv grew
	okStreak      int    // consecutive healthy cycles (recovery latch)
	errStreak     int    // consecutive probe transport/5xx failures
	kidSkewStreak int    // consecutive cycles jwksKIDs != healthy majority
	lastLiveRV    int64
	lastCacheRV   int64
	lastKIDs      string // last fetched JWKS kid set ("" = unfetchable)
	haveLast      bool
}

// probe measures live_rv and cache_rv of one apiserver backend.
// live_rv uses a consistent (quorum) list; cache_rv uses
// resourceVersion=0 which the apiserver answers from its watch cache —
// the gap between them IS the wedge signal.
func (g *apiServerEndpointGuard) probe(ctx context.Context, ip string) apiProbeResult {
	client, err := g.probeClient()
	if err != nil {
		return apiProbeResult{err: err}
	}
	liveRV, err := fetchListRV(ctx, client, ip,
		"/api/v1/namespaces/default/services?limit=1")
	if err != nil {
		return apiProbeResult{err: fmt.Errorf("live rv: %w", err)}
	}
	cacheRV, err := fetchListRV(ctx, client, ip,
		"/api/v1/nodes?limit=1&resourceVersion=0")
	if err != nil {
		return apiProbeResult{err: fmt.Errorf("cache rv: %w", err)}
	}
	// jwks-kid-skew: the JWKS kid set is best-effort — a fetch failure
	// yields "" and simply skips that backend in the skew census
	// (inconclusive, never a wedge signal by itself).
	kids, _ := fetchJWKSKIDs(ctx, client, ip)
	return apiProbeResult{liveRV: liveRV, cacheRV: cacheRV, jwksKIDs: kids}
}

// probeClient returns the single probe http.Client (transport() +
// the probe timeout), built once on first use — including when tests
// inject rt directly. Sharing one client (and one drained-body
// policy, see fetchListRV) is what makes keep-alive actually work.
// The mutex covers the whole check-and-build: the backend probes run
// in parallel, so an unguarded first cycle would race every goroutine
// through the InClusterConfig+TransportFor build and keep one client
// plus N leaked transports. A failed build caches nothing, so a later
// probe still retries instead of latching a broken client.
func (g *apiServerEndpointGuard) probeClient() (*http.Client, error) {
	g.clientMu.Lock()
	defer g.clientMu.Unlock()
	if g.client != nil {
		return g.client, nil
	}
	rt, err := g.transport()
	if err != nil {
		return nil, err
	}
	g.client = &http.Client{Transport: rt, Timeout: endpointGuardProbeTO}
	return g.client, nil
}

// transport lazily builds the in-cluster RoundTripper (SA bearer token
// + cluster CA). rest.InClusterConfig fails outside a pod — the error
// surfaces per-probe and fails closed (every backend "wedged" => the
// last-healthy guard blocks all edits), so Setup never aborts boot.
func (g *apiServerEndpointGuard) transport() (http.RoundTripper, error) {
	if g.rt != nil {
		return g.rt, nil
	}
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	// TLS peer verification is impossible by design here: probes hit
	// raw addresses — backend IPs, the LB VIP (103.186.101.x), WAN
	// controllers — that are NOT in the apiserver serving cert's SANs
	// (the cert carries node IPs + 10.96.0.1 + nebula IPs only). The
	// incumbent shell guard used `curl -sk` for the same reason. The
	// probe only needs liveness + resourceVersion, never peer
	// identity; apiserver-side auth is still enforced via the SA
	// bearer token that TransportFor wires in.
	cfg.TLSClientConfig = rest.TLSClientConfig{Insecure: true}
	rt, err := rest.TransportFor(cfg)
	if err != nil {
		return nil, err
	}
	g.rt = rt
	return rt, nil
}

// fetchJSON is the ONE owner of the raw-backend GET skeleton: build
// the request, send it over the shared probe client, drain the body
// before close (an unread body makes the connection unreusable, which
// silently defeated keep-alive on the shared transport — new TCP+TLS
// handshake per probe), treat any non-2xx as a wedge signal, and
// decode the JSON body into out.
func fetchJSON(ctx context.Context, client *http.Client, ip, path, accept string, out any) error {
	url := "https://" + net.JoinHostPort(ip, endpointGuardPort) + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// fetchListRV GETs a core-API list path on one backend and returns the
// list's metadata.resourceVersion. Any non-2xx is a wedge signal.
//
// The Accept header asks for a PartialObjectMetadataList: the probe
// only needs the list RV, and on resourceVersion=0 cache reads the
// apiserver IGNORES limit=1 — without it every probe decoded the FULL
// NodeList (hundreds of KB–MB per backend per cycle) just to reach
// .metadata.resourceVersion. The list-level RV sits in the same place
// on the metadata-only envelope, so the decoder below is unchanged.
func fetchListRV(ctx context.Context, client *http.Client, ip, path string) (int64, error) {
	var body struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
	}
	if err := fetchJSON(ctx, client, ip, path,
		"application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1", &body); err != nil {
		return 0, err
	}
	return strconv.ParseInt(body.Metadata.ResourceVersion, 10, 64)
}

// fetchJWKSKIDs GETs /openid/v1/jwks on one backend and returns its
// keys[].kid set sorted and space-joined — identical sets compare
// equal as strings (jwks-kid-skew sa.pub/sa.key rotation-skew audit).
func fetchJWKSKIDs(ctx context.Context, client *http.Client, ip string) (string, error) {
	var body struct {
		Keys []struct {
			KID string `json:"kid"`
		} `json:"keys"`
	}
	if err := fetchJSON(ctx, client, ip, "/openid/v1/jwks", "", &body); err != nil {
		return "", err
	}
	kids := make([]string, 0, len(body.Keys))
	for _, k := range body.Keys {
		if k.KID != "" {
			kids = append(kids, k.KID)
		}
	}
	slices.Sort(kids)
	return strings.Join(kids, " "), nil
}

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
// endpointGuardErrCycles consecutive failures, the RV-gap and
// frozen-cache streaks, and the ok-streak healthy backends accumulate.
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
		st.gapStreak, st.frozenStreak, st.okStreak = 0, 0, 0
		st.haveLast = false
		log.Error(res.err, "backend probe failed — wedge signal", "ip", st.ip)
		metrics.ObserveAPIBackend(st.ip, -1, quarantined)
		return o
	}
	st.errStreak = 0
	gap := res.liveRV - res.cacheRV
	if gap >= endpointGuardRVGap {
		st.gapStreak++
	} else {
		st.gapStreak = 0
	}
	if st.haveLast && res.cacheRV == st.lastCacheRV && res.liveRV > st.lastLiveRV {
		st.frozenStreak++
	} else if res.cacheRV < res.liveRV {
		// cp-component-restart: the cache still trails the quorum RV — a
		// quiet cycle (cache advanced a little, or nothing
		// changed) must KEEP the frozen streak instead of
		// re-arming it, or a slowly-lagging cache never
		// reaches the wedge threshold.
	} else {
		st.frozenStreak = 0
	}
	st.lastLiveRV, st.lastCacheRV, st.haveLast = res.liveRV, res.cacheRV, true
	st.lastKIDs = res.jwksKIDs
	o.wedged = st.gapStreak >= endpointGuardGapCycles ||
		st.frozenStreak >= endpointGuardFrozenCyc
	o.healthy = gap < endpointGuardRVGap && st.frozenStreak < endpointGuardFrozenCyc
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
// on probe-only clusters they must stay silent.
func (g *apiServerEndpointGuard) decideQuarantine(log logr.Logger,
	results map[string]backendOutcome, activeIPs []string,
	routableIPs, quarantinedIPs map[string]bool) (toRemove, toAdd []string, healthyActive int) {
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
		if results[ip].healthy {
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
	for _, ip := range slices.Sorted(maps.Keys(quarantinedIPs)) {
		if g.backends[ip].okStreak >= endpointGuardRecoverCyc {
			toAdd = append(toAdd, ip)
		} else {
			log.Info("quarantined backend still recovering",
				"ip", ip, "okStreak", g.backends[ip].okStreak, "need", endpointGuardRecoverCyc)
		}
	}
	return toRemove, toAdd, healthyActive
}
