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
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"slices"
	"strconv"

	"github.com/go-logr/logr"
	"k8s.io/client-go/rest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
)

// apiProbeResult is one backend probe outcome: the quorum (etcd) list
// RV, the watch-cache list RV, or the transport/HTTP error.
type apiProbeResult struct {
	liveRV  int64
	cacheRV int64
	err     error
}

// backendProbeState carries the consecutive-cycle streaks a single
// backend must accumulate before the guard acts — wedges are never a
// one-sample verdict (same convention as kubeletReaperProbes).
type backendProbeState struct {
	gapStreak    int // consecutive cycles with live_rv-cache_rv >= threshold
	frozenStreak int // consecutive cycles cache_rv flat while live_rv grew
	okStreak     int // consecutive healthy cycles (recovery latch)
	errStreak    int // consecutive probe transport/5xx failures
	lastLiveRV   int64
	lastCacheRV  int64
	haveLast     bool
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
	return apiProbeResult{liveRV: liveRV, cacheRV: cacheRV}
}

// probeClient returns the single probe http.Client (transport() +
// the probe timeout), built once on first use — including when tests
// inject rt directly. Sharing one client (and one drained-body
// policy, see fetchListRV) is what makes keep-alive actually work.
func (g *apiServerEndpointGuard) probeClient() (*http.Client, error) {
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
	url := "https://" + net.JoinHostPort(ip, endpointGuardPort) + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept",
		"application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() {
		// Drain before Close — an unread body makes the connection
		// unreusable, which silently defeated keep-alive on the
		// shared transport (new TCP+TLS handshake per probe).
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var body struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return 0, err
	}
	return strconv.ParseInt(body.Metadata.ResourceVersion, 10, 64)
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

// evaluateBackends probes every backend (active + quarantined) and
// folds the outcome into the per-backend streaks, prunes state +
// metric series for IPs that left the controller set, then expires
// quarantined IPs whose backend is never coming back. Returns the
// per-IP verdicts and the expired IPs; quarantinedIPs shrinks in
// place for the expiries.
func (g *apiServerEndpointGuard) evaluateBackends(ctx context.Context,
	allIPs, activeIPs []string, quarantinedIPs map[string]bool) (map[string]backendOutcome, []string) {
	log := logf.FromContext(ctx)
	results := make(map[string]backendOutcome, len(allIPs))
	for _, ip := range allIPs {
		st := g.backends[ip]
		if st == nil {
			st = &backendProbeState{}
			g.backends[ip] = st
		}
		res := g.probeFn(ctx, ip)

		var o backendOutcome
		if res.err != nil {
			// Timeout / non-2xx: wedge signal only after
			// endpointGuardErrCycles consecutive failures — a single
			// WAN/TLS blip must not pull a healthy backend. Streaks
			// reset so a flap doesn't resume mid-count on recovery.
			st.errStreak++
			o.wedged = st.errStreak >= endpointGuardErrCycles
			st.gapStreak, st.frozenStreak, st.okStreak = 0, 0, 0
			st.haveLast = false
			log.Error(res.err, "backend probe failed — wedge signal", "ip", ip)
			metrics.ObserveAPIBackend(ip, -1, quarantinedIPs[ip])
		} else {
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
				// W8-CP1: the cache still trails the quorum RV — a
				// quiet cycle (cache advanced a little, or nothing
				// changed) must KEEP the frozen streak instead of
				// re-arming it, or a slowly-lagging cache never
				// reaches the wedge threshold.
			} else {
				st.frozenStreak = 0
			}
			st.lastLiveRV, st.lastCacheRV, st.haveLast = res.liveRV, res.cacheRV, true
			o.wedged = st.gapStreak >= endpointGuardGapCycles ||
				st.frozenStreak >= endpointGuardFrozenCyc
			o.healthy = gap < endpointGuardRVGap && st.frozenStreak < endpointGuardFrozenCyc
			if o.healthy {
				st.okStreak++
			} else {
				st.okStreak = 0
			}
			metrics.ObserveAPIBackend(ip, float64(gap), quarantinedIPs[ip])
		}
		results[ip] = o
	}

	// Prune state + metric series for IPs that left the controller set.
	for ip := range g.backends {
		if !slices.Contains(allIPs, ip) {
			delete(g.backends, ip)
			metrics.ForgetAPIBackend(ip)
		}
	}

	// ---- Quarantine expiry ------------------------------------------
	// A permanently decommissioned backend never recovers AND the
	// endpoints reconciler stops re-adding it: absent from the current
	// address sets while probe-erring continuously for
	// endpointGuardExpireCyc cycles means it is never coming back, so
	// it drops out of the quarantine set (annotation rewrite below +
	// memQuarantine) instead of pinning a dead IP — and the 10s
	// re-apply cadence — forever. This is decided BEFORE the
	// min-backends gate: the expiry only shrinks the annotation, a
	// write that can never empty the endpoint set, so it stays legal
	// where address edits are banned — and its bookkeeping can never
	// deadlock behind the early return.
	var toExpire []string
	for _, ip := range slices.Sorted(maps.Keys(quarantinedIPs)) {
		if slices.Contains(activeIPs, ip) {
			continue // the reconciler re-added it — still a live backend
		}
		if st := g.backends[ip]; st != nil && st.errStreak >= endpointGuardExpireCyc {
			toExpire = append(toExpire, ip)
		}
	}
	for _, ip := range toExpire {
		delete(quarantinedIPs, ip)
		delete(g.backends, ip)
		metrics.ForgetAPIBackend(ip)
		log.Info("EXPIRE-QUARANTINE: backend absent from endpoints and unreachable — dropping quarantine",
			"ip", ip, "errCycles", endpointGuardExpireCyc)
	}
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
	if len(toRemove) > 0 && g.client != nil {
		// W8-CP1: quarantining the IP only protects NEW dials —
		// pooled keep-alive connections to the wedged backend stay
		// pinned until they break. Drop them so the very next probe
		// (and anything sharing this transport) re-dials onto a
		// healthy backend.
		g.client.CloseIdleConnections()
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
