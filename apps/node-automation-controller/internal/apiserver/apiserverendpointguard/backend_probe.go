// backend_probe.go — the live-vs-cached resourceVersion probe
// machinery of apiserver-endpoint-guard: raw HTTPS to
// https://<ip>:6443 with the pod's SA credentials (bypasses the
// 10.96.0.1 Service path on purpose: probing "the cluster IP" would
// only measure whichever backend iptables picked), the shared
// keep-alive transport/client, and the consecutive-cycle wedge
// streaks each backend accumulates. The per-cycle verdicts that fold
// probe results into those streaks and decide quarantines live in
// backend_verdicts.go.
package apiserverendpointguard

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"k8s.io/client-go/rest"
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
// The pair isolates the watch cache's own lag: live_rv is a
// consistent (quorum) list, cache_rv the same list at
// resourceVersion=0 served from the watch cache. BOTH reads are the
// CLUSTER-WIDE coordination.k8s.io/v1 Lease list: kube-system
// leader-election leases renew every ~10s and control-plane
// component leases every 2-5s, so the cache RV keeps advancing even
// when 100% of workers lose connectivity — the earlier
// kube-node-lease-only pairing froze cache_rv in exactly that
// scenario (worker kubelet lease writes are the ONLY writers there)
// while live_rv kept growing on unrelated writes, tripping a false
// watch-cache-wedged verdict and quarantining healthy backends.
// Unrelated write storms still cannot fake a wedge: a frozen
// cache_rv while live_rv grows remains the signature.
func (g *apiServerEndpointGuard) probe(ctx context.Context, ip string) apiProbeResult {
	client, err := g.probeClient()
	if err != nil {
		return apiProbeResult{err: err}
	}
	liveRV, err := fetchListRV(ctx, client, ip,
		"/apis/coordination.k8s.io/v1/leases?limit=1")
	if err != nil {
		return apiProbeResult{err: fmt.Errorf("live rv: %w", err)}
	}
	// resourceVersion=0 + no limit: the watch cache rejects Limit
	// on RV=0 reads anyway, and the cluster-wide lease set is what
	// keeps cache_rv advancing through a total worker outage.
	cacheRV, err := fetchListRV(ctx, client, ip,
		"/apis/coordination.k8s.io/v1/leases?resourceVersion=0")
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
