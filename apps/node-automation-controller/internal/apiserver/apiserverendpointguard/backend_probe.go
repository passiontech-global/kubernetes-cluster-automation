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
	"net"
	"net/http"
	"strconv"

	"k8s.io/client-go/rest"
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
		resp.Body.Close()
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
