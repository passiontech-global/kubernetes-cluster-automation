// apiserver-endpoint-guard — watch-cache wedge quarantine for the
// default/kubernetes endpoints (no bash ancestor — new module, Phase 2).
//
// Background: kube-aggregator / client-go informers pin to ONE apiserver
// behind the kubernetes Service (10.96.0.1:443). When that apiserver's
// watch cache wedges (upstream k0s/kine incident: cache_rv frozen while
// etcd live_rv keeps advancing), every pod routed to it watches a stale
// world — flux/argocd/cert-manager/external-secrets silently stop
// reacting while the apiserver still passes /healthz and stays in
// default/Endpoints/kubernetes, so nothing fails over.
//
// Every 30s the module reads the backend set from
// default/Endpoints/kubernetes (subsets[].addresses + notReadyAddresses)
// plus the IPs it quarantined earlier (annotation
// node.ops/quarantined-endpoints), then probes EACH backend directly at
// https://<ip>:6443 with the pod's ServiceAccount credentials:
//
//	live_rv  = list RV of GET /api/v1/namespaces/default/services?limit=1
//	           (plan said /leases — the SA has no leases read in ns
//	           default and /api/v1 has no leases resource; any
//	           consistent list returns the same quorum RV, and
//	           services get/list is already in the ClusterRole)
//	cache_rv = list RV of GET /api/v1/nodes?limit=1&resourceVersion=0
//	           (served from the watch cache, not etcd)
//
// A backend is wedged when ANY of:
//   - live_rv - cache_rv >= 200 for 2 consecutive cycles, or
//   - cache_rv unchanged for 3 cycles while live_rv advanced, or
//   - the probe errored (timeout / non-2xx incl. 5xx) this cycle.
//
// When a wedged backend has >= 1 OTHER backend healthy this cycle, its
// IP is pulled out of Endpoints + EndpointSlice and recorded in the
// quarantine annotation — 10.96.0.1 stops routing pods to the wedged
// apiserver. The last healthy endpoint is NEVER removed, and with < 2
// controller IPs total (production/cicd single-controller) the module
// only probes/logs/meters — it never edits the objects.
//
// A quarantined backend that probes healthy for 2 consecutive cycles is
// re-added to both objects and dropped from the annotation.
//
// Coverage caveats: the kube-apiserver endpoint reconciler re-adds
// quarantined IPs every ~10s (the wedged apiserver still renews its
// lease — writes bypass the watch cache), so while the quarantine set
// is non-empty the guard re-applies on a faster cadence (Start, 10s).
// And endpoint removal only affects NEW connections: pods already
// pinned to the wedged apiserver keep their TCP stream until it
// breaks — the real cure stays the sig13 k0scontroller restart; this
// module bridges the gap for new connections.
//
// RBAC (infrastructure/base/node-ops/node-automation-controller/rbac.yaml):
// Role in ns default — get/update/patch on endpoints[kubernetes] and
// endpointslices[kubernetes]; both objects are fetched by fixed name so
// no list/watch is needed and resourceNames scoping suffices.
package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
)

const (
	endpointGuardQueue = "apiserver-endpoint-guard"
	endpointGuardNS    = "default"
	endpointGuardName  = "kubernetes"
	endpointGuardPort  = "6443"
	// endpointGuardAnno records the comma-separated IPs the guard pulled
	// out of default/kubernetes — the wedge evidence survives pod
	// restarts and is human-readable in `kubectl describe ep kubernetes`.
	endpointGuardAnno = "node.ops/quarantined-endpoints"

	endpointGuardInterval           = 30 * time.Second
	endpointGuardQuarantineInterval = 10 * time.Second
	endpointGuardRunTimeout         = 25 * time.Second
	endpointGuardErrCycles          = 2
	endpointGuardProbeTO            = 8 * time.Second // same budget as the kubelet reaper probes
	endpointGuardRVGap              = 200             // live_rv - cache_rv at/above = lagging cache
	endpointGuardGapCycles          = 2               // consecutive gapped cycles before wedge
	endpointGuardFrozenCyc          = 3               // cache_rv frozen cycles (live_rv growing)
	endpointGuardRecoverCyc         = 2               // consecutive healthy cycles to re-add
	// endpointGuardMinBackends: clusters with fewer controller IPs than
	// this get probe+log+metrics only — editing endpoints there can only
	// empty the set (production/cicd run a single controller).
	endpointGuardMinBackends = 2
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

type apiServerEndpointGuard struct {
	cs kubernetes.Interface
	// Probe seam — same convention as kubeletReaper.probeFn /
	// deadNodeSweeper.probeFn: probing a backend's own :6443 is a raw
	// HTTPS call the fake clientset cannot serve, so tests stub the
	// outcome per IP.
	probeFn func(ctx context.Context, ip string) apiProbeResult
	// rt is the cached in-cluster transport (SA token + cluster CA)
	// shared by every backend probe — built lazily so the module still
	// constructs outside a cluster (probes then fail closed: all
	// backends "wedged", the last-healthy guard blocks every edit).
	rt       http.RoundTripper
	backends map[string]*backendProbeState
	log      logr.Logger
	// quarantineActive switches Start to the faster re-apply cadence —
	// set from the annotation each cycle.
	quarantineActive bool
}

// SetupAPIServerEndpointGuard registers the 30s wedge sweep.
func SetupAPIServerEndpointGuard(mgr ctrl.Manager, cs kubernetes.Interface) error {
	g := &apiServerEndpointGuard{cs: cs, backends: map[string]*backendProbeState{}}
	g.probeFn = g.probe
	g.log = mgr.GetLogger().WithName(endpointGuardQueue)
	return mgr.Add(g)
}

// Start implements manager.Runnable — leader-gated like every other
// periodic module (plain Runnables default NeedLeaderElection()=true).
// Adaptive cadence: 30s steady-state, 10s while the quarantine set is
// non-empty (see the coverage-caveats note above: the endpoint
// reconciler re-adds quarantined IPs every ~10s).
func (g *apiServerEndpointGuard) Start(ctx context.Context) error {
	interval := endpointGuardInterval
	for {
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
		// Per-cycle bound: sequential probes + clientset calls must
		// never stall the loop past the interval.
		runCtx, cancel := context.WithTimeout(ctx, endpointGuardRunTimeout)
		err := g.run(runCtx)
		cancel()
		if err != nil {
			metrics.IncError(endpointGuardQueue)
			g.log.Error(err, "sweep failed")
		}
		if g.quarantineActive {
			interval = endpointGuardQuarantineInterval
		} else {
			interval = endpointGuardInterval
		}
	}
}

func (g *apiServerEndpointGuard) run(ctx context.Context) error {
	log := logf.FromContext(ctx)

	ep, err := g.cs.CoreV1().Endpoints(endpointGuardNS).
		Get(ctx, endpointGuardName, metav1.GetOptions{})
	if err != nil {
		return err // periodic loop meters/logs — nothing to act on without it
	}
	// The slice is best-effort: managed by the same endpoints
	// reconciler, but absent on a cluster mid-upgrade it must not
	// veto the Endpoints guard.
	eps, err := g.cs.DiscoveryV1().EndpointSlices(endpointGuardNS).
		Get(ctx, endpointGuardName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			eps = nil
		} else {
			return err
		}
	}

	activeIPs := endpointIPs(ep)
	quarantinedIPs := parseQuarantineAnnotation(ep)
	g.quarantineActive = len(quarantinedIPs) > 0
	allIPs := unionIPs(activeIPs, quarantinedIPs)
	if len(allIPs) == 0 {
		log.Info("sweep done: no controller endpoints")
		return nil
	}

	// Probe every backend (active + quarantined) and fold the outcome
	// into the per-backend streaks.
	type outcome struct {
		wedged  bool
		healthy bool
	}
	results := make(map[string]outcome, len(allIPs))
	for _, ip := range allIPs {
		st := g.backends[ip]
		if st == nil {
			st = &backendProbeState{}
			g.backends[ip] = st
		}
		res := g.probeFn(ctx, ip)

		var o outcome
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

	// Fewer than 2 controller IPs total (single-controller clusters):
	// the probe streaks/metrics above still ran, but edits here can
	// only empty the endpoint set — hard no-op.
	if len(allIPs) < endpointGuardMinBackends {
		log.Info("sweep done: single-controller cluster — probe only, no edits",
			"backends", allIPs)
		return nil
	}

	// ---- Decide removals -------------------------------------------------
	// A wedged active IP may be quarantined only while at least one
	// OTHER active IP is healthy this cycle — processed in sorted order
	// so a multi-wedge cycle can never remove the last healthy backend.
	var toRemove []string
	healthyActive := 0
	for _, ip := range activeIPs {
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

	// ---- Decide re-adds --------------------------------------------------
	var toAdd []string
	for _, ip := range slices.Sorted(maps.Keys(quarantinedIPs)) {
		if g.backends[ip].okStreak >= endpointGuardRecoverCyc {
			toAdd = append(toAdd, ip)
		} else {
			log.Info("quarantined backend still recovering",
				"ip", ip, "okStreak", g.backends[ip].okStreak, "need", endpointGuardRecoverCyc)
		}
	}

	if len(toRemove) == 0 && len(toAdd) == 0 {
		log.Info("sweep done", "backends", len(allIPs), "healthyActive", healthyActive,
			"quarantined", len(quarantinedIPs))
		return nil
	}

	// ---- Mutate both objects, then persist -------------------------------
	// Endpoints first: it carries the quarantine annotation that is the
	// SSOT for "who is pulled". If this update fails nothing was
	// persisted and the next cycle retries the whole decision.
	ep = ep.DeepCopy()
	if ep.Annotations == nil {
		ep.Annotations = map[string]string{}
	}
	for _, ip := range toRemove {
		removeEndpointIP(ep, ip)
		quarantinedIPs[ip] = true
		log.Info("QUARANTINE: wedged apiserver pulled from kubernetes endpoints",
			"ip", ip, "remainingHealthy", healthyActive)
	}
	for _, ip := range toAdd {
		addEndpointIP(ep, ip)
		delete(quarantinedIPs, ip)
		log.Info("RE-ADD: recovered apiserver back in kubernetes endpoints", "ip", ip)
	}
	writeQuarantineAnnotation(ep, quarantinedIPs)
	if _, err := g.cs.CoreV1().Endpoints(endpointGuardNS).
		Update(ctx, ep, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update endpoints/%s: %w", endpointGuardName, err)
	}

	// EndpointSlice converges to the FULL quarantine set (not just
	// this cycle's removals) so a slice update that failed earlier is
	// retried instead of leaving a wedged IP routable forever.
	if eps != nil {
		eps = eps.DeepCopy()
		changedEPS := false
		for ip := range quarantinedIPs {
			if removeSliceIP(eps, ip) {
				changedEPS = true
			}
		}
		for _, ip := range toAdd {
			if addSliceIP(eps, ip) {
				changedEPS = true
			}
		}
		if changedEPS {
			if _, err := g.cs.DiscoveryV1().EndpointSlices(endpointGuardNS).
				Update(ctx, eps, metav1.UpdateOptions{}); err != nil {
				// Logged/metered, not returned: Endpoints already
				// persisted the decision and the next cycle re-applies
				// the slice diff.
				metrics.IncError(endpointGuardQueue)
				log.Error(err, "EndpointSlice update failed — retries next cycle")
			}
		}
	}

	log.Info("sweep done", "removed", toRemove, "readded", toAdd,
		"quarantined", slices.Sorted(maps.Keys(quarantinedIPs)))
	return nil
}

// ---------------------------------------------------------------------------
// Backend probes — raw HTTPS to https://<ip>:6443 with the pod's SA
// credentials (bypasses the 10.96.0.1 Service path on purpose: probing
// "the cluster IP" would only measure whichever backend iptables picked).
// ---------------------------------------------------------------------------

// probe measures live_rv and cache_rv of one apiserver backend.
// live_rv uses a consistent (quorum) list; cache_rv uses
// resourceVersion=0 which the apiserver answers from its watch cache —
// the gap between them IS the wedge signal.
func (g *apiServerEndpointGuard) probe(ctx context.Context, ip string) apiProbeResult {
	rt, err := g.transport()
	if err != nil {
		return apiProbeResult{err: err}
	}
	liveRV, err := fetchListRV(ctx, rt, ip,
		"/api/v1/namespaces/default/services?limit=1")
	if err != nil {
		return apiProbeResult{err: fmt.Errorf("live rv: %w", err)}
	}
	cacheRV, err := fetchListRV(ctx, rt, ip,
		"/api/v1/nodes?limit=1&resourceVersion=0")
	if err != nil {
		return apiProbeResult{err: fmt.Errorf("cache rv: %w", err)}
	}
	return apiProbeResult{liveRV: liveRV, cacheRV: cacheRV}
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
func fetchListRV(ctx context.Context, rt http.RoundTripper, ip, path string) (int64, error) {
	url := "https://" + net.JoinHostPort(ip, endpointGuardPort) + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := (&http.Client{Transport: rt, Timeout: endpointGuardProbeTO}).Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
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
// Endpoint / EndpointSlice mutation helpers.
// ---------------------------------------------------------------------------

// endpointIPs returns the sorted deduped controller IPs currently in
// the Endpoints subsets — notReadyAddresses count too: a not-ready
// backend is still a controller IP (and a wedge suspect).
func endpointIPs(ep *corev1.Endpoints) []string {
	set := map[string]bool{}
	for _, sub := range ep.Subsets {
		for _, a := range sub.Addresses {
			set[a.IP] = true
		}
		for _, a := range sub.NotReadyAddresses {
			set[a.IP] = true
		}
	}
	return slices.Sorted(maps.Keys(set))
}

// parseQuarantineAnnotation reads node.ops/quarantined-endpoints.
func parseQuarantineAnnotation(ep *corev1.Endpoints) map[string]bool {
	set := map[string]bool{}
	for _, ip := range strings.Split(ep.Annotations[endpointGuardAnno], ",") {
		if ip = strings.TrimSpace(ip); ip != "" {
			set[ip] = true
		}
	}
	return set
}

func writeQuarantineAnnotation(ep *corev1.Endpoints, set map[string]bool) {
	if len(set) == 0 {
		delete(ep.Annotations, endpointGuardAnno)
		return
	}
	ep.Annotations[endpointGuardAnno] = strings.Join(slices.Sorted(maps.Keys(set)), ",")
}

func unionIPs(a []string, b map[string]bool) []string {
	set := map[string]bool{}
	for _, ip := range a {
		set[ip] = true
	}
	for ip := range b {
		set[ip] = true
	}
	return slices.Sorted(maps.Keys(set))
}

// removeEndpointIP drops ip from every subset's Addresses AND
// NotReadyAddresses; a subset left with zero addresses is dropped so
// the object never serializes an empty-addresses subset.
func removeEndpointIP(ep *corev1.Endpoints, ip string) {
	subsets := ep.Subsets[:0]
	for _, sub := range ep.Subsets {
		sub.Addresses = dropAddr(sub.Addresses, ip)
		sub.NotReadyAddresses = dropAddr(sub.NotReadyAddresses, ip)
		if len(sub.Addresses) > 0 || len(sub.NotReadyAddresses) > 0 {
			subsets = append(subsets, sub)
		}
	}
	ep.Subsets = subsets
}

func dropAddr(addrs []corev1.EndpointAddress, ip string) []corev1.EndpointAddress {
	out := addrs[:0]
	for _, a := range addrs {
		if a.IP != ip {
			out = append(out, a)
		}
	}
	return out
}

// addEndpointIP appends ip to the subset serving :443 (the kubernetes
// API port — falls back to the first subset, then to a fresh subset so
// a cluster whose object was emptied can still be re-seeded).
func addEndpointIP(ep *corev1.Endpoints, ip string) {
	for _, sub := range ep.Subsets {
		for _, a := range sub.Addresses {
			if a.IP == ip {
				return // already back — reconciler beat us to it
			}
		}
	}
	idx := -1
	for i, sub := range ep.Subsets {
		for _, p := range sub.Ports {
			if p.Port == 6443 || p.Name == "https" {
				idx = i
				break
			}
		}
		if idx >= 0 {
			break
		}
	}
	if idx < 0 && len(ep.Subsets) > 0 {
		idx = 0
	}
	if idx < 0 {
		ep.Subsets = []corev1.EndpointSubset{{
			Addresses: []corev1.EndpointAddress{{IP: ip}},
			Ports: []corev1.EndpointPort{
				{Name: "https", Port: 6443, Protocol: corev1.ProtocolTCP},
			},
		}}
		return
	}
	ep.Subsets[idx].Addresses = append(ep.Subsets[idx].Addresses,
		corev1.EndpointAddress{IP: ip})
}

// removeSliceIP drops ip from every endpoint's addresses in the slice;
// an endpoint left with zero addresses is dropped. Returns whether the
// slice actually changed.
func removeSliceIP(eps *discoveryv1.EndpointSlice, ip string) bool {
	changed := false
	endpoints := eps.Endpoints[:0]
	for _, e := range eps.Endpoints {
		out := e.Addresses[:0]
		for _, a := range e.Addresses {
			if a == ip {
				changed = true
			} else {
				out = append(out, a)
			}
		}
		e.Addresses = out
		if len(e.Addresses) > 0 {
			endpoints = append(endpoints, e)
		}
	}
	eps.Endpoints = endpoints
	return changed
}

// addSliceIP appends a ready endpoint carrying ip unless the slice
// already lists it (the apiserver's own endpoints reconciler may have
// re-added it first — never duplicate).
func addSliceIP(eps *discoveryv1.EndpointSlice, ip string) bool {
	for _, e := range eps.Endpoints {
		if slices.Contains(e.Addresses, ip) {
			return false
		}
	}
	ready := true
	eps.Endpoints = append(eps.Endpoints, discoveryv1.Endpoint{
		Addresses:  []string{ip},
		Conditions: discoveryv1.EndpointConditions{Ready: &ready},
	})
	return true
}
