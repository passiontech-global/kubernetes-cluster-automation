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
//   - the probe errored (timeout / non-2xx incl. 5xx) for 2
//     consecutive cycles.
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
// Endpoint API version gate: core/v1 Endpoints is deprecated since
// v1.33 — the apiserver returns a Warning header ("v1 Endpoints is
// deprecated in v1.33+; use discovery.k8s.io/v1 EndpointSlice") on
// every get/update. The guard detects the server minor once at first
// sweep: <1.33 (or undetectable — Endpoints works on every supported
// version) keeps the Endpoints SSOT plus the best-effort slice
// mirror; >=1.33 promotes the EndpointSlice to the SSOT — backend
// set, quarantine annotation and all edits land on the slice and
// corev1 Endpoints is never touched.
//
// The slice's NAME is not fixed though: "kubernetes" exists only where
// the apiserver's own endpoint reconciler writes the slice (self-hosted
// control planes). Hosted/worker-plane clusters (k0smotron children —
// our cicd/nonprod/production) carry a generated-name slice
// (kubernetes-xxxxx) written by the endpointslicemirroring controller
// as a read-through projection of Endpoints/kubernetes. Discovery is
// therefore by the kubernetes.io/service-name=kubernetes label, and a
// mirror-managed slice is never the SSOT — edits to it are reverted on
// the next mirror reconcile, so on hosted planes Endpoints stays the
// SSOT regardless of the version gate.
//
// RBAC (infrastructure/base/node-ops/node-automation-controller/rbac.yaml):
// Role in ns default — get/update/patch on endpoints[kubernetes], and
// get/list + update/patch on endpointslices WITHOUT resourceNames
// scoping: list cannot be name-scoped and the generated slice name is
// unknowable ahead of time. The version probe hits /version — a
// non-resource URL open to every authenticated client.
package apiserverendpointguard

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
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
	// endpointGuardExpireCyc: consecutive probe-error cycles after
	// which a quarantined IP that is ALSO absent from the current
	// address sets is declared decommissioned and dropped from
	// quarantine — ~5m at the 10s quarantine cadence. Without the
	// expiry a dead IP pins quarantineActive (and the fast cadence)
	// forever.
	endpointGuardExpireCyc = 30
	// endpointGuardMinBackends: clusters with fewer controller IPs than
	// this get probe+log+metrics only — editing endpoints there can only
	// empty the set (production/cicd run a single controller).
	endpointGuardMinBackends = 2
	// endpointSliceSinceMinor: first Kubernetes minor where core/v1
	// Endpoints is deprecated — the guard moves its SSOT to the
	// EndpointSlice on >= this version.
	endpointSliceSinceMinor = 33
	// endpointSliceServiceSelector discovers the kubernetes Service's
	// slices by label — the fixed "kubernetes" name only exists where
	// the apiserver's own reconciler writes the slice; hosted control
	// planes carry generated-name (kubernetes-xxxxx) mirror slices.
	endpointSliceServiceSelector = discoveryv1.LabelServiceName + "=" + endpointGuardName
	// endpointSliceMirrorValue is the managed-by label value marking a
	// slice as a read-through projection of the Endpoints object — see
	// the SSOT note in run().
	endpointSliceMirrorValue = "endpointslicemirroring-controller.k8s.io"
)

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
	rt http.RoundTripper
	// client wraps rt with the probe timeout — built once on first
	// probe so every backend share one keep-alive pool. A fresh
	// http.Client per request would still reuse rt's pool, but the
	// old code also never drained resp.Body, which killed keep-alive
	// outright; the shared client + drain keeps conns reusable.
	client   *http.Client
	backends map[string]*backendProbeState
	log      logr.Logger
	// quarantineActive switches Start to the faster re-apply cadence —
	// set from the annotation each cycle.
	quarantineActive bool
	// serverMinorFn resolves the apiserver's minor version for the
	// endpoint-API gate — test seam (fake Discovery cannot make
	// ServerVersion fail). nil → serverMinor(g.cs).
	serverMinorFn func() (int, error)
	// sliceMode caches the detected endpoint API choice: nil =
	// undetected, true = EndpointSlice SSOT (>=v1.33), false = corev1
	// Endpoints. Cached after the first successful detection only, so
	// a discovery flap retries next cycle.
	sliceMode *bool
	// memQuarantine mirrors the persisted quarantine set in memory:
	// if the endpoints reconciler ever rebuilds the object wholesale
	// and drops our annotation mid-incident, the guard keeps tracking
	// (and re-pulling) the wedged IP instead of stranding it outside
	// the set with no evidence left.
	memQuarantine map[string]bool
}

// Setup registers the 30s wedge sweep.
func Setup(d shared.Deps) error {
	mgr, cs := d.Mgr, d.CS
	g := &apiServerEndpointGuard{cs: cs, backends: map[string]*backendProbeState{}}
	g.probeFn = g.probe
	g.log = mgr.GetLogger().WithName(endpointGuardQueue)
	// Dedicated clientset filtering the "v1 Endpoints is deprecated"
	// 299 warning: on hosted planes the guard writes the deprecated
	// object deliberately every sweep (it is the SSOT behind the
	// mirror slice), which the shared client's default WarningLogger
	// would turn into one klog line per cycle. Every other warning
	// still delegates. Fall back to the shared client when the
	// filtered one cannot be built — nil config on test doubles or a
	// construction failure — the guard works either way, just noisier.
	if cfg := mgr.GetConfig(); cfg != nil {
		if filtered, err := endpointsWarningClient(cfg, cs); err == nil {
			g.cs = filtered
		} else {
			g.log.Error(err, "filtered clientset build failed — sharing the noisy default client")
		}
	}
	return mgr.Add(g)
}

// NewWarningHandler returns the WarningHandler that drops
// only the apiserver's "v1 Endpoints is deprecated" header — exported
// so main can attach it to the shared rest.Config before the first
// clientset is built. The guard then recognizes its own filter on the
// manager config and reuses that clientset instead of paying for a
// second http.Transport and TLS connection pool.
func NewWarningHandler() rest.WarningHandler {
	return endpointGuardWarnings{delegate: rest.WarningLogger{}}
}

// endpointsWarningClient returns a clientset whose WarningHandler
// drops only the apiserver's Endpoints deprecation header — the
// guard's corev1 Endpoints reads/writes are intentional. When cfg
// already carries the guard's filter (main wires it onto the shared
// config before building cs), the incoming clientset is reused:
// cloning cfg into a second clientset would duplicate the
// http.Transport and its connection pool for zero behavioral gain.
func endpointsWarningClient(cfg *rest.Config, cs kubernetes.Interface) (kubernetes.Interface, error) {
	if cs != nil {
		if _, ok := cfg.WarningHandler.(endpointGuardWarnings); ok {
			return cs, nil
		}
	}
	cfg = rest.CopyConfig(cfg)
	cfg.WarningHandler = NewWarningHandler()
	return kubernetes.NewForConfig(cfg)
}

// endpointGuardWarnings suppresses exactly one warning: "v1 Endpoints
// is deprecated" (the deprecated object is written by design wherever
// the kubernetes slice is a mirror projection). Everything else still
// reaches the default WarningLogger.
type endpointGuardWarnings struct {
	delegate rest.WarningHandlerWithContext
}

func (w endpointGuardWarnings) HandleWarningHeader(code int, agent, message string) {
	w.HandleWarningHeaderWithContext(context.Background(), code, agent, message)
}

func (w endpointGuardWarnings) HandleWarningHeaderWithContext(ctx context.Context, code int, agent, message string) {
	if code == 299 && strings.Contains(message, "v1 Endpoints is deprecated") {
		return
	}
	w.delegate.HandleWarningHeaderWithContext(ctx, code, agent, message)
}

var _ rest.WarningHandlerWithContext = endpointGuardWarnings{}

// Start implements manager.Runnable — leader-gated like every other
// periodic module (plain Runnables default NeedLeaderElection()=true).
// Adaptive cadence: 30s steady-state, 10s while the quarantine set is
// non-empty (see the coverage-caveats note above: the endpoint
// reconciler re-adds quarantined IPs every ~10s).
func (g *apiServerEndpointGuard) Start(ctx context.Context) error {
	// Inject the named logger into the ctx run() sees: this runnable
	// bypasses shared.Periodic (it needs the adaptive interval), so
	// without this run()'s logf.FromContext would resolve the UNNAMED
	// root logger and every sweep line would lack
	// "logger":"apiserver-endpoint-guard". A guard built by hand may
	// leave g.log zero-value — fall back to naming the ctx logger
	// rather than silently discarding.
	log := g.log
	if log.GetSink() == nil {
		log = logf.FromContext(ctx).WithName(endpointGuardQueue)
	}
	ctx = logf.IntoContext(ctx, log)
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
			log.Error(err, "sweep failed")
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

	preferSlice, verr := g.endpointMode()
	if verr != nil {
		log.Error(verr, "k8s version undetectable — defaulting to corev1 Endpoints")
	}

	// Resolve the kubernetes endpoints objects. Two layouts exist:
	//   self-hosted — the apiserver's own endpoint reconciler writes
	//     BOTH endpoints/kubernetes AND a fixed-name
	//     endpointslice/kubernetes from the same lease set.
	//   hosted/worker plane — endpoints/kubernetes is seeded by the
	//     platform; the ONLY slice is a generated-name mirror of it
	//     owned by the endpointslicemirroring controller, so the slice
	//     must be discovered by the service-name label and the
	//     Endpoints object stays the SSOT on every version (edits to a
	//     mirror slice are reverted on the next mirror reconcile).
	epsList, err := g.kubernetesSlices(ctx)
	if err != nil {
		return fmt.Errorf("list endpointslices for %s/%s: %w",
			endpointGuardNS, endpointGuardName, err)
	}
	var primary *discoveryv1.EndpointSlice
	if len(epsList) > 0 {
		primary = epsList[0]
	}

	// Endpoints is fetched only when it can actually be the SSOT — on a
	// >=1.33 self-managed cluster (non-mirrored slice) the deprecated
	// object is never touched at all.
	var ep *corev1.Endpoints
	if primary == nil || mirrorManagedSlice(primary) || !preferSlice {
		e, err := g.cs.CoreV1().Endpoints(endpointGuardNS).
			Get(ctx, endpointGuardName, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
		case err != nil:
			// periodic loop meters/logs — nothing to act on without it
			return fmt.Errorf("get endpoints %s/%s: %w",
				endpointGuardNS, endpointGuardName, err)
		default:
			ep = e
		}
	}

	// Mirror slices are never the write SSOT while Endpoints exists
	// (the mirroring controller reverts edits), but when Endpoints
	// is GONE the mirror is the only readable source of backend IPs
	// — probing must keep working even though the quarantine edit it
	// may land is futile (reverted next reconcile). Erroring out
	// here instead would blind the probe entirely for as long as
	// the Endpoints object stays absent, which is strictly worse.
	useSlice := primary != nil &&
		(ep == nil || (preferSlice && !mirrorManagedSlice(primary)))
	if !useSlice && ep == nil {
		return fmt.Errorf("neither endpoints/%s nor a usable endpointslice exists",
			endpointGuardName)
	}

	var activeIPs []string
	var routableIPs map[string]bool
	var quarantinedIPs map[string]bool
	if useSlice {
		activeIPs = slicesIPs(epsList)
		routableIPs = routableSliceIPs(epsList)
		quarantinedIPs = parseQuarantineAnnotation(primary)
	} else {
		activeIPs = endpointIPs(ep)
		routableIPs = routableEndpointIPs(ep)
		quarantinedIPs = parseQuarantineAnnotation(ep)
	}
	// The endpoints reconciler may rebuild the SSOT object wholesale
	// and drop our annotation — the in-memory copy keeps a quarantined
	// backend tracked until it recovers or this pod restarts (the
	// reconciler re-adds pulled IPs every ~10s anyway, so nothing
	// stays quarantined by accident).
	for ip := range g.memQuarantine {
		quarantinedIPs[ip] = true
	}
	g.memQuarantine = maps.Clone(quarantinedIPs)
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

	// Fewer than 2 controller IPs total (single-controller clusters):
	// the probe streaks/metrics above still ran, but edits here can
	// only empty the endpoint set — hard no-op, EXCEPT the annotation
	// shrink a quarantine expiry asks for.
	if len(allIPs) < endpointGuardMinBackends && len(toExpire) == 0 {
		log.Info("sweep done: single-controller cluster — probe only, no edits",
			"backends", allIPs)
		return nil
	}

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
	var toRemove []string
	healthyActive := 0
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
	var toAdd []string
	for _, ip := range slices.Sorted(maps.Keys(quarantinedIPs)) {
		if g.backends[ip].okStreak >= endpointGuardRecoverCyc {
			toAdd = append(toAdd, ip)
		} else {
			log.Info("quarantined backend still recovering",
				"ip", ip, "okStreak", g.backends[ip].okStreak, "need", endpointGuardRecoverCyc)
		}
	}

	if len(toRemove) == 0 && len(toAdd) == 0 && len(toExpire) == 0 {
		log.Info("sweep done", "backends", len(allIPs), "healthyActive", healthyActive,
			"quarantined", len(quarantinedIPs))
		return nil
	}

	// ---- Mutate the SSOT object, then persist ------------------------------
	// Whichever object carries the quarantine annotation is the SSOT
	// for "who is pulled"; if its update fails nothing was persisted
	// and the next cycle retries the whole decision.
	if useSlice {
		copies := deepCopySlices(epsList)
		dirty := make([]bool, len(copies))
		for _, ip := range toRemove {
			quarantinedIPs[ip] = true
			log.Info("QUARANTINE: wedged apiserver pulled from kubernetes EndpointSlice",
				"ip", ip, "remainingHealthy", healthyActive)
			for i := range copies {
				if removeSliceIP(copies[i], ip) {
					dirty[i] = true
				}
			}
		}
		for _, ip := range toAdd {
			if i := sliceIdxForIP(copies, ip); i >= 0 && addSliceIP(copies[i], ip) {
				dirty[i] = true
			}
			delete(quarantinedIPs, ip)
			log.Info("RE-ADD: recovered apiserver back in kubernetes EndpointSlice", "ip", ip)
		}
		// The primary always carries the annotation — persist it even
		// when its endpoint set itself was unchanged this cycle.
		writeQuarantineAnnotation(copies[0], quarantinedIPs)
		for i, s := range copies {
			if i > 0 && !dirty[i] {
				continue
			}
			if _, err := g.cs.DiscoveryV1().EndpointSlices(endpointGuardNS).
				Update(ctx, s, metav1.UpdateOptions{}); err != nil {
				return fmt.Errorf("update endpointslice/%s: %w", s.Name, err)
			}
		}
	} else {
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

		// EndpointSlices converge to the FULL quarantine set (not just
		// this cycle's removals) so a slice update that failed earlier
		// is retried instead of leaving a wedged IP routable forever.
		// On hosted planes the mirror controller propagates the
		// Endpoints write itself within ~1s — this write just wins the
		// race when propagation lags.
		copies := deepCopySlices(epsList)
		dirty := make([]bool, len(copies))
		for i := range copies {
			for ip := range quarantinedIPs {
				if removeSliceIP(copies[i], ip) {
					dirty[i] = true
				}
			}
		}
		for _, ip := range toAdd {
			if i := sliceIdxForIP(copies, ip); i >= 0 && addSliceIP(copies[i], ip) {
				dirty[i] = true
			}
		}
		for i, s := range copies {
			if !dirty[i] {
				continue
			}
			if _, err := g.cs.DiscoveryV1().EndpointSlices(endpointGuardNS).
				Update(ctx, s, metav1.UpdateOptions{}); err != nil {
				// Logged/metered, not returned: Endpoints already
				// persisted the decision and the next cycle re-applies
				// the slice diff.
				metrics.IncError(endpointGuardQueue)
				log.Error(err, "EndpointSlice update failed — retries next cycle",
					"slice", s.Name)
			}
		}
	}
	g.memQuarantine = maps.Clone(quarantinedIPs)

	log.Info("sweep done", "removed", toRemove, "readded", toAdd,
		"quarantined", slices.Sorted(maps.Keys(quarantinedIPs)))
	return nil
}
