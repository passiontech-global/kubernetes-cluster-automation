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
// passiontech.dev/quarantined-endpoints), then probes EACH backend directly at
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
	"time"

	"github.com/go-logr/logr"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

const (
	endpointGuardNS   = "default"
	endpointGuardName = "kubernetes"
	endpointGuardPort = "6443"
	// endpointGuardAnno records the comma-separated IPs the guard pulled
	// out of default/kubernetes — the wedge evidence survives pod
	// restarts and is human-readable in `kubectl describe ep kubernetes`.
	endpointGuardAnno = kube.AnnoQuarantinedEndpoints

	endpointGuardInterval           = 30 * time.Second
	endpointGuardQuarantineInterval = 10 * time.Second
	endpointGuardRunTimeout         = 25 * time.Second
	endpointGuardErrCycles          = 2
	endpointGuardProbeTO            = 8 * time.Second // same budget as the kubelet reaper probes
	endpointGuardRVGap              = 200             // live_rv - cache_rv at/above = lagging cache
	endpointGuardGapCycles          = 2               // consecutive gapped cycles before wedge
	endpointGuardFrozenCyc          = 3               // cache_rv frozen cycles (live_rv growing)
	endpointGuardRecoverCyc         = 2               // consecutive healthy cycles to re-add
	endpointGuardKidSkewCycles      = 3               // consecutive JWKS kid-set minority cycles (W12-CP4b)
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

// endpointsGVR is the dynamic-client handle for the deprecated core/v1
// Endpoints object. The guard reaches it through unstructured maps so
// the deprecated type is never named in code — the object stays the
// write SSOT on hosted planes where the kubernetes slice is a mirror
// projection, but no source file has to reference corev1.Endpoints.
var endpointsGVR = schema.GroupVersionResource{Version: "v1", Resource: "endpoints"}

type apiServerEndpointGuard struct {
	cs kubernetes.Interface
	// dyn is the dynamic client — used ONLY for the deprecated
	// core/v1 Endpoints object (unstructured, so the deprecated type
	// is never named); slices/discovery stay on the typed clientset.
	dyn dynamic.Interface
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the named logger and every IncError label
	// come from one place.
	queue string
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
	g := &apiServerEndpointGuard{cs: cs, dyn: d.Dyn, queue: d.Name, backends: map[string]*backendProbeState{}}
	g.probeFn = g.probe
	g.log = mgr.GetLogger().WithName(g.queue)
	// Dedicated dynamic client filtering the "v1 Endpoints is
	// deprecated" 299 warning: on hosted planes the guard writes the
	// deprecated object deliberately every sweep (it is the SSOT
	// behind the mirror slice), which the shared client's default
	// WarningLogger would turn into one klog line per cycle. Every
	// other warning still delegates. Fall back to the shared dynamic
	// client when the filtered one cannot be built — nil config on
	// test doubles or a construction failure — the guard works either
	// way, just noisier.
	if cfg := mgr.GetConfig(); cfg != nil {
		if filtered, err := endpointsWarningClient(cfg, d.Dyn); err == nil {
			g.dyn = filtered
		} else {
			g.log.Error(err, "filtered dynamic client build failed — sharing the noisy default client")
		}
	}
	return mgr.Add(g)
}

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
		log = logf.FromContext(ctx).WithName(g.queue)
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
			metrics.IncError(g.queue)
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
	var ep *unstructured.Unstructured
	if primary == nil || mirrorManagedSlice(primary) || !preferSlice {
		e, getErr := g.dyn.Resource(endpointsGVR).Namespace(endpointGuardNS).
			Get(ctx, endpointGuardName, metav1.GetOptions{})
		gone, err := kube.ConfirmAbsent(getErr)
		if err != nil {
			// periodic loop meters/logs — nothing to act on without it
			return fmt.Errorf("get endpoints %s/%s: %w",
				endpointGuardNS, endpointGuardName, err)
		}
		if !gone {
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

	results, toExpire := g.evaluateBackends(ctx, allIPs, activeIPs, quarantinedIPs)

	// Fewer than 2 controller IPs total (single-controller clusters):
	// the probe streaks/metrics above still ran, but edits here can
	// only empty the endpoint set — hard no-op, EXCEPT the annotation
	// shrink a quarantine expiry asks for.
	if len(allIPs) < endpointGuardMinBackends && len(toExpire) == 0 {
		log.Info("sweep done: single-controller cluster — probe only, no edits",
			"backends", allIPs)
		return nil
	}

	toRemove, toAdd, healthyActive := g.decideQuarantine(log, results,
		activeIPs, routableIPs, quarantinedIPs)

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
		if _, err := g.dyn.Resource(endpointsGVR).Namespace(endpointGuardNS).
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
				metrics.IncError(g.queue)
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
