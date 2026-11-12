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
//	live_rv  = list RV of GET /apis/coordination.k8s.io/v1/namespaces/
//	           kube-node-lease/leases?limit=1 (consistent/quorum read)
//	cache_rv = the SAME LeaseList at resourceVersion=0 (watch cache)
//	           — same-resource RVs; node-lease renewals (~10s/node)
//	           guarantee steady churn a healthy cache must track, so
//	           a cache_rv frozen across cycles while live_rv grows is
//	           the wedge signature (the raw gap is storm noise)
//
// A backend is wedged when ANY of:
//   - cache_rv stays flat for 3 consecutive cycles while live_rv
//     keeps advancing (frozen watch cache — the only rv signal: the
//     instantaneous gap counts unrelated writes and false-positived
//     under storms), or
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
	"math/rand/v2"
	"net/http"
	"runtime/debug"
	"slices"
	"sync"
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
	// endpointGuardFrozenCyc: consecutive cycles the watch-cache RV
	// stays flat while the quorum RV grows — the ONLY rv-based wedge
	// signal. The instantaneous live-cache gap was removed: it counts
	// unrelated cluster writes and false-positived under storms.
	endpointGuardFrozenCyc     = 3 // cache_rv frozen cycles (live_rv growing)
	endpointGuardRecoverCyc    = 2 // consecutive healthy cycles to re-add
	endpointGuardKidSkewCycles = 3 // consecutive JWKS kid-set minority cycles (jwks-kid-skew)
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
	// nodeReader is the manager's informer-cache client for the
	// peer-IP node census (kube.ListNodesCached) — nil in tests
	// falls back to the direct clientset read.
	nodeReader kube.CachedNodeReader
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
	client *http.Client
	// clientMu serializes the lazy rt/client build — evaluateBackends
	// probes every backend in parallel, so the first cycle's
	// client==nil && rt==nil path would otherwise race N goroutines
	// into building duplicate http.Transport TLS pools (and trip the
	// race detector on the g.rt/g.client reads).
	clientMu sync.Mutex
	backends map[string]*backendProbeState
	log      logr.Logger
	// interval/quarantineInterval are the test seam for Start's
	// adaptive cadence — <=0 (production, unset) resolves to the
	// endpointGuardInterval/endpointGuardQuarantineInterval consts;
	// tests inject milliseconds so the cycle test doesn't sleep
	// ~40s.
	interval           time.Duration
	quarantineInterval time.Duration
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
	// peerHighWater is the process-lifetime set of every backend IP
	// that ever validly appeared in default/kubernetes
	// Endpoints/EndpointSlices — unioned into ssotPeerIPs so a
	// hosted control plane or workerless k0s controller (no CP Node
	// objects at all) still has peer evidence to re-add a recovered
	// quarantined backend. Bounded by distinct backend IPs ever
	// seen; run() is the only writer and sweeps serially.
	peerHighWater map[string]bool
}

// Setup registers the 30s wedge sweep. Gated through
// shared.SetupNoConfig like every other module: a disabled module
// registers nothing — no runnable, no periodic probe/GET cycle
// against the control-plane backends.
func Setup(d shared.Deps) error {
	return shared.SetupNoConfig(d, func() error {
		mgr, cs := d.Mgr, d.CS
		g := &apiServerEndpointGuard{cs: cs, dyn: d.Dyn, queue: d.Name, nodeReader: d.Mgr.GetClient(), backends: map[string]*backendProbeState{}}
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
	})
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
	interval := g.sweepInterval()
	// Startup jitter, same contract as shared.Periodic's first-tick
	// offset: the first sweep lands in [0, interval) instead of a
	// fixed interval, so a freshly-elected leader (or a pod restart
	// during an incident) doesn't probe every backend in lockstep.
	first := true
	for {
		wait := interval
		if first {
			wait = rand.N(g.sweepInterval())
			first = false
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
		interval = g.runCycle(ctx, log, interval)
	}
}

// runCycle executes one guarded sweep and returns the cadence the
// Start loop adopts next. It bypasses shared.Periodic (adaptive
// interval), which also bypasses that helper's panic recovery — so
// the recovery lives HERE: a panic in any clientset/dynamic call
// path (or a malformed unstructured Endpoints object slipping past
// the skip-garbage accessors) is contained to this cycle and logged,
// instead of unwinding into controller-runtime and killing the whole
// process. The cadence decision stays inside the guard so a panicking
// sweep cannot lose the fast-quarantine switch.
func (g *apiServerEndpointGuard) runCycle(ctx context.Context,
	log logr.Logger, interval time.Duration) (next time.Duration) {
	defer func() {
		if r := recover(); r != nil {
			metrics.IncError(g.queue)
			log.Error(nil, "endpoint guard sweep panicked — recovered, process continues",
				"panic", r, "stack", string(debug.Stack()))
			next = interval
		}
	}()
	// Per-cycle bound: sequential probes + clientset calls must
	// never stall the loop past the interval.
	runCtx, cancel := context.WithTimeout(ctx, endpointGuardRunTimeout)
	defer cancel()
	if err := g.run(runCtx); err != nil {
		metrics.IncError(g.queue)
		log.Error(err, "sweep failed")
	}
	if g.quarantineActive {
		return g.quarantineCadence()
	}
	return g.sweepInterval()
}

// sweepInterval resolves the steady-state cadence — the injected
// test knob when positive, else the production const.
func (g *apiServerEndpointGuard) sweepInterval() time.Duration {
	if g.interval > 0 {
		return g.interval
	}
	return endpointGuardInterval
}

// quarantineCadence resolves the fast re-apply cadence while the
// quarantine set is non-empty — same <=0 → const contract.
func (g *apiServerEndpointGuard) quarantineCadence() time.Duration {
	if g.quarantineInterval > 0 {
		return g.quarantineInterval
	}
	return endpointGuardQuarantineInterval
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
	// High-water peer evidence: every IP the SSOT currently carries
	// as an ACTIVE backend joins the persistent peer set
	// ssotPeerIPs unions with the CP node InternalIPs. Quarantined
	// IPs are deliberately NOT recorded — the suspect must never
	// vouch for itself (a pulled backend re-adding on its own
	// annotation would bypass SKIP-RE-ADD entirely). This is what
	// lets a hosted/workerless plane re-add a recovered backend it
	// has no Node object to vouch for: the IP was recorded while it
	// was still a valid active member.
	if g.peerHighWater == nil {
		g.peerHighWater = map[string]bool{}
	}
	for _, ip := range activeIPs {
		g.peerHighWater[ip] = true
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

	// Re-add membership verdict inputs (P0-3): reconcilerDriven marks
	// planes where the apiserver's own endpoint reconciler re-lists
	// live backends every ~10s — there activeIPs stays the
	// authoritative membership answer. Hosted planes have no such
	// reconciler (their kubernetes slice is a mirror projection or
	// absent), so a recovered quarantined IP needs independent peer
	// evidence — ssotPeerIPs, the control-plane node InternalIPs —
	// fetched lazily only when a re-add decision is actually pending.
	reconcilerDriven := primary != nil && !mirrorManagedSlice(primary)
	var peerIPs map[string]bool
	if len(quarantinedIPs) > 0 && !reconcilerDriven {
		peerIPs = g.ssotPeerIPs(ctx)
	}

	toRemove, toAdd, healthyActive := g.decideQuarantine(log, results,
		activeIPs, routableIPs, quarantinedIPs, reconcilerDriven, peerIPs)

	// On the Endpoints-SSOT path the sweep also mirrors the decision
	// onto the EndpointSlices below — a slice update that failed last
	// cycle ("retries next cycle") leaves the slice drifted while the
	// Endpoints-derived toAdd/toRemove diff is empty, so "is there
	// work" must be answered by diffing the ACTUAL slice contents
	// against the post-decision quarantine set: a drifted slice is
	// repaired every cycle until it matches, not just on cycles the
	// Endpoints object itself changes.
	qPost := maps.Clone(quarantinedIPs)
	for _, ip := range toRemove {
		qPost[ip] = true
	}
	for _, ip := range toAdd {
		delete(qPost, ip)
	}
	var sliceCopies []*discoveryv1.EndpointSlice
	var sliceDirty []bool
	if !useSlice {
		sliceCopies, sliceDirty = convergeSlices(epsList, qPost, toAdd)
	}

	if len(toRemove) == 0 && len(toAdd) == 0 && len(toExpire) == 0 &&
		!slices.Contains(sliceDirty, true) {
		log.Info("sweep done", "backends", len(allIPs), "healthyActive", healthyActive,
			"quarantined", len(quarantinedIPs))
		return nil
	}

	// ---- Mutate the SSOT object, then persist ------------------------------
	// Whichever object carries the quarantine annotation is the SSOT
	// for "who is pulled"; if its update fails nothing was persisted
	// and the next cycle retries the whole decision. Both appliers
	// (quarantine_apply.go) mutate quarantinedIPs in place as they go.
	if useSlice {
		err = g.applySliceQuarantine(ctx, log, epsList, toRemove, toAdd,
			quarantinedIPs, healthyActive)
	} else {
		err = g.applyEndpointsQuarantine(ctx, log, ep, toRemove, toAdd,
			quarantinedIPs, healthyActive, sliceCopies, sliceDirty)
	}
	if err != nil {
		return err
	}
	g.memQuarantine = maps.Clone(quarantinedIPs)

	log.Info("sweep done", "removed", toRemove, "readded", toAdd,
		"quarantined", slices.Sorted(maps.Keys(quarantinedIPs)))
	return nil
}
