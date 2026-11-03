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
package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"regexp"
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

// SetupAPIServerEndpointGuard registers the 30s wedge sweep.
func SetupAPIServerEndpointGuard(mgr ctrl.Manager, cs kubernetes.Interface) error {
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
		if filtered, err := endpointsWarningClient(cfg); err == nil {
			g.cs = filtered
		} else {
			g.log.Error(err, "filtered clientset build failed — sharing the noisy default client")
		}
	}
	return mgr.Add(g)
}

// endpointsWarningClient clones cfg into a clientset whose
// WarningHandler drops only the apiserver's Endpoints deprecation
// header — the guard's corev1 Endpoints reads/writes are intentional.
func endpointsWarningClient(cfg *rest.Config) (kubernetes.Interface, error) {
	cfg = rest.CopyConfig(cfg)
	cfg.WarningHandler = endpointGuardWarnings{delegate: rest.WarningLogger{}}
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
			return err // periodic loop meters/logs — nothing to act on without it
		default:
			ep = e
		}
	}

	useSlice := primary != nil &&
		(ep == nil || (preferSlice && !mirrorManagedSlice(primary)))
	if !useSlice && ep == nil {
		return fmt.Errorf("neither endpoints/%s nor a usable endpointslice exists",
			endpointGuardName)
	}

	var activeIPs []string
	var quarantinedIPs map[string]bool
	if useSlice {
		activeIPs = slicesIPs(epsList)
		quarantinedIPs = parseQuarantineAnnotation(primary)
	} else {
		activeIPs = endpointIPs(ep)
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

// ---------------------------------------------------------------------------
// Endpoint / EndpointSlice resolution — see the header note.
// ---------------------------------------------------------------------------

// kubernetesSlices returns every EndpointSlice serving the kubernetes
// Service, sorted by name so epsList[0] is a stable "primary" for the
// quarantine annotation. The slice's name is fixed ("kubernetes") only
// where the apiserver's own endpoint reconciler writes it; hosted
// control planes carry generated-name mirror slices, so discovery goes
// by the service-name label. Slices mid-deletion are ignored.
func (g *apiServerEndpointGuard) kubernetesSlices(ctx context.Context) ([]*discoveryv1.EndpointSlice, error) {
	l, err := g.cs.DiscoveryV1().EndpointSlices(endpointGuardNS).List(ctx,
		metav1.ListOptions{LabelSelector: endpointSliceServiceSelector})
	if err != nil {
		return nil, err
	}
	out := make([]*discoveryv1.EndpointSlice, 0, len(l.Items))
	for i := range l.Items {
		if l.Items[i].DeletionTimestamp == nil {
			out = append(out, &l.Items[i])
		}
	}
	slices.SortFunc(out, func(a, b *discoveryv1.EndpointSlice) int {
		return strings.Compare(a.Name, b.Name)
	})
	return out, nil
}

// mirrorManagedSlice reports whether the slice is generated by the
// endpointslicemirroring controller — a read-through projection of the
// Endpoints object (label managed-by, plus a controller ownerReference
// onto endpoints/kubernetes as belt&braces). A mirror is never the
// SSOT: its edits are rebuilt from the Endpoints object on the next
// mirror reconcile.
func mirrorManagedSlice(eps *discoveryv1.EndpointSlice) bool {
	if eps.Labels[discoveryv1.LabelManagedBy] == endpointSliceMirrorValue {
		return true
	}
	for _, r := range eps.OwnerReferences {
		if r.Kind == "Endpoints" && r.Controller != nil && *r.Controller {
			return true
		}
	}
	return false
}

func deepCopySlices(list []*discoveryv1.EndpointSlice) []*discoveryv1.EndpointSlice {
	out := make([]*discoveryv1.EndpointSlice, len(list))
	for i, s := range list {
		out[i] = s.DeepCopy()
	}
	return out
}

// slicesIPs unions the backend IPs across every resolved slice —
// dual-stack clusters carry one slice per address family.
func slicesIPs(list []*discoveryv1.EndpointSlice) []string {
	set := map[string]bool{}
	for _, s := range list {
		for _, ip := range sliceIPs(s) {
			set[ip] = true
		}
	}
	return slices.Sorted(maps.Keys(set))
}

// sliceIdxForIP picks the slice whose AddressType matches ip's family
// (re-adds must land in the same-family slice on dual-stack clusters);
// 0 falls back to the primary. -1 on an empty list.
func sliceIdxForIP(list []*discoveryv1.EndpointSlice, ip string) int {
	if len(list) == 0 {
		return -1
	}
	v6 := strings.Contains(ip, ":")
	for i, s := range list {
		if (s.AddressType == discoveryv1.AddressTypeIPv6) == v6 {
			return i
		}
	}
	return 0
}

// ---------------------------------------------------------------------------
// Endpoint API version gate — see the header note.
// ---------------------------------------------------------------------------

// endpointMode reports whether this cluster's SSOT is the EndpointSlice
// (true, >=v1.33) or corev1 Endpoints (false). Detection is cached
// after the first success; a discovery error returns (false, err) and
// retries next cycle — the caller logs it and keeps the Endpoints
// path, which stays valid on every supported version.
func (g *apiServerEndpointGuard) endpointMode() (bool, error) {
	if g.sliceMode != nil {
		return *g.sliceMode, nil
	}
	fn := g.serverMinorFn
	if fn == nil {
		fn = func() (int, error) { return serverMinor(g.cs) }
	}
	minor, err := fn()
	if err != nil {
		return false, err
	}
	use := minor >= endpointSliceSinceMinor
	g.sliceMode = &use
	return use, nil
}

// gitMinorRe extracts "vMAJOR.MINOR" from GitVersion as a last resort
// when Version.Minor is empty or unparseable.
var gitMinorRe = regexp.MustCompile(`^v?\d+\.(\d+)`)

// serverMinor resolves the apiserver's minor version. Minor carries a
// "+" suffix on some distros ("33+" on GKE/EKS) — leading digits win;
// an empty/unparseable Minor falls back to GitVersion.
func serverMinor(cs kubernetes.Interface) (int, error) {
	v, err := cs.Discovery().ServerVersion()
	if err != nil {
		return 0, err
	}
	digits := strings.TrimRightFunc(v.Minor,
		func(r rune) bool { return r < '0' || r > '9' })
	if n, err := strconv.Atoi(digits); err == nil {
		return n, nil
	}
	if m := gitMinorRe.FindStringSubmatch(v.GitVersion); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			return n, nil
		}
	}
	return 0, fmt.Errorf("unparseable server version %+v", v)
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

// parseQuarantineAnnotation reads node.ops/quarantined-endpoints off
// whichever object is the SSOT this cluster (Endpoints <1.33,
// EndpointSlice >=1.33).
func parseQuarantineAnnotation(obj metav1.Object) map[string]bool {
	set := map[string]bool{}
	for _, ip := range strings.Split(obj.GetAnnotations()[endpointGuardAnno], ",") {
		if ip = strings.TrimSpace(ip); ip != "" {
			set[ip] = true
		}
	}
	return set
}

func writeQuarantineAnnotation(obj metav1.Object, set map[string]bool) {
	a := obj.GetAnnotations()
	if len(set) == 0 {
		delete(a, endpointGuardAnno)
		return
	}
	if a == nil {
		a = map[string]string{}
		obj.SetAnnotations(a)
	}
	a[endpointGuardAnno] = strings.Join(slices.Sorted(maps.Keys(set)), ",")
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

// sliceIPs returns the sorted deduped backend IPs across all
// EndpointSlice endpoints — Ready=false/absent entries count too (same
// convention as Endpoints notReadyAddresses: still a controller IP,
// still a wedge suspect).
func sliceIPs(eps *discoveryv1.EndpointSlice) []string {
	set := map[string]bool{}
	for _, e := range eps.Endpoints {
		for _, a := range e.Addresses {
			set[a] = true
		}
	}
	return slices.Sorted(maps.Keys(set))
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
