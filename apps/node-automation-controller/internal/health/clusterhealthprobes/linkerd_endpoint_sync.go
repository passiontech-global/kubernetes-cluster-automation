// linkerd_endpoint_sync.go — the linkerd-endpoint-sync check
// (W9-NM2/W10-FIX7): audits headless Services in linkerd-injected
// namespaces for EndpointSlice desync, deletes provably-stale
// controller-owned slices, and bounces the oldest
// linkerd-destination pod past the persistence window.
package clusterhealthprobes

import (
	"context"
	"fmt"
	"maps"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

// linkerdEndpointSyncCheck is the W9-NM2 linkerd endpoint-sync
// watchdog — a headless Service whose EndpointSlice diverges from
// its Ready pod IPs, healed by bouncing linkerd-destination.
type linkerdEndpointSyncCheck struct {
	*deps

	// W9-NM2 watchdog state (under mu):
	//   - linkerdDesyncSince: "ns/svc" → first sweep the headless
	//     Service's EndpointSlice diverged from its Ready pod IPs;
	//     pruned when the divergence resolves so a later desync
	//     re-arms the window.
	//   - linkerdDesyncEmitted: gauge tuples held at 1 — a tuple not
	//     re-seen gets DeleteLabelValues, not a stale 1.
	//   - linkerdDesyncHealed: "ns/svc" → last linkerd-destination
	//     bounce — the 1h per-service cooldown (in-RAM: the pod is
	//     the heal target, nothing else can carry the stamp).
	linkerdDesyncSince   map[string]time.Time
	linkerdDesyncEmitted map[string]bool
	linkerdDesyncHealed  map[string]time.Time
}

// newLinkerdEndpointSyncCheck builds the W9-NM2 check with fresh
// tracking maps — the state-map initialization that used to live in
// the monolithic newClusterHealthProber literal.
func newLinkerdEndpointSyncCheck(d *deps) checkRunner {
	return &linkerdEndpointSyncCheck{deps: d,
		linkerdDesyncSince:   map[string]time.Time{},
		linkerdDesyncEmitted: map[string]bool{},
		linkerdDesyncHealed:  map[string]time.Time{},
	}
}

const (
	// W9-NM2 — linkerd-endpoint-sync knobs.
	checkNameLinkerdEndpointSync = "linkerd-endpoint-sync"
	linkerdEndpointDesyncMinAge  = 10 * time.Minute
	linkerdDestHealCooldown      = time.Hour
	linkerdInjectLabel           = "linkerd.io/inject"
	// linkerdSliceHealMinAge is the fuse on the missing-IP half of
	// the W10-FIX7 stale-slice delete: a Ready pod IP must have been
	// Ready this long before its absence from the service's managed
	// EndpointSlices counts as staleness — younger pods may simply
	// not have been reconciled into the slices yet.
	linkerdSliceHealMinAge = 3 * time.Minute
	// linkerdSliceManagedByESC marks EndpointSlices owned by
	// kube-controller-manager's endpointslice-controller — the only
	// slices the desync heal deletes, since that controller is what
	// recreates them with corrected contents.
	linkerdSliceManagedByESC = "endpointslice-controller.k8s.io"
)

// ---------------------------------------------------------------------------
// W9-NM2 — linkerd-endpoint-sync
// ---------------------------------------------------------------------------

// linkerdEndpointSetsDiverge reports whether a headless Service's
// EndpointSlice view diverged from its pods: a Ready pod IP missing
// from the Ready endpoint addresses (linkerd-destination never learns
// the endpoint exists), or a Ready endpoint address no live selected
// pod owns anymore (a deleted pod's stale IP keeps receiving traffic).
// readyIPs/liveIPs nil-safe: an empty pod set can still flag stale
// endpoint addresses.
func linkerdEndpointSetsDiverge(readyIPs, liveIPs, esReady map[string]bool) bool {
	for ip := range readyIPs {
		if !esReady[ip] {
			return true
		}
	}
	for ip := range esReady {
		if !liveIPs[ip] {
			return true
		}
	}
	return false
}

// linkerdSliceRef is one endpointslice-controller-owned EndpointSlice
// of an audited headless Service — a delete candidate when it
// provably holds stale endpoint data (W10-FIX7). addrs is the set of
// Ready endpoint addresses (nil Ready counts as ready, same
// convention as the aggregate census).
type linkerdSliceRef struct {
	ns, name string
	uid      types.UID
	addrs    map[string]bool
}

// podReadySince returns the pod's PodReady=True LastTransitionTime —
// the clock for the EndpointSlice heal's missing-IP fuse. ok=false
// when the pod is not Ready (mirrors shared.PodReadyCond, which
// returns on the first PodReady-typed condition).
func podReadySince(pod *corev1.Pod) (since time.Time, ok bool) {
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady {
			if c.Status != corev1.ConditionTrue {
				return time.Time{}, false
			}
			return c.LastTransitionTime.Time, true
		}
	}
	return time.Time{}, false
}

// staleLinkerdSlices picks the controller-owned EndpointSlices of a
// desynced headless Service that provably hold stale endpoint data
// (W10-FIX7):
//
//   - a slice retaining a Ready address no live selected pod owns
//     (a deleted pod's IP still receiving traffic) is stale on its
//     own — only that slice is returned;
//   - a Ready pod IP past linkerdSliceHealMinAge absent from the
//     UNION of all the service's managed slices means the slice SET
//     is incomplete — no single member is identifiable as the stale
//     one, so every managed slice is returned: deleting them forces
//     endpointslice-controller to rebuild the whole set.
//
// readyAged is the service's pod-IP set filtered to pods Ready past
// the fuse; liveIPs is every live selected pod IP. Both nil-safe.
func staleLinkerdSlices(slices []linkerdSliceRef,
	readyAged, liveIPs map[string]bool) []linkerdSliceRef {
	if len(slices) == 0 {
		return nil
	}
	union := map[string]bool{}
	var stale []linkerdSliceRef
	for _, sl := range slices {
		dead := false
		for a := range sl.addrs {
			union[a] = true
			if !liveIPs[a] {
				dead = true
			}
		}
		if dead {
			stale = append(stale, sl)
		}
	}
	for ip := range readyAged {
		if !union[ip] {
			return slices
		}
	}
	return stale
}

// checkLinkerdEndpointSync audits headless Services (spec.clusterIP
// "None" with a non-empty selector) in namespaces opted into linkerd
// injection: linkerd-destination builds its endpoint table from
// EndpointSlices, so a slice that misses a Ready pod IP — or keeps a
// deleted pod's address — silently blackholes or misroutes traffic
// for exactly the workloads headless services exist for (per-pod DNS,
// StatefulSet members). A divergence must persist
// linkerdEndpointDesyncMinAge before the gauge fires; past the window
// the oldest linkerd-destination pod is bounced (1h per-service
// cooldown, maintenance-gated, UID-preconditioned) to force a full
// resync — the same re-roll shape as the W8-NM3 wedged-pod heal.
// W10-FIX7 adds the other half of the heal: the bounce only re-reads
// EndpointSlices, so when the slices themselves are provably stale
// (a Ready address no live pod owns, or a >3m-Ready pod IP absent
// from the whole endpointslice-controller-owned set) the heal first
// deletes those slices — KCM's endpointslice-controller recreates
// them from current pod state and the bounce then resyncs from
// corrected data. Only managed-by=endpointslice-controller.k8s.io
// slices are delete candidates: mirror/third-party slices are not
// ours to reap.
func (p *linkerdEndpointSyncCheck) run(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	now := p.now()
	p.mu.Lock()
	if p.linkerdDesyncSince == nil {
		p.linkerdDesyncSince = map[string]time.Time{}
	}
	if p.linkerdDesyncEmitted == nil {
		p.linkerdDesyncEmitted = map[string]bool{}
	}
	if p.linkerdDesyncHealed == nil {
		p.linkerdDesyncHealed = map[string]time.Time{}
	}
	p.mu.Unlock()

	// Namespaces opted into injection — the only places a desynced
	// EndpointSlice actually strands mesh traffic.
	nsList, err := p.cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list namespaces: %w", err)}
	}
	injected := map[string]bool{}
	for i := range nsList.Items {
		if nsList.Items[i].Labels[linkerdInjectLabel] == "enabled" {
			injected[nsList.Items[i].Name] = true
		}
	}

	desynced := map[string]bool{} // "ns/name" diverged this sweep
	// staleSlices: "ns/svc" → the provably-stale managed EndpointSlices
	// to delete if the service's desync survives the window (W10-FIX7).
	staleSlices := map[string][]linkerdSliceRef{}
	if len(injected) > 0 {
		svcList, err := p.cs.CoreV1().Services(metav1.NamespaceAll).
			List(ctx, metav1.ListOptions{})
		if err != nil {
			return probeResult{infra: fmt.Errorf("list services: %w", err)}
		}
		podList, err := p.cs.CoreV1().Pods(metav1.NamespaceAll).
			List(ctx, metav1.ListOptions{})
		if err != nil {
			return probeResult{infra: fmt.Errorf("list pods: %w", err)}
		}
		// Audited services — headless + selector + injected ns, the
		// same filter the per-service loop applies. Only their
		// controller-owned slices are delete candidates (W10-FIX7).
		audited := map[string]bool{}
		for i := range svcList.Items {
			svc := &svcList.Items[i]
			if injected[svc.Namespace] &&
				svc.Spec.ClusterIP == corev1.ClusterIPNone &&
				len(svc.Spec.Selector) > 0 {
				audited[svc.Namespace+"/"+svc.Name] = true
			}
		}
		// Ready endpoint addresses per ns/service — same source and
		// nil-ready-counts-as-ready convention as the masterless
		// census. Paged like every cluster-wide read in this package.
		esReady := map[string]map[string]bool{}
		// managedSlices: "ns/svc" → the service's
		// endpointslice-controller-owned EndpointSlices with their
		// Ready address sets — the W10-FIX7 delete candidates.
		managedSlices := map[string][]linkerdSliceRef{}
		err = shared.ListEach(ctx,
			metav1.ListOptions{Limit: healthListPageSize},
			shared.EndpointSlices(p.cs, metav1.NamespaceAll),
			func(items []discoveryv1.EndpointSlice) error {
				for _, s := range items {
					svc := s.Labels[discoveryv1.LabelServiceName]
					if svc == "" {
						continue
					}
					key := s.Namespace + "/" + svc
					managed := audited[key] &&
						s.Labels[discoveryv1.LabelManagedBy] == linkerdSliceManagedByESC &&
						s.DeletionTimestamp == nil
					var sliceAddrs map[string]bool
					if managed {
						sliceAddrs = map[string]bool{}
					}
					set := esReady[key]
					if set == nil {
						set = map[string]bool{}
						esReady[key] = set
					}
					for _, ep := range s.Endpoints {
						if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
							continue
						}
						for _, a := range ep.Addresses {
							set[a] = true
							if managed {
								sliceAddrs[a] = true
							}
						}
					}
					if managed {
						managedSlices[key] = append(managedSlices[key],
							linkerdSliceRef{ns: s.Namespace, name: s.Name,
								uid: s.UID, addrs: sliceAddrs})
					}
				}
				return nil
			})
		if err != nil {
			return probeResult{infra: fmt.Errorf("list endpointslices: %w", err)}
		}

		podsByNS := map[string][]*corev1.Pod{}
		for i := range podList.Items {
			pod := &podList.Items[i]
			podsByNS[pod.Namespace] = append(podsByNS[pod.Namespace], pod)
		}
		for i := range svcList.Items {
			svc := &svcList.Items[i]
			if !injected[svc.Namespace] ||
				svc.Spec.ClusterIP != corev1.ClusterIPNone ||
				len(svc.Spec.Selector) == 0 {
				continue
			}
			sel := labels.SelectorFromSet(svc.Spec.Selector)
			readyIPs := map[string]bool{}
			liveIPs := map[string]bool{}
			readyAgedIPs := map[string]bool{}
			for _, pod := range podsByNS[svc.Namespace] {
				if pod.DeletionTimestamp != nil ||
					!sel.Matches(labels.Set(pod.Labels)) ||
					pod.Status.PodIP == "" {
					continue
				}
				liveIPs[pod.Status.PodIP] = true
				if since, ok := podReadySince(pod); ok {
					readyIPs[pod.Status.PodIP] = true
					// W10-FIX7 fuse — only a pod Ready past
					// linkerdSliceHealMinAge counts as "missing"
					// from the slices; a zero LastTransitionTime
					// reads as maximally aged.
					if now.Sub(since) >= linkerdSliceHealMinAge {
						readyAgedIPs[pod.Status.PodIP] = true
					}
				}
			}
			key := svc.Namespace + "/" + svc.Name
			if linkerdEndpointSetsDiverge(readyIPs, liveIPs, esReady[key]) {
				desynced[key] = true
			}
			if stale := staleLinkerdSlices(
				managedSlices[key], readyAgedIPs, liveIPs); len(stale) > 0 {
				staleSlices[key] = stale
			}
		}
	}

	emitted := map[string]bool{} // "ns/name" past the persistence window
	p.mu.Lock()
	for k := range p.linkerdDesyncSince {
		if !desynced[k] {
			delete(p.linkerdDesyncSince, k)
		}
	}
	for k := range desynced {
		first, ok := p.linkerdDesyncSince[k]
		if !ok {
			p.linkerdDesyncSince[k] = now
			log.Info("linkerd endpoint desync — tracking first-seen", "service", k)
			continue
		}
		if now.Sub(first) < linkerdEndpointDesyncMinAge {
			continue
		}
		emitted[k] = true
		parts := strings.SplitN(k, "/", 2)
		metrics.LinkerdEndpointDesync.WithLabelValues(parts[0], parts[1]).Set(1)
	}
	for k := range p.linkerdDesyncEmitted {
		if emitted[k] {
			continue
		}
		if parts := strings.SplitN(k, "/", 2); len(parts) == 2 {
			metrics.LinkerdEndpointDesync.DeleteLabelValues(parts[0], parts[1])
		}
		delete(p.linkerdDesyncEmitted, k)
	}
	maps.Copy(p.linkerdDesyncEmitted, emitted)
	// Prune expired heal-ledger entries — an entry past the cooldown
	// can never block again, so keeping it is pure map growth.
	for k, last := range p.linkerdDesyncHealed {
		if now.Sub(last) >= linkerdDestHealCooldown {
			delete(p.linkerdDesyncHealed, k)
		}
	}
	p.mu.Unlock()

	// Past the window: bounce the oldest linkerd-destination pod so
	// its endpoint table rebuilds from the current EndpointSlices.
	// The 1h cooldown is per desynced SERVICE — two services stuck on
	// the same root cause share one bounce.
	for k := range emitted {
		p.healLinkerdDestination(ctx, log, k, now, staleSlices[k])
	}

	if len(emitted) == 0 {
		return probeResult{pass: true}
	}
	keys := make([]string, 0, len(emitted))
	for k := range emitted {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return probeResult{why: fmt.Sprintf(
		"headless services with EndpointSlice desync >=%s: %s",
		linkerdEndpointDesyncMinAge, strings.Join(keys, ", "))}
}

// healLinkerdDestination repairs a desynced headless Service on two
// fronts (W10-FIX7):
//
//  1. DELETE the provably-stale endpointslice-controller-owned
//     EndpointSlices staleLinkerdSlices flagged — a bounce only
//     re-reads the slices, so without this the destination pod would
//     resync from the same stale data. KCM's endpointslice-controller
//     recreates them from current pod state (UID-preconditioned,
//     same delete shape as the orphan-slice cleaner).
//  2. delete the OLDEST linkerd-destination pod — the component that
//     turns EndpointSlices into proxy endpoint state, so restarting
//     it forces a full resync from the (now corrected) slices.
//
// Gates: the 1h in-RAM cooldown keyed on the desynced service (the
// heal targets are the slices + pod — nothing else can carry the
// stamp; one stamp covers BOTH actions so a 5m sweep cannot churn
// slice deletes inside the pod-bounce cooldown) and the maintenance
// mutex, same shape as every pod-delete heal in this package. The
// cooldown stamps when ANY heal action succeeded — a failed delete
// retries next sweep instead of burning the hour.
func (p *linkerdEndpointSyncCheck) healLinkerdDestination(ctx context.Context,
	log logr.Logger, svcKey string, now time.Time, stale []linkerdSliceRef) {

	p.mu.Lock()
	last, ok := p.linkerdDesyncHealed[svcKey]
	p.mu.Unlock()
	if ok && now.Sub(last) < linkerdDestHealCooldown {
		log.Info("skip heal: linkerd-destination inside cooldown",
			"service", svcKey, "ago", now.Sub(last).Truncate(time.Minute))
		return
	}
	held, why, err := shared.MaintenanceActive(ctx, p.cs, p.dyn)
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Info("WARN: maintenance check unverifiable — heal deferred (fail closed)",
			"service", svcKey, "error", err)
		return
	}
	if held {
		log.Info("maintenance in progress — heal deferred",
			"service", svcKey, "why", why)
		return
	}

	healed := false
	for _, sl := range stale {
		uid := sl.uid
		err := p.cs.DiscoveryV1().EndpointSlices(sl.ns).Delete(ctx, sl.name,
			metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &uid},
			})
		switch {
		case err == nil:
			healed = true
			log.Info("DELETE: stale EndpointSlice for endpoint desync — endpointslice-controller rebuild forced",
				"endpointslice", sl.ns+"/"+sl.name, "service", svcKey)
		case apierrors.IsNotFound(err):
			// Already gone — another actor or the controller beat
			// us to it; nothing to heal.
		default:
			metrics.IncError(clusterHealthQueue)
			log.Error(err, "stale endpointslice delete failed",
				"endpointslice", sl.ns+"/"+sl.name, "service", svcKey)
		}
	}

	pods, err := p.cs.CoreV1().Pods(linkerdNS).List(ctx, metav1.ListOptions{})
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Info("WARN: list linkerd pods failed — heal deferred",
			"error", err)
		return
	}
	var target *corev1.Pod
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.DeletionTimestamp != nil ||
			!linkerdPodMatchesComponent(pod, linkerdDestinationName) {
			continue
		}
		if target == nil ||
			pod.CreationTimestamp.Before(&target.CreationTimestamp) {
			target = pod
		}
	}
	if target != nil {
		uid := target.UID
		if err := p.cs.CoreV1().Pods(target.Namespace).Delete(ctx, target.Name,
			metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &uid},
			}); err != nil {
			metrics.IncError(clusterHealthQueue)
			log.Error(err, "linkerd-destination delete failed",
				"pod", target.Namespace+"/"+target.Name)
		} else {
			healed = true
			metrics.ControlPlanePodHealsTotal.WithLabelValues(linkerdDestinationName).Inc()
			log.Info("DELETE: linkerd-destination bounce for endpoint desync — forcing endpoint-table resync",
				"pod", target.Namespace+"/"+target.Name, "service", svcKey)
		}
	}
	if healed {
		p.mu.Lock()
		p.linkerdDesyncHealed[svcKey] = now
		p.mu.Unlock()
	}
}
