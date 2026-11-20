// probe_target.go — layer-2 probe-target selection for
// coredns-stale-watchdog: pick the newest Service <10m old with a
// ready EndpointSlice (its delta certainly crossed a healthy watch),
// else the coredns-probe-fallback fallback — the most-recently-changed EndpointSlice
// plus its owning Service's expected answer set.
package corednswatchdog

import (
	"cmp"
	"context"
	"slices"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// probeFQDNUncached picks the layer-2 probe target: the newest
// Service <10m old having an EndpointSlice with a ready endpoint —
// its delta certainly crossed a healthy watch — returning its
// <name>.<ns>.svc.cluster.local FQDN plus nil wantIPs (any answer
// proves freshness), the target's namespace/name, and fresh=true
// marking the <10m-Service selection path.
//
// coredns-probe-fallback fallback: on a quiet cluster no Service is <10m old, so the
// old code skipped layer 2 entirely — exactly the steady-state where a
// frozen watch rots longest. The fallback picks the most-recently-
// CHANGED EndpointSlice (highest resourceVersion) that still carries a
// ready endpoint and resolves its owning Service: the want set is the
// Service's clusterIPs, or — for a headless service — the ready
// endpoint pod IPs. A pod answering with anything else is serving a
// frozen cache. Returns ("", nil, "", "", false) when nothing
// qualifies.
func (w *coreDNSWatchdog) probeFQDNUncached(ctx context.Context) (string, map[string]bool, string, string, bool) {
	log := logf.FromContext(ctx)
	// Page the cluster-wide Service list — an unbounded List forces
	// etcd to serialize every Service into one response; 500-per-page
	// keeps each request cheap at fleet scale. ResourceVersion=0
	// serves the watch cache: this probe runs every cycle and only
	// needs a seconds-fresh view of the endpoint set, not a quorum
	// read — and the watch cache rejects Limit entirely, so no page
	// bound is set here at all.
	svcItems, err := kube.ListAll(ctx,
		metav1.ListOptions{ResourceVersion: "0"},
		kube.Services(w.cs, metav1.NamespaceAll))
	if err != nil {
		log.Info("dns: cannot list services — layer 2 inconclusive", "error", err)
		return "", nil, "", "", false
	}
	slices.SortFunc(svcItems, func(a, b corev1.Service) int {
		return -a.CreationTimestamp.Compare(b.CreationTimestamp.Time)
	})
	type svcCand struct {
		ns, name        string
		created         time.Time
		headless        bool
		publishNotReady bool
	}
	n := len(svcItems)
	if n > 8 { // bash: top-8 newest BEFORE the age filter
		n = 8
	}
	cands := make([]svcCand, 0, n)
	for i := range svcItems[:n] {
		s := &svcItems[i]
		cands = append(cands, svcCand{
			ns:      s.Namespace,
			name:    s.Name,
			created: s.CreationTimestamp.Time,
			// Headless is EXACTLY ClusterIP "None" — a headless
			// A record IS the live endpoint set, so its answers
			// are verifiable. "" (unallocated/ExternalName) takes
			// the any-answer ClusterIP path: there is no stable
			// IP set to verify against, but a fresh service name
			// resolving at all still proves the watch is live.
			headless: s.Spec.ClusterIP == corev1.ClusterIPNone,
			// publishNotReadyAddresses puts NotReady pod IPs into
			// the DNS answer set too — headlessWantSet must expect
			// them or every healthy answer reads stale.
			publishNotReady: s.Spec.PublishNotReadyAddresses,
		})
	}
	// Headless candidates win over ClusterIP ones (P0-11): a
	// ClusterIP answer is blind to a frozen watch — the IP is
	// allocated once — while a headless A record IS the live
	// endpoint set. Scan every <10m candidate for the newest
	// headless service with a ready endpoint; the newest
	// ClusterIP service is kept only as the fallback answer.
	var clusterIPPick *svcCand
	for i := range cands {
		svc := &cands[i]
		if w.now.Now().Sub(svc.created) >= corednsLogSinceS*time.Second {
			continue
		}
		eps, err := kube.ListAll(ctx,
			metav1.ListOptions{
				ResourceVersion: "0",
				LabelSelector:   discoveryv1.LabelServiceName + "=" + svc.name},
			kube.EndpointSlices(w.cs, svc.ns))
		if err != nil {
			log.Info("dns: cannot list endpointslices — skipping probe candidate",
				"service", svc.ns+"/"+svc.name, "error", err)
			continue
		}
		if !hasReadyEndpoint(eps) {
			continue
		}
		if svc.headless {
			want := headlessWantSetFromSlices(eps, svc.publishNotReady)
			if len(want) == 0 {
				continue // ready endpoint carried no addresses
			}
			return svc.name + "." + svc.ns + ".svc.cluster.local", want,
				svc.ns, svc.name, true
		}
		if clusterIPPick == nil {
			clusterIPPick = svc
		}
	}
	if clusterIPPick != nil {
		// Newest ClusterIP service with a ready endpoint — any
		// answer proves freshness for a <10m-old service (its IP
		// was just allocated, so a frozen watch cannot know it).
		return clusterIPPick.name + "." + clusterIPPick.ns +
				".svc.cluster.local", nil, clusterIPPick.ns,
			clusterIPPick.name, true
	}
	svcItems = nil
	return w.probeFQDNFromSlices(ctx)
}

// probeFQDNFromSlices is the coredns-probe-fallback fallback target: the
// most-recently-changed EndpointSlice (highest resourceVersion —
// slice objects carry no change timestamp, so the apiserver's RV is
// the recency proxy) with at least one ready endpoint. The answer set
// comes from the slice's Service: clusterIPs for a normal service,
// the ready endpoint pod IPs for a headless one.
//
// P0-11: a ClusterIP answer is BLIND to a frozen watch — the IP is
// allocated once and never changes, so CoreDNS serving a months-old
// cache still answers "correctly". The fallback therefore prefers
// HEADLESS services: their A records ARE the live endpoint set,
// which churns on every rollout/restart, so a stale answer is
// detectable. Candidates are tried in resourceVersion order (top 8)
// until a headless service resolves; a ClusterIP service is kept
// only as the last resort — strictly better than nothing, still no
// worse than the old single-pick behavior.
func (w *coreDNSWatchdog) probeFQDNFromSlices(ctx context.Context) (string, map[string]bool, string, string, bool) {
	log := logf.FromContext(ctx)
	type cand struct {
		ns, svc string
		rv      int64
	}
	type svcKey struct{ ns, svc string }
	type svcAddrs struct {
		ready    []string
		notReady []string
	}
	var cands []cand
	addrsBySvc := map[svcKey]*svcAddrs{}
	err := kube.ListEach(ctx,
		metav1.ListOptions{ResourceVersion: "0"},
		kube.EndpointSlices(w.cs, metav1.NamespaceAll),
		func(items []discoveryv1.EndpointSlice) error {
			for i := range items {
				es := &items[i]
				svcName := es.Labels[discoveryv1.LabelServiceName]
				if svcName == "" {
					continue
				}
				key := svcKey{es.Namespace, svcName}
				sa := addrsBySvc[key]
				ready := false
				for _, ep := range es.Endpoints {
					epReady := ep.Conditions.Ready != nil && *ep.Conditions.Ready
					if epReady {
						ready = true
					}
					if len(ep.Addresses) > 0 {
						if sa == nil {
							sa = &svcAddrs{}
							addrsBySvc[key] = sa
						}
						if epReady {
							sa.ready = append(sa.ready, ep.Addresses...)
						} else {
							sa.notReady = append(sa.notReady, ep.Addresses...)
						}
					}
				}
				if !ready {
					continue
				}
				rv, err := strconv.ParseInt(es.ResourceVersion, 10, 64)
				if err != nil {
					continue
				}
				cands = append(cands, cand{es.Namespace, svcName, rv})
			}
			return nil
		})
	if err != nil {
		log.Info("dns: cannot list endpointslices — fallback inconclusive", "error", err)
		return "", nil, "", "", false
	}
	if len(cands) == 0 {
		return "", nil, "", "", false
	}
	slices.SortFunc(cands, func(a, b cand) int { return cmp.Compare(b.rv, a.rv) })
	if len(cands) > 8 {
		cands = cands[:8]
	}
	// Try candidates newest-first: first HEADLESS service wins;
	// the newest ClusterIP service is the fallback answer.
	var clusterIPFallback *corev1.Service
	var clusterIPRef cand
	for _, c := range cands {
		svc, err := w.cs.CoreV1().Services(c.ns).Get(ctx, c.svc, metav1.GetOptions{})
		if err != nil {
			continue // service gone or unreadable — try the next slice
		}
		if svc.Spec.ClusterIP == corev1.ClusterIPNone {
			sa := addrsBySvc[svcKey{c.ns, c.svc}]
			var want map[string]bool
			if sa != nil {
				want = make(map[string]bool, len(sa.ready))
				for _, a := range sa.ready {
					want[a] = true
				}
				if svc.Spec.PublishNotReadyAddresses {
					for _, a := range sa.notReady {
						want[a] = true
					}
				}
			}
			if len(want) == 0 {
				continue
			}
			return c.svc + "." + c.ns + ".svc.cluster.local", want,
				c.ns, c.svc, false
		}
		if clusterIPFallback == nil {
			clusterIPFallback, clusterIPRef = svc, c
		}
	}
	if clusterIPFallback == nil {
		log.Info("dns: no fallback slice's service resolvable — inconclusive")
		return "", nil, "", "", false
	}
	// want is the expected answer set — nil (any answer counts)
	// when the service carries no usable IPs (unallocated
	// ClusterIP): an empty non-nil set would fail every real
	// answer in dnsAnswerFresh.
	var want map[string]bool
	if clusterIPFallback.Spec.ClusterIP != "" ||
		len(clusterIPFallback.Spec.ClusterIPs) > 0 {
		want = map[string]bool{}
		if clusterIPFallback.Spec.ClusterIP != "" {
			want[clusterIPFallback.Spec.ClusterIP] = true
		}
		for _, ip := range clusterIPFallback.Spec.ClusterIPs {
			want[ip] = true
		}
	}
	return clusterIPRef.svc + "." + clusterIPRef.ns + ".svc.cluster.local",
		want, clusterIPRef.ns, clusterIPRef.svc, false
}

// refreshProbeTarget re-validates a cached probe target through
// targeted reads — one Service GET plus one namespaced EndpointSlice
// list — instead of the cluster-wide re-pick probeFQDNUncached pays
// on every TTL expiry and invalidate-reprobe. The want-set is
// rebuilt from CURRENT slices, which is exactly what an invalidated
// cache needs (CoreDNS pod rolls change endpoint IPs, not the
// Service's identity).
//
// Re-qualification mirrors the pick rules: a fresh=true target must
// still sit inside the <10m age window its "delta crossed a healthy
// watch" proof runs on; both kinds need at least one ready endpoint,
// and headless targets need a non-empty want-set. Any failure
// returns ok=false so the caller falls back to the full pick —
// refresh can only ever REUSE a still-valid target, never stretch
// the semantics of a dead one.
func (w *coreDNSWatchdog) refreshProbeTarget(ctx context.Context,
	ns, name string, fresh bool) (string, map[string]bool, bool) {
	svc, err := w.cs.CoreV1().Services(ns).Get(ctx, name,
		metav1.GetOptions{})
	if err != nil {
		return "", nil, false
	}
	if !fresh && svc.Spec.ClusterIP != corev1.ClusterIPNone {
		return "", nil, false // never pin a ClusterIP fallback across refreshes
	}
	if fresh && w.now.Now().Sub(svc.CreationTimestamp.Time) >=
		corednsLogSinceS*time.Second {
		return "", nil, false // aged out of the freshness window
	}
	eps, err := kube.ListAll(ctx,
		metav1.ListOptions{
			ResourceVersion: "0",
			LabelSelector:   discoveryv1.LabelServiceName + "=" + name},
		kube.EndpointSlices(w.cs, ns))
	if err != nil {
		return "", nil, false
	}
	if !hasReadyEndpoint(eps) {
		return "", nil, false
	}
	fqdn := name + "." + ns + ".svc.cluster.local"
	if svc.Spec.ClusterIP == corev1.ClusterIPNone {
		want := headlessWantSetFromSlices(eps, svc.Spec.PublishNotReadyAddresses)
		if len(want) == 0 {
			return "", nil, false
		}
		return fqdn, want, true
	}
	// ClusterIP target: the exact-IP want-set (same construction as
	// the fallback pick) — nil when the service carries no usable
	// IPs, matching dnsAnswerFresh's any-answer contract.
	var want map[string]bool
	if svc.Spec.ClusterIP != "" || len(svc.Spec.ClusterIPs) > 0 {
		want = map[string]bool{}
		if svc.Spec.ClusterIP != "" {
			want[svc.Spec.ClusterIP] = true
		}
		for _, ip := range svc.Spec.ClusterIPs {
			want[ip] = true
		}
	}
	return fqdn, want, true
}

func hasReadyEndpoint(eps []discoveryv1.EndpointSlice) bool {
	for _, es := range eps {
		for _, ep := range es.Endpoints {
			// bash: conditions.ready == true — nil does NOT count.
			if ep.Conditions.Ready != nil && *ep.Conditions.Ready {
				return true
			}
		}
	}
	return false
}

// headlessWantSetFromSlices builds the expected A-record set for a
// headless service: every Ready endpoint address across ALL slices
// the Service owns — a Ready IP in a second slice is a valid DNS
// answer the single-slice want set would wrongly judge stale.
// publishNotReady mirrors spec.publishNotReadyAddresses: when the
// Service opts in, DNS publishes NotReady addresses too, so they
// belong in the expected set as well.
func headlessWantSetFromSlices(eps []discoveryv1.EndpointSlice, publishNotReady bool) map[string]bool {
	want := map[string]bool{}
	for _, es := range eps {
		for _, ep := range es.Endpoints {
			ready := ep.Conditions.Ready != nil && *ep.Conditions.Ready
			if !ready && !publishNotReady {
				continue
			}
			for _, a := range ep.Addresses {
				want[a] = true
			}
		}
	}
	return want
}
