// probe_target.go — layer-2 probe-target selection for
// coredns-stale-watchdog: pick the newest Service <10m old with a
// ready EndpointSlice (its delta certainly crossed a healthy watch),
// else the coredns-probe-fallback fallback — the most-recently-changed EndpointSlice
// plus its owning Service's expected answer set.
package corednswatchdog

import (
	"context"
	"sort"
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
// proves freshness).
//
// coredns-probe-fallback fallback: on a quiet cluster no Service is <10m old, so the
// old code skipped layer 2 entirely — exactly the steady-state where a
// frozen watch rots longest. The fallback picks the most-recently-
// CHANGED EndpointSlice (highest resourceVersion) that still carries a
// ready endpoint and resolves its owning Service: the want set is the
// Service's clusterIPs, or — for a headless service — the ready
// endpoint pod IPs. A pod answering with anything else is serving a
// frozen cache. Returns ("", nil) when nothing qualifies.
func (w *coreDNSWatchdog) probeFQDNUncached(ctx context.Context) (string, map[string]bool) {
	log := logf.FromContext(ctx)
	// Page the cluster-wide Service list — an unbounded List forces
	// etcd to serialize every Service into one response; 500-per-page
	// keeps each request cheap at fleet scale.
	svcItems, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.Services(w.cs, metav1.NamespaceAll))
	if err != nil {
		log.Info("dns: cannot list services — layer 2 inconclusive", "error", err)
		return "", nil
	}
	sort.Slice(svcItems, func(i, j int) bool {
		return svcItems[i].CreationTimestamp.
			After(svcItems[j].CreationTimestamp.Time)
	})
	type svcCand struct {
		ns, name string
		created  time.Time
	}
	n := len(svcItems)
	if n > 8 { // bash: top-8 newest BEFORE the age filter
		n = 8
	}
	cands := make([]svcCand, 0, n)
	for i := 0; i < n; i++ {
		s := &svcItems[i]
		cands = append(cands, svcCand{
			ns:      s.Namespace,
			name:    s.Name,
			created: s.CreationTimestamp.Time,
		})
	}
	for _, svc := range cands {
		if w.now.Now().Sub(svc.created) >= corednsLogSinceS*time.Second {
			continue
		}
		eps, err := w.cs.DiscoveryV1().EndpointSlices(svc.ns).List(ctx,
			metav1.ListOptions{LabelSelector: "kubernetes.io/service-name=" + svc.name})
		if err != nil {
			log.Info("dns: cannot list endpointslices — skipping probe candidate",
				"service", svc.ns+"/"+svc.name, "error", err)
			continue
		}
		for _, es := range eps.Items {
			for _, ep := range es.Endpoints {
				// bash: conditions.ready == true — nil does NOT count.
				if ep.Conditions.Ready != nil && *ep.Conditions.Ready {
					return svc.name + "." + svc.ns + ".svc.cluster.local", nil
				}
			}
		}
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
func (w *coreDNSWatchdog) probeFQDNFromSlices(ctx context.Context) (string, map[string]bool) {
	log := logf.FromContext(ctx)
	var best *discoveryv1.EndpointSlice
	var bestRV int64
	err := kube.ListEach(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.EndpointSlices(w.cs, metav1.NamespaceAll),
		func(items []discoveryv1.EndpointSlice) error {
			for i := range items {
				es := &items[i]
				if es.Labels[discoveryv1.LabelServiceName] == "" {
					continue
				}
				ready := false
				for _, ep := range es.Endpoints {
					if ep.Conditions.Ready != nil && *ep.Conditions.Ready {
						ready = true
						break
					}
				}
				if !ready {
					continue
				}
				rv, err := strconv.ParseInt(es.ResourceVersion, 10, 64)
				if err != nil || rv <= bestRV {
					continue
				}
				best, bestRV = es, rv
			}
			return nil
		})
	if err != nil {
		log.Info("dns: cannot list endpointslices — fallback inconclusive", "error", err)
		return "", nil
	}
	if best == nil {
		return "", nil
	}
	ns, svcName := best.Namespace, best.Labels[discoveryv1.LabelServiceName]
	svc, err := w.cs.CoreV1().Services(ns).Get(ctx, svcName, metav1.GetOptions{})
	if err != nil {
		log.Info("dns: fallback slice's service unresolvable — inconclusive",
			"service", ns+"/"+svcName, "error", err)
		return "", nil
	}
	want := map[string]bool{}
	if svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != corev1.ClusterIPNone {
		want[svc.Spec.ClusterIP] = true
		for _, ip := range svc.Spec.ClusterIPs {
			want[ip] = true
		}
	} else {
		// Headless: the A record IS the endpoint set — and that set
		// spans EVERY slice the Service owns, not just the freshest:
		// a Ready IP in a second slice is a valid DNS answer the
		// single-slice want set would wrongly judge stale.
		eps, err := w.cs.DiscoveryV1().EndpointSlices(ns).List(ctx,
			metav1.ListOptions{
				LabelSelector: discoveryv1.LabelServiceName + "=" + svcName})
		if err != nil {
			log.Info("dns: cannot list sibling endpointslices — inconclusive",
				"service", ns+"/"+svcName, "error", err)
			return "", nil
		}
		for _, es := range eps.Items {
			for _, ep := range es.Endpoints {
				if ep.Conditions.Ready == nil || !*ep.Conditions.Ready {
					continue
				}
				for _, a := range ep.Addresses {
					want[a] = true
				}
			}
		}
	}
	if len(want) == 0 {
		return "", nil
	}
	return svcName + "." + ns + ".svc.cluster.local", want
}
