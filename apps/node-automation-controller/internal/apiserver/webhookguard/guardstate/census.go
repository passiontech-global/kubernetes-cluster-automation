// census.go — the W5.5/W9-CP1 endpoint census: the once-per-run
// EndpointSlice ready count (raw + node-health-discounted effective),
// the webhook-backend probe set, the TCP+TLS brownout probe and the
// backing-pod refs the stage-1 bounce deletes. Shared by the circuit
// breaker, the CRD conversion-backend check and the injector-health
// gate, which all draw from Snapshot.ReadyCounts.
package guardstate

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"slices"
	"strconv"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// ListPageSize bounds every cluster-wide namespaced List below —
// an unbounded all-namespaces EndpointSlice/pod/Service list is a
// heap spike every sweep, so they page through the apiserver's
// continue token instead. The snapshot's cluster-scoped lists
// (Namespaces, Mutating/ValidatingWebhookConfigurations) stay
// unpaged: they are tiny by definition.
const ListPageSize = kube.DefaultListPageSize

// CustomResourceDefinitionGVR is where the conversion-webhook checks
// read CRDs — the typed clientset has no apiextensions surface, so
// the objects reach through dyn like every other CRD this controller
// consumes.
var CustomResourceDefinitionGVR = schema.GroupVersionResource{
	Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}

const (
	// W9-CP1 — Admission Webhook gray-failure TCP/TLS brownout
	// probe: a webhook backend whose EndpointSlice still reports
	// Ready endpoints on healthy nodes but whose pods all fail the
	// TCP+TLS handshake is hung, not partitioned. The probe dials
	// up to probeMaxPerSvc Ready endpoint IPs per backend service.
	probeMaxPerSvc   = 2  // endpoint IPs dialed per service
	probeMaxPodRefs  = 32 // backing-pod candidates kept per service
	probeDefaultPort = 443
)

// EndpointCensus is the W5.5 dual ready-endpoint count: raw counts
// every Ready endpoint; effective excludes the Ready endpoints whose
// pod sits on an unhealthy node (partitioned/unresponsive — reachable
// in the API sense but dead for webhook traffic).
//
// W9-CP1 adds the brownout fields, populated ONLY for services a
// webhook config's clientConfig.service references (the probeSet in
// webhookBackendServices — probing every Service cluster-wide would
// be a dial storm):
//   - ProbeIPs/ProbePort: up to probeMaxPerSvc Ready endpoint
//     IPs on healthy nodes plus the port the handshake targets.
//   - BackingPods: Ready endpoint pod refs for the stage-1 bounce.
//   - Probed/Responsive: per-service handshake outcome — Probed marks
//     a service whose endpoints were actually dialed this run;
//     Responsive is true when ANY probed IP completed TCP+TLS. A
//     probed service with Responsive=false is "unresponsive": its
//     pods are hung, which the breaker treats as effective=0.
type EndpointCensus struct {
	Raw       map[string]int
	Effective map[string]int
	ProbeIPs  map[string][]string
	ProbePort map[string]int32
	// BackingPods identifies one Ready endpoint's backing Pod — the
	// bounce candidates for an unresponsive service.
	BackingPods map[string][]PodRef
	Probed      map[string]bool
	Responsive  map[string]bool
}

// PodRef is a namespace/name pair for a Pod discovered through an
// EndpointSlice targetRef.
type PodRef struct{ Namespace, Name string }

// readyEndpointCounts builds the ns/service → Ready-endpoint census
// from the cluster-wide EndpointSlice list (paged — see ListPageSize),
// in TWO counts (W5.5): raw counts every Ready endpoint; effective
// drops the endpoints whose NodeName is flagged unhealthy by the
// node census — a "Ready" pod on a partitioned node still fails every
// apiserver webhook call. The kubernetes.io/service-name label binds
// each slice to its Service; a nil conditions.ready counts as ready
// (the field defaults to true server-side). No degraded mode: without
// a complete census "0 ready" is indistinguishable from "no data", so
// a list error — endpoints OR nodes — skips the whole breaker rather
// than trip healthy webhooks.
func (g *Guard) readyEndpointCounts(ctx context.Context, snap *Snapshot) (EndpointCensus, error) {
	if snap.NodesErr != nil {
		return EndpointCensus{}, fmt.Errorf("list nodes — circuit breaker skipped: %w", snap.NodesErr)
	}
	ready := EndpointCensus{
		Raw:         map[string]int{},
		Effective:   map[string]int{},
		ProbeIPs:    map[string][]string{},
		ProbePort:   map[string]int32{},
		BackingPods: map[string][]PodRef{},
		Probed:      map[string]bool{},
		Responsive:  map[string]bool{},
	}
	// W9-CP1 — only Services a webhook config actually calls get
	// probed: the brownout check exists to keep admission webhooks
	// honest, and dialing every Service in the cluster would be a
	// handshake storm for zero signal. A missing config list (API
	// flap) yields an empty probeSet — the census still counts, the
	// breaker just sees no probe data (unresponsive stays false).
	probeSet := webhookBackendServices(snap)
	err := kube.ListEach(ctx,
		metav1.ListOptions{Limit: ListPageSize},
		kube.EndpointSlices(g.CS, metav1.NamespaceAll),
		func(items []discoveryv1.EndpointSlice) error {
			for _, s := range items {
				svc := s.Labels[discoveryv1.LabelServiceName]
				if svc == "" {
					continue // no owning Service — cannot map to a webhook backend
				}
				key := s.Namespace + "/" + svc
				probeSvc := probeSet[key]
				for _, ep := range s.Endpoints {
					if ep.Conditions.Ready == nil || *ep.Conditions.Ready {
						ready.Raw[key]++
						// A nil NodeName (off-cluster target, not yet
						// bound) cannot be attributed to a bad node —
						// benefit of the doubt, count it effective.
						effective := ep.NodeName == nil || !snap.UnhealthyNodes[*ep.NodeName]
						if effective {
							ready.Effective[key]++
						}
						// W9-CP1 — collect probe candidates and backing
						// pod refs ONLY for effective-ready endpoints on
						// webhook backends: endpoints stranded on
						// unhealthy nodes are already discounted, and
						// probing them would just re-measure the
						// partition.
						if probeSvc && effective {
							collectProbeCandidates(&ready, key, &s, &ep)
						}
					}
				}
			}
			return nil
		})
	if err != nil {
		return EndpointCensus{}, fmt.Errorf("list endpointslices — circuit breaker skipped: %w", err)
	}
	// W9-CP1 — TCP+TLS brownout probe, up to probeMaxPerSvc
	// Ready endpoint IPs per webhook backend. Responsive is an
	// ANY-success verdict: one answering endpoint means the Service
	// is not brownout-hung even if siblings are.
	prober := g.EndpointProber
	if prober == nil {
		prober = tcpTLSEndpointProber
	}
	for key, ips := range ready.ProbeIPs {
		ready.Probed[key] = true
		ok := false
		for _, ip := range ips {
			if prober(ctx, ip, ready.ProbePort[key]) {
				ok = true
				break
			}
		}
		ready.Responsive[key] = ok
	}
	return ready, nil
}

// webhookBackendServices returns the set of "namespace/name" Service
// keys referenced by any sub-webhook's clientConfig.service across
// both webhook-config kinds PLUS every CRD spec.conversion webhook's
// service — the only services the W9-CP1 probe dials. Nil config
// lists and a failed CRD list (API flap) contribute nothing.
func webhookBackendServices(snap *Snapshot) map[string]bool {
	out := map[string]bool{}
	add := func(svc *admissionv1.ServiceReference) {
		if svc != nil && svc.Namespace != "" && svc.Name != "" {
			out[svc.Namespace+"/"+svc.Name] = true
		}
	}
	if snap.MWC != nil {
		for i := range snap.MWC.Items {
			for j := range snap.MWC.Items[i].Webhooks {
				add(snap.MWC.Items[i].Webhooks[j].ClientConfig.Service)
			}
		}
	}
	if snap.VWC != nil {
		for i := range snap.VWC.Items {
			for j := range snap.VWC.Items[i].Webhooks {
				add(snap.VWC.Items[i].Webhooks[j].ClientConfig.Service)
			}
		}
	}
	// CRD conversion backends join the probe set — a hung conversion
	// pod is the same brownout signature, and its probe verdict feeds
	// the tls_probe_failed reason + the stage-1 bounce.
	for i := range snap.CRDs {
		if key, _, _, ok := CRDConversionServiceKey(&snap.CRDs[i]); ok {
			out[key] = true
		}
	}
	return out
}

// collectProbeCandidates records one effective-ready endpoint's
// address (up to probeMaxPerSvc distinct IPs) and its backing
// Pod ref (up to probeMaxPodRefs) for service key — the probe
// and bounce inputs of the W9-CP1 brownout path.
func collectProbeCandidates(ready *EndpointCensus,
	key string, s *discoveryv1.EndpointSlice, ep *discoveryv1.Endpoint) {
	if len(ready.ProbeIPs[key]) < probeMaxPerSvc && len(ep.Addresses) > 0 {
		for _, addr := range ep.Addresses {
			if !slices.Contains(ready.ProbeIPs[key], addr) {
				ready.ProbeIPs[key] = append(ready.ProbeIPs[key], addr)
				break
			}
		}
	}
	if _, ok := ready.ProbePort[key]; !ok {
		// The webhook port: the slice's first declared port, default
		// 443 — admission webhooks are HTTPS-only, and a slice with
		// no ports still targets the Service's own port mapping.
		port := int32(probeDefaultPort)
		for _, p := range s.Ports {
			if p.Port != nil {
				port = *p.Port
				break
			}
		}
		ready.ProbePort[key] = port
	}
	if ep.TargetRef != nil && ep.TargetRef.Kind == "Pod" && ep.TargetRef.Name != "" {
		ns := ep.TargetRef.Namespace
		if ns == "" {
			ns = s.Namespace // endpointSlice-local pods carry no namespace on the ref
		}
		ref := PodRef{Namespace: ns, Name: ep.TargetRef.Name}
		if len(ready.BackingPods[key]) < probeMaxPodRefs &&
			!slices.Contains(ready.BackingPods[key], ref) {
			ready.BackingPods[key] = append(ready.BackingPods[key], ref)
		}
	}
}

// webhookUnhealthyNodeTaints are the taint keys marking a node whose
// pod network is presumed dead for admission purposes — the passiontech.dev
// pair this operator asserts itself plus the kubelet/node-controller
// lifecycle taints.
var webhookUnhealthyNodeTaints = []string{
	kube.TaintNetworkPartitioned,
	kube.TaintKubeletUnresponsive,
	"node.kubernetes.io/unreachable",
	"node.kubernetes.io/not-ready",
	"node.kubernetes.io/out-of-service",
}

// nodeUnhealthyForEndpoints reports whether Ready pods on this node
// should be DISCOUNTED from a webhook backend census: the node is
// NotReady, carries a partition/unresponsive/lifecycle taint, or
// reports an explicit NetworkPartitioned condition — in all three
// cases the apiserver's webhook call to that pod times out, so the
// endpoint is Ready in name only.
func nodeUnhealthyForEndpoints(n *corev1.Node) bool {
	if !kube.NodeReady(n) {
		return true
	}
	for _, k := range webhookUnhealthyNodeTaints {
		if kube.HasTaint(n.Spec.Taints, k) {
			return true
		}
	}
	for _, c := range n.Status.Conditions {
		if c.Type == "NetworkPartitioned" && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// tcpTLSEndpointProber is the production EndpointProber: a 2s
// TCP-connect + TLS handshake against ip:port. InsecureSkipVerify —
// the probe answers "is the webhook port serving TLS at all", not
// "is the certificate valid": a brownout pod fails the handshake
// entirely, while a healthy one completes it regardless of SANs the
// probe cannot vouch for.
func tcpTLSEndpointProber(ctx context.Context, ip string, port int32) bool {
	if err := ctx.Err(); err != nil {
		return false
	}
	d := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp",
		net.JoinHostPort(ip, strconv.Itoa(int(port))),
		&tls.Config{InsecureSkipVerify: true}) // liveness probe only
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
