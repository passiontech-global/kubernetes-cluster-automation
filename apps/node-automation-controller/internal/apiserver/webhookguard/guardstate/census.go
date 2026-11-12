// census.go — the endpoint-census/circuit-breaker-bounce endpoint census: the once-per-run
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
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// ListPageSize bounds every cluster-wide namespaced List below —
// an unbounded all-namespaces EndpointSlice/pod/Service list is a
// heap spike every sweep, so they page through the apiserver's
// continue token instead. The snapshot's cluster-scoped lists
// (Namespaces, Mutating/ValidatingWebhookConfigurations) stay
// unpaged: they are tiny by definition.
const ListPageSize = kube.DefaultListPageSize

// crdPageSize bounds one page of the CRD census — tighter than
// ListPageSize because a CRD page carries full OpenAPI schemas
// (the fattest objects any census here lists); 25 keeps a page's
// transient heap in the low MiB before compactCRDConversion drops
// the schemas and the page is GC'd.
const crdPageSize = 25

// CRDs are read through kube.GVRCustomResourceDefinition — the typed
// clientset has no apiextensions surface, so the objects reach
// through dyn like every other CRD this controller consumes.

const (
	// circuit-breaker-bounce — Admission Webhook gray-failure TCP/TLS brownout
	// probe: a webhook backend whose EndpointSlice still reports
	// Ready endpoints on healthy nodes but whose pods all fail the
	// TCP+TLS handshake is hung, not partitioned. The probe dials
	// up to probeMaxPerSvc Ready endpoint IPs per backend service.
	probeMaxPerSvc   = 2  // endpoint IPs dialed per service
	probeMaxPodRefs  = 32 // backing-pod candidates kept per service
	probeDefaultPort = 443

	// probeWorkers bounds the brownout probe's concurrency — at most
	// four TCP+TLS handshakes in flight per sweep, no matter how many
	// webhook backends the cluster carries.
	probeWorkers = 4
)

// EndpointCensus is the endpoint-census dual ready-endpoint count: raw counts
// every Ready endpoint; effective excludes the Ready endpoints whose
// pod sits on an unhealthy node (partitioned/unresponsive — reachable
// in the API sense but dead for webhook traffic).
//
// circuit-breaker-bounce adds the brownout fields, populated ONLY for services a
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
// in TWO counts (endpoint-census): raw counts every Ready endpoint; effective
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
	// circuit-breaker-bounce — only Services a webhook config actually calls get
	// probed: the brownout check exists to keep admission webhooks
	// honest, and dialing every Service in the cluster would be a
	// handshake storm for zero signal. A missing config list (API
	// flap) yields an empty probeSet — the census still counts, the
	// breaker just sees no probe data (unresponsive stays false).
	probeSet := webhookBackendServices(snap)
	// The EndpointSlice a webhook backend fronts can carry several
	// ports (HTTPS webhook + HTTP metrics), so Ports[0] is not a
	// safe probe target — resolve each probe service's preferred
	// port set ONCE (one Service Get per backend, before the paged
	// slice walk) for collectProbeCandidates to pick against.
	probePrefs := make(map[string]slicePortPref, len(probeSet))
	for key, svcPorts := range probeSet {
		probePrefs[key] = resolveSlicePortPref(snap, key, svcPorts)
	}
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
				_, probeSvc := probeSet[key]
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
						// circuit-breaker-bounce — collect probe candidates and backing
						// pod refs ONLY for effective-ready endpoints on
						// webhook backends: endpoints stranded on
						// unhealthy nodes are already discounted, and
						// probing them would just re-measure the
						// partition.
						if probeSvc && effective {
							collectProbeCandidates(&ready, key, &s, &ep, probePrefs[key])
						}
					}
				}
			}
			return nil
		})
	if err != nil {
		return EndpointCensus{}, fmt.Errorf("list endpointslices — circuit breaker skipped: %w", err)
	}
	// circuit-breaker-bounce — TCP+TLS brownout probe, up to probeMaxPerSvc
	// Ready endpoint IPs per webhook backend, fanned out through a
	// bounded worker pool (probeWorkers dials at most four handshakes
	// at once — a cluster with dozens of webhook backends must not
	// open dozens of concurrent TLS connections every sweep).
	// Responsive is an ANY-success verdict: one answering endpoint
	// means the Service is not brownout-hung even if siblings are.
	// A ctx cancellation stops the probe immediately and leaves the
	// in-flight services UNRECORDED — Probed/Responsive stay unset so
	// a cancelled sweep cannot read as "every webhook unresponsive"
	// and stamp the brownout ledgers.
	prober := g.EndpointProber
	if prober == nil {
		prober = tcpTLSEndpointProber
	}
	probeKeys := slices.Sorted(maps.Keys(ready.ProbeIPs))
	type probeVerdict struct {
		key        string
		responsive bool
	}
	workers := min(probeWorkers, len(probeKeys))
	jobs := make(chan string)
	results := make(chan probeVerdict, len(probeKeys))
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for key := range jobs {
				ok := false
				for _, ip := range ready.ProbeIPs[key] {
					if prober(ctx, ip, ready.ProbePort[key]) {
						ok = true
						break
					}
				}
				// The run's budget expired mid-probe: leave the
				// service unrecorded — an aborted dial is not
				// evidence of a hung webhook.
				if ctx.Err() != nil {
					continue
				}
				results <- probeVerdict{key: key, responsive: ok}
			}
		}()
	}
	for _, key := range probeKeys {
		jobs <- key
	}
	close(jobs)
	wg.Wait()
	close(results)
	for v := range results {
		ready.Probed[v.key] = true
		ready.Responsive[v.key] = v.responsive
	}
	return ready, nil
}

// webhookBackendServices maps each "namespace/name" Service key
// referenced by any sub-webhook's clientConfig.service across both
// webhook-config kinds PLUS every CRD spec.conversion webhook's
// service to the declared SERVICE ports the referencing webhooks
// carry (clientConfig.service.port, nil → the apiserver default
// 443) — the only services the circuit-breaker-bounce probe dials, and the input the
// slice-port preference resolves through spec.ports. Nil config
// lists and a failed CRD list (API flap) contribute nothing.
func webhookBackendServices(snap *Snapshot) map[string][]int32 {
	out := map[string][]int32{}
	addPort := func(key string, port int32) {
		if !slices.Contains(out[key], port) {
			out[key] = append(out[key], port)
		}
	}
	add := func(svc *admissionv1.ServiceReference) {
		if svc == nil || svc.Namespace == "" || svc.Name == "" {
			return
		}
		port := int32(probeDefaultPort)
		if svc.Port != nil {
			port = *svc.Port
		}
		addPort(svc.Namespace+"/"+svc.Name, port)
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
			port := int32(probeDefaultPort)
			if p, found := kube.NestedInt64(snap.CRDs[i].Object,
				"spec", "conversion", "webhook", "clientConfig",
				"service", "port"); found {
				port = int32(p)
			}
			addPort(key, port)
		}
	}
	return out
}

// slicePortPref is one webhook-backend Service's acceptable
// EndpointSlice port set: names that mark the webhook's HTTPS
// listener plus resolved targetPort numbers — the preference
// pickSlicePort applies instead of a bare Ports[0] grab.
type slicePortPref struct {
	names   map[string]bool
	numbers map[int32]bool
}

// webhookPortNames are the EndpointSlice port names that mark a
// webhook's TLS listener — a slice can front an HTTP metrics port
// too, and probing THAT reads a hung webhook as healthy.
var webhookPortNames = map[string]bool{"https": true, "webhook": true, "tls": true}

// resolveSlicePortPref builds the acceptable-port set for one probe
// service: the conventional webhook port names, plus — resolved
// through the Service's spec.ports — the port name and targetPort
// the declared ServiceReference port maps to (a ServiceReference
// port is the SERVICE port; the slice carries TARGET ports, so the
// Service object is the only honest translation). An unresolvable
// Service degrades to name matching alone.
func resolveSlicePortPref(snap *Snapshot,
	key string, svcPorts []int32) slicePortPref {
	pref := slicePortPref{names: map[string]bool{}, numbers: map[int32]bool{}}
	for n := range webhookPortNames {
		pref.names[n] = true
	}
	ns, name, ok := strings.Cut(key, "/")
	if !ok {
		return pref
	}
	// The snapshot's paged Services census replaces the per-backend
	// Get — a missing service or a failed census degrades to name
	// matching alone, same as the old Get-error path.
	var svc *corev1.Service
	for i := range snap.Services {
		if snap.Services[i].Namespace == ns &&
			snap.Services[i].Name == name {
			svc = &snap.Services[i]
			break
		}
	}
	if svc == nil {
		return pref // cannot resolve — the named-port preference still applies
	}
	for _, sp := range svc.Spec.Ports {
		if !slices.Contains(svcPorts, sp.Port) {
			continue // not a port a webhook declared
		}
		if sp.Name != "" {
			pref.names[strings.ToLower(sp.Name)] = true
		}
		if sp.TargetPort.IntVal != 0 {
			pref.numbers[sp.TargetPort.IntVal] = true
		}
		if sp.TargetPort.StrVal != "" {
			pref.names[strings.ToLower(sp.TargetPort.StrVal)] = true
		}
	}
	return pref
}

// pickSlicePort chooses the EndpointSlice port the TLS probe dials:
// a port whose name marks the webhook listener (https/webhook/tls or
// the name the Service gave the declared port) or whose number
// equals a resolved targetPort wins; the first declared port is the
// fallback (matching the old Ports[0] pick), then 443.
func pickSlicePort(s *discoveryv1.EndpointSlice, pref slicePortPref) int32 {
	port := int32(probeDefaultPort)
	for i, p := range s.Ports {
		if p.Port == nil {
			continue
		}
		if i == 0 {
			port = *p.Port // the bare first-port fallback
		}
		if p.Name != nil && pref.names[strings.ToLower(*p.Name)] {
			return *p.Port
		}
		if pref.numbers[*p.Port] {
			return *p.Port
		}
	}
	return port
}

// collectProbeCandidates records one effective-ready endpoint's
// address (up to probeMaxPerSvc distinct IPs) and its backing
// Pod ref (up to probeMaxPodRefs) for service key — the probe
// and bounce inputs of the circuit-breaker-bounce brownout path.
func collectProbeCandidates(ready *EndpointCensus,
	key string, s *discoveryv1.EndpointSlice, ep *discoveryv1.Endpoint,
	pref slicePortPref) {
	if len(ready.ProbeIPs[key]) < probeMaxPerSvc && len(ep.Addresses) > 0 {
		for _, addr := range ep.Addresses {
			if !slices.Contains(ready.ProbeIPs[key], addr) {
				ready.ProbeIPs[key] = append(ready.ProbeIPs[key], addr)
				break
			}
		}
	}
	if _, ok := ready.ProbePort[key]; !ok {
		// The webhook port: the slice's HTTPS port by name or by the
		// resolved Service mapping — a bare first-port pick can land
		// on an HTTP metrics port and read a healthy webhook as a
		// brownout (or a wedged one as serving).
		ready.ProbePort[key] = pickSlicePort(s, pref)
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
// pod network is presumed dead for admission purposes — the
// passiontech.dev marks this operator asserts itself plus the
// kubelet/node-controller lifecycle taints.
var webhookUnhealthyNodeTaints = []string{
	kube.TaintNetworkPartitioned,
	kube.TaintKubeletUnresponsive,
	kube.TaintApiserverUnreachable,
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
// TCP-connect + TLS handshake against ip:port, dialed through
// tls.Dialer.DialContext so the caller's ctx cancels the handshake
// itself (tls.DialWithDialer's legacy path could outlive it).
// InsecureSkipVerify — the probe answers "is the webhook port serving
// TLS at all", not "is the certificate valid": a brownout pod fails
// the handshake entirely, while a healthy one completes it regardless
// of SANs the probe cannot vouch for.
func tcpTLSEndpointProber(ctx context.Context, ip string, port int32) bool {
	if err := ctx.Err(); err != nil {
		return false
	}
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 2 * time.Second},
		Config:    &tls.Config{InsecureSkipVerify: true}, // liveness probe only
	}
	conn, err := d.DialContext(ctx, "tcp",
		net.JoinHostPort(ip, strconv.Itoa(int(port))))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
