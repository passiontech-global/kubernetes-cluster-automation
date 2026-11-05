// Port of hooks/55-admission-webhook-guard.sh.
//
// Removes "orphan" admission webhook entries whose backend Service lives
// in a namespace that no longer exists (e.g. Flux pruned linkerd → the
// cluster-scoped MutatingWebhookConfiguration outlived its control plane
// and every pod create fail-closed, incident 2026-10-20).
//
// Rules (faithful to bash):
//   - namespace exists + Service exists      → nothing.
//   - namespace exists + Service missing     → WARN only, never patch
//     (a mid-rollout Service looks exactly like this).
//   - namespace gone                         → remove that webhook entry
//     only; sibling entries in the same config are kept.
//
// Safety: the namespace list is snapshotted once — any error aborts the
// run before anything is patched (an API flap must never be read as
// "namespace deleted").
//
// C1 — self-deadlock circuit breaker (env WEBHOOK_CIRCUIT_BREAKER_ENABLED,
// default on): a sub-webhook with failurePolicy=Fail whose backend
// Service reports 0 Ready endpoints for webhookDeadThreshold straight
// is a cluster-wide deadlock — every admission it matches fails closed,
// including the creates that would bring the backend back. The breaker
// flips such entries to Ignore and records their names in the
// node.ops/circuit-broken-webhooks annotation on the config; when the
// Service reports >= 1 Ready endpoint again the declared Fail policy
// is restored and the annotation shrinks (removed when empty).
// W5.5 — the endpoint census is node-aware: Ready endpoints on
// partitioned/unresponsive/NotReady nodes are discounted, and when
// they are ALL that remains the breaker trips on the faster
// partitionZeroThreshold (90s) instead of webhookDeadThreshold.
//
// 2.2 — unmeshed-pod-auditor + post-circuit-breaker healer. Pods
// created while the C1 breaker held linkerd-proxy-injector open run
// WITHOUT their linkerd-proxy sidecar: no mTLS, invisible to service
// mesh policy, and permanently unmeshed (injection happens at admit
// time — nothing re-injects a running pod). Each sweep audits Running
// Pods whose Namespace OR the Pod itself opts into injection
// (linkerd.io/inject=enabled, minus hostNetwork pods, Job/CronJob
// children and explicit inject=disabled opt-outs) and exports
// node_automation_unmeshed_pods{namespace,pod} for every pod missing
// the linkerd-proxy container+initContainer. When the injector
// webhook is provably healthy again — not circuit-broken, failurePolicy
// still Fail, Ready endpoints > 0 — and UNMESHED_POD_REMEDIATION_ENABLED
// is not "false", the auditor EVICTS up to 2 unmeshed pods per cycle
// (only pods >2m old, not already terminating, with a non-Node
// controller ownerReference, so a controller recreates them meshed;
// at most 4 delete attempts so a persistently failing apiserver
// cannot turn the sweep into an API storm) and counts
// node_automation_unmeshed_pods_recreated_total.
// Pods are list/watch-locked in the manager cache (kube-system +
// k8s-app=cilium only), so the audit reads through the direct
// clientset exactly like every other module.
//
// W7-C1 — remediation hardening: before evicting anything the sweep
// holds the shared maintenance mutex (a cordon/drain/kured reboot or
// an in-flight k0s autopilot upgrade defers the work), and the pod
// kill goes through the policy/v1 Eviction API — a raw Delete would
// bypass every PodDisruptionBudget and could take the last Ready
// replica of an already-degraded workload. An apiserver 429 (PDB
// refusing the disruption) is a deferral, not an error: the pod is
// kept and the next candidate is tried.
package webhookguard

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

const (
	webhookGuardQueue = "admission-webhook-guard"

	// kind label values for the WebhookCircuit* metrics — the short
	// forms matching webhookPatch.mutating.
	webhookKindMutating   = "mutating"
	webhookKindValidating = "validating"
)

// webhookGuard is the facade behind the single
// "admission-webhook-guard" periodic: it owns the shared clients, the
// clock and probe seams, and the per-run sweepSnapshot, and embeds the
// three independent sweeps — orphanSweep, circuitBreaker and
// unmeshedPodAuditor — each of which owns only its own state. run()
// invokes them in a fixed order through the promoted methods, so the
// externally visible contract (queue name, interval, metric series)
// is unchanged by the split.
type webhookGuard struct {
	cs kubernetes.Interface
	// dyn feeds the autopilot-Plan signal of the maintenance mutex
	// (W7-C1) — wired through Setup like every other dynamic-client
	// module. A nil dyn (unit tests that build the guard directly)
	// narrows the mutex to the clientset-only signals (node cordon +
	// kured lock) instead of failing closed.
	dyn dynamic.Interface
	// nowFn is the clock seam for the dead-backend streak — tests pin
	// a scripted now to reach past webhookDeadThreshold. nil → time.Now.
	nowFn shared.Clock
	// endpointProber is the W9-CP1 brownout probe — a TCP connect +
	// TLS handshake against a Ready endpoint IP on the webhook port.
	// Injectable for tests; nil falls back to tcpTLSEndpointProber.
	endpointProber func(ctx context.Context, ip string, port int32) bool

	// The three sweeps share cs/dyn/nowFn/endpointProber through
	// snap.g and hand each other nothing else; embedding keeps the
	// guard's method set — and every in-package test fixture — stable
	// across the split.
	orphanSweep
	circuitBreaker
	unmeshedPodAuditor
}

// Setup registers the 5-minute sweep (was crontab */5). dyn feeds
// the autopilot-Plan signal of the maintenance mutex consulted by
// the unmeshed-pod healer (W7-C1).
func Setup(d shared.Deps) error {
	logf.Log.WithName(webhookGuardQueue).Info("registered",
		"interval", 5*time.Minute, "circuitBreaker", circuitBreakerEnabled(),
		"unmeshedRemediation", unmeshedRemediationEnabled())
	// The bookkeeping ledgers (brokenEmitted, unmeshedEmitted,
	// deadSince, bounceAt) are shared.* zero-value types — nothing to
	// initialize here.
	g := &webhookGuard{cs: d.CS, dyn: d.Dyn, nowFn: time.Now}
	return shared.AddPeriodic(d.Mgr, webhookGuardQueue, 5*time.Minute, g.run)
}

// listPageSize bounds every cluster-wide namespaced List below —
// an unbounded all-namespaces EndpointSlice/pod/Service list is a
// heap spike every sweep, so they page through the apiserver's
// continue token instead. The snapshot's cluster-scoped lists
// (Namespaces, Mutating/ValidatingWebhookConfigurations) stay
// unpaged: they are tiny by definition.
const listPageSize = 500

// sweepSnapshot carries the cluster state one run shares across its
// sub-sweeps: the namespace census and both webhook-config lists are
// identical inputs for the orphan sweep, the circuit breaker and the
// unmeshed-pod audit, so they are listed ONCE per run instead of once
// per consumer. A list failure is recorded on the snapshot, not
// returned — every duty still decides for itself whether the missing
// piece aborts it (fail-closed source) or merely skips a check.
type sweepSnapshot struct {
	g   *webhookGuard
	ctx context.Context

	ns     *corev1.NamespaceList
	nsErr  error
	mwc    *admissionv1.MutatingWebhookConfigurationList
	mwcErr error
	vwc    *admissionv1.ValidatingWebhookConfigurationList
	vwcErr error

	// unhealthyNodes is the W5.5 node census: nodes whose Ready
	// endpoints cannot actually serve webhook traffic (NotReady,
	// partitioned, kubelet-unresponsive, unreachable/out-of-service
	// taints, or an explicit NetworkPartitioned condition). The
	// endpoint census discounts endpoints hosted on them.
	unhealthyNodes map[string]bool
	nodesErr       error

	// readyOnce/ready/readyErr lazily cache the EndpointSlice ready
	// census — the circuit breaker and the injector-health check
	// share it, and a run whose breaker is disabled and has no
	// unmeshed candidates never pays for the list at all.
	readyOnce sync.Once
	ready     endpointCensus
	readyErr  error
}

// takeSnapshot lists the shared inputs once — see sweepSnapshot.
func (g *webhookGuard) takeSnapshot(ctx context.Context) *sweepSnapshot {
	s := &sweepSnapshot{g: g, ctx: ctx}
	s.ns, s.nsErr = g.cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	s.mwc, s.mwcErr = g.cs.AdmissionregistrationV1().
		MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	s.vwc, s.vwcErr = g.cs.AdmissionregistrationV1().
		ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	// W5.5 — the node census feeds the effective-ready math: a
	// "Ready" webhook pod on a partitioned node cannot be called by
	// the apiserver, so it must not count toward backend health.
	s.unhealthyNodes = map[string]bool{}
	nodes, err := shared.ListNodes(ctx, g.cs)
	s.nodesErr = err
	if err == nil {
		for i := range nodes {
			if nodeUnhealthyForEndpoints(&nodes[i]) {
				s.unhealthyNodes[nodes[i].Name] = true
			}
		}
	}
	return s
}

// webhookUnhealthyNodeTaints are the taint keys marking a node whose
// pod network is presumed dead for admission purposes — the node.ops
// pair this operator asserts itself plus the kubelet/node-controller
// lifecycle taints.
var webhookUnhealthyNodeTaints = []string{
	"node.ops/network-partitioned",
	"node.ops/kubelet-unresponsive",
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
	if !shared.NodeReady(n) {
		return true
	}
	for _, k := range webhookUnhealthyNodeTaints {
		if shared.HasTaint(n.Spec.Taints, k) {
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

// endpointCensus is the W5.5 dual ready-endpoint count: raw counts
// every Ready endpoint; effective excludes the Ready endpoints whose
// pod sits on an unhealthy node (partitioned/unresponsive — reachable
// in the API sense but dead for webhook traffic).
//
// W9-CP1 adds the brownout fields, populated ONLY for services a
// webhook config's clientConfig.service references (the probeSet in
// readyEndpointCounts — probing every Service cluster-wide would be
// a dial storm):
//   - probeIPs/probePort: up to webhookProbeMaxPerSvc Ready endpoint
//     IPs on healthy nodes plus the port the handshake targets.
//   - backingPods: Ready endpoint pod refs for the stage-1 bounce.
//   - probed/responsive: per-service handshake outcome — probed marks
//     a service whose endpoints were actually dialed this run;
//     responsive is true when ANY probed IP completed TCP+TLS. A
//     probed service with responsive=false is "unresponsive": its
//     pods are hung, which the breaker treats as effective=0.
type endpointCensus struct {
	raw       map[string]int
	effective map[string]int
	probeIPs  map[string][]string
	probePort map[string]int32
	// podRef identifies one Ready endpoint's backing Pod — the
	// bounce candidates for an unresponsive service.
	backingPods map[string][]podRef
	probed      map[string]bool
	responsive  map[string]bool
}

// podRef is a namespace/name pair for a Pod discovered through an
// EndpointSlice targetRef.
type podRef struct{ namespace, name string }

// readyCounts returns the EndpointSlice ready census, listing it at
// most once per run — the circuit breaker and the injector-health
// check both draw from the same result, including the same error.
func (s *sweepSnapshot) readyCounts() (endpointCensus, error) {
	s.readyOnce.Do(func() {
		s.ready, s.readyErr = s.g.readyEndpointCounts(s.ctx, s)
	})
	return s.ready, s.readyErr
}

func (g *webhookGuard) now() time.Time {
	if g.nowFn != nil {
		return g.nowFn()
	}
	return time.Now()
}

func (g *webhookGuard) run(ctx context.Context) error {
	// The orphan sweep, the circuit breaker and the unmeshed-pod
	// auditor are independent duties — a failure in one must never
	// skip the others, so all run and their errors join
	// (nil+nil+nil → nil). All three read the same cluster state, so
	// the shared snapshot is listed once up front instead of once per
	// consumer.
	snap := g.takeSnapshot(ctx)
	orphanErr := g.sweepOrphans(ctx, snap)
	var breakerErr error
	if circuitBreakerEnabled() {
		breakerErr = g.sweepCircuitBreaker(ctx, snap)
	}
	unmeshedErr := g.sweepUnmeshedPods(ctx, snap)
	return errors.Join(orphanErr, breakerErr, unmeshedErr)
}

// readyEndpointCounts builds the ns/service → Ready-endpoint census
// from the cluster-wide EndpointSlice list (paged — see listPageSize),
// in TWO counts (W5.5): raw counts every Ready endpoint; effective
// drops the endpoints whose NodeName is flagged unhealthy by the
// node census — a "Ready" pod on a partitioned node still fails every
// apiserver webhook call. The kubernetes.io/service-name label binds
// each slice to its Service; a nil conditions.ready counts as ready
// (the field defaults to true server-side). No degraded mode: without
// a complete census "0 ready" is indistinguishable from "no data", so
// a list error — endpoints OR nodes — skips the whole breaker rather
// than trip healthy webhooks.
func (g *webhookGuard) readyEndpointCounts(ctx context.Context, snap *sweepSnapshot) (endpointCensus, error) {
	if snap.nodesErr != nil {
		return endpointCensus{}, fmt.Errorf("list nodes — circuit breaker skipped: %w", snap.nodesErr)
	}
	ready := endpointCensus{
		raw:         map[string]int{},
		effective:   map[string]int{},
		probeIPs:    map[string][]string{},
		probePort:   map[string]int32{},
		backingPods: map[string][]podRef{},
		probed:      map[string]bool{},
		responsive:  map[string]bool{},
	}
	// W9-CP1 — only Services a webhook config actually calls get
	// probed: the brownout check exists to keep admission webhooks
	// honest, and dialing every Service in the cluster would be a
	// handshake storm for zero signal. A missing config list (API
	// flap) yields an empty probeSet — the census still counts, the
	// breaker just sees no probe data (unresponsive stays false).
	probeSet := webhookBackendServices(snap)
	err := shared.ListEach(ctx,
		metav1.ListOptions{Limit: listPageSize},
		shared.EndpointSlices(g.cs, metav1.NamespaceAll),
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
						ready.raw[key]++
						// A nil NodeName (off-cluster target, not yet
						// bound) cannot be attributed to a bad node —
						// benefit of the doubt, count it effective.
						effective := ep.NodeName == nil || !snap.unhealthyNodes[*ep.NodeName]
						if effective {
							ready.effective[key]++
						}
						// W9-CP1 — collect probe candidates and backing
						// pod refs ONLY for effective-ready endpoints on
						// webhook backends: endpoints stranded on
						// unhealthy nodes are already discounted, and
						// probing them would just re-measure the
						// partition.
						if probeSvc && effective {
							g.collectProbeCandidates(&ready, key, &s, &ep)
						}
					}
				}
			}
			return nil
		})
	if err != nil {
		return endpointCensus{}, fmt.Errorf("list endpointslices — circuit breaker skipped: %w", err)
	}
	// W9-CP1 — TCP+TLS brownout probe, up to webhookProbeMaxPerSvc
	// Ready endpoint IPs per webhook backend. responsive is an
	// ANY-success verdict: one answering endpoint means the Service
	// is not brownout-hung even if siblings are.
	prober := g.endpointProber
	if prober == nil {
		prober = tcpTLSEndpointProber
	}
	for key, ips := range ready.probeIPs {
		ready.probed[key] = true
		ok := false
		for _, ip := range ips {
			if prober(ctx, ip, ready.probePort[key]) {
				ok = true
				break
			}
		}
		ready.responsive[key] = ok
	}
	return ready, nil
}

// webhookBackendServices returns the set of "namespace/name" Service
// keys referenced by any sub-webhook's clientConfig.service across
// both webhook-config kinds — the only services the W9-CP1 probe
// dials. Nil config lists (API flap) contribute nothing.
func webhookBackendServices(snap *sweepSnapshot) map[string]bool {
	out := map[string]bool{}
	add := func(svc *admissionv1.ServiceReference) {
		if svc != nil && svc.Namespace != "" && svc.Name != "" {
			out[svc.Namespace+"/"+svc.Name] = true
		}
	}
	if snap.mwc != nil {
		for i := range snap.mwc.Items {
			for _, h := range mutHookViews(snap.mwc.Items[i].Webhooks) {
				add(h.svc)
			}
		}
	}
	if snap.vwc != nil {
		for i := range snap.vwc.Items {
			for _, h := range valHookViews(snap.vwc.Items[i].Webhooks) {
				add(h.svc)
			}
		}
	}
	return out
}

// collectProbeCandidates records one effective-ready endpoint's
// address (up to webhookProbeMaxPerSvc distinct IPs) and its backing
// Pod ref (up to webhookProbeMaxPodRefs) for service key — the probe
// and bounce inputs of the W9-CP1 brownout path.
func (g *webhookGuard) collectProbeCandidates(ready *endpointCensus,
	key string, s *discoveryv1.EndpointSlice, ep *discoveryv1.Endpoint) {
	if len(ready.probeIPs[key]) < webhookProbeMaxPerSvc && len(ep.Addresses) > 0 {
		for _, addr := range ep.Addresses {
			if !slices.Contains(ready.probeIPs[key], addr) {
				ready.probeIPs[key] = append(ready.probeIPs[key], addr)
				break
			}
		}
	}
	if _, ok := ready.probePort[key]; !ok {
		// The webhook port: the slice's first declared port, default
		// 443 — admission webhooks are HTTPS-only, and a slice with
		// no ports still targets the Service's own port mapping.
		port := int32(webhookProbeDefaultPort)
		for _, p := range s.Ports {
			if p.Port != nil {
				port = *p.Port
				break
			}
		}
		ready.probePort[key] = port
	}
	if ep.TargetRef != nil && ep.TargetRef.Kind == "Pod" && ep.TargetRef.Name != "" {
		ns := ep.TargetRef.Namespace
		if ns == "" {
			ns = s.Namespace // endpointSlice-local pods carry no namespace on the ref
		}
		ref := podRef{namespace: ns, name: ep.TargetRef.Name}
		if len(ready.backingPods[key]) < webhookProbeMaxPodRefs &&
			!slices.Contains(ready.backingPods[key], ref) {
			ready.backingPods[key] = append(ready.backingPods[key], ref)
		}
	}
}

// tcpTLSEndpointProber is the production endpointProber: a 2s
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
		&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // liveness probe only
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// maintenanceActive runs the cluster maintenance mutex (W7-C1) —
// the shared three-signal check when a dynamic client is wired
// (node cordon + kured lock + autopilot Plan), narrowed to the
// clientset-only signals (node cordon + kured lock) when it is not:
// a missing dyn is a test-only construction, so the check degrades
// instead of failing closed like a real client outage must.
func (g *webhookGuard) maintenanceActive(ctx context.Context) (bool, string, error) {
	if g.dyn != nil {
		return shared.MaintenanceActive(ctx, g.cs, g.dyn)
	}
	nodes, err := shared.ListNodes(ctx, g.cs)
	if err != nil {
		return false, "", fmt.Errorf("list nodes (maintenance mutex): %w", err)
	}
	for i := range nodes {
		if nodes[i].Spec.Unschedulable {
			return true, "node " + nodes[i].Name + " unschedulable", nil
		}
	}
	ds, err := g.cs.AppsV1().DaemonSets(shared.KuredDaemonSetNS).
		Get(ctx, shared.KuredDaemonSetName, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		// kured not installed — no signal.
	case err != nil:
		return false, "", fmt.Errorf("get daemonset %s/%s (maintenance mutex): %w",
			shared.KuredDaemonSetNS, shared.KuredDaemonSetName, err)
	default:
		if v := ds.Annotations[shared.KuredLockAnno]; v != "" {
			return true, "kured lock held by " + v, nil
		}
	}
	return false, "", nil
}
