// guard.go — the shared dep bundle and the per-run Snapshot every
// webhookguard duty draws from: Guard carries the clients, queue
// name, clock, probe seam and maintenance-mutex verdict the sweeps
// reach through snap.G, and Snapshot is the once-per-run cluster
// census (namespaces, both webhook-config lists, CRDs, node health)
// plus the lazily-computed ready-endpoint census.
package guardstate

import (
	"context"
	"errors"
	"sync"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

// EndpointProber is the circuit-breaker-bounce brownout probe seam — a TCP connect +
// TLS handshake against a Ready endpoint IP on the webhook port.
// Injectable for tests; a nil Guard.EndpointProber falls back to
// tcpTLSEndpointProber.
type EndpointProber func(ctx context.Context, ip string, port int32) bool

// Guard bundles the deps every webhookguard duty shares — the direct
// clientset, the dynamic client (autopilot-Plan signal of the
// maintenance mutex, unmeshed-pod-auditor), the ops queue name every IncError label
// is stamped from, the clock seam, the brownout probe seam, and the
// verdict memoizing the maintenance-mutex evaluation the pod-kill
// paths share within a run. The facade embeds it so the sweep state
// and the deps live on one object across runs.
type Guard struct {
	CS    kubernetes.Interface
	Dyn   dynamic.Interface
	Queue string
	// Now is the clock seam for the dead-backend streak — tests pin
	// a scripted now to reach past the dead threshold. A nil Clock
	// reads as system time (shared.Clock.Now is nil-safe).
	Now shared.Clock
	// EndpointProber is the circuit-breaker-bounce brownout probe — injectable for
	// tests; nil falls back to tcpTLSEndpointProber.
	EndpointProber EndpointProber
	// Verdict memoizes the maintenance-mutex evaluation the unmeshed-pod-auditor
	// gates (pod bounce + unmeshed remediation) share within a run —
	// one evaluation per Verdict TTL instead of three API reads per
	// consumer.
	Verdict kube.Verdict
	// NodeReader backs ListNodesCached — the manager's
	// informer-backed client. A nil reader (literally-built test
	// fixtures) falls back to the direct clientset read.
	NodeReader kube.CachedNodeReader
}

// Snapshot carries the cluster state one run shares across its
// sub-sweeps: the namespace census and both webhook-config lists are
// identical inputs for the orphan sweep, the circuit breaker and the
// unmeshed-pod audit, so they are listed ONCE per run instead of once
// per consumer.
type Snapshot struct {
	G   *Guard
	Ctx context.Context

	NS     *corev1.NamespaceList
	NSErr  error
	MWC    *admissionv1.MutatingWebhookConfigurationList
	MWCErr error
	VWC    *admissionv1.ValidatingWebhookConfigurationList
	VWCErr error

	// CRDs feeds the conversion-webhook duties — the orphan sweep's
	// missing-backend warn and the unhealthy-backend gauge + pod
	// bounce. A list failure degrades those duties only: the
	// admission sweeps never see the error.
	CRDs   []unstructured.Unstructured
	CRDErr error

	// UnhealthyNodes is the endpoint-census node census: nodes whose Ready
	// endpoints cannot actually serve webhook traffic (NotReady,
	// partitioned, kubelet-unresponsive, unreachable/out-of-service
	// taints, or an explicit NetworkPartitioned condition). The
	// endpoint census discounts endpoints hosted on them.
	UnhealthyNodes map[string]bool
	NodesErr       error

	// Services is the cluster-wide Service census the probe-port
	// resolver and the ready-endpoint math share — the orphansweep
	// already pays for the same LIST; taking it once here removes
	// the per-backend Services(ns).Get fan-out. A list failure is
	// recorded like every other snapshot input: consumers degrade
	// to their no-data verdicts.
	Services    []corev1.Service
	ServicesErr error

	// readyOnce/ready/readyErr lazily cache the EndpointSlice ready
	// census — the circuit breaker and the injector-health check
	// share it, and a run whose breaker is disabled and has no
	// unmeshed candidates never pays for the list at all.
	readyOnce sync.Once
	ready     EndpointCensus
	readyErr  error
}

// TakeSnapshot lists the shared inputs once — see Snapshot. A list
// failure is recorded on the snapshot, not returned — every duty
// still decides for itself whether the missing piece aborts it
// (fail-closed source) or merely skips a check.
func (g *Guard) TakeSnapshot(ctx context.Context) *Snapshot {
	s := &Snapshot{G: g, Ctx: ctx}
	// Paged censuses — the bare List calls below used to rely on the
	// apiserver's default page size; on a cluster past it the webhook
	// duties silently audited a truncated census.
	opts := metav1.ListOptions{Limit: ListPageSize}
	if items, err := kube.ListAll(ctx, opts, kube.Namespaces(g.CS)); err != nil {
		s.NSErr = err
	} else {
		s.NS = &corev1.NamespaceList{Items: items}
	}
	if items, err := kube.ListAll(ctx, opts,
		kube.MutatingWebhookConfigurations(g.CS)); err != nil {
		s.MWCErr = err
	} else {
		s.MWC = &admissionv1.MutatingWebhookConfigurationList{Items: items}
	}
	if items, err := kube.ListAll(ctx, opts,
		kube.ValidatingWebhookConfigurations(g.CS)); err != nil {
		s.VWCErr = err
	} else {
		s.VWC = &admissionv1.ValidatingWebhookConfigurationList{Items: items}
	}
	// endpoint-census — the node census feeds the effective-ready math: a
	// "Ready" webhook pod on a partitioned node cannot be called by
	// the apiserver, so it must not count toward backend health.
	s.UnhealthyNodes = map[string]bool{}
	nodes, err := kube.ListNodesCached(ctx, g.NodeReader, g.CS)
	s.NodesErr = err
	if err == nil {
		for i := range nodes {
			if nodeUnhealthyForEndpoints(&nodes[i]) {
				s.UnhealthyNodes[nodes[i].Name] = true
			}
		}
	}
	// Conversion-webhook CRDs — listed once here because the orphan
	// sweep and the backend-health sweep both read them. A missing
	// dynamic client or a list error is recorded, not fatal: the
	// admission duties above already have their inputs.
	if g.Dyn == nil {
		s.CRDErr = errors.New("no dynamic client — CRD list skipped")
	} else {
		// ListEach at the CRD page bound: each page's full objects
		// (OpenAPI schemas included) are projected to name +
		// spec.conversion inside the visit and die with the page —
		// retaining the raw census pinned ~80–150 MiB of schema for
		// the whole run. The duties only ever read spec.conversion.*
		// and the name, so the compact objects are value-identical
		// for every consumer.
		s.CRDErr = kube.ListEach(ctx,
			metav1.ListOptions{Limit: crdPageSize},
			kube.DynamicPage(g.Dyn.Resource(kube.GVRCustomResourceDefinition)),
			func(page []unstructured.Unstructured) error {
				for i := range page {
					s.CRDs = append(s.CRDs,
						compactCRDConversion(&page[i]))
				}
				return nil
			})
	}
	// Services — paged cluster census shared by the probe-port
	// resolver (was one Get per webhook backend) and any duty that
	// needs Service spec data.
	s.Services, s.ServicesErr = kube.ListAll(ctx,
		metav1.ListOptions{Limit: ListPageSize},
		kube.Services(g.CS, metav1.NamespaceAll))
	return s
}

// SetMWC writes a just-patched MutatingWebhookConfiguration back
// into the snapshot — every duty that patches a config (orphan
// entry drops, circuit-breaker failurePolicy flips) must keep the
// shared view current or the later duties (the unmeshed
// injector-health read, the next circuitPatch evaluation) act on
// stale webhook entries. A name absent from the list is ignored.
func (s *Snapshot) SetMWC(cfg *admissionv1.MutatingWebhookConfiguration) {
	if s.MWC == nil || cfg == nil {
		return
	}
	for i := range s.MWC.Items {
		if s.MWC.Items[i].Name == cfg.Name {
			s.MWC.Items[i] = *cfg
			return
		}
	}
}

// SetVWC is the ValidatingWebhookConfiguration twin of SetMWC.
func (s *Snapshot) SetVWC(cfg *admissionv1.ValidatingWebhookConfiguration) {
	if s.VWC == nil || cfg == nil {
		return
	}
	for i := range s.VWC.Items {
		if s.VWC.Items[i].Name == cfg.Name {
			s.VWC.Items[i] = *cfg
			return
		}
	}
}

// ReadyCounts returns the EndpointSlice ready census, listing it at
// most once per run — the circuit breaker and the injector-health
// check both draw from the same result, including the same error.
func (s *Snapshot) ReadyCounts() (EndpointCensus, error) {
	s.readyOnce.Do(func() {
		if s.Ctx == nil {
			// Literally-built test fixtures carry no ctx — the probe
			// pool reads ctx.Err(), which would nil-deref otherwise.
			s.Ctx = context.Background()
		}
		s.ready, s.readyErr = s.G.readyEndpointCounts(s.Ctx, s)
	})
	return s.ready, s.readyErr
}
