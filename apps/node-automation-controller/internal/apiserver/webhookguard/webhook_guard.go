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
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

const (
	webhookGuardQueue = "admission-webhook-guard"

	// webhookCircuitAnno records, on the webhook config object itself,
	// the comma-separated names of the sub-webhooks the C1 circuit
	// breaker flipped to failurePolicy=Ignore — the trip record
	// survives pod restarts and is human-readable in kubectl describe.
	// Comma-separated is unambiguous: webhook names are DNS-1123
	// subdomains, which can never contain a comma.
	webhookCircuitAnno = "node.ops/circuit-broken-webhooks"

	// webhookDeadThreshold is how long a fail-closed sub-webhook's
	// backend Service must report 0 Ready endpoints before the breaker
	// trips it to Ignore.
	webhookDeadThreshold = 5 * time.Minute
	// webhookPartitionedThreshold is the faster trip window used when
	// the Service still reports Ready endpoints but EVERY one sits on
	// a partitioned/unresponsive node (W5.5): those pods cannot serve
	// the apiserver's webhook calls, so the deadlock is real now — 90s
	// of that condition is already an outage, no need to wait out the
	// full dead-backend window.
	webhookPartitionedThreshold = 90 * time.Second

	// kind label values for the WebhookCircuit* metrics — the short
	// forms matching webhookPatch.mutating.
	webhookKindMutating   = "mutating"
	webhookKindValidating = "validating"

	// linkerdInjectKey is the label/annotation both linkerd and this
	// auditor read on Namespaces and Pods: enabled opts in, disabled
	// opts out.
	linkerdInjectKey = "linkerd.io/inject"
	// linkerdProxyContainer is the sidecar name injection adds — a
	// pod carrying it in containers OR initContainers counts as
	// meshed.
	linkerdProxyContainer = "linkerd-proxy"
	// linkerdInjectorWebhook is the injector's full sub-webhook name
	// inside the MutatingWebhookConfiguration — matched exactly so a
	// similarly-named webhook (e.g. "acme-linkerd-proxy-injector.example.com")
	// can never impersonate the health signal.
	linkerdInjectorWebhook = "linkerd-proxy-injector.linkerd.io"
	// unmeshedMinPodAge: a pod must be this old before deletion —
	// younger pods may simply be mid-admission/mid-start.
	unmeshedMinPodAge = 2 * time.Minute
	// unmeshedDeleteCap bounds successful remediation per cycle — the
	// owner controller recreates each pod, so slow rolling is safer
	// than a sweep-wide delete burst.
	unmeshedDeleteCap = 2
	// unmeshedDeleteAttempts bounds delete ATTEMPTS per cycle —
	// without it a persistently failing delete (RBAC drift, an
	// apiserver in partial outage) would be retried for every
	// candidate, turning the sweep itself into an API storm.
	unmeshedDeleteAttempts = 4
)

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
	nowFn func() time.Time
	// deadSince is the first-seen timestamp of each
	// kind/config/sub-webhook sighted fail-closed against a Service
	// with 0 Ready endpoints. A sighting that disappears (endpoints
	// back, entry removed) resets the streak.
	deadSince map[string]time.Time
	// brokenEmitted is the ledger of WebhookCircuitBroken label tuples
	// ("kind/config/webhook") currently held at =1. Each sweep
	// rebuilds it from the triples it re-asserted; a tuple not
	// re-seen — config deleted, recreated without the annotation,
	// entry pruned by the orphan sweep — gets its series deleted via
	// DeleteLabelValues instead of pinning the alert forever (same
	// seen-set hygiene as the cert drift auditor).
	brokenEmitted map[string]bool
	// unmeshedEmitted is the same ledger for UnmeshedPods
	// ("namespace/pod") — deleted pods and pods that gained the
	// sidecar get their series pruned each sweep.
	unmeshedEmitted map[string]bool
	// zeroThreshold / partitionZeroThreshold override the two trip
	// windows — tests shrink them; a zero value falls back to
	// webhookDeadThreshold / webhookPartitionedThreshold.
	zeroThreshold          time.Duration
	partitionZeroThreshold time.Duration
}

// Setup registers the 5-minute sweep (was crontab */5). dyn feeds
// the autopilot-Plan signal of the maintenance mutex consulted by
// the unmeshed-pod healer (W7-C1).
func Setup(mgr ctrl.Manager, cs kubernetes.Interface, dyn dynamic.Interface) error {
	logf.Log.WithName(webhookGuardQueue).Info("registered",
		"interval", 5*time.Minute, "circuitBreaker", circuitBreakerEnabled())
	g := &webhookGuard{cs: cs, dyn: dyn, nowFn: time.Now,
		deadSince:       map[string]time.Time{},
		brokenEmitted:   map[string]bool{},
		unmeshedEmitted: map[string]bool{}}
	return shared.AddPeriodic(mgr, webhookGuardQueue, 5*time.Minute, g.run)
}

// circuitBreakerEnabled reads the kill-switch every run — an env flip
// takes effect on the next sweep without a code change.
func circuitBreakerEnabled() bool {
	return os.Getenv("WEBHOOK_CIRCUIT_BREAKER_ENABLED") != "false"
}

// webhookPatch is one queued strategic-merge patch on a single
// config's /webhooks list (bash did per-index removes; the merge-key
// patch is the equivalent that cannot shift indices mid-patch AND
// cannot revert a concurrent writer's entries — see collect).
type webhookPatch struct {
	mutating bool
	name     string
	payload  []byte
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
type endpointCensus struct {
	raw       map[string]int
	effective map[string]int
}

// readyCounts returns the EndpointSlice ready census, listing it at
// most once per run — the circuit breaker and the injector-health
// check both draw from the same result, including the same error.
func (s *sweepSnapshot) readyCounts() (endpointCensus, error) {
	s.readyOnce.Do(func() {
		s.ready, s.readyErr = s.g.readyEndpointCounts(s.ctx, s)
	})
	return s.ready, s.readyErr
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

func (g *webhookGuard) sweepOrphans(ctx context.Context, snap *sweepSnapshot) error {
	log := logf.FromContext(ctx)

	// Namespace snapshot — the ONLY source of "deleted" truth. Any error
	// or a missing kube-system means API flap: abort, patch nothing.
	if snap.nsErr != nil {
		return fmt.Errorf("list namespaces (API flap) — abort: %w", snap.nsErr)
	}
	namespaces := make(map[string]bool, len(snap.ns.Items))
	for _, ns := range snap.ns.Items {
		namespaces[ns.Name] = true
	}
	if !namespaces["kube-system"] {
		return fmt.Errorf("kube-system absent from namespace list (API flap) — abort")
	}

	// Service snapshot feeds only the WARN branch — a failure here
	// degrades to namespace-only checking, it must not block orphans.
	// Paged like every cluster-wide list in this module.
	haveSvc := true
	services := map[string]bool{}
	svcOpts := metav1.ListOptions{Limit: listPageSize}
	for {
		svcList, err := g.cs.CoreV1().Services(metav1.NamespaceAll).List(ctx, svcOpts)
		if err != nil {
			metrics.IncError(webhookGuardQueue)
			log.Info("WARN: cannot list services — skipping service check (namespace check still runs)", "error", err)
			haveSvc = false
			break
		}
		for _, s := range svcList.Items {
			services[s.Namespace+"/"+s.Name] = true
		}
		if svcList.Continue == "" {
			break
		}
		svcOpts.Continue = svcList.Continue
	}

	if snap.mwcErr != nil {
		return fmt.Errorf("list mutatingwebhookconfigurations (API flap) — abort: %w", snap.mwcErr)
	}
	if snap.vwcErr != nil {
		return fmt.Errorf("list validatingwebhookconfigurations (API flap) — abort: %w", snap.vwcErr)
	}
	mwc, vwc := snap.mwc, snap.vwc

	var patches []webhookPatch
	// collect queues ONE strategic-merge patch per config listing every
	// orphan entry as {"name": X, "$patch": "delete"}: the webhooks
	// list is patchMergeKey=name + patchStrategy=merge (and
	// +listType=map), so each removal deletes by merge key instead of
	// re-serializing the whole array from our List snapshot. A
	// concurrent writer's entry — cainjector rotating caBundle, GitOps
	// adding a webhook — is merged around, never silently reverted.
	collect := func(mutating bool, cfgName string, removed []string) {
		if len(removed) == 0 {
			return
		}
		dels := make([]map[string]any, 0, len(removed))
		for _, name := range removed {
			dels = append(dels, map[string]any{"name": name, "$patch": "delete"})
		}
		payload, err := json.Marshal(map[string]any{"webhooks": dels})
		if err != nil {
			// Absorbed sub-failure: the sweep logs and continues —
			// metered so the dropped work is still counted.
			metrics.IncError(webhookGuardQueue)
			log.Error(err, "marshal webhook patch",
				"config", cfgName, "mutating", mutating)
			return
		}
		patches = append(patches, webhookPatch{mutating: mutating, name: cfgName, payload: payload})
	}

	for _, cfg := range mwc.Items {
		var removed []string
		for i, w := range cfg.Webhooks {
			if g.orphanEntry(log, "mutatingwebhookconfigurations", cfg.Name, i, w.ClientConfig.Service, namespaces, services, haveSvc) {
				removed = append(removed, w.Name)
			}
		}
		collect(true, cfg.Name, removed)
	}
	for _, cfg := range vwc.Items {
		var removed []string
		for i, w := range cfg.Webhooks {
			if g.orphanEntry(log, "validatingwebhookconfigurations", cfg.Name, i, w.ClientConfig.Service, namespaces, services, haveSvc) {
				removed = append(removed, w.Name)
			}
		}
		collect(false, cfg.Name, removed)
	}

	if len(patches) == 0 {
		log.Info("sweep done: no orphan admission webhooks")
		return nil
	}

	failed := false
	for _, p := range patches {
		kind := webhookKindValidating
		if p.mutating {
			kind = webhookKindMutating
		}
		log.Info("PATCH: drop orphan entries by merge key",
			"kind", kind, "config", p.name)
		var err error
		if p.mutating {
			_, err = g.cs.AdmissionregistrationV1().MutatingWebhookConfigurations().Patch(ctx, p.name, types.StrategicMergePatchType, p.payload, metav1.PatchOptions{})
		} else {
			_, err = g.cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().Patch(ctx, p.name, types.StrategicMergePatchType, p.payload, metav1.PatchOptions{})
		}
		if err != nil {
			log.Error(err, "webhook config patch failed",
				"kind", kind, "config", p.name)
			failed = true
		}
	}
	if failed {
		return fmt.Errorf("some webhook config patches failed — orphan webhooks may remain")
	}
	log.Info("sweep done: removed orphan webhook entries (namespace deleted)",
		"configsPatched", len(patches))
	return nil
}

// orphanEntry classifies one webhook entry. Returns true only when the
// backend Service's namespace is gone (→ caller drops the entry).
// A missing Service in a still-live namespace warns and is never patched.
func (g *webhookGuard) orphanEntry(log logr.Logger, kind, cfg string, idx int, svcRef *admissionv1.ServiceReference, namespaces, services map[string]bool, haveSvc bool) bool {
	if svcRef == nil || svcRef.Namespace == "" {
		return false // malformed/no-service entry — not an orphan
	}
	if !namespaces[svcRef.Namespace] {
		log.Info(fmt.Sprintf("ORPHAN: %s/%s webhook[%d] -> %s/%s (namespace gone) — removing entry",
			kind, cfg, idx, svcRef.Namespace, svcRef.Name))
		return true
	}
	if haveSvc && !services[svcRef.Namespace+"/"+svcRef.Name] {
		log.Info(fmt.Sprintf("WARN: %s/%s webhook[%d] -> %s/%s (Service missing) — warn only, not patched",
			kind, cfg, idx, svcRef.Namespace, svcRef.Name))
	}
	return false
}

// ---------------------------------------------------------------------------
// C1 — admission webhook self-deadlock circuit breaker.
// ---------------------------------------------------------------------------

func (g *webhookGuard) now() time.Time {
	if g.nowFn != nil {
		return g.nowFn()
	}
	return time.Now()
}

// sweepCircuitBreaker trips fail-closed sub-webhooks whose backend
// Service has reported 0 Ready endpoints continuously for
// webhookDeadThreshold, and restores previously tripped entries once
// the Service has endpoints again. It runs after the orphan sweep so
// it always evaluates post-prune state; a patch failure on one config
// is logged and the sweep continues with the rest.
func (g *webhookGuard) sweepCircuitBreaker(ctx context.Context, snap *sweepSnapshot) error {
	log := logf.FromContext(ctx)
	now := g.now()
	if g.deadSince == nil {
		g.deadSince = map[string]time.Time{}
	}
	if g.brokenEmitted == nil {
		g.brokenEmitted = map[string]bool{}
	}

	ready, err := snap.readyCounts()
	if err != nil {
		return err
	}
	if snap.mwcErr != nil {
		return fmt.Errorf("list mutatingwebhookconfigurations — circuit breaker skipped: %w", snap.mwcErr)
	}
	if snap.vwcErr != nil {
		return fmt.Errorf("list validatingwebhookconfigurations — circuit breaker skipped: %w", snap.vwcErr)
	}
	mwcs, vwcs := snap.mwc, snap.vwc

	// seen marks the deadSince keys still under evaluation — streaks
	// for entries gone since the last sweep are pruned below.
	seen := map[string]bool{}
	// emitted collects the WebhookCircuitBroken label tuples
	// re-asserted at =1 this sweep — the new brokenEmitted ledger.
	emitted := map[string]bool{}
	var failed []string
	for i := range mwcs.Items {
		cfg := &mwcs.Items[i]
		payload, trips, recovered := g.circuitPatch(log, webhookKindMutating,
			cfg.Name, cfg.Annotations[webhookCircuitAnno],
			mutHookViews(cfg.Webhooks), ready, now, seen, emitted)
		if payload == nil {
			continue
		}
		if _, err := g.cs.AdmissionregistrationV1().MutatingWebhookConfigurations().
			Patch(ctx, cfg.Name, types.StrategicMergePatchType, payload, metav1.PatchOptions{}); err != nil {
			log.Error(err, "circuit breaker patch failed",
				"kind", webhookKindMutating, "config", cfg.Name)
			failed = append(failed, cfg.Name)
			continue
		}
		circuitMetrics(emitted, webhookKindMutating, cfg.Name, trips, recovered)
	}
	for i := range vwcs.Items {
		cfg := &vwcs.Items[i]
		payload, trips, recovered := g.circuitPatch(log, webhookKindValidating,
			cfg.Name, cfg.Annotations[webhookCircuitAnno],
			valHookViews(cfg.Webhooks), ready, now, seen, emitted)
		if payload == nil {
			continue
		}
		if _, err := g.cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().
			Patch(ctx, cfg.Name, types.StrategicMergePatchType, payload, metav1.PatchOptions{}); err != nil {
			log.Error(err, "circuit breaker patch failed",
				"kind", webhookKindValidating, "config", cfg.Name)
			failed = append(failed, cfg.Name)
			continue
		}
		circuitMetrics(emitted, webhookKindValidating, cfg.Name, trips, recovered)
	}

	// Prune broken series whose label tuple was not re-seen — a config
	// deleted while broken, recreated without the annotation, or an
	// entry removed must not pin circuit_broken=1 forever. Keys are
	// "kind/config/webhook"; all three are DNS-1123 identifiers so "/"
	// is unambiguous (same SplitN convention as the PDB watchdog).
	for k := range g.brokenEmitted {
		if emitted[k] {
			continue
		}
		if parts := strings.SplitN(k, "/", 3); len(parts) == 3 {
			metrics.WebhookCircuitBroken.
				DeleteLabelValues(parts[0], parts[1], parts[2])
		}
	}
	g.brokenEmitted = emitted

	for k := range g.deadSince {
		if !seen[k] {
			delete(g.deadSince, k)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("circuit breaker patches failed for: %s",
			strings.Join(failed, ", "))
	}
	return nil
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
	ready := endpointCensus{raw: map[string]int{}, effective: map[string]int{}}
	opts := metav1.ListOptions{Limit: listPageSize}
	for {
		sliceList, err := g.cs.DiscoveryV1().EndpointSlices(metav1.NamespaceAll).
			List(ctx, opts)
		if err != nil {
			return endpointCensus{}, fmt.Errorf("list endpointslices — circuit breaker skipped: %w", err)
		}
		for _, s := range sliceList.Items {
			svc := s.Labels[discoveryv1.LabelServiceName]
			if svc == "" {
				continue // no owning Service — cannot map to a webhook backend
			}
			key := s.Namespace + "/" + svc
			for _, ep := range s.Endpoints {
				if ep.Conditions.Ready == nil || *ep.Conditions.Ready {
					ready.raw[key]++
					// A nil NodeName (off-cluster target, not yet
					// bound) cannot be attributed to a bad node —
					// benefit of the doubt, count it effective.
					if ep.NodeName == nil || !snap.unhealthyNodes[*ep.NodeName] {
						ready.effective[key]++
					}
				}
			}
		}
		if sliceList.Continue == "" {
			return ready, nil
		}
		opts.Continue = sliceList.Continue
	}
}

// hookView is the breaker's uniform projection over MutatingWebhook /
// ValidatingWebhook — identical relevant fields, distinct Go types.
type hookView struct {
	name string
	fp   *admissionv1.FailurePolicyType
	svc  *admissionv1.ServiceReference
}

func mutHookViews(ws []admissionv1.MutatingWebhook) []hookView {
	out := make([]hookView, len(ws))
	for i := range ws {
		out[i] = hookView{
			name: ws[i].Name, fp: ws[i].FailurePolicy,
			svc: ws[i].ClientConfig.Service,
		}
	}
	return out
}

func valHookViews(ws []admissionv1.ValidatingWebhook) []hookView {
	out := make([]hookView, len(ws))
	for i := range ws {
		out[i] = hookView{
			name: ws[i].Name, fp: ws[i].FailurePolicy,
			svc: ws[i].ClientConfig.Service,
		}
	}
	return out
}

// tripThreshold picks the dead-backend streak window for this webhook:
// when the Service still reports Ready endpoints but every one sits on
// a partitioned/unresponsive node (raw > 0, effective == 0) the
// deadlock is already real — the shorter partition threshold applies;
// a genuinely empty backend keeps the full dead threshold. The fields
// are test seams; zero values fall back to the package defaults.
func (g *webhookGuard) tripThreshold(rawReady int) time.Duration {
	if rawReady > 0 {
		if g.partitionZeroThreshold > 0 {
			return g.partitionZeroThreshold
		}
		return webhookPartitionedThreshold
	}
	if g.zeroThreshold > 0 {
		return g.zeroThreshold
	}
	return webhookDeadThreshold
}

// circuitPatch evaluates one config's sub-webhooks against the ready
// census and builds the strategic-merge patch that flips long-dead
// entries to Ignore, restores recovered ones to Fail and rewrites the
// circuit-broken annotation (merge-patch null removes the key when the
// set empties). hooks views the config's live webhook list; each
// changed entry lands in the patch as {"name": X, "failurePolicy":
// ...} — the webhooks list is patchMergeKey=name + patchStrategy=merge
// (+listType=map), so only the touched element's failurePolicy is
// rewritten and a concurrent writer's sibling entries survive instead
// of being reverted by a whole-array reserialize. emitted records the
// WebhookCircuitBroken label tuples re-asserted at =1 this sweep — the
// caller rebuilds the guard's series ledger from it and prunes
// whatever was not re-seen. Returns nil payload when nothing changed;
// trips/recovered are the names whose metric updates the caller must
// apply only after the patch lands.
func (g *webhookGuard) circuitPatch(log logr.Logger, kind, cfgName, annoVal string,
	hooks []hookView, ready endpointCensus, now time.Time,
	seen, emitted map[string]bool) ([]byte, []string, []string) {

	broken := parseCircuitAnnotation(annoVal)
	// present holds every live sub-webhook name — the staleness check
	// below compares the annotation against it (a freshly tripped name
	// is present even though it was not in the annotation yet).
	present := map[string]bool{}
	// hookMerges collects the strategic-merge entries for every
	// failurePolicy flip — one {"name": X, "failurePolicy": ...} map
	// per touched sub-webhook (each hook is visited once, so a plain
	// append cannot duplicate a merge key).
	var hookMerges []map[string]any
	flip := func(h hookView, fp admissionv1.FailurePolicyType) {
		hookMerges = append(hookMerges, map[string]any{
			"name": h.name, "failurePolicy": string(fp)})
	}
	changed := false
	var trips, recovered []string

	for _, h := range hooks {
		present[h.name] = true
		key := kind + "/" + cfgName + "/" + h.name
		isBroken := broken[h.name]
		// svcEffective < 0 marks "not Service-backed" — URL webhooks
		// and malformed refs are unmeasurable, the breaker never
		// trips them. effective excludes Ready endpoints sitting on
		// partitioned/unresponsive nodes (W5.5); raw keeps them for
		// the threshold pick.
		svcEffective, svcRaw := -1, -1
		svc := ""
		if h.svc != nil && h.svc.Namespace != "" && h.svc.Name != "" {
			svc = h.svc.Namespace + "/" + h.svc.Name
			svcEffective = ready.effective[svc]
			svcRaw = ready.raw[svc]
		}
		switch {
		case isBroken && svcEffective != 0:
			// RECOVER — the Service has >= 1 reachable Ready endpoint
			// again, or the entry was repointed off its Service
			// entirely (svcEffective < 0): the breaker cannot measure
			// a URL, so it hands back the declared Fail and steps
			// out. Endpoints on partitioned nodes do NOT count —
			// they still fail every apiserver call.
			flip(h, admissionv1.Fail)
			delete(broken, h.name)
			recovered = append(recovered, h.name)
			changed = true
			log.Info(fmt.Sprintf("CIRCUIT-RECOVER: %s/%s webhook %q -> %s — restoring failurePolicy=Fail",
				kind, cfgName, h.name, svcRefString(h.svc)))
		case isBroken:
			// Still dead — the annotation is the SSOT, so re-assert
			// Ignore if the policy was flipped back externally.
			if h.fp == nil || *h.fp != admissionv1.Ignore {
				flip(h, admissionv1.Ignore)
				changed = true
			}
			metrics.WebhookCircuitBroken.WithLabelValues(kind, cfgName, h.name).Set(1)
			emitted[key] = true
		case svcEffective == 0 && failClosed(h.fp):
			seen[key] = true
			first, ok := g.deadSince[key]
			if !ok {
				g.deadSince[key] = now
				log.Info("circuit breaker: fail-closed webhook on a dead Service — tracking",
					"kind", kind, "config", cfgName, "webhook", h.name,
					"service", svc, "rawReady", svcRaw)
				continue
			}
			threshold := g.tripThreshold(svcRaw)
			if now.Sub(first) < threshold {
				continue
			}
			// TRIP — dead backend past the threshold. deadSince is
			// deliberately NOT cleared here: if the patch fails the
			// annotation never lands, so keeping the streak lets the
			// next sweep retry immediately instead of re-opening a
			// fresh window. Once the entry is broken it no longer
			// marks seen[key], so the ledger prunes itself.
			flip(h, admissionv1.Ignore)
			broken[h.name] = true
			trips = append(trips, h.name)
			changed = true
			if svcRaw > 0 {
				log.Info(fmt.Sprintf("CIRCUIT-TRIP: %s/%s webhook %q -> %s (all %d ready endpoints on partitioned/unresponsive nodes >= %s) — patching failurePolicy=Ignore",
					kind, cfgName, h.name, svc, svcRaw, threshold))
			} else {
				log.Info(fmt.Sprintf("CIRCUIT-TRIP: %s/%s webhook %q -> %s (0 ready endpoints >= %s) — patching failurePolicy=Ignore",
					kind, cfgName, h.name, svc, threshold))
			}
		}
	}

	// Stale annotation names (the sub-webhook itself is gone — e.g.
	// removed by the orphan sweep) drop out so the record stays exact.
	for name := range broken {
		if !present[name] {
			delete(broken, name)
			metrics.WebhookCircuitBroken.DeleteLabelValues(kind, cfgName, name)
			changed = true
			log.Info("CIRCUIT-CLEAN: annotation entry has no live webhook — dropping",
				"kind", kind, "config", cfgName, "webhook", name)
		}
	}
	if !changed {
		return nil, nil, nil
	}

	anno := map[string]any{webhookCircuitAnno: nil} // merge-patch null deletes the key
	if len(broken) > 0 {
		anno[webhookCircuitAnno] = strings.Join(slices.Sorted(maps.Keys(broken)), ",")
	}
	doc := map[string]any{
		"metadata": map[string]any{"annotations": anno},
	}
	if len(hookMerges) > 0 {
		doc["webhooks"] = hookMerges
	}
	payload, err := json.Marshal(doc)
	if err != nil {
		// Absorbed sub-failure: the sweep logs and continues —
		// metered so the dropped work is still counted.
		metrics.IncError(webhookGuardQueue)
		log.Error(err, "marshal circuit breaker patch", "config", cfgName)
		return nil, nil, nil
	}
	return payload, trips, recovered
}

// circuitMetrics applies the trip/recovery side-effects — called only
// after the config patch landed, so a failed patch retries next sweep
// without double-counting trips. A tripped series is recorded in
// emitted (the sweep's new ledger); a recovered one is deleted
// outright — a cleared breaker emits no series, not a 0, and the
// sweep-end ledger rebuild drops it for good.
func circuitMetrics(emitted map[string]bool, kind, cfgName string, trips, recovered []string) {
	for _, n := range trips {
		metrics.WebhookCircuitBroken.WithLabelValues(kind, cfgName, n).Set(1)
		emitted[kind+"/"+cfgName+"/"+n] = true
		metrics.WebhookCircuitBreakerTripsTotal.WithLabelValues(kind, cfgName).Inc()
	}
	for _, n := range recovered {
		metrics.WebhookCircuitBroken.DeleteLabelValues(kind, cfgName, n)
	}
}

// failClosed reports whether the entry currently fails closed. A nil
// failurePolicy defaults to Fail server-side; anything not explicitly
// Ignore is treated as fail-closed.
func failClosed(fp *admissionv1.FailurePolicyType) bool {
	return fp == nil || *fp != admissionv1.Ignore
}

// parseCircuitAnnotation splits the comma-separated annotation value
// into a name set. Webhook names are DNS-1123 subdomains — commas can
// never appear in them, so the plain split is unambiguous.
func parseCircuitAnnotation(v string) map[string]bool {
	out := map[string]bool{}
	for _, n := range strings.Split(v, ",") {
		if n = strings.TrimSpace(n); n != "" {
			out[n] = true
		}
	}
	return out
}

// svcRefString renders a webhook's Service reference for log lines.
func svcRefString(ref *admissionv1.ServiceReference) string {
	if ref == nil || ref.Namespace == "" || ref.Name == "" {
		return "<none>"
	}
	return ref.Namespace + "/" + ref.Name
}

// ---------------------------------------------------------------------------
// 2.2 — unmeshed-pod-auditor + post-circuit-breaker pod healer.
// ---------------------------------------------------------------------------

// unmeshedRemediationEnabled reads the kill-switch every run — an env
// flip takes effect on the next sweep without a code change (same
// pattern as circuitBreakerEnabled).
func unmeshedRemediationEnabled() bool {
	return os.Getenv("UNMESHED_POD_REMEDIATION_ENABLED") != "false"
}

// sweepUnmeshedPods audits Running Pods that opted into linkerd
// injection (namespace OR pod linkerd.io/inject=enabled) but carry no
// linkerd-proxy container or initContainer — the signature of a pod
// admitted while the C1 breaker held the injector open. The gauge is
// exported unconditionally; deletion additionally requires the
// injector webhook provably healthy and the remediation flag on.
func (g *webhookGuard) sweepUnmeshedPods(ctx context.Context, snap *sweepSnapshot) error {
	log := logf.FromContext(ctx)
	if g.unmeshedEmitted == nil {
		// Lazily arm for direct-constructed fixtures — Setup always
		// initializes.
		g.unmeshedEmitted = map[string]bool{}
	}

	// The namespace census carries the ns-level inject=enabled
	// opt-in. An empty list is an API flap — a pod whose namespace
	// cannot be checked must never be classified, so abort the
	// audit before anything is emitted or deleted.
	if snap.nsErr != nil {
		return fmt.Errorf("list namespaces — unmeshed audit skipped: %w", snap.nsErr)
	}
	if len(snap.ns.Items) == 0 {
		return fmt.Errorf("empty namespace list (API flap) — unmeshed audit skipped")
	}
	nsInject := make(map[string]string, len(snap.ns.Items))
	for _, ns := range snap.ns.Items {
		nsInject[ns.Name] = injectDirective(ns.Labels, ns.Annotations)
	}

	// Server-side phase filter (the informer cache is list/watch-
	// locked to kube-system cilium pods, so this goes through cs like
	// every other module); the in-code phase check stays because
	// fake clientsets ignore field selectors. The list is PAGED —
	// all Running pods cluster-wide is an unbounded read, and each
	// page is processed then dropped instead of pinning the whole
	// list for the sweep.
	now := g.now()
	emitted := map[string]bool{}
	var candidates []corev1.Pod
	listOpts := metav1.ListOptions{
		FieldSelector: "status.phase=Running",
		Limit:         listPageSize,
	}
	for {
		pods, err := g.cs.CoreV1().Pods(metav1.NamespaceAll).List(ctx, listOpts)
		if err != nil {
			return fmt.Errorf("list pods — unmeshed audit skipped: %w", err)
		}
		for i := range pods.Items {
			p := &pods.Items[i]
			if p.Status.Phase != corev1.PodRunning {
				continue // mirrors the FieldSelector for fake clients
			}
			if !podWantsMesh(p, nsInject[p.Namespace]) {
				continue
			}
			if podHasSidecar(p) {
				continue
			}
			emitted[p.Namespace+"/"+p.Name] = true
			metrics.UnmeshedPods.WithLabelValues(p.Namespace, p.Name).Set(1)
			log.Info("UNMESHED: pod running without linkerd-proxy sidecar",
				"pod", p.Namespace+"/"+p.Name)
			// Deletion requires a CONTROLLER owner (a bare
			// ownerReference proves nothing is recreating the pod)
			// that is not a Node — mirror pods only reflect a
			// static manifest, deleting one changes nothing — and
			// the pod must not already be terminating: its
			// replacement gets the sidecar at admission, so a
			// second delete buys nothing. The candidate is COPIED
			// out of the page — holding pointers would keep the
			// whole pods.Items backing array reachable until the
			// deletes finish.
			if owner := metav1.GetControllerOf(p); owner != nil &&
				owner.Kind != "Node" &&
				p.DeletionTimestamp.IsZero() &&
				now.Sub(p.CreationTimestamp.Time) >= unmeshedMinPodAge {
				candidates = append(candidates, *p)
			}
		}
		if pods.Continue == "" {
			break
		}
		listOpts.Continue = pods.Continue
	}

	// Prune series for pods that vanished or gained the sidecar —
	// same DeleteLabelValues hygiene as brokenEmitted.
	for k := range g.unmeshedEmitted {
		if emitted[k] {
			continue
		}
		if parts := strings.SplitN(k, "/", 2); len(parts) == 2 {
			metrics.UnmeshedPods.DeleteLabelValues(parts[0], parts[1])
		}
	}
	g.unmeshedEmitted = emitted

	if len(candidates) == 0 {
		return nil
	}
	if !unmeshedRemediationEnabled() {
		log.Info("unmeshed remediation disabled (UNMESHED_POD_REMEDIATION_ENABLED=false)",
			"candidates", len(candidates))
		return nil
	}

	// Remediation only runs when the injector is provably back: the
	// webhook not circuit-broken, its declared Fail policy intact,
	// and >= 1 Ready endpoint behind its Service. An unverifiable
	// answer fails closed — a wrong "healthy" verdict deletes pods
	// that would only be recreated unmeshed again.
	healthy, err := g.linkerdInjectorHealthy(snap)
	if err != nil {
		metrics.IncError(webhookGuardQueue)
		log.Info("WARN: injector health unverifiable — remediation skipped (fail closed)",
			"error", err, "candidates", len(candidates))
		return nil
	}
	if !healthy {
		log.Info("injector webhook not healthy — remediation deferred",
			"candidates", len(candidates))
		return nil
	}

	// W7-C1 — the maintenance mutex gates the evictions: killing
	// pods mid-drain/upgrade is exactly what the mutex exists to
	// prevent, and "cannot verify" fails closed like every other
	// caller of shared.MaintenanceActive.
	held, why, err := g.maintenanceActive(ctx)
	if err != nil {
		metrics.IncError(webhookGuardQueue)
		log.Info("WARN: maintenance check unverifiable — "+
			"DEFER: unmeshed remediation skipped (fail closed)",
			"error", err, "candidates", len(candidates))
		return nil
	}
	if held {
		log.Info("DEFER: maintenance active — unmeshed remediation skipped",
			"why", why, "candidates", len(candidates))
		return nil
	}

	// Deterministic order so the cap picks the same pods.
	slices.SortFunc(candidates, func(a, b corev1.Pod) int {
		return strings.Compare(a.Namespace+"/"+a.Name, b.Namespace+"/"+b.Name)
	})
	deleted, attempts := 0, 0
	for i := range candidates {
		p := &candidates[i]
		if deleted >= unmeshedDeleteCap || attempts >= unmeshedDeleteAttempts {
			break
		}
		attempts++
		log.Info("EVICT: unmeshed pod — owner controller recreates it meshed",
			"pod", p.Namespace+"/"+p.Name,
			"age", now.Sub(p.CreationTimestamp.Time).Truncate(time.Second))
		// The kill goes through the policy/v1 Eviction API, NOT a raw
		// Delete (W7-C1): the apiserver enforces PodDisruptionBudgets
		// and consumes a disruption slot atomically, so an already
		// degraded workload cannot lose its last replica to a
		// cosmetic fix. The UID precondition closes the TOCTOU
		// window between the audit snapshot and the evict — a
		// same-named pod recreated in between was admitted after
		// the injector recovered and is not ours to reap.
		uid := p.UID
		eviction := &policyv1.Eviction{
			ObjectMeta: metav1.ObjectMeta{
				Name:      p.Name,
				Namespace: p.Namespace,
			},
			DeleteOptions: &metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &uid},
			},
		}
		if err := g.cs.CoreV1().Pods(p.Namespace).EvictV1(ctx, eviction); err != nil {
			if apierrors.IsTooManyRequests(err) {
				// HTTP 429 — a PDB with disruptionsAllowed==0
				// refused the eviction. That is a deferral, not a
				// failure: the workload is already at its replica
				// floor and killing this pod would finish the
				// outage. Keep it, count no error, move on.
				log.Info("DEFER: PDB refused eviction of unmeshed pod — keeping pod alive",
					"pod", p.Namespace+"/"+p.Name)
				continue
			}
			log.Error(err, "unmeshed pod eviction failed", "pod", p.Namespace+"/"+p.Name)
			metrics.IncError(webhookGuardQueue)
			continue
		}
		metrics.UnmeshedPodsRecreatedTotal.WithLabelValues(p.Namespace).Inc()
		deleted++
	}
	log.Info("unmeshed audit done", "unmeshed", len(emitted),
		"candidates", len(candidates), "deleted", deleted)
	return nil
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

// podWantsMesh reports whether the pod opted into linkerd injection:
// the pod's own linkerd.io/inject directive decides first (disabled
// opts out even inside an enabled namespace, enabled opts in even
// inside a disabled one); when the pod says nothing the namespace
// directive applies.
func podWantsMesh(p *corev1.Pod, nsDirective string) bool {
	if p.Spec.HostNetwork {
		return false // hostNetwork pods are never injected
	}
	for _, ref := range p.OwnerReferences {
		if ref.Kind == "Job" || ref.Kind == "CronJob" {
			return false // batch pods are never injected
		}
	}
	switch d := injectDirective(p.Labels, p.Annotations); {
	case d == "disabled":
		return false
	case d == "enabled":
		return true
	default:
		return nsDirective == "enabled"
	}
}

// podHasSidecar reports whether the pod carries a linkerd-proxy
// container or initContainer — the injection signature.
func podHasSidecar(p *corev1.Pod) bool {
	for _, c := range p.Spec.Containers {
		if c.Name == linkerdProxyContainer {
			return true
		}
	}
	for _, c := range p.Spec.InitContainers {
		if c.Name == linkerdProxyContainer {
			return true
		}
	}
	return false
}

// injectDirective reads linkerd.io/inject from an object's labels and
// annotations — annotations are checked BEFORE labels and the first
// recognized directive wins (linkerd's own precedence); an absent or
// unrecognized annotation value falls through to the label check, and
// no directive anywhere returns "".
func injectDirective(labels, annotations map[string]string) string {
	for _, m := range []map[string]string{annotations, labels} {
		switch m[linkerdInjectKey] {
		case "disabled":
			return "disabled"
		case "enabled":
			return "enabled"
		}
	}
	return ""
}

// linkerdInjectorHealthy reports whether the linkerd-proxy-injector
// mutating webhook is fully back: not circuit-broken, failurePolicy
// still Fail (a tripped breaker leaves Ignore behind), and >= 1 Ready
// endpoint behind its backend Service. Any measurement failure is a
// real error — the caller treats "cannot verify" as "not healthy".
// Runs only when unmeshed candidates exist, so its census +
// config-list inputs are drawn from the shared run snapshot (the
// census is computed lazily on first use — see sweepSnapshot).
func (g *webhookGuard) linkerdInjectorHealthy(snap *sweepSnapshot) (bool, error) {
	ready, err := snap.readyCounts()
	if err != nil {
		return false, err
	}
	if snap.mwcErr != nil {
		return false, fmt.Errorf("list mutatingwebhookconfigurations — injector health unknown: %w", snap.mwcErr)
	}
	mwcs := snap.mwc
	found := false
	for i := range mwcs.Items {
		cfg := &mwcs.Items[i]
		broken := parseCircuitAnnotation(cfg.Annotations[webhookCircuitAnno])
		for _, w := range cfg.Webhooks {
			if w.Name != linkerdInjectorWebhook {
				continue // exact match — a lookalike name is not the injector
			}
			found = true
			if broken[w.Name] || !failClosed(w.FailurePolicy) {
				continue // circuit-broken (or manually set to Ignore)
			}
			if w.ClientConfig.Service == nil {
				continue
			}
			svc := w.ClientConfig.Service.Namespace + "/" + w.ClientConfig.Service.Name
			if ready.effective[svc] > 0 {
				return true, nil
			}
		}
	}
	if !found {
		logf.FromContext(snap.ctx).Info("injector health: no linkerd-proxy-injector webhook found")
	}
	return false, nil
}
