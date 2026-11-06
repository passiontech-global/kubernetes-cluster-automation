// unmeshed_audit.go — the unmeshed-pod auditor, the third of the
// three independent duties behind webhookGuard.run: it exports
// node_automation_unmeshed_pods{namespace,pod} for every Running pod
// that opted into linkerd injection but carries no linkerd-proxy
// sidecar (the signature of a pod admitted while the C1 breaker held
// the injector open), and — once the injector is provably healthy
// again — evicts a bounded number of them so their owner controller
// recreates them meshed. Its state (the emitted-series ledger) lives
// on unmeshedPodAuditor; shared deps are reached through snap.g.
package webhookguard

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

const (
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

// ---------------------------------------------------------------------------
// 2.2 — unmeshed-pod-auditor + post-circuit-breaker pod healer.
// ---------------------------------------------------------------------------

// unmeshedRemediationEnabled reads the kill-switch EVERY run — the
// sanctioned exception to the resolve-at-Setup rule: remediation is an
// ops lever that must stay flippable mid-incident, so an env flip
// takes effect on the next sweep without an operator restart (the
// same deliberate hot reload circuitBreakerEnabled carries).
func unmeshedRemediationEnabled() bool {
	return envx.Gate("UNMESHED_POD_REMEDIATION_ENABLED", true)
}

// unmeshedPodAuditor owns the unmeshed-pod sweep's per-sweep state —
// embedded in webhookGuard so the facade's method set (and every
// in-package test fixture built on it) is unchanged by the split.
// Shared deps (cs/dyn/now) are reached through snap.g; only the
// emitted-series ledger lives here.
type unmeshedPodAuditor struct {
	// unmeshedEmitted is the same ledger for UnmeshedPods
	// ("namespace/pod") — deleted pods and pods that gained the
	// sidecar get their series pruned each sweep.
	unmeshedEmitted state.GaugeLedger[string]
}

// sweepUnmeshedPods audits Running Pods that opted into linkerd
// injection (namespace OR pod linkerd.io/inject=enabled) but carry no
// linkerd-proxy container or initContainer — the signature of a pod
// admitted while the C1 breaker held the injector open. The gauge is
// exported unconditionally; deletion additionally requires the
// injector webhook provably healthy and the remediation flag on.
func (a *unmeshedPodAuditor) sweepUnmeshedPods(ctx context.Context, snap *sweepSnapshot) error {
	g := snap.g
	log := logf.FromContext(ctx)

	// The namespace census carries the ns-level inject=enabled
	// opt-in. An empty list is an API flap — a pod whose namespace
	// cannot be checked must never be classified, so abort the
	// audit before anything is emitted or deleted.
	if snap.nsErr != nil {
		return fmt.Errorf("list namespaces — unmeshed audit skipped: %w", snap.nsErr)
	}
	if len(snap.ns.Items) == 0 {
		return errors.New("empty namespace list (API flap) — unmeshed audit skipped")
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
	now := g.now.Now()
	unmeshed := 0 // UnmeshedPods tuples re-asserted this sweep
	var candidates []corev1.Pod
	listOpts := metav1.ListOptions{
		FieldSelector: "status.phase=Running",
		Limit:         listPageSize,
	}
	err := kube.ListEach(ctx, listOpts,
		kube.Pods(g.cs, metav1.NamespaceAll),
		func(items []corev1.Pod) error {
			for i := range items {
				p := &items[i]
				if p.Status.Phase != corev1.PodRunning {
					continue // mirrors the FieldSelector for fake clients
				}
				if !podWantsMesh(p, nsInject[p.Namespace]) {
					continue
				}
				if podHasSidecar(p) {
					continue
				}
				a.unmeshedEmitted.Set(metrics.UnmeshedPods, 1,
					p.Namespace+"/"+p.Name, p.Namespace, p.Name)
				unmeshed++
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
			return nil
		})
	if err != nil {
		return fmt.Errorf("list pods — unmeshed audit skipped: %w", err)
	}

	// Prune series for pods that vanished or gained the sidecar —
	// same DeleteLabelValues hygiene as brokenEmitted.
	a.unmeshedEmitted.Prune(metrics.UnmeshedPods.DeleteLabelValues)

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
	healthy, err := a.linkerdInjectorHealthy(snap)
	if err != nil {
		metrics.IncError(g.queue)
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
	// caller of kube.MaintenanceActive.
	held, why, err := g.maintenanceActive(ctx)
	if err != nil {
		metrics.IncError(g.queue)
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
		deleteOpts := kube.UIDDeleteOptions(uid, "")
		eviction := &policyv1.Eviction{
			ObjectMeta: metav1.ObjectMeta{
				Name:      p.Name,
				Namespace: p.Namespace,
			},
			DeleteOptions: &deleteOpts,
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
			metrics.IncError(g.queue)
			continue
		}
		metrics.UnmeshedPodsRecreatedTotal.WithLabelValues(p.Namespace).Inc()
		deleted++
	}
	log.Info("unmeshed audit done", "unmeshed", unmeshed,
		"candidates", len(candidates), "deleted", deleted)
	return nil
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
	switch d := injectDirective(p.Labels, p.Annotations); d {
	case "disabled":
		return false
	case "enabled":
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
func (a *unmeshedPodAuditor) linkerdInjectorHealthy(snap *sweepSnapshot) (bool, error) {
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
