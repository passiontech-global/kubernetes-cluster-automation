// unmeshed_census.go — the audit's census half: the per-namespace
// inject-directive map and the paged Running-pod scan that emits
// UnmeshedPods tuples and collects eviction candidates. Called by
// Sweep before any remediation gate is evaluated — a candidate list
// built off a partial census is the thing the fail-closed returns
// exist to prevent.
package unmeshed

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// nsAudit bundles one namespace's audit inputs: the linkerd.io/inject
// directive plus the label set (with kubernetes.io/metadata.name
// merged, the same synthetic label the criticalns matcher adds) the
// injector webhook's namespaceSelector matches against.
type nsAudit struct {
	directive string
	labels    labels.Set
}

// nsAudits folds the snapshot's namespace census into the per-ns
// audit map. An empty list is an API flap — a pod whose namespace
// cannot be checked must never be classified, so the error aborts
// the audit before anything is emitted or deleted.
func nsAudits(snap *guardstate.Snapshot) (map[string]nsAudit, error) {
	if snap.NSErr != nil {
		return nil, fmt.Errorf("list namespaces — unmeshed audit skipped: %w", snap.NSErr)
	}
	if len(snap.NS.Items) == 0 {
		return nil, errors.New("empty namespace list (API flap) — unmeshed audit skipped")
	}
	out := make(map[string]nsAudit, len(snap.NS.Items))
	for i := range snap.NS.Items {
		ns := &snap.NS.Items[i]
		merged := make(labels.Set, len(ns.Labels)+1)
		for k, v := range ns.Labels {
			merged[k] = v
		}
		merged["kubernetes.io/metadata.name"] = ns.Name
		out[ns.Name] = nsAudit{
			directive: injectDirective(ns.Labels, ns.Annotations),
			labels:    merged,
		}
	}
	return out, nil
}

// injectorSelectors resolves the live linkerd-proxy-injector mutating
// webhook's namespace/object selectors — the ground truth for "would
// the injector even look at this pod". The linkerd.io/inject
// directive alone is not sufficient: the webhook's own selectors can
// exclude namespaces/pods the directive logic would flag, and
// evicting those just recreates them unmeshed forever. A nil
// selector or absent injector webhook degrades to match-all so the
// directive logic stays the fallback; an MWCErr is a hard error — a
// pod whose injector scope cannot be checked must never be
// classified.
func injectorSelectors(snap *guardstate.Snapshot) (labels.Selector, labels.Selector, error) {
	nsSel, objSel := labels.Everything(), labels.Everything()
	if snap.MWCErr != nil {
		return nil, nil, fmt.Errorf("list mutatingwebhookconfigurations — injector selectors unknown: %w", snap.MWCErr)
	}
	if snap.MWC == nil {
		return nsSel, objSel, nil
	}
	for i := range snap.MWC.Items {
		cfg := &snap.MWC.Items[i]
		for j := range cfg.Webhooks {
			w := &cfg.Webhooks[j]
			if w.Name != kube.LinkerdInjectorWebhook {
				continue // exact match — a lookalike is not the injector
			}
			// A malformed selector fails LabelSelectorAsSelector —
			// keep match-all rather than suppress detection on a
			// config the apiserver itself would reject.
			if w.NamespaceSelector != nil {
				if s, err := metav1.LabelSelectorAsSelector(w.NamespaceSelector); err == nil {
					nsSel = s
				}
			}
			if w.ObjectSelector != nil {
				if s, err := metav1.LabelSelectorAsSelector(w.ObjectSelector); err == nil {
					objSel = s
				}
			}
			return nsSel, objSel, nil
		}
	}
	return nsSel, objSel, nil
}

// censusUnmeshed pages the Running pods cluster-wide and applies the
// unmeshed signature: opted into injection (podWantsMesh) but no
// linkerd-proxy container (podHasSidecar) — the shape of a pod
// admitted while the C1 breaker held the injector open. Every match
// re-asserts its UnmeshedPods tuple; matches that also look
// safely-evictable (a controller owner that is not a Node — mirror
// pods only reflect a static manifest — not already terminating,
// and past unmeshedMinPodAge so mid-admission pods don't count)
// are COPIED into the candidate list — holding pointers would keep
// each page's backing array reachable until the deletes finish.
// Returns the emitted-tuple count for the done-line.
func (a *Auditor) censusUnmeshed(ctx context.Context, snap *guardstate.Snapshot,
	nss map[string]nsAudit, now time.Time, log logr.Logger) (int, []corev1.Pod, error) {
	g := snap.G
	injNS, injObj, err := injectorSelectors(snap)
	if err != nil {
		return 0, nil, err
	}
	unmeshed := 0 // UnmeshedPods tuples re-asserted this sweep
	var candidates []corev1.Pod
	// Server-side phase filter (the informer cache is list/watch-
	// locked to kube-system cilium pods, so this goes through CS like
	// every other module); the in-code phase check stays because
	// fake clientsets ignore field selectors. The list is PAGED —
	// all Running pods cluster-wide is an unbounded read, and each
	// page is processed then dropped instead of pinning the whole
	// list for the sweep.
	listOpts := metav1.ListOptions{
		FieldSelector: "status.phase=Running",
		Limit:         guardstate.ListPageSize,
	}
	err = kube.ListEach(ctx, listOpts,
		kube.Pods(g.CS, metav1.NamespaceAll),
		func(items []corev1.Pod) error {
			for i := range items {
				p := &items[i]
				if p.Status.Phase != corev1.PodRunning {
					continue // mirrors the FieldSelector for fake clients
				}
				// A namespace missing from the census keeps the
				// zero nsAudit — directive "" and nil labels — so a
				// pod-level inject=enabled can still classify while
				// the injector selectors judge the empty label set.
				nsv := nss[p.Namespace]
				if !podWantsMesh(p, nsv.directive, nsv.labels, injNS, injObj) {
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
		return 0, nil, fmt.Errorf("list pods — unmeshed audit skipped: %w", err)
	}
	return unmeshed, candidates, nil
}

// podWantsMesh reports whether the pod opted into linkerd injection:
// the pod's own linkerd.io/inject directive decides first (disabled
// opts out even inside an enabled namespace, enabled opts in even
// inside a disabled one); when the pod says nothing the namespace
// directive applies. The injector webhook's live namespace/object
// selectors (injNS/injObj — match-all when the injector config is
// absent) gate BOTH paths: a pod they reject can never gain a
// sidecar, so flagging or evicting it just recreates it unmeshed
// forever.
func podWantsMesh(p *corev1.Pod, nsDirective string, nsLabels labels.Set,
	injNS, injObj labels.Selector) bool {
	if p.Spec.HostNetwork {
		return false // hostNetwork pods are never injected
	}
	for _, ref := range p.OwnerReferences {
		if ref.Kind == "Job" || ref.Kind == "CronJob" {
			return false // batch pods are never injected
		}
	}
	if !injNS.Matches(nsLabels) || !injObj.Matches(labels.Set(p.Labels)) {
		return false
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
		if c.Name == kube.LinkerdProxyContainer {
			return true
		}
	}
	for _, c := range p.Spec.InitContainers {
		if c.Name == kube.LinkerdProxyContainer {
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
		switch m[kube.LinkerdInjectKey] {
		case "disabled":
			return "disabled"
		case "enabled":
			return "enabled"
		}
	}
	return ""
}
