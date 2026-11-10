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

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// nsInjectDirectives folds the snapshot's namespace census into the
// ns-level linkerd.io/inject directive map. An empty list is an API
// flap — a pod whose namespace cannot be checked must never be
// classified, so the error aborts the audit before anything is
// emitted or deleted.
func nsInjectDirectives(snap *guardstate.Snapshot) (map[string]string, error) {
	if snap.NSErr != nil {
		return nil, fmt.Errorf("list namespaces — unmeshed audit skipped: %w", snap.NSErr)
	}
	if len(snap.NS.Items) == 0 {
		return nil, errors.New("empty namespace list (API flap) — unmeshed audit skipped")
	}
	nsInject := make(map[string]string, len(snap.NS.Items))
	for _, ns := range snap.NS.Items {
		nsInject[ns.Name] = injectDirective(ns.Labels, ns.Annotations)
	}
	return nsInject, nil
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
	nsInject map[string]string, now time.Time, log logr.Logger) (int, []corev1.Pod, error) {
	g := snap.G
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
	err := kube.ListEach(ctx, listOpts,
		kube.Pods(g.CS, metav1.NamespaceAll),
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
