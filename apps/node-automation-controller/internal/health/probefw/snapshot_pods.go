// snapshot_pods.go — the pod census readers of the per-sweep
// snapshot: AllPods plus its namespace/selector filters and the
// pod-derived PodNodes placement join (split out of snapshot.go —
// see its header for the memoizer contract).
package probefw

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// AllPods returns the sweep's cluster-wide pod census — one paged
// LIST per run(), memoized; outside a sweep it lists fresh per call
// (the pre-snapshot semantics).
func (d *Deps) AllPods(ctx context.Context) ([]corev1.Pod, error) {
	s := sweepSnap(ctx)
	s.muPods.Lock()
	defer s.muPods.Unlock()
	if !s.podsSet {
		s.podsSet = true
		lctx, cancel := s.listCtx(ctx)
		defer cancel()
		s.pods, s.podsErr = kube.ListAll(lctx,
			metav1.ListOptions{Limit: HealthListPageSize},
			kube.Pods(d.CS, metav1.NamespaceAll))
	}
	return s.pods, s.podsErr
}

// PodsIn filters the shared census to one namespace — the client-side
// equivalent of Pods(ns).List for the namespace-scoped readers. The
// returned slice is freshly allocated; elements still alias the
// snapshot's pod structs, so treat them read-only like AllPods.
func (d *Deps) PodsIn(ctx context.Context, ns string) ([]*corev1.Pod, error) {
	pods, err := d.AllPods(ctx)
	if err != nil {
		return nil, err
	}
	var out []*corev1.Pod
	for i := range pods {
		if pods[i].Namespace == ns {
			out = append(out, &pods[i])
		}
	}
	return out, nil
}

// PodsMatching filters the shared census to one namespace (""
// = cluster-wide) plus a label selector — the client-side equivalent
// of Pods(ns).List{LabelSelector: sel} for the equality-based
// selectors the checks use. An unparseable selector is a caller bug
// surfaced as an error (the apiserver would have rejected it too).
func (d *Deps) PodsMatching(ctx context.Context, ns, selector string) ([]*corev1.Pod, error) {
	sel, err := labels.Parse(selector)
	if err != nil {
		return nil, fmt.Errorf("parse label selector %q: %w", selector, err)
	}
	pods, err := d.AllPods(ctx)
	if err != nil {
		return nil, err
	}
	var out []*corev1.Pod
	for i := range pods {
		pod := &pods[i]
		if ns != "" && pod.Namespace != ns {
			continue
		}
		if sel.Matches(labels.Set(pod.Labels)) {
			out = append(out, pod)
		}
	}
	return out, nil
}

// PodNodes is the pod twin: "ns/name" → spec.nodeName over the
// shared pod census — the placement join the endpoint zone
// resolvers walk as their last fallback (a slice's own zone and
// nodeName hints can lag a rebinding; the pod's bound node is the
// ground truth) and the targetRef → node hop the skew checks make.
// Same memoized-error posture as NodeZones, and pod-derived — a
// mid-sweep pod delete stales it, so InvalidatePods drops it
// alongside the census. Read-only like every snapshot payload.
func (d *Deps) PodNodes(ctx context.Context) (map[string]string, error) {
	s := sweepSnap(ctx)
	s.muPodNodes.Lock()
	defer s.muPodNodes.Unlock()
	if !s.podNodesSet {
		s.podNodesSet = true
		var pods []corev1.Pod
		pods, s.podNodesErr = d.AllPods(ctx)
		if s.podNodesErr == nil {
			s.podNodes = make(map[string]string, len(pods))
			for i := range pods {
				s.podNodes[pods[i].Namespace+"/"+pods[i].Name] =
					pods[i].Spec.NodeName
			}
		}
	}
	return s.podNodes, s.podNodesErr
}
