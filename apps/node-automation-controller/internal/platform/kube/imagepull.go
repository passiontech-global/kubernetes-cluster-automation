// imagepull.go — the W18-8/W18-9 image-pull stall census: the
// pod-shape predicate (any container status.waiting.reason in
// ImagePullBackOff/ErrImagePull) and the cluster-wide count behind
// the descheduler-storm-gate's storm signal (e) — a pull storm means
// images are not landing anywhere, so rebalancing just spreads
// unrunnable pods across more nodes. The statefulset-ondelete-roller
// runs the same predicate per owned pod to defer a set whose member
// cannot pull its (possibly new) image — deleting the next member on
// top stacks a second stuck pod. W10-GI5's alerting health check
// (health/nodehealth/image_pull_storm) keeps its own richer scan
// (registry-outage markers, per-namespace classification, first-seen
// windows); this is the cheap predicate+census the GATING modules
// share.
package kube

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ImagePullStallReason returns the kubelet waiting reason
// ("ImagePullBackOff" or "ErrImagePull") when any of the pod's
// containers — init, regular or ephemeral — is currently waiting on
// an image-pull failure, "" when none is. The waiting state carries
// no timestamp of its own, so "how long" is the caller's concern
// (the storm gate reads the census per sweep; the roller defers for
// the cycle) — here only the CURRENT state counts, never LastState:
// a container that already recovered from a pull failure is running
// now and must not defer a roll.
func ImagePullStallReason(p *corev1.Pod) string {
	for _, cs := range p.Status.ContainerStatuses {
		if r := pullWaitingReason(cs); r != "" {
			return r
		}
	}
	for _, cs := range p.Status.InitContainerStatuses {
		if r := pullWaitingReason(cs); r != "" {
			return r
		}
	}
	for _, cs := range p.Status.EphemeralContainerStatuses {
		if r := pullWaitingReason(cs); r != "" {
			return r
		}
	}
	return ""
}

// pullWaitingReason extracts the stall reason from one container
// status — the two kubelet-native pull-failure spellings (as in
// image_pull_storm's pullWaitingReasons; upstream defines them in
// kubelet's images package, not k8s.io/api). Anything else
// (CrashLoopBackOff, CreateContainerConfigError) is not a pull stall.
func pullWaitingReason(cs corev1.ContainerStatus) string {
	if cs.State.Waiting == nil {
		return ""
	}
	switch cs.State.Waiting.Reason {
	case "ImagePullBackOff", "ErrImagePull":
		return cs.State.Waiting.Reason
	}
	return ""
}

// PodImagePullStalled reports whether any container of the pod is
// waiting on an image-pull failure.
func PodImagePullStalled(p *corev1.Pod) bool {
	return ImagePullStallReason(p) != ""
}

// CountImagePullStalledPods returns (podCount, namespaceCount) for
// the cluster-wide census of pods with at least one container
// waiting in ImagePullBackOff/ErrImagePull. Paged like every
// cluster-wide read; a List error is returned — the callers' storm
// verdicts must not compute on an empty read.
func CountImagePullStalledPods(ctx context.Context,
	cs kubernetes.Interface) (podCount, namespaceCount int, err error) {

	nsSeen := map[string]bool{}
	err = ListEach(ctx,
		metav1.ListOptions{Limit: DefaultListPageSize},
		Pods(cs, metav1.NamespaceAll),
		func(items []corev1.Pod) error {
			for i := range items {
				if !PodImagePullStalled(&items[i]) {
					continue
				}
				podCount++
				nsSeen[items[i].Namespace] = true
			}
			return nil
		})
	return podCount, len(nsSeen), err
}
