// statefulset_roller_pods.go — the pod-side helpers of the
// statefulset on-delete roller: opt-in annotation check, owned-pod
// census and ordinal parsing. Split from statefulset_roller.go to
// keep both under ~500 LOC.
package statefulsetroller

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// stsAutoRollOptedIn reports the opt-in: passiontech.dev/auto-roll-ondelete
// on the StatefulSet itself OR on its pod template — operators like
// dragonfly-operator propagate CR spec.annotations into the pod
// template only, so the STS object never carries the annotation even
// though the workload opted in (2.1.6).
func stsAutoRollOptedIn(sts *appsv1.StatefulSet) bool {
	return sts.Annotations[stsAutoRollAnno] == "true" ||
		sts.Spec.Template.Annotations[stsAutoRollAnno] == "true"
}

// ownedPods lists the pods the StatefulSet controls — the apiserver
// pre-filters by the STS's own spec.selector (without it every STS
// would drag the whole namespace's pod list across the wire per
// sweep, paged at DefaultListPageSize so the read stays cheap at
// fleet scale), then the controller ownerReference decides (name+kind, not
// UID: fake clients and hand-built fixtures rarely carry matching
// UIDs). A selector that fails to parse fails CLOSED — an error
// skips this STS rather than rolling it on an unfiltered pod list.
// Pods already terminating are excluded: they are never delete
// candidates (the delete is already in flight) and they must not
// block the all-Ready gate either — a member wedged in Terminating
// (finalizer, lost node) would pin the roll forever, while a real
// mid-deletion disruption is still caught by the PDB gate's
// disruptionsAllowed.
func (r *statefulSetOnDeleteRoller) ownedPods(ctx context.Context,
	sts *appsv1.StatefulSet) ([]*corev1.Pod, error) {
	sel, err := metav1.LabelSelectorAsSelector(sts.Spec.Selector)
	if err != nil {
		return nil, fmt.Errorf("parse selector of statefulset %s/%s: %w",
			sts.Namespace, sts.Name, err)
	}
	// The apiserver pre-filters by the STS's own spec.selector
	// (without it every STS would drag the whole namespace's pod list
	// across the wire per sweep, paged at DefaultListPageSize so the
	// read stays cheap at fleet scale); the controller
	// ownerReference decides inside the page visit (name+kind, not
	// UID: fake clients and hand-built fixtures rarely carry matching
	// UIDs) and each page's non-owned pods die with it.
	var out []*corev1.Pod
	err = kube.ListEach(ctx, metav1.ListOptions{
		LabelSelector: sel.String(),
		Limit:         kube.DefaultListPageSize,
	}, kube.Pods(r.cs, sts.Namespace),
		func(page []corev1.Pod) error {
			for i := range page {
				p := &page[i]
				if !p.DeletionTimestamp.IsZero() {
					continue
				}
				ref := metav1.GetControllerOf(p)
				if ref != nil && ref.Kind == "StatefulSet" && ref.Name == sts.Name {
					out = append(out, p)
				}
			}
			return nil
		})
	if err != nil {
		return nil, fmt.Errorf("list pods in %s: %w", sts.Namespace, err)
	}
	return out, nil
}

// podOrdinal parses the trailing ordinal out of "<stsName>-<N>".
func podOrdinal(stsName, podName string) (int, bool) {
	suffix := strings.TrimPrefix(podName, stsName+"-")
	if suffix == podName {
		return 0, false
	}
	n, err := strconv.Atoi(suffix)
	if err != nil {
		return 0, false
	}
	return n, true
}
