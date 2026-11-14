// wedged_challenge.go — the wedged-ACME-Challenge cross-check: a
// pending Order is only reaped once a Challenge explicitly linked to
// it (ownerReference or the acme.cert-manager.io/order-name
// label/annotation) shows the self-check-retry-forever signature —
// presented+processing with no state transition past
// orderPendingMinAge. Order→Certificate attribution lives in
// certificate_reap.go's per-namespace orderIndex.
package certmanagerreaper

import (
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// stuckChallengeForOrder reports whether any Challenge in the
// namespace is both wedged and attributable to this order. Only
// explicit linkage (ownerReference or the acme order-name
// label/annotation naming this order) counts — a linkage-free
// challenge is ambiguous in a shared namespace and justifies nothing.
func stuckChallengeForOrder(order *unstructured.Unstructured,
	chals []unstructured.Unstructured, now time.Time) bool {
	for i := range chals {
		ch := &chals[i]
		if !challengeWedged(ch, now) {
			continue
		}
		if challengeLinkedToOrder(ch, order) {
			return true
		}
	}
	return false
}

// challengeWedged is the self-check-retry-forever signature: the
// challenge resource was presented to the ACME server and is still
// processing, with no state transition for over 30m before now. Uses
// status.lastTransitionTime when present (real objects do not carry
// it — fixtures may), else creationTimestamp.
func challengeWedged(ch *unstructured.Unstructured, now time.Time) bool {
	presented, _ := kube.NestedBool(ch.Object, "status", "presented")
	processing, _ := kube.NestedBool(ch.Object, "status", "processing")
	if !presented || !processing {
		return false
	}
	since := kube.NestedStatusTimeOrCreated(ch, "lastTransitionTime")
	return now.Sub(since) > orderPendingMinAge
}

// challengeLinkedToOrder requires EXPLICIT linkage — an ownerReference
// or the acme.cert-manager.io/order-name label/annotation naming this
// order. A challenge carrying no linkage at all could belong to a
// different cert's order on a busy namespace: it does not count as
// cross-check evidence for THIS order (fail closed, matching the
// order-attribution rule above).
func challengeLinkedToOrder(ch, order *unstructured.Unstructured) bool {
	for _, or := range ch.GetOwnerReferences() {
		if or.Name == order.GetName() {
			return true
		}
	}
	if ln := ch.GetLabels()["acme.cert-manager.io/order-name"]; ln != "" &&
		ln == order.GetName() {
		return true
	}
	if an := ch.GetAnnotations()["acme.cert-manager.io/order-name"]; an != "" &&
		an == order.GetName() {
		return true
	}
	return false
}
