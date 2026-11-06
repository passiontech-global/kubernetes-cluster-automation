// webhooks.go — the webhook-config helpers more than one
// webhookguard duty needs: the kind label values the metrics share,
// the circuit-broken annotation record, the fail-closed predicate
// and the CRD conversion service key.
package guardstate

import (
	"strings"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

const (
	// KindMutating / KindValidating are the kind label values for
	// the WebhookCircuit* and WebhookMissingCriticalNSExclusion
	// metrics — the short forms matching webhookPatch.mutating.
	KindMutating   = "mutating"
	KindValidating = "validating"
)

// CircuitBrokenAnno records, on the webhook config object itself,
// the comma-separated names of the sub-webhooks the C1 circuit
// breaker flipped to failurePolicy=Ignore — the trip record
// survives pod restarts and is human-readable in kubectl describe.
// Comma-separated is unambiguous: webhook names are DNS-1123
// subdomains, which can never contain a comma.
const CircuitBrokenAnno = kube.AnnoCircuitBrokenWebhooks

// ParseCircuitAnnotation splits the comma-separated annotation value
// into a name set. Webhook names are DNS-1123 subdomains — commas can
// never appear in them, so the plain split is unambiguous.
func ParseCircuitAnnotation(v string) map[string]bool {
	out := map[string]bool{}
	for _, n := range strings.Split(v, ",") {
		if n = strings.TrimSpace(n); n != "" {
			out[n] = true
		}
	}
	return out
}

// FailClosed reports whether the entry currently fails closed. A nil
// failurePolicy defaults to Fail server-side; anything not explicitly
// Ignore is treated as fail-closed.
func FailClosed(fp *admissionv1.FailurePolicyType) bool {
	return fp == nil || *fp != admissionv1.Ignore
}

// CRDConversionServiceKey extracts the "namespace/name" Service key a
// CRD's spec.conversion webhook targets — ok=false when the CRD does
// not convert via webhook (strategy missing or something else) or the
// clientConfig is URL-targeted / malformed. The sweep treats those
// like the breaker's URL entries: unmeasurable, never flagged.
func CRDConversionServiceKey(crd *unstructured.Unstructured) (key, ns, name string, ok bool) {
	strategy, _ := kube.NestedString(crd.Object, "spec", "conversion", "strategy")
	if strategy != "Webhook" {
		return "", "", "", false
	}
	ns, _ = kube.NestedString(crd.Object,
		"spec", "conversion", "webhook", "clientConfig", "service", "namespace")
	name, _ = kube.NestedString(crd.Object,
		"spec", "conversion", "webhook", "clientConfig", "service", "name")
	if ns == "" || name == "" {
		return "", "", "", false
	}
	return ns + "/" + name, ns, name, true
}
