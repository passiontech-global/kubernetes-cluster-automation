// webhooks.go — the webhook-config helpers more than one
// webhookguard duty needs: the kind label values the metrics share,
// the circuit-broken annotation record, the fail-closed predicate
// and the CRD conversion service key.
package guardstate

import (
	"fmt"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

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
	return kube.ParseCommaSet(v)
}

// FailClosed reports whether the entry currently fails closed. A nil
// failurePolicy defaults to Fail server-side; anything not explicitly
// Ignore is treated as fail-closed.
func FailClosed(fp *admissionv1.FailurePolicyType) bool {
	return fp == nil || *fp != admissionv1.Ignore
}

// InjectorHealthy reports whether the linkerd-proxy-injector mutating
// webhook is fully back: not circuit-broken, failurePolicy still Fail
// (a tripped breaker leaves Ignore behind), and >= 1 Ready endpoint
// behind its backend Service. Any measurement failure is a real error
// — the caller treats "cannot verify" as "not healthy". Its one
// consumer is the unmeshed-pod remediation, which runs only when
// unmeshed candidates exist, so the census + config-list inputs are
// drawn from the shared run snapshot (the census is computed lazily on
// first use — see Snapshot).
func InjectorHealthy(snap *Snapshot) (bool, error) {
	ready, err := snap.ReadyCounts()
	if err != nil {
		return false, err
	}
	if snap.MWCErr != nil {
		return false, fmt.Errorf("list mutatingwebhookconfigurations — injector health unknown: %w", snap.MWCErr)
	}
	mwcs := snap.MWC
	found := false
	for i := range mwcs.Items {
		cfg := &mwcs.Items[i]
		broken := ParseCircuitAnnotation(cfg.Annotations[CircuitBrokenAnno])
		for _, w := range cfg.Webhooks {
			if w.Name != kube.LinkerdInjectorWebhook {
				continue // exact match — a lookalike name is not the injector
			}
			found = true
			if broken[w.Name] || !FailClosed(w.FailurePolicy) {
				continue // circuit-broken (or manually set to Ignore)
			}
			if w.ClientConfig.Service == nil {
				continue
			}
			svc := w.ClientConfig.Service.Namespace + "/" + w.ClientConfig.Service.Name
			// W9-CP1 brownout guard: an effective-ready endpoint set
			// that was probed AND failed every TCP+TLS handshake is
			// hung, not healthy — evicting unmeshed pods now would
			// only recreate them unmeshed again. A service that was
			// never probed gets the benefit of the doubt.
			if ready.Effective[svc] > 0 && (!ready.Probed[svc] || ready.Responsive[svc]) {
				return true, nil
			}
		}
	}
	if !found {
		logf.FromContext(snap.Ctx).Info("injector health: no linkerd-proxy-injector webhook found")
	}
	return false, nil
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
