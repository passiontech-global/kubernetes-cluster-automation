// webhooks.go — the webhook-config helpers more than one
// webhookguard duty needs: the kind label values the metrics share,
// the circuit-broken annotation record, the fail-closed predicate
// and the CRD conversion service key.
package guardstate

import (
	"context"
	"fmt"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
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

// WebhookView is a read-only uniform projection over MutatingWebhook
// and ValidatingWebhook so downstream duties (circuitbreaker,
// criticalns, orphansweep, census) share one traversal instead of
// duplicating MWC/VWC loops.
type WebhookView struct {
	Name              string
	FailurePolicy     *admissionv1.FailurePolicyType
	NamespaceSelector *metav1.LabelSelector
	Rules             []admissionv1.RuleWithOperations
	Service           *admissionv1.ServiceReference
}

// WebhookConfigView projects one MutatingWebhookConfiguration or
// ValidatingWebhookConfiguration together with a snapshot-updating
// Patch closure.
type WebhookConfigView struct {
	Kind     string
	Resource string
	Name     string
	Anno     string
	Object   metav1.Object
	Hooks    []WebhookView
	Patch    func(ctx context.Context, pt types.PatchType, payload []byte) error
}

// ForEachWebhookConfig walks all mutating then validating webhook
// configurations in the snapshot, invoking visit with each projected
// WebhookConfigView and a Patch closure that refreshes the snapshot
// in place on success. Nil MWC/VWC lists are skipped.
func (s *Snapshot) ForEachWebhookConfig(visit func(WebhookConfigView)) {
	if s.MWC != nil {
		for i := range s.MWC.Items {
			cfg := &s.MWC.Items[i]
			hooks := make([]WebhookView, len(cfg.Webhooks))
			for j := range cfg.Webhooks {
				w := &cfg.Webhooks[j]
				hooks[j] = WebhookView{
					Name:              w.Name,
					FailurePolicy:     w.FailurePolicy,
					NamespaceSelector: w.NamespaceSelector,
					Rules:             w.Rules,
					Service:           w.ClientConfig.Service,
				}
			}
			visit(WebhookConfigView{
				Kind:     KindMutating,
				Resource: "mutatingwebhookconfigurations",
				Name:     cfg.Name,
				Anno:     cfg.Annotations[CircuitBrokenAnno],
				Object:   cfg,
				Hooks:    hooks,
				Patch: func(ctx context.Context, pt types.PatchType, payload []byte) error {
					patched, err := s.G.CS.AdmissionregistrationV1().MutatingWebhookConfigurations().
						Patch(ctx, cfg.Name, pt, payload, metav1.PatchOptions{})
					if err != nil {
						return err
					}
					s.SetMWC(patched)
					return nil
				},
			})
		}
	}
	if s.VWC != nil {
		for i := range s.VWC.Items {
			cfg := &s.VWC.Items[i]
			hooks := make([]WebhookView, len(cfg.Webhooks))
			for j := range cfg.Webhooks {
				w := &cfg.Webhooks[j]
				hooks[j] = WebhookView{
					Name:              w.Name,
					FailurePolicy:     w.FailurePolicy,
					NamespaceSelector: w.NamespaceSelector,
					Rules:             w.Rules,
					Service:           w.ClientConfig.Service,
				}
			}
			visit(WebhookConfigView{
				Kind:     KindValidating,
				Resource: "validatingwebhookconfigurations",
				Name:     cfg.Name,
				Anno:     cfg.Annotations[CircuitBrokenAnno],
				Object:   cfg,
				Hooks:    hooks,
				Patch: func(ctx context.Context, pt types.PatchType, payload []byte) error {
					patched, err := s.G.CS.AdmissionregistrationV1().ValidatingWebhookConfigurations().
						Patch(ctx, cfg.Name, pt, payload, metav1.PatchOptions{})
					if err != nil {
						return err
					}
					s.SetVWC(patched)
					return nil
				},
			})
		}
	}
}

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
			// circuit-breaker-bounce brownout guard: an effective-ready endpoint set
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

// compactCRDConversion projects one listed CRD down to the slice the
// conversion duties actually read — metadata.name plus the whole
// spec.conversion subtree — inside the ListEach page visit, so the
// page's full objects (OpenAPI v3 schemas are the bulk of a CRD
// census's heap, ~80–150 MiB cluster-wide) are garbage-collected
// with the page instead of pinning the snapshot for the whole run.
// The retained object keeps the unstructured shape every consumer
// (CRDConversionServiceKey, NestedInt64 port reads, GetName) already
// understands — only the unread fields are dropped.
func compactCRDConversion(crd *unstructured.Unstructured) unstructured.Unstructured {
	out := unstructured.Unstructured{Object: map[string]any{}}
	out.SetName(crd.GetName())
	if conv, found, _ := unstructured.NestedFieldNoCopy(
		crd.Object, "spec", "conversion"); found {
		// NestedFieldNoCopy aliases the page object's subtree — safe
		// here: the snapshot contract is read-only, and the alias is
		// exactly the data the compact object exists to keep.
		_ = unstructured.SetNestedField(out.Object, conv, "spec", "conversion")
	}
	return out
}

// compactCRDFromTyped is compactCRDConversion's twin for objects read
// from the manager's CRD informer cache (typed, schema-stripped with
// .spec.conversion preserved by the cache transform): it produces the
// SAME compact shape — metadata.name plus the whole spec.conversion
// subtree — so every consumer (CRDConversionServiceKey, NestedInt64
// port reads, GetName) sees identical data whichever source served
// the census. The unstructured conversion materializes only the
// conversion subtree, never the stripped schema bulk.
func compactCRDFromTyped(
	crd *apiextensionsv1.CustomResourceDefinition) unstructured.Unstructured {

	out := unstructured.Unstructured{Object: map[string]any{}}
	out.SetName(crd.Name)
	if crd.Spec.Conversion != nil {
		conv, err := runtime.DefaultUnstructuredConverter.ToUnstructured(
			crd.Spec.Conversion)
		if err == nil && len(conv) > 0 {
			_ = unstructured.SetNestedField(out.Object, conv,
				"spec", "conversion")
		}
	}
	return out
}
