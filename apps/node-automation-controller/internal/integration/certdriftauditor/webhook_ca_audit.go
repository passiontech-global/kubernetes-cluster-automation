// webhook_ca_audit.go — Check A of cert-drift-auditor: the webhook
// caBundle surface. Every MutatingWebhook / ValidatingWebhook entry
// gets the two annotation-independent checks (caBundle days-to-expiry,
// empty-bundle + failurePolicy=Fail outage flag); configs carrying a
// cainjector inject annotation additionally get their entries'
// caBundle diffed against the resolved injection-source Secret
// (inject-ca-from Certificate → spec.secretName, or
// inject-ca-from-secret directly). The same three checks then run on
// every CustomResourceDefinition whose spec.conversion.strategy is
// Webhook: cainjector injects into conversion clientConfigs through
// the identical annotations, and a drifted or empty bundle there
// fails EVERY CR read for the whole API group — conversion calls
// have no failurePolicy=Ignore escape hatch. Detect-only — the
// config objects are Flux/cainjector-owned.
package certdriftauditor

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// ---------------------------------------------------------------------------
// Check A — webhook CA bundle drift
// ---------------------------------------------------------------------------

func (a *certDriftAuditor) auditWebhookCABundles(ctx context.Context) error {
	a.seenWebhookExpiry.Begin() // drop any aborted sweep's leftover emissions
	a.seenWebhooks.Begin()      // drop any aborted sweep's leftover emissions
	mutating, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.MutatingWebhookConfigurations(a.cs))
	if err != nil {
		return fmt.Errorf("list mutatingwebhookconfigurations: %w", err)
	}
	validating, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.ValidatingWebhookConfigurations(a.cs))
	if err != nil {
		return fmt.Errorf("list validatingwebhookconfigurations: %w", err)
	}

	for i := range mutating {
		m := &mutating[i]
		a.auditOneWebhookConfig(ctx, "MutatingWebhookConfiguration",
			m.Name, m.Annotations, mutatingEntries(m.Webhooks))
	}
	for i := range validating {
		v := &validating[i]
		a.auditOneWebhookConfig(ctx, "ValidatingWebhookConfiguration",
			v.Name, v.Annotations, validatingEntries(v.Webhooks))
	}

	// CRD conversion webhooks share the caBundle surface — the
	// cainjector annotations and the empty/drifted-bundle failure
	// modes are identical, but the object reaches through dyn (the
	// typed clientset has no apiextensions surface) and the bundle
	// arrives base64-encoded like every []byte JSON field. The list
	// runs AFTER the admission-config audits so their emissions land
	// first, and its failure skips the prune below: "can't read the
	// surface" must not delete live drift series.
	if a.dyn == nil {
		return errors.New("list customresourcedefinitions: no dynamic client")
	}
	crds, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.DynamicPage(a.dyn.Resource(kube.GVRCustomResourceDefinition)))
	if err != nil {
		return fmt.Errorf("list customresourcedefinitions: %w", err)
	}
	for i := range crds {
		crd := &crds[i]
		// Only spec.conversion is read below — strip the OpenAPI
		// schemas (the bulk of a CRD object's heap) before the
		// audit walks the census.
		kube.StripCRDSchemaVersions(crd)
		entry, ok := crdConversionEntry(crd)
		if !ok {
			continue
		}
		a.auditOneWebhookConfig(ctx, "CustomResourceDefinition",
			crd.GetName(), crd.GetAnnotations(), []webhookEntry{entry})
	}

	// Prune series for entries no longer covered — a webhook entry
	// deleted or an annotation removed must not pin drift=1 (or a
	// dead expiry figure) forever.
	a.seenWebhooks.Prune(metrics.WebhookCABundleMismatch.DeleteLabelValues)
	a.seenWebhookExpiry.Prune(metrics.WebhookCABundleDaysToExpiry.DeleteLabelValues)
	return nil
}

// auditOneWebhookConfig runs the two annotation-independent checks on
// EVERY entry first — caBundle expiry (days-until-NotAfter) and the
// empty-bundle fail-closed flag — then the cainjector drift diff for
// configs carrying an inject annotation. When the source cannot be
// resolved (annotation malformed, Certificate/Secret missing), the
// config's previously-emitted drift series are carried forward into
// `current` — a transient lookup failure must not flap an active
// drift alert off.
func (a *certDriftAuditor) auditOneWebhookConfig(ctx context.Context,
	kind, cfgName string, annos map[string]string,
	entries []webhookEntry) {
	log := logf.FromContext(ctx)

	// 2.4 — full surface: expiry + empty-bundle checks apply with or
	// without a cainjector annotation — a hand-managed webhook
	// expires/breaks identically.
	for _, e := range entries {
		k := webhookMetricKey{kind, cfgName, e.name}
		if len(e.caBundle) == 0 {
			// A service-targeted entry with NO caBundle cannot be
			// verified by the apiserver — with failurePolicy=Fail
			// every call errors: an outage signature, flagged as
			// mismatch=1. url-targeted entries legitimately carry
			// no bundle (public CA), so they skip.
			if e.service != nil && e.fail {
				a.seenWebhooks.Set(metrics.WebhookCABundleMismatch, 1,
					k, k.kind, k.name, k.webhook)
				log.Info("webhook entry has empty caBundle with failurePolicy=Fail — admission calls will fail",
					"kind", kind, "config", cfgName, "webhook", e.name)
			}
			continue
		}
		if days, ok := earliestCertExpiryDays(e.caBundle, a.now.Now()); ok {
			a.seenWebhookExpiry.Set(metrics.WebhookCABundleDaysToExpiry, days,
				k, k.kind, k.name, k.webhook)
		} else {
			log.Info("skip: caBundle carries no parseable X.509 PEM",
				"kind", kind, "config", cfgName, "webhook", e.name)
		}
	}

	// The cainjector annotations cover the WHOLE config — without one,
	// no entry is injected, so the config drops out of the drift diff
	// and any previously-emitted series prunes. Distinguish this from
	// "annotated but the source is unresolvable" below: the former is
	// a clean exit, the latter is "can't tell".
	hasInjectAnno := strings.TrimSpace(annos[injectCAFromAnno]) != "" ||
		strings.TrimSpace(annos[injectCAFromSecretAnno]) != ""
	if !hasInjectAnno {
		return
	}

	ca, ok := a.injectionCA(ctx, kind, cfgName, annos)
	if !ok {
		// Keep any previously-emitted series for this config alive —
		// an unresolved source is "can't tell", not "clean", so the
		// alert must not silently flap off on a transient lookup miss.
		for k, lv := range a.seenWebhooks.Last() {
			if k.kind == kind && k.name == cfgName {
				a.seenWebhooks.Emit(k, lv...)
			}
		}
		return
	}
	for _, e := range entries {
		k := webhookMetricKey{kind, cfgName, e.name}
		v := 0.0
		if !bytes.Equal(e.caBundle, ca) {
			v = 1
			log.Info("webhook caBundle drifted from cainjector source",
				"kind", kind, "config", cfgName, "webhook", e.name)
		}
		a.seenWebhooks.Set(metrics.WebhookCABundleMismatch, v,
			k, k.kind, k.name, k.webhook)
	}
}

// injectionCA resolves the CA bytes cainjector is configured to write
// into this webhook config. inject-ca-from wins (it is the canonical
// cert-manager wiring); inject-ca-from-secret is the direct-secret
// fallback. Returns ok=false when there is nothing to compare against
// — no annotation, malformed reference, or an unfetchable source.
func (a *certDriftAuditor) injectionCA(ctx context.Context,
	kind, cfgName string, annos map[string]string) ([]byte, bool) {
	log := logf.FromContext(ctx)

	if ref := strings.TrimSpace(annos[injectCAFromAnno]); ref != "" {
		ns, name, ok := splitNSName(ref)
		if !ok {
			// Malformed — fall THROUGH to inject-ca-from-secret
			// instead of dropping the whole config: cainjector
			// still honors the valid second annotation.
			log.Info("skip: malformed inject-ca-from annotation",
				"kind", kind, "config", cfgName, "value", ref)
		} else {
			secretName, resolved := a.certSecretName(ctx, ns, name)
			if !resolved {
				// Unresolvable source — "can't tell". The caller's
				// carry-forward keeps any emitted series alive.
				return nil, false
			}
			return a.secretCA(ctx, ns, secretName, kind, cfgName)
		}
	}

	if ref := strings.TrimSpace(annos[injectCAFromSecretAnno]); ref != "" {
		ns, name, ok := splitNSName(ref)
		if !ok {
			log.Info("skip: malformed inject-ca-from-secret annotation",
				"kind", kind, "config", cfgName, "value", ref)
			return nil, false
		}
		return a.secretCA(ctx, ns, name, kind, cfgName)
	}

	return nil, false // no inject annotation — config not covered
}

// certSecretName resolves the Secret a Certificate writes to:
// spec.secretName, falling back to the Certificate's own name (the
// de-facto convention and the required fallback when the Certificate
// object or cert-manager CRDs are absent). ok=false means "can't
// resolve": a transient API/RBAC failure must NOT guess the name
// convention — a same-named unrelated Secret would fabricate drift
// (or hide a real one).
func (a *certDriftAuditor) certSecretName(ctx context.Context, ns, certName string) (string, bool) {
	cert, err := a.dyn.Resource(certificateGVR).Namespace(ns).
		Get(ctx, certName, metav1.GetOptions{})
	if err != nil {
		// Only a genuine absence falls back to the name convention;
		// every other failure is unresolvable, not a fallback.
		if apierrors.IsNotFound(err) {
			return certName, true
		}
		logf.FromContext(ctx).Error(err,
			"certificate get failed — injection source unresolvable",
			"cert", ns+"/"+certName)
		return "", false
	}
	if sn, ok := kube.NestedString(
		cert.Object, "spec", "secretName"); ok && sn != "" {
		return sn, true
	}
	return certName, true
}

// secretCA fetches the CA bytes from the injection-source Secret —
// ca.crt is where cainjector reads the bundle from, tls.crt is the
// fallback for secrets that only carry the leaf pair.
func (a *certDriftAuditor) secretCA(ctx context.Context,
	ns, name, kind, cfgName string) ([]byte, bool) {
	log := logf.FromContext(ctx)
	s, err := a.cs.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			log.Error(err, "inject-source secret get failed",
				"kind", kind, "config", cfgName, "secret", ns+"/"+name)
		}
		return nil, false // NotFound is routine (cert not issued yet)
	}
	if ca := s.Data["ca.crt"]; len(ca) > 0 {
		return ca, true
	}
	if ca := s.Data["tls.crt"]; len(ca) > 0 {
		return ca, true
	}
	log.Info("skip: inject-source secret has no ca.crt/tls.crt",
		"kind", kind, "config", cfgName, "secret", ns+"/"+name)
	return nil, false
}

// webhookFails resolves failurePolicy — nil means the API default,
// which IS Fail.
func webhookFails(fp *admissionv1.FailurePolicyType) bool {
	return fp == nil || *fp == admissionv1.Fail
}

func mutatingEntries(ws []admissionv1.MutatingWebhook) []webhookEntry {
	out := make([]webhookEntry, 0, len(ws))
	for _, w := range ws {
		out = append(out, webhookEntry{
			name: w.Name, caBundle: w.ClientConfig.CABundle,
			service: w.ClientConfig.Service, fail: webhookFails(w.FailurePolicy)})
	}
	return out
}

func validatingEntries(ws []admissionv1.ValidatingWebhook) []webhookEntry {
	out := make([]webhookEntry, 0, len(ws))
	for _, w := range ws {
		out = append(out, webhookEntry{
			name: w.Name, caBundle: w.ClientConfig.CABundle,
			service: w.ClientConfig.Service, fail: webhookFails(w.FailurePolicy)})
	}
	return out
}

// crdConversionEntry projects one CRD's spec.conversion webhook into
// the audit's uniform entry shape — ok=false for non-Webhook
// strategies, which have no caBundle surface at all. The "webhook"
// label reads "conversion": a CRD carries exactly one conversion
// clientConfig and it has no name of its own. fail is hard-wired —
// unlike admission webhooks, conversion calls have NO failurePolicy
// knob: an unverifiable backend errors the whole CR read for every
// client, so a service-targeted entry with an empty bundle IS the
// outage signature. The bundle decodes from base64 — []byte fields
// serialize that way through the apiserver's JSON.
func crdConversionEntry(crd *unstructured.Unstructured) (webhookEntry, bool) {
	strategy, _ := kube.NestedString(crd.Object, "spec", "conversion", "strategy")
	if strategy != "Webhook" {
		return webhookEntry{}, false
	}
	e := webhookEntry{name: "conversion", fail: true}
	if b64, ok := kube.NestedString(crd.Object,
		"spec", "conversion", "webhook", "clientConfig", "caBundle"); ok && b64 != "" {
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			// An undecodable bundle is as broken as an empty one —
			// leave caBundle nil so the fail-closed check flags it.
			logf.Log.Info("skip: CRD conversion caBundle is not valid base64",
				"crd", crd.GetName())
		} else {
			e.caBundle = raw
		}
	}
	ns, _ := kube.NestedString(crd.Object,
		"spec", "conversion", "webhook", "clientConfig", "service", "namespace")
	name, _ := kube.NestedString(crd.Object,
		"spec", "conversion", "webhook", "clientConfig", "service", "name")
	if ns != "" && name != "" {
		e.service = &admissionv1.ServiceReference{Namespace: ns, Name: name}
	}
	return e, true
}
