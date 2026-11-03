// cert-drift-auditor — C5 detect-only sweep for the two silent
// certificate failure modes that take down admission and mTLS with no
// warning until they fire:
//
//  1. Webhook CA bundle drift. cert-manager's cainjector copies the
//     issuing CA into EVERY webhook entry's clientConfig.caBundle on
//     the MutatingWebhookConfiguration / ValidatingWebhookConfiguration
//     objects annotated cert-manager.io/inject-ca-from (resolve the
//     Certificate → spec.secretName) or
//     cert-manager.io/inject-ca-from-secret (direct Secret ref). When
//     the CA rotates but cainjector is down, crashlooping, or denied,
//     the caBundle keeps the OLD CA — the apiserver then rejects every
//     webhook call with x509 unknown-authority errors, and any
//     failurePolicy:Fail webhook turns the cluster read-only for
//     admission. The audit diffs each covered entry's caBundle against
//     the live injection-source Secret (ca.crt, fallback tls.crt) and
//     exports drift per sub-webhook. It never patches: admission
//     config is Flux/cainjector-owned and writing it from here would
//     fight the owning controller.
//  2. TLS secret expiry. Every kubernetes.io/tls Secret's tls.crt is
//     parsed and days-until-NotAfter exported as a gauge — catching
//     the secrets cert-manager does NOT manage (hand-installed vendor
//     certs, bootstrap PKI) that have no Certificate object to alert
//     through. Negative days = already expired.
//
// Series lifecycle: both gauges keep a seen-set — secrets deleted and
// webhook entries/annotations removed since the last sweep get their
// series pruned via DeleteLabelValues so /metrics cannot pin a stale
// drift alert forever.
package integration

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/controller/shared"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
)

const (
	certDriftQueue = "cert-drift-auditor"
	// injectCAFromAnno carries "namespace/certificateName" — cainjector
	// resolves the Certificate's spec.secretName to find the CA secret.
	injectCAFromAnno = "cert-manager.io/inject-ca-from"
	// injectCAFromSecretAnno carries "namespace/secretName" — a direct
	// reference, no Certificate hop.
	injectCAFromSecretAnno = "cert-manager.io/inject-ca-from-secret"
)

// webhookMetricKey / secretMetricKey are the exact label tuples of the
// two exported gauge vecs — keeping them as map keys makes the
// prune-sweep trivially exact (no string splitting on re-emit).
type webhookMetricKey struct{ kind, name, webhook string }
type secretMetricKey struct{ namespace, name string }

// webhookEntry flattens the two webhook entry types (MutatingWebhook /
// ValidatingWebhook share WebhookClientConfig) down to the pair this
// audit compares.
type webhookEntry struct {
	name     string
	caBundle []byte
}

type certDriftAuditor struct {
	cs  kubernetes.Interface
	dyn dynamic.Interface
	// nowFn is the clock seam — tests pin it so days-until-expiry and
	// staleness windows are deterministic.
	nowFn func() time.Time
	// seenWebhooks: gauge series emitted last sweep, kept so an entry
	// that disappears (webhook removed, annotation dropped, config
	// deleted) gets its series pruned instead of pinning drift=1
	// forever.
	seenWebhooks map[webhookMetricKey]bool
	// seenSecrets: same lifecycle for the TLS-expiry gauge.
	seenSecrets map[secretMetricKey]bool
}

// SetupCertDriftAuditor registers the 15m sweep — or nothing when the
// cluster opts out (CERT_DRIFT_AUDITOR_ENABLED=false in main.go feeds
// `enabled`): same disabled-flag pattern as certmanager-reaper.
func SetupCertDriftAuditor(mgr ctrl.Manager, cs kubernetes.Interface,
	dyn dynamic.Interface, enabled bool) error {
	if !enabled {
		logf.Log.WithName(certDriftQueue).Info("disabled — module not registered")
		return nil
	}
	a := &certDriftAuditor{
		cs:           cs,
		dyn:          dyn,
		nowFn:        time.Now,
		seenWebhooks: map[webhookMetricKey]bool{},
		seenSecrets:  map[secretMetricKey]bool{},
	}
	return shared.AddPeriodic(mgr, certDriftQueue, 15*time.Minute, a.run)
}

func (a *certDriftAuditor) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	// Lazily arm the zero-value struct — unit tests construct the
	// auditor literally without the Setup path.
	if a.nowFn == nil {
		a.nowFn = time.Now
	}
	if a.seenWebhooks == nil {
		a.seenWebhooks = map[webhookMetricKey]bool{}
	}
	if a.seenSecrets == nil {
		a.seenSecrets = map[secretMetricKey]bool{}
	}

	// The two audits are independent: a broken webhook list must not
	// blind the TLS-expiry gauge (and vice versa). The first error
	// propagates — the periodic wrapper owns run-level IncError, so
	// this run() must not count the error it returns (double-count).
	var firstErr error
	if err := a.auditWebhookCABundles(ctx); err != nil {
		log.Error(err, "webhook ca-bundle audit failed")
		firstErr = err
	}
	if err := a.auditTLSSecrets(ctx); err != nil {
		log.Error(err, "tls secret expiry audit failed")
		if firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// ---------------------------------------------------------------------------
// Check A — webhook CA bundle drift
// ---------------------------------------------------------------------------

func (a *certDriftAuditor) auditWebhookCABundles(ctx context.Context) error {
	mutating, err := a.cs.AdmissionregistrationV1().
		MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list mutatingwebhookconfigurations: %w", err)
	}
	validating, err := a.cs.AdmissionregistrationV1().
		ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list validatingwebhookconfigurations: %w", err)
	}

	current := map[webhookMetricKey]bool{}
	for i := range mutating.Items {
		m := &mutating.Items[i]
		a.auditOneWebhookConfig(ctx, "MutatingWebhookConfiguration",
			m.Name, m.Annotations, mutatingEntries(m.Webhooks), current)
	}
	for i := range validating.Items {
		v := &validating.Items[i]
		a.auditOneWebhookConfig(ctx, "ValidatingWebhookConfiguration",
			v.Name, v.Annotations, validatingEntries(v.Webhooks), current)
	}

	// Prune series for entries no longer covered — a webhook entry
	// deleted or an annotation removed must not pin drift=1 forever.
	for k := range a.seenWebhooks {
		if !current[k] {
			metrics.WebhookCABundleMismatch.DeleteLabelValues(k.kind, k.name, k.webhook)
		}
	}
	a.seenWebhooks = current
	return nil
}

// auditOneWebhookConfig resolves the config's cainjector source and
// diffs every covered webhook entry's caBundle against it. The
// cainjector annotations cover the WHOLE config (every entry gets the
// CA written), so entries only fall outside the audit when the config
// carries no inject annotation at all. When the source cannot be
// resolved (annotation malformed, Certificate/Secret missing), the
// config's previously-emitted series are carried forward into
// `current` — a transient lookup failure must not flap an active
// drift alert off.
func (a *certDriftAuditor) auditOneWebhookConfig(ctx context.Context,
	kind, cfgName string, annos map[string]string,
	entries []webhookEntry, current map[webhookMetricKey]bool) {
	log := logf.FromContext(ctx)

	// The cainjector annotations cover the WHOLE config — without one,
	// no entry is injected, so the config drops out of the audit and
	// any previously-emitted series prunes. Distinguish this from
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
		for k := range a.seenWebhooks {
			if k.kind == kind && k.name == cfgName {
				current[k] = true
			}
		}
		return
	}
	for _, e := range entries {
		k := webhookMetricKey{kind, cfgName, e.name}
		current[k] = true
		v := 0.0
		if !bytes.Equal(e.caBundle, ca) {
			v = 1
			log.Info("webhook caBundle drifted from cainjector source",
				"kind", kind, "config", cfgName, "webhook", e.name)
		}
		metrics.WebhookCABundleMismatch.WithLabelValues(k.kind, k.name, k.webhook).Set(v)
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
			secretName := a.certSecretName(ctx, ns, name)
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
// object or cert-manager CRDs are absent).
func (a *certDriftAuditor) certSecretName(ctx context.Context, ns, certName string) string {
	cert, err := a.dyn.Resource(certificateGVR).Namespace(ns).
		Get(ctx, certName, metav1.GetOptions{})
	if err != nil {
		// Only a genuine absence falls back to the name convention;
		// a transient API/RBAC failure could resolve to a Secret of
		// the same name holding a DIFFERENT CA → false drift.
		if apierrors.IsNotFound(err) {
			return certName
		}
		logf.FromContext(ctx).Error(err,
			"certificate get failed — keeping cert name (may be wrong)",
			"cert", ns+"/"+certName)
		return certName
	}
	if sn, _, _ := unstructured.NestedString(
		cert.Object, "spec", "secretName"); sn != "" {
		return sn
	}
	return certName
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

// splitNSName parses the "namespace/name" annotation value format —
// exactly two non-empty segments or the reference is malformed.
func splitNSName(ref string) (ns, name string, ok bool) {
	parts := strings.Split(ref, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func mutatingEntries(ws []admissionv1.MutatingWebhook) []webhookEntry {
	out := make([]webhookEntry, 0, len(ws))
	for _, w := range ws {
		out = append(out, webhookEntry{name: w.Name, caBundle: w.ClientConfig.CABundle})
	}
	return out
}

func validatingEntries(ws []admissionv1.ValidatingWebhook) []webhookEntry {
	out := make([]webhookEntry, 0, len(ws))
	for _, w := range ws {
		out = append(out, webhookEntry{name: w.Name, caBundle: w.ClientConfig.CABundle})
	}
	return out
}

// ---------------------------------------------------------------------------
// Check B — TLS secret expiry
// ---------------------------------------------------------------------------

func (a *certDriftAuditor) auditTLSSecrets(ctx context.Context) error {
	log := logf.FromContext(ctx)
	secrets, err := a.cs.CoreV1().Secrets(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{
			FieldSelector: "type=kubernetes.io/tls",
		})
	if err != nil {
		return fmt.Errorf("list tls secrets: %w", err)
	}

	current := map[secretMetricKey]bool{}
	for i := range secrets.Items {
		s := &secrets.Items[i]
		// Belt-and-suspenders: the type field selector is applied
		// server-side on a real apiserver, but fake clientsets ignore
		// it — an in-code check keeps both honest (same rule as the
		// pod-phase filter in cilium_identity_auditor).
		if s.Type != corev1.SecretTypeTLS {
			continue
		}
		block, _ := pem.Decode(s.Data["tls.crt"])
		if block == nil {
			log.Info("skip: tls secret carries no decodable tls.crt PEM",
				"secret", s.Namespace+"/"+s.Name)
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Error(err, "tls.crt parse failed",
				"secret", s.Namespace+"/"+s.Name)
			continue
		}
		key := secretMetricKey{s.Namespace, s.Name}
		current[key] = true
		// Days, not seconds — the alert budget this feeds ("fires
		// <30d, pages <7d") thinks in days; negatives mean expired.
		days := cert.NotAfter.Sub(a.nowFn()).Hours() / 24
		metrics.TLSSecretDaysToExpiry.
			WithLabelValues(s.Namespace, s.Name).Set(days)
	}

	// Prune series for secrets gone (or no longer parseable) since the
	// last sweep — otherwise /metrics keeps reporting a dead secret.
	for k := range a.seenSecrets {
		if !current[k] {
			metrics.TLSSecretDaysToExpiry.DeleteLabelValues(k.namespace, k.name)
		}
	}
	a.seenSecrets = current
	return nil
}
