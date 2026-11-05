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
//  3. Webhook caBundle expiry — every clientConfig.caBundle of every
//     webhook entry (annotated or not) feeds days-to-expiry, and an
//     EMPTY bundle on a service-targeted entry with
//     failurePolicy=Fail flags mismatch=1 (an apiserver that cannot
//     verify TLS + fail-closed = admission outage).
//  4. Linkerd trust bundles — ConfigMap
//     linkerd/linkerd-identity-trust-roots (ca-bundle.crt) and any
//     Secret in namespace linkerd carrying ca.crt/crt.pem (Opaque
//     included, e.g. linkerd-identity-issuer) get days-to-expiry of
//     the earliest cert in the bundle.
//  5. kubernetes-replicator sync drift (W7-C6) — every TLS Secret
//     carrying replicator.v1.mittwald.de/replicated-from has its
//     tls.crt compared against the source Secret's. A mismatch that
//     persists across >= 2 consecutive scans flags
//     replicated_secret_drift=1 (the replicator missed a watch
//     event or the copy was hand-edited); a single-scan mismatch is
//     ignored because it catches the replicator mid-sync.
//
// Series lifecycle: both gauges keep a seen-set — secrets deleted and
// webhook entries/annotations removed since the last sweep get their
// series pruned via DeleteLabelValues so /metrics cannot pin a stale
// drift alert forever.
package certdriftauditor

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

const (
	certDriftQueue = "cert-drift-auditor"
	// injectCAFromAnno carries "namespace/certificateName" — cainjector
	// resolves the Certificate's spec.secretName to find the CA secret.
	injectCAFromAnno = "cert-manager.io/inject-ca-from"
	// injectCAFromSecretAnno carries "namespace/secretName" — a direct
	// reference, no Certificate hop.
	injectCAFromSecretAnno = "cert-manager.io/inject-ca-from-secret"
	// certDriftListPage caps each cluster-wide List response — the
	// all-namespaces TLS-secret read is unbounded.
	certDriftListPage = 500
	// replicatedFromAnno carries "src-namespace/src-name" — the
	// kubernetes-replicator annotation marking a replicated copy
	// (W7-C6).
	replicatedFromAnno = "replicator.v1.mittwald.de/replicated-from"
	// replicationDriftScans is how many consecutive sweeps a tls.crt
	// mismatch must persist before the drift gauge fires — a
	// single-scan diff just catches the replicator mid-sync.
	replicationDriftScans = 2
	// replicatedFromVersionAnno is the replicator's source-version
	// stamp — removing it on a drifted destination forces
	// kubernetes-replicator to resync the copy (W8-NM2).
	replicatedFromVersionAnno = "replicator.v1.mittwald.de/replicated-from-version"
	replicationResyncCooldown = time.Hour
	// linkerd-identity-issuer fingerprint tracking (W8-NM2): the
	// issuer cert's SerialNumber is the fingerprint — a change means
	// cert-manager rotated the issuer and linkerd-identity must
	// re-roll to pick the new bundle up.
	linkerdIssuerSecret      = "linkerd-identity-issuer"
	linkerdIssuerDeploy      = "linkerd-identity"
	linkerdIssuerRolloutAnno = "kubectl.kubernetes.io/restartedAt"
	linkerdIssuerCooldown    = 30 * time.Minute
)

// certificateGVR resolves a Certificate's spec.secretName — the only
// cert-manager type this module reads.
var certificateGVR = shared.GVRCertificate

// webhookMetricKey / secretMetricKey are the exact label tuples of the
// two exported gauge vecs — keeping them as map keys makes the
// prune-sweep trivially exact (no string splitting on re-emit).
type webhookMetricKey struct{ kind, name, webhook string }
type secretMetricKey struct{ namespace, name string }

// replicationMetricKey is the exact label tuple of the
// ReplicatedSecretDrift gauge — source is the verbatim
// "src-ns/src-name" annotation value (a slash inside a label VALUE
// is unambiguous).
type replicationMetricKey struct{ namespace, name, source string }

// replicatedSecretRef is one replicated TLS Secret discovered in the
// sweep — the destination identity plus its raw tls.crt for the
// source comparison.
type replicatedSecretRef struct {
	namespace, name, source string
	dest                    []byte
}

// webhookEntry flattens the two webhook entry types (MutatingWebhook /
// ValidatingWebhook share WebhookClientConfig) down to the fields this
// audit compares.
type webhookEntry struct {
	name     string
	caBundle []byte
	// service non-nil means the entry targets an in-cluster Service
	// (vs a url clientConfig) — the only shape where a caBundle is
	// strictly required.
	service *admissionv1.ServiceReference
	// fail resolves spec.failurePolicy == Fail — nil counts too:
	// the API default IS Fail.
	fail bool
}

type certDriftAuditor struct {
	cs  kubernetes.Interface
	dyn dynamic.Interface
	// nowFn is the clock seam — tests pin it so days-until-expiry and
	// staleness windows are deterministic.
	nowFn shared.Clock
	// seenWebhooks: gauge series emitted last sweep, kept so an entry
	// that disappears (webhook removed, annotation dropped, config
	// deleted) gets its series pruned instead of pinning drift=1
	// forever.
	seenWebhooks shared.GaugeLedger[webhookMetricKey]
	// seenSecrets: same lifecycle for the TLS-expiry gauge.
	seenSecrets shared.GaugeLedger[secretMetricKey]
	// seenWebhookExpiry / seenTrustBundles: same lifecycle for the
	// caBundle days-to-expiry and linkerd trust-bundle gauges.
	seenWebhookExpiry shared.GaugeLedger[webhookMetricKey]
	seenTrustBundles  shared.GaugeLedger[secretMetricKey]
	// replicationMismatch counts consecutive scans where a
	// replicated secret's tls.crt differed from its source — drift
	// fires only at replicationDriftScans, so a replicator mid-sync
	// never raises a false alert (W7-C6).
	replicationMismatch map[replicationMetricKey]int
	// seenReplication: series ledger for ReplicatedSecretDrift —
	// re-synced or gone replicas get DeleteLabelValues, never a
	// parked 1.
	seenReplication shared.GaugeLedger[replicationMetricKey]
	// resyncNudged: replicationMetricKey → last replicated-from-
	// version annotation strip (1h cooldown, in-RAM only).
	resyncNudged map[replicationMetricKey]time.Time
	// linkerdIssuerSerial / linkerdIssuerHealed: the tracked issuer
	// fingerprint and the last rollout-stamp moment (30m cooldown).
	linkerdIssuerSerial  string
	linkerdIssuerHealed  time.Time
	linkerdIssuerTracked bool
}

// Setup registers the 15m sweep — or nothing when the
// cluster opts out (CERT_DRIFT_AUDITOR_ENABLED=false): same
// disabled-flag pattern as certmanager-reaper.
func Setup(d shared.Deps) error {
	mgr, cs, dyn := d.Mgr, d.CS, d.Dyn
	if !shared.Gate("CERT_DRIFT_AUDITOR_ENABLED", true) {
		logf.Log.WithName(certDriftQueue).Info("disabled — module not registered")
		return nil
	}
	a := &certDriftAuditor{
		cs:                  cs,
		dyn:                 dyn,
		nowFn:               time.Now,
		replicationMismatch: map[replicationMetricKey]int{},
		resyncNudged:        map[replicationMetricKey]time.Time{},
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
	if a.replicationMismatch == nil {
		a.replicationMismatch = map[replicationMetricKey]int{}
	}

	// The audits are independent: a broken webhook list must not
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
	if err := a.auditTrustBundles(ctx); err != nil {
		log.Error(err, "linkerd trust-bundle audit failed")
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

	for i := range mutating.Items {
		m := &mutating.Items[i]
		a.auditOneWebhookConfig(ctx, "MutatingWebhookConfiguration",
			m.Name, m.Annotations, mutatingEntries(m.Webhooks))
	}
	for i := range validating.Items {
		v := &validating.Items[i]
		a.auditOneWebhookConfig(ctx, "ValidatingWebhookConfiguration",
			v.Name, v.Annotations, validatingEntries(v.Webhooks))
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
				a.seenWebhooks.Emit(k, k.kind, k.name, k.webhook)
				metrics.WebhookCABundleMismatch.
					WithLabelValues(k.kind, k.name, k.webhook).Set(1)
				log.Info("webhook entry has empty caBundle with failurePolicy=Fail — admission calls will fail",
					"kind", kind, "config", cfgName, "webhook", e.name)
			}
			continue
		}
		if days, ok := earliestCertExpiryDays(e.caBundle, a.nowFn()); ok {
			a.seenWebhookExpiry.Emit(k, k.kind, k.name, k.webhook)
			metrics.WebhookCABundleDaysToExpiry.
				WithLabelValues(k.kind, k.name, k.webhook).Set(days)
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
		a.seenWebhooks.Emit(k, k.kind, k.name, k.webhook)
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
	if sn, ok := shared.NestedString(
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

// splitNSName parses the "namespace/name" annotation value format —
// exactly two non-empty segments or the reference is malformed.
func splitNSName(ref string) (ns, name string, ok bool) {
	parts := strings.Split(ref, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
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

// ---------------------------------------------------------------------------
// Check B — TLS secret expiry
// ---------------------------------------------------------------------------

func (a *certDriftAuditor) auditTLSSecrets(ctx context.Context) error {
	log := logf.FromContext(ctx)

	// W7-C6 — the sweep collects two extra payloads on the same
	// paged read: tlsData snapshots every TLS secret's raw tls.crt
	// (parseable or not — drift is a byte comparison, not a cert
	// parse), and replicated holds every destination carrying the
	// replicated-from annotation for the source-diff pass.
	tlsData := map[string][]byte{}
	var replicated []replicatedSecretRef
	// Server-side type filter + continue-token pagination: the
	// all-namespaces secret read is the biggest this module makes —
	// page it at certDriftListPage so no single response dominates.
	err := shared.ListEach(ctx, metav1.ListOptions{
		FieldSelector: "type=kubernetes.io/tls",
		Limit:         certDriftListPage,
	}, shared.Secrets(a.cs, metav1.NamespaceAll),
		func(items []corev1.Secret) error {
			for i := range items {
				s := &items[i]
				// Belt-and-suspenders: the type field selector is applied
				// server-side on a real apiserver, but fake clientsets
				// ignore it — an in-code check keeps both honest (same
				// rule as the pod-phase filter in cilium_identity_auditor).
				if s.Type != corev1.SecretTypeTLS {
					continue
				}
				tlsData[s.Namespace+"/"+s.Name] = s.Data["tls.crt"]
				if src := strings.TrimSpace(s.Annotations[replicatedFromAnno]); src != "" {
					replicated = append(replicated, replicatedSecretRef{
						namespace: s.Namespace, name: s.Name,
						source: src, dest: s.Data["tls.crt"],
					})
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
				a.seenSecrets.Emit(key, s.Namespace, s.Name)
				// Days, not seconds — the alert budget this feeds ("fires
				// <30d, pages <7d") thinks in days; negatives mean expired.
				days := cert.NotAfter.Sub(a.nowFn()).Hours() / 24
				metrics.TLSSecretDaysToExpiry.
					WithLabelValues(s.Namespace, s.Name).Set(days)
			}
			return nil
		})
	if err != nil {
		return fmt.Errorf("list tls secrets: %w", err)
	}

	// Prune series for secrets gone (or no longer parseable) since the
	// last sweep — otherwise /metrics keeps reporting a dead secret.
	a.seenSecrets.Prune(metrics.TLSSecretDaysToExpiry.DeleteLabelValues)

	// W7-C6 — the replicator drift diff rides the same read: every
	// replicated destination's tls.crt is compared against its
	// source (the TLS map first, a direct Get for non-TLS sources).
	a.auditReplicatedSecrets(ctx, tlsData, replicated)
	return nil
}

// ---------------------------------------------------------------------------
// Check E — kubernetes-replicator sync drift (W7-C6)
// ---------------------------------------------------------------------------

// auditReplicatedSecrets diffs each replicated TLS secret's tls.crt
// against its source. The comparison is bytes — the replicator
// copies data verbatim, so ANY byte difference is drift (a rotated
// source cert the copy missed, or a hand-edited destination). A
// mismatch must persist replicationDriftScans consecutive sweeps
// before the gauge fires: a single-scan diff is the replicator
// mid-sync, not a wedge. A matched copy resets the streak and drops
// any held series via DeleteLabelValues.
func (a *certDriftAuditor) auditReplicatedSecrets(ctx context.Context,
	tlsData map[string][]byte, replicated []replicatedSecretRef) {
	log := logf.FromContext(ctx)

	for _, d := range replicated {
		k := replicationMetricKey{
			namespace: d.namespace, name: d.name, source: d.source}
		src, ok := tlsData[d.source]
		if !ok {
			// Source not in the TLS sweep — it may be a non-TLS
			// (Opaque) secret; a direct Get resolves it. Malformed
			// refs and genuinely-missing sources are skipped —
			// "can't compare" is not drift. A transient Get failure
			// carries the last verdict forward (same shape as the
			// cainjector path's carry-forward).
			srcNS, srcName, refOK := splitNSName(d.source)
			if !refOK {
				log.Info("skip: malformed replicated-from annotation",
					"secret", d.namespace+"/"+d.name, "value", d.source)
				continue
			}
			s, err := a.cs.CoreV1().Secrets(srcNS).Get(ctx, srcName, metav1.GetOptions{})
			switch {
			case err == nil:
				src = s.Data["tls.crt"]
				if len(src) == 0 {
					continue // source has no tls.crt — nothing to compare
				}
			case apierrors.IsNotFound(err):
				continue // source gone — the replica's problem, not drift
			default:
				log.Error(err, "replicated source get failed — verdict carried forward",
					"secret", d.namespace+"/"+d.name, "source", d.source)
				if lv, ok := a.seenReplication.Last()[k]; ok {
					a.seenReplication.Emit(k, lv...)
				}
				continue
			}
		}
		a.seenReplication.Emit(k, k.namespace, k.name, k.source)
		if bytes.Equal(d.dest, src) {
			delete(a.replicationMismatch, k)
			if _, ok := a.seenReplication.Last()[k]; ok {
				metrics.ReplicatedSecretDrift.
					DeleteLabelValues(k.namespace, k.name, k.source)
			}
			continue
		}
		a.replicationMismatch[k]++
		if a.replicationMismatch[k] < replicationDriftScans {
			continue // first mismatch — the replicator may be mid-sync
		}
		metrics.ReplicatedSecretDrift.
			WithLabelValues(k.namespace, k.name, k.source).Set(1)
		log.Info("replicated tls secret drifted from source across scans",
			"secret", d.namespace+"/"+d.name, "source", d.source,
			"consecutiveScans", a.replicationMismatch[k])
		// W8-NM2: a confirmed drift means the replicator missed the
		// update — stripping the replicated-from-version stamp
		// makes it resync on its next reconcile (1h cooldown).
		a.forceReplicationResync(ctx, d, k)
	}

	// Prune series + streaks for replicas gone (or sources no longer
	// comparable) since the last sweep.
	a.seenReplication.Prune(metrics.ReplicatedSecretDrift.DeleteLabelValues)
	for k := range a.replicationMismatch {
		if _, ok := a.seenReplication.Last()[k]; !ok {
			delete(a.replicationMismatch, k)
		}
	}
}

// forceReplicationResync strips the replicated-from-version
// annotation on a drifted destination so kubernetes-replicator copies
// the source fresh on its next pass — rate-limited to once per
// destination per hour (in-RAM: the annotation removal is the heal).
func (a *certDriftAuditor) forceReplicationResync(ctx context.Context,
	d replicatedSecretRef, k replicationMetricKey) {
	log := logf.FromContext(ctx)
	if a.resyncNudged == nil {
		a.resyncNudged = map[replicationMetricKey]time.Time{} // literal-constructed auditors (tests)
	}
	now := a.nowFn()
	if last, ok := a.resyncNudged[k]; ok && now.Sub(last) < replicationResyncCooldown {
		log.Info("skip resync: replicated secret inside cooldown",
			"secret", d.namespace+"/"+d.name,
			"ago", now.Sub(last).Truncate(time.Minute))
		return
	}
	payload, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"annotations": map[string]any{
			replicatedFromVersionAnno: nil,
		}},
	})
	if err != nil {
		return
	}
	if _, err := a.cs.CoreV1().Secrets(d.namespace).Patch(ctx, d.name,
		types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		metrics.IncError(certDriftQueue)
		log.Error(err, "replicated-from-version strip failed",
			"secret", d.namespace+"/"+d.name)
		return
	}
	a.resyncNudged[k] = now
	log.Info("ACTION: stripped replicated-from-version — forcing kubernetes-replicator resync",
		"secret", d.namespace+"/"+d.name, "source", d.source)
}

// auditLinkerdIssuer tracks the linkerd-identity-issuer Secret's
// certificate fingerprint (SerialNumber): a cert-manager rotation
// changes it, and linkerd-identity must re-roll to serve the new
// issuer — a wedged rollout after rotation breaks mTLS mesh-wide.
// First sight only seeds the fingerprint; a CHANGE patches a rollout
// annotation on Deployment/linkerd-identity (30m cooldown).
func (a *certDriftAuditor) auditLinkerdIssuer(ctx context.Context, s *corev1.Secret) {
	log := logf.FromContext(ctx)
	var serial string
	for _, key := range []string{"tls.crt", "crt.pem", "ca.crt"} {
		block, _ := pem.Decode(s.Data[key])
		if block == nil {
			continue
		}
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			serial = cert.SerialNumber.String()
			break
		}
	}
	if serial == "" {
		return
	}
	if !a.linkerdIssuerTracked {
		a.linkerdIssuerTracked = true
		a.linkerdIssuerSerial = serial
		return
	}
	if serial == a.linkerdIssuerSerial {
		return
	}
	a.linkerdIssuerSerial = serial
	now := a.nowFn()
	if now.Sub(a.linkerdIssuerHealed) < linkerdIssuerCooldown {
		log.Info("skip issuer rollout: inside cooldown",
			"ago", now.Sub(a.linkerdIssuerHealed).Truncate(time.Minute))
		return
	}
	payload, err := json.Marshal(map[string]any{
		"spec": map[string]any{"template": map[string]any{
			"metadata": map[string]any{"annotations": map[string]string{
				linkerdIssuerRolloutAnno: now.UTC().Format(time.RFC3339),
			}},
		}},
	})
	if err != nil {
		return
	}
	if _, err := a.cs.AppsV1().Deployments(linkerdNS).Patch(ctx, linkerdIssuerDeploy,
		types.StrategicMergePatchType, payload, metav1.PatchOptions{}); err != nil {
		metrics.IncError(certDriftQueue)
		log.Error(err, "linkerd-identity rollout stamp failed")
		return
	}
	a.linkerdIssuerHealed = now
	metrics.ControlPlanePodHealsTotal.WithLabelValues(linkerdIssuerDeploy).Inc()
	log.Info("ACTION: issuer cert rotated (serial changed) — stamped rollout annotation on linkerd-identity")
}

// earliestCertExpiryDays returns days until the earliest NotAfter
// across every CERTIFICATE PEM block in the bundle — a bundle is as
// dead as its first-to-expire cert for alerting purposes. ok=false
// when nothing parses.
func earliestCertExpiryDays(bundle []byte, now time.Time) (float64, bool) {
	var earliest *time.Time
	rest := bundle
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		t := cert.NotAfter
		if earliest == nil || t.Before(*earliest) {
			earliest = &t
		}
	}
	if earliest == nil {
		return 0, false
	}
	return earliest.Sub(now).Hours() / 24, true
}

// ---------------------------------------------------------------------------
// Check D — linkerd trust-bundle expiry (2.4)
// ---------------------------------------------------------------------------

const (
	linkerdNS            = "linkerd"
	linkerdTrustRootsCM  = "linkerd-identity-trust-roots"
	linkerdTrustRootsKey = "ca-bundle.crt"
)

// auditTrustBundles exports days-to-expiry for the linkerd trust
// surface: the linkerd-identity-trust-roots ConfigMap
// (ca-bundle.crt) plus every Secret in namespace linkerd carrying a
// ca.crt or crt.pem key — linkerd-identity-issuer is a plain Opaque
// Secret (not kubernetes.io/tls), which is exactly why the TLS-secret
// audit above cannot see it. An expired trust root wedges every new
// proxy handshake (no mTLS) while existing connections still work —
// the classic "mesh died silently" failure.
func (a *certDriftAuditor) auditTrustBundles(ctx context.Context) error {
	// The trust-roots ConfigMap is optional — clusters without
	// linkerd (or a differently-named install) simply skip.
	cm, err := a.cs.CoreV1().ConfigMaps(linkerdNS).
		Get(ctx, linkerdTrustRootsCM, metav1.GetOptions{})
	switch {
	case err == nil:
		a.emitTrustBundle(ctx, linkerdNS, linkerdTrustRootsCM,
			[]byte(cm.Data[linkerdTrustRootsKey]))
	case !apierrors.IsNotFound(err):
		return fmt.Errorf("get linkerd trust-roots configmap: %w", err)
	}

	secrets, err := a.cs.CoreV1().Secrets(linkerdNS).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list linkerd secrets: %w", err)
	}
	for i := range secrets.Items {
		s := &secrets.Items[i]
		// Concatenate every bundle key — earliest expiry across
		// ca.crt + crt.pem is what the gauge reports.
		var bundle []byte
		for _, key := range []string{"ca.crt", "crt.pem"} {
			bundle = append(bundle, s.Data[key]...)
		}
		if len(bundle) == 0 {
			continue
		}
		a.emitTrustBundle(ctx, s.Namespace, s.Name, bundle)
		if s.Name == linkerdIssuerSecret {
			a.auditLinkerdIssuer(ctx, s)
		}
	}

	// Prune series for bundles deleted since the last sweep — the
	// same seen-set lifecycle as the other two gauges.
	a.seenTrustBundles.Prune(metrics.TrustBundleDaysToExpiry.DeleteLabelValues)
	return nil
}

// emitTrustBundle parses the earliest cert expiry out of a PEM bundle
// and lands it on the gauge — unparseable bundles log + emit nothing.
func (a *certDriftAuditor) emitTrustBundle(ctx context.Context, ns, name string,
	bundle []byte) {
	if len(bundle) == 0 {
		return
	}
	days, ok := earliestCertExpiryDays(bundle, a.nowFn())
	if !ok {
		logf.FromContext(ctx).Info("skip: trust bundle carries no parseable X.509 PEM",
			"object", ns+"/"+name)
		return
	}
	a.seenTrustBundles.Emit(secretMetricKey{ns, name}, ns, name)
	metrics.TrustBundleDaysToExpiry.WithLabelValues(ns, name).Set(days)
}
