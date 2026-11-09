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
//  5. kubernetes-replicator sync drift (replicator-cert-drift) — every TLS Secret
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
//
// Layout: this file holds the shared state/types, the Setup + run
// entry point and the shared helpers; webhook_ca_audit.go Check A,
// tls_secret_audit.go Check B (+ the issuer-serial-watch issuer-serial watch),
// replicated_secret_audit.go Check E, trust_bundle_audit.go Check D.
package certdriftauditor

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

const (
	// injectCAFromAnno carries "namespace/certificateName" — cainjector
	// resolves the Certificate's spec.secretName to find the CA secret.
	injectCAFromAnno = "cert-manager.io/inject-ca-from"
	// injectCAFromSecretAnno carries "namespace/secretName" — a direct
	// reference, no Certificate hop.
	injectCAFromSecretAnno = "cert-manager.io/inject-ca-from-secret"
	// replicatedFromAnno carries "src-namespace/src-name" — the
	// kubernetes-replicator annotation marking a replicated copy
	// (replicator-cert-drift).
	replicatedFromAnno = "replicator.v1.mittwald.de/replicated-from"
	// replicationDriftScans is how many consecutive sweeps a tls.crt
	// mismatch must persist before the drift gauge fires — a
	// single-scan diff just catches the replicator mid-sync.
	replicationDriftScans = 2
	// replicatedFromVersionAnno is the replicator's source-version
	// stamp — removing it on a drifted destination forces
	// kubernetes-replicator to resync the copy (issuer-serial-watch).
	replicatedFromVersionAnno = "replicator.v1.mittwald.de/replicated-from-version"
	replicationResyncCooldown = time.Hour
	// tlsExpiryEmitWindow bounds TLSSecretDaysToExpiry cardinality:
	// the gauge only opens a series for Secrets whose tls.crt expires
	// within this window (or is already expired) — the same budget the
	// downstream alert runs on ("fires <30d, pages <7d"). Far-future
	// certs (the bulk of a cluster's TLS Secrets, and the churners in
	// rotate-name setups) never open a series; one that rotates into
	// the window starts one on the next sweep, and a re-rotation that
	// pushes a tracked Secret back past the window lets the ledger
	// prune its series again.
	tlsExpiryEmitWindow = 30 * 24 * time.Hour
	// linkerd-identity-issuer fingerprint tracking (issuer-serial-watch): the
	// issuer cert's SerialNumber is the fingerprint — a change means
	// cert-manager rotated the issuer and linkerd-identity must
	// re-roll to pick the new bundle up. linkerdIssuerSecret names
	// this module's audit target; the namespace and the Deployment
	// come from the shared kube topology identifiers (LinkerdNS,
	// LinkerdIdentityName).
	linkerdIssuerSecret      = "linkerd-identity-issuer"
	linkerdIssuerRolloutAnno = "kubectl.kubernetes.io/restartedAt"
	linkerdIssuerCooldown    = 30 * time.Minute
)

// certificateGVR resolves a Certificate's spec.secretName — the only
// cert-manager type this module reads.
var certificateGVR = kube.GVRCertificate

// customResourceDefinitionGVR is where Check A reads the CRD
// spec.conversion webhook surface — the typed clientset has no
// apiextensions surface, so CRDs reach through dyn like the
// cert-manager CRDs.
var customResourceDefinitionGVR = schema.GroupVersionResource{
	Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}

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
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the periodic's name and every IncError label
	// come from one place.
	queue string
	// now is the clock seam — tests pin it so days-until-expiry and
	// staleness windows are deterministic.
	now shared.Clock
	// seenWebhooks: gauge series emitted last sweep, kept so an entry
	// that disappears (webhook removed, annotation dropped, config
	// deleted) gets its series pruned instead of pinning drift=1
	// forever.
	seenWebhooks state.GaugeLedger[webhookMetricKey]
	// seenSecrets: same lifecycle for the TLS-expiry gauge.
	seenSecrets state.GaugeLedger[secretMetricKey]
	// seenWebhookExpiry / seenTrustBundles: same lifecycle for the
	// caBundle days-to-expiry and linkerd trust-bundle gauges.
	seenWebhookExpiry state.GaugeLedger[webhookMetricKey]
	seenTrustBundles  state.GaugeLedger[secretMetricKey]
	// replicationMismatch counts consecutive scans where a
	// replicated secret's tls.crt differed from its source — drift
	// fires only at replicationDriftScans, so a replicator mid-sync
	// never raises a false alert (replicator-cert-drift). StreakLedger arms itself
	// lazily, so literal-constructed fixtures need no nil dance.
	replicationMismatch state.StreakLedger
	// seenReplication: series ledger for ReplicatedSecretDrift —
	// re-synced or gone replicas get DeleteLabelValues, never a
	// parked 1.
	seenReplication state.GaugeLedger[replicationMetricKey]
	// resyncHeals: replicationMetricKey → last replicated-from-
	// version annotation strip (1h cooldown, in-RAM only).
	resyncHeals state.CooldownSet
	// linkerdIssuerSerial: the tracked issuer fingerprint;
	// linkerdIssuerHeals is the last rollout-stamp moment — the
	// WIDER of the in-RAM stamp and the
	// passiontech.dev/last-linkerd-issuer-rollout annotation on the
	// Deployment (the annotation survives an operator restart, the
	// ledger survives a failed patch) plus the maintenance-mutex
	// verdict memoized for the sweep.
	linkerdIssuerSerial  string
	linkerdIssuerHeals   state.CooldownSet
	linkerdIssuerTracked bool
	// verdict memoizes the maintenance-mutex evaluation across
	// AllowedV calls within the 1m Verdict TTL. This module gates a
	// single target (the linkerd-identity Deployment) once per 15m
	// sweep, so the memo never serves a second call — kept for
	// parity with the per-target heal loops, not for load.
	verdict kube.Verdict
}

// Setup registers the 15m sweep — or nothing when the
// cluster opts out (CERT_DRIFT_AUDITOR_ENABLED=false, resolved by
// setupModules into Deps.Disabled): same disabled-flag pattern as
// certmanager-reaper.
func Setup(d shared.Deps) error {
	mgr, cs, dyn := d.Mgr, d.CS, d.Dyn
	return shared.SetupNoConfig(d, func() error {
		a := &certDriftAuditor{
			cs:    cs,
			dyn:   dyn,
			queue: d.Name,
			now:   shared.SystemClock,
		}
		return shared.AddPeriodic(mgr, a.queue, 15*time.Minute, a.run)
	})
}

func (a *certDriftAuditor) run(ctx context.Context) error {
	// The audits are independent duties: a broken webhook list must
	// not blind the TLS-expiry gauge (and vice versa), so all three
	// run and their errors join (nil+nil+nil → nil). The periodic
	// wrapper owns run-level IncError, so this run() must not count
	// the error it returns (double-count).
	webhookErr := a.auditWebhookCABundles(ctx)
	tlsErr := a.auditTLSSecrets(ctx)
	trustErr := a.auditTrustBundles(ctx)
	return errors.Join(webhookErr, tlsErr, trustErr)
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// splitNSName parses the "namespace/name" annotation value format —
// exactly two non-empty segments or the reference is malformed.
func splitNSName(ref string) (ns, name string, ok bool) {
	parts := strings.Split(ref, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
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
