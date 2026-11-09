// trust_bundle_audit.go — Check D of cert-drift-auditor: days-to-
// expiry for the linkerd trust surface — the
// linkerd-identity-trust-roots ConfigMap (ca-bundle.crt) plus every
// Secret in namespace linkerd carrying ca.crt/crt.pem (Opaque
// included, e.g. linkerd-identity-issuer, which the TLS-secret audit
// cannot see). The issuer-serial rollout watch lives in
// tls_secret_audit.go.
package certdriftauditor

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// ---------------------------------------------------------------------------
// Check D — linkerd trust-bundle expiry (2.4)
// ---------------------------------------------------------------------------

const (
	// linkerdTrustRootsCM/Key name the trust surface; the namespace
	// is the shared kube.kube.LinkerdNS topology identifier.
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
	a.seenTrustBundles.Begin() // drop any aborted sweep's leftover emissions
	// The trust-roots ConfigMap is optional — clusters without
	// linkerd (or a differently-named install) simply skip.
	var trustRootsPEM []byte
	cm, err := a.cs.CoreV1().ConfigMaps(kube.LinkerdNS).
		Get(ctx, linkerdTrustRootsCM, metav1.GetOptions{})
	switch {
	case err == nil:
		trustRootsPEM = []byte(cm.Data[linkerdTrustRootsKey])
		a.emitTrustBundle(ctx, kube.LinkerdNS, linkerdTrustRootsCM,
			trustRootsPEM)
	case !apierrors.IsNotFound(err):
		return fmt.Errorf("get linkerd trust-roots configmap: %w", err)
	}

	var issuerPEM []byte
	issuerSeen := false
	secrets, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.Secrets(a.cs, kube.LinkerdNS))
	if err != nil {
		return fmt.Errorf("list linkerd secrets: %w", err)
	}
	for i := range secrets {
		s := &secrets[i]
		if s.Name == linkerdIssuerSecret {
			issuerSeen = true
			// W19-NM2 — the issuer's serving cert is crt.pem;
			// ca.crt/tls.crt are the fallbacks for installs that
			// key it differently. Detected BEFORE the bundle-empty
			// skip below: an issuer carrying only tls.crt still
			// counts as "seen" for the skew audit.
			for _, key := range []string{"crt.pem", "ca.crt", "tls.crt"} {
				if len(s.Data[key]) > 0 {
					issuerPEM = s.Data[key]
					break
				}
			}
			a.auditLinkerdIssuer(ctx, s)
		}
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
	}
	a.auditTrustAnchorSkew(ctx, trustRootsPEM, issuerPEM, issuerSeen)

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
	days, ok := earliestCertExpiryDays(bundle, a.now.Now())
	if !ok {
		logf.FromContext(ctx).Info("skip: trust bundle carries no parseable X.509 PEM",
			"object", ns+"/"+name)
		return
	}
	a.seenTrustBundles.Set(metrics.TrustBundleDaysToExpiry, days,
		secretMetricKey{ns, name}, ns, name)
}

// ---------------------------------------------------------------------------
// W19-NM2 — issuer↔trust-roots chain verification
// ---------------------------------------------------------------------------

// auditTrustAnchorSkew lands the skew verdict on
// LinkerdTrustAnchorSkew: 1 when the issuer cert cannot chain to ANY
// trust root, 0 when it verifies (or when no issuer secret exists —
// an absent pair cannot skew). Unparseable inputs leave the gauge
// untouched: the expiry audit already owns the "bundle carries no
// parseable X.509" signal, and an unverifiable read must not clear
// a real skew.
func (a *certDriftAuditor) auditTrustAnchorSkew(ctx context.Context,
	trustRootsPEM, issuerPEM []byte, issuerSeen bool) {

	if !issuerSeen {
		metrics.LinkerdTrustAnchorSkew.Set(0)
		return
	}
	skew, checked := verifyLinkerdIssuerChain(trustRootsPEM, issuerPEM)
	if !checked {
		return
	}
	if skew {
		metrics.LinkerdTrustAnchorSkew.Set(1)
		logf.FromContext(ctx).Info(
			"linkerd identity issuer does not chain to trust roots — new mTLS handshakes will fail",
			"issuer", kube.LinkerdNS+"/"+linkerdIssuerSecret,
			"trustRoots", kube.LinkerdNS+"/"+linkerdTrustRootsCM)
		return
	}
	metrics.LinkerdTrustAnchorSkew.Set(0)
}

// verifyLinkerdIssuerChain reports whether the issuer certificate
// (first CERTIFICATE block of issuerPEM) chains to at least one
// trust root — cryptographically via CheckSignatureFrom AND by
// AKI/SKI: when both key ids are present they must match, which
// catches a re-keyed root whose signature material happens to
// overlap. checked=false means nothing parseable — "can't tell",
// never skew.
func verifyLinkerdIssuerChain(trustRootsPEM, issuerPEM []byte) (skew bool, checked bool) {
	roots := parseCertificatePEMs(trustRootsPEM)
	issuers := parseCertificatePEMs(issuerPEM)
	if len(roots) == 0 || len(issuers) == 0 {
		return false, false
	}
	issuer := issuers[0]
	for _, root := range roots {
		if len(root.SubjectKeyId) > 0 && len(issuer.AuthorityKeyId) > 0 &&
			!bytes.Equal(root.SubjectKeyId, issuer.AuthorityKeyId) {
			continue // key ids disagree — this root cannot be the parent
		}
		if err := issuer.CheckSignatureFrom(root); err == nil {
			return false, true
		}
	}
	return true, true
}

// parseCertificatePEMs decodes every CERTIFICATE PEM block in the
// bundle into parsed certs — unparseable blocks are skipped.
func parseCertificatePEMs(bundle []byte) []*x509.Certificate {
	var out []*x509.Certificate
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
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			out = append(out, cert)
		}
	}
	return out
}
