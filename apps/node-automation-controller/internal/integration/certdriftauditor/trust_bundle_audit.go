// trust_bundle_audit.go — Check D of cert-drift-auditor: days-to-
// expiry for the linkerd trust surface — the
// linkerd-identity-trust-roots ConfigMap (ca-bundle.crt) plus every
// Secret in namespace linkerd carrying ca.crt/crt.pem (Opaque
// included, e.g. linkerd-identity-issuer, which the TLS-secret audit
// cannot see). The issuer-serial rollout watch lives in
// tls_secret_audit.go.
package certdriftauditor

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

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

	secrets, err := shared.ListAll(ctx,
		metav1.ListOptions{Limit: certDriftListPage},
		shared.Secrets(a.cs, linkerdNS))
	if err != nil {
		return fmt.Errorf("list linkerd secrets: %w", err)
	}
	for i := range secrets {
		s := &secrets[i]
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
	days, ok := earliestCertExpiryDays(bundle, a.now.Now())
	if !ok {
		logf.FromContext(ctx).Info("skip: trust bundle carries no parseable X.509 PEM",
			"object", ns+"/"+name)
		return
	}
	a.seenTrustBundles.Emit(secretMetricKey{ns, name}, ns, name)
	metrics.TrustBundleDaysToExpiry.WithLabelValues(ns, name).Set(days)
}
