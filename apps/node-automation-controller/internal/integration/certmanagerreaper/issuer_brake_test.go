package certmanagerreaper

import (
	"maps"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func makeBrakeDyn(objs ...runtime.Object) *certManagerReaper {
	kinds := maps.Clone(testutil.DynListKinds())
	kinds[issuerGVR] = "IssuerList"
	kinds[clusterIssuerGVR] = "ClusterIssuerList"
	dyn := testutil.NewFakeDyn(kinds, objs...)
	return &certManagerReaper{
		dyn:   dyn,
		queue: "certmanager-reaper-brake-test",
	}
}

func wedgedCertOrderChallenge(ns, certName, orderName, issuerKind, issuerName, orderReason, chalReason string) (
	*unstructured.Unstructured, *unstructured.Unstructured, *unstructured.Unstructured, *unstructured.Unstructured,
) {
	now := time.Now()
	cert := cmrCert(ns, certName, "False", "")
	_ = unstructured.SetNestedMap(cert.Object, map[string]any{
		"kind": issuerKind, "name": issuerName, "group": "cert-manager.io",
	}, "spec", "issuerRef")

	cr := testutil.Unstructured(certificateRequestGVR.GroupVersion().WithKind("CertificateRequest"), ns, certName+"-cr", nil)
	cr.SetOwnerReferences([]metav1.OwnerReference{{Kind: "Certificate", Name: certName}})

	ord := cmrOrder(ns, orderName, "pending", time.Hour)
	ord.SetOwnerReferences([]metav1.OwnerReference{{Kind: "CertificateRequest", Name: certName + "-cr"}})
	if orderReason != "" {
		_ = unstructured.SetNestedField(ord.Object, orderReason, "status", "reason")
	}

	ch := testutil.Unstructured(challengeGVR.GroupVersion().WithKind("Challenge"), ns, orderName+"-ch", nil)
	ch.SetCreationTimestamp(metav1.NewTime(now.Add(-time.Hour)))
	ch.SetOwnerReferences([]metav1.OwnerReference{{Kind: "Order", Name: orderName}})
	_ = unstructured.SetNestedField(ch.Object, true, "status", "presented")
	_ = unstructured.SetNestedField(ch.Object, true, "status", "processing")
	if chalReason != "" {
		_ = unstructured.SetNestedField(ch.Object, chalReason, "status", "reason")
	}
	return cert, cr, ord, ch
}

func TestCertManagerReaperSafetyBrakeNotReadyIssuerAndACME429(t *testing.T) {
	ctx := t.Context()

	t.Run("notready_clusterissuer_pauses_order_reap", func(t *testing.T) {
		ci := testutil.Unstructured(clusterIssuerGVR.GroupVersion().WithKind("ClusterIssuer"), "", "letsencrypt-prod", map[string]any{
			"status": map[string]any{
				"conditions": []any{map[string]any{"type": "Ready", "status": "False", "reason": "ErrRegister"}},
			},
		})
		cert, cr, ord, ch := wedgedCertOrderChallenge("apps", "web-tls", "ord-1", "ClusterIssuer", "letsencrypt-prod", "", "")
		r := makeBrakeDyn(ci, cert, cr, ord, ch)
		if err := r.run(ctx); err != nil {
			t.Fatalf("run: %v", err)
		}
		if _, err := r.dyn.Resource(orderGVR).Namespace("apps").Get(ctx, "ord-1", metav1.GetOptions{}); err != nil {
			t.Fatalf("Order should NOT be deleted when ClusterIssuer is Ready=False: %v", err)
		}
	})

	t.Run("acme_429_ratelimit_on_challenge_pauses_reap_even_with_ready_issuer", func(t *testing.T) {
		iss := testutil.Unstructured(issuerGVR.GroupVersion().WithKind("Issuer"), "apps", "acme-iss", map[string]any{
			"status": map[string]any{
				"conditions": []any{map[string]any{"type": "Ready", "status": "True"}},
			},
		})
		cert, cr, ord, ch := wedgedCertOrderChallenge("apps", "api-tls", "ord-2", "Issuer", "acme-iss", "", "429 urn:ietf:params:acme:error:rateLimited")
		r := makeBrakeDyn(iss, cert, cr, ord, ch)
		if err := r.run(ctx); err != nil {
			t.Fatalf("run: %v", err)
		}
		if _, err := r.dyn.Resource(orderGVR).Namespace("apps").Get(ctx, "ord-2", metav1.GetOptions{}); err != nil {
			t.Fatalf("Order should NOT be deleted on 429 rateLimited Challenge: %v", err)
		}
	})

	t.Run("opt_out_brake_allows_reap_when_ready_or_disabled", func(t *testing.T) {
		ci := testutil.Unstructured(clusterIssuerGVR.GroupVersion().WithKind("ClusterIssuer"), "", "letsencrypt-prod", map[string]any{
			"status": map[string]any{
				"conditions": []any{map[string]any{"type": "Ready", "status": "False"}},
			},
		})
		cert, cr, ord, ch := wedgedCertOrderChallenge("apps", "web-tls", "ord-3", "ClusterIssuer", "letsencrypt-prod", "", "")
		r := makeBrakeDyn(ci, cert, cr, ord, ch)
		r.issuerBrakeDisabled = true
		if err := r.run(ctx); err != nil {
			t.Fatalf("run: %v", err)
		}
		if _, err := r.dyn.Resource(orderGVR).Namespace("apps").Get(ctx, "ord-3", metav1.GetOptions{}); err == nil {
			t.Fatal("expected Order deletion when brake explicitly disabled")
		}
	})
}
