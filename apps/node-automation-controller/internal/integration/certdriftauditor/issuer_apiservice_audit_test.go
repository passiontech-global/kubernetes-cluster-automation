package certdriftauditor

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"maps"
	"math/big"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func testCertPEM(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ca"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestAuditIssuersAndAPIServiceCABundleExpiry(t *testing.T) {
	now := time.Now().UTC()
	t.Cleanup(func() {
		certManagerIssuerUnhealthyGauge.DeleteLabelValues("Issuer", "apps", "bad-issuer")
		certManagerIssuerUnhealthyGauge.DeleteLabelValues("ClusterIssuer", "", "bad-cluster-issuer")
		metrics.WebhookCABundleDaysToExpiry.DeleteLabelValues("APIService", "v1beta1.custom.io", "apiservice")
		metrics.WebhookCABundleMismatch.DeleteLabelValues("APIService", "v1beta1.empty.io", "apiservice")
	})

	kinds := maps.Clone(testutil.DynListKinds())
	kinds[issuerGVR] = "IssuerList"
	kinds[clusterIssuerGVR] = "ClusterIssuerList"
	kinds[kube.GVRCustomResourceDefinition] = "CustomResourceDefinitionList"

	badIssuer := testutil.Unstructured(issuerGVR.GroupVersion().WithKind("Issuer"), "apps", "bad-issuer", map[string]any{
		"status": map[string]any{
			"conditions": []any{map[string]any{
				"type":               "Ready",
				"status":             "False",
				"reason":             "ErrInit",
				"lastTransitionTime": now.Add(-20 * time.Minute).Format(time.RFC3339),
			}},
		},
	})
	freshClusterIssuer := testutil.Unstructured(clusterIssuerGVR.GroupVersion().WithKind("ClusterIssuer"), "", "bad-cluster-issuer", map[string]any{
		"status": map[string]any{
			"conditions": []any{map[string]any{
				"type":               "Ready",
				"status":             "False",
				"reason":             "Pending",
				"lastTransitionTime": now.Add(-5 * time.Minute).Format(time.RFC3339),
			}},
		},
	})

	pemBytes := testCertPEM(t, now.Add(12*24*time.Hour))
	apiSvcWithCert := testutil.Unstructured(kube.GVRAPIService.GroupVersion().WithKind("APIService"), "", "v1beta1.custom.io", map[string]any{
		"spec": map[string]any{
			"service":  map[string]any{"namespace": "kube-system", "name": "metrics-server"},
			"caBundle": base64.StdEncoding.EncodeToString(pemBytes),
		},
	})
	apiSvcEmpty := testutil.Unstructured(kube.GVRAPIService.GroupVersion().WithKind("APIService"), "", "v1beta1.empty.io", map[string]any{
		"spec": map[string]any{
			"service": map[string]any{"namespace": "kube-system", "name": "custom-api"},
		},
	})

	dyn := testutil.NewFakeDyn(kinds, badIssuer, freshClusterIssuer, apiSvcWithCert, apiSvcEmpty)
	a := &certDriftAuditor{
		cs:    fake.NewSimpleClientset(),
		dyn:   dyn,
		queue: "cert-drift-auditor-test",
		now:   func() time.Time { return now },
	}
	if err := a.auditWebhookCABundles(ctx); err != nil {
		t.Fatalf("auditWebhookCABundles: %v", err)
	}
	if err := a.auditIssuers(ctx); err != nil {
		t.Fatalf("auditIssuers: %v", err)
	}

	if v, ok := testutil.GaugeSeriesValue(t, "node_automation_certmanager_issuer_unhealthy", map[string]string{
		"kind": "Issuer", "namespace": "apps", "name": "bad-issuer",
	}); !ok || v != 1 {
		t.Fatalf("bad-issuer unhealthy = (%v, %v), want (1, true)", v, ok)
	}
	if _, ok := testutil.GaugeSeriesValue(t, "node_automation_certmanager_issuer_unhealthy", map[string]string{
		"kind": "ClusterIssuer", "namespace": "", "name": "bad-cluster-issuer",
	}); ok {
		t.Fatal("<15m ClusterIssuer must not emit unhealthy yet")
	}

	if days, ok := testutil.GaugeSeriesValue(t, "node_automation_webhook_ca_bundle_days_to_expiry", map[string]string{
		"kind": "APIService", "name": "v1beta1.custom.io", "webhook": "apiservice",
	}); !ok || days < 11.5 || days > 12.5 {
		t.Fatalf("APIService days_to_expiry = (%v, %v), want ~12", days, ok)
	}
	if m, ok := testutil.GaugeSeriesValue(t, "node_automation_webhook_ca_bundle_mismatch", map[string]string{
		"kind": "APIService", "name": "v1beta1.empty.io", "webhook": "apiservice",
	}); !ok || m != 1 {
		t.Fatalf("APIService empty caBundle mismatch = (%v, %v), want (1, true)", m, ok)
	}

	// Recover bad-issuer -> pruned.
	_ = unstructured.SetNestedSlice(badIssuer.Object, []any{map[string]any{
		"type": "Ready", "status": "True",
	}}, "status", "conditions")
	_, _ = dyn.Resource(issuerGVR).Namespace("apps").Update(ctx, badIssuer, metav1.UpdateOptions{})
	if err := a.auditIssuers(ctx); err != nil {
		t.Fatalf("auditIssuers 2: %v", err)
	}
	if _, ok := testutil.GaugeSeriesValue(t, "node_automation_certmanager_issuer_unhealthy", map[string]string{
		"kind": "Issuer", "namespace": "apps", "name": "bad-issuer",
	}); ok {
		t.Fatal("recovered Issuer unhealthy metric not pruned")
	}
}
