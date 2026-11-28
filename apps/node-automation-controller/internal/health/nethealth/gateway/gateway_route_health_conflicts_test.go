package gateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func testValidTLSSecret(t *testing.T, ns, name string, notAfter time.Time) *corev1.Secret {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "gw.example.com"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"tls.crt": pemBytes},
	}
}

func TestGatewayListenerConflictedAndTLSSecretAudit(t *testing.T) {
	now := time.Now()
	testutil.CleanupMetric(t, gatewayRouteUnhealthyGauge, "Gateway", "edge", "gw-conflicted", gwReasonListenerConflicted)
	testutil.CleanupMetric(t, gatewayRouteUnhealthyGauge, "Gateway", "edge", "gw-missing-sec", gwReasonTLSCertMissing)
	testutil.CleanupMetric(t, gatewayRouteUnhealthyGauge, "Gateway", "edge", "gw-expiring-sec", gwReasonTLSCertExpiring)

	gc := gatewayClassFixture("cilium", "io.cilium/gateway-controller",
		gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute)))

	gwConf := gatewayFixture("edge", "gw-conflicted", "cilium", now.Add(-20*time.Minute),
		gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute)),
		gwCondAt("Programmed", "True", "", now.Add(-30*time.Minute)))
	_ = unstructured.SetNestedSlice(gwConf.Object, []any{map[string]any{
		"name": "http",
		"conditions": []any{
			gwCondAt("Conflicted", "True", "HostnameConflict", now.Add(-20*time.Minute)),
		},
	}}, "status", "listeners")

	gwMissing := gatewayFixture("edge", "gw-missing-sec", "cilium", now.Add(-20*time.Minute),
		gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute)),
		gwCondAt("Programmed", "True", "", now.Add(-30*time.Minute)))
	_ = unstructured.SetNestedSlice(gwMissing.Object, []any{map[string]any{
		"name": "https",
		"tls": map[string]any{
			"certificateRefs": []any{map[string]any{"kind": "Secret", "name": "absent-tls"}},
		},
	}}, "spec", "listeners")

	gwExpiring := gatewayFixture("edge", "gw-expiring-sec", "cilium", now.Add(-20*time.Minute),
		gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute)),
		gwCondAt("Programmed", "True", "", now.Add(-30*time.Minute)))
	_ = unstructured.SetNestedSlice(gwExpiring.Object, []any{map[string]any{
		"name": "https",
		"tls": map[string]any{
			"certificateRefs": []any{map[string]any{"kind": "Secret", "name": "soon-expiring"}},
		},
	}}, "spec", "listeners")

	cs := fake.NewSimpleClientset(testValidTLSSecret(t, "edge", "soon-expiring", now.Add(5*24*time.Hour)))
	p := testProberDyn(cs, gwOpDyn(t, gc, gwConf, gwMissing, gwExpiring))
	probetest.FreezeNow(p.Deps, now)
	chk := probetest.MustCheck[*gatewayRouteHealthCheck](t, p)
	res := chk.Run(probetest.SweepCtx(t.Context(), p.Deps))
	if res.Pass {
		t.Fatalf("expected Gateway conflicted/missing/expiring failure, got %+v", res)
	}
	for _, tc := range []struct{ gw, reason string }{
		{"gw-conflicted", gwReasonListenerConflicted},
		{"gw-missing-sec", gwReasonTLSCertMissing},
		{"gw-expiring-sec", gwReasonTLSCertExpiring},
	} {
		m := probetest.FindMetric(t, "node_automation_gateway_route_unhealthy", map[string]string{
			"kind": "Gateway", "namespace": "edge", "name": tc.gw, "reason": tc.reason,
		})
		if m == nil || m.GetGauge().GetValue() != 1 {
			t.Fatalf("expected metric=1 for %s/%s, got %v", tc.gw, tc.reason, m)
		}
	}
}

func TestGatewayCrossNamespaceHTTPRouteConflict(t *testing.T) {
	now := time.Now()
	testutil.CleanupMetric(t, gatewayRouteConflictGauge, "edge/shared-gw", "https", "app.example.com", "PathPrefix:/api")

	r1 := routeFixture("HTTPRoute", "team-a", "api-route")
	_ = unstructured.SetNestedSlice(r1.Object, []any{map[string]any{
		"namespace": "edge", "name": "shared-gw", "sectionName": "https",
	}}, "spec", "parentRefs")
	_ = unstructured.SetNestedSlice(r1.Object, []any{"app.example.com"}, "spec", "hostnames")
	_ = unstructured.SetNestedSlice(r1.Object, []any{map[string]any{
		"matches": []any{map[string]any{"path": map[string]any{"type": "PathPrefix", "value": "/api"}}},
	}}, "spec", "rules")

	r2 := routeFixture("HTTPRoute", "team-b", "hijack-route")
	_ = unstructured.SetNestedSlice(r2.Object, []any{map[string]any{
		"namespace": "edge", "name": "shared-gw", "sectionName": "https",
	}}, "spec", "parentRefs")
	_ = unstructured.SetNestedSlice(r2.Object, []any{"app.example.com"}, "spec", "hostnames")
	_ = unstructured.SetNestedSlice(r2.Object, []any{map[string]any{
		"matches": []any{map[string]any{"path": map[string]any{"type": "PathPrefix", "value": "/api"}}},
	}}, "spec", "rules")

	cs := fake.NewSimpleClientset()
	p := testProberDyn(cs, gwOpDyn(t, r1, r2))
	probetest.FreezeNow(p.Deps, now)
	chk := probetest.MustCheck[*gatewayRouteHealthCheck](t, p)
	res := chk.Run(probetest.SweepCtx(t.Context(), p.Deps))
	if res.Pass {
		t.Fatalf("expected cross-namespace HTTPRoute conflict failure, got %+v", res)
	}
	m := probetest.FindMetric(t, "node_automation_gateway_route_conflict", map[string]string{
		"gateway": "edge/shared-gw", "section": "https", "hostname": "app.example.com", "path": "PathPrefix:/api",
	})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("expected node_automation_gateway_route_conflict=1, got %v", m)
	}
	evs, err := cs.EventsV1().Events("team-a").List(t.Context(), metav1.ListOptions{})
	if err != nil || len(evs.Items) == 0 {
		t.Fatalf("expected Warning Event in team-a, got err=%v count=%d", err, len(evs.Items))
	}
}
