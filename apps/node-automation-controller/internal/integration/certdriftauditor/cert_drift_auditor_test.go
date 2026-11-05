package certdriftauditor

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

var cdaListKinds = map[schema.GroupVersionResource]string{
	certificateGVR: "CertificateList",
}

// cdaCertificate builds an unstructured cert-manager Certificate; an
// empty secretName leaves spec.secretName absent (name-convention
// fallback path).
func cdaCertificate(ns, name, secretName string) *unstructured.Unstructured {
	o := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cert-manager.io/v1",
		"kind":       "Certificate",
	}}
	o.SetNamespace(ns)
	o.SetName(name)
	if secretName != "" {
		_ = unstructured.SetNestedField(o.Object, secretName, "spec", "secretName")
	}
	return o
}

// makeCertPEM returns a self-signed certificate PEM expiring at
// notAfter — real x509 material so ParseCertificate accepts it.
func makeCertPEM(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "cert-drift-auditor-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func tlsSecret(t *testing.T, ns, name string, notAfter time.Time) *corev1.Secret {
	t.Helper()
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"tls.crt": makeCertPEM(t, notAfter)},
	}
}

// caSecret builds the cainjector-source Secret — key selects ca.crt
// vs tls.crt as the carrier.
func caSecret(ns, name, key string, ca []byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Data:       map[string][]byte{key: ca},
	}
}

func mutHook(name string, ca []byte) admissionv1.MutatingWebhook {
	return admissionv1.MutatingWebhook{
		Name:         name,
		ClientConfig: admissionv1.WebhookClientConfig{CABundle: ca},
	}
}

func valHook(name string, ca []byte) admissionv1.ValidatingWebhook {
	return admissionv1.ValidatingWebhook{
		Name:         name,
		ClientConfig: admissionv1.WebhookClientConfig{CABundle: ca},
	}
}

func mutatingCfg(name string, annos map[string]string,
	hooks ...admissionv1.MutatingWebhook) *admissionv1.MutatingWebhookConfiguration {
	return &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: name, Annotations: annos},
		Webhooks:   hooks,
	}
}

func validatingCfg(name string, annos map[string]string,
	hooks ...admissionv1.ValidatingWebhook) *admissionv1.ValidatingWebhookConfiguration {
	return &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: name, Annotations: annos},
		Webhooks:   hooks,
	}
}

func newCertDriftAuditor(cs kubernetes.Interface, dyn dynamic.Interface,
	now time.Time) *certDriftAuditor {
	return &certDriftAuditor{
		cs:    cs,
		dyn:   dyn,
		nowFn: func() time.Time { return now },
	}
}

// caMismatch reads the drift gauge for one (kind, config, webhook)
// series.
func caMismatch(kind, cfg, hook string) float64 {
	return promtestutil.ToFloat64(
		metrics.WebhookCABundleMismatch.WithLabelValues(kind, cfg, hook))
}

// ---------------------------------------------------------------------------
// Webhook CA bundle drift
// ---------------------------------------------------------------------------

var (
	caBundleA = []byte("CA-BUNDLE-AAAA")
	caBundleB = []byte("CA-BUNDLE-BBBB")
)

// inject-ca-from-secret: every webhook entry in the annotated config is
// compared — matching bundles gauge 0, drifted bundles gauge 1.
func TestCertDriftAuditorWebhookInjectSecret(t *testing.T) {
	cs := fake.NewSimpleClientset(
		caSecret("cert-ns", "ca-secret", "ca.crt", caBundleA),
		mutatingCfg("mwc", map[string]string{
			injectCAFromSecretAnno: "cert-ns/ca-secret",
		},
			mutHook("hook-ok.example.com", caBundleA),
			mutHook("hook-stale.example.com", caBundleB),
		))
	a := newCertDriftAuditor(cs, testutil.NewFakeDyn(cdaListKinds), time.Now())

	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := caMismatch("MutatingWebhookConfiguration", "mwc", "hook-ok.example.com"); got != 0 {
		t.Fatalf("matching bundle mismatch=%v, want 0", got)
	}
	if got := caMismatch("MutatingWebhookConfiguration", "mwc", "hook-stale.example.com"); got != 1 {
		t.Fatalf("drifted bundle mismatch=%v, want 1", got)
	}
}

// inject-ca-from resolves the Certificate's spec.secretName through the
// dynamic client — ValidatingWebhookConfiguration coverage too.
func TestCertDriftAuditorWebhookInjectFromCertificate(t *testing.T) {
	cs := fake.NewSimpleClientset(
		caSecret("cert-ns", "real-secret", "ca.crt", caBundleA),
		validatingCfg("vwc", map[string]string{
			injectCAFromAnno: "cert-ns/my-cert",
		}, valHook("hook.example.com", caBundleB)))
	dyn := testutil.NewFakeDyn(cdaListKinds,
		cdaCertificate("cert-ns", "my-cert", "real-secret"))
	a := newCertDriftAuditor(cs, dyn, time.Now())

	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := caMismatch("ValidatingWebhookConfiguration", "vwc", "hook.example.com"); got != 1 {
		t.Fatalf("mismatch=%v, want 1 (caBundleB != source caBundleA)", got)
	}
}

// No Certificate object (cert-manager CRDs absent / cert deleted) →
// the secret falls back to the Certificate's own name.
func TestCertDriftAuditorInjectFromSecretNameFallback(t *testing.T) {
	cs := fake.NewSimpleClientset(
		caSecret("cert-ns", "my-cert", "ca.crt", caBundleA),
		validatingCfg("vwc", map[string]string{
			injectCAFromAnno: "cert-ns/my-cert",
		}, valHook("hook.example.com", caBundleA)))
	a := newCertDriftAuditor(cs, testutil.NewFakeDyn(cdaListKinds), time.Now())

	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := caMismatch("ValidatingWebhookConfiguration", "vwc", "hook.example.com"); got != 0 {
		t.Fatalf("mismatch=%v, want 0 via cert-name fallback", got)
	}
}

// A config with NO inject annotation is outside cainjector's coverage —
// nothing is compared and no series is emitted (DeleteLabelValues
// returning false proves the series never existed).
func TestCertDriftAuditorUnannotatedConfigSkipped(t *testing.T) {
	cs := fake.NewSimpleClientset(
		mutatingCfg("plain-mwc", nil, mutHook("hook.example.com", caBundleA)))
	a := newCertDriftAuditor(cs, testutil.NewFakeDyn(cdaListKinds), time.Now())
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if metrics.WebhookCABundleMismatch.DeleteLabelValues(
		"MutatingWebhookConfiguration", "plain-mwc", "hook.example.com") {
		t.Fatal("series emitted for a config with no inject annotation")
	}
}

// An unresolved source (annotation points at a missing Secret) must not
// flap an active drift alert: the previously-emitted series survives
// the sweep with its value intact.
func TestCertDriftAuditorUnresolvedSourceKeepsSeries(t *testing.T) {
	cs := fake.NewSimpleClientset(
		caSecret("cert-ns", "ca-secret", "ca.crt", caBundleA),
		mutatingCfg("mwc", map[string]string{
			injectCAFromSecretAnno: "cert-ns/ca-secret",
		}, mutHook("hook.example.com", caBundleB)))
	a := newCertDriftAuditor(cs, testutil.NewFakeDyn(cdaListKinds), time.Now())
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := caMismatch("MutatingWebhookConfiguration", "mwc", "hook.example.com"); got != 1 {
		t.Fatalf("mismatch=%v, want 1 before the source vanished", got)
	}

	// Source Secret deleted — the audit can no longer tell whether the
	// bundle drifted, but the alert must not silently clear.
	if err := cs.CoreV1().Secrets("cert-ns").
		Delete(ctx, "ca-secret", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := caMismatch("MutatingWebhookConfiguration", "mwc", "hook.example.com"); got != 1 {
		t.Fatalf("drift series flapped off when the source vanished: %v", got)
	}
}

// A transient Certificate Get failure must NOT fall back to the
// name convention: a same-named Secret holding a DIFFERENT CA would
// fabricate a drift verdict (or mask a real one). "Can't resolve"
// carries the emitted series forward like any other unresolvable
// source.
func TestCertDriftAuditorCertGetErrorCarriesSeries(t *testing.T) {
	cs := fake.NewSimpleClientset(
		caSecret("cert-ns", "real-secret", "ca.crt", caBundleA),
		// The trap: a Secret named after the Certificate whose bundle
		// matches the webhook — a name-convention fallback would read
		// it and clear a REAL drift alert.
		caSecret("cert-ns", "my-cert", "ca.crt", caBundleB),
		mutatingCfg("mwc", map[string]string{
			injectCAFromAnno: "cert-ns/my-cert",
		}, mutHook("hook.example.com", caBundleB)))
	dyn := testutil.NewFakeDyn(cdaListKinds,
		cdaCertificate("cert-ns", "my-cert", "real-secret"))
	a := newCertDriftAuditor(cs, dyn, time.Now())

	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := caMismatch("MutatingWebhookConfiguration", "mwc", "hook.example.com"); got != 1 {
		t.Fatalf("mismatch=%v, want 1 before the API failure", got)
	}

	// Certificates unreachable (RBAC, transient API) — NOT NotFound.
	dyn.PrependReactor("get", "certificates",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := caMismatch("MutatingWebhookConfiguration", "mwc", "hook.example.com"); got != 1 {
		t.Fatalf("drift series flapped on a transient certificate get failure: %v", got)
	}
}

// Dropping the inject annotation makes the entry uncovered — its
// series is pruned on the next sweep.
func TestCertDriftAuditorPrunesDroppedAnnotation(t *testing.T) {
	cfg := mutatingCfg("mwc", map[string]string{
		injectCAFromSecretAnno: "cert-ns/ca-secret",
	}, mutHook("hook.example.com", caBundleB))
	cs := fake.NewSimpleClientset(
		caSecret("cert-ns", "ca-secret", "ca.crt", caBundleA), cfg)
	a := newCertDriftAuditor(cs, testutil.NewFakeDyn(cdaListKinds), time.Now())
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := caMismatch("MutatingWebhookConfiguration", "mwc", "hook.example.com"); got != 1 {
		t.Fatalf("mismatch=%v, want 1", got)
	}

	// cainjector wiring removed — the series must prune, not pin 1.
	cfg.Annotations = nil
	if _, err := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().
		Update(ctx, cfg, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if metrics.WebhookCABundleMismatch.DeleteLabelValues(
		"MutatingWebhookConfiguration", "mwc", "hook.example.com") {
		t.Fatal("stale series kept after the inject annotation was dropped")
	}
}

// A webhook-config list failure propagates as the run's error (the
// periodic wrapper owns IncError — shared's
// TestPeriodicErrorIncrementsErrorMetric proves that path) — but it
// must NOT blind the independent TLS-expiry audit, which still runs.
func TestCertDriftAuditorWebhookListError(t *testing.T) {
	fixedNow := time.Now().Truncate(time.Second) // x509 serializes cert times at second precision
	cs := fake.NewSimpleClientset(
		tlsSecret(t, "app", "tls-a", fixedNow.Add(10*24*time.Hour)))
	cs.PrependReactor("list", "mutatingwebhookconfigurations",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	a := newCertDriftAuditor(cs, testutil.NewFakeDyn(cdaListKinds), fixedNow)

	if err := a.run(ctx); err == nil {
		t.Fatal("expected error when the webhook config list fails")
	}
	if got := promtestutil.ToFloat64(
		metrics.TLSSecretDaysToExpiry.WithLabelValues("app", "tls-a")); got != 10 {
		t.Fatalf("TLS audit skipped after webhook failure — days=%v, want 10", got)
	}
}

// ---------------------------------------------------------------------------
// TLS secret expiry
// ---------------------------------------------------------------------------

// tls.crt expiry lands on the gauge in whole days; an already-expired
// cert goes negative. The field selector is server-side, so non-TLS
// secrets in the fake feed the in-code type check too.
func TestCertDriftAuditorTLSExpiry(t *testing.T) {
	fixedNow := time.Now().Truncate(time.Second) // x509 serializes cert times at second precision
	cs := fake.NewSimpleClientset(
		tlsSecret(t, "app", "tls-good", fixedNow.Add(30*24*time.Hour)),
		tlsSecret(t, "app", "tls-dead", fixedNow.Add(-48*time.Hour)),
		&corev1.Secret{ // non-TLS — must be ignored even though the fake ignores the field selector
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "opaque"},
			Type:       corev1.SecretTypeOpaque,
		})
	a := newCertDriftAuditor(cs, testutil.NewFakeDyn(cdaListKinds), fixedNow)

	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := promtestutil.ToFloat64(
		metrics.TLSSecretDaysToExpiry.WithLabelValues("app", "tls-good")); got != 30 {
		t.Fatalf("tls-good days=%v, want 30", got)
	}
	if got := promtestutil.ToFloat64(
		metrics.TLSSecretDaysToExpiry.WithLabelValues("app", "tls-dead")); got != -2 {
		t.Fatalf("tls-dead days=%v, want -2 (expired)", got)
	}
	if metrics.TLSSecretDaysToExpiry.DeleteLabelValues("app", "opaque") {
		t.Fatal("non-TLS secret produced an expiry series")
	}
}

// A tls.crt that is not PEM (or not a cert) is skipped — no series, no
// crash; the rest of the sweep still lands.
func TestCertDriftAuditorTLSUnparseableSkipped(t *testing.T) {
	fixedNow := time.Now().Truncate(time.Second) // x509 serializes cert times at second precision
	cs := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "tls-broken"},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{"tls.crt": []byte("not-a-pem")},
		},
		tlsSecret(t, "app", "tls-ok", fixedNow.Add(5*24*time.Hour)))
	a := newCertDriftAuditor(cs, testutil.NewFakeDyn(cdaListKinds), fixedNow)

	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if metrics.TLSSecretDaysToExpiry.DeleteLabelValues("app", "tls-broken") {
		t.Fatal("unparseable tls.crt produced an expiry series")
	}
	if got := promtestutil.ToFloat64(
		metrics.TLSSecretDaysToExpiry.WithLabelValues("app", "tls-ok")); got != 5 {
		t.Fatalf("tls-ok days=%v, want 5", got)
	}
}

// A secret deleted between sweeps gets its series pruned — /metrics
// must not keep reporting expiry for a dead object.
func TestCertDriftAuditorTLSPrunesDeletedSecret(t *testing.T) {
	fixedNow := time.Now().Truncate(time.Second) // x509 serializes cert times at second precision
	s := tlsSecret(t, "app", "tls-temp", fixedNow.Add(10*24*time.Hour))
	cs := fake.NewSimpleClientset(s)
	a := newCertDriftAuditor(cs, testutil.NewFakeDyn(cdaListKinds), fixedNow)

	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := promtestutil.ToFloat64(
		metrics.TLSSecretDaysToExpiry.WithLabelValues("app", "tls-temp")); got != 10 {
		t.Fatalf("days=%v, want 10", got)
	}
	if err := cs.CoreV1().Secrets("app").
		Delete(ctx, "tls-temp", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if metrics.TLSSecretDaysToExpiry.DeleteLabelValues("app", "tls-temp") {
		t.Fatal("expiry series kept after the secret was deleted")
	}
}

// A TLS-secret list failure propagates as the run's error — the
// periodic wrapper owns the IncError for it.
func TestCertDriftAuditorTLSListError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "secrets",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	a := newCertDriftAuditor(cs, testutil.NewFakeDyn(cdaListKinds), time.Now())

	if err := a.run(ctx); err == nil {
		t.Fatal("expected error when the tls secret list fails")
	}
}

// splitNSName: exactly "ns/name" parses; every other shape is refused.
func TestSplitNSName(t *testing.T) {
	for _, tc := range []struct {
		ref  string
		ns   string
		name string
		ok   bool
	}{
		{"cert-ns/my-cert", "cert-ns", "my-cert", true},
		{"no-slash", "", "", false},
		{"/name", "", "", false},
		{"ns/", "", "", false},
		{"a/b/c", "", "", false},
		{"", "", "", false},
	} {
		t.Run(tc.ref, func(t *testing.T) {
			ns, name, ok := splitNSName(tc.ref)
			if ok != tc.ok || ns != tc.ns || name != tc.name {
				t.Fatalf("splitNSName(%q) = %q,%q,%v want %q,%q,%v",
					tc.ref, ns, name, ok, tc.ns, tc.name, tc.ok)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 2.4 — full certificate surface: webhook caBundle expiry + trust bundles
// ---------------------------------------------------------------------------

func caExpiryGauge(kind, cfg, hook string) float64 {
	return promtestutil.ToFloat64(
		metrics.WebhookCABundleDaysToExpiry.WithLabelValues(kind, cfg, hook))
}

func trustBundleGauge(ns, name string) float64 {
	return promtestutil.ToFloat64(
		metrics.TrustBundleDaysToExpiry.WithLabelValues(ns, name))
}

// mutHookSvc builds a MutatingWebhook entry targeting a Service — the
// shape where a caBundle is strictly required.
func mutHookSvc(name string, ca []byte, fp *admissionv1.FailurePolicyType) admissionv1.MutatingWebhook {
	return admissionv1.MutatingWebhook{
		Name: name,
		ClientConfig: admissionv1.WebhookClientConfig{
			CABundle: ca,
			Service:  &admissionv1.ServiceReference{Name: "svc", Namespace: "app", Port: ptr443()},
		},
		FailurePolicy: fp,
	}
}

func ptr443() *int32 { p := int32(443); return &p }

// Every entry's caBundle feeds the expiry gauge even without a
// cainjector annotation — the earliest cert in the bundle wins.
func TestCertDriftAuditorWebhookBundleExpiry(t *testing.T) {
	fixedNow := time.Now().Truncate(time.Second)
	bundle := makeCertPEM(t, fixedNow.Add(20*24*time.Hour))
	oldest := append(append([]byte{}, makeCertPEM(t, fixedNow.Add(5*24*time.Hour))...), bundle...)
	cs := fake.NewSimpleClientset(
		mutatingCfg("unannotated-mwc", nil, mutHook("hook-a.example.com", oldest)),
		validatingCfg("unannotated-vwc", nil, valHook("hook-b.example.com", bundle)))
	a := newCertDriftAuditor(cs, testutil.NewFakeDyn(cdaListKinds), fixedNow)

	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := caExpiryGauge("MutatingWebhookConfiguration", "unannotated-mwc", "hook-a.example.com"); got != 5 {
		t.Fatalf("mwc days=%v, want 5 (earliest cert in bundle)", got)
	}
	if got := caExpiryGauge("ValidatingWebhookConfiguration", "unannotated-vwc", "hook-b.example.com"); got != 20 {
		t.Fatalf("vwc days=%v, want 20", got)
	}
}

// An EMPTY caBundle on a service-targeted entry with
// failurePolicy=Fail (explicit or API-default nil) is an outage
// signature → mismatch=1. failurePolicy=Ignore and url-targeted
// entries stay quiet.
func TestCertDriftAuditorWebhookEmptyBundleFailClosed(t *testing.T) {
	ignore := admissionv1.Ignore
	fail := admissionv1.Fail
	cs := fake.NewSimpleClientset(
		mutatingCfg("mwc", nil,
			mutHookSvc("fail.example.com", nil, &fail),
			mutHookSvc("default-fail.example.com", nil, nil), // nil = API-default Fail
			mutHookSvc("ignore.example.com", nil, &ignore),
			mutHook("url.example.com", nil), // url clientConfig — no service
		))
	a := newCertDriftAuditor(cs, testutil.NewFakeDyn(cdaListKinds), time.Now())

	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := caMismatch("MutatingWebhookConfiguration", "mwc", "fail.example.com"); got != 1 {
		t.Fatalf("empty-bundle Fail entry mismatch=%v, want 1", got)
	}
	if got := caMismatch("MutatingWebhookConfiguration", "mwc", "default-fail.example.com"); got != 1 {
		t.Fatalf("empty-bundle default-Fail entry mismatch=%v, want 1", got)
	}
	for _, hook := range []string{"ignore.example.com", "url.example.com"} {
		if metrics.WebhookCABundleMismatch.DeleteLabelValues(
			"MutatingWebhookConfiguration", "mwc", hook) {
			t.Fatalf("hook %s produced a mismatch series — only service+Fail may flag", hook)
		}
	}
}

// The linkerd trust surface: trust-roots ConfigMap + Opaque
// linkerd-identity-issuer Secret both land on the gauge with the
// earliest cert expiry; an unrelated secret without bundle keys does
// not.
func TestCertDriftAuditorTrustBundles(t *testing.T) {
	fixedNow := time.Now().Truncate(time.Second)
	cs := fake.NewSimpleClientset(
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: "linkerd", Name: "linkerd-identity-trust-roots"},
			Data: map[string]string{
				"ca-bundle.crt": string(makeCertPEM(t, fixedNow.Add(40*24*time.Hour))),
			},
		},
		&corev1.Secret{ // Opaque issuer — invisible to the TLS-secret audit
			ObjectMeta: metav1.ObjectMeta{Namespace: "linkerd", Name: "linkerd-identity-issuer"},
			Type:       corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				"crt.pem": makeCertPEM(t, fixedNow.Add(7*24*time.Hour)),
			},
		},
		&corev1.Secret{ // no bundle keys — skipped
			ObjectMeta: metav1.ObjectMeta{Namespace: "linkerd", Name: "unrelated"},
			Data:       map[string][]byte{"other": []byte("x")},
		},
		&corev1.Secret{ // bundle keys but outside linkerd — skipped
			ObjectMeta: metav1.ObjectMeta{Namespace: "other-ns", Name: "s"},
			Data:       map[string][]byte{"ca.crt": makeCertPEM(t, fixedNow.Add(9*24*time.Hour))},
		})
	a := newCertDriftAuditor(cs, testutil.NewFakeDyn(cdaListKinds), fixedNow)

	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := trustBundleGauge("linkerd", "linkerd-identity-trust-roots"); got != 40 {
		t.Fatalf("trust-roots days=%v, want 40", got)
	}
	if got := trustBundleGauge("linkerd", "linkerd-identity-issuer"); got != 7 {
		t.Fatalf("issuer days=%v, want 7", got)
	}
	for _, key := range [][2]string{
		{"linkerd", "unrelated"}, {"other-ns", "s"},
	} {
		if metrics.TrustBundleDaysToExpiry.DeleteLabelValues(key[0], key[1]) {
			t.Fatalf("non-bundle object %s/%s produced an expiry series", key[0], key[1])
		}
	}
}

// ---------------------------------------------------------------------------
// W7-C6 — kubernetes-replicator tls.crt drift
// ---------------------------------------------------------------------------

// replicatedSecret builds a TLS-type secret carrying the
// replicated-from annotation and an arbitrary tls.crt payload —
// drift is a byte comparison, the bytes need not parse as PEM (the
// expiry audit just skips them).
func replicatedSecret(ns, name, sourceRef, crt string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name,
			Annotations: map[string]string{replicatedFromAnno: sourceRef}},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{"tls.crt": []byte(crt)},
	}
}

func driftGauge(ns, name, src string) float64 {
	return promtestutil.ToFloat64(
		metrics.ReplicatedSecretDrift.WithLabelValues(ns, name, src))
}

// The drift latch: a single-scan mismatch is the replicator mid-sync
// — only the SECOND consecutive mismatch sets the gauge.
func TestReplicatedDriftLatchesAfterTwoScans(t *testing.T) {
	metrics.ReplicatedSecretDrift.DeleteLabelValues("apps", "tls-copy", "sec/tls-src")
	t.Cleanup(func() {
		metrics.ReplicatedSecretDrift.DeleteLabelValues("apps", "tls-copy", "sec/tls-src")
	})
	cs := fake.NewSimpleClientset(
		replicatedSecret("sec", "tls-src", "", "CRT-v2"),
		replicatedSecret("apps", "tls-copy", "sec/tls-src", "CRT-v1"))
	a := newCertDriftAuditor(cs, testutil.NewFakeDyn(cdaListKinds), time.Now())

	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := driftGauge("apps", "tls-copy", "sec/tls-src"); got != 0 {
		t.Fatalf("drift gauge = %v after one scan, want 0 (mid-sync)", got)
	}
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := driftGauge("apps", "tls-copy", "sec/tls-src"); got != 1 {
		t.Fatalf("drift gauge = %v after two scans, want 1", got)
	}
}

// A matching copy resets the streak AND prunes the held series —
// recovered drift must not park a 1 in /metrics.
func TestReplicatedDriftClearsOnResync(t *testing.T) {
	metrics.ReplicatedSecretDrift.DeleteLabelValues("apps", "tls-copy", "sec/tls-src")
	t.Cleanup(func() {
		metrics.ReplicatedSecretDrift.DeleteLabelValues("apps", "tls-copy", "sec/tls-src")
	})
	cs := fake.NewSimpleClientset(
		replicatedSecret("sec", "tls-src", "", "CRT-v1"),
		replicatedSecret("apps", "tls-copy", "sec/tls-src", "CRT-old"))
	a := newCertDriftAuditor(cs, testutil.NewFakeDyn(cdaListKinds), time.Now())
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := driftGauge("apps", "tls-copy", "sec/tls-src"); got != 1 {
		t.Fatalf("precondition: gauge = %v, want 1", got)
	}
	// The replicator catches up — dest now matches the source.
	if err := cs.Tracker().Update(
		corev1.SchemeGroupVersion.WithResource("secrets"),
		replicatedSecret("apps", "tls-copy", "sec/tls-src", "CRT-v1"), "apps"); err != nil {
		t.Fatal(err)
	}
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := driftGauge("apps", "tls-copy", "sec/tls-src"); got != 0 {
		t.Fatalf("drift series still held after re-sync: %v", got)
	}
	if len(a.replicationMismatch) != 0 {
		t.Fatalf("mismatch streak not reset: %v", a.replicationMismatch)
	}
}

// A source that is NOT a TLS secret resolves via the direct-Get
// fallback, not the tlsData sweep map.
func TestReplicatedDriftOpaqueSourceFallback(t *testing.T) {
	metrics.ReplicatedSecretDrift.DeleteLabelValues("apps", "tls-copy", "sec/tls-src")
	t.Cleanup(func() {
		metrics.ReplicatedSecretDrift.DeleteLabelValues("apps", "tls-copy", "sec/tls-src")
	})
	src := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "sec", Name: "tls-src"},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"tls.crt": []byte("CRT-v2")},
	}
	cs := fake.NewSimpleClientset(src,
		replicatedSecret("apps", "tls-copy", "sec/tls-src", "CRT-v1"))
	a := newCertDriftAuditor(cs, testutil.NewFakeDyn(cdaListKinds), time.Now())
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := driftGauge("apps", "tls-copy", "sec/tls-src"); got != 1 {
		t.Fatalf("opaque-source drift not detected: %v, want 1", got)
	}
}

// A missing source is "can't compare", not drift — no streak, no
// gauge.
func TestReplicatedDriftMissingSourceQuiet(t *testing.T) {
	cs := fake.NewSimpleClientset(
		replicatedSecret("apps", "tls-copy", "sec/tls-src", "CRT-v1"))
	a := newCertDriftAuditor(cs, testutil.NewFakeDyn(cdaListKinds), time.Now())
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if len(a.replicationMismatch) != 0 {
		t.Fatalf("missing source counted as drift: %v", a.replicationMismatch)
	}
}
