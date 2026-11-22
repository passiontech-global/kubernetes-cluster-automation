package certdriftauditor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func genSelfSignedCert(t *testing.T, serial int64, notAfter time.Time, dnsName string) (*x509.Certificate, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: dnsName},
		NotBefore:    notAfter.Add(-365 * 24 * time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{dnsName},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, pemBytes
}

func makeTLSSecret(ns, name string, crt []byte, created time.Time) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         ns,
			Name:              name,
			CreationTimestamp: metav1.NewTime(created),
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{"tls.crt": crt, "tls.key": []byte("key")},
	}
}

func makeReadyTLSPod(ns, name, ip, secretName string, owner metav1.OwnerReference) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       ns,
			Name:            name,
			Labels:          map[string]string{"app": name},
			OwnerReferences: []metav1.OwnerReference{owner},
		},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{{
				Name: "tls",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{SecretName: secretName},
				},
			}},
			Containers: []corev1.Container{{
				Name:  "srv",
				Image: "srv:v1",
				Ports: []corev1.ContainerPort{{Name: "https", ContainerPort: 8443}},
			}},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodPhase("Running"),
			PodIP: ip,
			Conditions: []corev1.PodCondition{{
				Type:   corev1.PodReady,
				Status: corev1.ConditionTrue,
			}},
		},
	}
}

func TestLiveSocketDriftFourClassesStreakEventAndRollout(t *testing.T) {
	metrics.TLSLiveSocketDrift.Reset()
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

	oldCert, _ := genSelfSignedCert(t, 1001, now.Add(3*24*time.Hour), "svc.apps.svc")
	_, newPEM := genSelfSignedCert(t, 2002, now.Add(90*24*time.Hour), "svc.apps.svc")
	freshCert, _ := genSelfSignedCert(t, 2002, now.Add(90*24*time.Hour), "svc.apps.svc")

	isCtrl := true
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "wh-app", UID: "dep-1"},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "wh-pod"}}},
		},
	}
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "wh-app-rs",
			OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "wh-app", Controller: &isCtrl}},
		},
	}
	// StatefulSet WITH opt-in annotation -> should rollout.
	stsOptIn := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "api-sts",
			Annotations: map[string]string{kube.AnnoCertDriftReloadOptIn: "true"},
		},
	}
	// StatefulSet WITHOUT opt-in -> should NOT rollout, only metric + event.
	stsNoOptIn := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "plain-sts"},
	}

	objs := []runtime.Object{
		makeTLSSecret("apps", "wh-tls", newPEM, now.Add(-10*time.Minute)),
		makeTLSSecret("apps", "api-tls", newPEM, now.Add(-10*time.Minute)),
		makeTLSSecret("apps", "ing-tls", newPEM, now.Add(-10*time.Minute)),
		makeTLSSecret("apps", "port-tls", newPEM, now.Add(-10*time.Minute)),
		dep, rs, stsOptIn, stsNoOptIn,
		// Class 1: Webhook Service (port 8080 non-standard, discovered via VWC).
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "wh-svc", UID: "svc-1"},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{"app": "wh-pod"},
				Ports:    []corev1.ServicePort{{Port: 8080}},
			},
		},
		makeReadyTLSPod("apps", "wh-pod", "10.0.0.1", "wh-tls", metav1.OwnerReference{Kind: "ReplicaSet", Name: "wh-app-rs", Controller: &isCtrl}),
		&admissionv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "wh-vwc"},
			Webhooks: []admissionv1.ValidatingWebhook{{
				Name: "wh.example.com",
				ClientConfig: admissionv1.WebhookClientConfig{
					Service: &admissionv1.ServiceReference{Namespace: "apps", Name: "wh-svc"},
				},
			}},
		},
		// Class 2: Aggregated APIService Service (port 7443 non-standard, discovered via APIService).
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "api-svc", UID: "svc-2"},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{"app": "api-pod"},
				Ports:    []corev1.ServicePort{{Port: 7443}},
			},
		},
		makeReadyTLSPod("apps", "api-pod", "10.0.0.2", "api-tls", metav1.OwnerReference{Kind: "StatefulSet", Name: "api-sts", Controller: &isCtrl}),
		// Class 3: TLS Service discovered by its TLS port. Ingress/HTTPRoute
		// discovery was removed (NAC has no `ingresses` RBAC — the old
		// list guaranteed a 403 that tore down the whole audit).
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "ing-svc", UID: "svc-3"},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{"app": "ing-pod"},
				Ports:    []corev1.ServicePort{{Name: "https", Port: 443, TargetPort: intstr.FromInt32(8443)}},
			},
		},
		makeReadyTLSPod("apps", "ing-pod", "10.0.0.3", "ing-tls", metav1.OwnerReference{Kind: "StatefulSet", Name: "plain-sts", Controller: &isCtrl}),
		// Class 4: Service with Ready TLS Pod exposing port 8443.
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "port-svc", UID: "svc-4"},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{"app": "port-pod"},
				Ports:    []corev1.ServicePort{{Name: "https", Port: 443, TargetPort: intstr.FromInt32(8443)}},
			},
		},
		makeReadyTLSPod("apps", "port-pod", "10.0.0.4", "port-tls", metav1.OwnerReference{}),
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "apps", Name: "port-svc-slice",
				Labels: map[string]string{discoveryv1.LabelServiceName: "port-svc"},
			},
			Endpoints: []discoveryv1.Endpoint{{
				Addresses: []string{"10.0.0.4"},
				TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: "apps", Name: "port-pod"},
			}},
		},
	}

	apiSvc := testutil.Unstructured(kube.GVRAPIService.GroupVersion().WithKind("APIService"), "", "v1beta1.custom.io", nil)
	_ = unstructured.SetNestedMap(apiSvc.Object, map[string]any{"namespace": "apps", "name": "api-svc"}, "spec", "service")

	cs := fake.NewSimpleClientset(objs...)
	dyn := cdaDyn(apiSvc)
	servingOld := true
	a := &certDriftAuditor{
		cs:  cs,
		dyn: dyn,
		now: func() time.Time { return now },
		prober: func(_ context.Context, addr, _ string) (*x509.Certificate, error) {
			if !servingOld {
				return freshCert, nil
			}
			return oldCert, nil
		},
	}

	// Scan 1: streak=1 -> no metric, no Event, no rollout yet.
	if err := a.auditLiveSockets(ctx); err != nil {
		t.Fatalf("scan 1: %v", err)
	}
	if v := ptestutil.ToFloat64(metrics.TLSLiveSocketDrift.WithLabelValues("apps", "wh-svc", "wh-tls")); v != 0 {
		t.Fatalf("expected 0 drift after 1 scan, got %v", v)
	}

	// Scan 2: streak=2 -> metric=1 on all 4 classes, Events emitted, wh-app Deployment & opted-in api-sts rolled, plain-sts NOT rolled.
	now = now.Add(15 * time.Minute)
	if err := a.auditLiveSockets(ctx); err != nil {
		t.Fatalf("scan 2: %v", err)
	}
	for _, svc := range []struct{ svc, sec string }{
		{"wh-svc", "wh-tls"},
		{"api-svc", "api-tls"},
		{"ing-svc", "ing-tls"},
		{"port-svc", "port-tls"},
	} {
		if v := ptestutil.ToFloat64(metrics.TLSLiveSocketDrift.WithLabelValues("apps", svc.svc, svc.sec)); v != 1 {
			t.Fatalf("expected drift=1 for %s/%s, got %v", svc.svc, svc.sec, v)
		}
	}

	evs, err := cs.EventsV1().Events("apps").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs.Items) != 4 {
		t.Fatalf("expected 4 Warning Events (one per class), got %d", len(evs.Items))
	}

	gotDep, _ := cs.AppsV1().Deployments("apps").Get(ctx, "wh-app", metav1.GetOptions{})
	if gotDep.Spec.Template.Annotations[kube.RestartedAtAnno] == "" {
		t.Fatalf("expected Deployment wh-app rolled out, got annotations %v", gotDep.Spec.Template.Annotations)
	}
	if gotDep.Annotations[kube.AnnoLastCertDriftRollout] == "" {
		t.Fatalf("expected persisted cooldown annotation on Deployment")
	}

	gotOptIn, _ := cs.AppsV1().StatefulSets("apps").Get(ctx, "api-sts", metav1.GetOptions{})
	if gotOptIn.Spec.Template.Annotations[kube.RestartedAtAnno] == "" {
		t.Fatalf("expected opted-in StatefulSet api-sts rolled out")
	}
	gotNoOptIn, _ := cs.AppsV1().StatefulSets("apps").Get(ctx, "plain-sts", metav1.GetOptions{})
	if gotNoOptIn.Spec.Template.Annotations[kube.RestartedAtAnno] != "" {
		t.Fatalf("non-opted-in StatefulSet plain-sts must NOT roll out")
	}

	// Scan 3: sockets now serve freshCert -> drift series pruned back to 0.
	servingOld = false
	now = now.Add(15 * time.Minute)
	if err := a.auditLiveSockets(ctx); err != nil {
		t.Fatalf("scan 3: %v", err)
	}
	if v := ptestutil.ToFloat64(metrics.TLSLiveSocketDrift.WithLabelValues("apps", "wh-svc", "wh-tls")); v != 0 {
		t.Fatalf("expected drift pruned to 0 once socket serves fresh cert, got %v", v)
	}
}

// The ingress RBAC denial is the exact production symptom: NAC has no
// "ingresses" permission, so the old collectIngressTLSServices list
// returned 403 and aborted the entire 15m live-socket audit. A Pod
// mounting two TLS Secrets must also not be reported as drifted when
// the socket serves EITHER of them.
func TestLiveSocketAuditSkipsForbiddenIngressAndMultiSecret(t *testing.T) {
	metrics.TLSLiveSocketDrift.Reset()
	now := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	_, pemA := genSelfSignedCert(t, 111, now.Add(90*24*time.Hour), "svc.apps.svc")
	certB, pemB := genSelfSignedCert(t, 222, now.Add(90*24*time.Hour), "other.apps.svc")
	isCtrl := true

	cs := fake.NewSimpleClientset(
		makeTLSSecret("apps", "svc-tls", pemA, now.Add(-time.Hour)),
		makeTLSSecret("apps", "extra-tls", pemB, now.Add(-time.Hour)),
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "multi-svc", UID: "svc-multi"},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{"app": "multi-pod"},
				Ports:    []corev1.ServicePort{{Name: "https", Port: 443, TargetPort: intstr.FromInt32(8443)}},
			},
		},
		func() *corev1.Pod {
			p := makeReadyTLSPod("apps", "multi-pod", "10.0.0.9", "svc-tls",
				metav1.OwnerReference{Kind: "Deployment", Name: "multi", Controller: &isCtrl})
			p.Spec.Volumes = append(p.Spec.Volumes, corev1.Volume{
				Name: "extra", VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{SecretName: "extra-tls"},
				},
			})
			return p
		}(),
	)
	cs.PrependReactor("list", "ingresses", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(
			schema.GroupResource{Group: "networking.k8s.io", Resource: "ingresses"}, "",
			errors.New("ingresses is forbidden: User node-ops-operator cannot list"))
	})

	a := &certDriftAuditor{
		cs: cs, now: func() time.Time { return now },
		prober: func(context.Context, string, string) (*x509.Certificate, error) {
			return certB, nil // the *second* mounted Secret's cert
		},
	}
	for i := 0; i < liveDriftConfirmScans; i++ {
		if err := a.auditLiveSockets(ctx); err != nil {
			t.Fatalf("scan %d: forbidden ingress must not abort the audit: %v", i+1, err)
		}
	}
	if v := ptestutil.ToFloat64(metrics.TLSLiveSocketDrift.WithLabelValues("apps", "multi-svc", "svc-tls")); v != 0 {
		t.Fatalf("socket serving a mounted Secret must not be drift, got %v", v)
	}
}

// A webhook ServiceReference.Port is a SERVICE port. The probe dials a
// pod IP, so it must be translated through targetPort — otherwise every
// webhook with port != targetPort dials a closed port and looks broken.
// A TLS-port-only Service whose Pod mounts a client mTLS Secret must not
// be restarted: the socket serves an identity no mounted Secret bears,
// so there is no proof a mounted Secret serves the port. The old blind
// mounted[0] fallback paged and bounced it every 2h.
func TestLiveSocketAuditSkipsClientMTLSSecretOnTLSPortOnlyService(t *testing.T) {
	metrics.TLSLiveSocketDrift.Reset()
	now := time.Date(2026, 11, 18, 11, 0, 0, 0, time.UTC)
	_, clientPEM := genSelfSignedCert(t, 111, now.Add(90*24*time.Hour), "client.apps.svc")
	served, _ := genSelfSignedCert(t, 999, now.Add(90*24*time.Hour), "server.apps.svc")
	isCtrl := true

	cs := fake.NewSimpleClientset(
		makeTLSSecret("apps", "client-mtls", clientPEM, now.Add(-time.Hour)),
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "client-svc", UID: "svc-client"},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{"app": "client-pod"},
				Ports:    []corev1.ServicePort{{Name: "https", Port: 443, TargetPort: intstr.FromInt32(8443)}},
			},
		},
		makeReadyTLSPod("apps", "client-pod", "10.0.0.21", "client-mtls",
			metav1.OwnerReference{Kind: "Deployment", Name: "client-dep", Controller: &isCtrl}),
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "client-dep", UID: "dep-client"},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "client-pod"}}},
			},
		},
		&appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "apps", Name: "client-dep-rs",
				OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "client-dep", Controller: &isCtrl}},
			},
		},
	)
	probed := false
	a := &certDriftAuditor{
		cs: cs, now: func() time.Time { return now },
		prober: func(context.Context, string, string) (*x509.Certificate, error) {
			probed = true
			return served, nil
		},
	}
	for i := 0; i < liveDriftConfirmScans; i++ {
		if err := a.auditLiveSockets(ctx); err != nil {
			t.Fatalf("scan %d: %v", i+1, err)
		}
	}
	if !probed {
		t.Fatal("target was never probed — test setup did not exercise the audit")
	}
	if v := ptestutil.ToFloat64(metrics.TLSLiveSocketDrift.WithLabelValues("apps", "client-svc", "client-mtls")); v != 0 {
		t.Fatalf("client mTLS Secret must not be flagged as drift, got %v", v)
	}
	got, _ := cs.AppsV1().Deployments("apps").Get(ctx, "client-dep", metav1.GetOptions{})
	if got.Spec.Template.Annotations[kube.RestartedAtAnno] != "" {
		t.Fatal("client mTLS pod must not be restarted on a guessed Secret")
	}
}

// certWithIPSAN builds a real IP-SAN certificate so Check B's census
// can be tested end-to-end (the DNS-only helper above cannot populate
// cert.IPAddresses).
func certWithIPSAN(t *testing.T, ip net.IP) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4242),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IPAddresses:  []net.IP{ip},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// Check B builds the census reused by the live-socket audit: an IP-only
// served cert must find its Secret through ipNames (it was always nil
// here, so the Secret was never matched).
func TestAuditTLSSecretsFillsIPNames(t *testing.T) {
	cs := fake.NewSimpleClientset(makeTLSSecret("apps", "ip-san",
		certWithIPSAN(t, net.ParseIP("10.1.2.3")), time.Now()))
	a := &certDriftAuditor{cs: cs, now: func() time.Time { return time.Now() }}
	if err := a.auditTLSSecrets(ctx); err != nil {
		t.Fatalf("auditTLSSecrets: %v", err)
	}
	meta, ok := a.liveRunSecretMeta[secretMetricKey{"apps", "ip-san"}]
	if !ok {
		t.Fatal("census missing the IP-SAN Secret")
	}
	if len(meta.ipNames) != 1 || meta.ipNames[0] != "10.1.2.3" {
		t.Fatalf("ipNames = %v, want [10.1.2.3]", meta.ipNames)
	}
	served := &x509.Certificate{IPAddresses: []net.IP{net.ParseIP("10.1.2.3")}}
	if matched, ok := matchServedSecret([]tlsSecretMeta{meta}, served); !ok || matched.name != "ip-san" {
		t.Fatalf("IP-SAN served cert did not match its Secret: %+v ok=%v", matched, ok)
	}
}

// An empty CN is not an identity: a served cert with an empty SAN
// entry must not match every mounted Secret that also has no CN.
func TestMatchServedSecretIgnoresEmptyCommonName(t *testing.T) {
	served := &x509.Certificate{DNSNames: []string{""}}
	mounted := []tlsSecretMeta{{name: "no-cn", dnsNames: []string{"other.example"}}}
	if matched, ok := matchServedSecret(mounted, served); ok {
		t.Fatalf("empty commonName must not match, got %+v", matched)
	}
}

// A named targetPort owned by a native sidecar (restartPolicy: Always
// init container) must resolve; one-shot init containers and main
// containers keep their existing precedence.
func TestResolveContainerPortIncludesRestartableInitContainers(t *testing.T) {
	always := corev1.ContainerRestartPolicyAlways
	pod := &corev1.Pod{Spec: corev1.PodSpec{
		Containers: []corev1.Container{{Name: "app", Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}}}},
		InitContainers: []corev1.Container{
			{Name: "oneshot", Ports: []corev1.ContainerPort{{Name: "tls", ContainerPort: 9443}}},
			{Name: "proxy", RestartPolicy: &always, Ports: []corev1.ContainerPort{{Name: "tls", ContainerPort: 8443}}},
		},
	}}
	for _, tc := range []struct {
		port string
		want int32
	}{
		{"tls", 8443},    // sidecar owns it; one-shot init's 9443 ignored
		{"http", 8080},   // main container still resolved
		{"missing", 443}, // unknown name falls back to the Service port
	} {
		sp := &corev1.ServicePort{Port: 443, TargetPort: intstr.FromString(tc.port)}
		if got := resolveContainerPort(sp, pod); got != tc.want {
			t.Errorf("targetPort %q = %d, want %d", tc.port, got, tc.want)
		}
	}
}

func TestPickServingSecretDoesNotGuess(t *testing.T) {
	m := tlsSecretMeta{name: "client-mtls", commonName: "client.apps.svc", dnsNames: []string{"client.apps.svc"}}
	got, ok := pickServingSecret([]tlsSecretMeta{m}, "server-svc", "server-svc.apps.svc")
	if ok || got.name != "" {
		t.Fatalf("pickServingSecret must not fall back to mounted[0], got %+v ok=%v", got, ok)
	}
	// A real SAN match is still picked so the probe gets the right SNI.
	served := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "server.apps.svc"},
		DNSNames: []string{"server.apps.svc"},
	}
	if matched, ok := matchServedSecret([]tlsSecretMeta{m}, served); ok || matched.name != "" {
		t.Fatalf("unrelated served identity must not match, got %+v ok=%v", matched, ok)
	}
}

func TestPodMountsTLSSecretFromInitContainer(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "init-pod"},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{{
				Name: "init-tls", VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{SecretName: "init-tls"},
				},
			}},
			InitContainers: []corev1.Container{{
				Name:         "cert-init",
				VolumeMounts: []corev1.VolumeMount{{Name: "init-tls", MountPath: "/tls"}},
			}},
		},
	}
	secrets := map[secretMetricKey]tlsSecretMeta{
		{"apps", "init-tls"}: {name: "init-tls"},
	}
	if !podMountsTLSSecret(pod, secrets) {
		t.Fatal("Secret staged by an init container must be counted as mounted")
	}
	if got := mountedTLSSecrets(pod, secrets); len(got) != 1 || got[0].name != "init-tls" {
		t.Fatalf("init container TLS Secret missing from mounted set: %+v", got)
	}
}

// The census flag, not an empty map, decides whether Check B already ran
// this sweep: an empty-but-populated census must not trigger a second
// full TLS Secret list.
func TestLiveSocketAuditReusesEmptySecretCensus(t *testing.T) {
	cs := fake.NewSimpleClientset()
	secretLists := 0
	cs.PrependReactor("list", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		secretLists++
		return true, &corev1.SecretList{}, nil
	})
	a := &certDriftAuditor{cs: cs, now: func() time.Time { return time.Now() }}
	a.liveRunSecretSet = true
	a.liveRunSecretMeta = map[secretMetricKey]tlsSecretMeta{}
	if err := a.auditLiveSockets(ctx); err != nil {
		t.Fatal(err)
	}
	if secretLists != 0 {
		t.Fatalf("re-listed TLS Secrets %d time(s) despite liveRunSecretSet", secretLists)
	}
}

func TestLiveDriftDBQuorumLabelsCoverStatefulOperators(t *testing.T) {
	for _, want := range []string{
		"pxc.percona.com/cluster", "psmdb.percona.com/cluster",
		"dragonflydb.io/cluster", "nats_cluster",
	} {
		found := false
		for _, label := range liveDriftDBQuorumLabels {
			if label == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("liveDriftDBQuorumLabels missing %q", want)
		}
	}
}

func TestLiveSocketAuditPinnedServicePortIsTranslated(t *testing.T) {
	metrics.TLSLiveSocketDrift.Reset()
	now := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	served, _ := genSelfSignedCert(t, 1001, now.Add(3*24*time.Hour), "svc.apps.svc")
	_, newPEM := genSelfSignedCert(t, 2002, now.Add(90*24*time.Hour), "svc.apps.svc")
	isCtrl := true
	pin := int32(8443)

	cs := fake.NewSimpleClientset(
		makeTLSSecret("apps", "pin-tls", newPEM, now.Add(-time.Hour)),
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "pin-svc", UID: "svc-pin"},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{"app": "pin-pod"},
				Ports:    []corev1.ServicePort{{Port: 8443, TargetPort: intstr.FromInt32(9443)}},
			},
		},
		makeReadyTLSPod("apps", "pin-pod", "10.0.0.11", "pin-tls",
			metav1.OwnerReference{Kind: "Deployment", Name: "pin-dep", Controller: &isCtrl}),
		&admissionv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "pin-vwc"},
			Webhooks: []admissionv1.ValidatingWebhook{{
				Name: "pin.example.com",
				ClientConfig: admissionv1.WebhookClientConfig{
					Service: &admissionv1.ServiceReference{Namespace: "apps", Name: "pin-svc", Port: &pin},
				},
			}},
		},
	)

	var probedAddr string
	a := &certDriftAuditor{
		cs: cs, now: func() time.Time { return now },
		prober: func(_ context.Context, addr, _ string) (*x509.Certificate, error) {
			probedAddr = addr
			return served, nil
		},
	}
	if err := a.auditLiveSockets(ctx); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(probedAddr, ":9443") {
		t.Fatalf("pinned service port 8443 must be translated to targetPort 9443, probed %q", probedAddr)
	}
}

func TestLiveSocketAuditEarlyListErrorDoesNotPruneStreakOrMetric(t *testing.T) {
	metrics.TLSLiveSocketDrift.Reset()
	now := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	servedOld, _ := genSelfSignedCert(t, 1001, now.Add(90*24*time.Hour), "svc.apps.svc")
	_, newPEM := genSelfSignedCert(t, 2002, now.Add(90*24*time.Hour), "svc.apps.svc")
	_, matchedPEM := genSelfSignedCert(t, 1001, now.Add(90*24*time.Hour), "svc.apps.svc")
	isCtrl := true
	pin := int32(443)

	cs := fake.NewSimpleClientset(
		makeTLSSecret("apps", "my-tls", newPEM, now.Add(-time.Hour)),
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "my-svc", UID: "svc-1"},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{"app": "my-pod"},
				Ports:    []corev1.ServicePort{{Port: 443, TargetPort: intstr.FromInt32(8443)}},
			},
		},
		makeReadyTLSPod("apps", "my-pod", "10.0.0.12", "my-tls",
			metav1.OwnerReference{Kind: "Deployment", Name: "my-dep", Controller: &isCtrl}),
		&admissionv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "my-vwc"},
			Webhooks: []admissionv1.ValidatingWebhook{{
				Name: "my.example.com",
				ClientConfig: admissionv1.WebhookClientConfig{
					Service: &admissionv1.ServiceReference{Namespace: "apps", Name: "my-svc", Port: &pin},
				},
			}},
		},
	)

	var failPods, failSecrets bool
	cs.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		if failPods {
			return true, nil, errors.New("pods list error")
		}
		return false, nil, nil
	})
	cs.PrependReactor("list", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		if failSecrets {
			return true, nil, errors.New("secrets list error")
		}
		return false, nil, nil
	})

	var currentServed = servedOld
	a := &certDriftAuditor{
		cs: cs, now: func() time.Time { return now },
		disableLiveRollout: true,
		prober: func(_ context.Context, _, _ string) (*x509.Certificate, error) {
			return currentServed, nil
		},
	}

	// Scan 1: streak=1 (no metric yet).
	if err := a.auditLiveSockets(ctx); err != nil {
		t.Fatal(err)
	}
	streakKey := "apps/my-svc/my-tls"
	if got := a.liveDriftStreak.Count(streakKey); got != 1 {
		t.Fatalf("after scan 1 streak = %d, want 1", got)
	}

	// Transient pods list error must NOT prune streak=1.
	a.beginLiveRun()
	failPods = true
	if err := a.auditLiveSockets(ctx); err == nil {
		t.Fatal("expected pods list error")
	}
	if got := a.liveDriftStreak.Count(streakKey); got != 1 {
		t.Fatalf("after pods error streak = %d, want 1 (must not prune)", got)
	}
	failPods = false

	// Scan 2: streak=2 -> TLSLiveSocketDrift = 1.
	a.beginLiveRun()
	if err := a.auditLiveSockets(ctx); err != nil {
		t.Fatal(err)
	}
	if got := ptestutil.ToFloat64(metrics.TLSLiveSocketDrift.WithLabelValues("apps", "my-svc", "my-tls")); got != 1 {
		t.Fatalf("drift metric = %v, want 1", got)
	}

	// Transient secrets list error must NOT prune active metric or streak.
	a.beginLiveRun()
	failSecrets = true
	if err := a.auditLiveSockets(ctx); err == nil {
		t.Fatal("expected secrets list error")
	}
	if got := ptestutil.ToFloat64(metrics.TLSLiveSocketDrift.WithLabelValues("apps", "my-svc", "my-tls")); got != 1 {
		t.Fatalf("after secrets error drift metric = %v, want 1 (must not prune)", got)
	}
	if got := a.liveDriftStreak.Count(streakKey); got != 2 {
		t.Fatalf("after secrets error streak = %d, want 2 (must not prune)", got)
	}
	failSecrets = false

	// Secret rotates / pod serves matching cert -> clean sweep prunes both metric and streak.
	a.beginLiveRun()
	if _, err := cs.CoreV1().Secrets("apps").Update(ctx,
		makeTLSSecret("apps", "my-tls", matchedPEM, now.Add(-time.Hour)),
		metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := a.auditLiveSockets(ctx); err != nil {
		t.Fatal(err)
	}
	if got := ptestutil.CollectAndCount(metrics.TLSLiveSocketDrift); got != 0 {
		t.Fatalf("after clean sweep metric count = %d, want 0 (pruned)", got)
	}
	if got := a.liveDriftStreak.Count(streakKey); got != 0 {
		t.Fatalf("after clean sweep streak = %d, want 0 (pruned)", got)
	}
}

func TestMaybeRolloutWorkloadFluxGateAndReservation(t *testing.T) {
	isCtrl := true
	wKey := "apps/Deployment/wh-app"

	newTargetAndObjs := func(mgr string) (*liveProbeTarget, *appsv1.Deployment, []runtime.Object) {
		dep := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "wh-app", UID: "dep-1"},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "wh-pod"}}},
			},
		}
		if mgr != "" {
			dep.ManagedFields = []metav1.ManagedFieldsEntry{{
				Manager:   mgr,
				Operation: metav1.ManagedFieldsOperationApply,
			}}
		}
		rs := &appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "apps", Name: "wh-app-rs",
				OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "wh-app", Controller: &isCtrl}},
			},
		}
		pod := makeReadyTLSPod("apps", "wh-pod", "10.0.0.1", "wh-tls",
			metav1.OwnerReference{Kind: "ReplicaSet", Name: "wh-app-rs", Controller: &isCtrl})
		target := &liveProbeTarget{
			svc: corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "wh-svc"}},
			pod: pod,
			secret: tlsSecretMeta{
				name: "wh-tls",
			},
		}
		return target, dep, []runtime.Object{dep, rs, pod}
	}

	cases := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "FluxPatchGate_denies",
			run: func(t *testing.T) {
				heal.ConfigureBudget(1, time.Hour)
				heal.ConfigureFluxConflictLoop(2, 30*time.Minute)
				t.Cleanup(func() {
					heal.ConfigureBudget(0, 0)
					heal.ConfigureFluxConflictLoop(0, 0)
				})

				fixedNow := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
				target, dep, objs := newTargetAndObjs("kustomize-controller")
				cs := fake.NewSimpleClientset(objs...)
				a := &certDriftAuditor{cs: cs, dyn: cdaDyn(), queue: "live-flux-deny-test"}
				sctx := kube.WithSweepOverlay(ctx)
				rolled := map[string]bool{}

				if !heal.FluxPatchGate("deployment", dep, "live-socket-audit:"+wKey, fixedNow) {
					t.Fatal("pre-warm sighting unexpectedly denied")
				}
				before := testutil.QueueErrorCount(t, a.queue)
				a.maybeRolloutWorkload(sctx, logr.Discard(), target, rolled, fixedNow)

				if got := testutil.QueueErrorCount(t, a.queue) - before; got != 0 {
					t.Fatalf("queue error delta = %v, want 0", got)
				}
				gotDep, _ := cs.AppsV1().Deployments("apps").Get(ctx, "wh-app", metav1.GetOptions{})
				if gotDep.Spec.Template.Annotations[kube.RestartedAtAnno] != "" {
					t.Fatalf("RestartedAtAnno=%q, want empty on FluxPatchGate denial", gotDep.Spec.Template.Annotations[kube.RestartedAtAnno])
				}
				if rolled[wKey] {
					t.Fatal("rolled[wKey] = true, want false")
				}
				if !kube.TryReserveWorkloadKey(sctx, wKey) {
					t.Fatal("ownerDisrupt key leaked on FluxPatchGate denial")
				}
				if proceed, unverifiable := heal.Gate(ctx, logr.Discard(), nil, cs, cdaDyn(), "after-flux-deny", fixedNow); !proceed || unverifiable {
					t.Fatalf("Gate after FluxPatchGate denial = (%v,%v), want (true,false)", proceed, unverifiable)
				}
			},
		},
		{
			name: "Duty_key_isolation_across_duties_and_kinds",
			run: func(t *testing.T) {
				heal.ConfigureBudget(2, time.Hour)
				heal.ConfigureFluxConflictLoop(2, 30*time.Minute)
				t.Cleanup(func() {
					heal.ConfigureBudget(0, 0)
					heal.ConfigureFluxConflictLoop(0, 0)
				})

				fixedNow := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
				target, dep, objs := newTargetAndObjs("kustomize-controller")
				sts := &appsv1.StatefulSet{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "apps", Name: "wh-app",
						Annotations:   map[string]string{kube.AnnoCertDriftReloadOptIn: "true"},
						ManagedFields: dep.ManagedFields,
					},
				}
				stsPod := makeReadyTLSPod("apps", "sts-pod", "10.0.0.2", "wh-tls",
					metav1.OwnerReference{Kind: "StatefulSet", Name: "wh-app", Controller: &isCtrl})
				stsTarget := &liveProbeTarget{
					svc:    corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "sts-svc"}},
					pod:    stsPod,
					secret: tlsSecretMeta{name: "wh-tls"},
				}
				cs := fake.NewSimpleClientset(append(objs, sts, stsPod)...)
				a := &certDriftAuditor{cs: cs, dyn: cdaDyn(), queue: "live-duty-iso-test"}
				sctx := kube.WithSweepOverlay(ctx)
				rolled := map[string]bool{}

				// Exhaust sibling duty key and bare ns/name key.
				heal.FluxPatchGate("deployment", dep, "tls-secret-audit:"+wKey, fixedNow)
				heal.FluxPatchGate("deployment", dep, "tls-secret-audit:"+wKey, fixedNow)
				heal.FluxPatchGate("deployment", dep, "apps/wh-app", fixedNow)
				heal.FluxPatchGate("deployment", dep, "apps/wh-app", fixedNow)
				// Also exhaust Deployment key twice and verify same-name StatefulSet is isolated by kind.
				heal.FluxPatchGate("statefulset", sts, "live-socket-audit:apps/StatefulSet/wh-app", fixedNow)
				heal.FluxPatchGate("statefulset", sts, "live-socket-audit:apps/StatefulSet/wh-app", fixedNow)

				a.maybeRolloutWorkload(sctx, logr.Discard(), target, rolled, fixedNow)
				gotDep, _ := cs.AppsV1().Deployments("apps").Get(ctx, "wh-app", metav1.GetOptions{})
				if gotDep.Spec.Template.Annotations[kube.RestartedAtAnno] == "" {
					t.Fatal("Deployment rollout blocked despite duty/kind key isolation")
				}
				if !rolled[wKey] {
					t.Fatal("expected rolled[wKey] == true")
				}
				if kube.TryReserveWorkloadKey(sctx, wKey) {
					t.Fatal("wKey must stay reserved after successful rollout")
				}

				// Same-name StatefulSet is denied because its own kind-scoped key was exhausted.
				a.maybeRolloutWorkload(sctx, logr.Discard(), stsTarget, rolled, fixedNow)
				gotSts, _ := cs.AppsV1().StatefulSets("apps").Get(ctx, "wh-app", metav1.GetOptions{})
				if gotSts.Spec.Template.Annotations[kube.RestartedAtAnno] != "" {
					t.Fatal("StatefulSet rollout should be denied by its own exhausted kind-scoped key")
				}
			},
		},
		{
			name: "Patch_API_error_releases_key_keeps_grant_spent",
			run: func(t *testing.T) {
				heal.ConfigureBudget(1, time.Hour)
				t.Cleanup(func() { heal.ConfigureBudget(0, 0) })

				fixedNow := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
				target, _, objs := newTargetAndObjs("")
				cs := fake.NewSimpleClientset(objs...)
				cs.PrependReactor("patch", "deployments", func(k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, apierrors.NewInternalError(errors.New("boom"))
				})
				a := &certDriftAuditor{cs: cs, dyn: cdaDyn(), queue: "live-patch-500-test"}
				sctx := kube.WithSweepOverlay(ctx)
				rolled := map[string]bool{}

				before := testutil.QueueErrorCount(t, a.queue)
				a.maybeRolloutWorkload(sctx, logr.Discard(), target, rolled, fixedNow)

				if got := testutil.QueueErrorCount(t, a.queue) - before; got != 1 {
					t.Fatalf("queue error delta = %v, want 1", got)
				}
				gotDep, _ := cs.AppsV1().Deployments("apps").Get(ctx, "wh-app", metav1.GetOptions{})
				if gotDep.Spec.Template.Annotations[kube.RestartedAtAnno] != "" {
					t.Fatalf("RestartedAtAnno=%q, want empty on 500 Patch", gotDep.Spec.Template.Annotations[kube.RestartedAtAnno])
				}
				if rolled[wKey] {
					t.Fatal("rolled[wKey] = true on 500 Patch")
				}
				if !kube.TryReserveWorkloadKey(sctx, wKey) {
					t.Fatal("ownerDisrupt key leaked on 500 Patch failure")
				}
				if proceed, unverifiable := heal.Gate(ctx, logr.Discard(), nil, cs, cdaDyn(), "after-500", fixedNow); proceed || unverifiable {
					t.Fatalf("Gate after 500 Patch = (%v,%v), want (false,false) — grant must stay spent", proceed, unverifiable)
				}
			},
		},
		{
			name: "Patch_404_releases_key_and_refunds_grant",
			run: func(t *testing.T) {
				heal.ConfigureBudget(1, time.Hour)
				t.Cleanup(func() { heal.ConfigureBudget(0, 0) })

				fixedNow := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
				target, _, objs := newTargetAndObjs("")
				cs := fake.NewSimpleClientset(objs...)
				cs.PrependReactor("patch", "deployments", func(k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, apierrors.NewNotFound(
						schema.GroupResource{Group: "apps", Resource: "deployments"}, "wh-app")
				})
				a := &certDriftAuditor{cs: cs, dyn: cdaDyn(), queue: "live-patch-404-test"}
				sctx := kube.WithSweepOverlay(ctx)
				rolled := map[string]bool{}

				before := testutil.QueueErrorCount(t, a.queue)
				a.maybeRolloutWorkload(sctx, logr.Discard(), target, rolled, fixedNow)

				if got := testutil.QueueErrorCount(t, a.queue) - before; got != 0 {
					t.Fatalf("queue error delta = %v, want 0", got)
				}
				gotDep, _ := cs.AppsV1().Deployments("apps").Get(ctx, "wh-app", metav1.GetOptions{})
				if gotDep.Spec.Template.Annotations[kube.RestartedAtAnno] != "" {
					t.Fatalf("RestartedAtAnno=%q, want empty on 404 Patch", gotDep.Spec.Template.Annotations[kube.RestartedAtAnno])
				}
				if rolled[wKey] {
					t.Fatal("rolled[wKey] = true on 404 Patch")
				}
				if !kube.TryReserveWorkloadKey(sctx, wKey) {
					t.Fatal("ownerDisrupt key leaked on 404 Patch failure")
				}
				if proceed, unverifiable := heal.Gate(ctx, logr.Discard(), nil, cs, cdaDyn(), "after-404", fixedNow); !proceed || unverifiable {
					t.Fatalf("Gate after 404 Patch = (%v,%v), want (true,false) — grant not refunded", proceed, unverifiable)
				}
			},
		},
		{
			name: "Pre_reserved_workload_defers_and_refunds_grant",
			run: func(t *testing.T) {
				heal.ConfigureBudget(1, time.Hour)
				t.Cleanup(func() { heal.ConfigureBudget(0, 0) })

				fixedNow := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
				target, _, objs := newTargetAndObjs("")
				cs := fake.NewSimpleClientset(objs...)
				a := &certDriftAuditor{cs: cs, dyn: cdaDyn(), queue: "live-prereserved-test"}
				sctx := kube.WithSweepOverlay(ctx)
				if !kube.TryReserveWorkloadKey(sctx, wKey) {
					t.Fatal("pre-reserve failed")
				}
				rolled := map[string]bool{}

				before := testutil.QueueErrorCount(t, a.queue)
				a.maybeRolloutWorkload(sctx, logr.Discard(), target, rolled, fixedNow)

				if got := testutil.QueueErrorCount(t, a.queue) - before; got != 0 {
					t.Fatalf("queue error delta = %v, want 0", got)
				}
				gotDep, _ := cs.AppsV1().Deployments("apps").Get(ctx, "wh-app", metav1.GetOptions{})
				if gotDep.Spec.Template.Annotations[kube.RestartedAtAnno] != "" {
					t.Fatalf("RestartedAtAnno=%q, want empty when workload pre-reserved", gotDep.Spec.Template.Annotations[kube.RestartedAtAnno])
				}
				if rolled[wKey] {
					t.Fatal("rolled[wKey] = true when workload pre-reserved")
				}
				if proceed, unverifiable := heal.Gate(ctx, logr.Discard(), nil, cs, cdaDyn(), "after-prereserve", fixedNow); !proceed || unverifiable {
					t.Fatalf("Gate after pre-reserve deferral = (%v,%v), want (true,false)", proceed, unverifiable)
				}
			},
		},
		{
			name: "AllowedVPersisted_precedes_FluxPatchGate",
			run: func(t *testing.T) {
				heal.ConfigureFluxConflictLoop(2, 30*time.Minute)
				var hookCalls int
				heal.SetFluxConflictHook(func(heal.FluxConflictSignal) { hookCalls++ })
				t.Cleanup(func() {
					heal.ConfigureFluxConflictLoop(0, 0)
					heal.SetFluxConflictHook(nil)
				})

				fixedNow := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
				target, _, objs := newTargetAndObjs("helm-controller")
				cs := fake.NewSimpleClientset(append(objs, cordonedNode("worker-0"))...)
				a := &certDriftAuditor{cs: cs, dyn: cdaDyn(), queue: "live-maint-order-test"}
				rolled := map[string]bool{}

				for i := range 2 {
					a.maybeRolloutWorkload(kube.WithSweepOverlay(ctx), logr.Discard(), target, rolled, fixedNow)
					gotDep, _ := cs.AppsV1().Deployments("apps").Get(ctx, "wh-app", metav1.GetOptions{})
					if gotDep.Spec.Template.Annotations[kube.RestartedAtAnno] != "" {
						t.Fatalf("held call %d stamped RestartedAtAnno", i+1)
					}
					if rolled[wKey] {
						t.Fatalf("held call %d marked rolled", i+1)
					}
				}
				if hookCalls != 0 {
					t.Fatalf("FluxConflictHook fired %d times while maintenance held, want 0", hookCalls)
				}

				if err := cs.CoreV1().Nodes().Delete(ctx, "worker-0", metav1.DeleteOptions{}); err != nil {
					t.Fatal(err)
				}
				a.maybeRolloutWorkload(kube.WithSweepOverlay(ctx), logr.Discard(), target, rolled, fixedNow)
				gotDep, _ := cs.AppsV1().Deployments("apps").Get(ctx, "wh-app", metav1.GetOptions{})
				if gotDep.Spec.Template.Annotations[kube.RestartedAtAnno] == "" || !rolled[wKey] {
					t.Fatal("post-maintenance call failed — phantom sightings recorded during hold")
				}
			},
		},
		{
			name: "StampPersisted_error_keeps_wKey_reserved",
			run: func(t *testing.T) {
				fixedNow := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
				target, _, objs := newTargetAndObjs("")
				cs := fake.NewSimpleClientset(objs...)
				patchCalls := 0
				cs.PrependReactor("patch", "deployments", func(k8stesting.Action) (bool, runtime.Object, error) {
					patchCalls++
					if patchCalls == 2 { // 1st is RestartTemplatePatch, 2nd is StampPersisted
						return true, nil, apierrors.NewInternalError(errors.New("stamp failed"))
					}
					return false, nil, nil
				})
				a := &certDriftAuditor{cs: cs, dyn: cdaDyn(), queue: "live-stamp-err-test"}
				sctx := kube.WithSweepOverlay(ctx)
				rolled := map[string]bool{}

				before := testutil.QueueErrorCount(t, a.queue)
				a.maybeRolloutWorkload(sctx, logr.Discard(), target, rolled, fixedNow)

				if got := testutil.QueueErrorCount(t, a.queue) - before; got != 1 {
					t.Fatalf("queue error delta = %v, want 1", got)
				}
				gotDep, _ := cs.AppsV1().Deployments("apps").Get(ctx, "wh-app", metav1.GetOptions{})
				if gotDep.Spec.Template.Annotations[kube.RestartedAtAnno] == "" || !rolled[wKey] {
					t.Fatal("expected rollout to succeed when 1st patch succeeded")
				}
				if kube.TryReserveWorkloadKey(sctx, wKey) {
					t.Fatal("wKey must NOT be released when patchFn succeeded and only StampPersisted failed")
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, tc.run)
	}
}

func genTLSTestCert(t *testing.T, serial int64, cn string, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) ([]byte, *ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		DNSNames:              []string{cn},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	if isCA {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	signerCert := tmpl
	signerKey := priv
	if parent != nil && parentKey != nil {
		signerCert = parent
		signerKey = parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &priv.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return der, priv, parsed
}

func startLoopbackTLSServer(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer func() { _ = c.Close() }()
				tc := tls.Server(c, cfg)
				_ = tc.Handshake()
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// TestDefaultLiveCertProber exercises loopback TLS/TCP dialing, leaf
// extraction from a chain, SNI propagation, closed-port errors,
// non-TLS/EOF listeners, and context handshake timeouts.
func TestDefaultLiveCertProber(t *testing.T) {
	leafDER, leafKey, _ := genTLSTestCert(t, 101, "leaf.apps.svc", false, nil, nil)
	leafTLSCert := tls.Certificate{
		Certificate: [][]byte{leafDER},
		PrivateKey:  leafKey,
	}

	caDER, caKey, caCert := genTLSTestCert(t, 900, "test-root-ca", true, nil, nil)
	chainLeafDER, chainLeafKey, _ := genTLSTestCert(t, 102, "chain-leaf.apps.svc", false, caCert, caKey)
	chainTLSCert := tls.Certificate{
		Certificate: [][]byte{chainLeafDER, caDER},
		PrivateKey:  chainLeafKey,
	}

	cases := []struct {
		name         string
		setup        func(t *testing.T) (addr, serverName string, probeCtx context.Context, verify func(t *testing.T, cert *x509.Certificate, err error))
		wantDuration time.Duration
	}{
		{
			name: "valid_self_signed_leaf",
			setup: func(t *testing.T) (string, string, context.Context, func(*testing.T, *x509.Certificate, error)) {
				addr := startLoopbackTLSServer(t, &tls.Config{Certificates: []tls.Certificate{leafTLSCert}})
				return addr, "leaf.apps.svc", ctx, func(t *testing.T, got *x509.Certificate, err error) {
					if err != nil {
						t.Fatalf("unexpected err: %v", err)
					}
					if got == nil || got.SerialNumber.Int64() != 101 || got.Subject.CommonName != "leaf.apps.svc" {
						t.Fatalf("got cert = %+v, want serial=101 CN=leaf.apps.svc", got)
					}
				}
			},
		},
		{
			name: "cert_chain_returns_leaf_not_ca",
			setup: func(t *testing.T) (string, string, context.Context, func(*testing.T, *x509.Certificate, error)) {
				addr := startLoopbackTLSServer(t, &tls.Config{Certificates: []tls.Certificate{chainTLSCert}})
				return addr, "chain-leaf.apps.svc", ctx, func(t *testing.T, got *x509.Certificate, err error) {
					if err != nil {
						t.Fatalf("unexpected err: %v", err)
					}
					if got == nil || got.SerialNumber.Int64() != 102 || got.Subject.CommonName != "chain-leaf.apps.svc" {
						t.Fatalf("got cert = %+v, want leaf serial=102 CN=chain-leaf.apps.svc (not CA 900)", got)
					}
				}
			},
		},
		{
			name: "sni_server_name_propagated",
			setup: func(t *testing.T) (string, string, context.Context, func(*testing.T, *x509.Certificate, error)) {
				var mu sync.Mutex
				var gotSNI string
				addr := startLoopbackTLSServer(t, &tls.Config{
					GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
						mu.Lock()
						gotSNI = chi.ServerName
						mu.Unlock()
						return &leafTLSCert, nil
					},
				})
				return addr, "webhook.apps.svc", ctx, func(t *testing.T, got *x509.Certificate, err error) {
					if err != nil {
						t.Fatalf("unexpected err: %v", err)
					}
					mu.Lock()
					sni := gotSNI
					mu.Unlock()
					if sni != "webhook.apps.svc" {
						t.Fatalf("got SNI = %q, want %q", sni, "webhook.apps.svc")
					}
					if got == nil || got.SerialNumber.Int64() != 101 {
						t.Fatalf("got cert = %+v, want serial 101", got)
					}
				}
			},
		},
		{
			name: "empty_sni_allowed",
			setup: func(t *testing.T) (string, string, context.Context, func(*testing.T, *x509.Certificate, error)) {
				var mu sync.Mutex
				gotSNI := "unset"
				addr := startLoopbackTLSServer(t, &tls.Config{
					GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
						mu.Lock()
						gotSNI = chi.ServerName
						mu.Unlock()
						return &leafTLSCert, nil
					},
				})
				return addr, "", ctx, func(t *testing.T, got *x509.Certificate, err error) {
					if err != nil {
						t.Fatalf("unexpected err: %v", err)
					}
					mu.Lock()
					sni := gotSNI
					mu.Unlock()
					if sni != "" {
						t.Fatalf("got SNI = %q, want empty", sni)
					}
					if got == nil || got.SerialNumber.Int64() != 101 {
						t.Fatalf("got cert = %+v, want serial 101", got)
					}
				}
			},
		},
		{
			name: "dial_error_closed_port",
			setup: func(t *testing.T) (string, string, context.Context, func(*testing.T, *x509.Certificate, error)) {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				addr := ln.Addr().String()
				_ = ln.Close()
				return addr, "closed.apps.svc", ctx, func(t *testing.T, got *x509.Certificate, err error) {
					if err == nil || got != nil {
						t.Fatalf("expected dial error on closed port, got cert=%+v err=%v", got, err)
					}
				}
			},
		},
		{
			name: "non_tls_plaintext_server",
			setup: func(t *testing.T) (string, string, context.Context, func(*testing.T, *x509.Certificate, error)) {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				var wg sync.WaitGroup
				t.Cleanup(func() {
					_ = ln.Close()
					wg.Wait()
				})
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						c, err := ln.Accept()
						if err != nil {
							return
						}
						_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
						_ = c.Close()
					}
				}()
				return ln.Addr().String(), "plain.apps.svc", ctx, func(t *testing.T, got *x509.Certificate, err error) {
					if err == nil || got != nil {
						t.Fatalf("expected TLS error on plaintext server, got cert=%+v err=%v", got, err)
					}
				}
			},
		},
		{
			name: "eof_immediate_close",
			setup: func(t *testing.T) (string, string, context.Context, func(*testing.T, *x509.Certificate, error)) {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				var wg sync.WaitGroup
				t.Cleanup(func() {
					_ = ln.Close()
					wg.Wait()
				})
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						c, err := ln.Accept()
						if err != nil {
							return
						}
						_ = c.Close()
					}
				}()
				return ln.Addr().String(), "eof.apps.svc", ctx, func(t *testing.T, got *x509.Certificate, err error) {
					if err == nil || got != nil {
						t.Fatalf("expected EOF error on immediate close, got cert=%+v err=%v", got, err)
					}
				}
			},
		},
		{
			name:         "handshake_timeout_via_context",
			wantDuration: 500 * time.Millisecond,
			setup: func(t *testing.T) (string, string, context.Context, func(*testing.T, *x509.Certificate, error)) {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				stop := make(chan struct{})
				var wg sync.WaitGroup
				t.Cleanup(func() {
					close(stop)
					_ = ln.Close()
					wg.Wait()
				})
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						c, err := ln.Accept()
						if err != nil {
							return
						}
						wg.Add(1)
						go func(conn net.Conn) {
							defer wg.Done()
							<-stop
							_ = conn.Close()
						}(c)
					}
				}()
				pctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
				t.Cleanup(cancel)
				return ln.Addr().String(), "stall.apps.svc", pctx, func(t *testing.T, got *x509.Certificate, err error) {
					if !errors.Is(err, context.DeadlineExceeded) || got != nil {
						t.Fatalf("expected DeadlineExceeded and nil cert, got cert=%+v err=%v", got, err)
					}
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr, sni, pctx, verify := tc.setup(t)
			start := time.Now()
			got, err := defaultLiveCertProber(pctx, addr, sni)
			if tc.wantDuration > 0 && time.Since(start) >= tc.wantDuration {
				t.Fatalf("probe elapsed = %v, want < %v", time.Since(start), tc.wantDuration)
			}
			verify(t, got, err)
		})
	}
}

func TestAddMutatingWebhookRefs(t *testing.T) {
	portPtr := func(p int32) *int32 { return &p }
	strPtr := func(s string) *string { return &s }

	cases := []struct {
		name string
		ws   []admissionv1.MutatingWebhook
		want map[string]int32
	}{
		{
			name: "nil_webhooks",
			ws:   nil,
			want: map[string]int32{},
		},
		{
			name: "empty_webhooks",
			ws:   []admissionv1.MutatingWebhook{},
			want: map[string]int32{},
		},
		{
			name: "url_only_ignored",
			ws: []admissionv1.MutatingWebhook{{
				Name:         "ext.webhook.io",
				ClientConfig: admissionv1.WebhookClientConfig{URL: strPtr("https://ext.example/mutate")},
			}},
			want: map[string]int32{},
		},
		{
			name: "service_with_port_and_path",
			ws: []admissionv1.MutatingWebhook{{
				Name: "svc.webhook.io",
				ClientConfig: admissionv1.WebhookClientConfig{
					Service: &admissionv1.ServiceReference{
						Namespace: "apps", Name: "wh-svc", Port: portPtr(8443), Path: strPtr("/mutate"),
					},
				},
			}},
			want: map[string]int32{"apps/wh-svc": 8443},
		},
		{
			name: "service_nil_port_stores_zero",
			ws: []admissionv1.MutatingWebhook{{
				Name: "nilport.webhook.io",
				ClientConfig: admissionv1.WebhookClientConfig{
					Service: &admissionv1.ServiceReference{
						Namespace: "apps", Name: "wh-svc", Port: nil,
					},
				},
			}},
			want: map[string]int32{"apps/wh-svc": 0},
		},
		{
			name: "empty_namespace_or_name_skipped",
			ws: []admissionv1.MutatingWebhook{
				{
					Name: "no-ns.webhook.io",
					ClientConfig: admissionv1.WebhookClientConfig{
						Service: &admissionv1.ServiceReference{Namespace: "", Name: "svc", Port: portPtr(443)},
					},
				},
				{
					Name: "no-name.webhook.io",
					ClientConfig: admissionv1.WebhookClientConfig{
						Service: &admissionv1.ServiceReference{Namespace: "apps", Name: "", Port: portPtr(443)},
					},
				},
			},
			want: map[string]int32{},
		},
		{
			name: "dedup_zero_upgraded_by_nonzero_port",
			ws: []admissionv1.MutatingWebhook{
				{
					Name: "first.webhook.io",
					ClientConfig: admissionv1.WebhookClientConfig{
						Service: &admissionv1.ServiceReference{Namespace: "apps", Name: "wh", Port: nil},
					},
				},
				{
					Name: "second.webhook.io",
					ClientConfig: admissionv1.WebhookClientConfig{
						Service: &admissionv1.ServiceReference{Namespace: "apps", Name: "wh", Port: portPtr(9443)},
					},
				},
			},
			want: map[string]int32{"apps/wh": 9443},
		},
		{
			name: "dedup_nonzero_preserved_over_nil_and_later_nonzero",
			ws: []admissionv1.MutatingWebhook{
				{
					Name: "first.webhook.io",
					ClientConfig: admissionv1.WebhookClientConfig{
						Service: &admissionv1.ServiceReference{Namespace: "apps", Name: "wh", Port: portPtr(8443)},
					},
				},
				{
					Name: "second.webhook.io",
					ClientConfig: admissionv1.WebhookClientConfig{
						Service: &admissionv1.ServiceReference{Namespace: "apps", Name: "wh", Port: nil},
					},
				},
				{
					Name: "third.webhook.io",
					ClientConfig: admissionv1.WebhookClientConfig{
						Service: &admissionv1.ServiceReference{Namespace: "apps", Name: "wh", Port: portPtr(9443)},
					},
				},
			},
			want: map[string]int32{"apps/wh": 8443},
		},
		{
			name: "multiple_services_mixed_url_and_service",
			ws: []admissionv1.MutatingWebhook{
				{
					Name:         "url.webhook.io",
					ClientConfig: admissionv1.WebhookClientConfig{URL: strPtr("https://ext.example/mutate")},
				},
				{
					Name: "svc1.webhook.io",
					ClientConfig: admissionv1.WebhookClientConfig{
						Service: &admissionv1.ServiceReference{Namespace: "ns1", Name: "s1", Port: portPtr(443)},
					},
				},
				{
					Name: "svc2.webhook.io",
					ClientConfig: admissionv1.WebhookClientConfig{
						Service: &admissionv1.ServiceReference{Namespace: "ns2", Name: "s2", Port: nil},
					},
				},
			},
			want: map[string]int32{"ns1/s1": 443, "ns2/s2": 0},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			refs := map[string]int32{}
			addMutatingWebhookRefs(refs, tc.ws)
			if !reflect.DeepEqual(refs, tc.want) {
				t.Fatalf("refs = %v, want %v", refs, tc.want)
			}
		})
	}
}
