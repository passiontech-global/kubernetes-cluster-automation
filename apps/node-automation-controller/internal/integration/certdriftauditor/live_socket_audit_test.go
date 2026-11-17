package certdriftauditor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
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
		// Class 3: TLS Ingress Backend (port 8000 non-standard, discovered via Ingress).
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "ing-svc", UID: "svc-3"},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{"app": "ing-pod"},
				Ports:    []corev1.ServicePort{{Port: 8000}},
			},
		},
		makeReadyTLSPod("apps", "ing-pod", "10.0.0.3", "ing-tls", metav1.OwnerReference{Kind: "StatefulSet", Name: "plain-sts", Controller: &isCtrl}),
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web-ing"},
			Spec: networkingv1.IngressSpec{
				TLS: []networkingv1.IngressTLS{{Hosts: []string{"web.example.com"}, SecretName: "ing-tls"}},
				DefaultBackend: &networkingv1.IngressBackend{
					Service: &networkingv1.IngressServiceBackend{Name: "ing-svc"},
				},
			},
		},
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
