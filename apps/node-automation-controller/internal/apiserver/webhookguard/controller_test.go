package webhookguard

import (
	"testing"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// ---------------------------------------------------------------------------
// admission-webhook-guard
// ---------------------------------------------------------------------------

func TestWebhookGuardRemovesOrphan(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "cfg"},
		Webhooks: []admissionv1.MutatingWebhook{
			{
				Name: "keep.example.com",
				ClientConfig: admissionv1.WebhookClientConfig{
					Service: &admissionv1.ServiceReference{
						Namespace: "alive", Name: "svc",
					},
				},
			},
			{
				Name: "orphan.example.com",
				ClientConfig: admissionv1.WebhookClientConfig{
					Service: &admissionv1.ServiceReference{
						Namespace: "dead-ns", Name: "svc",
					},
				},
			},
		},
	}
	cs := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "alive"}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "alive", Name: "svc"}},
		mwc)
	g := &webhookGuard{cs: cs}
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().
		Get(ctx, "cfg", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Webhooks) != 1 || got.Webhooks[0].Name != "keep.example.com" {
		t.Fatalf("orphan not pruned correctly: %+v", got.Webhooks)
	}
}

func TestWebhookGuardAbortsWithoutNamespaceSnapshot(t *testing.T) {
	cs := fake.NewSimpleClientset() // no kube-system -> API flap guard
	g := &webhookGuard{cs: cs}
	if err := g.run(ctx); err == nil {
		t.Fatal("expected abort when kube-system is missing from the list")
	}
}
