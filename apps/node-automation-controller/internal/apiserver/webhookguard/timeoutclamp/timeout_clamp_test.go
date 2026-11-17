package timeoutclamp

import (
	"context"
	"testing"
	"time"

	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func i32(v int32) *int32 { return &v }

func TestTimeoutClampMWCVWCAndCRDAudit(t *testing.T) {
	metrics.WebhookExcessiveTimeout.Reset()

	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "clamp-mwc"},
		Webhooks: []admissionv1.MutatingWebhook{
			{
				Name:           "pods.example.com",
				FailurePolicy:  new(admissionv1.Fail),
				TimeoutSeconds: i32(30),
				Rules: []admissionv1.RuleWithOperations{{
					Rule: admissionv1.Rule{Resources: []string{"pods"}},
				}},
			},
			{
				Name:           "widgets.example.com",
				FailurePolicy:  new(admissionv1.Fail),
				TimeoutSeconds: i32(30),
				Rules: []admissionv1.RuleWithOperations{{
					Rule: admissionv1.Rule{Resources: []string{"widgets"}},
				}},
			},
			{
				Name:           "ignore.example.com",
				FailurePolicy:  new(admissionv1.Ignore),
				TimeoutSeconds: i32(30),
				Rules: []admissionv1.RuleWithOperations{{
					Rule: admissionv1.Rule{Resources: []string{"nodes"}},
				}},
			},
		},
	}
	vwc := &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "optout-vwc",
			Annotations: map[string]string{kube.AnnoWebhookNeverFailOpen: "true"},
		},
		Webhooks: []admissionv1.ValidatingWebhook{{
			Name:           "leases.example.com",
			FailurePolicy:  new(admissionv1.Fail),
			TimeoutSeconds: i32(25),
			Rules: []admissionv1.RuleWithOperations{{
				Rule: admissionv1.Rule{Resources: []string{"leases"}},
			}},
		}},
	}
	crd := testutil.Unstructured(
		kube.GVRCustomResourceDefinition.GroupVersion().WithKind("CustomResourceDefinition"),
		"", "slowcrds.example.com", nil)
	_ = unstructured.SetNestedField(crd.Object, "Webhook", "spec", "conversion", "strategy")
	_ = unstructured.SetNestedField(crd.Object, int64(25), "spec", "conversion", "webhook", "timeoutSeconds")

	cs := fake.NewSimpleClientset(mwc, vwc)
	dyn := testutil.NewDynWithCRDs(crd)
	g := &guardstate.Guard{
		CS:                       cs,
		Dyn:                      dyn,
		Now:                      func() time.Time { return time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC) },
		TimeoutClampEnabled:      true,
		MaxWebhookTimeoutSeconds: 10,
	}
	var s Sweeper
	snap := g.TakeSnapshot(context.Background())
	if err := s.Sweep(context.Background(), snap); err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	gotMWC, _ := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(context.Background(), "clamp-mwc", metav1.GetOptions{})
	if got := *gotMWC.Webhooks[0].TimeoutSeconds; got != 5 {
		t.Fatalf("pods.example.com timeoutSeconds = %d, want 5", got)
	}
	if got := *gotMWC.Webhooks[1].TimeoutSeconds; got != 30 {
		t.Fatalf("non-core widgets.example.com timeoutSeconds = %d, want 30", got)
	}
	if got := *gotMWC.Webhooks[2].TimeoutSeconds; got != 30 {
		t.Fatalf("Ignore webhook timeoutSeconds = %d, want 30", got)
	}

	gotVWC, _ := cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(context.Background(), "optout-vwc", metav1.GetOptions{})
	if got := *gotVWC.Webhooks[0].TimeoutSeconds; got != 25 {
		t.Fatalf("opt-out VWC timeoutSeconds should remain 25, got %d", got)
	}

	if v := ptestutil.ToFloat64(metrics.WebhookExcessiveTimeout.WithLabelValues("mutating", "clamp-mwc", "pods.example.com")); v != 1 {
		t.Fatalf("expected MWC excessive timeout gauge=1, got %v", v)
	}
	if v := ptestutil.ToFloat64(metrics.WebhookExcessiveTimeout.WithLabelValues("validating", "optout-vwc", "leases.example.com")); v != 1 {
		t.Fatalf("expected opt-out VWC excessive timeout gauge=1, got %v", v)
	}
	if v := ptestutil.ToFloat64(metrics.WebhookExcessiveTimeout.WithLabelValues("crd", "slowcrds.example.com", "slowcrds.example.com")); v != 1 {
		t.Fatalf("expected CRD excessive timeout gauge=1, got %v", v)
	}

	// Next sweep sees clamped MWC (timeoutSeconds=5) -> MWC gauge prunes to 0.
	snap2 := g.TakeSnapshot(context.Background())
	if err := s.Sweep(context.Background(), snap2); err != nil {
		t.Fatalf("Sweep 2: %v", err)
	}
	if v := ptestutil.ToFloat64(metrics.WebhookExcessiveTimeout.WithLabelValues("mutating", "clamp-mwc", "pods.example.com")); v != 0 {
		t.Fatalf("expected MWC excessive timeout gauge pruned to 0 after clamp, got %v", v)
	}
}
