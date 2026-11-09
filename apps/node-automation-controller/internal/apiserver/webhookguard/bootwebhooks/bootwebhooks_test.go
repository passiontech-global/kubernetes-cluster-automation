// bootwebhooks_test.go — the boot fail-open sweep is pure policy over
// a snapshot: these tests pin the scope guards (only medik8s
// config/template entries flip), the one-way semantics (Ignore stays
// untouched, no patch emitted), the patch-after-land metric discipline
// (a failed patch retries without counting), and the hot-reload gate.
package bootwebhooks

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
)

const (
	service = "self-node-remediation-controller-manager-service"
	ns      = "operators"
)

// vwc builds a validating webhook config with the medik8s family:
// the boot-path entries of all three groups (self-node-remediation,
// fence-agents-remediation, node-healthcheck), the
// self-node-remediation CR entry (must stay Fail), a mixed-scope
// entry, an already-open entry, and — for contrast — a genuinely
// foreign webhook that must never be touched by this duty.
func vwc() *admissionv1.ValidatingWebhookConfiguration {
	fpf := func(p admissionv1.FailurePolicyType) *admissionv1.FailurePolicyType { return &p }
	return &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "vselfnoderemediation.kb.io-4qh96"},
		Webhooks: []admissionv1.ValidatingWebhook{
			{
				Name:          "vselfnoderemediationconfig.kb.io",
				ClientConfig:  admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Namespace: ns, Name: service}},
				FailurePolicy: fpf(admissionv1.Fail),
				Rules: []admissionv1.RuleWithOperations{{
					Operations: []admissionv1.OperationType{admissionv1.Create, admissionv1.Update},
					Rule: admissionv1.Rule{APIGroups: []string{"self-node-remediation.medik8s.io"},
						APIVersions: []string{"v1alpha1"}, Resources: []string{"selfnoderemediationconfigs"}},
				}},
			},
			{
				Name:          "vselfnoderemediationtemplate.kb.io",
				ClientConfig:  admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Namespace: ns, Name: service}},
				FailurePolicy: fpf(admissionv1.Fail),
				Rules: []admissionv1.RuleWithOperations{{
					Operations: []admissionv1.OperationType{admissionv1.Create, admissionv1.Update},
					Rule: admissionv1.Rule{APIGroups: []string{"self-node-remediation.medik8s.io"},
						APIVersions: []string{"v1alpha1"}, Resources: []string{"selfnoderemediationtemplates"}},
				}},
			},
			{
				// The remediation-CR entry — upstream Ignore, and even a
				// Fail twin must stay Fail: flipping it would open
				// validation on the remediation CR itself.
				Name:          "vselfnoderemediation.kb.io",
				ClientConfig:  admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Namespace: ns, Name: service}},
				FailurePolicy: fpf(admissionv1.Fail),
				Rules: []admissionv1.RuleWithOperations{{
					Operations: []admissionv1.OperationType{admissionv1.Create, admissionv1.Update},
					Rule: admissionv1.Rule{APIGroups: []string{"self-node-remediation.medik8s.io"},
						APIVersions: []string{"v1alpha1"}, Resources: []string{"selfnoderemediations"}},
				}},
			},
			{
				// A mixed-scope entry: medik8s group but covering BOTH the
				// boot CRs and the remediation CR in one rule — strictly
				// out of scope, the flip would open remediation-CR
				// validation too.
				Name:          "vmixed.kb.io",
				ClientConfig:  admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Namespace: ns, Name: service}},
				FailurePolicy: fpf(admissionv1.Fail),
				Rules: []admissionv1.RuleWithOperations{{
					Operations: []admissionv1.OperationType{admissionv1.Create},
					Rule: admissionv1.Rule{APIGroups: []string{"self-node-remediation.medik8s.io"},
						APIVersions: []string{"v1alpha1"},
						Resources:   []string{"selfnoderemediationconfigs", "selfnoderemediations"}},
				}},
			},
			{
				// An already-open boot entry — no write, no metric.
				Name:          "vselfnoderemediationconfig.kb.io-open",
				ClientConfig:  admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Namespace: ns, Name: service}},
				FailurePolicy: fpf(admissionv1.Ignore),
				Rules: []admissionv1.RuleWithOperations{{
					Operations: []admissionv1.OperationType{admissionv1.Create},
					Rule: admissionv1.Rule{APIGroups: []string{"self-node-remediation.medik8s.io"},
						APIVersions: []string{"v1alpha1"}, Resources: []string{"selfnoderemediationconfigs"}},
				}},
			},
			{
				// The fence-agents-remediation boot pair (W20) — FAR's
				// own webhook-fatal boot path, flips like the
				// self-node-remediation config/template entries.
				Name:          "vfenceagentsremediation.kb.io",
				ClientConfig:  admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Namespace: ns, Name: service}},
				FailurePolicy: fpf(admissionv1.Fail),
				Rules: []admissionv1.RuleWithOperations{{
					Operations: []admissionv1.OperationType{admissionv1.Create, admissionv1.Update},
					Rule: admissionv1.Rule{APIGroups: []string{"fence-agents-remediation.medik8s.io"},
						APIVersions: []string{"v1alpha1"}, Resources: []string{"fenceagentsremediations"}},
				}},
			},
			{
				Name:          "vfenceagentsremediationtemplate.kb.io",
				ClientConfig:  admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Namespace: ns, Name: service}},
				FailurePolicy: fpf(admissionv1.Fail),
				Rules: []admissionv1.RuleWithOperations{{
					Operations: []admissionv1.OperationType{admissionv1.Create, admissionv1.Update},
					Rule: admissionv1.Rule{APIGroups: []string{"fence-agents-remediation.medik8s.io"},
						APIVersions: []string{"v1alpha1"}, Resources: []string{"fenceagentsremediationtemplates"}},
				}},
			},
			{
				// The node-healthcheck boot entry (W20) — the NHC
				// operator's webhook-validated CR, flips too.
				Name:          "vnodehealthcheck.kb.io",
				ClientConfig:  admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Namespace: ns, Name: service}},
				FailurePolicy: fpf(admissionv1.Fail),
				Rules: []admissionv1.RuleWithOperations{{
					Operations: []admissionv1.OperationType{admissionv1.Create, admissionv1.Update},
					Rule: admissionv1.Rule{APIGroups: []string{"remediation.medik8s.io"},
						APIVersions: []string{"v1alpha1"}, Resources: []string{"nodehealthchecks"}},
				}},
			},
			{
				// Non-medik8s group — foreign, untouched.
				Name:          "vforeign.kb.io",
				ClientConfig:  admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Namespace: ns, Name: service}},
				FailurePolicy: fpf(admissionv1.Fail),
				Rules: []admissionv1.RuleWithOperations{{
					Operations: []admissionv1.OperationType{admissionv1.Create},
					Rule: admissionv1.Rule{APIGroups: []string{"cert-manager.io"},
						APIVersions: []string{"v1"}, Resources: []string{"certificates"}},
				}},
			},
		},
	}
}

func TestSweepFlipsOnlyBootEntries(t *testing.T) {
	cfg := vwc()
	cs := k8sfake.NewClientset(cfg)
	snap := &guardstate.Snapshot{G: &guardstate.Guard{CS: cs}}
	var err error
	snap.VWC, err = cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("seed list: %v", err)
	}

	if err := Sweep(context.Background(), snap); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	got, err := cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(
		context.Background(), cfg.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get after sweep: %v", err)
	}
	policies := map[string]admissionv1.FailurePolicyType{}
	for _, w := range got.Webhooks {
		policies[w.Name] = *w.FailurePolicy
	}
	want := map[string]admissionv1.FailurePolicyType{
		"vselfnoderemediationconfig.kb.io":      admissionv1.Ignore,
		"vselfnoderemediationtemplate.kb.io":    admissionv1.Ignore,
		"vfenceagentsremediation.kb.io":         admissionv1.Ignore,
		"vfenceagentsremediationtemplate.kb.io": admissionv1.Ignore,
		"vnodehealthcheck.kb.io":                admissionv1.Ignore,
		"vselfnoderemediation.kb.io":            admissionv1.Fail,
		"vmixed.kb.io":                          admissionv1.Fail,
		"vselfnoderemediationconfig.kb.io-open": admissionv1.Ignore,
		"vforeign.kb.io":                        admissionv1.Fail,
	}
	for name, wantPol := range want {
		if policies[name] != wantPol {
			t.Errorf("webhook %s: policy = %v, want %v", name, policies[name], wantPol)
		}
	}

	// Exactly one patch, carrying exactly the two boot entries — the
	// strategic-merge payload is the observable contract OLM drift
	// heals against.
	patches := 0
	for _, a := range cs.Actions() {
		pa, ok := a.(clienttesting.PatchAction)
		if !ok {
			continue
		}
		patches++
		if pa.GetName() != cfg.Name {
			t.Errorf("patch hit %q, want %q", pa.GetName(), cfg.Name)
		}
		if pa.GetPatchType() != types.StrategicMergePatchType {
			t.Errorf("patch type = %v, want strategic-merge", pa.GetPatchType())
		}
		var p vwcPatch
		if err := json.Unmarshal(pa.GetPatch(), &p); err != nil {
			t.Fatalf("patch payload: %v", err)
		}
		if len(p.Webhooks) != 5 {
			t.Fatalf("patch flips %d entries, want 5: %+v", len(p.Webhooks), p.Webhooks)
		}
		names := map[string]bool{}
		for _, e := range p.Webhooks {
			names[e.Name] = true
			if e.FailurePolicy == nil || *e.FailurePolicy != admissionv1.Ignore {
				t.Errorf("patch entry %s: policy %+v, want Ignore", e.Name, e.FailurePolicy)
			}
		}
		for _, want := range []string{
			"vselfnoderemediationconfig.kb.io", "vselfnoderemediationtemplate.kb.io",
			"vfenceagentsremediation.kb.io", "vfenceagentsremediationtemplate.kb.io",
			"vnodehealthcheck.kb.io",
		} {
			if !names[want] {
				t.Errorf("patch missing boot entry %s", want)
			}
		}
	}
	if patches != 1 {
		t.Errorf("patch actions = %d, want 1", patches)
	}
	for _, w := range []string{
		"vselfnoderemediationconfig.kb.io", "vselfnoderemediationtemplate.kb.io",
		"vfenceagentsremediation.kb.io", "vfenceagentsremediationtemplate.kb.io",
		"vnodehealthcheck.kb.io",
	} {
		if got := testutil.ToFloat64(metrics.BootWebhookFailOpenTotal.WithLabelValues(cfg.Name, w)); got != 1 {
			t.Errorf("failopen counter %s = %v, want 1 (metric only after patch landed)", w, got)
		}
	}
	if got := testutil.ToFloat64(metrics.BootWebhookFailOpenTotal.WithLabelValues(cfg.Name, "vselfnoderemediation.kb.io")); got != 0 {
		t.Errorf("remediation-CR entry counted %v, want 0", got)
	}
}

func TestSweepIdempotent(t *testing.T) {
	cs := k8sfake.NewClientset(vwc())
	list := func() *guardstate.Snapshot {
		snap := &guardstate.Snapshot{G: &guardstate.Guard{CS: cs}}
		// Production takes a FRESH snapshot every sweep — the stale
		// list here would re-report the pre-sweep Fail policies.
		snap.VWC, _ = cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(context.Background(), metav1.ListOptions{})
		return snap
	}
	if err := Sweep(context.Background(), list()); err != nil {
		t.Fatalf("first sweep: %v", err)
	}
	cs.ClearActions()
	if err := Sweep(context.Background(), list()); err != nil {
		t.Fatalf("second sweep: %v", err)
	}
	for _, a := range cs.Actions() {
		if _, ok := a.(clienttesting.PatchAction); ok {
			t.Fatalf("second sweep patched %+v — enforcement must be no-op once Ignore", a)
		}
	}
}

func TestSweepListErrorFailsLoud(t *testing.T) {
	snap := &guardstate.Snapshot{
		G:      &guardstate.Guard{CS: k8sfake.NewClientset()},
		VWCErr: context.DeadlineExceeded,
	}
	if err := Sweep(context.Background(), snap); err == nil {
		t.Fatal("snapshot list error must surface, not silently skip the run")
	}
}

func TestGateOffRegistersNothing(t *testing.T) {
	t.Setenv(FailOpenGate, "false")
	cfg := vwc()
	cs := k8sfake.NewClientset(cfg)
	snap := &guardstate.Snapshot{G: &guardstate.Guard{CS: cs}}
	snap.VWC, _ = cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(context.Background(), metav1.ListOptions{})

	if Enabled() {
		t.Fatalf("gate: Enabled() = true with %s=false", FailOpenGate)
	}
	if err := Sweep(context.Background(), snap); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	for _, a := range cs.Actions() {
		if _, ok := a.(clienttesting.PatchAction); ok {
			t.Fatalf("gate-off sweep patched %+v", a)
		}
	}
}

func TestGateOnByDefault(t *testing.T) {
	t.Setenv(FailOpenGate, "")
	if !Enabled() {
		t.Fatalf("gate: Enabled() = false with unset %s — must default on", FailOpenGate)
	}
}

func TestPatchFailureDoesNotCount(t *testing.T) {
	// The sweep lists the config, then the patch fails with a real
	// apiserver error. The counter must stay at zero so the retry next
	// sweep counts exactly once (circuit-metrics discipline). NotFound
	// is deliberately NOT this test: a config deleted between list and
	// patch is a benign skip, not an error.
	cfg := vwc()
	// The counter vec is package-level and shared across tests in this
	// process — clear the tuples this test asserts so earlier sweeps'
	// increments (the flips + idempotence tests) cannot leak in.
	for _, w := range []string{"vselfnoderemediationconfig.kb.io", "vselfnoderemediationtemplate.kb.io"} {
		metrics.BootWebhookFailOpenTotal.DeleteLabelValues(cfg.Name, w)
	}
	cs := k8sfake.NewClientset()
	cs.PrependReactor("patch", "validatingwebhookconfigurations",
		func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, context.DeadlineExceeded
		})
	snap := &guardstate.Snapshot{G: &guardstate.Guard{CS: cs}}
	snap.VWC = &admissionv1.ValidatingWebhookConfigurationList{Items: []admissionv1.ValidatingWebhookConfiguration{*cfg}}

	err := Sweep(context.Background(), snap)
	if err == nil {
		t.Fatal("patch failure must surface as a sweep error")
	}
	if got := testutil.ToFloat64(metrics.BootWebhookFailOpenTotal.WithLabelValues(cfg.Name, "vselfnoderemediationconfig.kb.io")); got != 0 {
		t.Errorf("failopen counter = %v after failed patch, want 0", got)
	}
}
