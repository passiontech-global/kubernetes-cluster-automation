package watchdogs

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	flowcontrolv1 "k8s.io/api/flowcontrol/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
)

// apfShieldCheck builds the check against a Deps wired to cs with an
// explicit config — tests never rely on ambient env.
func apfShieldCheck(t *testing.T, cs *fake.Clientset,
	cfg apfShieldConfig) *apfSelfHealShieldCheck {

	t.Helper()
	d := probetest.NewDeps(cs, nil)
	return &apfSelfHealShieldCheck{Deps: d, cfg: cfg}
}

var apfTestCfg = apfShieldConfig{
	enforce:   true,
	namespace: "node-ops",
	extraSAs: []apfShieldSA{
		{namespace: "monitoring", name: "prometheus"},
	},
}

// An empty cluster gets both shield objects created; the sweep that
// had to create them still reports degraded (the objects were
// missing at read time) and the NEXT run converges clean.
func TestAPFSelfHealShieldCreatesMissing(t *testing.T) {
	cs := fake.NewSimpleClientset()
	p := apfShieldCheck(t, cs, apfTestCfg)
	res := p.Run(probetest.SweepCtx(ctx, p.Deps))
	if res.Pass {
		t.Fatalf("missing shield objects must fail this sweep: %+v", res)
	}
	plc, err := cs.FlowcontrolV1().PriorityLevelConfigurations().
		Get(ctx, apfShieldPLCName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("PLC not created: %v", err)
	}
	if plc.Spec.Type != flowcontrolv1.PriorityLevelEnablementLimited ||
		plc.Spec.Limited == nil ||
		*plc.Spec.Limited.NominalConcurrencyShares != 40 ||
		*plc.Spec.Limited.LendablePercent != 50 {
		t.Fatalf("PLC spec not converged: %+v", plc.Spec)
	}
	fs, err := cs.FlowcontrolV1().FlowSchemas().
		Get(ctx, apfShieldFlowSchemaName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("FlowSchema not created: %v", err)
	}
	if apfShieldMatchingPrecedence != 550 {
		t.Fatalf("apfShieldMatchingPrecedence = %d, want 550 (node-ops-apf.yaml, not cilium-apf's 500)",
			apfShieldMatchingPrecedence)
	}
	if fs.Spec.MatchingPrecedence != apfShieldMatchingPrecedence {
		t.Fatalf("FlowSchema matchingPrecedence = %d, want %d",
			fs.Spec.MatchingPrecedence, apfShieldMatchingPrecedence)
	}
	// Subjects: controller@node-ops, node-host-agent@kube-system,
	// coredns@kube-system, plus the extra SA.
	got := map[string]bool{}
	for _, s := range fs.Spec.Rules[0].Subjects {
		if s.Kind != flowcontrolv1.SubjectKindServiceAccount ||
			s.ServiceAccount == nil {
			t.Fatalf("non-ServiceAccount subject: %+v", s)
		}
		got[s.ServiceAccount.Namespace+"/"+s.ServiceAccount.Name] = true
	}
	for _, want := range []string{
		"node-ops/node-ops-operator",
		"node-ops/node-automation-controller",
		"node-ops/node-host-agent",
		"kube-system/node-host-agent",
		"kube-system/coredns",
		"monitoring/prometheus",
	} {
		if !got[want] {
			t.Fatalf("subject %s missing from %+v", want, got)
		}
	}
	if len(got) != 6 {
		t.Fatalf("unexpected subject count: %+v", got)
	}
	// Second run: converged — clean pass, zero writes.
	var writes int
	cs.PrependReactor("update", "*", func(ktesting.Action) (bool, runtime.Object, error) {
		writes++
		return false, nil, nil
	})
	cs.PrependReactor("create", "*", func(ktesting.Action) (bool, runtime.Object, error) {
		writes++
		return false, nil, nil
	})
	res = p.Run(probetest.SweepCtx(ctx, p.Deps))
	if !res.Pass {
		t.Fatalf("converged shield must pass: %+v", res)
	}
	if writes != 0 {
		t.Fatalf("converged shield issued %d writes", writes)
	}
	if got := testutil.ToFloat64(apfShieldDegraded); got != 0 {
		t.Fatalf("degraded gauge = %v after converge, want 0", got)
	}
}

// A drifted FlowSchema (wrong precedence + missing subjects) and a
// drifted PLC (wrong shares) get repaired in place during the same
// sweep — the sweep still reports degraded because the objects WERE
// divergent at read time.
func TestAPFSelfHealShieldRepairsDrift(t *testing.T) {
	badPLC := &flowcontrolv1.PriorityLevelConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: apfShieldPLCName},
		Spec: flowcontrolv1.PriorityLevelConfigurationSpec{
			Type: flowcontrolv1.PriorityLevelEnablementLimited,
			Limited: &flowcontrolv1.LimitedPriorityLevelConfiguration{
				NominalConcurrencyShares: ptr.To(int32(10)),
				LimitResponse: flowcontrolv1.LimitResponse{
					Type: flowcontrolv1.LimitResponseTypeReject,
				},
			},
		},
	}
	badFS := &flowcontrolv1.FlowSchema{
		ObjectMeta: metav1.ObjectMeta{Name: apfShieldFlowSchemaName},
		Spec: flowcontrolv1.FlowSchemaSpec{
			MatchingPrecedence: 9000,
			PriorityLevelConfiguration: flowcontrolv1.PriorityLevelConfigurationReference{
				Name: "workload-low",
			},
		},
	}
	cs := fake.NewSimpleClientset(badPLC, badFS)
	p := apfShieldCheck(t, cs, apfTestCfg)
	res := p.Run(probetest.SweepCtx(ctx, p.Deps))
	if res.Pass {
		t.Fatal("drifted shield must fail — objects were divergent at read")
	}
	// The repair already landed during the same Run — verify objects.
	plc, _ := cs.FlowcontrolV1().PriorityLevelConfigurations().
		Get(ctx, apfShieldPLCName, metav1.GetOptions{})
	if *plc.Spec.Limited.NominalConcurrencyShares != 40 ||
		*plc.Spec.Limited.LendablePercent != 50 ||
		plc.Spec.Limited.LimitResponse.Type != flowcontrolv1.LimitResponseTypeQueue {
		t.Fatalf("PLC not repaired: %+v", plc.Spec)
	}
	fs, _ := cs.FlowcontrolV1().FlowSchemas().
		Get(ctx, apfShieldFlowSchemaName, metav1.GetOptions{})
	if fs.Spec.MatchingPrecedence != 550 ||
		fs.Spec.PriorityLevelConfiguration.Name != apfShieldPLCName ||
		len(fs.Spec.Rules) != 1 || len(fs.Spec.Rules[0].Subjects) != 6 {
		t.Fatalf("FlowSchema not repaired: %+v", fs.Spec)
	}
}

// enforce=false is report-only: drift stays, gauge fails, zero writes.
func TestAPFSelfHealShieldReportOnly(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cfg := apfTestCfg
	cfg.enforce = false
	p := apfShieldCheck(t, cs, cfg)
	res := p.Run(probetest.SweepCtx(ctx, p.Deps))
	if res.Pass {
		t.Fatal("missing shield must fail even in report-only mode")
	}
	if _, err := cs.FlowcontrolV1().PriorityLevelConfigurations().
		Get(ctx, apfShieldPLCName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatal("report-only mode created the PLC")
	}
	if _, err := cs.FlowcontrolV1().FlowSchemas().
		Get(ctx, apfShieldFlowSchemaName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatal("report-only mode created the FlowSchema")
	}
}

// A 403 on create is a WARN only: the optional shield is simply not
// granted, so the sweep PASSES with degraded=0 — no panic, no Infra,
// and above all no permanent false alarm.
func TestAPFSelfHealShieldForbiddenDegrades(t *testing.T) {
	cs := fake.NewSimpleClientset()
	forbidden := apierrors.NewForbidden(
		schema.GroupResource{Group: "flowcontrol.apiserver.k8s.io", Resource: "prioritylevelconfigurations"},
		apfShieldPLCName, nil)
	cs.PrependReactor("create", "prioritylevelconfigurations",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, forbidden
		})
	cs.PrependReactor("create", "flowschemas",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewForbidden(
				schema.GroupResource{Group: "flowcontrol.apiserver.k8s.io", Resource: "flowschemas"},
				apfShieldFlowSchemaName, nil)
		})
	p := apfShieldCheck(t, cs, apfTestCfg)
	res := p.Run(probetest.SweepCtx(ctx, p.Deps))
	if !res.Pass {
		t.Fatalf("forbidden writes must PASS gracefully (degraded=0): %+v", res)
	}
	if res.Infra != nil {
		t.Fatalf("403 must not surface as Infra: %v", res.Infra)
	}
	if got := testutil.ToFloat64(apfShieldDegraded); got != 0 {
		t.Fatalf("degraded gauge = %v, want 0 — RBAC 403 must not page", got)
	}
}

// A Flux-owned drifted object trips FluxPatchGate — the update is
// skipped and the check reports the loop instead of fighting Git.
func TestAPFSelfHealShieldFluxGate(t *testing.T) {
	heal.ConfigureFluxConflictLoop(3, 30*time.Minute)
	defer heal.ConfigureFluxConflictLoop(0, 0)

	fluxFS := &flowcontrolv1.FlowSchema{
		ObjectMeta: metav1.ObjectMeta{
			Name: apfShieldFlowSchemaName,
			ManagedFields: []metav1.ManagedFieldsEntry{{
				Manager:    "helm-controller",
				Operation:  metav1.ManagedFieldsOperationApply,
				APIVersion: "flowcontrol.apiserver.k8s.io/v1",
				FieldsType: "FieldsV1",
			}},
		},
		Spec: flowcontrolv1.FlowSchemaSpec{MatchingPrecedence: 9000},
	}
	cs := fake.NewSimpleClientset(apfTestCfg.plcDesired(), fluxFS)

	// Two allowed sightings — the check's update would be #3.
	now := time.Now()
	for i := 0; i < 2; i++ {
		if !heal.FluxPatchGate("flowschema", fluxFS,
			"flowschema/"+apfShieldFlowSchemaName, now) {
			t.Fatalf("sighting %d unexpectedly denied", i+1)
		}
	}
	p := apfShieldCheck(t, cs, apfTestCfg)
	res := p.Run(probetest.SweepCtx(ctx, p.Deps))
	if res.Pass {
		t.Fatal("flux-gated drift must fail")
	}
	fs, _ := cs.FlowcontrolV1().FlowSchemas().
		Get(ctx, apfShieldFlowSchemaName, metav1.GetOptions{})
	if fs.Spec.MatchingPrecedence != 9000 {
		t.Fatal("flux-gated update was not skipped")
	}
}

// apfShieldConfigFromEnv resolves the knobs: enforce defaults on,
// namespace defaults node-ops, EXTRA_SAS parses ns/name pairs and
// skips malformed entries.
func TestAPFSelfHealShieldConfigFromEnv(t *testing.T) {
	t.Setenv("NODE_AUTOMATION_APF_SHIELD_ENFORCE", "false")
	t.Setenv("NODE_AUTOMATION_APF_SHIELD_NAMESPACE", "ops")
	t.Setenv("NODE_AUTOMATION_APF_SHIELD_EXTRA_SAS",
		"monitoring/prometheus, badentry , kube-system/cilium")
	cfg := apfShieldConfigFromEnv()
	if cfg.enforce {
		t.Fatal("enforce should be false")
	}
	if cfg.namespace != "ops" {
		t.Fatalf("namespace = %q", cfg.namespace)
	}
	if len(cfg.extraSAs) != 2 ||
		cfg.extraSAs[0] != (apfShieldSA{"monitoring", "prometheus"}) ||
		cfg.extraSAs[1] != (apfShieldSA{"kube-system", "cilium"}) {
		t.Fatalf("extraSAs = %+v", cfg.extraSAs)
	}
}
