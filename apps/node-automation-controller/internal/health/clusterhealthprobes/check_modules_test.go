// check_modules_test.go — the CheckReg merge contract: collected
// check registrations BECOME the prober roster via Deps.CheckRegs
// (in collection order), dedupe by name, and a wrong-typed New
// fails prober construction loudly (a silent skip would boot a
// roster missing a check ops believes is registered). The
// gated-off-collection half is covered at registry level
// (TestSetupModulesCheckRegGate).
package clusterhealthprobes

import (
	"strings"
	"testing"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/gitops"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/ported"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func countCheck(p *clusterHealthProber, name string) int {
	n := 0
	for _, c := range p.checks {
		if c.name == name {
			n++
		}
	}
	return n
}

// An enabled check row's contribution — the CheckReg SetupModules
// collected into Deps.CheckRegs — lands in the prober's roster in
// collection order. There is no static half anymore: the regs ARE
// the whole roster.
func TestCheckRegJoinsRoster(t *testing.T) {
	p, err := newClusterHealthProber(shared.Deps{
		Name: "cluster-health-probes",
		CS:   fake.NewSimpleClientset(), Dyn: testutil.NewDynamicClient(),
		CheckRegs: []shared.CheckReg{
			{Name: gitops.CheckNameFluxKustomizationHealth,
				New: gitops.NewFluxKustomizationHealthCheck},
			{Name: gitops.CheckNameWorkloadScaleFlapping,
				New: gitops.NewWorkloadScaleFlappingCheck},
		},
	}, probefw.Config{})
	if err != nil {
		t.Fatalf("newClusterHealthProber: %v", err)
	}
	if len(p.checks) != 2 {
		t.Fatalf("roster = %d checks, want exactly the 2 collected regs", len(p.checks))
	}
	// Roster order follows collection order — that is the sweep
	// order contract.
	if p.checks[0].name != gitops.CheckNameFluxKustomizationHealth ||
		p.checks[1].name != gitops.CheckNameWorkloadScaleFlapping {
		t.Fatalf("roster order = %q,%q — want collection order",
			p.checks[0].name, p.checks[1].name)
	}
}

// Setup forwards Deps.CheckRegs into prober construction: a valid
// reg registers the sweep runnable, a mistyped New fails Setup with
// an error naming the check instead of booting a roster that
// silently lacks it.
func TestSetupConsumesCheckRegs(t *testing.T) {
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{
		Name: "cluster-health-probes",
		Mgr:  m, CS: fake.NewSimpleClientset(), Dyn: testutil.NewDynamicClient(),
		CheckRegs: []shared.CheckReg{{
			Name: gitops.CheckNameWorkloadScaleFlapping,
			New:  gitops.NewWorkloadScaleFlappingCheck,
		}},
	}); err != nil {
		t.Fatalf("setup with valid CheckReg: %v", err)
	}
	if len(m.Added) != 1 {
		t.Fatalf("registered %d runnables, want 1", len(m.Added))
	}

	bad := testutil.NewStubManager()
	err := Setup(shared.Deps{
		Name: "cluster-health-probes",
		Mgr:  bad, CS: fake.NewSimpleClientset(), Dyn: testutil.NewDynamicClient(),
		CheckRegs: []shared.CheckReg{{
			Name: "not-a-check",
			New:  "not-a-constructor",
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "not-a-check") {
		t.Fatalf("mistyped CheckReg.New must fail Setup naming the check, got %v", err)
	}
	if len(bad.Added) != 0 {
		t.Fatalf("failed prober build registered %d runnables, want 0", len(bad.Added))
	}
}

// Roster dedupe: a CheckReg repeating an earlier reg's name is
// skipped — the old registerCheck idempotence — so a duplicated row
// (or a stray second row naming the same check) can never
// double-register. The name is the identity: the FIRST reg under a
// name wins, even when a repeat carries a different constructor.
func TestCheckRegDedupes(t *testing.T) {
	p, err := newClusterHealthProber(shared.Deps{
		Name: "cluster-health-probes",
		CS:   fake.NewSimpleClientset(), Dyn: testutil.NewDynamicClient(),
		CheckRegs: []shared.CheckReg{
			{Name: ported.CheckNameDNS,
				New: ported.NewDNSStatusCheck},
			{Name: gitops.CheckNameImagePullSecretAuditor,
				New: gitops.NewImagePullSecretAuditorCheck},
			// Repeats — one under an already-taken name with a
			// different constructor, one exact.
			{Name: ported.CheckNameDNS,
				New: gitops.NewImagePullSecretAuditorCheck},
			{Name: gitops.CheckNameImagePullSecretAuditor,
				New: gitops.NewImagePullSecretAuditorCheck},
		},
	}, probefw.Config{})
	if err != nil {
		t.Fatalf("newClusterHealthProber: %v", err)
	}
	if got := countCheck(p, ported.CheckNameDNS); got != 1 {
		t.Fatalf("%q appears %d times, want 1 (first wins)",
			ported.CheckNameDNS, got)
	}
	if got := countCheck(p, gitops.CheckNameImagePullSecretAuditor); got != 1 {
		t.Fatalf("%q appears %d times, want 1 (dedupe)",
			gitops.CheckNameImagePullSecretAuditor, got)
	}
	if len(p.checks) != 2 {
		t.Fatalf("roster = %d checks, want 2 (deduped)", len(p.checks))
	}
}
