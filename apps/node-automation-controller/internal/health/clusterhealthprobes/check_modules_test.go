// check_modules_test.go — the CheckReg merge contract: collected
// check registrations BECOME the prober roster via Deps.CheckRegs
// (in collection order), dedupe by name. (The old wrong-typed-New
// half moved to compile time — CheckReg.New is the typed
// constructor field.) The gated-off-collection half is covered at
// registry level (TestSetupModulesCheckRegGate).
package clusterhealthprobes

import (
	"testing"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/gitops"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/ported"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
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
// reg registers the sweep runnable. (The old mistyped-New half of
// this contract is now compile-time — CheckReg.New is the typed
// constructor field, so a wrong shape cannot be built.)
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
