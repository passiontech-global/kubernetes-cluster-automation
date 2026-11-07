// check_modules_test.go — the CheckReg merge contract: collected
// check registrations join the prober roster via Deps.CheckRegs,
// dedupe by name, and a wrong-typed New fails prober construction
// loudly (a silent skip would boot a roster missing a check ops
// believes is gated on). The gated-off-collection half is covered at
// registry level (TestSetupModulesCheckRegGate).
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
// collected into Deps.CheckRegs — lands in the prober's roster after
// the static checkDefs.
func TestCheckRegJoinsRoster(t *testing.T) {
	p, err := newClusterHealthProber("cluster-health-probes",
		fake.NewSimpleClientset(), testutil.NewDynamicClient(), nil,
		probefw.Config{}, []shared.CheckReg{{
			Name: gitops.CheckNameFluxKustomizationHealth,
			New:  gitops.NewFluxKustomizationHealthCheck,
		}})
	if err != nil {
		t.Fatalf("newClusterHealthProber: %v", err)
	}
	if got := countCheck(p, gitops.CheckNameFluxKustomizationHealth); got != 1 {
		t.Fatalf("%q appears %d times in roster, want 1",
			gitops.CheckNameFluxKustomizationHealth, got)
	}
	// CheckReg entries sort after the static roster.
	if p.checks[len(p.checks)-1].name != gitops.CheckNameFluxKustomizationHealth {
		t.Fatalf("CheckReg check not appended after checkDefs: last = %q",
			p.checks[len(p.checks)-1].name)
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

// Roster dedupe: a CheckReg repeating a static checkDefs name — or a
// sibling CheckReg's name — is skipped, the old registerCheck
// idempotence.
func TestCheckRegDedupes(t *testing.T) {
	p, err := newClusterHealthProber("cluster-health-probes",
		fake.NewSimpleClientset(), testutil.NewDynamicClient(), nil,
		probefw.Config{}, []shared.CheckReg{
			{Name: gitops.CheckNameImagePullSecretAuditor,
				New: gitops.NewImagePullSecretAuditorCheck},
			{Name: gitops.CheckNameImagePullSecretAuditor,
				New: gitops.NewImagePullSecretAuditorCheck},
			// A name already in the static roster is skipped too —
			// even with a valid constructor.
			{Name: ported.CheckNameDNS,
				New: gitops.NewImagePullSecretAuditorCheck},
		})
	if err != nil {
		t.Fatalf("newClusterHealthProber: %v", err)
	}
	if got := countCheck(p, gitops.CheckNameImagePullSecretAuditor); got != 1 {
		t.Fatalf("%q appears %d times, want 1 (dedupe)",
			gitops.CheckNameImagePullSecretAuditor, got)
	}
	if got := countCheck(p, ported.CheckNameDNS); got != 1 {
		t.Fatalf("%q appears %d times, want 1 (static only)",
			ported.CheckNameDNS, got)
	}
}
