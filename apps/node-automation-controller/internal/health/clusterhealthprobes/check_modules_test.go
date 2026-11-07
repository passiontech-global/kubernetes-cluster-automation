// check_modules_test.go — the per-check module adapters: registerCheck
// dedupe, SetupNoConfig's Disabled gate, and the roster pickup.
package clusterhealthprobes

import (
	"testing"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/gitops"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// saveCheckDefs snapshots and restores the roster around a test —
// registerCheck mutates the package-level var and other tests in the
// package build probers from it.
func saveCheckDefs(t *testing.T) {
	t.Helper()
	orig := checkDefs
	t.Cleanup(func() { checkDefs = orig })
}

func checkNames(defs []checkDef) map[string]bool {
	out := map[string]bool{}
	for _, d := range defs {
		out[d.name] = true
	}
	return out
}

// An enabled module Setup appends its check to the sweep roster;
// a Disabled one registers nothing.
func TestCheckModuleSetupGate(t *testing.T) {
	saveCheckDefs(t)
	base := len(checkDefs)

	if err := SetupFluxKustomizationHealth(shared.Deps{
		Name: "flux-kustomization-health"}); err != nil {
		t.Fatalf("enabled setup: %v", err)
	}
	if len(checkDefs) != base+1 {
		t.Fatalf("roster grew %d, want 1", len(checkDefs)-base)
	}
	if !checkNames(checkDefs)[gitops.CheckNameFluxKustomizationHealth] {
		t.Fatal("flux-kustomization-health not in roster")
	}

	// Disabled — registration skipped.
	if err := SetupWorkloadScaleFlapping(shared.Deps{
		Name: "workload-scale-flapping", Disabled: true}); err != nil {
		t.Fatalf("disabled setup: %v", err)
	}
	if checkNames(checkDefs)[gitops.CheckNameWorkloadScaleFlapping] {
		t.Fatal("disabled module must not register its check")
	}
}

// Registering the same check twice is idempotent — SetupModules may
// run more than once in a test binary.
func TestRegisterCheckDedupes(t *testing.T) {
	saveCheckDefs(t)
	registerCheck("dedupe-probe", func(d *probefw.Deps) probefw.Check {
		return nil
	})
	before := len(checkDefs)
	registerCheck("dedupe-probe", func(d *probefw.Deps) probefw.Check {
		return nil
	})
	if len(checkDefs) != before {
		t.Fatal("registerCheck must dedupe by name")
	}
}

// A registered check is picked up by the prober construction — the
// end-to-end contract the registry rows rely on.
func TestRegisteredCheckJoinsProber(t *testing.T) {
	saveCheckDefs(t)
	m := testutil.NewStubManager()
	if err := SetupImagePullSecretAuditor(shared.Deps{
		Name: "imagepull-secret-auditor", Mgr: m}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	p := newClusterHealthProber("cluster-health-probes",
		fake.NewSimpleClientset(), testutil.NewDynamicClient(), nil, probefw.Config{})
	found := false
	for _, c := range p.checks {
		if c.name == gitops.CheckNameImagePullSecretAuditor {
			found = true
		}
	}
	if !found {
		t.Fatal("registered check missing from prober roster")
	}
}
