// check_modules.go — the per-check module adapters (W13): each new
// gitops sweep check gets its own internal/registry row so it carries
// a real GateEnv (NODE_AUTOMATION_*_ENABLED) and a -modules
// selectable name like every other module. The row's Setup does not
// register a runnable — the check is not a standalone module, it is a
// component of this sweep: Setup appends the check's {name, ctor}
// pair to checkDefs, and the prober built during the
// cluster-health-probes Setup picks it up like every sibling — same
// kuberhealthy_check reporting, same sweep-order roster.
//
// Semantics that fall out of the shape:
//
//   - GateEnv off (or -modules excludes the check row) → Setup runs
//     with Deps.Disabled / never runs → registerCheck is skipped →
//     the check never joins the roster. That is the per-check gate
//     the rows exist for.
//   - The check still requires the cluster-health-probes module
//     itself: a check row selected WITHOUT cluster-health-probes
//     registers into a roster nothing consumes. Documented next to
//     the registry rows and in docs/env.md.
//   - registry-row ordering matters: check modules must precede the
//     cluster-health-probes row in internal/registry.Modules so
//     registration lands before the prober is built.
//
// registerCheck dedupes by name so a repeated Setup (tests driving
// SetupModules more than once in one binary) cannot double-register.
package clusterhealthprobes

import (
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/gitops"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

// registerCheck appends the check to the sweep roster once — the
// name is the dedupe key and the kuberhealthy_check label value.
// Called only from module Setups, which run before the
// cluster-health-probes Setup builds the prober.
func registerCheck(name string, new func(*probefw.Deps) probefw.Check) {
	for _, d := range checkDefs {
		if d.name == name {
			return
		}
	}
	checkDefs = append(checkDefs, checkDef{name: name, new: new})
}

// setupCheck is the shared Setup body for the per-check module rows:
// nothing to parse, so SetupNoConfig carries the Deps.Disabled gate —
// a gated-off check registers nothing (the roster never sees it).
func setupCheck(d shared.Deps, name string,
	new func(*probefw.Deps) probefw.Check) error {
	return shared.SetupNoConfig(d, func() error {
		registerCheck(name, new)
		logf.Log.WithName(d.Name).Info(
			"check registered into cluster-health-probes sweep", "check", name)
		return nil
	})
}

// SetupFluxKustomizationHealth registers the W13-GO1 check into the
// sweep roster — gated by
// NODE_AUTOMATION_FLUX_KUSTOMIZATION_HEALTH_ENABLED on its registry
// row.
func SetupFluxKustomizationHealth(d shared.Deps) error {
	return setupCheck(d, gitops.CheckNameFluxKustomizationHealth,
		gitops.NewFluxKustomizationHealthCheck)
}

// SetupWorkloadScaleFlapping registers the W13-SC1 flapping detector —
// gated by NODE_AUTOMATION_WORKLOAD_SCALE_FLAPPING_ENABLED.
func SetupWorkloadScaleFlapping(d shared.Deps) error {
	return setupCheck(d, gitops.CheckNameWorkloadScaleFlapping,
		gitops.NewWorkloadScaleFlappingCheck)
}

// SetupImagePullSecretAuditor registers the W13-SC1 pull-secret
// auditor — gated by NODE_AUTOMATION_IMAGEPULL_SECRET_AUDITOR_ENABLED.
func SetupImagePullSecretAuditor(d shared.Deps) error {
	return setupCheck(d, gitops.CheckNameImagePullSecretAuditor,
		gitops.NewImagePullSecretAuditorCheck)
}
