// deps.go — the Deps bundle every module's Setup receives: the
// manager, the direct clientset, the dynamic client, the logger and
// the Disabled gate flag.
package shared

import (
	"github.com/go-logr/logr"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// Deps bundles the process-wide dependencies every module's Setup
// receives. Modules take `Setup(d Deps) error` so main.go can wire
// the whole fleet from one registry entry per module — no per-module
// parameter plumbing, and a module that needs nothing beyond the
// standard clients still gets a uniform signature.
//
//   - Name is the module's ops/queue name from its registry row —
//     setupModules stamps it before calling Setup. Modules use it
//     for AddPeriodic and metrics.IncError instead of carrying a
//     private queue-name const, so the registry stays the single
//     source of truth. Empty in literally-constructed test Deps —
//     tests that assert a registered runnable's name should set it.
//   - Mgr is the controller-runtime manager (Add/runables, builder
//     watches, cached client).
//   - CS is the direct (uncached) clientset — RBAC intentionally
//     grants no watch on most types, so module reads go through it.
//   - Dyn is the dynamic client for CRD types (helmreleases,
//     cert-manager, externalsecrets, ...).
//   - Log is the manager logger, for Setup-time registration lines.
//   - Disabled is set by setupModules when the module's registration
//     gate (Module.GateEnv) evaluated off. Setup STILL RUNS so
//     knob-parsing warnings fire even for a disabled module (the
//     corednspatcher/metricsserverpatcher contract), but it must
//     return nil before registering anything. The zero value is
//     enabled — literally-constructed Deps in tests behave as
//     gate-on.
//   - CheckRegs carries the health-sweep check registrations
//     registry.SetupModules collected from the ENABLED CheckReg
//     module rows (the per-check gate rows — a gated-off or
//     unselected row contributes nothing). SetupModules stamps the
//     same slice on every row's Deps; only the
//     cluster-health-probes sweep consumes it. Nil in
//     literally-constructed test Deps.
type Deps struct {
	Name      string
	Mgr       manager.Manager
	CS        kubernetes.Interface
	Dyn       dynamic.Interface
	Log       logr.Logger
	Disabled  bool
	CheckRegs []CheckReg
}
