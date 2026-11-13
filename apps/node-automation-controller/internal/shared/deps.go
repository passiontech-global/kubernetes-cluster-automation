// deps.go — the Deps bundle every module's Setup receives: the
// manager, the direct clientset, the dynamic client, the logger and
// the Disabled gate flag.
package shared

import (
	"github.com/go-logr/logr"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/maintenance"
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
//   - Meta is the metadata client — PartialObjectMetadata reads
//     (labels/annotations/ownerRefs without the resource payload)
//     through kube.ListPartialOrFallback. Nil in literally-
//     constructed test Deps; the helper falls back to CS/Dyn.
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
//     module rows, in registry order — that order IS the sweep
//     order (a gated-off or unselected row contributes nothing).
//     SetupModules stamps the same slice only on rows marked
//     Module.ConsumesCheckRegs (the cluster-health-probes sweep);
//     every other module's CheckRegs stays nil. Nil in
//     literally-constructed test Deps.
//   - ProbeCS/ProbeDyn are the latency-sensitive probe clients (own
//     client-go rate limiter — see cmd/manager main.go). SetupModules
//     hands them to a module's Setup AS CS/Dyn when the module row
//     opts in (Module.ProbeClients), so the probe modules read the
//     same call sites; nil (tests, StubManager wiring) leaves the
//     row's CS/Dyn untouched.
type Deps struct {
	Name      string
	Mgr       manager.Manager
	CS        kubernetes.Interface
	Dyn       dynamic.Interface
	Meta      metadata.Interface
	ProbeCS   kubernetes.Interface
	ProbeDyn  dynamic.Interface
	ProbeMeta metadata.Interface
	// Maintenance is the ONE maintenance-mutex verdict every heal
	// gate in the process memoizes on (platform/maintenance.Verdict)
	// — modules and the sweep share it so a drain in flight is
	// evaluated once per Verdict TTL cluster-wide, not once per
	// module. main.go wires it with NodeReader set to the manager's
	// cached client, so the mutex's node census rides the informer
	// instead of a direct apiserver LIST per TTL. Nil (tests,
	// StubManager wiring) leaves each consumer's own fallback verdict
	// in place.
	Maintenance *maintenance.Verdict
	Log         logr.Logger
	Disabled    bool
	CheckRegs   []CheckReg
}

// CachedClient returns the manager's informer-backed read client —
// the client.Reader every CachedNodeReader/CachedObjectReader seam
// accepts. A nil Mgr (literally-constructed test Deps, the shape
// this file documents) returns nil instead of dereferencing: the
// reader seams treat nil as "no cache wired" and fall back to the
// direct clientset, so Setup keeps working on fixtures that never
// built a manager. This is the one sanctioned accessor for the
// cached read client — a bare d.Mgr.GetClient() skips the guard and
// panics Setup on exactly those fixtures.
func (d Deps) CachedClient() client.Client {
	if d.Mgr == nil {
		return nil
	}
	return d.Mgr.GetClient()
}
