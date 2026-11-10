// unmeshed_audit.go — the unmeshed-pod auditor, one of the four
// independent duties behind the admission-webhook-guard run: it
// exports node_automation_unmeshed_pods{namespace,pod} for every
// Running pod that opted into linkerd injection but carries no
// linkerd-proxy sidecar (the signature of a pod admitted while the
// C1 breaker held the injector open), and — once the injector is
// provably healthy again — evicts a bounded number of them so their
// owner controller recreates them meshed. Its state (the
// emitted-series ledgers) lives on Auditor; shared deps are reached
// through snap.G. The duty splits by phase: the census half lives in
// unmeshed_census.go (namespace directives + the paged pod scan +
// the mesh-signature helpers), the destructive remediation half in
// unmeshed_evict.go (gates + the bounded EvictV1 loop); this file
// keeps the kill-switch, the Auditor state and the orchestration.
package unmeshed

import (
	"context"
	"time"

	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// The linkerd identifiers (inject annotation key, injected sidecar
// container name, injector sub-webhook name) live in platform/kube —
// the nethealth checks and the zombie-sidecar reaper match the same
// identity.
const (
	// unmeshedMinPodAge: a pod must be this old before deletion —
	// younger pods may simply be mid-admission/mid-start.
	unmeshedMinPodAge = 2 * time.Minute
	// unmeshedDeleteCap bounds successful remediation per cycle — the
	// owner controller recreates each pod, so slow rolling is safer
	// than a sweep-wide delete burst.
	unmeshedDeleteCap = 2
	// unmeshedDeleteAttempts bounds delete ATTEMPTS per cycle —
	// without it a persistently failing delete (RBAC drift, an
	// apiserver in partial outage) would be retried for every
	// candidate, turning the sweep itself into an API storm.
	unmeshedDeleteAttempts = 4
)

// ---------------------------------------------------------------------------
// 2.2 — unmeshed-pod-auditor + post-circuit-breaker pod healer.
// ---------------------------------------------------------------------------

// RemediationEnabled reads the kill-switch EVERY run — the
// sanctioned exception to the resolve-at-Setup rule: remediation is an
// ops lever that must stay flippable mid-incident, so an env flip
// takes effect on the next sweep without an operator restart (the
// same deliberate hot reload the circuit-breaker lever carries).
func RemediationEnabled() bool {
	return envx.Gate("UNMESHED_POD_REMEDIATION_ENABLED", true)
}

// Auditor owns the unmeshed-pod sweep's per-sweep state — the facade
// holds one across runs so the emitted-series ledgers persist. Shared
// deps (CS/Dyn/Now) are reached through snap.G; only the
// emitted-series ledgers live here.
type Auditor struct {
	// unmeshedEmitted is the ledger for UnmeshedPods
	// ("namespace/pod") — deleted pods and pods that gained the
	// sidecar get their series pruned each sweep.
	unmeshedEmitted state.GaugeLedger[string]
}

// Sweep audits Running Pods that opted into linkerd
// injection (namespace OR pod linkerd.io/inject=enabled) but carry no
// linkerd-proxy container or initContainer — the signature of a pod
// admitted while the C1 breaker held the injector open. The gauge is
// exported unconditionally; deletion additionally requires the
// injector webhook provably healthy and the remediation flag on.
func (a *Auditor) Sweep(ctx context.Context, snap *guardstate.Snapshot) error {
	a.unmeshedEmitted.Begin() // drop any aborted sweep's leftover emissions
	g := snap.G
	log := logf.FromContext(ctx)

	// Census phase (unmeshed_census.go) — the namespace inject map
	// first: a pod whose namespace cannot be checked must never be
	// classified.
	nsInject, err := nsInjectDirectives(snap)
	if err != nil {
		return err
	}
	now := g.Now.Now()
	unmeshed, candidates, err := a.censusUnmeshed(ctx, snap, nsInject, now, log)
	if err != nil {
		return err
	}

	// Prune series for pods that vanished or gained the sidecar —
	// same DeleteLabelValues hygiene as the circuit breaker's ledger.
	a.unmeshedEmitted.Prune(metrics.UnmeshedPods.DeleteLabelValues)

	if len(candidates) == 0 {
		return nil
	}
	// Remediation phase (unmeshed_evict.go) — the three fail-closed
	// gates then the bounded EvictV1 pass.
	a.remediate(ctx, snap, candidates, unmeshed, now, log)
	return nil
}
