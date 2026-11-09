// Port of hooks/55-admission-webhook-guard.sh.
//
// Removes "orphan" admission webhook entries whose backend Service lives
// in a namespace that no longer exists (e.g. Flux pruned linkerd → the
// cluster-scoped MutatingWebhookConfiguration outlived its control plane
// and every pod create fail-closed, incident 2026-10-20).
//
// Rules (faithful to bash):
//   - namespace exists + Service exists      → nothing.
//   - namespace exists + Service missing     → WARN only, never patch
//     (a mid-rollout Service looks exactly like this).
//   - namespace gone                         → remove that webhook entry
//     only; sibling entries in the same config are kept.
//
// Safety: the namespace list is snapshotted once — any error aborts the
// run before anything is patched (an API flap must never be read as
// "namespace deleted").
//
// C1 — self-deadlock circuit breaker (env WEBHOOK_CIRCUIT_BREAKER_ENABLED,
// default on): a sub-webhook with failurePolicy=Fail whose backend
// Service reports 0 Ready endpoints for webhookDeadThreshold straight
// is a cluster-wide deadlock — every admission it matches fails closed,
// including the creates that would bring the backend back. The breaker
// flips such entries to Ignore and records their names in the
// passiontech.dev/circuit-broken-webhooks annotation on the config; when the
// Service reports >= 1 Ready endpoint again the declared Fail policy
// is restored and the annotation shrinks (removed when empty).
// endpoint-census — the endpoint census is node-aware: Ready endpoints on
// partitioned/unresponsive/NotReady nodes are discounted, and when
// they are ALL that remains the breaker trips on the faster
// partitionZeroThreshold (90s) instead of webhookDeadThreshold.
//
// 2.2 — unmeshed-pod-auditor + post-circuit-breaker healer. Pods
// created while the C1 breaker held linkerd-proxy-injector open run
// WITHOUT their linkerd-proxy sidecar: no mTLS, invisible to service
// mesh policy, and permanently unmeshed (injection happens at admit
// time — nothing re-injects a running pod). Each sweep audits Running
// Pods whose Namespace OR the Pod itself opts into injection
// (linkerd.io/inject=enabled, minus hostNetwork pods, Job/CronJob
// children and explicit inject=disabled opt-outs) and exports
// node_automation_unmeshed_pods{namespace,pod} for every pod missing
// the linkerd-proxy container+initContainer. When the injector
// webhook is provably healthy again — not circuit-broken, failurePolicy
// still Fail, Ready endpoints > 0 — and UNMESHED_POD_REMEDIATION_ENABLED
// is not "false", the auditor EVICTS up to 2 unmeshed pods per cycle
// (only pods >2m old, not already terminating, with a non-Node
// controller ownerReference, so a controller recreates them meshed;
// at most 4 delete attempts so a persistently failing apiserver
// cannot turn the sweep into an API storm) and counts
// node_automation_unmeshed_pods_recreated_total.
// Pods are list/watch-locked in the manager cache (kube-system +
// k8s-app=cilium only), so the audit reads through the direct
// clientset exactly like every other module.
//
// unmeshed-pod-auditor — remediation hardening: before evicting anything the sweep
// holds the shared maintenance mutex (a cordon/drain/kured reboot or
// an in-flight k0s autopilot upgrade defers the work), and the pod
// kill goes through the policy/v1 Eviction API — a raw Delete would
// bypass every PodDisruptionBudget and could take the last Ready
// replica of an already-degraded workload. An apiserver 429 (PDB
// refusing the disruption) is a deferral, not an error: the pod is
// kept and the next candidate is tried.
//
// bootwebhooks — the medik8s boot fail-open enforcement. The medik8s
// operators ensure their default config/template CRs at manager
// startup through their OWN validating webhooks (failurePolicy=Fail
// from the CSV webhookdefinitions); a stale/wrong endpoint set at that
// moment i/o-times the call and the manager exit-1s into a crash loop
// (incident 2026-11-08: stale pod IP reassigned to a passiontech pod,
// SYN blackholed by network policy, both SNR managers down ~3d). The
// duty enforces Ignore, ONE-WAY, on validating entries whose rules
// reference only the selfnoderemediationconfigs / selfnoderemediationtemplates
// resources of the medik8s group — one-way because a restore-to-Fail
// would re-arm the fatality at the next operator restart. OLM
// re-asserts Fail from the CSV on reconcile/upgrade; the sweep re-heals
// that drift every cycle. Mutating configs, the remediation-CR entry
// and every non-medik8s webhook are untouched. Gate:
// MEDIK8S_BOOT_FAIL_OPEN_ENABLED (on unless "false").
//
// The package is split into leaf subpackages — guardstate (shared
// deps + run snapshot + endpoint census), orphansweep, circuitbreaker,
// criticalns, unmeshed and bootwebhooks — each owning one duty; this
// facade keeps only the registry-facing Setup and the errors.Join sweep
// orchestration.
package webhookguard

import (
	"context"
	"errors"
	"time"

	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/bootwebhooks"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/circuitbreaker"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/criticalns"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/orphansweep"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/unmeshed"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

// webhookGuard is the facade behind the single
// "admission-webhook-guard" periodic: it embeds the shared
// guardstate.Guard dep bundle (clients, queue name, clock, probe
// seam, maintenance verdict) and holds the two stateful duties —
// circuitbreaker.Breaker and unmeshed.Auditor (orphansweep is
// stateless, so it needs no struct). run() takes the shared
// snapshot once and invokes the duties in a fixed order, so the
// externally visible contract (queue name, interval, metric series,
// errors.Join error accounting) is unchanged by the split.
type webhookGuard struct {
	guardstate.Guard
	breaker  circuitbreaker.Breaker
	critical criticalns.Sweeper
	auditor  unmeshed.Auditor
}

// Setup registers the 5-minute sweep (was crontab */5). dyn feeds
// the autopilot-Plan signal of the maintenance mutex consulted by
// the unmeshed-pod healer (unmeshed-pod-auditor). Gated through shared.SetupNoConfig:
// a disabled module registers nothing — no runnable, no periodic
// cluster LIST against the apiserver.
func Setup(d shared.Deps) error {
	return shared.SetupNoConfig(d, func() error {
		logf.Log.WithName(d.Name).Info("registered",
			"interval", 5*time.Minute, "circuitBreaker", circuitbreaker.Enabled(),
			"bootFailOpen", bootwebhooks.Enabled(),
			"unmeshedRemediation", unmeshed.RemediationEnabled())
		// The bookkeeping ledgers inside the duty structs (deadSince,
		// brokenEmitted, bounceAt, crdUnhealthyEmitted, unmeshedEmitted,
		// criticalns' exclusionEmitted/heartbeatEmitted) are shared.*
		// zero-value types — nothing to initialize here.
		g := &webhookGuard{Guard: guardstate.Guard{
			CS: d.CS, Dyn: d.Dyn, Queue: d.Name, Now: shared.SystemClock,
			NodeReader: d.Mgr.GetClient()}}
		return shared.AddPeriodic(d.Mgr, g.Queue, 5*time.Minute, g.run)
	})
}

func (g *webhookGuard) run(ctx context.Context) error {
	// The orphan sweep, the circuit breaker, the CRD conversion-
	// backend check, the critical-NS audits and the unmeshed-pod
	// auditor are independent duties — a failure in one must never
	// skip the others, so all run and their errors join (nils → nil).
	// All read the same cluster state, so the shared snapshot is
	// listed once up front instead of once per consumer. The ops
	// levers (WEBHOOK_CIRCUIT_BREAKER_ENABLED,
	// UNMESHED_POD_REMEDIATION_ENABLED,
	// WEBHOOK_CRITICAL_NS_ENFORCE_ENABLED — the last inside
	// critical.Sweep) are read fresh on every sweep — the sanctioned
	// hot-reload exception to the resolve-at-Setup env rule.
	snap := g.TakeSnapshot(ctx)
	orphanErr := orphansweep.Sweep(ctx, snap)
	var breakerErr error
	if circuitbreaker.Enabled() {
		breakerErr = g.breaker.Sweep(ctx, snap)
	}
	conversionErr := g.breaker.SweepCRDConversionBackends(ctx, snap)
	// The medik8s boot fail-open enforcement runs on the same shared
	// snapshot — it only reads the validating list the census already
	// fetched.
	bootErr := bootwebhooks.Sweep(ctx, snap)
	// The critical-ns audits run here — where they sat at the top of
	// the unmeshed sweep before the duty moved to its own leaf
	// subpackage — so they read post-breaker webhook state.
	g.critical.Sweep(snap)
	unmeshedErr := g.auditor.Sweep(ctx, snap)
	return errors.Join(orphanErr, breakerErr, conversionErr, bootErr, unmeshedErr)
}
