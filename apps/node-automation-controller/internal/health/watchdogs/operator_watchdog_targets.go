// operator_watchdog_targets.go — the watched-operator table of the
// operator-workqueue-watchdog check (operator-workqueue-watchdog): the opStuckResource /
// operatorTarget wiring binding each operator's leader-election
// Lease + pod selector to its CRD signature set. The generic per-CRD
// stuck predicates live in operator_stuck_signatures.go; the gateway-API
// stuck signatures and ownership filters live in gateway_targets.go.
//
// File layout: this file holds the module wiring — the
// opStuckResource/operatorTarget types, the stuck-window/reason
// constants and targetPodNS; operator_watchdog_targets_inventory.go
// the operatorTargets rows; gateway_targets.go the gateway-API stuck
// signatures and the ciliumOwns*/cftOwns* ownership filters.
package watchdogs

import (
	"context"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	// ciliumStuckMinAge is the stuck window for the gateway-API
	// resources cilium-operator reconciles.
	ciliumStuckMinAge = 10 * time.Minute
	// operatorStuckMinAge is the default stuck window for the other
	// watched operators.
	operatorStuckMinAge = 20 * time.Minute
	// opReasonStaleGWStatus is the cilium signature: a gateway-API
	// object whose status.parents is empty/absent or whose
	// observedGeneration lags — the gateway controller never
	// attached it.
	opReasonStaleGWStatus = "stale_gateway_status"
	// ciliumGatewayController is the spec.controllerName a
	// GatewayClass carries when cilium's gateway-api controller
	// serves it — the ownership key for the gateway-API resources
	// in cilium-operator's target set.
	ciliumGatewayController = "io.cilium/gateway-controller"
	// opReasonNoConditions is the never-reconciled signature for CR
	// types that carry no observedGeneration — their controller
	// stamps status.conditions on the first reconcile pass, so an
	// absent/empty list means it never picked the object up (operator-watchdog-targets).
	opReasonNoConditions = "no_status_conditions"
	// opReasonNoPhase is the same signature for CR types that report
	// a status.phase (argocd): an empty phase means the operator
	// never reconciled the object (operator-watchdog-targets).
	opReasonNoPhase = "no_status_phase"
	// opReasonNoStatus is the medik8s variant: status.phase AND
	// status.conditions both absent — the operator never completed
	// a reconcile pass on either channel (operator-workqueue-watchdog).
	opReasonNoStatus = "no_status_at_all"
)

// ---------------------------------------------------------------------------
// operator-workqueue-watchdog (operator-workqueue-watchdog) — lease-holding zombie detector
// + auto-healer.
// ---------------------------------------------------------------------------

// opStuckResource binds a watched CRD GVR to its stall signature: the
// reason label reported on operatorWorkqueueFrozenGauge and the predicate
// deciding whether one object counts as unreconciled. owns optionally
// filters stuck objects down to those this operator is actually
// responsible for — required on resource types shared by several
// controllers (gateway-api objects on this cluster split between
// cilium-operator and the cloudflare-tunnel gateway controller, so a
// stuck route must not be blamed on — or healed by — the wrong
// operator). Nil means every stuck object counts.
type opStuckResource struct {
	gvr    schema.GroupVersionResource
	reason string
	stuck  func(o *unstructured.Unstructured) bool
	owns   func(ctx context.Context, p *operatorWorkqueueCheck, o *unstructured.Unstructured) bool
}

// operatorTarget is one watched operator: the leader-election Lease
// proving liveness, the pod label selector resolving the holder to a
// pod when holderIdentity parsing fails, the stuck persistence window
// and the CRD resources it is responsible for reconciling. A nil
// opStuckResource.owns means every stuck object counts.
//
// leaseNames lists every leader-election Lease id the operator may
// hold — upstream ships more than one across versions (Percona
// operators rotate their election ids, medik8s uses a fixed hash),
// so a single hardcoded name would silently disable the watch on the
// others. The first existing candidate wins.
//
// podNS overrides the namespace pods are looked up in when it differs
// from the Lease's namespace — the cert-manager chart elects leaders
// in kube-system while its pods live in cert-manager (operator-watchdog-leases).
//
// leaseOptional marks operators that legitimately run without a
// leader-election Lease (external-secrets runs replicas:1 with
// leaderElect:false, dragonfly-operator has --leader-elect patched
// out — operator-watchdog-leases): when no candidate Lease is found the watchdog
// falls back to a Running pod matching podSelector as the liveness
// proof — a live pod whose CRs still sit unreconciled is the same
// zombie shape the Lease renewTime proves for electing operators.
type operatorTarget struct {
	name          string
	leaseNS       string
	leaseNames    []string
	podNS         string
	podSelector   string
	leaseOptional bool
	stuckMinAge   time.Duration
	resources     []opStuckResource
}

// targetPodNS resolves the namespace operator pods live in: the
// explicit podNS override when set (lease and pods split across
// namespaces), else the Lease's own namespace.
func targetPodNS(t operatorTarget) string {
	if t.podNS != "" {
		return t.podNS
	}
	return t.leaseNS
}
