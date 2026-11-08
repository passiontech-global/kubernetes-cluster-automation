// domains.go — domain topology identifiers shared ACROSS domain
// trees: the namespace and control-plane component names that more
// than one tree references (health checks bounce these pods,
// integration auditors gate on their identity, watchdogs guard
// them). depguard denies cross-tree imports — health may not import
// integration and vice versa — so platform is the one sanctioned
// sharing layer, exactly like the Flux GVR/artifact vocabulary in
// fluxconditions.go.
//
// Scope guard: only cross-tree topology identifiers belong here.
// Single-package constants stay beside their consumer; the health
// tree's intra-tree identifiers import this file too rather than
// redeclaring; ops-contract strings (annotation/taint keys, metric
// names) live in annos.go and internal/metrics, never here.
package kube

const (
	// DragonflyOperatorNS is the dragonfly-operator namespace: the
	// datastore checks bounce its operator pods to resync CRs, and
	// the workqueue watchdog treats it as one of the operator
	// targets it guards.
	DragonflyOperatorNS = "dragonfly-operator-system"

	// LinkerdNS is the linkerd control-plane namespace, and
	// LinkerdDestinationName / LinkerdIdentityName the control-plane
	// component names: the nethealth/linkerd endpoint-sync check
	// re-rolls their wedged pods, the mesh control-plane watchdog
	// heals the same pods on its own signatures, and the cert-drift
	// auditor restarts the linkerd-identity Deployment when the
	// issuer certificate rotates.
	LinkerdNS              = "linkerd"
	LinkerdDestinationName = "linkerd-destination"
	LinkerdIdentityName    = "linkerd-identity"
)
