// Package watchdogs holds the workqueue/control-plane watchdog checks
// riding the cluster-health sweep: kcm-workqueue-watchdog (C6 — a
// kube-controller-manager whose leader Lease renews while its object
// controllers stop reconciling), operator-workqueue-watchdog (operator-workqueue-watchdog —
// the same gray-failure shape generalized to third-party operators,
// with the stuck-leader pod-delete auto-heal), the scheduler watchdog,
// the mesh control-plane watchdog and the apiserver-relist-storm
// breaker. The controller-lease-guard and api-object-sprawl census
// split into the leases/ and sprawl/ subpackages. Each reports on the
// shared kuberhealthy_check series under its own check name.
package watchdogs
