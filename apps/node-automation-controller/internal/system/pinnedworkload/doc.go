// Package pinnedworkload is the shared framework for the "pinned
// workload" patcher modules — corednspatcher and metricsserverpatcher
// (kube-system Deployments) plus konnectivitypatcher (a kube-system
// DaemonSet). Each keeps a k0s stack-applier-owned workload at its
// pinned spec via a For() watch that re-pins drift in <1s, with the
// 15m requeue as the safety net the hourly crontabs used to be.
//
// The package holds the pieces the modules were byte-identical on:
// the ns/name For() predicate (OnlyNamespacedName), the
// create/delete-only Node predicate (NodeCountChanges) and the
// proportional replica pin behind it (ReplicaPin — knob pair,
// wantReplicas computation, conditional watch wiring), and the two
// reconcile skeletons (DeploymentSpec / DaemonSetSpec). The modules
// keep the ops surface — env knobs, drift checks, patch bodies, the
// queue name on every metric label, and the sweep keys.
package pinnedworkload
