// master_role.go — the master-role pod predicate the
// dragonfly-replica-sync-storm verdict uses to tell a live master
// from a stuck replica. Copy of stateful_masterless_services.go's
// predicate: the datastore subpackages are self-contained (none
// imports the flat sweep package), so the storm check carries its
// own copy — see the flat file for the shared history.
package dragonfly

import (
	"slices"

	corev1 "k8s.io/api/core/v1"
)

// masterlessRoleKeys are the label keys marking a Service that routes
// only to the master/primary of a stateful set — 0 Ready endpoints on
// it means the workload is leaderless. cnpg.io/instanceRole carries
// CloudNativePG's primary/replica role; postgres-operator.crunchydata.com/role
// is the Crunchy/Percona-PGv2 (Everest) master/replica role.
var masterlessRoleKeys = []string{
	"role", "redis-role", "app.kubernetes.io/role",
	"cnpg.io/instanceRole", "postgres-operator.crunchydata.com/role",
}

// masterlessRoleValues are the role values identifying the master
// side of a replicated stateful service.
var masterlessRoleValues = []string{"master", "primary", "leader"}

// podMasterRole reports whether the pod carries a master/primary/
// leader value under any master-role label key — the positive form
// of the dual-replica deadlock check (a pod already holding the
// master role means the election produced a winner and a pod kill
// would fight it).
func podMasterRole(pod *corev1.Pod) bool {
	for _, k := range masterlessRoleKeys {
		if slices.Contains(masterlessRoleValues, pod.Labels[k]) {
			return true
		}
	}
	return false
}
