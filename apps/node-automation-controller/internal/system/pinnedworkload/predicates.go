// predicates.go — the watch predicates the pinned-workload modules
// share: the ns/name pin every For() watch carries
// (OnlyNamespacedName) and the create/delete-only Node predicate the
// proportional replica pin's second watch installs
// (NodeCountChanges).
package pinnedworkload

import (
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// OnlyNamespacedName pins a For() watch to one namespace/name — the
// informer sees every object of the kind, so each module's
// only<Workload><Kind> package var is this predicate with its own
// ns/name filled in. The vars stay package-level in the modules so
// tests exercise the exact predicate the controller installs instead
// of introspecting controller-runtime internals.
func OnlyNamespacedName(namespace, name string) predicate.Funcs {
	return predicate.NewPredicateFuncs(func(o client.Object) bool {
		return o.GetNamespace() == namespace && o.GetName() == name
	})
}

// NodeCountChanges is the Node watch predicate for the proportional
// replica pin — node add/remove changes the replica total. The
// formula's includeUnschedulableNodes=true counts EVERY Node object,
// so updates (cordon flips, ~20s kubelet heartbeats) can never change
// the count and must not enqueue — only create/delete fire.
var NodeCountChanges = predicate.Funcs{
	CreateFunc:  func(event.CreateEvent) bool { return true },
	DeleteFunc:  func(event.DeleteEvent) bool { return true },
	UpdateFunc:  func(event.UpdateEvent) bool { return false },
	GenericFunc: func(event.GenericEvent) bool { return false },
}
