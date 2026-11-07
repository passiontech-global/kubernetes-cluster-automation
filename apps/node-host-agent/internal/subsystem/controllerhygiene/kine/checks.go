// checks.go — the kine-domain check constructors. The parent
// controllerhygiene package wires the checks into its ordered
// dispatch table (check.go) — order there is load-bearing.
package kine

import "github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"

// NewPool returns the kine->DB connection-spiral backstop.
func NewPool(d *cdeps.Deps) *PoolCheck { return &PoolCheck{d: d} }

// NewTTL returns the module-22 kine TTL dead/rewedge-loop kill guard.
func NewTTL(d *cdeps.Deps) *TTLCheck { return &TTLCheck{d: d} }

// NewStorage returns the W10-CP2 Kine store health check — it rides
// the apiserver freeze check's ungated slot, not its own table row.
func NewStorage(d *cdeps.Deps) *StorageCheck { return &StorageCheck{d: d} }
