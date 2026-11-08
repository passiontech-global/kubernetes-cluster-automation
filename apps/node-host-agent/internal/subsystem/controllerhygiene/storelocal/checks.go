// Package storelocal is the LOCAL controller sqlite state.db
// hygiene: the kine-backend checks that run on the k0s controller
// itself — the connection-spiral backstop (pool), the module-22 TTL
// dead/rewedge-loop kill guard, and the W10-CP2 store-size +
// WAL-checkpoint health check. Runtime contracts (check names,
// latch/latchdef keys, node_agent_kine_* metric names, env vars)
// keep their kine spellings verbatim.
//
// NOT to be confused with the kinedb subsystem
// (internal/subsystem/kinedb): that one owns the EXTERNAL Kine-DB
// VM (postgres/pgbouncer) — storelocal never leaves the controller
// node.
//
// The parent controllerhygiene package wires the checks into its
// ordered dispatch table (check.go) — order there is load-bearing.
package storelocal

import "github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"

// NewPool returns the kine->DB connection-spiral backstop.
func NewPool(d *cdeps.Deps) *PoolCheck { return &PoolCheck{d: d} }

// NewTTL returns the module-22 kine TTL dead/rewedge-loop kill guard.
func NewTTL(d *cdeps.Deps) *TTLCheck { return &TTLCheck{d: d} }

// NewStorage returns the W10-CP2 Kine store health check — it rides
// the apiserver freeze check's ungated slot, not its own table row.
func NewStorage(d *cdeps.Deps) *StorageCheck { return &StorageCheck{d: d} }
