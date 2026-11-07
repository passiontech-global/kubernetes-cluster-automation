// checks.go — the etcd-domain check constructors. The parent
// controllerhygiene package wires the checks into its ordered
// dispatch table (check.go) — order there is load-bearing.
package etcd

import "github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"

// NewGuard returns the embedded-etcd quota self-defence.
func NewGuard(d *cdeps.Deps) *GuardCheck { return &GuardCheck{d: d} }
