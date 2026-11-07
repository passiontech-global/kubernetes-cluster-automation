// checks.go — the oom-domain check constructors. The parent
// controllerhygiene package wires the checks into its ordered
// dispatch table (check.go) — order there is load-bearing.
package oom

import "github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"

// NewLoop returns the memcg OOM-loop detector + shield.
func NewLoop(d *cdeps.Deps) *LoopCheck { return &LoopCheck{d: d} }
