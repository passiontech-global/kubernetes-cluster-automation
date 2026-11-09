// checks.go — the apiserver-domain check constructors. The parent
// controllerhygiene package wires the checks into its ordered
// dispatch table (check.go) — order there is load-bearing.
package apiserver

import "github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"

// NewHub returns the module-22 sig13 apiserver watch-cache wedge
// guard.
func NewHub(d *cdeps.Deps) *HubCheck { return &HubCheck{d: d} }

// NewFreeze returns the cp-freeze-heal/kcm-queue-stall KCM/scheduler freeze
// auto-heal. storage and kubecert are the kine-storage/kubeconfig-cert-expiry
// ride-alongs sharing its ungated dispatch slot (Run invokes them
// before its own probe so they keep the pre-uptime-gate position
// they had as inlined calls).
func NewFreeze(d *cdeps.Deps, storage, kubecert cdeps.Check) *FreezeCheck {
	return &FreezeCheck{d: d, Storage: storage, KubeCert: kubecert}
}
