// checks.go — the kubelet-domain check constructors plus the T15
// feeder's exported entry points. The parent workerhygiene package
// wires the checks into its ordered dispatch list and calls
// RunKubeletFeeder from Run; the KubeletFeederActive/KubeletFeedTick
// exports exist for the parent's test-contract forwarders.
package kubelet

import (
	"context"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// NewStall returns the 05 kubelet-stall check.
func NewStall(d *wdeps.Deps) *StallCheck { return &StallCheck{d: d} }

// NewWatchWedge returns the 06 kubelet-watch-wedge check.
func NewWatchWedge(d *wdeps.Deps) *WatchWedgeCheck {
	return &WatchWedgeCheck{d: d}
}

// NewSyncloop returns the A4 PLEG/syncloop probe.
func NewSyncloop(d *wdeps.Deps) *SyncloopCheck {
	return &SyncloopCheck{d: d}
}

// NewCtrsock returns the A4 containerd-socket hang probe.
func NewCtrsock(d *wdeps.Deps) *CtrsockCheck {
	return &CtrsockCheck{d: d}
}

// KubeletFeederActive reports whether the feeder should probe this
// node — see kubelet_feeder.go for the activation contract.
func KubeletFeederActive(d *wdeps.Deps) bool { return kubeletFeederActive(d) }

// KubeletFeedTick runs one feeder round — exported for the parent's
// test-contract forwarders.
func KubeletFeedTick(ctx context.Context, d *wdeps.Deps) {
	kubeletFeedTick(d, ctx)
}
