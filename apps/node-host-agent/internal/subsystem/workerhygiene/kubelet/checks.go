// checks.go — the kubelet-domain check constructors plus the T15
// feeder's constructor. The parent workerhygiene package wires the
// checks into its ordered dispatch list and Spawns Feeder.Run from
// its own Run; tests drive Feeder.Tick/Active through the named
// Hygiene field.
package kubelet

import (
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
