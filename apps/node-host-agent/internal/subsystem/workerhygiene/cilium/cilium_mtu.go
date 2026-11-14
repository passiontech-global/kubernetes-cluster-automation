// cilium_mtu.go — B4 MTU-drift check (CiliumMTUCheck): the cilium
// datapath (or the double-encap cilium_wg0) running an MTU above
// the nebula overlay → latch state-cilium-mtu-drift for NPD.
package cilium

import (
	"context"
	"fmt"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

const (
	// wgEncapOverheadBytes is the WireGuard encapsulation overhead
	// subtracted from the overlay MTU for the cilium_wg0 drift check.
	wgEncapOverheadBytes = 60
)

// --- Check: MTU drift, cilium datapath vs overlay (B4) ---
// A pod created before the MTU change keeps MTU 1500 while the
// overlay neb1 is 1300 — the bpf policy-route then returns
// FRAG_NEEDED and the flow dies after SYN-ACK. Latch +
// ACTION cilium-mtu-drift: so nodereporter raises
// CiliumMTUExceedsOverlay.
//
// The MTU readers themselves are procfs.MTUOfIface /
// procfs.RuntimeConfigMTU (sysfs mtu file + agent-runtime-config.json
// fallback, MAX-wins over several `mtu` keys).

// CiliumMTUCheck is the B4 MTU-drift guard as a Check (no streak —
// the latch IS the state).
type CiliumMTUCheck struct{ d *wdeps.Deps }

// Name returns the check label / WD_SIG key.
func (c *CiliumMTUCheck) Name() string { return wdeps.CheckCiliumMTU }

// Run executes one cilium-mtu round.
func (c *CiliumMTUCheck) Run(_ context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckCiliumMTU) {
		return
	}
	neb, nebOK := procfs.MTUOfIface(c.d.Cfg.SysClassNet, c.d.Cfg.NebulaIface)
	cil, cilOK := procfs.MTUOfIface(c.d.Cfg.SysClassNet, c.d.Cfg.Cilium.Iface)
	if !cilOK {
		cil, cilOK = procfs.RuntimeConfigMTU(c.d.Cfg.Cilium.RuntimeConfig)
	}
	// double-encap guard: on the WireGuard datapath cilium_wg0
	// carries pod traffic INSIDE the nebula overlay — its MTU must
	// leave room for the WG header (~60B) under the overlay MTU.
	// A wg0 MTU above neb−60 means pod packets exceed what the
	// double-encapsulated path can carry → silent blackhole.
	wg, wgOK := procfs.MTUOfIface(c.d.Cfg.SysClassNet, c.d.Cfg.Cilium.WG0Iface)
	// lxc-mtu-drift: pod lxc* veths. A pod created before the MTU change
	// keeps its stale MTU on its host-side veth even when every
	// cilium_* datapath iface is aligned — the same FRAG_NEEDED
	// blackhole, so the pod veth MAX votes on the same latch.
	lxcMax, lxcOK := procfs.MaxPodLxcMTU(c.d.Cfg.SysClassNet)
	if !nebOK {
		// No overlay to compare against — a drift latch from
		// before must not linger.
		c.d.State.Exit(latchdefs.LatchCiliumMTUDrift, nil)
		c.d.CycleResult(wdeps.CheckCiliumMTU, "ok")
		return
	}
	var driftWhy string
	switch {
	case cilOK && cil > neb:
		driftWhy = fmt.Sprintf("cilium_net=%d nebula=%d", cil, neb)
	case wgOK && wg > neb-wgEncapOverheadBytes:
		driftWhy = fmt.Sprintf("cilium_wg0=%d nebula=%d (wg overhead %d)",
			wg, neb, wgEncapOverheadBytes)
	case lxcOK && lxcMax > neb:
		driftWhy = fmt.Sprintf("pod lxc*=%d nebula=%d", lxcMax, neb)
	}
	if driftWhy != "" {
		// BUG-H6: the mtime refresh runs EVERY drift cycle, not only
		// on entry — the janitor reaps state-* files older than 24h
		// and a multi-day MTU drift must not lose its latch between
		// checks. EnterFresh refreshes when held, creates when absent
		// and returns true only on transition for the one-shot ACTION line.
		if c.d.State.EnterFresh(latchdefs.LatchCiliumMTUDrift, driftWhy) {
			// NPD contract: nodereporter maps this line to the
			// CiliumMTUExceedsOverlay Event + problem_counter.
			c.d.State.AppendLog(
				latchdefs.ActionEntryPrefix(latchdefs.LatchCiliumMTUDrift) + driftWhy)
		}
	} else {
		c.d.State.Exit(latchdefs.LatchCiliumMTUDrift, nil)
	}
	c.d.CycleResult(wdeps.CheckCiliumMTU, "ok")
}
