// cilium_mtu.go — B4 MTU-drift check (ciliumMTUCheck): the cilium
// datapath (or the W9 double-encap cilium_wg0) running an MTU above
// the nebula overlay → latch state-cilium-mtu-drift for NPD.
package workerhygiene

import (
	"context"
	"fmt"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
)

const (
	defaultNebulaIface         = "neb1"
	defaultCiliumIface         = "cilium_net"
	defaultCiliumWG0Iface      = "cilium_wg0"
	defaultCiliumRuntimeConfig = "/host/run/cilium/state/agent-runtime-config.json"
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
// The MTU readers themselves are hostutil.MTUOfIface /
// hostutil.RuntimeConfigMTU (sysfs mtu file + agent-runtime-config.json
// fallback, MAX-wins over several `mtu` keys).

// ciliumMTUCheck is the B4 MTU-drift guard as a Check (no streak —
// the latch IS the state).
type ciliumMTUCheck struct{ d *deps }

// Name returns the check label / WD_SIG key.
func (c *ciliumMTUCheck) Name() string { return checkCiliumMTU }

// Run executes one cilium-mtu round.
func (c *ciliumMTUCheck) Run(_ context.Context, e *cycleEnv) {
	if !e.workerActive {
		c.d.cycles.WithLabelValues(checkCiliumMTU, "gated").Inc()
		return
	}
	neb, nebOK := hostutil.MTUOfIface(c.d.cfg.Net.SysClassNet, c.d.cfg.Net.NebulaIface)
	cil, cilOK := hostutil.MTUOfIface(c.d.cfg.Net.SysClassNet, c.d.cfg.Cilium.Iface)
	if !cilOK {
		cil, cilOK = hostutil.RuntimeConfigMTU(c.d.cfg.Cilium.RuntimeConfig)
	}
	// W9 double-encap guard: on the WireGuard datapath cilium_wg0
	// carries pod traffic INSIDE the nebula overlay — its MTU must
	// leave room for the WG header (~60B) under the overlay MTU.
	// A wg0 MTU above neb−60 means pod packets exceed what the
	// double-encapsulated path can carry → silent blackhole.
	wg, wgOK := hostutil.MTUOfIface(c.d.cfg.Net.SysClassNet, c.d.cfg.Cilium.WG0Iface)
	if !nebOK {
		// No overlay to compare against — a drift latch from
		// before must not linger.
		c.d.state.Exit(hoststate.LatchCiliumMTUDrift, nil)
		c.d.cycles.WithLabelValues(checkCiliumMTU, "ok").Inc()
		return
	}
	var driftWhy string
	switch {
	case cilOK && cil > neb:
		driftWhy = fmt.Sprintf("cilium_net=%d nebula=%d", cil, neb)
	case wgOK && wg > neb-wgEncapOverheadBytes:
		driftWhy = fmt.Sprintf("cilium_wg0=%d nebula=%d (wg overhead %d)",
			wg, neb, wgEncapOverheadBytes)
	}
	if driftWhy != "" {
		if !c.d.state.Exists(hoststate.LatchCiliumMTUDrift) {
			c.d.state.Enter(hoststate.LatchCiliumMTUDrift, driftWhy)
			// NPD contract: nodereporter maps this line to the
			// CiliumMTUExceedsOverlay Event + problem_counter.
			c.d.state.AppendLog(
				"ACTION cilium-mtu-drift: " + driftWhy)
		}
	} else {
		c.d.state.Exit(hoststate.LatchCiliumMTUDrift, nil)
	}
	c.d.cycles.WithLabelValues(checkCiliumMTU, "ok").Inc()
}

// checkCiliumMTU forwards to the migrated Check — tests written
// before the interface still call the old method shape.
func (h *Hygiene) checkCiliumMTU(workerActive bool) {
	h.ciliumMTU.Run(context.Background(), &cycleEnv{workerActive: workerActive})
}
