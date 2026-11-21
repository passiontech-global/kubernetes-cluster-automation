// cilium_mtu.go — B4 MTU-drift check (CiliumMTUCheck): the cilium
// datapath (or the double-encap cilium_wg0) running an MTU above
// the nebula overlay → latch state-cilium-mtu-drift for NPD.
package cilium

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

// mtuReadInconclusive checks whether path failed with a non-ENOENT error
// (e.g. EACCES, EIO, ENOTDIR) so sysfs read failures abort rather than
// masquerade as absent interfaces.
func mtuReadInconclusive(path string) error {
	_, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// isPodLxcIface matches the Cilium host-side pod veth names ("lxc" + hex)
// identical to procfs.MaxPodLxcMTU (plus uppercase hex), excluding lxc_health.
func isPodLxcIface(name string) bool {
	if name == "lxc_health" || !strings.HasPrefix(name, "lxc") || len(name) <= len("lxc") {
		return false
	}
	for i := len("lxc"); i < len(name); i++ {
		c := name[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// Run executes one cilium-mtu round.
func (c *CiliumMTUCheck) Run(_ context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckCiliumMTU) {
		return
	}
	if _, err := os.ReadDir(c.d.Cfg.SysClassNet); err != nil && !os.IsNotExist(err) {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cilium-mtu read %s failed: %v — inconclusive, keeping state",
			c.d.Cfg.SysClassNet, err))
		c.d.CycleResult(wdeps.CheckCiliumMTU, "abort")
		return
	}
	neb, nebOK := procfs.MTUOfIface(c.d.Cfg.SysClassNet, c.d.Cfg.NebulaIface)
	if !nebOK {
		nebMTU := filepath.Join(c.d.Cfg.SysClassNet, c.d.Cfg.NebulaIface, "mtu")
		if err := mtuReadInconclusive(nebMTU); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: cilium-mtu read %s failed: %v — inconclusive, keeping state",
				nebMTU, err))
			c.d.CycleResult(wdeps.CheckCiliumMTU, "abort")
			return
		}
		// No overlay to compare against — a drift latch from
		// before must not linger.
		c.d.State.Exit(latchdefs.LatchCiliumMTUDrift, nil)
		c.d.CycleResult(wdeps.CheckCiliumMTU, "ok")
		return
	}
	cil, cilOK := procfs.MTUOfIface(c.d.Cfg.SysClassNet, c.d.Cfg.Cilium.Iface)
	if !cilOK {
		cilMTU := filepath.Join(c.d.Cfg.SysClassNet, c.d.Cfg.Cilium.Iface, "mtu")
		if err := mtuReadInconclusive(cilMTU); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: cilium-mtu read %s failed: %v — inconclusive, keeping state",
				cilMTU, err))
			c.d.CycleResult(wdeps.CheckCiliumMTU, "abort")
			return
		}
		cil, cilOK = procfs.RuntimeConfigMTU(c.d.Cfg.Cilium.RuntimeConfig)
		if !cilOK && c.d.Cfg.Cilium.RuntimeConfig != "" {
			if err := mtuReadInconclusive(c.d.Cfg.Cilium.RuntimeConfig); err != nil {
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: cilium-mtu read %s failed: %v — inconclusive, keeping state",
					c.d.Cfg.Cilium.RuntimeConfig, err))
				c.d.CycleResult(wdeps.CheckCiliumMTU, "abort")
				return
			}
		}
	}
	// double-encap guard: on the WireGuard datapath cilium_wg0
	// carries pod traffic INSIDE the nebula overlay — its MTU must
	// leave room for the WG header (~60B) under the overlay MTU.
	// A wg0 MTU above neb−60 means pod packets exceed what the
	// double-encapsulated path can carry → silent blackhole.
	wg, wgOK := procfs.MTUOfIface(c.d.Cfg.SysClassNet, c.d.Cfg.Cilium.WG0Iface)
	if !wgOK && c.d.Cfg.Cilium.WG0Iface != "" {
		wgMTU := filepath.Join(c.d.Cfg.SysClassNet, c.d.Cfg.Cilium.WG0Iface, "mtu")
		if err := mtuReadInconclusive(wgMTU); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: cilium-mtu read %s failed: %v — inconclusive, keeping state",
				wgMTU, err))
			c.d.CycleResult(wdeps.CheckCiliumMTU, "abort")
			return
		}
	}
	// lxc-mtu-drift: pod lxc* veths. A pod created before the MTU change
	// keeps its stale MTU on its host-side veth even when every
	// cilium_* datapath iface is aligned — the same FRAG_NEEDED
	// blackhole, so the pod veth MAX votes on the same latch.
	lxcMax, lxcOK := procfs.MaxPodLxcMTU(c.d.Cfg.SysClassNet)
	if entries, err := os.ReadDir(c.d.Cfg.SysClassNet); err != nil {
		if !os.IsNotExist(err) {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: cilium-mtu read %s failed: %v — inconclusive, keeping state",
				c.d.Cfg.SysClassNet, err))
			c.d.CycleResult(wdeps.CheckCiliumMTU, "abort")
			return
		}
	} else {
		for _, ent := range entries {
			if !isPodLxcIface(ent.Name()) {
				continue
			}
			lxcMTU := filepath.Join(c.d.Cfg.SysClassNet, ent.Name(), "mtu")
			if err := mtuReadInconclusive(lxcMTU); err != nil {
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: cilium-mtu read %s failed: %v — inconclusive, keeping state",
					lxcMTU, err))
				c.d.CycleResult(wdeps.CheckCiliumMTU, "abort")
				return
			}
		}
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
