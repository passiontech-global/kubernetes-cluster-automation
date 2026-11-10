// cilium_mtu_test.go — B4 cilium_net vs nebula MTU drift latch
// + runtime-config MTU max-resolution.
package cilium_test

import (
	"context"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
)

// --- B4: MTU drift ---

func TestCiliumMTUDriftLatchesAndLogs(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "neb1", "mtu"), "1300\n")
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "cilium_net", "mtu"), "1500\n")
	e.H.Cycle(context.Background())
	if !e.H.State.Exists("cilium-mtu-drift") {
		t.Fatal("state-cilium-mtu-drift should latch when cilium_mtu > neb1")
	}
	data, err := os.ReadFile(e.H.Cfg.WatchdogLogFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "ACTION cilium-mtu-drift: cilium_net=1500 nebula=1300") {
		t.Fatalf("log missing drift ACTION line:\n%s", data)
	}
	// Drift fixed → latch clears.
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "cilium_net", "mtu"), "1300\n")
	e.H.Cycle(context.Background())
	if e.H.State.Exists("cilium-mtu-drift") {
		t.Fatal("latch should clear once MTUs align")
	}
}

func TestCiliumMTURuntimeConfigFallback(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "neb1", "mtu"), "1300\n")
	wdepstest.WriteFile(t, e.CiliumRt, `{"mtu":1500,"other":1}`)
	e.H.Cycle(context.Background())
	if !e.H.State.Exists("cilium-mtu-drift") {
		t.Fatal("runtime-config MTU 1500 > neb1 1300 should latch drift")
	}
}

// TestRuntimeConfigMTUMaxDeterministic pins the multi-mtu
// behaviour: several `mtu`-keyed values (nested maps AND arrays)
// must resolve to the MAX — a "first match" walk is unstable
// under Go's random map iteration order.
func TestRuntimeConfigMTUMaxDeterministic(t *testing.T) {
	e := fixture(t)
	wdepstest.WriteFile(t, e.CiliumRt,
		`{"a":{"mtu":1300},"list":[{"mtu":1400},{"mtu":1500}],"z":{"MTU":900}}`)
	got, ok := hostutil.RuntimeConfigMTU(e.CiliumRt)
	if !ok || got != 1500 {
		t.Fatalf("RuntimeConfigMTU=%v,%v want 1500,true (max of all mtu keys)", got, ok)
	}
}

// TestCiliumMTUWG0DriftLatches: on the WireGuard datapath the
// double-encap interface must sit at least wgEncapOverheadBytes under
// the overlay — wg0 above nebula−60 blackholes pod traffic.
func TestCiliumMTUWG0DriftLatches(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "neb1", "mtu"), "1300\n")
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "cilium_net", "mtu"), "1300\n")
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "cilium_wg0", "mtu"), "1300\n")
	e.H.Cycle(context.Background())
	if !e.H.State.Exists("cilium-mtu-drift") {
		t.Fatal("wg0 MTU 1300 > nebula 1300-60 must latch drift")
	}
	if !strings.Contains(e.LogLines(t),
		"cilium_wg0=1300 nebula=1300 (wg overhead 60)") {
		t.Fatalf("missing wg0 drift reason:\n%s", e.LogLines(t))
	}
	// Aligning wg0 clears the latch.
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "cilium_wg0", "mtu"), "1240\n")
	e.H.Cycle(context.Background())
	if e.H.State.Exists("cilium-mtu-drift") {
		t.Fatal("drift latch must clear once wg0 fits the encap budget")
	}
}

// TestCiliumMTULxcDriftVotes: a stale pod veth (lxc<hex>) above the
// overlay MTU votes on the same latch; lxc_health must not.
func TestCiliumMTULxcDriftVotes(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "neb1", "mtu"), "1300\n")
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "lxc9aa1bb", "mtu"), "1400\n")
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "lxc_health", "mtu"), "9000\n")
	e.H.Cycle(context.Background())
	if !e.H.State.Exists("cilium-mtu-drift") {
		t.Fatal("pod lxc* MTU 1400 > nebula 1300 must latch drift")
	}
	if !strings.Contains(e.LogLines(t), "pod lxc*=1400 nebula=1300") {
		t.Fatalf("missing lxc drift reason (lxc_health must not win):\n%s", e.LogLines(t))
	}
}

// TestCiliumMTUNoOverlayClearsStaleLatch: without neb1 there is
// nothing to compare against — a pre-existing drift latch must not
// linger on a node that no longer runs the overlay.
func TestCiliumMTUNoOverlayClearsStaleLatch(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "cilium_net", "mtu"), "1500\n")
	e.H.State.Enter("cilium-mtu-drift", "stale evidence")
	e.H.Cycle(context.Background())
	if e.H.State.Exists("cilium-mtu-drift") {
		t.Fatal("drift latch kept without an overlay to compare against")
	}
}

// TestCiliumMTUDriftRefreshStaysQuiet: while the drift persists the
// latch file is refreshed (janitor-reap protection) but the NPD
// ACTION line stays one-shot per episode.
func TestCiliumMTUDriftRefreshStaysQuiet(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "neb1", "mtu"), "1300\n")
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "cilium_net", "mtu"), "1500\n")
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if n := strings.Count(e.LogLines(t), "ACTION cilium-mtu-drift:"); n != 1 {
		t.Fatalf("drift ACTION lines=%d want exactly 1 across a held latch", n)
	}
}
