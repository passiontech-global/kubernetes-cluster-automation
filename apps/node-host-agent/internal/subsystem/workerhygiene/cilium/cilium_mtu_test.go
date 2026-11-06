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
