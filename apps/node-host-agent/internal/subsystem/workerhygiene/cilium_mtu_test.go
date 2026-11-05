// cilium_mtu_test.go — B4 cilium_net vs nebula MTU drift latch
// + runtime-config MTU max-resolution.
package workerhygiene

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
)

// --- B4: MTU drift ---

func TestCiliumMTUDriftLatchesAndLogs(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	writeFile(t, filepath.Join(e.sysnet, "neb1", "mtu"), "1300\n")
	writeFile(t, filepath.Join(e.sysnet, "cilium_net", "mtu"), "1500\n")
	e.h.Cycle(context.Background())
	if !e.h.state.Exists("cilium-mtu-drift") {
		t.Fatal("state-cilium-mtu-drift should latch when cilium_mtu > neb1")
	}
	data, err := os.ReadFile(e.h.cfg.WatchdogLogFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "ACTION cilium-mtu-drift: cilium_net=1500 nebula=1300") {
		t.Fatalf("log missing drift ACTION line:\n%s", data)
	}
	// Drift fixed → latch clears.
	writeFile(t, filepath.Join(e.sysnet, "cilium_net", "mtu"), "1300\n")
	e.h.Cycle(context.Background())
	if e.h.state.Exists("cilium-mtu-drift") {
		t.Fatal("latch should clear once MTUs align")
	}
}

func TestCiliumMTURuntimeConfigFallback(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	writeFile(t, filepath.Join(e.sysnet, "neb1", "mtu"), "1300\n")
	writeFile(t, e.ciliumRt, `{"mtu":1500,"other":1}`)
	e.h.Cycle(context.Background())
	if !e.h.state.Exists("cilium-mtu-drift") {
		t.Fatal("runtime-config MTU 1500 > neb1 1300 should latch drift")
	}
}

// TestRuntimeConfigMTUMaxDeterministic pins the multi-mtu
// behaviour: several `mtu`-keyed values (nested maps AND arrays)
// must resolve to the MAX — a "first match" walk is unstable
// under Go's random map iteration order.
func TestRuntimeConfigMTUMaxDeterministic(t *testing.T) {
	e := fixture(t)
	writeFile(t, e.ciliumRt,
		`{"a":{"mtu":1300},"list":[{"mtu":1400},{"mtu":1500}],"z":{"MTU":900}}`)
	got, ok := hostutil.RuntimeConfigMTU(e.ciliumRt)
	if !ok || got != 1500 {
		t.Fatalf("RuntimeConfigMTU=%v,%v want 1500,true (max of all mtu keys)", got, ok)
	}
}
