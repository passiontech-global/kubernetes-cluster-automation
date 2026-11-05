// collect_procs_cgroup_test.go — Wave-2 zombie count, cgroup pids ratio, and MTU-drift series.

package hostmetrics

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

func TestZombieCount(t *testing.T) {
	cfg, _ := fixture(t)
	for _, pid := range []int{301, 302} {
		d := filepath.Join(cfg.ProcRoot, strconv.Itoa(pid))
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		testutil.WriteFile(t, filepath.Join(d, "stat"),
			fmt.Sprintf("%d (x) Z 1 0 0", pid))
	}
	d := filepath.Join(cfg.ProcRoot, "303")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(d, "stat"), "303 (y) S 1 0 0")
	c := New(cfg)
	got, ok := metricValue(t, c, "node_host_agent_processes_zombie_count",
		map[string]string{"node": "node-a"})
	if !ok || got != 2 {
		t.Fatalf("zombie_count=%v ok=%v want 2", got, ok)
	}
}

func TestCgroupPidsRatio(t *testing.T) {
	cfg, _ := fixture(t)
	d := filepath.Join(cfg.CgroupRoot, "system.slice/k0sworker.service")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(d, "pids.current"), "900\n")
	testutil.WriteFile(t, filepath.Join(d, "pids.max"), "1024\n")
	// "max" (unlimited) must emit no ratio — not a fake 0.
	d2 := filepath.Join(cfg.CgroupRoot, "kubepods.slice")
	if err := os.MkdirAll(d2, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(d2, "pids.current"), "50\n")
	testutil.WriteFile(t, filepath.Join(d2, "pids.max"), "max\n")
	c := New(cfg)
	got, ok := metricValue(t, c, "node_host_agent_cgroup_pids_used_ratio",
		map[string]string{"node": "node-a",
			"slice": "system.slice/k0sworker.service"})
	if !ok || got != 900.0/1024.0 {
		t.Fatalf("pids ratio=%v ok=%v want %v", got, ok, 900.0/1024.0)
	}
	if _, ok := metricValue(t, c, "node_host_agent_cgroup_pids_used_ratio",
		map[string]string{"node": "node-a", "slice": "kubepods.slice"}); ok {
		t.Fatal("pids.max=max must emit no ratio")
	}
}

func TestMTUDrift(t *testing.T) {
	cfg, dirs := fixture(t)
	for _, n := range []string{"neb1", "cilium_net"} {
		if err := os.MkdirAll(filepath.Join(dirs["sysnet"], n), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	testutil.WriteFile(t, filepath.Join(dirs["sysnet"], "neb1", "mtu"), "1300\n")
	testutil.WriteFile(t, filepath.Join(dirs["sysnet"], "cilium_net", "mtu"), "1500\n")
	c := New(cfg)
	got, ok := metricValue(t, c, "node_host_agent_mtu_drift",
		map[string]string{"node": "node-a"})
	if !ok || got != 1 {
		t.Fatalf("mtu_drift=%v ok=%v want 1", got, ok)
	}
	testutil.WriteFile(t, filepath.Join(dirs["sysnet"], "cilium_net", "mtu"), "1300\n")
	got, ok = metricValue(t, c, "node_host_agent_mtu_drift",
		map[string]string{"node": "node-a"})
	if !ok || got != 0 {
		t.Fatalf("aligned MTUs: drift=%v ok=%v want 0", got, ok)
	}
}

func TestMTUDriftRuntimeConfigFallback(t *testing.T) {
	cfg, dirs := fixture(t)
	if err := os.MkdirAll(filepath.Join(dirs["sysnet"], "neb1"), 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(dirs["sysnet"], "neb1", "mtu"), "1300\n")
	testutil.WriteFile(t, cfg.CiliumRuntimeConfig, `{"mtu":1500}`)
	c := New(cfg)
	got, ok := metricValue(t, c, "node_host_agent_mtu_drift",
		map[string]string{"node": "node-a"})
	if !ok || got != 1 {
		t.Fatalf("runtime-config fallback: drift=%v ok=%v want 1", got, ok)
	}
}

// TestRuntimeConfigMTUMaxDeterministic pins the multi-mtu
// behaviour: several `mtu`-keyed values (nested maps AND arrays)
// must resolve to the MAX — a "first match" walk is unstable
// under Go's random map iteration order.
func TestRuntimeConfigMTUMaxDeterministic(t *testing.T) {
	cfg, _ := fixture(t)
	testutil.WriteFile(t, cfg.CiliumRuntimeConfig,
		`{"a":{"mtu":1300},"list":[{"mtu":1400},{"mtu":1500}],"z":{"MTU":900}}`)
	got, ok := hostutil.RuntimeConfigMTU(cfg.CiliumRuntimeConfig)
	if !ok || got != 1500 {
		t.Fatalf("RuntimeConfigMTU=%v,%v want 1500,true (max of all mtu keys)", got, ok)
	}
}

func TestMTUDriftAbsentWhenNoSources(t *testing.T) {
	cfg, _ := fixture(t)
	c := New(cfg)
	if _, ok := metricValue(t, c, "node_host_agent_mtu_drift",
		map[string]string{"node": "node-a"}); ok {
		t.Fatal("no neb1/cilium source → series must be absent")
	}
}

// --- Wave-9: cilium_wg0 double-encap MTU + OpenEBS LocalPV bytes ---

// TestMTUDriftWG0Encap: cilium_wg0 must stay <= nebula-60 — the WG
// header overhead inside the overlay. Above that the double-encap
// path blackholes and drift reports 1 even with no cilium_net.
func TestMTUDriftWG0Encap(t *testing.T) {
	cfg, dirs := fixture(t)
	for _, n := range []string{"neb1", "cilium_wg0"} {
		if err := os.MkdirAll(filepath.Join(dirs["sysnet"], n), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	testutil.WriteFile(t, filepath.Join(dirs["sysnet"], "neb1", "mtu"), "1300\n")
	testutil.WriteFile(t, filepath.Join(dirs["sysnet"], "cilium_wg0", "mtu"), "1250\n")
	c := New(cfg)
	got, ok := metricValue(t, c, "node_host_agent_mtu_drift",
		map[string]string{"node": "node-a"})
	if !ok || got != 1 {
		t.Fatalf("wg0=1250 > 1300-60: drift=%v ok=%v want 1", got, ok)
	}
	// Exactly at budget → no drift.
	testutil.WriteFile(t, filepath.Join(dirs["sysnet"], "cilium_wg0", "mtu"), "1240\n")
	got, ok = metricValue(t, c, "node_host_agent_mtu_drift",
		map[string]string{"node": "node-a"})
	if !ok || got != 0 {
		t.Fatalf("wg0=1240 == 1300-60: drift=%v ok=%v want 0", got, ok)
	}
}

// TestMTUDriftWG0AbsentNoVote: with nebula up but NO datapath MTU
// resolvable the series is absent — absent ifaces do not vote, and
// "no datapath" must stay distinguishable from "aligned datapaths".
func TestMTUDriftWG0AbsentNoVote(t *testing.T) {
	cfg, dirs := fixture(t)
	if err := os.MkdirAll(filepath.Join(dirs["sysnet"], "neb1"), 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(dirs["sysnet"], "neb1", "mtu"), "1300\n")
	c := New(cfg)
	if _, ok := metricValue(t, c, "node_host_agent_mtu_drift",
		map[string]string{"node": "node-a"}); ok {
		t.Fatal("series emitted with nebula but zero datapath MTUs")
	}
}
