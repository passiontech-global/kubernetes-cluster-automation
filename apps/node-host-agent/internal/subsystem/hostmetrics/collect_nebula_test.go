// collect_nebula_test.go — nebula interface-up / route-present series.

package hostmetrics

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

func TestNebulaUpWithRoute(t *testing.T) {
	cfg, dirs := fixture(t)
	iface := filepath.Join(dirs["sysnet"], "neb1")
	if err := os.MkdirAll(iface, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(iface, "operstate"), "up\n")
	testutil.WriteFile(t, cfg.RouteFile,
		"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"+
			"eth0\t00000000\t0102A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"+
			"neb1\t00C0A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n")
	c := New(cfg)

	if v, ok := metricValue(t, c, "node_host_agent_nebula_interface_up", nil); !ok || v != 1 {
		t.Fatalf("nebula_interface_up=%v ok=%v want 1", v, ok)
	}
	if v, ok := metricValue(t, c, "node_host_agent_nebula_route_present", nil); !ok || v != 1 {
		t.Fatalf("nebula_route_present=%v ok=%v want 1", v, ok)
	}
}

func TestNebulaDownNoRoute(t *testing.T) {
	cfg, dirs := fixture(t)
	iface := filepath.Join(dirs["sysnet"], "neb1")
	if err := os.MkdirAll(iface, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(iface, "operstate"), "down\n")
	testutil.WriteFile(t, cfg.RouteFile,
		"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"+
			"eth0\t00000000\t0102A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n")
	c := New(cfg)

	if v, ok := metricValue(t, c, "node_host_agent_nebula_interface_up", nil); !ok || v != 0 {
		t.Fatalf("nebula_interface_up=%v ok=%v want 0", v, ok)
	}
	if v, ok := metricValue(t, c, "node_host_agent_nebula_route_present", nil); !ok || v != 0 {
		t.Fatalf("nebula_route_present=%v ok=%v want 0", v, ok)
	}
}

func TestNebulaAbsent(t *testing.T) {
	cfg, _ := fixture(t)
	c := New(cfg)
	if _, ok := metricValue(t, c, "node_host_agent_nebula_interface_up", nil); ok {
		t.Fatal("nebula_interface_up emitted without interface")
	}
	if _, ok := metricValue(t, c, "node_host_agent_nebula_route_present", nil); ok {
		t.Fatal("nebula_route_present emitted without interface")
	}
}
