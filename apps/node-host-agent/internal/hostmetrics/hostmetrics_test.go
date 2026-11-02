package hostmetrics

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// fixture lays out the host filesystem tree under t.TempDir().
func fixture(t *testing.T) (Config, map[string]string) {
	t.Helper()
	root := t.TempDir()
	dirs := map[string]string{
		"state":   filepath.Join(root, "node-watchdog"),
		"sysnet":  filepath.Join(root, "net"),
		"k0s":     filepath.Join(root, "k0s"),
		"systemd": filepath.Join(root, "systemd", "system"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return Config{
		NodeName:         "node-a",
		WatchdogStateDir: dirs["state"],
		SysClassNet:      dirs["sysnet"],
		NebulaIface:      "neb1",
		RouteFile:        filepath.Join(root, "route"),
		K0sConfigFile:    filepath.Join(dirs["k0s"], "k0s.yaml"),
		K0sUnitFile:      filepath.Join(dirs["systemd"], "k0scontroller.service"),
	}, dirs
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// metricValue gathers the collector once and returns the value of the
// metric whose name and full label set match; ok=false if absent.
func metricValue(t *testing.T, c *Collector, name string,
	labels map[string]string) (float64, bool) {
	t.Helper()
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.Metric {
			if !matchLabels(m, labels) {
				continue
			}
			return m.GetGauge().GetValue(), true
		}
	}
	return 0, false
}

func matchLabels(m *dto.Metric, want map[string]string) bool {
	got := map[string]string{}
	for _, lp := range m.GetLabel() {
		got[lp.GetName()] = lp.GetValue()
	}
	if len(got) != len(want) {
		return false
	}
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}

func TestWatchdogStates(t *testing.T) {
	cfg, dirs := fixture(t)
	write(t, filepath.Join(dirs["state"], "state-kubelet-runtime-stall"), "1730000000\n")
	write(t, filepath.Join(dirs["state"], "state-node-overloaded"), "1730000001\n")
	write(t, filepath.Join(dirs["state"], "consecutive-x"), "3\n") // not a latch
	c := New(cfg)

	for _, st := range []string{"kubelet-runtime-stall", "node-overloaded"} {
		v, ok := metricValue(t, c, "node_host_agent_watchdog_state",
			map[string]string{"node": "node-a", "state": st})
		if !ok || v != 1 {
			t.Fatalf("watchdog_state{%s}=%v ok=%v want 1", st, v, ok)
		}
	}
	if _, ok := metricValue(t, c, "node_host_agent_watchdog_state",
		map[string]string{"node": "node-a", "state": "consecutive-x"}); ok {
		t.Fatal("non-latch file emitted a series")
	}
}

func TestWatchdogStateClearsToZero(t *testing.T) {
	cfg, dirs := fixture(t)
	latch := filepath.Join(dirs["state"], "state-dns-fallback")
	write(t, latch, "1730000000\n")
	c := New(cfg)
	_, _ = metricValue(t, c, "node_host_agent_watchdog_state",
		map[string]string{"node": "node-a", "state": "dns-fallback"})

	if err := os.Remove(latch); err != nil {
		t.Fatal(err)
	}
	v, ok := metricValue(t, c, "node_host_agent_watchdog_state",
		map[string]string{"node": "node-a", "state": "dns-fallback"})
	if !ok || v != 0 {
		t.Fatalf("cleared state=%v ok=%v want emitted 0 (emit-0 semantics)", v, ok)
	}
}

func TestNebulaUpWithRoute(t *testing.T) {
	cfg, dirs := fixture(t)
	iface := filepath.Join(dirs["sysnet"], "neb1")
	if err := os.MkdirAll(iface, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(iface, "operstate"), "up\n")
	write(t, cfg.RouteFile,
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
	write(t, filepath.Join(iface, "operstate"), "down\n")
	write(t, cfg.RouteFile,
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

func k0sDrift(t *testing.T, c *Collector) (float64, bool) {
	t.Helper()
	return metricValue(t, c, "node_k0s_config_drift", nil)
}

func TestK0sDriftRemovedFlag(t *testing.T) {
	cfg, _ := fixture(t)
	write(t, cfg.K0sUnitFile, "[Unit]\n")
	write(t, cfg.K0sConfigFile,
		"apiVersion: k0s.k0sproject.io/v1beta1\nkind: ClusterConfig\n"+
			"spec:\n  api:\n    extraArgs:\n      concurrent-service-syncs: \"5\"\n")
	if v, ok := k0sDrift(t, New(cfg)); !ok || v != 1 {
		t.Fatalf("drift=%v ok=%v want 1 (removed flag present)", v, ok)
	}
}

func TestK0sDriftMissingConfig(t *testing.T) {
	cfg, _ := fixture(t)
	write(t, cfg.K0sUnitFile, "[Unit]\n")
	// k0s.yaml absent → drift=1.
	if v, ok := k0sDrift(t, New(cfg)); !ok || v != 1 {
		t.Fatalf("drift=%v ok=%v want 1 (config missing)", v, ok)
	}
}

func TestK0sDriftUnparseable(t *testing.T) {
	cfg, _ := fixture(t)
	write(t, cfg.K0sUnitFile, "[Unit]\n")
	write(t, cfg.K0sConfigFile, "  {not: [valid: yaml\n")
	if v, ok := k0sDrift(t, New(cfg)); !ok || v != 1 {
		t.Fatalf("drift=%v ok=%v want 1 (unparseable)", v, ok)
	}
}

func TestK0sNoDriftCleanConfig(t *testing.T) {
	cfg, _ := fixture(t)
	write(t, cfg.K0sUnitFile, "[Unit]\n")
	write(t, cfg.K0sConfigFile,
		"apiVersion: k0s.k0sproject.io/v1beta1\nkind: ClusterConfig\nspec: {}\n")
	if v, ok := k0sDrift(t, New(cfg)); !ok || v != 0 {
		t.Fatalf("drift=%v ok=%v want 0 (clean config)", v, ok)
	}
}

func TestK0sMetricAbsentOnWorker(t *testing.T) {
	cfg, _ := fixture(t)
	// No k0scontroller.service → worker → no series even if config exists.
	write(t, cfg.K0sConfigFile, "spec:\n  concurrent-service-syncs: true\n")
	if v, ok := k0sDrift(t, New(cfg)); ok {
		t.Fatalf("node_k0s_config_drift=%v emitted on non-controller node", v)
	}
}

func TestApplyDefaults(t *testing.T) {
	c := New(Config{})
	if c.cfg.WatchdogStateDir != defaultWatchdogStateDir {
		t.Fatalf("WatchdogStateDir=%q want %q", c.cfg.WatchdogStateDir, defaultWatchdogStateDir)
	}
	if c.cfg.SysClassNet != defaultSysClassNet {
		t.Fatalf("SysClassNet=%q want %q", c.cfg.SysClassNet, defaultSysClassNet)
	}
	if c.cfg.NebulaIface != defaultNebulaIface {
		t.Fatalf("NebulaIface=%q want %q", c.cfg.NebulaIface, defaultNebulaIface)
	}
	if c.cfg.RouteFile != defaultRouteFile {
		t.Fatalf("RouteFile=%q want %q", c.cfg.RouteFile, defaultRouteFile)
	}
	if c.cfg.K0sConfigFile != defaultK0sConfigFile {
		t.Fatalf("K0sConfigFile=%q want %q", c.cfg.K0sConfigFile, defaultK0sConfigFile)
	}
	if c.cfg.K0sUnitFile != defaultK0sUnitFile {
		t.Fatalf("K0sUnitFile=%q want %q", c.cfg.K0sUnitFile, defaultK0sUnitFile)
	}
	if len(c.cfg.RemovedFlags) != 1 || c.cfg.RemovedFlags[0] != "concurrent-service-syncs" {
		t.Fatalf("RemovedFlags=%v want [concurrent-service-syncs]", c.cfg.RemovedFlags)
	}
}

func TestRemovedFlagsCustom(t *testing.T) {
	// A custom flag list replaces the default entirely — a config
	// carrying the default removed flag must not drift when the custom
	// list doesn't contain it.
	cfg, _ := fixture(t)
	write(t, cfg.K0sUnitFile, "[Unit]\n")
	write(t, cfg.K0sConfigFile,
		"spec:\n  api:\n    extraArgs:\n      concurrent-service-syncs: \"5\"\n")
	cfg.RemovedFlags = []string{"some-other-flag"}
	if v, ok := k0sDrift(t, New(cfg)); !ok || v != 0 {
		t.Fatalf("drift=%v ok=%v want 0 (custom flags keep concurrent-service-syncs ignored)", v, ok)
	}

	// And the custom flag itself is honoured.
	write(t, cfg.K0sConfigFile, "spec:\n  some-other-flag: true\n")
	if v, ok := k0sDrift(t, New(cfg)); !ok || v != 1 {
		t.Fatalf("drift=%v ok=%v want 1 (custom removed flag present)", v, ok)
	}
}

func TestDescribe(t *testing.T) {
	c := New(Config{})
	ch := make(chan *prometheus.Desc, 8)
	c.Describe(ch)
	if got := len(ch); got != 4 {
		t.Fatalf("Describe emitted %d descs want 4", got)
	}
}

func TestWatchdogSkipsNonRegularAndEmptyNames(t *testing.T) {
	cfg, dirs := fixture(t)
	// A directory named state-* is not a latch file — skipped by the
	// IsRegular guard.
	if err := os.MkdirAll(filepath.Join(dirs["state"], "state-dir-latch"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A file named exactly "state-" has an empty latch name — skipped.
	write(t, filepath.Join(dirs["state"], "state-"), "1730000000\n")
	// A real latch alongside — still collected.
	write(t, filepath.Join(dirs["state"], "state-real"), "1730000000\n")
	c := New(cfg)

	if v, ok := metricValue(t, c, "node_host_agent_watchdog_state",
		map[string]string{"node": "node-a", "state": "real"}); !ok || v != 1 {
		t.Fatalf("watchdog_state{real}=%v ok=%v want 1", v, ok)
	}
	if _, ok := metricValue(t, c, "node_host_agent_watchdog_state",
		map[string]string{"node": "node-a", "state": "dir-latch"}); ok {
		t.Fatal("directory named state-* emitted a series")
	}
	if _, ok := metricValue(t, c, "node_host_agent_watchdog_state",
		map[string]string{"node": "node-a", "state": ""}); ok {
		t.Fatal("file named 'state-' emitted a series")
	}
}

func TestWatchdogStateDirAbsentStillEmitsSeen(t *testing.T) {
	// If the state dir disappears (node-watchdog removed), a
	// previously-seen latch keeps exporting 0 — ReadDir error is
	// tolerated, not fatal.
	cfg, dirs := fixture(t)
	latch := filepath.Join(dirs["state"], "state-net-fail")
	write(t, latch, "1730000000\n")
	c := New(cfg)
	_, _ = metricValue(t, c, "node_host_agent_watchdog_state",
		map[string]string{"node": "node-a", "state": "net-fail"})

	if err := os.RemoveAll(dirs["state"]); err != nil {
		t.Fatal(err)
	}
	v, ok := metricValue(t, c, "node_host_agent_watchdog_state",
		map[string]string{"node": "node-a", "state": "net-fail"})
	if !ok || v != 0 {
		t.Fatalf("watchdog_state after dir removal=%v ok=%v want 0", v, ok)
	}
}
