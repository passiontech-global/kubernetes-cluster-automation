package hostmetrics

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"golang.org/x/sys/unix"
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
		"proc":    filepath.Join(root, "proc"),
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
		NebulaCertFile:   filepath.Join(root, "host.crt"),
		// Deliberately nonexistent: the real /proc/pressure/cpu would
		// feed live data into the overload hysteresis and rewrite
		// test-managed latches.
		PSIFile: filepath.Join(root, "no-such-psi"),
		// Never re-measure during unrelated tests — the real
		// busy-loop only runs where a test injects cpuMeasure.
		CPUDeliveredInterval: 24 * time.Hour,
		// Deliberately nonexistent: the real /proc files would feed
		// live host data into the scrapes. Tests that exercise a
		// source write their own fake file under root.
		ConntrackCountFile: filepath.Join(root, "nf_conntrack_count"),
		ConntrackMaxFile:   filepath.Join(root, "nf_conntrack_max"),
		FileNRFile:         filepath.Join(root, "file-nr"),
		SockstatFile:       filepath.Join(root, "sockstat"),
		FilesystemTargets:  []string{"/fake/etc", "/fake/k0s"},
		// Wave-2 sources under root — never the real /proc or /sys:
		// an fdinfo/zombie sweep of the live host would leak real
		// series into the scrape assertions.
		ProcRoot:                filepath.Join(root, "proc"),
		HostRoot:                filepath.Join(root, "hostroot"),
		InotifyMaxInstancesFile: filepath.Join(root, "max_user_instances"),
		InotifyMaxWatchesFile:   filepath.Join(root, "max_user_watches"),
		InotifyScanInterval:     60 * time.Second,
		CgroupRoot:              filepath.Join(root, "cgroup"),
		CiliumRuntimeConfig:     filepath.Join(root, "agent-runtime-config.json"),
		PKICertPaths:            []string{filepath.Join(root, "pki")},
		// Default stub: returns no result — the real 0.3 cpu-s
		// busy-loop would otherwise spin once per collector instance
		// (~20 concurrent goroutines during a suite run).
		cpuMeasure: func() (float64, float64, bool) { return 0, 0, false },
		// Default stubs keep unrelated scrapes hermetic — the real
		// adjtimex/statfs would feed live host data into assertions.
		adjtimexFn: func(*unix.Timex) (int, error) { return 0, unix.ENOSYS },
		statfsFn:   func(string, *unix.Statfs_t) error { return unix.ENOENT },
		// Never wait the real 2s in tests — the stall tests inject
		// their own hanging statfsFn against this shortened deadline.
		fsProbeTimeout: 50 * time.Millisecond,
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

// TestSeenStatesTTLExpiry: a cleared latch emits 0 while inside
// seenStateTTL, then the bookkeeping entry is dropped and the series
// disappears — the emit-0 window cannot grow seenStates forever.
func TestSeenStatesTTLExpiry(t *testing.T) {
	cfg, dirs := fixture(t)
	now := time.Now()
	cfg.nowFn = func() time.Time { return now }
	latch := filepath.Join(dirs["state"], "state-tmp-latch")
	write(t, latch, "1730000000\n")
	c := New(cfg)
	labels := map[string]string{"node": "node-a", "state": "tmp-latch"}

	if v, ok := metricValue(t, c, "node_host_agent_watchdog_state", labels); !ok || v != 1 {
		t.Fatalf("latched state=%v ok=%v want 1", v, ok)
	}
	if err := os.Remove(latch); err != nil {
		t.Fatal(err)
	}
	// First cleared scrape stamps the entry — still emits 0.
	if v, ok := metricValue(t, c, "node_host_agent_watchdog_state", labels); !ok || v != 0 {
		t.Fatalf("cleared state=%v ok=%v want emitted 0", v, ok)
	}
	// Inside the TTL the emit-0 contract still holds.
	now = now.Add(seenStateTTL - time.Minute)
	if _, ok := metricValue(t, c, "node_host_agent_watchdog_state", labels); !ok {
		t.Fatal("series dropped before seenStateTTL elapsed")
	}
	// Past the TTL the entry is evicted and the series disappears.
	now = now.Add(2 * time.Minute)
	if _, ok := metricValue(t, c, "node_host_agent_watchdog_state", labels); ok {
		t.Fatal("series kept after seenStateTTL elapsed")
	}
	if _, ok := c.seenStates["tmp-latch"]; ok {
		t.Fatal("expired cleared state kept in seenStates")
	}
}

// TestSeenStatesCapEvictsOldestCleared: beyond maxSeenStates the
// longest-cleared entries are evicted first; an active latch is
// never evicted.
func TestSeenStatesCapEvictsOldestCleared(t *testing.T) {
	cfg, dirs := fixture(t)
	now := time.Now()
	cfg.nowFn = func() time.Time { return now }
	write(t, filepath.Join(dirs["state"], "state-real"), "1730000000\n")
	c := New(cfg)
	// Pre-seed over-cap cleared entries, oldest first.
	for i := 0; i < maxSeenStates+10; i++ {
		c.seenStates[fmt.Sprintf("old-%03d", i)] = now.Add(-time.Duration(i+1) * time.Second)
	}
	labels := map[string]string{"node": "node-a", "state": "real"}
	if v, ok := metricValue(t, c, "node_host_agent_watchdog_state", labels); !ok || v != 1 {
		t.Fatalf("latched state=%v ok=%v want 1", v, ok)
	}
	if got := len(c.seenStates); got > maxSeenStates {
		t.Fatalf("seenStates = %d, want <= %d", got, maxSeenStates)
	}
	if ts, ok := c.seenStates["real"]; !ok || !ts.IsZero() {
		t.Fatal("active latch missing or got a cleared timestamp")
	}
	// The oldest-cleared entries must have been evicted.
	if _, ok := c.seenStates[fmt.Sprintf("old-%03d", maxSeenStates+9)]; ok {
		t.Fatal("oldest cleared entry was not evicted")
	}
	if _, ok := c.seenStates["old-000"]; !ok {
		t.Fatal("freshest cleared entry was evicted")
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

func k0sDrift(t *testing.T, c *Collector, reason, key string) (float64, bool) {
	t.Helper()
	return metricValue(t, c, "node_k0s_config_drift",
		map[string]string{"reason": reason, "key": key})
}

// k0sCleanYAML renders a k0s.yaml whose controllerManager.extraArgs
// matches the default ExpectedKCMArgs exactly — the only shape that
// produces zero missing-key findings.
func k0sCleanYAML(extraKeys ...string) string {
	var b strings.Builder
	b.WriteString("apiVersion: k0s.k0sproject.io/v1beta1\n" +
		"kind: ClusterConfig\nspec:\n  controllerManager:\n    extraArgs:\n")
	for _, k := range defaultExpectedKCMArgs {
		b.WriteString("      " + k + ": \"5\"\n")
	}
	for _, k := range extraKeys {
		b.WriteString("      " + k + ": \"9\"\n")
	}
	return b.String()
}

func TestK0sDriftRemovedFlag(t *testing.T) {
	cfg, _ := fixture(t)
	write(t, cfg.K0sUnitFile, "[Unit]\n")
	write(t, cfg.K0sConfigFile,
		"apiVersion: k0s.k0sproject.io/v1beta1\nkind: ClusterConfig\n"+
			"spec:\n  api:\n    extraArgs:\n      concurrent-service-syncs: \"5\"\n")
	if v, ok := k0sDrift(t, New(cfg), "removed-flag", "concurrent-service-syncs"); !ok || v != 1 {
		t.Fatalf("removed-flag=%v ok=%v want 1 (removed flag present)", v, ok)
	}
}

func TestK0sDriftMissingConfig(t *testing.T) {
	cfg, _ := fixture(t)
	write(t, cfg.K0sUnitFile, "[Unit]\n")
	// k0s.yaml absent → unreadable finding (drift=1 under the new schema).
	if v, ok := k0sDrift(t, New(cfg), "unreadable", "k0s.yaml"); !ok || v != 1 {
		t.Fatalf("unreadable=%v ok=%v want 1 (config missing)", v, ok)
	}
}

func TestK0sDriftUnparseable(t *testing.T) {
	cfg, _ := fixture(t)
	write(t, cfg.K0sUnitFile, "[Unit]\n")
	write(t, cfg.K0sConfigFile, "  {not: [valid: yaml\n")
	if v, ok := k0sDrift(t, New(cfg), "unreadable", "k0s.yaml"); !ok || v != 1 {
		t.Fatalf("unreadable=%v ok=%v want 1 (unparseable)", v, ok)
	}
}

func TestK0sNoDriftCleanConfig(t *testing.T) {
	cfg, _ := fixture(t)
	write(t, cfg.K0sUnitFile, "[Unit]\n")
	write(t, cfg.K0sConfigFile, k0sCleanYAML())
	if v, ok := k0sDrift(t, New(cfg), "none", "none"); !ok || v != 0 {
		t.Fatalf("none=%v ok=%v want 0 (clean config)", v, ok)
	}
}

func TestK0sDriftMissingKey(t *testing.T) {
	cfg, _ := fixture(t)
	write(t, cfg.K0sUnitFile, "[Unit]\n")
	// An empty extraArgs block → every expected KCM key is missing.
	write(t, cfg.K0sConfigFile,
		"apiVersion: k0s.k0sproject.io/v1beta1\nkind: ClusterConfig\n"+
			"spec:\n  controllerManager:\n    extraArgs: {}\n")
	c := New(cfg)
	if v, ok := k0sDrift(t, c, "missing-key", "kube-api-qps"); !ok || v != 1 {
		t.Fatalf("missing-key=%v ok=%v want 1", v, ok)
	}
	if _, ok := k0sDrift(t, c, "none", "none"); ok {
		t.Fatal("none series emitted alongside findings")
	}
}

func TestK0sDriftExtraKey(t *testing.T) {
	cfg, _ := fixture(t)
	write(t, cfg.K0sUnitFile, "[Unit]\n")
	write(t, cfg.K0sConfigFile, k0sCleanYAML("bogus-extra-flag"))
	if v, ok := k0sDrift(t, New(cfg), "extra-key", "bogus-extra-flag"); !ok || v != 1 {
		t.Fatalf("extra-key=%v ok=%v want 1", v, ok)
	}
}

func TestK0sDriftRemovedFlagNotDoubleCounted(t *testing.T) {
	cfg, _ := fixture(t)
	write(t, cfg.K0sUnitFile, "[Unit]\n")
	// The removed flag sits INSIDE controllerManager.extraArgs: it
	// must report as removed-flag only, not also as extra-key.
	write(t, cfg.K0sConfigFile, k0sCleanYAML("concurrent-service-syncs"))
	c := New(cfg)
	if v, ok := k0sDrift(t, c, "removed-flag", "concurrent-service-syncs"); !ok || v != 1 {
		t.Fatalf("removed-flag=%v ok=%v want 1", v, ok)
	}
	if _, ok := k0sDrift(t, c, "extra-key", "concurrent-service-syncs"); ok {
		t.Fatal("removed flag double-reported as extra-key")
	}
}

func TestK0sMetricAbsentOnWorker(t *testing.T) {
	cfg, _ := fixture(t)
	// No k0scontroller.service → worker → no series even if config exists.
	write(t, cfg.K0sConfigFile, "spec:\n  concurrent-service-syncs: true\n")
	c := New(cfg)
	for _, r := range []string{"removed-flag", "missing-key", "unreadable", "none"} {
		key := "x"
		if r == "unreadable" {
			key = "k0s.yaml"
		} else if r == "none" {
			key = "none"
		}
		if v, ok := k0sDrift(t, c, r, key); ok {
			t.Fatalf("node_k0s_config_drift{reason=%s}=%v emitted on non-controller node", r, v)
		}
	}
}

func TestWatchdogTmpStateFileIgnored(t *testing.T) {
	cfg, dirs := fixture(t)
	// The atomic-write tmp name ".tmp-state-x" (apiprober's
	// writeFileAtomic, workerhygiene's stateEnter) must NOT register
	// a watchdog_state series — the old "state-x.tmp" shape would
	// have cut to a phantom "x.tmp" latch that then sits at 0 forever.
	write(t, filepath.Join(dirs["state"], ".tmp-state-atomic"), "1730000000\n")
	write(t, filepath.Join(dirs["state"], "state-real"), "1730000000\n")
	c := New(cfg)

	if v, ok := metricValue(t, c, "node_host_agent_watchdog_state",
		map[string]string{"node": "node-a", "state": "real"}); !ok || v != 1 {
		t.Fatalf("watchdog_state{real}=%v ok=%v want 1", v, ok)
	}
	for _, st := range []string{"atomic", ".tmp-state-atomic", "state-atomic"} {
		if _, ok := metricValue(t, c, "node_host_agent_watchdog_state",
			map[string]string{"node": "node-a", "state": st}); ok {
			t.Fatalf("tmp file emitted watchdog_state{state=%s}", st)
		}
	}
}

func TestK0sDriftDuplicateRemovedFlagsDeduped(t *testing.T) {
	// A duplicated flag in the config list must emit ONE finding —
	// the precompiled map keys dedupe. Duplicate identical series
	// would make prometheus Gather fail outright (metricValue's
	// Gather → t.Fatal covers that).
	cfg, _ := fixture(t)
	write(t, cfg.K0sUnitFile, "[Unit]\n")
	write(t, cfg.K0sConfigFile, k0sCleanYAML("concurrent-service-syncs"))
	cfg.RemovedFlags = []string{"concurrent-service-syncs", "concurrent-service-syncs"}
	c := New(cfg)
	if v, ok := k0sDrift(t, c, "removed-flag", "concurrent-service-syncs"); !ok || v != 1 {
		t.Fatalf("removed-flag=%v ok=%v want 1 (single finding)", v, ok)
	}
}

// bumpMtime forces a distinct mtime so the k0s.yaml stat cache sees
// the file as changed — same-second writes can alias otherwise.
func bumpMtime(t *testing.T, path string) {
	t.Helper()
	mt := time.Now().Add(time.Hour)
	if err := os.Chtimes(path, mt, mt); err != nil {
		t.Fatal(err)
	}
}

func TestK0sConfigCacheRevalidates(t *testing.T) {
	cfg, _ := fixture(t)
	write(t, cfg.K0sUnitFile, "[Unit]\n")
	write(t, cfg.K0sConfigFile, k0sCleanYAML())
	c := New(cfg)

	// First scrape loads the file; unchanged mtime+size would serve
	// the cache — findings stay consistent across scrapes.
	if v, ok := k0sDrift(t, c, "none", "none"); !ok || v != 0 {
		t.Fatalf("clean config none=%v ok=%v want 0", v, ok)
	}
	if v, ok := k0sDrift(t, c, "none", "none"); !ok || v != 0 {
		t.Fatalf("second scrape none=%v ok=%v want 0", v, ok)
	}

	// Content change + bumped mtime → the next scrape re-reads.
	write(t, cfg.K0sConfigFile, k0sCleanYAML("bogus-extra-flag"))
	bumpMtime(t, cfg.K0sConfigFile)
	if v, ok := k0sDrift(t, c, "extra-key", "bogus-extra-flag"); !ok || v != 1 {
		t.Fatalf("extra-key=%v ok=%v want 1 after config change", v, ok)
	}

	// File gone → unreadable finding, never a stale cached parse.
	if err := os.Remove(cfg.K0sConfigFile); err != nil {
		t.Fatal(err)
	}
	if v, ok := k0sDrift(t, c, "unreadable", "k0s.yaml"); !ok || v != 1 {
		t.Fatalf("unreadable=%v ok=%v want 1 after file removal", v, ok)
	}

	// Restored → findings track the new file again.
	write(t, cfg.K0sConfigFile, k0sCleanYAML())
	bumpMtime(t, cfg.K0sConfigFile)
	if v, ok := k0sDrift(t, c, "none", "none"); !ok || v != 0 {
		t.Fatalf("restored config none=%v ok=%v want 0", v, ok)
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
	if c.cfg.NebulaCertFile != defaultNebulaCertFile {
		t.Fatalf("NebulaCertFile=%q want %q", c.cfg.NebulaCertFile, defaultNebulaCertFile)
	}
	if len(c.cfg.ExpectedKCMArgs) != len(defaultExpectedKCMArgs) {
		t.Fatalf("ExpectedKCMArgs=%v want defaults", c.cfg.ExpectedKCMArgs)
	}
	if c.cfg.ConntrackCountFile != defaultConntrackCountFile {
		t.Fatalf("ConntrackCountFile=%q want %q", c.cfg.ConntrackCountFile, defaultConntrackCountFile)
	}
	if c.cfg.ConntrackMaxFile != defaultConntrackMaxFile {
		t.Fatalf("ConntrackMaxFile=%q want %q", c.cfg.ConntrackMaxFile, defaultConntrackMaxFile)
	}
	if c.cfg.FileNRFile != defaultFileNRFile {
		t.Fatalf("FileNRFile=%q want %q", c.cfg.FileNRFile, defaultFileNRFile)
	}
	if c.cfg.SockstatFile != defaultSockstatFile {
		t.Fatalf("SockstatFile=%q want %q", c.cfg.SockstatFile, defaultSockstatFile)
	}
	if len(c.cfg.FilesystemTargets) != len(defaultFilesystemTargets) {
		t.Fatalf("FilesystemTargets=%v want defaults", c.cfg.FilesystemTargets)
	}
	if c.cfg.adjtimexFn == nil {
		t.Fatal("adjtimexFn not defaulted to unix.Adjtimex")
	}
	if c.cfg.statfsFn == nil {
		t.Fatal("statfsFn not defaulted to unix.Statfs")
	}
	if c.cfg.fsProbeTimeout != defaultFSProbeTimeout {
		t.Fatalf("fsProbeTimeout=%v want %v", c.cfg.fsProbeTimeout, defaultFSProbeTimeout)
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
	if _, ok := k0sDrift(t, New(cfg), "removed-flag", "concurrent-service-syncs"); ok {
		t.Fatal("default removed flag reported despite custom list")
	}

	// And the custom flag itself is honoured.
	write(t, cfg.K0sConfigFile, "spec:\n  some-other-flag: true\n")
	if v, ok := k0sDrift(t, New(cfg), "removed-flag", "some-other-flag"); !ok || v != 1 {
		t.Fatalf("removed-flag=%v ok=%v want 1 (custom removed flag present)", v, ok)
	}
}

func TestDescribe(t *testing.T) {
	c := New(Config{})
	ch := make(chan *prometheus.Desc, 64)
	c.Describe(ch)
	// 10 base descs + the 2 legacy prom_emit aliases
	// (node_watchdog_state, node_watchdog_egress_relay) + 16
	// gray-failure telemetry descs (H1/H2/H3/H6/H7) + 7 W7 descs
	// (dstate, systemd scopes, conntrack insert_failed/drop, arp,
	// cgroup memory high/oom_kill).
	// + 2 W8 descs (kernel-keys ratio, sockstat tcp close_wait).
	if got := len(ch); got != 50 {
		t.Fatalf("Describe emitted %d descs want 50", got)
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

// --- nebula cert expiry ---

// pbVarint, pbTag, pbLenField, pbVarField hand-encode the protobuf
// wire fields the parser reads — keeps the test independent of a
// real nebula-cert binary while exercising the same wire shape:
// NebulaCertificate{Details(field 1, LEN)=details, Signature(2)},
// details{...,NotAfter(field 6, varint)}.
func pbVarint(v uint64) []byte {
	var b []byte
	for {
		c := byte(v & 0x7f)
		v >>= 7
		if v == 0 {
			return append(b, c)
		}
		b = append(b, c|0x80)
	}
}

func pbTag(field, wire int) []byte {
	return pbVarint(uint64(field<<3 | wire))
}

func pbLenField(field int, payload []byte) []byte {
	out := append(pbTag(field, 2), pbVarint(uint64(len(payload)))...)
	return append(out, payload...)
}

func pbVarField(field int, v uint64) []byte {
	return append(pbTag(field, 0), pbVarint(v)...)
}

// nebulaCertPEM builds a PEM "NEBULA CERTIFICATE" blob carrying
// notAfter — structurally identical to what nebula-cert writes.
func nebulaCertPEM(notAfter int64) []byte {
	var details []byte
	details = append(details, pbLenField(1, []byte("node-a"))...)
	details = append(details, pbVarField(5, 1_700_000_000)...)    // NotBefore
	details = append(details, pbVarField(6, uint64(notAfter))...) // NotAfter
	details = append(details, pbLenField(7, []byte{0xde, 0xad, 0xbe, 0xef})...)
	var cert []byte
	cert = append(cert, pbLenField(1, details)...)
	cert = append(cert, pbLenField(2, []byte{0x01, 0x02, 0x03})...)
	return pem.EncodeToMemory(&pem.Block{Type: "NEBULA CERTIFICATE", Bytes: cert})
}

func TestNebulaCertNotAfterParse(t *testing.T) {
	var details []byte
	details = append(details, pbLenField(1, []byte("x"))...)
	details = append(details, pbVarField(6, 1_800_000_000)...)
	cert := append(pbLenField(1, details), pbLenField(2, []byte{9})...)
	if got, ok := nebulaCertNotAfter(cert); !ok || got != 1_800_000_000 {
		t.Fatalf("nebulaCertNotAfter=%d,%v want 1800000000,true", got, ok)
	}
}

func TestNebulaCertNotAfterRejectsGarbage(t *testing.T) {
	cases := map[string][]byte{
		"empty":           {},
		"truncated tag":   {0x80},
		"details no f6":   append(pbLenField(1, pbLenField(1, []byte("x"))), pbLenField(2, []byte{1})...),
		"truncated len":   append(pbTag(1, 2), 0x7f, 0x01), // declared len beyond payload
		"bad wire in top": append(append(pbTag(1, 3), 0x01), pbLenField(2, []byte{1})...),
		"details f6 len":  pbLenField(1, append(pbTag(6, 2), 0x01, 0x00)), // f6 as LEN not varint
	}
	for name, der := range cases {
		if _, ok := nebulaCertNotAfter(der); ok {
			t.Fatalf("nebulaCertNotAfter(%s) want ok=false", name)
		}
	}
}

func TestNebulaCertDaysLeftMetric(t *testing.T) {
	cfg, _ := fixture(t)
	notAfter := time.Now().Unix() + 10*86400 + 3600 // ~10 days → <30 → expiring
	if err := os.WriteFile(cfg.NebulaCertFile, nebulaCertPEM(notAfter), 0o644); err != nil {
		t.Fatal(err)
	}
	c := New(cfg)
	if v, ok := metricValue(t, c, "node_host_agent_nebula_cert_days_left", nil); !ok || v != 10 {
		t.Fatalf("cert_days_left=%v ok=%v want 10", v, ok)
	}
	if v, ok := metricValue(t, c, "node_host_agent_watchdog_state",
		map[string]string{"node": "node-a", "state": "nebula-cert-expiring"}); !ok || v != 1 {
		t.Fatalf("cert-expiring state=%v ok=%v want 1", v, ok)
	}
}

func TestNebulaCertHealthyEmitsZero(t *testing.T) {
	cfg, _ := fixture(t)
	notAfter := time.Now().Unix() + 90*86400 // ~90 days → no expiring
	if err := os.WriteFile(cfg.NebulaCertFile, nebulaCertPEM(notAfter), 0o644); err != nil {
		t.Fatal(err)
	}
	c := New(cfg)
	if v, ok := metricValue(t, c, "node_host_agent_nebula_cert_days_left", nil); !ok || v != 90 {
		t.Fatalf("cert_days_left=%v ok=%v want 90", v, ok)
	}
	// Alert contract: explicit 0 once the cert was readable.
	if v, ok := metricValue(t, c, "node_host_agent_watchdog_state",
		map[string]string{"node": "node-a", "state": "nebula-cert-expiring"}); !ok || v != 0 {
		t.Fatalf("cert-expiring state=%v ok=%v want emitted 0", v, ok)
	}
}

func TestNebulaCertAbsentEmitsNothing(t *testing.T) {
	cfg, _ := fixture(t)
	c := New(cfg)
	if _, ok := metricValue(t, c, "node_host_agent_nebula_cert_days_left", nil); ok {
		t.Fatal("cert_days_left emitted without cert")
	}
	if _, ok := metricValue(t, c, "node_host_agent_watchdog_state",
		map[string]string{"node": "node-a", "state": "nebula-cert-expiring"}); ok {
		t.Fatal("cert-expiring emitted though the cert was never readable")
	}
}

func TestNebulaCertUnparseableEmitsNothing(t *testing.T) {
	cfg, _ := fixture(t)
	write(t, cfg.NebulaCertFile, "-----BEGIN NEBULA CERTIFICATE-----\nnot-base64!!!\n-----END NEBULA CERTIFICATE-----\n")
	c := New(cfg)
	if _, ok := metricValue(t, c, "node_host_agent_nebula_cert_days_left", nil); ok {
		t.Fatal("cert_days_left emitted for garbage PEM")
	}
}

func TestNebulaCertStatePersistsZeroAfterRemoval(t *testing.T) {
	cfg, _ := fixture(t)
	notAfter := time.Now().Unix() + 10*86400
	if err := os.WriteFile(cfg.NebulaCertFile, nebulaCertPEM(notAfter), 0o644); err != nil {
		t.Fatal(err)
	}
	c := New(cfg)
	// First scrape registers the state (value 1 while expiring).
	if v, ok := metricValue(t, c, "node_host_agent_watchdog_state",
		map[string]string{"node": "node-a", "state": "nebula-cert-expiring"}); !ok || v != 1 {
		t.Fatalf("cert-expiring=%v ok=%v want 1", v, ok)
	}
	// Cert vanishes — the seenStates bookkeeping must keep the
	// series alive at 0 (auto-resolve), not drop it.
	if err := os.Remove(cfg.NebulaCertFile); err != nil {
		t.Fatal(err)
	}
	v, ok := metricValue(t, c, "node_host_agent_watchdog_state",
		map[string]string{"node": "node-a", "state": "nebula-cert-expiring"})
	if !ok || v != 0 {
		t.Fatalf("cert-expiring after removal=%v ok=%v want emitted 0", v, ok)
	}
	if _, ok := metricValue(t, c, "node_host_agent_nebula_cert_days_left", nil); ok {
		t.Fatal("cert_days_left emitted after cert removal")
	}
}

// --- PSI overload (runner's node-overloaded) ---

func TestPSIGaugeAndOverloadLatch(t *testing.T) {
	cfg, dirs := fixture(t)
	cfg.PSIFile = filepath.Join(t.TempDir(), "cpu")
	c := New(cfg)

	write(t, cfg.PSIFile, "some avg10=10.00 avg60=45.50 avg300=20.00 total=123\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
	v, ok := metricValue(t, c, "node_watchdog_psi_cpu_some_avg60", map[string]string{})
	if !ok || v != 45.5 {
		t.Fatalf("psi=%v,%v want 45.5", v, ok)
	}
	latch := filepath.Join(dirs["state"], "state-node-overloaded")
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("overload latch not created at avg60>=40: %v", err)
	}
	// Hysteresis: 30% is between 40/25 — latch persists.
	write(t, cfg.PSIFile, "some avg10=5.00 avg60=30.00 avg300=10.00 total=9\n")
	metricValue(t, c, "node_watchdog_psi_cpu_some_avg60", map[string]string{})
	if _, err := os.Stat(latch); err != nil {
		t.Fatal("latch dropped inside hysteresis band")
	}
	// Below 25 → released.
	write(t, cfg.PSIFile, "some avg10=1.00 avg60=20.00 avg300=5.00 total=4\n")
	metricValue(t, c, "node_watchdog_psi_cpu_some_avg60", map[string]string{})
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("latch kept below the 25% release threshold")
	}
}

func TestPSIUnreadableKeepsLatch(t *testing.T) {
	cfg, dirs := fixture(t)
	cfg.PSIFile = filepath.Join(t.TempDir(), "missing")
	latch := filepath.Join(dirs["state"], "state-node-overloaded")
	write(t, latch, "1\n")
	c := New(cfg)
	if _, ok := metricValue(t, c, "node_watchdog_psi_cpu_some_avg60",
		map[string]string{}); ok {
		t.Fatal("psi gauge emitted with unreadable PSI file")
	}
	// Inconclusive read → existing latch kept.
	if _, err := os.Stat(latch); err != nil {
		t.Fatal("latch dropped on unreadable PSI")
	}
}

// --- cpu-delivered probe ---

func TestCPUDeliveredEmitsAfterMeasure(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.CPUDeliveredInterval = time.Minute
	c := New(cfg)
	c.cfg.nowFn = func() time.Time { return time.Unix(1000, 0) }
	c.cfg.cpuMeasure = func() (float64, float64, bool) { return 0.95, 0.32, true }

	// First scrape: probe launched async — wait for it.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if v, ok := metricValue(t, c, "node_cpu_delivered_ratio",
			map[string]string{}); ok {
			if v != 0.95 {
				t.Fatalf("ratio=%v want 0.95", v)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cpu delivered ratio never emitted")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if v, ok := metricValue(t, c, "node_cpu_delivered_probe_wall_seconds",
		map[string]string{}); !ok || v != 0.32 {
		t.Fatalf("wall=%v,%v want 0.32", v, ok)
	}
}

func TestCPUDeliveredAbsentBeforeMeasure(t *testing.T) {
	cfg, _ := fixture(t)
	c := New(cfg)
	// Blocked forever — no result, and the scrape still completes.
	c.cfg.cpuMeasure = func() (float64, float64, bool) {
		select {} // never returns — simulates a probe still running
	}
	if _, ok := metricValue(t, c, "node_cpu_delivered_ratio",
		map[string]string{}); ok {
		t.Fatal("ratio emitted before first completed measurement")
	}
}

// --- fail2ban banned counts ---

func TestFail2banBannedMetric(t *testing.T) {
	cfg, dirs := fixture(t)
	write(t, filepath.Join(dirs["state"], "fail2ban-banned"), "sshd=7 recidive=1\n")
	c := New(cfg)
	v, ok := metricValue(t, c, "node_fail2ban_banned_ips",
		map[string]string{"jail": "sshd"})
	if !ok || v != 7 {
		t.Fatalf("sshd=%v,%v want 7", v, ok)
	}
	if v, ok := metricValue(t, c, "node_fail2ban_banned_ips",
		map[string]string{"jail": "recidive"}); !ok || v != 1 {
		t.Fatalf("recidive=%v,%v want 1", v, ok)
	}
}

func TestFail2banAbsentWithoutFile(t *testing.T) {
	cfg, _ := fixture(t)
	c := New(cfg)
	if _, ok := metricValue(t, c, "node_fail2ban_banned_ips",
		map[string]string{"jail": "sshd"}); ok {
		t.Fatal("banned metric emitted without the file (fake 0)")
	}
}

// --- egress relay gauge ---

func TestEgressRelayGauge(t *testing.T) {
	cfg, dirs := fixture(t)
	cfg.EgressRelays = []string{"8.8.8.8", "1.1.1.1"}
	write(t, filepath.Join(dirs["state"], "egress-state-8.8.8.8"), "relay\n")
	write(t, filepath.Join(dirs["state"], "egress-state-1.1.1.1"), "direct\n")
	c := New(cfg)
	if v, ok := metricValue(t, c, "node_overlay_egress_relay_active",
		map[string]string{"target": "8.8.8.8"}); !ok || v != 1 {
		t.Fatalf("relay=%v,%v want 1", v, ok)
	}
	// Explicit 0 while direct — series always emitted per target.
	if v, ok := metricValue(t, c, "node_overlay_egress_relay_active",
		map[string]string{"target": "1.1.1.1"}); !ok || v != 0 {
		t.Fatalf("direct=%v,%v want 0", v, ok)
	}
}

// --- legacy prom_emit aliases (node_watchdog_state /
// node_watchdog_egress_relay — the fluxcd PrometheusRules contract) ---

func TestWatchdogLegacyAlias(t *testing.T) {
	cfg, dirs := fixture(t)
	write(t, filepath.Join(dirs["state"], "state-fail2ban-down"), "1730000000\n")
	c := New(cfg)

	// Alias mirrors the latch with signal=state (no node label).
	if v, ok := metricValue(t, c, "node_watchdog_state",
		map[string]string{"signal": "fail2ban-down"}); !ok || v != 1 {
		t.Fatalf("node_watchdog_state{fail2ban-down}=%v ok=%v want 1", v, ok)
	}
	// Same latch, both series live alongside each other.
	if v, ok := metricValue(t, c, "node_host_agent_watchdog_state",
		map[string]string{"node": "node-a", "state": "fail2ban-down"}); !ok || v != 1 {
		t.Fatalf("node_host_agent_watchdog_state=%v ok=%v want 1", v, ok)
	}

	// Cleared latch → the alias keeps emitting an explicit 0, same
	// emit-0 contract as the primary series.
	if err := os.Remove(filepath.Join(dirs["state"], "state-fail2ban-down")); err != nil {
		t.Fatal(err)
	}
	if v, ok := metricValue(t, c, "node_watchdog_state",
		map[string]string{"signal": "fail2ban-down"}); !ok || v != 0 {
		t.Fatalf("node_watchdog_state{fail2ban-down}=%v ok=%v want 0 after clear", v, ok)
	}
}

func TestEgressRelayLegacyAlias(t *testing.T) {
	cfg, dirs := fixture(t)
	cfg.EgressRelays = []string{"8.8.8.8", "1.1.1.1"}
	write(t, filepath.Join(dirs["state"], "egress-state-8.8.8.8"), "relay\n")
	write(t, filepath.Join(dirs["state"], "egress-state-1.1.1.1"), "direct\n")
	c := New(cfg)

	if v, ok := metricValue(t, c, "node_watchdog_egress_relay",
		map[string]string{"target": "8.8.8.8"}); !ok || v != 1 {
		t.Fatalf("node_watchdog_egress_relay{8.8.8.8}=%v ok=%v want 1", v, ok)
	}
	if v, ok := metricValue(t, c, "node_watchdog_egress_relay",
		map[string]string{"target": "1.1.1.1"}); !ok || v != 0 {
		t.Fatalf("node_watchdog_egress_relay{1.1.1.1}=%v ok=%v want 0", v, ok)
	}
}

// --- WriteTextfile (standalone prom_emit port) ---

func TestWriteTextfile(t *testing.T) {
	cfg, dirs := fixture(t)
	cfg.EgressRelays = []string{"8.8.8.8"}
	write(t, filepath.Join(dirs["state"], "state-fail2ban-down"), "1730000000\n")
	write(t, filepath.Join(dirs["state"], "egress-state-8.8.8.8"), "relay\n")
	c := New(cfg)

	dir := filepath.Join(t.TempDir(), "textfile")
	if err := c.WriteTextfile(dir); err != nil {
		t.Fatalf("WriteTextfile: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "node-watchdog.prom"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		"# HELP node_watchdog_state ",
		"# TYPE node_watchdog_state gauge",
		`node_watchdog_state{signal="fail2ban-down"} 1`,
		`node_host_agent_watchdog_state{node="node-a",state="fail2ban-down"} 1`,
		`node_watchdog_egress_relay{target="8.8.8.8"} 1`,
		`node_overlay_egress_relay_active{target="8.8.8.8"} 1`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("textfile missing %q\n%s", want, text)
		}
	}
	// Atomic contract: no staging file left behind.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() == textfileTmpName || strings.HasPrefix(e.Name(), ".tmp-") {
			t.Fatalf("staging file left behind: %s", e.Name())
		}
	}

	// Second render after the latch clears emits the explicit 0 —
	// the prom_emit emit-0 alert contract.
	if err := os.Remove(filepath.Join(dirs["state"], "state-fail2ban-down")); err != nil {
		t.Fatal(err)
	}
	if err := c.WriteTextfile(dir); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(filepath.Join(dir, "node-watchdog.prom"))
	if !strings.Contains(string(data),
		`node_watchdog_state{signal="fail2ban-down"} 0`) {
		t.Fatalf("cleared latch did not emit 0\n%s", data)
	}
}

func TestWriteTextfileTmpNameEscapesPromGlob(t *testing.T) {
	// node_exporter ingests every file matching *.prom — the
	// staging name must never match, or a partially-written file
	// could be scraped (and ".tmp-x.prom" DOES match: * swallows
	// the leading dot).
	if ok, _ := filepath.Match("*.prom", textfileTmpName); ok {
		t.Fatalf("staging name %q matches the *.prom glob", textfileTmpName)
	}
	if ok, _ := filepath.Match("*.prom", ".tmp-"+TextfileName); !ok {
		t.Fatal("sanity: the old .tmp- prefix really did match *.prom")
	}
	if ok, _ := filepath.Match("*.prom", TextfileName); !ok {
		t.Fatalf("final name %q must match the *.prom glob", TextfileName)
	}
}

func TestWriteTextfileNoDuplicateSeries(t *testing.T) {
	cfg, dirs := fixture(t)
	cfg.EgressRelays = []string{"8.8.8.8"}
	write(t, filepath.Join(dirs["state"], "state-a"), "1\n")
	c := New(cfg)
	dir := t.TempDir()
	if err := c.WriteTextfile(dir); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "node-watchdog.prom"))
	if err != nil {
		t.Fatal(err)
	}
	// A duplicated series would make node_exporter reject the whole
	// file — each sample line must appear exactly once.
	count := strings.Count(string(data),
		`node_watchdog_state{signal="a"} 1`)
	if count != 1 {
		t.Fatalf("series emitted %d times want 1\n%s", count, data)
	}
}

// --- H1: clock sync (adjtimex) ---

func TestClockUnsynchronizedAndEstError(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.adjtimexFn = func(tx *unix.Timex) (int, error) {
		tx.Status = unix.STA_UNSYNC
		tx.Esterror = 750_000 // µs → 0.75 s
		return 0, nil
	}
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	if v, ok := metricValue(t, c, "node_host_agent_clock_unsynchronized",
		node); !ok || v != 1 {
		t.Fatalf("clock_unsynchronized=%v ok=%v want 1 (STA_UNSYNC)", v, ok)
	}
	if v, ok := metricValue(t, c,
		"node_host_agent_clock_estimated_error_seconds",
		node); !ok || v != 0.75 {
		t.Fatalf("estimated_error=%v ok=%v want 0.75 (µs→s)", v, ok)
	}
}

func TestClockSynchronizedEmitsZero(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.adjtimexFn = func(tx *unix.Timex) (int, error) {
		tx.Status = unix.STA_PLL // synced flags, no STA_UNSYNC
		tx.Esterror = 12_000
		return 0, nil
	}
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	if v, ok := metricValue(t, c, "node_host_agent_clock_unsynchronized",
		node); !ok || v != 0 {
		t.Fatalf("clock_unsynchronized=%v ok=%v want explicit 0", v, ok)
	}
	if v, ok := metricValue(t, c,
		"node_host_agent_clock_estimated_error_seconds",
		node); !ok || v != 0.012 {
		t.Fatalf("estimated_error=%v ok=%v want 0.012", v, ok)
	}
}

func TestClockAbsentWhenAdjtimexFails(t *testing.T) {
	cfg, _ := fixture(t)
	// fixture stub already errors — inconclusive read must emit no
	// series rather than a fake "synchronized" 0.
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	if _, ok := metricValue(t, c, "node_host_agent_clock_unsynchronized",
		node); ok {
		t.Fatal("clock_unsynchronized emitted despite adjtimex error")
	}
	if _, ok := metricValue(t, c,
		"node_host_agent_clock_estimated_error_seconds", node); ok {
		t.Fatal("estimated_error emitted despite adjtimex error")
	}
}

// --- H2: conntrack table pressure ---

func TestConntrackMetrics(t *testing.T) {
	cfg, _ := fixture(t)
	write(t, cfg.ConntrackCountFile, "230000\n")
	write(t, cfg.ConntrackMaxFile, "262144\n")
	c := New(cfg)
	node := map[string]string{"node": "node-a"}

	if v, ok := metricValue(t, c, "node_host_agent_conntrack_entries",
		node); !ok || v != 230000 {
		t.Fatalf("entries=%v ok=%v want 230000", v, ok)
	}
	if v, ok := metricValue(t, c, "node_host_agent_conntrack_limit",
		node); !ok || v != 262144 {
		t.Fatalf("limit=%v ok=%v want 262144", v, ok)
	}
	want := 230000.0 / 262144.0
	if v, ok := metricValue(t, c, "node_host_agent_conntrack_used_ratio",
		node); !ok || math.Abs(v-want) > 1e-9 {
		t.Fatalf("used_ratio=%v ok=%v want %v", v, ok, want)
	}
}

func TestConntrackAbsentWithoutFiles(t *testing.T) {
	cfg, _ := fixture(t)
	// A node without the conntrack module has neither file → all
	// three series absent (no fake 0).
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	for _, name := range []string{
		"node_host_agent_conntrack_entries",
		"node_host_agent_conntrack_limit",
		"node_host_agent_conntrack_used_ratio",
	} {
		if _, ok := metricValue(t, c, name, node); ok {
			t.Fatalf("%s emitted without proc files", name)
		}
	}
}

func TestConntrackPartialData(t *testing.T) {
	cfg, _ := fixture(t)
	// Only the count file reads — entries emits, limit+ratio stay
	// absent (each gauge tracks its own source).
	write(t, cfg.ConntrackCountFile, "42\n")
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	if v, ok := metricValue(t, c, "node_host_agent_conntrack_entries",
		node); !ok || v != 42 {
		t.Fatalf("entries=%v ok=%v want 42", v, ok)
	}
	if _, ok := metricValue(t, c, "node_host_agent_conntrack_limit",
		node); ok {
		t.Fatal("limit emitted without the max file")
	}
	if _, ok := metricValue(t, c, "node_host_agent_conntrack_used_ratio",
		node); ok {
		t.Fatal("ratio emitted without the max file")
	}
}

func TestConntrackZeroLimitSkipsRatio(t *testing.T) {
	cfg, _ := fixture(t)
	write(t, cfg.ConntrackCountFile, "10\n")
	write(t, cfg.ConntrackMaxFile, "0\n")
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	if v, ok := metricValue(t, c, "node_host_agent_conntrack_limit",
		node); !ok || v != 0 {
		t.Fatalf("limit=%v ok=%v want 0", v, ok)
	}
	if _, ok := metricValue(t, c, "node_host_agent_conntrack_used_ratio",
		node); ok {
		t.Fatal("ratio emitted with a zero limit (div-by-zero)")
	}
}

func TestConntrackMalformedSkipped(t *testing.T) {
	cfg, _ := fixture(t)
	write(t, cfg.ConntrackCountFile, "not-a-number\n")
	write(t, cfg.ConntrackMaxFile, "\n")
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	for _, name := range []string{
		"node_host_agent_conntrack_entries",
		"node_host_agent_conntrack_limit",
		"node_host_agent_conntrack_used_ratio",
	} {
		if _, ok := metricValue(t, c, name, node); ok {
			t.Fatalf("%s emitted for malformed data", name)
		}
	}
}

// --- H3 + H7: filesystem inode stats + hung-mount probe ---

func TestFilesystemInodeMetrics(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.FilesystemTargets = []string{"/mnt/data", "/mnt/logs"}
	cfg.statfsFn = func(path string, st *unix.Statfs_t) error {
		if path == "/mnt/data" {
			st.Files = 1000
			st.Ffree = 250
			return nil
		}
		return unix.ENOENT
	}
	c := New(cfg)

	data := map[string]string{"node": "node-a", "mount": "/mnt/data"}
	if v, ok := metricValue(t, c,
		"node_host_agent_filesystem_inodes_total", data); !ok || v != 1000 {
		t.Fatalf("inodes_total=%v ok=%v want 1000", v, ok)
	}
	if v, ok := metricValue(t, c,
		"node_host_agent_filesystem_inodes_free", data); !ok || v != 250 {
		t.Fatalf("inodes_free=%v ok=%v want 250", v, ok)
	}
	if v, ok := metricValue(t, c,
		"node_host_agent_filesystem_inodes_used_ratio",
		data); !ok || v != 0.75 {
		t.Fatalf("inodes_used_ratio=%v ok=%v want 0.75", v, ok)
	}
	// probe_stalled emits for EVERY configured target — 0 means the
	// probe answered in time.
	if v, ok := metricValue(t, c,
		"node_host_agent_filesystem_probe_stalled",
		data); !ok || v != 0 {
		t.Fatalf("probe_stalled=%v ok=%v want 0", v, ok)
	}

	// An erroring-but-fast probe still reports stalled=0, while the
	// inode gauges stay absent (no fake numbers).
	logs := map[string]string{"node": "node-a", "mount": "/mnt/logs"}
	if v, ok := metricValue(t, c,
		"node_host_agent_filesystem_probe_stalled",
		logs); !ok || v != 0 {
		t.Fatalf("probe_stalled{/mnt/logs}=%v ok=%v want 0", v, ok)
	}
	if _, ok := metricValue(t, c,
		"node_host_agent_filesystem_inodes_total", logs); ok {
		t.Fatal("inodes emitted for a failed statfs")
	}
}

func TestFilesystemZeroInodesSkipsRatio(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.FilesystemTargets = []string{"/mnt/empty"}
	cfg.statfsFn = func(path string, st *unix.Statfs_t) error {
		st.Files, st.Ffree = 0, 0
		return nil
	}
	c := New(cfg)
	mnt := map[string]string{"node": "node-a", "mount": "/mnt/empty"}
	if v, ok := metricValue(t, c,
		"node_host_agent_filesystem_inodes_total", mnt); !ok || v != 0 {
		t.Fatalf("inodes_total=%v ok=%v want 0", v, ok)
	}
	if _, ok := metricValue(t, c,
		"node_host_agent_filesystem_inodes_used_ratio", mnt); ok {
		t.Fatal("inodes_used_ratio emitted with Files=0 (div-by-zero)")
	}
}

func TestFilesystemProbeStalledOnHang(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.FilesystemTargets = []string{"/mnt/hung"}
	release := make(chan struct{})
	defer close(release) // lets the stuck probe goroutine exit
	var calls atomic.Int32
	cfg.statfsFn = func(path string, st *unix.Statfs_t) error {
		calls.Add(1)
		<-release // simulates a mount hung in uninterruptible sleep
		return nil
	}
	c := New(cfg)
	mnt := map[string]string{"node": "node-a", "mount": "/mnt/hung"}

	// The probe exceeds fsProbeTimeout → stalled=1, and no inode
	// series for a mount that never answered.
	if v, ok := metricValue(t, c,
		"node_host_agent_filesystem_probe_stalled",
		mnt); !ok || v != 1 {
		t.Fatalf("probe_stalled=%v ok=%v want 1 on hung mount", v, ok)
	}
	if _, ok := metricValue(t, c,
		"node_host_agent_filesystem_inodes_total", mnt); ok {
		t.Fatal("inodes emitted for a hung mount")
	}

	// While the first probe is still stuck in the kernel, the next
	// scrape reports stalled WITHOUT spawning another statfs — at
	// most one goroutine piles up per mount.
	if v, ok := metricValue(t, c,
		"node_host_agent_filesystem_probe_stalled",
		mnt); !ok || v != 1 {
		t.Fatalf("probe_stalled=%v ok=%v want 1 while still hung", v, ok)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("statfs called %d times want 1 (in-flight probe not re-spawned)", got)
	}
}

func TestFilesystemProbeRecoversAfterHang(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.FilesystemTargets = []string{"/mnt/flaky"}
	release := make(chan struct{})
	var calls atomic.Int32
	cfg.statfsFn = func(path string, st *unix.Statfs_t) error {
		if calls.Add(1) == 1 {
			<-release // first probe hangs past the deadline
			return unix.EIO
		}
		st.Files, st.Ffree = 100, 50
		return nil
	}
	c := New(cfg)
	mnt := map[string]string{"node": "node-a", "mount": "/mnt/flaky"}

	if v, ok := metricValue(t, c,
		"node_host_agent_filesystem_probe_stalled",
		mnt); !ok || v != 1 {
		t.Fatalf("probe_stalled=%v ok=%v want 1 while hung", v, ok)
	}

	// Once the stuck syscall returns, the in-flight bookkeeping
	// clears and the next scrape probes fresh → back to 0 with the
	// inode gauges populated.
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for {
		v, ok := metricValue(t, c,
			"node_host_agent_filesystem_probe_stalled", mnt)
		if ok && v == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("probe_stalled never recovered to 0 after unhang")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if v, ok := metricValue(t, c,
		"node_host_agent_filesystem_inodes_total", mnt); !ok || v != 100 {
		t.Fatalf("inodes_total=%v ok=%v want 100 after recovery", v, ok)
	}
}

// --- H6: FD + socket pressure (file-nr, sockstat) ---

func TestFileFDMetrics(t *testing.T) {
	cfg, _ := fixture(t)
	write(t, cfg.FileNRFile, "12345\t0\t9999999\n")
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	if v, ok := metricValue(t, c, "node_host_agent_filefd_allocated",
		node); !ok || v != 12345 {
		t.Fatalf("allocated=%v ok=%v want 12345", v, ok)
	}
	if v, ok := metricValue(t, c, "node_host_agent_filefd_maximum",
		node); !ok || v != 9999999 {
		t.Fatalf("maximum=%v ok=%v want 9999999", v, ok)
	}
	want := 12345.0 / 9999999.0
	if v, ok := metricValue(t, c, "node_host_agent_filefd_used_ratio",
		node); !ok || math.Abs(v-want) > 1e-9 {
		t.Fatalf("used_ratio=%v ok=%v want %v", v, ok, want)
	}
}

func TestFileFDAbsentOnMissingOrMalformed(t *testing.T) {
	cfg, _ := fixture(t)
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	names := []string{
		"node_host_agent_filefd_allocated",
		"node_host_agent_filefd_maximum",
		"node_host_agent_filefd_used_ratio",
	}
	for _, name := range names {
		if _, ok := metricValue(t, c, name, node); ok {
			t.Fatalf("%s emitted without the file", name)
		}
	}
	for _, content := range []string{
		"12345\n",         // too few fields
		"abc\t0\tdef\n",   // non-numeric
		"12345\t0\tmax\n", // non-numeric max
	} {
		write(t, cfg.FileNRFile, content)
		for _, name := range names {
			if _, ok := metricValue(t, c, name, node); ok {
				t.Fatalf("%s emitted for malformed %q", name, content)
			}
		}
	}
}

func TestFileFDZeroMaxSkipsRatio(t *testing.T) {
	cfg, _ := fixture(t)
	write(t, cfg.FileNRFile, "10\t0\t0\n")
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	if v, ok := metricValue(t, c, "node_host_agent_filefd_maximum",
		node); !ok || v != 0 {
		t.Fatalf("maximum=%v ok=%v want 0", v, ok)
	}
	if _, ok := metricValue(t, c, "node_host_agent_filefd_used_ratio",
		node); ok {
		t.Fatal("used_ratio emitted with a zero maximum (div-by-zero)")
	}
}

func TestSockstatMetrics(t *testing.T) {
	cfg, _ := fixture(t)
	write(t, cfg.SockstatFile,
		"sockets: used 1847\n"+
			"TCP: inuse 25 orphan 2 tw 4 alloc 1200 mem 456\n"+
			"UDP: inuse 10 mem 20\n"+
			"UDPLITE: inuse 0\n"+
			"RAW: inuse 0\n"+
			"FRAG: inuse 0 memory 0\n")
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	checks := map[string]float64{
		"node_host_agent_sockstat_sockets_used": 1847,
		"node_host_agent_sockstat_tcp_inuse":    25,
		"node_host_agent_sockstat_tcp_orphan":   2,
		"node_host_agent_sockstat_tcp_tw":       4,
	}
	for name, want := range checks {
		if v, ok := metricValue(t, c, name, node); !ok || v != want {
			t.Fatalf("%s=%v ok=%v want %v", name, v, ok, want)
		}
	}
}

func TestSockstatAbsentWithoutFile(t *testing.T) {
	cfg, _ := fixture(t)
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	for _, name := range []string{
		"node_host_agent_sockstat_sockets_used",
		"node_host_agent_sockstat_tcp_inuse",
		"node_host_agent_sockstat_tcp_orphan",
		"node_host_agent_sockstat_tcp_tw",
	} {
		if _, ok := metricValue(t, c, name, node); ok {
			t.Fatalf("%s emitted without sockstat", name)
		}
	}
}

func TestSockstatMissingAndMalformedSections(t *testing.T) {
	cfg, _ := fixture(t)
	// No TCP line at all — sockets_used still emits, the TCP series
	// stay absent rather than guessing 0.
	write(t, cfg.SockstatFile, "sockets: used 99\nUDP: inuse 3\n")
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	if v, ok := metricValue(t, c, "node_host_agent_sockstat_sockets_used",
		node); !ok || v != 99 {
		t.Fatalf("sockets_used=%v ok=%v want 99", v, ok)
	}
	if _, ok := metricValue(t, c, "node_host_agent_sockstat_tcp_inuse",
		node); ok {
		t.Fatal("tcp_inuse emitted without a TCP line")
	}

	// A malformed TCP line (odd field count / non-numeric value)
	// is skipped entirely — never emit junk.
	write(t, cfg.SockstatFile,
		"sockets: used 99\nTCP: inuse five orphan 0\nTCP: dangling\n")
	for _, name := range []string{
		"node_host_agent_sockstat_tcp_inuse",
		"node_host_agent_sockstat_tcp_orphan",
		"node_host_agent_sockstat_tcp_tw",
	} {
		if _, ok := metricValue(t, c, name, node); ok {
			t.Fatalf("%s emitted for malformed TCP lines", name)
		}
	}
}

// --- WriteTextfile: gray-failure series in the prom_emit port ---

func TestWriteTextfileIncludesGrayFailureMetrics(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.adjtimexFn = func(tx *unix.Timex) (int, error) {
		tx.Status = unix.STA_UNSYNC
		tx.Esterror = 500_000
		return 0, nil
	}
	write(t, cfg.ConntrackCountFile, "100\n")
	write(t, cfg.ConntrackMaxFile, "1000\n")
	write(t, cfg.FileNRFile, "50\t0\t500\n")
	write(t, cfg.SockstatFile,
		"sockets: used 42\nTCP: inuse 7 orphan 1 tw 3 alloc 9 mem 2\n")
	cfg.FilesystemTargets = []string{"/mnt/data"}
	cfg.statfsFn = func(path string, st *unix.Statfs_t) error {
		st.Files, st.Ffree = 200, 50
		return nil
	}
	c := New(cfg)

	dir := t.TempDir()
	if err := c.WriteTextfile(dir); err != nil {
		t.Fatalf("WriteTextfile: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "node-watchdog.prom"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	// Label pairs render sorted — mount before node.
	for _, want := range []string{
		`node_host_agent_clock_unsynchronized{node="node-a"} 1`,
		`node_host_agent_clock_estimated_error_seconds{node="node-a"} 0.5`,
		`node_host_agent_conntrack_entries{node="node-a"} 100`,
		`node_host_agent_conntrack_limit{node="node-a"} 1000`,
		`node_host_agent_conntrack_used_ratio{node="node-a"} 0.1`,
		`node_host_agent_filesystem_inodes_total{mount="/mnt/data",node="node-a"} 200`,
		`node_host_agent_filesystem_inodes_free{mount="/mnt/data",node="node-a"} 50`,
		`node_host_agent_filesystem_inodes_used_ratio{mount="/mnt/data",node="node-a"} 0.75`,
		`node_host_agent_filesystem_probe_stalled{mount="/mnt/data",node="node-a"} 0`,
		`node_host_agent_filefd_allocated{node="node-a"} 50`,
		`node_host_agent_filefd_maximum{node="node-a"} 500`,
		`node_host_agent_filefd_used_ratio{node="node-a"} 0.1`,
		`node_host_agent_sockstat_tcp_inuse{node="node-a"} 7`,
		`node_host_agent_sockstat_tcp_orphan{node="node-a"} 1`,
		`node_host_agent_sockstat_tcp_tw{node="node-a"} 3`,
		`node_host_agent_sockstat_sockets_used{node="node-a"} 42`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("textfile missing %q\n%s", want, text)
		}
	}
}

// --- Wave-2 tests: 2.4 PKI certs, A1 inotify, A2 zombie/cgroup, B4 MTU ---

// mkTestCertPEM generates a throwaway self-signed cert expiring at
// notAfter — enough for the pki-cert-days-left parse path.
func mkTestCertPEM(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl,
		&key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestPKICertDaysLeft(t *testing.T) {
	cfg, _ := fixture(t)
	pkiDir := cfg.PKICertPaths[0]
	if err := os.MkdirAll(pkiDir, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(pkiDir, "ca.crt"),
		string(mkTestCertPEM(t, time.Now().Add(40*24*time.Hour))))
	write(t, filepath.Join(pkiDir, "notacert.key"), "PRIVATE KEY")
	c := New(cfg)
	got, ok := metricValue(t, c, "node_host_agent_pki_cert_days_left",
		map[string]string{"node": "node-a",
			"path": filepath.Join(pkiDir, "ca.crt")})
	if !ok {
		t.Fatal("pki_cert_days_left{ca.crt} absent")
	}
	if got < 39 || got > 41 {
		t.Fatalf("days_left=%v want ~40", got)
	}
	if _, ok := metricValue(t, c, "node_host_agent_pki_cert_days_left",
		map[string]string{"node": "node-a",
			"path": filepath.Join(pkiDir, "notacert.key")}); ok {
		t.Fatal("non-cert file must not emit a series")
	}
}

func TestPKICertDaysLeftStandaloneFile(t *testing.T) {
	cfg, _ := fixture(t)
	f := filepath.Join(t.TempDir(), "kubelet-client-current.pem")
	write(t, f, string(mkTestCertPEM(t, time.Now().Add(10*24*time.Hour))))
	cfg.PKICertPaths = []string{f}
	c := New(cfg)
	got, ok := metricValue(t, c, "node_host_agent_pki_cert_days_left",
		map[string]string{"node": "node-a", "path": f})
	if !ok || got < 9 || got > 11 {
		t.Fatalf("single-file PKI source: days=%v ok=%v want ~10", got, ok)
	}
}

// TestPKICertPathLabelLeadingSlash pins the {path} label shape:
// HostRoot="/" (standalone) must emit the SAME series a pod with
// HostRoot="/host" does — TrimPrefix would otherwise strip the
// leading slash and split the series by run mode.
func TestPKICertPathLabelLeadingSlash(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.HostRoot = "/"
	pkiDir := t.TempDir()
	write(t, filepath.Join(pkiDir, "ca.crt"),
		string(mkTestCertPEM(t, time.Now().Add(40*24*time.Hour))))
	cfg.PKICertPaths = []string{pkiDir}
	c := New(cfg)
	want := filepath.Join(pkiDir, "ca.crt") // absolute, leading slash kept
	if _, ok := metricValue(t, c, "node_host_agent_pki_cert_days_left",
		map[string]string{"node": "node-a", "path": want}); !ok {
		t.Fatalf("series with path=%s absent — leading slash must be kept", want)
	}
}

// TestPKICertDaysLeftExpiredFloors: an expired cert's negative
// days-left must floor (−1.9d → −2), not truncate toward zero.
func TestPKICertDaysLeftExpiredFloors(t *testing.T) {
	cfg, _ := fixture(t)
	pkiDir := cfg.PKICertPaths[0]
	if err := os.MkdirAll(pkiDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// ~45h past expiry → −1.875d.
	write(t, filepath.Join(pkiDir, "expired.crt"),
		string(mkTestCertPEM(t, time.Now().Add(-45*time.Hour))))
	c := New(cfg)
	got, ok := metricValue(t, c, "node_host_agent_pki_cert_days_left",
		map[string]string{"node": "node-a",
			"path": filepath.Join(pkiDir, "expired.crt")})
	if !ok || got != -2 {
		t.Fatalf("days_left=%v ok=%v want -2 (floor, not truncation)", got, ok)
	}
}

// mkFdLink creates a fake /proc/<pid>/fd/<fd> symlink with the
// given target — the fd symlink carries the fd TYPE, which is how
// sweepInotify counts inotify instances (anon_inode:inotify).
func mkFdLink(t *testing.T, proc string, pid, fd int, target string) {
	t.Helper()
	d := filepath.Join(proc, strconv.Itoa(pid), "fd")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(d, strconv.Itoa(fd))); err != nil {
		t.Fatal(err)
	}
}

// mkFdinfo writes a fake /proc/<pid>/fdinfo/<fd> with n inotify wd
// lines AND the matching fd symlink pointing at
// anon_inode:inotify — a real inotify fd carries both; the
// instance count comes from the symlink, the watch count from
// fdinfo.
func mkFdinfo(t *testing.T, proc string, pid, fd, n int) {
	t.Helper()
	mkFdLink(t, proc, pid, fd, "anon_inode:inotify")
	d := filepath.Join(proc, strconv.Itoa(pid), "fdinfo")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("pos:\t0\nflags:\t02004000\n")
	for i := 0; i < n; i++ {
		b.WriteString(fmt.Sprintf("inotify wd:%d ino:1 sdev:8 mask:1 ignored_mask:0 fhandle-bytes:8 fhandle-type:1 f_handle:xx\n", i))
	}
	if err := os.WriteFile(filepath.Join(d, strconv.Itoa(fd)),
		[]byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestInotifyRatios(t *testing.T) {
	cfg, _ := fixture(t)
	write(t, cfg.InotifyMaxInstancesFile, "10\n")
	write(t, cfg.InotifyMaxWatchesFile, "100\n")
	mkFdinfo(t, cfg.ProcRoot, 111, 3, 5)  // 1 fd, 5 watches
	mkFdinfo(t, cfg.ProcRoot, 111, 4, 5)  // another fd → 2 inst
	mkFdinfo(t, cfg.ProcRoot, 222, 6, 10) // other pid → 3rd inst
	c := New(cfg)
	got, ok := metricValue(t, c, "node_host_agent_inotify_instances_used_ratio",
		map[string]string{"node": "node-a"})
	if !ok || got != 0.3 {
		t.Fatalf("instances ratio=%v ok=%v want 0.3", got, ok)
	}
	got, ok = metricValue(t, c, "node_host_agent_inotify_watches_used_ratio",
		map[string]string{"node": "node-a"})
	if !ok || got != 0.2 {
		t.Fatalf("watches ratio=%v ok=%v want 0.2", got, ok)
	}
}

func TestInotifyCacheServesWithinInterval(t *testing.T) {
	cfg, _ := fixture(t)
	write(t, cfg.InotifyMaxInstancesFile, "10\n")
	mkFdinfo(t, cfg.ProcRoot, 111, 3, 1)
	c := New(cfg)
	if got, _ := metricValue(t, c, "node_host_agent_inotify_instances_used_ratio",
		map[string]string{"node": "node-a"}); got != 0.1 {
		t.Fatalf("first scrape=%v want 0.1", got)
	}
	// More fds appear — the cached sweep must still answer 0.1.
	mkFdinfo(t, cfg.ProcRoot, 111, 9, 1)
	if got, _ := metricValue(t, c, "node_host_agent_inotify_instances_used_ratio",
		map[string]string{"node": "node-a"}); got != 0.1 {
		t.Fatalf("cached scrape=%v want 0.1", got)
	}
}

// TestInotifyZeroWatchInstanceCounts covers the leak the metric
// exists for: an inotify_init() fd holding ZERO watches emits no
// identifying line in fdinfo — the instance must still count (the
// fd symlink carries the type), else a zero-watch leak reads ~0
// while the host hits max_user_instances.
func TestInotifyZeroWatchInstanceCounts(t *testing.T) {
	cfg, _ := fixture(t)
	write(t, cfg.InotifyMaxInstancesFile, "10\n")
	write(t, cfg.InotifyMaxWatchesFile, "100\n")
	// fd 3: leaked inotify group — symlink present, NO fdinfo at
	// all (not even a header): instance, 0 watches.
	mkFdLink(t, cfg.ProcRoot, 111, 3, "anon_inode:inotify")
	// fd 4: a socket fd — must not count as an instance.
	mkFdLink(t, cfg.ProcRoot, 111, 4, "socket:[12345]")
	// fd 5: another inotify group, fdinfo present but zero wd
	// lines — also a zero-watch instance.
	mkFdinfo(t, cfg.ProcRoot, 111, 5, 0)
	// fd 6: normal inotify group with 2 watches.
	mkFdinfo(t, cfg.ProcRoot, 111, 6, 2)
	c := New(cfg)
	got, ok := metricValue(t, c, "node_host_agent_inotify_instances_used_ratio",
		map[string]string{"node": "node-a"})
	if !ok || got != 0.3 {
		t.Fatalf("instances ratio=%v ok=%v want 0.3 (3 inotify fds incl. 2 zero-watch)", got, ok)
	}
	got, ok = metricValue(t, c, "node_host_agent_inotify_watches_used_ratio",
		map[string]string{"node": "node-a"})
	if !ok || got != 0.02 {
		t.Fatalf("watches ratio=%v ok=%v want 0.02 (2 watches)", got, ok)
	}
}

func TestZombieCount(t *testing.T) {
	cfg, _ := fixture(t)
	for _, pid := range []int{301, 302} {
		d := filepath.Join(cfg.ProcRoot, strconv.Itoa(pid))
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		write(t, filepath.Join(d, "stat"),
			fmt.Sprintf("%d (x) Z 1 0 0", pid))
	}
	d := filepath.Join(cfg.ProcRoot, "303")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(d, "stat"), "303 (y) S 1 0 0")
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
	write(t, filepath.Join(d, "pids.current"), "900\n")
	write(t, filepath.Join(d, "pids.max"), "1024\n")
	// "max" (unlimited) must emit no ratio — not a fake 0.
	d2 := filepath.Join(cfg.CgroupRoot, "kubepods.slice")
	if err := os.MkdirAll(d2, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(d2, "pids.current"), "50\n")
	write(t, filepath.Join(d2, "pids.max"), "max\n")
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
	write(t, filepath.Join(dirs["sysnet"], "neb1", "mtu"), "1300\n")
	write(t, filepath.Join(dirs["sysnet"], "cilium_net", "mtu"), "1500\n")
	c := New(cfg)
	got, ok := metricValue(t, c, "node_host_agent_mtu_drift",
		map[string]string{"node": "node-a"})
	if !ok || got != 1 {
		t.Fatalf("mtu_drift=%v ok=%v want 1", got, ok)
	}
	write(t, filepath.Join(dirs["sysnet"], "cilium_net", "mtu"), "1300\n")
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
	write(t, filepath.Join(dirs["sysnet"], "neb1", "mtu"), "1300\n")
	write(t, cfg.CiliumRuntimeConfig, `{"mtu":1500}`)
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
	write(t, cfg.CiliumRuntimeConfig,
		`{"a":{"mtu":1300},"list":[{"mtu":1400},{"mtu":1500}],"z":{"MTU":900}}`)
	got, ok := runtimeConfigMTU(cfg.CiliumRuntimeConfig)
	if !ok || got != 1500 {
		t.Fatalf("runtimeConfigMTU=%v,%v want 1500,true (max of all mtu keys)", got, ok)
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

func TestWriteTextfileIncludesNewMetrics(t *testing.T) {
	cfg, dirs := fixture(t)
	pkiDir := cfg.PKICertPaths[0]
	if err := os.MkdirAll(pkiDir, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(pkiDir, "ca.crt"),
		string(mkTestCertPEM(t, time.Now().Add(40*24*time.Hour))))
	write(t, cfg.InotifyMaxInstancesFile, "10\n")
	write(t, cfg.InotifyMaxWatchesFile, "100\n")
	for _, n := range []string{"neb1", "cilium_net"} {
		if err := os.MkdirAll(filepath.Join(dirs["sysnet"], n), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(dirs["sysnet"], "neb1", "mtu"), "1300\n")
	write(t, filepath.Join(dirs["sysnet"], "cilium_net", "mtu"), "1500\n")
	c := New(cfg)
	out := filepath.Join(t.TempDir(), "textfile")
	if err := c.WriteTextfile(out); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(out, "node-watchdog.prom"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"node_host_agent_pki_cert_days_left",
		"node_host_agent_inotify_instances_used_ratio",
		"node_host_agent_inotify_watches_used_ratio",
		"node_host_agent_processes_zombie_count",
		"node_host_agent_mtu_drift",
	} {
		if !strings.Contains(string(data), name) {
			t.Fatalf("textfile missing %s:\n%s", name, data)
		}
	}
}
