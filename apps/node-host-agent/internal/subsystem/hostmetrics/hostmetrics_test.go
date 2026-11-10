package hostmetrics

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
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
	cfg := Config{
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
		// Deliberately nonexistent (real /proc/1/mountinfo would leak
		// live mount counts into the filefd-family scrapes); the
		// mountinfo test writes its own fake under root.
		MountinfoFile:     filepath.Join(root, "mountinfo"),
		NetstatFile:       filepath.Join(root, "netstat"),
		SNMPFile:          filepath.Join(root, "snmp"),
		FilesystemTargets: []string{"/fake/etc", "/fake/k0s"},
		// Base sources under root — never the real /proc or /sys:
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
	}
	fixtureSeams(root)
	return cfg, dirs
}

// fixtureSeams pins the deep-failure seams to a nonexistent path for the
// whole test binary — fixture() re-points them at its own temp root
// per test. Without this every refreshLatches would open the REAL
// /dev/kmsg and exec REAL dmesg/chronyc on the test host — the
// vars feed the kernelfail engine through Deps closures, so the
// stubs still land across the package boundary. (The
// textfileDirOverride seam moved into kernelfail with the textfile
// writers; nothing under fixture() reaches a textfile write —
// updatePidFDPressure/updateStealEntropy early-return on the empty
// fixture proc.)
func fixtureSeams(root string) {
	kmsgDevicePaths = func(string) []string {
		return []string{filepath.Join(root, "dev", "kmsg")}
	}
	runHostCmd = func(context.Context, ...string) (string, error) {
		return "", errors.New("exec disabled in tests")
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
			if g := m.GetGauge(); g != nil {
				return g.GetValue(), true
			}
			return m.GetCounter().GetValue(), true
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

func TestDescribe(t *testing.T) {
	c := New(Config{})
	ch := make(chan *prometheus.Desc, 80) // > total descs — Describe blocks on a full buffer
	c.Describe(ch)
	// 10 base descs + the 2 legacy prom_emit aliases
	// (node_watchdog_state, node_watchdog_egress_relay) + 16
	// gray-failure telemetry descs (H1/H2/H3/H6/H7) + 7 host-guard descs
	// (dstate, systemd scopes, conntrack insert_failed/drop, arp,
	// cgroup memory high/oom_kill).
	// + 2 kernel descs (kernel-keys ratio, sockstat tcp close_wait).
	// + 1 localpv desc (localpv dir bytes).
	// + 6 netstat/snmp kernel TCP/IP counter descs.
	// + 4 conntrack-port-pressure descs (ephemeral port saturation, tcp CLOSE_WAIT
	// count, node_exporter-named nf_conntrack insert_failed/drop).
	// + 1 sa-pub-key-fingerprint desc (sa.pub signer-key fingerprint hash).
	// + 6 guard descs (daemon fd ratio, containerd meta.db,
	//   k0scontroller children RSS, fs bytes used ratio, eBPF
	//   programs/maps counts).
	// + 3 clocksource/conntrack descs (clocksource_non_tsc, conntrack
	//   search_restarts/invalid counters).
	// + 1 mountinfo desc (mountinfo entries count).
	// + 3 aio-pressure AIO descs (aio allocated/maximum/used_ratio in the
	//   filefd domain) + 1 max_user_namespaces desc (kernel-resource-table-tuning).
	// + 1 cgroup oom_group_kill desc (pod-cgroup-oomkill-metrics — kubepods.slice joins the
	//   memory.events unit set).
	if got := len(ch); got != 77 {
		t.Fatalf("Describe emitted %d descs want 77", got)
	}
}

// --- WriteTextfile (standalone prom_emit port) ---

func TestWriteTextfile(t *testing.T) {
	cfg, dirs := fixture(t)
	cfg.EgressRelays = []string{"8.8.8.8"}
	testutil.WriteFile(t, filepath.Join(dirs["state"], "state-fail2ban-down"), "1730000000\n")
	testutil.WriteFile(t, filepath.Join(dirs["state"], "egress-state-8.8.8.8"), "relay\n")
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
		if e.Name() != TextfileName {
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
	// could be scraped. Staging now lives in platform/promfile
	// (TestStagingNameEscapesPromGlob covers the pattern); here we
	// only re-check the final-name contract.
	if ok, _ := filepath.Match("*.prom", TextfileName); !ok {
		t.Fatalf("final name %q must match the *.prom glob", TextfileName)
	}
}

func TestWriteTextfileNoDuplicateSeries(t *testing.T) {
	cfg, dirs := fixture(t)
	cfg.EgressRelays = []string{"8.8.8.8"}
	testutil.WriteFile(t, filepath.Join(dirs["state"], "state-a"), "1\n")
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

// --- WriteTextfile: gray-failure series in the prom_emit port ---

func TestWriteTextfileIncludesGrayFailureMetrics(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.adjtimexFn = func(tx *unix.Timex) (int, error) {
		tx.Status = unix.STA_UNSYNC
		tx.Esterror = 500_000
		return 0, nil
	}
	testutil.WriteFile(t, cfg.ConntrackCountFile, "100\n")
	testutil.WriteFile(t, cfg.ConntrackMaxFile, "1000\n")
	testutil.WriteFile(t, cfg.FileNRFile, "50\t0\t500\n")
	testutil.WriteFile(t, cfg.SockstatFile,
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

func TestWriteTextfileIncludesNewMetrics(t *testing.T) {
	cfg, dirs := fixture(t)
	pkiDir := cfg.PKICertPaths[0]
	if err := os.MkdirAll(pkiDir, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(pkiDir, "ca.crt"),
		string(mkTestCertPEM(t, time.Now().Add(40*24*time.Hour))))
	testutil.WriteFile(t, cfg.InotifyMaxInstancesFile, "10\n")
	testutil.WriteFile(t, cfg.InotifyMaxWatchesFile, "100\n")
	for _, n := range []string{"neb1", "cilium_net"} {
		if err := os.MkdirAll(filepath.Join(dirs["sysnet"], n), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	testutil.WriteFile(t, filepath.Join(dirs["sysnet"], "neb1", "mtu"), "1300\n")
	testutil.WriteFile(t, filepath.Join(dirs["sysnet"], "cilium_net", "mtu"), "1500\n")
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

// TestWriteTextfileCounters: the vmstat swap-thrash counters are the
// set's counters — the renderer must type them counter and emit
// their samples, not silently drop them as non-gauges; undeclared
// vmstat keys never leak into the file.
func TestWriteTextfileCounters(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.VMStatFile = filepath.Join(t.TempDir(), "vmstat")
	testutil.WriteFile(t, cfg.VMStatFile,
		"pgfree 12345\npswpin 21\npswpout 34\n")
	c := New(cfg)

	dir := filepath.Join(t.TempDir(), "textfile")
	if err := c.WriteTextfile(dir); err != nil {
		t.Fatalf("WriteTextfile: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, TextfileName))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		"# TYPE node_host_agent_vmstat_pswpin_total counter",
		`node_host_agent_vmstat_pswpin_total{node="node-a"} 21`,
		"# TYPE node_host_agent_vmstat_pswpout_total counter",
		`node_host_agent_vmstat_pswpout_total{node="node-a"} 34`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("textfile missing %q\n%s", want, text)
		}
	}
	if strings.Contains(text, "pgfree") {
		t.Fatalf("undeclared vmstat key leaked into the textfile\n%s", text)
	}
}
