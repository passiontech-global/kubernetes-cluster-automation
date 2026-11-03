package hostmetrics

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
		NebulaCertFile:   filepath.Join(root, "host.crt"),
		// Deliberately nonexistent: the real /proc/pressure/cpu would
		// feed live data into the overload hysteresis and rewrite
		// test-managed latches.
		PSIFile: filepath.Join(root, "no-such-psi"),
		// Never re-measure during unrelated tests — the real
		// busy-loop only runs where a test injects cpuMeasure.
		CPUDeliveredInterval: 24 * time.Hour,
		// Default stub: returns no result — the real 0.3 cpu-s
		// busy-loop would otherwise spin once per collector instance
		// (~20 concurrent goroutines during a suite run).
		cpuMeasure: func() (float64, float64, bool) { return 0, 0, false },
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
	ch := make(chan *prometheus.Desc, 16)
	c.Describe(ch)
	if got := len(ch); got != 10 {
		t.Fatalf("Describe emitted %d descs want 10", got)
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
