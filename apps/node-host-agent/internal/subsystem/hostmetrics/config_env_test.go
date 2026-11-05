package hostmetrics

import (
	"slices"
	"testing"
	"time"
)

// testHostPath mirrors cmd/agent's hostPath closure: identity on "/",
// root-join otherwise.
func testHostPath(root string) func(string) string {
	return func(p string) string {
		if root == "/" {
			return p
		}
		return root + p
	}
}

// TestConfigFromEnvDefaults covers the no-env path: deps pass through
// and every knob falls back to its compiled/hostPath default —
// including the FilesystemTargets envList→closure pattern, which must
// produce the hostPath-joined set, NOT defaultFilesystemTargets.
func TestConfigFromEnvDefaults(t *testing.T) {
	cfg := ConfigFromEnv(EnvDeps{
		NodeName:            "node-1",
		WatchdogStateDir:    "/wd/state",
		Standalone:          true,
		OverlayEgressRelays: []string{"10.9.0.1", "10.9.0.2"},
		NebulaNet:           "mynet",
		HostPath:            testHostPath("/host"),
	})

	if cfg.NodeName != "node-1" || cfg.WatchdogStateDir != "/wd/state" ||
		!cfg.Standalone {
		t.Fatalf("deps not passed through: %+v", cfg)
	}
	if !slices.Equal(cfg.EgressRelays, []string{"10.9.0.1", "10.9.0.2"}) {
		t.Fatalf("EgressRelays = %v", cfg.EgressRelays)
	}
	// hostPath-joined defaults.
	if cfg.K0sUnitFile != "/host/etc/systemd/system/k0scontroller.service" {
		t.Fatalf("K0sUnitFile = %q", cfg.K0sUnitFile)
	}
	if cfg.NebulaCertFile != "/host/etc/nebula/mynet/host.crt" {
		t.Fatalf("NebulaCertFile = %q", cfg.NebulaCertFile)
	}
	wantFS := []string{"/host/etc", "/host/var/lib/k0s", "/var/openebs/local"}
	if !slices.Equal(cfg.FilesystemTargets, wantFS) {
		t.Fatalf("FilesystemTargets = %v, want %v", cfg.FilesystemTargets, wantFS)
	}
	// Compiled defaults via envx fallbacks.
	if cfg.KeyUsersFile != "/proc/key-users" {
		t.Fatalf("KeyUsersFile = %q", cfg.KeyUsersFile)
	}
	if cfg.LatchInterval != 30*time.Second {
		t.Fatalf("LatchInterval = %v", cfg.LatchInterval)
	}
	if cfg.CPUDeliveredInterval != 2*time.Minute {
		t.Fatalf("CPUDeliveredInterval = %v", cfg.CPUDeliveredInterval)
	}
	// envList unset → nil → applyDefaults supplies the package set.
	if cfg.ExpectedKCMArgs != nil {
		t.Fatalf("ExpectedKCMArgs = %v, want nil", cfg.ExpectedKCMArgs)
	}
	if cfg.CgroupMemUnits != nil {
		t.Fatalf("CgroupMemUnits = %v, want nil", cfg.CgroupMemUnits)
	}
	// HostRoot stays unset — applyDefaults auto-detects.
	if cfg.HostRoot != "" {
		t.Fatalf("HostRoot = %q, want empty (auto-detect)", cfg.HostRoot)
	}
}

// TestConfigFromEnvOverrides sets every knob and verifies env wins —
// including the envList parsers' trim/drop-empty behaviour.
func TestConfigFromEnvOverrides(t *testing.T) {
	t.Setenv("NODE_HOST_AGENT_KEY_USERS_FILE", "/x/key-users")
	t.Setenv("NODE_HOST_AGENT_LATCH_INTERVAL", "45s")
	t.Setenv("NODE_HOST_AGENT_SYS_CLASS_NET", "/sys2")
	t.Setenv("NODE_HOST_AGENT_NEBULA_IFACE", "neb9")
	t.Setenv("NODE_HOST_AGENT_HOST_ROUTE_FILE", "/route")
	t.Setenv("NODE_HOST_AGENT_K0S_CONFIG", "/k0s.yaml")
	t.Setenv("NODE_HOST_AGENT_K0S_UNIT", "/unit.service")
	t.Setenv("NODE_HOST_AGENT_NEBULA_CERT", "/cert.crt")
	t.Setenv("NODE_HOST_AGENT_K0S_EXPECTED_KCM_ARGS", "a, b ,,c")
	t.Setenv("NODE_HOST_AGENT_PSI_FILE", "/psi")
	t.Setenv("NODE_HOST_AGENT_CPU_DELIVERED_INTERVAL", "5m")
	t.Setenv("NODE_HOST_AGENT_CONNTRACK_STAT_FILE", "/ctstat")
	t.Setenv("NODE_HOST_AGENT_ARP_TABLE_FILE", "/arp")
	t.Setenv("NODE_HOST_AGENT_CGROUP_MEM_UNITS", "u1, u2")
	t.Setenv("NODE_HOST_AGENT_FILESYSTEM_TARGETS", "/f1, /f2")

	cfg := ConfigFromEnv(EnvDeps{HostPath: testHostPath("/host")})

	if cfg.KeyUsersFile != "/x/key-users" ||
		cfg.SysClassNet != "/sys2" ||
		cfg.NebulaIface != "neb9" ||
		cfg.RouteFile != "/route" ||
		cfg.K0sConfigFile != "/k0s.yaml" ||
		cfg.K0sUnitFile != "/unit.service" ||
		cfg.NebulaCertFile != "/cert.crt" ||
		cfg.PSIFile != "/psi" ||
		cfg.ConntrackStatFile != "/ctstat" ||
		cfg.ARPTableFile != "/arp" {
		t.Fatalf("env string/duration knobs not applied: %+v", cfg)
	}
	if cfg.LatchInterval != 45*time.Second {
		t.Fatalf("LatchInterval = %v", cfg.LatchInterval)
	}
	if cfg.CPUDeliveredInterval != 5*time.Minute {
		t.Fatalf("CPUDeliveredInterval = %v", cfg.CPUDeliveredInterval)
	}
	if want := []string{"a", "b", "c"}; !slices.Equal(cfg.ExpectedKCMArgs, want) {
		t.Fatalf("ExpectedKCMArgs = %v, want %v", cfg.ExpectedKCMArgs, want)
	}
	if want := []string{"u1", "u2"}; !slices.Equal(cfg.CgroupMemUnits, want) {
		t.Fatalf("CgroupMemUnits = %v, want %v", cfg.CgroupMemUnits, want)
	}
	if want := []string{"/f1", "/f2"}; !slices.Equal(cfg.FilesystemTargets, want) {
		t.Fatalf("FilesystemTargets = %v, want %v", cfg.FilesystemTargets, want)
	}
}

// TestConfigFromEnvStandalonePaths exercises the identity hostPath
// (standalone host, hostRoot "/"): defaults must NOT gain a "/host"
// prefix.
func TestConfigFromEnvStandalonePaths(t *testing.T) {
	cfg := ConfigFromEnv(EnvDeps{
		NebulaNet: "interdc",
		HostPath:  testHostPath("/"),
	})
	if cfg.K0sUnitFile != "/etc/systemd/system/k0scontroller.service" {
		t.Fatalf("K0sUnitFile = %q", cfg.K0sUnitFile)
	}
	if cfg.NebulaCertFile != "/etc/nebula/interdc/host.crt" {
		t.Fatalf("NebulaCertFile = %q", cfg.NebulaCertFile)
	}
	wantFS := []string{"/etc", "/var/lib/k0s", "/var/openebs/local"}
	if !slices.Equal(cfg.FilesystemTargets, wantFS) {
		t.Fatalf("FilesystemTargets = %v, want %v", cfg.FilesystemTargets, wantFS)
	}

	// Nil HostPath → identity, same result.
	cfg2 := ConfigFromEnv(EnvDeps{NebulaNet: "interdc"})
	if cfg2.K0sUnitFile != cfg.K0sUnitFile ||
		cfg2.NebulaCertFile != cfg.NebulaCertFile {
		t.Fatalf("nil HostPath not identity: %+v", cfg2)
	}
}
