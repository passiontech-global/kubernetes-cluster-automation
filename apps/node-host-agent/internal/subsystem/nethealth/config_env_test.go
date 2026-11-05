package nethealth

import (
	"slices"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/watchdogconf"
)

// TestConfigFromEnvDefaults covers the no-env path: deps pass through
// and every knob falls back to its compiled/hostPath default.
func TestConfigFromEnvDefaults(t *testing.T) {
	wd := &watchdogconf.Config{}
	wdSrc := watchdogconf.NewReloader("/nonexistent/node-watchdog.conf", wd)
	sd := systemd.New(systemd.Config{HostRoot: "/host"})

	cfg := ConfigFromEnv(EnvDeps{
		WatchdogStateDir: "/wd/state",
		WatchdogLogFile:  "/wd/watchdog.log",
		HostRoot:         "/host",
		Watchdog:         wd,
		WatchdogSrc:      wdSrc,
		Systemd:          sd,
		HostPath: func(p string) string {
			if p == "/" {
				return p
			}
			return "/host" + p
		},
	})

	if !cfg.Enabled {
		t.Fatal("Enabled = false, want true (wire func set it unconditionally)")
	}
	if cfg.WatchdogStateDir != "/wd/state" || cfg.WatchdogLogFile != "/wd/watchdog.log" ||
		cfg.HostRoot != "/host" || cfg.Watchdog != wd || cfg.WatchdogSrc != wdSrc ||
		cfg.Systemd != sd {
		t.Fatalf("deps not passed through: %+v", cfg)
	}
	// hostPath-joined defaults (NOT the "/host"-hardcoded package
	// defaults — those assume DaemonSet mode).
	if cfg.HostResolvConf != "/host/etc/resolv.conf" {
		t.Fatalf("HostResolvConf = %q", cfg.HostResolvConf)
	}
	if cfg.HostsFile != "/host/etc/hosts" {
		t.Fatalf("HostsFile = %q", cfg.HostsFile)
	}
	// Compiled defaults.
	if cfg.Interval != 2*time.Minute {
		t.Fatalf("Interval = %v", cfg.Interval)
	}
	if cfg.ConsecNeeded != 2 {
		t.Fatalf("ConsecNeeded = %d", cfg.ConsecNeeded)
	}
	if cfg.MinRestart != 30*time.Minute {
		t.Fatalf("MinRestart = %v", cfg.MinRestart)
	}
	if cfg.ProcNetUDP != "/proc/1/net/udp" || cfg.ProcNetUDP6 != "/proc/1/net/udp6" ||
		cfg.UptimeFile != "/proc/uptime" {
		t.Fatalf("proc defaults wrong: %+v", cfg)
	}
	// envIntList unset → nil → applyDefaults supplies the package set.
	if cfg.NebulaDirectTCPPorts != nil {
		t.Fatalf("NebulaDirectTCPPorts = %v, want nil", cfg.NebulaDirectTCPPorts)
	}
}

// TestConfigFromEnvOverrides sets every knob and verifies env wins,
// including the comma-list parser's skip-non-numeric behaviour.
func TestConfigFromEnvOverrides(t *testing.T) {
	t.Setenv("NODE_HOST_AGENT_NETHEALTH_INTERVAL", "90s")
	t.Setenv("NODE_HOST_AGENT_HOST_RESOLV_CONF", "/etc/resolv.conf")
	t.Setenv("NODE_HOST_AGENT_HOSTS_FILE", "/etc/hosts")
	t.Setenv("NODE_HOST_AGENT_PROC_NET_UDP", "/p/udp")
	t.Setenv("NODE_HOST_AGENT_PROC_NET_UDP6", "/p/udp6")
	t.Setenv("NODE_HOST_AGENT_UPTIME_FILE", "/p/uptime")
	t.Setenv("NODE_HOST_AGENT_NETHEALTH_CONSEC_NEEDED", "5")
	t.Setenv("NODE_HOST_AGENT_NETHEALTH_MIN_RESTART", "10m")
	t.Setenv("NODE_HOST_AGENT_NEBULA_DIRECT_TCP_PORTS", "22, 6443 ,bogus,9443")

	cfg := ConfigFromEnv(EnvDeps{HostRoot: "/"})

	if cfg.Interval != 90*time.Second {
		t.Fatalf("Interval = %v", cfg.Interval)
	}
	if cfg.HostResolvConf != "/etc/resolv.conf" || cfg.HostsFile != "/etc/hosts" {
		t.Fatalf("host file knobs = %q %q", cfg.HostResolvConf, cfg.HostsFile)
	}
	if cfg.ProcNetUDP != "/p/udp" || cfg.ProcNetUDP6 != "/p/udp6" ||
		cfg.UptimeFile != "/p/uptime" {
		t.Fatalf("proc knobs = %q %q %q",
			cfg.ProcNetUDP, cfg.ProcNetUDP6, cfg.UptimeFile)
	}
	if cfg.ConsecNeeded != 5 {
		t.Fatalf("ConsecNeeded = %d", cfg.ConsecNeeded)
	}
	if cfg.MinRestart != 10*time.Minute {
		t.Fatalf("MinRestart = %v", cfg.MinRestart)
	}
	if want := []int{22, 6443, 9443}; !slices.Equal(cfg.NebulaDirectTCPPorts, want) {
		t.Fatalf("NebulaDirectTCPPorts = %v, want %v",
			cfg.NebulaDirectTCPPorts, want)
	}
}

// TestConfigFromEnvStandalonePaths exercises the identity hostPath
// (standalone host, hostRoot "/"): resolv.conf/hosts defaults must be
// the bare host paths, not the "/host"-prefixed package defaults.
func TestConfigFromEnvStandalonePaths(t *testing.T) {
	cfg := ConfigFromEnv(EnvDeps{HostRoot: "/"})
	if cfg.HostResolvConf != "/etc/resolv.conf" {
		t.Fatalf("HostResolvConf = %q", cfg.HostResolvConf)
	}
	if cfg.HostsFile != "/etc/hosts" {
		t.Fatalf("HostsFile = %q", cfg.HostsFile)
	}
}
