package workerhygiene

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/testutil"
)

func testEnvDeps(t *testing.T) EnvDeps {
	t.Helper()
	return EnvDeps{
		Client:                  testutil.FakeKube(),
		NodeName:                "node-a",
		Systemd:                 systemd.New(systemd.Config{HostRoot: "/"}),
		Watchdog:                &watchdogconf.Config{APIBackends: []watchdogconf.APIBackend{{Name: "cp1", Addr: "10.0.0.1:6443"}}},
		WatchdogSrc:             watchdogconf.NewReloader(filepath.Join(t.TempDir(), "node-watchdog.conf"), nil),
		WatchdogStateDir:        "/sd",
		WatchdogLogFile:         "/lf",
		VarsDir:                 t.TempDir(),
		JournalDirs:             []string{"/jd1", "/jd2"},
		JournalUnreadableNeeded: 9,
		// hostPath join like cmd/agent's "/host" DaemonSet root.
		HostPath: func(p string) string { return "/host" + p },
	}
}

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("NODE_HOST_AGENT_HYGIENE_INTERVAL", "5m")
	t.Setenv("NODE_HOST_AGENT_PROC_ROOT", "/host/proc")
	t.Setenv("NODE_HOST_AGENT_CONTAINERD_SOCKET", "/custom/containerd.sock")
	t.Setenv("NODE_HOST_AGENT_KUBELET_TOKEN_FILE", "/custom/sa-token")
	t.Setenv("NODE_HOST_AGENT_KUBELET_WATCHDOG_HOSTS", "a , b")
	t.Setenv("NODE_HOST_AGENT_HYGIENE_STUCK_DELETE_AGE", "20m")
	t.Setenv("NODE_HOST_AGENT_HYGIENE_MAX_FORCE_DELETE", "9")
	t.Setenv("NODE_HOST_AGENT_DSTATE_STORM_THRESHOLD", "7")
	t.Setenv("NODE_HOST_AGENT_CALICO_ORPHAN_VETH_THRESHOLD", "77")

	d := testEnvDeps(t)
	cfg := ConfigFromEnv(d)

	if !cfg.Enabled {
		t.Fatal("Enabled should be true — the enable gate stays in the caller")
	}
	if cfg.Client != d.Client {
		t.Fatal("Client not passed through")
	}
	if cfg.NodeName != "node-a" || cfg.Systemd != d.Systemd ||
		cfg.Watchdog != d.Watchdog || cfg.WatchdogSrc != d.WatchdogSrc {
		t.Fatalf("deps not passed through: %+v", cfg)
	}
	if cfg.WatchdogStateDir != "/sd" || cfg.WatchdogLogFile != "/lf" {
		t.Fatalf("state dirs: %+v", cfg)
	}
	if !reflect.DeepEqual(cfg.JournalDirs, d.JournalDirs) ||
		cfg.JournalUnreadableNeeded != d.JournalUnreadableNeeded {
		t.Fatalf("journal deps: %+v", cfg)
	}
	if cfg.Interval != 5*time.Minute {
		t.Fatalf("Interval=%v", cfg.Interval)
	}
	if cfg.ProcRoot != "/host/proc" {
		t.Fatalf("ProcRoot=%q", cfg.ProcRoot)
	}
	// hostPath-joined defaults — the "/host" prefix must come from
	// EnvDeps.HostPath, not the package's "/host"-hardcoded defaults.
	if cfg.CtrTaskRoot != "/host/run/k0s/containerd/io.containerd.runtime.v2.task/k8s.io" {
		t.Fatalf("CtrTaskRoot=%q", cfg.CtrTaskRoot)
	}
	if cfg.ContainerdSocket != "/custom/containerd.sock" {
		t.Fatalf("ContainerdSocket=%q", cfg.ContainerdSocket)
	}
	if cfg.KubeletTokenPath != "/custom/sa-token" {
		t.Fatalf("KubeletTokenPath=%q", cfg.KubeletTokenPath)
	}
	if !reflect.DeepEqual(cfg.KubeletWatchdogHosts, []string{"a", "b"}) {
		t.Fatalf("KubeletWatchdogHosts=%v", cfg.KubeletWatchdogHosts)
	}
	if cfg.StuckDeleteAge != 20*time.Minute {
		t.Fatalf("StuckDeleteAge=%v", cfg.StuckDeleteAge)
	}
	if cfg.MaxForceDelete != 9 {
		t.Fatalf("MaxForceDelete=%d", cfg.MaxForceDelete)
	}
	if cfg.DStateStormThreshold != 7 {
		t.Fatalf("DStateStormThreshold=%d", cfg.DStateStormThreshold)
	}
	if cfg.CalicoOrphanVethThreshold != 77 {
		t.Fatalf("CalicoOrphanVethThreshold=%d", cfg.CalicoOrphanVethThreshold)
	}
	// APIBackends derives from the watchdog conf, not env.
	if !reflect.DeepEqual(cfg.APIBackends, []string{"10.0.0.1"}) {
		t.Fatalf("APIBackends=%v", cfg.APIBackends)
	}
}

func TestConfigFromEnvDefaults(t *testing.T) {
	// No env set: package defaults + hostPath join + wdCfg fallback.
	d := testEnvDeps(t)
	cfg := ConfigFromEnv(d)
	if cfg.Interval != defaultInterval {
		t.Fatalf("Interval=%v want %v", cfg.Interval, defaultInterval)
	}
	if cfg.KubeletTokenPath != defaultKubeletTokenPath {
		t.Fatalf("KubeletTokenPath=%q", cfg.KubeletTokenPath)
	}
	if cfg.CiliumSocket != "/host/run/cilium/cilium.sock" {
		t.Fatalf("CiliumSocket=%q", cfg.CiliumSocket)
	}
	// Vars dir has no vars files → advisory host list is nil.
	if cfg.KubeletWatchdogHosts != nil {
		t.Fatalf("KubeletWatchdogHosts=%v want nil", cfg.KubeletWatchdogHosts)
	}
	// nil Watchdog → no APIBackends, no panic.
	cfg = ConfigFromEnv(EnvDeps{Client: d.Client, NodeName: "n"})
	if cfg.APIBackends != nil {
		t.Fatalf("APIBackends=%v want nil", cfg.APIBackends)
	}
	// nil HostPath → identity join.
	if cfg.CtrTaskRoot != "/run/k0s/containerd/io.containerd.runtime.v2.task/k8s.io" {
		t.Fatalf("identity CtrTaskRoot=%q", cfg.CtrTaskRoot)
	}
}

// --- kubeletWatchdogHosts (ported from cmd/agent's main_test) ---

func TestKubeletWatchdogHosts(t *testing.T) {
	t.Run("env list wins", func(t *testing.T) {
		t.Setenv("NODE_HOST_AGENT_KUBELET_WATCHDOG_HOSTS", "a , b")
		got := kubeletWatchdogHosts(t.TempDir(), "n")
		if len(got) != 2 || got[0] != "a" || got[1] != "b" {
			t.Fatalf("env hosts=%v", got)
		}
	})

	t.Run("systemd_watchdog_hosts from vars dir", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "interdc_nodes.yaml"),
			[]byte("{}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cluster.yaml"),
			[]byte("systemd_watchdog_hosts:\n  - node-x\n  - node-y\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		got := kubeletWatchdogHosts(dir, "node-a")
		if len(got) != 2 || got[0] != "node-x" || got[1] != "node-y" {
			t.Fatalf("vars hosts=%v", got)
		}
	})

	t.Run("missing vars dir is nil not error", func(t *testing.T) {
		if got := kubeletWatchdogHosts(t.TempDir(), "n"); got != nil {
			t.Fatalf("hosts=%v want nil", got)
		}
	})
}
