package wdeps_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

func testEnvDeps(t *testing.T) wdeps.EnvDeps {
	t.Helper()
	return wdeps.EnvDeps{
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
	t.Setenv(envnames.EnvHygieneInterval, "5m")
	t.Setenv(envnames.EnvProcRoot, "/host/proc")
	t.Setenv(envnames.EnvContainerdSocket, "/custom/containerd.sock")
	t.Setenv(envnames.EnvKubeletTokenFile, "/custom/sa-token")
	t.Setenv(envnames.EnvKubeletWatchdogHosts, "a , b")
	t.Setenv(envnames.EnvHygieneStuckDeleteAge, "20m")
	t.Setenv(envnames.EnvHygieneMaxForceDelete, "9")
	t.Setenv(envnames.EnvDstateStormThreshold, "7")
	t.Setenv(envnames.EnvCalicoOrphanVethThreshold, "77")
	t.Setenv(envnames.EnvCgroupRoot, "/custom/cgroup")
	t.Setenv(envnames.EnvSystemdSessionsDir, "/custom/sessions")

	d := testEnvDeps(t)
	cfg := wdeps.ConfigFromEnv(d)

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
	if !reflect.DeepEqual(cfg.Journal.Dirs, d.JournalDirs) ||
		cfg.Journal.UnreadableNeeded != d.JournalUnreadableNeeded {
		t.Fatalf("journal deps: %+v", cfg)
	}
	if cfg.Interval != 5*time.Minute {
		t.Fatalf("Interval=%v", cfg.Interval)
	}
	if cfg.ProcRoot != "/host/proc" {
		t.Fatalf("ProcRoot=%q", cfg.ProcRoot)
	}
	// hostPath-joined defaults — the "/host" prefix must come from
	// wdeps.EnvDeps.HostPath, not the package's "/host"-hardcoded defaults.
	if cfg.CtrTaskRoot != "/host/run/k0s/containerd/io.containerd.runtime.v2.task/k8s.io" {
		t.Fatalf("CtrTaskRoot=%q", cfg.CtrTaskRoot)
	}
	if cfg.CtrSocket != "/custom/containerd.sock" {
		t.Fatalf("ContainerdSocket=%q", cfg.CtrSocket)
	}
	if cfg.Kubelet.TokenPath != "/custom/sa-token" {
		t.Fatalf("KubeletTokenPath=%q", cfg.Kubelet.TokenPath)
	}
	if !reflect.DeepEqual(cfg.Kubelet.WatchdogHosts, []string{"a", "b"}) {
		t.Fatalf("KubeletWatchdogHosts=%v", cfg.Kubelet.WatchdogHosts)
	}
	if cfg.Teardown.StuckDeleteAge != 20*time.Minute {
		t.Fatalf("StuckDeleteAge=%v", cfg.Teardown.StuckDeleteAge)
	}
	if cfg.Teardown.MaxForceDelete != 9 {
		t.Fatalf("MaxForceDelete=%d", cfg.Teardown.MaxForceDelete)
	}
	if cfg.Pressure.DStateStormThreshold != 7 {
		t.Fatalf("DStateStormThreshold=%d", cfg.Pressure.DStateStormThreshold)
	}
	if cfg.Calico.OrphanVethThreshold != 77 {
		t.Fatalf("CalicoOrphanVethThreshold=%d", cfg.Calico.OrphanVethThreshold)
	}
	if cfg.Runtime.CgroupRoot != "/custom/cgroup" {
		t.Fatalf("Runtime.CgroupRoot=%q", cfg.Runtime.CgroupRoot)
	}
	if cfg.Runtime.SessionsDir != "/custom/sessions" {
		t.Fatalf("Runtime.SessionsDir=%q", cfg.Runtime.SessionsDir)
	}
	// APIBackends derives from the watchdog conf, not env.
	if !reflect.DeepEqual(cfg.APIBackends, []string{"10.0.0.1"}) {
		t.Fatalf("APIBackends=%v", cfg.APIBackends)
	}
}

func TestConfigFromEnvDefaults(t *testing.T) {
	// No env set: package defaults + hostPath join + wdCfg fallback.
	d := testEnvDeps(t)
	cfg := wdeps.ConfigFromEnv(d)
	if cfg.Interval != wdeps.DefaultInterval {
		t.Fatalf("Interval=%v want %v", cfg.Interval, wdeps.DefaultInterval)
	}
	if cfg.Kubelet.TokenPath != wdeps.DefaultKubeletTokenPath {
		t.Fatalf("KubeletTokenPath=%q", cfg.Kubelet.TokenPath)
	}
	if cfg.Cilium.Socket != "/host/run/cilium/cilium.sock" {
		t.Fatalf("CiliumSocket=%q", cfg.Cilium.Socket)
	}
	// W10 runtime-resource guards — same hostPath-joined default
	// contract as the mount paths above.
	if cfg.Runtime.CgroupRoot != "/host/sys/fs/cgroup" {
		t.Fatalf("Runtime.CgroupRoot=%q", cfg.Runtime.CgroupRoot)
	}
	if cfg.Runtime.SessionsDir != "/host/run/systemd/sessions" {
		t.Fatalf("Runtime.SessionsDir=%q", cfg.Runtime.SessionsDir)
	}
	// Vars dir has no vars files → advisory host list is nil.
	if cfg.Kubelet.WatchdogHosts != nil {
		t.Fatalf("KubeletWatchdogHosts=%v want nil", cfg.Kubelet.WatchdogHosts)
	}
	// nil Watchdog → no APIBackends, no panic.
	cfg = wdeps.ConfigFromEnv(wdeps.EnvDeps{Client: d.Client, NodeName: "n"})
	if cfg.APIBackends != nil {
		t.Fatalf("APIBackends=%v want nil", cfg.APIBackends)
	}
	// nil HostPath → identity join.
	if cfg.CtrTaskRoot != "/run/k0s/containerd/io.containerd.runtime.v2.task/k8s.io" {
		t.Fatalf("identity CtrTaskRoot=%q", cfg.CtrTaskRoot)
	}
	// The writable-layer Warning threshold defaults to 5 GiB
	// (via the env knob's default) and must stay independent of the
	// W6.3 eviction threshold (15 GiB) — parity with the wave plan
	// without altering eviction behavior. BloatPodThresholdBytes has
	// no env row; ApplyDefaults fills it exactly like New does.
	if cfg.Disk.WLayerBloatThresholdBytes != int64(5)<<30 {
		t.Fatalf("WLayerBloatThresholdBytes=%d want 5 GiB",
			cfg.Disk.WLayerBloatThresholdBytes)
	}
	cfg.ApplyDefaults()
	if cfg.Disk.BloatPodThresholdBytes != int64(15)<<30 {
		t.Fatalf("BloatPodThresholdBytes=%d want 15 GiB",
			cfg.Disk.BloatPodThresholdBytes)
	}
	if cfg.Disk.WLayerBloatThresholdBytes != int64(5)<<30 {
		t.Fatalf("ApplyDefaults clobbered WLayerBloatThresholdBytes=%d",
			cfg.Disk.WLayerBloatThresholdBytes)
	}
	if cfg.Runtime.CgroupRoot != "/sys/fs/cgroup" ||
		cfg.Runtime.SessionsDir != "/run/systemd/sessions" {
		t.Fatalf("identity Runtime paths: %+v", cfg.Runtime)
	}
}

// --- wdeps.KubeletWatchdogHosts (ported from cmd/agent's main_test) ---

func TestKubeletWatchdogHosts(t *testing.T) {
	t.Run("env list wins", func(t *testing.T) {
		t.Setenv(envnames.EnvKubeletWatchdogHosts, "a , b")
		got := wdeps.KubeletWatchdogHosts(t.TempDir(), "n")
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
		got := wdeps.KubeletWatchdogHosts(dir, "node-a")
		if len(got) != 2 || got[0] != "node-x" || got[1] != "node-y" {
			t.Fatalf("vars hosts=%v", got)
		}
	})

	t.Run("missing vars dir is nil not error", func(t *testing.T) {
		if got := wdeps.KubeletWatchdogHosts(t.TempDir(), "n"); got != nil {
			t.Fatalf("hosts=%v want nil", got)
		}
	})
}
