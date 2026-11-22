// collect_k8s135_readiness_test.go — unit tests for K5 Kubernetes 1.35+
// cgroup v2 & kubelet/k0s.yaml upgrade readiness collector and latch lifecycle.
package hostmetrics

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

func k8s135DriftMetric(t *testing.T, c *Collector, reason, key string) (float64, bool) {
	t.Helper()
	return metricValue(t, c, "node_host_agent_k8s135_readiness_drift",
		map[string]string{"node": "node-a", "reason": reason, "key": key})
}

func gatherK8s135DriftCount(t *testing.T, c *Collector) int {
	t.Helper()
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() == "node_host_agent_k8s135_readiness_drift" {
			return len(mf.Metric)
		}
	}
	return 0
}

func TestK8s135ReadinessCleanAndAutoSkip(t *testing.T) {
	t.Run("minimal fixture auto-skips with zero findings", func(t *testing.T) {
		cfg, _ := fixture(t)
		c := New(cfg)
		if got := gatherK8s135DriftCount(t, c); got != 0 {
			t.Fatalf("minimal fixture emitted %d readiness series, want 0", got)
		}
	})

	t.Run("empty temp CgroupRoot and empty MountinfoFile auto-skips cleanly", func(t *testing.T) {
		cfg, _ := fixture(t)
		cfg.CgroupRoot = t.TempDir()
		testutil.WriteFile(t, cfg.MountinfoFile, "")
		cfg.statfsFn = func(path string, st *unix.Statfs_t) error {
			st.Type = unix.TMPFS_MAGIC
			return nil
		}
		c := New(cfg)
		if got := gatherK8s135DriftCount(t, c); got != 0 {
			t.Fatalf("empty sandbox emitted %d readiness series, want 0", got)
		}
	})

	t.Run("clean cgroup2 host and clean kubelet/k0s config emits zero series", func(t *testing.T) {
		cfg, _ := fixture(t)
		cfg.applyDefaults()
		cfg.CgroupRoot = t.TempDir()
		cfg.statfsFn = func(path string, st *unix.Statfs_t) error {
			st.Type = unix.CGROUP2_SUPER_MAGIC
			return nil
		}
		testutil.WriteFile(t, cfg.MountinfoFile,
			"25 1 0:23 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw\n")
		testutil.WriteFile(t, cfg.KubeletConfigPaths[0],
			"apiVersion: kubelet.config.k8s.io/v1beta1\nkind: KubeletConfiguration\ncgroupDriver: systemd\nfailCgroupV1: true\n")
		testutil.WriteFile(t, cfg.K0sConfigFile,
			"apiVersion: k0s.k0sproject.io/v1beta1\nkind: ClusterConfig\nspec:\n  workerProfiles:\n    - name: default\n      values:\n        cgroupDriver: systemd\n        failCgroupV1: true\n")
		c := New(cfg)
		if got := gatherK8s135DriftCount(t, c); got != 0 {
			t.Fatalf("clean host emitted %d readiness series, want 0", got)
		}
	})

	t.Run("statfs ENOENT with cgroup2 mountinfo or cgroup.controllers is healthy", func(t *testing.T) {
		cfg, _ := fixture(t)
		if err := os.MkdirAll(cfg.CgroupRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		testutil.WriteFile(t, filepath.Join(cfg.CgroupRoot, "cgroup.controllers"), "cpu memory io pids\n")
		testutil.WriteFile(t, cfg.MountinfoFile,
			"25 1 0:23 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n")
		c := New(cfg)
		if got := gatherK8s135DriftCount(t, c); got != 0 {
			t.Fatalf("cgroup2 fallback emitted %d readiness series, want 0", got)
		}
	})
}

func TestK8s135ReadinessCgroupV1Detection(t *testing.T) {
	cases := []struct {
		name      string
		statfsRes func(string, *unix.Statfs_t) error
		mountinfo string
		wantDrift bool
	}{
		{
			name: "pure cgroup v1 via statfs CGROUP_SUPER_MAGIC",
			statfsRes: func(_ string, st *unix.Statfs_t) error {
				st.Type = unix.CGROUP_SUPER_MAGIC
				return nil
			},
			wantDrift: true,
		},
		{
			name: "hybrid tmpfs plus cgroup v1 submount in mountinfo",
			statfsRes: func(_ string, st *unix.Statfs_t) error {
				st.Type = unix.TMPFS_MAGIC
				return nil
			},
			mountinfo: "25 1 0:23 / /sys/fs/cgroup rw - tmpfs tmpfs rw\n" +
				"26 25 0:24 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n",
			wantDrift: true,
		},
		{
			name: "cgroup2 plus lingering cgroup v1 controller in mountinfo",
			statfsRes: func(_ string, st *unix.Statfs_t) error {
				st.Type = unix.CGROUP2_SUPER_MAGIC
				return nil
			},
			mountinfo: "25 1 0:23 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n" +
				"26 25 0:24 / /sys/fs/cgroup/systemd rw - cgroup cgroup rw,name=systemd\n",
			wantDrift: true,
		},
		{
			name: "escaped mount path with space under /sys/fs/cgroup",
			statfsRes: func(_ string, st *unix.Statfs_t) error {
				return unix.ENOENT
			},
			mountinfo: `26 25 0:24 / /sys/fs/cgroup/my\040v1 rw - cgroup cgroup rw` + "\n",
			wantDrift: true,
		},
		{
			name: "non-cgroup tmpfs mount elsewhere does not false positive",
			statfsRes: func(_ string, st *unix.Statfs_t) error {
				return unix.ENOENT
			},
			mountinfo: "240 1 8:1 / /var/lib/dead-mount rw - tmpfs tmpfs rw\n",
			wantDrift: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _ := fixture(t)
			cfg.CgroupRoot = t.TempDir()
			cfg.statfsFn = tc.statfsRes
			if tc.mountinfo != "" {
				testutil.WriteFile(t, cfg.MountinfoFile, tc.mountinfo)
			}
			c := New(cfg)
			v, ok := k8s135DriftMetric(t, c, "cgroup-v1", "cgroup")
			if ok != tc.wantDrift || (tc.wantDrift && v != 1) {
				t.Fatalf("cgroup-v1 metric = (%v, %v), want drift=%v", v, ok, tc.wantDrift)
			}
		})
	}
}

func TestK8s135ReadinessKubeletConfigAudit(t *testing.T) {
	t.Run("discovers candidate fallback path and audits driver/failCgroupV1/gates", func(t *testing.T) {
		cfg, _ := fixture(t)
		cfg.applyDefaults()
		// Skip index 0 (absent), populate index 2 (/run/k0s/kubelet-config.yaml).
		testutil.WriteFile(t, cfg.KubeletConfigPaths[2], `
cgroupDriver: cgroupfs
failCgroupV1: false
featureGates:
  KubeletEnsureSecretPulledImages: false
  DynamicKubeletConfig: true
  SomeValidGate: true
`)
		// Index 3 should be ignored once index 2 is found.
		testutil.WriteFile(t, cfg.KubeletConfigPaths[3], `
cgroupDriver: systemd
featureGates:
  ExecProbeTimeout: true
`)
		c := New(cfg)

		for _, tc := range []struct {
			reason, key string
		}{
			{"kubelet-cgroup-driver", "cgroupDriver"},
			{"kubelet-fail-cgroupv1", "failCgroupV1"},
			{"removed-feature-gate", "KubeletEnsureSecretPulledImages"},
			{"removed-feature-gate", "DynamicKubeletConfig"},
		} {
			if v, ok := k8s135DriftMetric(t, c, tc.reason, tc.key); !ok || v != 1 {
				t.Fatalf("missing finding %s/%s: v=%v ok=%v", tc.reason, tc.key, v, ok)
			}
		}
		if _, ok := k8s135DriftMetric(t, c, "removed-feature-gate", "SomeValidGate"); ok {
			t.Fatal("valid gate flagged as removed")
		}
		if _, ok := k8s135DriftMetric(t, c, "removed-feature-gate", "ExecProbeTimeout"); ok {
			t.Fatal("second candidate file audited despite first candidate already matching")
		}
	})

	t.Run("unparseable kubelet config emits unreadable finding", func(t *testing.T) {
		cfg, _ := fixture(t)
		cfg.applyDefaults()
		testutil.WriteFile(t, cfg.KubeletConfigPaths[1], ":::not: [valid yaml\n")
		c := New(cfg)
		if v, ok := k8s135DriftMetric(t, c, "unreadable", "kubelet-config"); !ok || v != 1 {
			t.Fatalf("unreadable kubelet-config = (%v, %v), want (1, true)", v, ok)
		}
	})
}

func TestK8s135ReadinessK0sWorkerProfilesAndDeduplication(t *testing.T) {
	t.Run("audits k0s.yaml workerProfiles on worker node without K0sUnitFile and deduplicates", func(t *testing.T) {
		cfg, _ := fixture(t)
		cfg.applyDefaults()
		// Deliberately leave K0sUnitFile absent (worker node).
		testutil.WriteFile(t, cfg.KubeletConfigPaths[0], `
cgroupDriver: cgroupfs
failCgroupV1: false
featureGates:
  KubeletEnsureSecretPulledImages: false
`)
		testutil.WriteFile(t, cfg.K0sConfigFile, `
apiVersion: k0s.k0sproject.io/v1beta1
kind: ClusterConfig
spec:
  workerProfiles:
    - name: default
      values:
        cgroupDriver: cgroupfs
        failCgroupV1: false
        featureGates:
          KubeletEnsureSecretPulledImages: false
    - name: gpu
      values:
        cgroupDriver: cgroupfs
        featureGates:
          DynamicKubeletConfig: false
`)
		c := New(cfg)
		// Gather() must succeed without duplicate metric-label errors.
		if got := gatherK8s135DriftCount(t, c); got != 4 {
			t.Fatalf("deduplicated readiness finding count = %d, want 4", got)
		}
		if _, ok := metricValue(t, c, "node_k0s_config_drift", map[string]string{"reason": "none", "key": "none"}); ok {
			t.Fatal("node_k0s_config_drift leaked onto worker node without K0sUnitFile")
		}
	})

	t.Run("unparseable k0s.yaml does not duplicate unreadable finding into K5", func(t *testing.T) {
		cfg, _ := fixture(t)
		testutil.WriteFile(t, cfg.K0sUnitFile, "[Unit]\n")
		testutil.WriteFile(t, cfg.K0sConfigFile, ":::bad yaml [[[\n")
		c := New(cfg)
		if got := gatherK8s135DriftCount(t, c); got != 0 {
			t.Fatalf("unparseable k0s.yaml emitted %d K5 findings, want 0", got)
		}
	})
}

func TestK8s135ReadinessTextfileAndLatchLifecycle(t *testing.T) {
	t.Run("WriteTextfile omits series when clean and renders when drifted", func(t *testing.T) {
		cfg, _ := fixture(t)
		cfg.applyDefaults()
		c := New(cfg)
		outDir := t.TempDir()
		if err := c.WriteTextfile(outDir); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(outDir, TextfileName))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "node_host_agent_k8s135_readiness_drift") {
			t.Fatalf("clean host textfile emitted readiness drift:\n%s", data)
		}

		testutil.WriteFile(t, cfg.KubeletConfigPaths[0], "cgroupDriver: cgroupfs\n")
		if err := c.WriteTextfile(outDir); err != nil {
			t.Fatal(err)
		}
		data, err = os.ReadFile(filepath.Join(outDir, TextfileName))
		if err != nil {
			t.Fatal(err)
		}
		wantLine := `node_host_agent_k8s135_readiness_drift{key="cgroupDriver",node="node-a",reason="kubelet-cgroup-driver"} 1`
		if !strings.Contains(string(data), wantLine) {
			t.Fatalf("drifted textfile missing %q:\n%s", wantLine, data)
		}
	})

	t.Run("refreshLatches enters on drift, exits on recovery, and BUG-H6 touches Wave-5 latches", func(t *testing.T) {
		cfg, _ := fixture(t)
		fixed := time.Unix(1760000000, 0)
		cfg.Clock = timex.NewCell(func() time.Time { return fixed })
		cfg.WatchdogLogFile = filepath.Join(t.TempDir(), "watchdog.log")
		testutil.WriteFile(t, cfg.K0sConfigFile, `
spec:
  workerProfiles:
    - name: default
      values:
        cgroupDriver: cgroupfs
        failCgroupV1: false
        featureGates:
          KubeletEnsureSecretPulledImages: false
`)
		c := New(cfg)
		l := c.Latches()
		l.refreshLatches(context.Background())

		latchPath := filepath.Join(cfg.WatchdogStateDir,
			latchdefs.LatchFilePrefix+latchdefs.LatchK8s135ReadinessDrift)
		if _, err := os.Stat(latchPath); err != nil {
			t.Fatalf("state-k8s135-readiness-drift missing on drift: %v", err)
		}
		logBytes, err := os.ReadFile(cfg.WatchdogLogFile)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(logBytes), latchdefs.StateEnterPrefix+latchdefs.LatchK8s135ReadinessDrift) {
			t.Fatalf("watchdog log missing STATE-ENTER:\n%s", logBytes)
		}

		// Age both Wave-5 latches past LatchTouchMinInterval; KMSv2 latch
		// must be touched by BUG-H6, and K5 latch stays alive while drift persists.
		kmsPath := filepath.Join(cfg.WatchdogStateDir,
			latchdefs.LatchFilePrefix+latchdefs.LatchKMSv2Unhealthy)
		testutil.WriteFile(t, kmsPath, "1700000000\n")
		old := fixed.Add(-48 * time.Hour)
		for _, p := range []string{latchPath, kmsPath} {
			if err := os.Chtimes(p, old, old); err != nil {
				t.Fatal(err)
			}
		}

		l.refreshLatches(context.Background())
		for _, p := range []string{latchPath, kmsPath} {
			fi, err := os.Stat(p)
			if err != nil {
				t.Fatalf("%s vanished: %v", p, err)
			}
			if !fi.ModTime().Equal(fixed) {
				t.Fatalf("%s mtime = %v, want touched %v", p, fi.ModTime(), fixed)
			}
		}

		// Recovery clears K5 latch and logs STATE-EXIT.
		testutil.WriteFile(t, cfg.K0sConfigFile, `
spec:
  workerProfiles:
    - name: default
      values:
        cgroupDriver: systemd
        failCgroupV1: true
`)
		bumpMtime(t, cfg.K0sConfigFile)
		l.refreshLatches(context.Background())
		if _, err := os.Stat(latchPath); !os.IsNotExist(err) {
			t.Fatalf("state-k8s135-readiness-drift still exists after recovery: %v", err)
		}
		logBytes, err = os.ReadFile(cfg.WatchdogLogFile)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(logBytes), latchdefs.StateExitPrefix+latchdefs.LatchK8s135ReadinessDrift) {
			t.Fatalf("watchdog log missing STATE-EXIT:\n%s", logBytes)
		}
	})
}

func TestK8s135ReadinessBoundedNonBlockingAndConfinement(t *testing.T) {
	t.Run("oversized sparse kubelet config emits unreadable on scrape and latch tick", func(t *testing.T) {
		cfg, _ := fixture(t)
		cfg.applyDefaults()
		if err := os.MkdirAll(filepath.Dir(cfg.KubeletConfigPaths[0]), 0o755); err != nil {
			t.Fatal(err)
		}
		f, err := os.Create(cfg.KubeletConfigPaths[0])
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(256 << 20); err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
		_ = f.Close()

		c := New(cfg)
		start := time.Now()
		if v, ok := k8s135DriftMetric(t, c, "unreadable", "kubelet-config"); !ok || v != 1 {
			t.Fatalf("oversized kubelet-config = (%v,%v), want (1,true)", v, ok)
		}
		if time.Since(start) > time.Second {
			t.Fatalf("oversized kubelet-config scrape took >1s")
		}

		start = time.Now()
		c.Latches().refreshLatches(context.Background())
		if time.Since(start) > time.Second {
			t.Fatalf("oversized kubelet-config refreshLatches took >1s")
		}
		latchPath := filepath.Join(cfg.WatchdogStateDir,
			latchdefs.LatchFilePrefix+latchdefs.LatchK8s135ReadinessDrift)
		if _, err := os.Stat(latchPath); err != nil {
			t.Fatalf("expected readiness drift latch on unreadable oversized kubelet config: %v", err)
		}
	})

	t.Run("named FIFO kubelet config emits unreadable promptly without deadlocking metrics or latches", func(t *testing.T) {
		cfg, _ := fixture(t)
		cfg.applyDefaults()
		if err := os.MkdirAll(filepath.Dir(cfg.KubeletConfigPaths[0]), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(cfg.KubeletConfigPaths[0], 0o600); err != nil {
			t.Fatal(err)
		}

		c := New(cfg)
		start := time.Now()
		if v, ok := k8s135DriftMetric(t, c, "unreadable", "kubelet-config"); !ok || v != 1 {
			t.Fatalf("FIFO kubelet-config = (%v,%v), want (1,true)", v, ok)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("FIFO kubelet-config scrape took %s, want <1s", elapsed)
		}

		start = time.Now()
		c.Latches().refreshLatches(context.Background())
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("FIFO kubelet-config refreshLatches took %s, want <1s", elapsed)
		}
	})

	t.Run("directory kubelet config emits unreadable without skipping", func(t *testing.T) {
		cfg, _ := fixture(t)
		cfg.applyDefaults()
		if err := os.MkdirAll(cfg.KubeletConfigPaths[0], 0o755); err != nil {
			t.Fatal(err)
		}
		c := New(cfg)
		if v, ok := k8s135DriftMetric(t, c, "unreadable", "kubelet-config"); !ok || v != 1 {
			t.Fatalf("dir kubelet-config = (%v,%v), want (1,true)", v, ok)
		}
	})

	t.Run("oversized and FIFO k0s.yaml on worker node do not block metrics or latches", func(t *testing.T) {
		for _, kind := range []string{"oversized", "fifo"} {
			t.Run(kind, func(t *testing.T) {
				cfg, _ := fixture(t)
				cfg.applyDefaults()
				if kind == "oversized" {
					f, err := os.Create(cfg.K0sConfigFile)
					if err != nil {
						t.Fatal(err)
					}
					if err := f.Truncate(256 << 20); err != nil {
						_ = f.Close()
						t.Fatal(err)
					}
					_ = f.Close()
				} else {
					if err := syscall.Mkfifo(cfg.K0sConfigFile, 0o600); err != nil {
						t.Fatal(err)
					}
				}

				c := New(cfg)
				start := time.Now()
				if got := gatherK8s135DriftCount(t, c); got != 0 {
					t.Fatalf("%s k0s.yaml on worker emitted %d K5 findings, want 0", kind, got)
				}
				if elapsed := time.Since(start); elapsed > time.Second {
					t.Fatalf("%s k0s.yaml scrape took %s, want <1s", kind, elapsed)
				}

				start = time.Now()
				c.Latches().refreshLatches(context.Background())
				if elapsed := time.Since(start); elapsed > time.Second {
					t.Fatalf("%s k0s.yaml refreshLatches took %s, want <1s", kind, elapsed)
				}
			})
		}
	})

	t.Run("HostRoot symlink escape on kubelet config rejected fail-closed", func(t *testing.T) {
		root := t.TempDir()
		realHR := filepath.Join(root, "real_hr")
		evilHR := filepath.Join(root, "real_hr_evil")
		if err := os.MkdirAll(filepath.Join(realHR, "run", "k0s", "kubelet"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(evilHR, 0o755); err != nil {
			t.Fatal(err)
		}
		testutil.WriteFile(t, filepath.Join(evilHR, "config.yaml"), "cgroupDriver: systemd\n")
		if err := os.Symlink(filepath.Join(evilHR, "config.yaml"), filepath.Join(realHR, "run", "k0s", "kubelet", "config.yaml")); err != nil {
			t.Fatal(err)
		}

		cfg, _ := fixture(t)
		cfg.HostRoot = realHR
		cfg.KubeletConfigPaths = nil
		cfg.applyDefaults()
		c := New(cfg)
		if v, ok := k8s135DriftMetric(t, c, "unreadable", "kubelet-config"); !ok || v != 1 {
			t.Fatalf("escaping kubelet-config symlink = (%v,%v), want (1,true)", v, ok)
		}
	})
}
