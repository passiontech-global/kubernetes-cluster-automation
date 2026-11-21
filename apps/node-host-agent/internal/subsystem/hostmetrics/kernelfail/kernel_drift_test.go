// kernel_drift_test.go — unit tests for Wave-4 #9 Host Kernel Drift Guard.
package kernelfail

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

func seedTHP(t *testing.T, hostRoot, enabled, defrag string) {
	t.Helper()
	dir := filepath.Join(hostRoot, "sys", "kernel", "mm", "transparent_hugepage")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if enabled != "" {
		testutil.WriteFile(t, filepath.Join(dir, "enabled"), enabled)
	}
	if defrag != "" {
		testutil.WriteFile(t, filepath.Join(dir, "defrag"), defrag)
	}
}

func seedRPFilter(t *testing.T, procRoot string, vals map[string]string) {
	t.Helper()
	for iface, val := range vals {
		dir := filepath.Join(procRoot, "sys", "net", "ipv4", "conf", iface)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		testutil.WriteFile(t, filepath.Join(dir, "rp_filter"), val+"\n")
	}
}

func TestParseBracketedSysfs(t *testing.T) {
	tests := []struct {
		name   string
		raw    string
		want   string
		wantOK bool
	}{
		{name: "madvise", raw: "always [madvise] never\n", want: "madvise", wantOK: true},
		{name: "defer_plus_madvise", raw: "always defer [defer+madvise] madvise never\n", want: "defer+madvise", wantOK: true},
		{name: "single_bare", raw: "madvise\n", want: "madvise", wantOK: true},
		{name: "empty", raw: "", want: "", wantOK: false},
		{name: "whitespace", raw: "  \n", want: "", wantOK: false},
		{name: "unbracketed_multi", raw: "always madvise never\n", want: "", wantOK: false},
		{name: "empty_brackets", raw: "always [] never\n", want: "", wantOK: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseBracketedSysfs([]byte(tc.raw))
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("parseBracketedSysfs(%q) = (%q, %v), want (%q, %v)", tc.raw, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestKernelDriftInconclusiveDoesNotClearLatch(t *testing.T) {
	f := kfixture(t)
	latchPath := f.deps.Store.Path(latchdefs.LatchHostKernelDrift)
	testutil.WriteFile(t, latchPath, "1700000000\n")
	f.r.kernelDriftStreak = 1

	// Empty HostRoot and ProcRoot -> 0 readable targets -> inconclusive.
	f.r.updateKernelDrift(context.Background())

	if _, err := os.Stat(latchPath); err != nil {
		t.Fatalf("inconclusive read cleared pre-seeded latch: %v", err)
	}
	if f.r.kernelDriftStreak != 1 {
		t.Fatalf("inconclusive read reset streak to %d, want 1", f.r.kernelDriftStreak)
	}
}

func TestKernelDriftHealthyClearsLatch(t *testing.T) {
	f := kfixture(t)
	f.deps.Store.Enter(latchdefs.LatchHostKernelDrift, "prior drift")
	f.r.kernelDriftStreak = 3

	seedTHP(t, f.deps.HostRoot, "always [madvise] never\n", "always defer [defer+madvise] madvise never\n")
	seedRPFilter(t, f.deps.ProcRoot, map[string]string{
		"all":         "2",
		"default":     "2",
		"cilium_host": "0",
		"nebula0":     "0",
		"neb1":        "0",
		"lxc1":        "0",
		"eth0":        "1", // physical NICs ignored
	})

	f.r.updateKernelDrift(context.Background())

	latchPath := f.deps.Store.Path(latchdefs.LatchHostKernelDrift)
	if _, err := os.Stat(latchPath); !os.IsNotExist(err) {
		t.Fatalf("healthy state did not clear latch: %v", err)
	}
	if f.r.kernelDriftStreak != 0 {
		t.Fatalf("healthy state streak = %d, want 0", f.r.kernelDriftStreak)
	}
	logBytes, err := os.ReadFile(f.log)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logBytes), latchdefs.StateExitPrefix+latchdefs.LatchHostKernelDrift) {
		t.Fatalf("expected STATE-EXIT in log:\n%s", logBytes)
	}
}

func TestKernelDriftTransientHealClearsWithoutLatch(t *testing.T) {
	f := kfixture(t)
	f.r.deps.KernelDriftHeal = true

	seedTHP(t, f.deps.HostRoot, "[always] madvise never\n", "[always] defer defer+madvise madvise never\n")
	seedRPFilter(t, f.deps.ProcRoot, map[string]string{
		"all":         "1",
		"default":     "1",
		"cilium_host": "1",
		"nebula0":     "1",
		"neb1":        "1",
		"lxc1":        "1",
		"eth0":        "1", // physical NIC must NOT be touched or flagged
	})

	var calls [][]string
	f.r.deps.RunHostCmd = func(_ context.Context, argv ...string) (string, error) {
		calls = append(calls, slices.Clone(argv))
		// Apply simulated heal onto the fixture files so tick 2 reads clean.
		if len(argv) >= 6 && argv[0] == "sh" && argv[1] == "-c" {
			switch argv[5] {
			case "/sys/kernel/mm/transparent_hugepage/enabled":
				seedTHP(t, f.deps.HostRoot, "always ["+argv[4]+"] never\n", "")
			case "/sys/kernel/mm/transparent_hugepage/defrag":
				seedTHP(t, f.deps.HostRoot, "", "always defer ["+argv[4]+"] madvise never\n")
			}
		} else if len(argv) == 3 && argv[0] == "sysctl" && argv[1] == "-w" {
			kv := strings.TrimPrefix(argv[2], "net.ipv4.conf.")
			iface, val, ok := strings.Cut(kv, ".rp_filter=")
			if ok {
				seedRPFilter(t, f.deps.ProcRoot, map[string]string{iface: val})
			}
		}
		return "", nil
	}

	// Tick 1: heals all drifted targets, logs ACTION:, does NOT raise latch.
	f.r.updateKernelDrift(context.Background())

	latchPath := f.deps.Store.Path(latchdefs.LatchHostKernelDrift)
	if _, err := os.Stat(latchPath); !os.IsNotExist(err) {
		t.Fatal("latch raised prematurely on tick 1 transient drift")
	}
	if f.r.kernelDriftStreak != 1 {
		t.Fatalf("streak = %d, want 1", f.r.kernelDriftStreak)
	}

	wantCalls := [][]string{
		{"sh", "-c", "printf '%s' \"$1\" > \"$2\"", "sh", "madvise", "/sys/kernel/mm/transparent_hugepage/enabled"},
		{"sh", "-c", "printf '%s' \"$1\" > \"$2\"", "sh", "defer+madvise", "/sys/kernel/mm/transparent_hugepage/defrag"},
		{"sysctl", "-w", "net.ipv4.conf.all.rp_filter=2"},
		{"sysctl", "-w", "net.ipv4.conf.cilium_host.rp_filter=0"},
		{"sysctl", "-w", "net.ipv4.conf.default.rp_filter=2"},
		{"sysctl", "-w", "net.ipv4.conf.lxc1.rp_filter=0"},
		{"sysctl", "-w", "net.ipv4.conf.neb1.rp_filter=0"},
		{"sysctl", "-w", "net.ipv4.conf.nebula0.rp_filter=0"},
	}
	if len(calls) != len(wantCalls) {
		t.Fatalf("RunHostCmd calls (%d) = %v, want (%d) %v", len(calls), calls, len(wantCalls), wantCalls)
	}
	for i := range wantCalls {
		if !slices.Equal(calls[i], wantCalls[i]) {
			t.Fatalf("call[%d] = %v, want %v", i, calls[i], wantCalls[i])
		}
	}

	logBytes, err := os.ReadFile(f.log)
	if err != nil {
		t.Fatal(err)
	}
	logStr := string(logBytes)
	for _, want := range []string{
		latchdefs.ActionPrefix + "healed THP enabled always->madvise",
		latchdefs.ActionPrefix + "healed THP defrag always->defer+madvise",
		latchdefs.ActionPrefix + "healed net.ipv4.conf.all.rp_filter=2 (was 1)",
		latchdefs.ActionPrefix + "healed net.ipv4.conf.cilium_host.rp_filter=0 (was 1)",
	} {
		if !strings.Contains(logStr, want) {
			t.Fatalf("log missing %q:\n%s", want, logStr)
		}
	}

	// Tick 2: converged -> streak resets, no extra RunHostCmd calls, latch remains absent.
	calls = nil
	f.r.updateKernelDrift(context.Background())
	if len(calls) != 0 {
		t.Fatalf("unexpected RunHostCmd calls after heal: %v", calls)
	}
	if f.r.kernelDriftStreak != 0 {
		t.Fatalf("streak after convergence = %d, want 0", f.r.kernelDriftStreak)
	}
	if _, err := os.Stat(latchPath); !os.IsNotExist(err) {
		t.Fatal("latch appeared after converged tick")
	}
}

func TestKernelDriftPersistentRaisesLatchAndClears(t *testing.T) {
	t.Run("heal_fails", func(t *testing.T) {
		f := kfixture(t)
		now := time.Unix(1760000000, 0)
		f.deps.Clock.Set(func() time.Time { return now })
		f.r.deps.KernelDriftHeal = true
		f.r.deps.RunHostCmd = func(context.Context, ...string) (string, error) {
			return "read-only filesystem", errors.New("exit status 1")
		}

		seedTHP(t, f.deps.HostRoot, "[always] madvise never\n", "always defer [defer+madvise] madvise never\n")
		seedRPFilter(t, f.deps.ProcRoot, map[string]string{"cilium_host": "1"})

		latchPath := f.deps.Store.Path(latchdefs.LatchHostKernelDrift)

		// Tick 1: streak=1, no latch yet.
		f.r.updateKernelDrift(context.Background())
		if _, err := os.Stat(latchPath); !os.IsNotExist(err) {
			t.Fatal("latch set on tick 1")
		}

		// Tick 2: streak=2 >= 2 -> latch raised + STATE-ENTER logged.
		f.r.updateKernelDrift(context.Background())
		if _, err := os.Stat(latchPath); err != nil {
			t.Fatalf("latch missing after tick 2: %v", err)
		}
		logStr := testutil.ReadFile(t, f.log)
		if !strings.Contains(logStr, latchdefs.StateEnterPrefix+latchdefs.LatchHostKernelDrift) ||
			!strings.Contains(logStr, "thp.enabled=always!=madvise") ||
			!strings.Contains(logStr, "rp_filter.cilium_host=1!=0") {
			t.Fatalf("STATE-ENTER evidence wrong:\n%s", logStr)
		}

		// Tick 3 with aged latch: ensureStateLatch refreshes mtime via TouchIfDue.
		old := now.Add(-48 * time.Hour)
		if err := os.Chtimes(latchPath, old, old); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Minute)
		f.r.updateKernelDrift(context.Background())
		fi, err := os.Stat(latchPath)
		if err != nil {
			t.Fatal(err)
		}
		if !fi.ModTime().Equal(now) {
			t.Fatalf("held latch mtime = %v, want %v", fi.ModTime(), now)
		}

		// Recovery: values converge -> latch cleared + STATE-EXIT logged.
		seedTHP(t, f.deps.HostRoot, "always [madvise] never\n", "")
		seedRPFilter(t, f.deps.ProcRoot, map[string]string{"cilium_host": "0"})
		f.r.updateKernelDrift(context.Background())
		if _, err := os.Stat(latchPath); !os.IsNotExist(err) {
			t.Fatal("latch not cleared on recovery")
		}
		logStr = testutil.ReadFile(t, f.log)
		if !strings.Contains(logStr, latchdefs.StateExitPrefix+latchdefs.LatchHostKernelDrift) {
			t.Fatalf("STATE-EXIT missing:\n%s", logStr)
		}
	})

	t.Run("heal_disabled", func(t *testing.T) {
		f := kfixture(t)
		f.r.deps.KernelDriftHeal = false
		cmdCalled := false
		f.r.deps.RunHostCmd = func(context.Context, ...string) (string, error) {
			cmdCalled = true
			return "", nil
		}

		seedTHP(t, f.deps.HostRoot, "[always] madvise never\n", "always defer [defer+madvise] madvise never\n")
		latchPath := f.deps.Store.Path(latchdefs.LatchHostKernelDrift)

		f.r.updateKernelDrift(context.Background())
		if _, err := os.Stat(latchPath); !os.IsNotExist(err) {
			t.Fatal("latch set on tick 1 with heal disabled")
		}
		f.r.updateKernelDrift(context.Background())
		if _, err := os.Stat(latchPath); err != nil {
			t.Fatalf("latch missing after tick 2 with heal disabled: %v", err)
		}
		if cmdCalled {
			t.Fatal("RunHostCmd invoked when KernelDriftHeal=false")
		}

		seedTHP(t, f.deps.HostRoot, "always [madvise] never\n", "")
		f.r.updateKernelDrift(context.Background())
		if _, err := os.Stat(latchPath); !os.IsNotExist(err) {
			t.Fatal("latch not cleared on recovery with heal disabled")
		}
	})
}

func TestKernelDriftTHPOverrideTargetsAndUnsafeGuard(t *testing.T) {
	f := kfixture(t)
	f.r.deps.KernelDriftHeal = true
	f.r.deps.THPEnabled = "always"
	f.r.deps.THPDefrag = "never"

	seedTHP(t, f.deps.HostRoot, "always [madvise] never\n", "always defer [defer+madvise] madvise never\n")

	var calls [][]string
	f.r.deps.RunHostCmd = func(_ context.Context, argv ...string) (string, error) {
		calls = append(calls, slices.Clone(argv))
		return "", nil
	}

	f.r.updateKernelDrift(context.Background())
	if len(calls) != 2 {
		t.Fatalf("expected 2 custom THP heal calls, got %v", calls)
	}
	if calls[0][4] != "always" || calls[1][4] != "never" {
		t.Fatalf("custom THP heal targets = (%q, %q), want (always, never)", calls[0][4], calls[1][4])
	}

	// Unsafe target token must never reach RunHostCmd.
	seedTHP(t, f.deps.HostRoot, "", "always defer defer+madvise madvise [never]\n")
	f.r.deps.THPEnabled = "always; rm -rf /"
	calls = nil
	f.r.updateKernelDrift(context.Background())
	if len(calls) != 0 {
		t.Fatalf("unsafe THP target passed to RunHostCmd: %v", calls)
	}
}

func TestKernelDriftVarsDirAndConcurrentReload(t *testing.T) {
	t.Run("full_topology_override_and_jinja", func(t *testing.T) {
		f := kfixture(t)
		varsDir := t.TempDir()
		testutil.WriteFile(t, filepath.Join(varsDir, "interdc_nodes.yaml"), "node-a:\n  name: a\n  ip: 10.0.0.1\n  site: s1\n")
		testutil.WriteFile(t, filepath.Join(varsDir, "defaults.yaml"), "host_thp_enabled: always\nthp_defrag_mode: madvise\n")
		testutil.WriteFile(t, filepath.Join(varsDir, "cluster.yaml"), "host_thp_enabled: never\nhost_thp_defrag: \"{{ thp_defrag_mode }}\"\n")

		f.r.deps.VarsDir = varsDir
		f.r.deps.NodeName = "node-a"
		if en, df := f.r.THPTargets(); en != "never" || df != "madvise" {
			t.Fatalf("THPTargets() = (%q, %q), want (never, madvise)", en, df)
		}
	})

	t.Run("malformed_yaml_keeps_last_good_and_recovers", func(t *testing.T) {
		f := kfixture(t)
		varsDir := t.TempDir()
		defaultsPath := filepath.Join(varsDir, "defaults.yaml")
		testutil.WriteFile(t, defaultsPath, "host_thp_enabled: never\nhost_thp_defrag: never\n")
		f.r.deps.VarsDir = varsDir

		if en, df := f.r.THPTargets(); en != "never" || df != "never" {
			t.Fatalf("initial THPTargets() = (%q, %q), want (never, never)", en, df)
		}

		// Corrupt YAML -> must preserve last good ("never", "never"), not revert to madvise.
		testutil.WriteFile(t, defaultsPath, "host_thp_enabled: [\n")
		if en, df := f.r.THPTargets(); en != "never" || df != "never" {
			t.Fatalf("corrupt YAML THPTargets() = (%q, %q), want preserved (never, never)", en, df)
		}

		// Valid update -> picks up new values cleanly.
		testutil.WriteFile(t, defaultsPath, "host_thp_enabled: always\nhost_thp_defrag: defer\n")
		if en, df := f.r.THPTargets(); en != "always" || df != "defer" {
			t.Fatalf("recovered THPTargets() = (%q, %q), want (always, defer)", en, df)
		}
	})

	t.Run("concurrent_reads_and_atomic_updates_race_free", func(t *testing.T) {
		f := kfixture(t)
		varsDir := t.TempDir()
		defaultsPath := filepath.Join(varsDir, "defaults.yaml")
		testutil.WriteFile(t, defaultsPath, "host_thp_enabled: never\nhost_thp_defrag: never\n")
		f.r.deps.VarsDir = varsDir

		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range 30 {
					en, df := f.r.THPTargets()
					if en == "" || df == "" {
						t.Errorf("empty THPTargets (%q, %q)", en, df)
					}
				}
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 10 {
				tmp := defaultsPath + ".tmp"
				val := "never"
				if i%2 == 0 {
					val = "always"
				}
				_ = os.WriteFile(tmp, []byte("host_thp_enabled: "+val+"\nhost_thp_defrag: "+val+"\n"), 0o644)
				_ = os.Rename(tmp, defaultsPath)
			}
		}()
		wg.Wait()
	})
}
