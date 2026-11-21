// kernel_drift_vars_test.go — adversarial tests verifying hostmetrics/kernelfail
// THP target precedence matches hostconfig (env > VarsDir > compiled default)
// and reloads VarsDir dynamically without heal-revert tug-of-war.
package hostmetrics

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostctx"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

func seedTHPSysfs(t *testing.T, hostRoot, enabled, defrag string) {
	t.Helper()
	dir := filepath.Join(hostRoot, "sys", "kernel", "mm", "transparent_hugepage")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(dir, "enabled"), enabled)
	testutil.WriteFile(t, filepath.Join(dir, "defrag"), defrag)
}

func TestTHPVarsDirPrecedenceMatchesHostconfig(t *testing.T) {
	root := t.TempDir()
	varsDir := filepath.Join(root, "vars")
	hostRoot := filepath.Join(root, "host")
	procRoot := filepath.Join(root, "proc")
	stateDir := filepath.Join(root, "state")
	logFile := filepath.Join(root, "watchdog.log")
	for _, d := range []string{varsDir, hostRoot, procRoot, stateDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// Seed VarsDir with host_thp_enabled=never and host_thp_defrag=never (env unset).
	testutil.WriteFile(t, filepath.Join(varsDir, "defaults.yaml"),
		"host_thp_enabled: never\nhost_thp_defrag: never\n")
	// Sysfs already converged by hostconfig to [never].
	seedTHPSysfs(t, hostRoot, "always madvise [never]\n", "always defer defer+madvise madvise [never]\n")

	t.Setenv(envnames.EnvTHPEnabled, "")
	t.Setenv(envnames.EnvTHPDefrag, "")
	t.Setenv(envnames.EnvHostconfigVarsDir, varsDir)

	baseCfg, _ := fixture(t)
	deps := hostctx.Deps{
		NodeName:         "node-a",
		HostRoot:         hostRoot,
		VarsDir:          varsDir,
		WatchdogStateDir: stateDir,
		WatchdogLogFile:  logFile,
		Clock:            timex.NewCell(func() time.Time { return time.Unix(1760000000, 0) }),
	}
	cfg := ConfigFromEnv(EnvDeps{Deps: deps})
	// Keep all unrelated filesystem/proc probes hermetic like fixture(t).
	cfg.HostRoot = hostRoot
	cfg.ProcRoot = procRoot
	cfg.PSIFile = baseCfg.PSIFile
	cfg.NebulaCertFile = baseCfg.NebulaCertFile
	cfg.FilesystemTargets = nil
	cfg.KeyUsersFile = baseCfg.KeyUsersFile
	cfg.ClocksourceCurrentFile = baseCfg.ClocksourceCurrentFile
	cfg.ClocksourceAvailableFile = baseCfg.ClocksourceAvailableFile
	cfg.BpffsDir = filepath.Join(root, "no-bpffs")
	cfg.kmsgDevicePaths = baseCfg.kmsgDevicePaths
	cfg.adjtimexFn = baseCfg.adjtimexFn
	cfg.statfsFn = baseCfg.statfsFn
	cfg.TCPCensusFn = baseCfg.TCPCensusFn
	cfg.cpuMeasure = baseCfg.cpuMeasure

	var healCalls [][]string
	cfg.runHostCmd = func(_ context.Context, argv ...string) (string, error) {
		for _, a := range argv {
			if strings.Contains(a, "transparent_hugepage") {
				healCalls = append(healCalls, slices.Clone(argv))
				break
			}
		}
		return "", nil
	}

	if cfg.THPEnabled != "" || cfg.THPDefrag != "" {
		t.Fatalf("ConfigFromEnv with unset THP env = (%q, %q), want empty overrides", cfg.THPEnabled, cfg.THPDefrag)
	}

	c := New(cfg)
	if en, df := c.THPTargets(); en != "never" || df != "never" {
		t.Fatalf("THPTargets() = (%q, %q), want (never, never)", en, df)
	}

	// Run 3 latch ticks: sysfs=[never] matches VarsDir -> zero THP heal calls, zero HostKernelDrift latch.
	for i := range 3 {
		c.Latches().refreshLatches(context.Background())
		if len(healCalls) != 0 {
			t.Fatalf("tick %d: unexpected RunHostCmd heal calls when sysfs matches VarsDir: %v", i+1, healCalls)
		}
	}
	latchPath := filepath.Join(stateDir, latchdefs.LatchFilePrefix+latchdefs.LatchHostKernelDrift)
	if _, err := os.Stat(latchPath); !os.IsNotExist(err) {
		t.Fatalf("HostKernelDrift latch raised despite matching VarsDir: err=%v", err)
	}

	// Runtime VarsDir update (cluster.yaml overrides enabled to madvise; defrag stays never).
	testutil.WriteFile(t, filepath.Join(varsDir, "cluster.yaml"), "host_thp_enabled: madvise\n")
	if en, df := c.THPTargets(); en != "madvise" || df != "never" {
		t.Fatalf("after cluster.yaml update THPTargets() = (%q, %q), want (madvise, never)", en, df)
	}
	c.Latches().refreshLatches(context.Background())
	if len(healCalls) != 1 || healCalls[0][4] != "madvise" || healCalls[0][5] != "/sys/kernel/mm/transparent_hugepage/enabled" {
		t.Fatalf("expected enabled-only heal to madvise after cluster.yaml update, got %v", healCalls)
	}

	// Env var overrides VarsDir (partial override: enabled from env, defrag still from VarsDir).
	t.Setenv(envnames.EnvTHPEnabled, "always")
	cfgEnvPartial := ConfigFromEnv(EnvDeps{Deps: deps})
	cfgEnvPartial.HostRoot = hostRoot
	cfgEnvPartial.ProcRoot = procRoot
	cfgEnvPartial.BpffsDir = filepath.Join(root, "no-bpffs")
	cfgEnvPartial.kmsgDevicePaths = baseCfg.kmsgDevicePaths
	cfgEnvPartial.adjtimexFn = baseCfg.adjtimexFn
	cfgEnvPartial.statfsFn = baseCfg.statfsFn
	cfgEnvPartial.TCPCensusFn = baseCfg.TCPCensusFn
	cfgEnvPartial.cpuMeasure = baseCfg.cpuMeasure
	cfgEnvPartial.runHostCmd = baseCfg.runHostCmd
	cPartial := New(cfgEnvPartial)
	if en, df := cPartial.THPTargets(); en != "always" || df != "never" {
		t.Fatalf("partial env override THPTargets() = (%q, %q), want (always, never)", en, df)
	}

	// Full env override beats VarsDir on both knobs and heals sysfs to env targets.
	t.Setenv(envnames.EnvTHPDefrag, "defer+madvise")
	cfgEnvFull := ConfigFromEnv(EnvDeps{Deps: deps})
	cfgEnvFull.HostRoot = hostRoot
	cfgEnvFull.ProcRoot = procRoot
	cfgEnvFull.PSIFile = baseCfg.PSIFile
	cfgEnvFull.NebulaCertFile = baseCfg.NebulaCertFile
	cfgEnvFull.FilesystemTargets = nil
	cfgEnvFull.KeyUsersFile = baseCfg.KeyUsersFile
	cfgEnvFull.ClocksourceCurrentFile = baseCfg.ClocksourceCurrentFile
	cfgEnvFull.ClocksourceAvailableFile = baseCfg.ClocksourceAvailableFile
	cfgEnvFull.BpffsDir = filepath.Join(root, "no-bpffs")
	cfgEnvFull.kmsgDevicePaths = baseCfg.kmsgDevicePaths
	cfgEnvFull.adjtimexFn = baseCfg.adjtimexFn
	cfgEnvFull.statfsFn = baseCfg.statfsFn
	cfgEnvFull.TCPCensusFn = baseCfg.TCPCensusFn
	cfgEnvFull.cpuMeasure = baseCfg.cpuMeasure
	var envHeals [][]string
	cfgEnvFull.runHostCmd = func(_ context.Context, argv ...string) (string, error) {
		for _, a := range argv {
			if strings.Contains(a, "transparent_hugepage") {
				envHeals = append(envHeals, slices.Clone(argv))
				break
			}
		}
		return "", nil
	}
	cFull := New(cfgEnvFull)
	if en, df := cFull.THPTargets(); en != "always" || df != "defer+madvise" {
		t.Fatalf("full env override THPTargets() = (%q, %q), want (always, defer+madvise)", en, df)
	}
	cFull.Latches().refreshLatches(context.Background())
	if len(envHeals) != 2 || envHeals[0][4] != "always" || envHeals[1][4] != "defer+madvise" {
		t.Fatalf("expected env override heals (always, defer+madvise), got %v", envHeals)
	}
}
