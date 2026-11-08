// env_test.go — ConfigFromEnv: every NODE_HOST_AGENT_* knob resolves
// through the env → watchdogconf → package-default chains, the
// host-fs paths are PathJoin-derived (NOT the "/host"-hardcoded
// package defaults), and the NOTIFY_SOCKET passthrough rides along.
package cdeps_test

import (
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostctx"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostexec"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/sdnotify"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

// envDeps builds the EnvDeps with a "/host2"-prefixing HostPath —
// any unchanged package-default path would show up unprefixed.
func envDeps(wd *watchdogconf.Config, src *watchdogconf.Reloader) cdeps.EnvDeps {
	return cdeps.EnvDeps{Deps: hostctx.Deps{
		Watchdog:                wd,
		WatchdogSrc:             src,
		WatchdogStateDir:        "/wd-state",
		WatchdogLogFile:         "/wd-state/log",
		HostRoot:                "/host2",
		HostPath:                func(p string) string { return "/host2" + p },
		Systemd:                 systemd.New(hostexec.Config{}),
		JournalDirs:             []string{"/j1", "/j2"},
		JournalUnreadableNeeded: 3,
		Clock:                   timex.NewCell(nil),
	}}
}

func TestConfigFromEnvDefaults(t *testing.T) {
	// Nothing set anywhere: every value is the compiled default or
	// the PathJoin-derived path.
	cfg := cdeps.ConfigFromEnv(envDeps(nil, nil))

	if cfg.Interval != 60*time.Second {
		t.Errorf("Interval=%s", cfg.Interval)
	}
	if cfg.ProcRoot != "/proc" {
		t.Errorf("ProcRoot=%s", cfg.ProcRoot)
	}
	// The Base splice carried the shared watchdog context.
	if cfg.WatchdogStateDir != "/wd-state" || cfg.WatchdogLogFile != "/wd-state/log" ||
		cfg.HostRoot != "/host2" || cfg.Systemd == nil || cfg.Clock == nil {
		t.Fatalf("Base splice incomplete: %+v", cfg.Base)
	}
	// PathJoin-derived paths — "/host2" prefixed, NOT defaultK0sDir.
	if cfg.K0sControllerUnitFile != "/host2/etc/systemd/system/k0scontroller.service" {
		t.Errorf("K0sControllerUnitFile=%s", cfg.K0sControllerUnitFile)
	}
	if cfg.EtcdBackupDir != "/host2/var/backups/etcd" {
		t.Errorf("EtcdBackupDir=%s", cfg.EtcdBackupDir)
	}
	if cfg.OOMLoop.CGroupEventsFile != "/host2/sys/fs/cgroup/system.slice/k0scontroller.service/memory.events" {
		t.Errorf("CGroupEventsFile=%s", cfg.OOMLoop.CGroupEventsFile)
	}
	if cfg.AdminKubeconfig != "/host2/var/lib/k0s/pki/admin.conf" ||
		cfg.AdminCert != "/host2/var/lib/k0s/pki/admin.crt" ||
		cfg.AdminKey != "/host2/var/lib/k0s/pki/admin.key" ||
		cfg.AdminCA != "/host2/var/lib/k0s/pki/ca.crt" {
		t.Errorf("admin paths unprefixed: %s %s %s %s",
			cfg.AdminKubeconfig, cfg.AdminCert, cfg.AdminKey, cfg.AdminCA)
	}
	if cfg.Feeder.StateDir != "/host2/var/lib/k0s-systemd-watchdog" ||
		cfg.Feeder.RemediatePeerFile != "/host2/etc/default/k0scontroller-watchdog" {
		t.Errorf("feeder paths: %s %s",
			cfg.Feeder.StateDir, cfg.Feeder.RemediatePeerFile)
	}
	if cfg.K0sDir != "/host2/var/lib/k0s" {
		t.Errorf("K0sDir=%s", cfg.K0sDir)
	}
	// Nil conf → the env→conf chains fall through empty.
	if cfg.Hub.SelfAPI != "" || cfg.Hub.PeerAPI != "" || cfg.Hub.KineDBProbe != "" {
		t.Errorf("hub identity derived from a nil conf: %+v", cfg.Hub)
	}
	if cfg.Sig13.Mode != "" || cfg.Sig13.StaleMinErrs != 15 ||
		cfg.Sig13.GapMin != 10000 || cfg.Sig13.MinRestart != 2*time.Hour {
		t.Errorf("Sig13 defaults: %+v", cfg.Sig13)
	}
	if cfg.EtcdGuard.Endpoint != cdeps.DefaultEtcdEndpoint ||
		cfg.EtcdGuard.DBSizeLimit != 0 {
		t.Errorf("EtcdGuard: %+v", cfg.EtcdGuard)
	}
	if cfg.TotalControllers != 0 || cfg.EtcdSnapshotDir != "" {
		t.Errorf("topology knobs: %d %q", cfg.TotalControllers, cfg.EtcdSnapshotDir)
	}
	if cfg.InsecureTLS != true || cfg.Feeder.Enabled != true {
		t.Errorf("bool defaults: insecure=%v feeder=%v", cfg.InsecureTLS, cfg.Feeder.Enabled)
	}
	// Journal blindness inputs spliced from the shared bundle.
	if len(cfg.JournalDirs) != 2 || cfg.JournalDirs[0] != "/j1" ||
		cfg.JournalUnreadableNeeded != 3 {
		t.Errorf("journal inputs: %v %d", cfg.JournalDirs, cfg.JournalUnreadableNeeded)
	}
}

func TestConfigFromEnvConfMiddleLayer(t *testing.T) {
	wd := &watchdogconf.Config{
		APISelf:             "10.9.0.1:6443",
		APIPeer:             "10.9.0.2:6443",
		KineDBProbe:         "10.9.0.5:5432",
		Sig13Autofix:        "dry-run",
		Sig13StaleMinErrs:   7,
		Sig13GapMin:         20000,
		Sig13GapCycles:      4,
		Sig13FrozenCycles:   5,
		Sig13SoloCycles:     6,
		Sig13MinRestartS:    3600,
		KineTTLAutofix:      "enforce",
		KineTTLMinRestartS:  1200,
		KineTTLCtlRestartS:  3600,
		KineTTLRewedgeCycle: 7,
		KinePoolAutofix:     "enforce",
		KinePoolMaxConns:    90,
		KinePoolCycles:      4,
		KinePoolMinRestartS: 900,
		OOMLoopAutofix:      "enforce",
		OOMLoopMinKills:     5,
		OOMLoopWindowS:      1800,
	}
	cfg := cdeps.ConfigFromEnv(envDeps(wd, nil))

	if cfg.Hub.SelfAPI != "10.9.0.1:6443" || cfg.Hub.PeerAPI != "10.9.0.2:6443" ||
		cfg.Hub.KineDBProbe != "10.9.0.5:5432" {
		t.Errorf("hub conf chain: %+v", cfg.Hub)
	}
	if cfg.Sig13.Mode != "dry-run" || cfg.Sig13.StaleMinErrs != 7 ||
		cfg.Sig13.GapMin != 20000 || cfg.Sig13.GapCycles != 4 ||
		cfg.Sig13.FrozenCycles != 5 || cfg.Sig13.SoloCycles != 6 ||
		cfg.Sig13.MinRestart != time.Hour {
		t.Errorf("sig13 conf chain: %+v", cfg.Sig13)
	}
	if cfg.KineTTL.Mode != "enforce" || cfg.KineTTL.MinRestart != 20*time.Minute ||
		cfg.KineTTL.CtlRestart != time.Hour || cfg.KineTTL.RewedgeCycles != 7 {
		t.Errorf("kine-ttl conf chain: %+v", cfg.KineTTL)
	}
	if cfg.KinePool.Mode != "enforce" || cfg.KinePool.MaxConns != 90 ||
		cfg.KinePool.Cycles != 4 || cfg.KinePool.MinRestart != 15*time.Minute {
		t.Errorf("kine-pool conf chain: %+v", cfg.KinePool)
	}
	if cfg.OOMLoop.Mode != "enforce" || cfg.OOMLoop.MinKills != 5 ||
		cfg.OOMLoop.Window != 30*time.Minute {
		t.Errorf("oomloop conf chain: %+v", cfg.OOMLoop)
	}
}

func TestConfigFromEnvWinsOverConf(t *testing.T) {
	t.Setenv(envnames.EnvAPISelf, "10.0.0.9:6443")
	t.Setenv(envnames.EnvStaleMinErrs, "11")
	t.Setenv(envnames.EnvGapMin, "30000")
	t.Setenv(envnames.EnvSig13MinRestartS, "600")
	t.Setenv(envnames.EnvControllerInterval, "45s")
	t.Setenv(envnames.EnvProcRoot, "/hostproc")
	t.Setenv(envnames.EnvControllerInsecureTLS, "false")
	t.Setenv(envnames.EnvEnableFeeder, "0")
	t.Setenv(envnames.EnvK0sDir, "/k0s-env")
	t.Setenv(envnames.EnvEtcdEndpoint, "https://10.1.1.5:2379")
	t.Setenv(envnames.EnvEtcdDBSizeLimit, "999")
	t.Setenv(envnames.EnvTotalControllers, "3")
	t.Setenv(envnames.EnvEtcdSnapshotDir, "/snaps")
	t.Setenv(sdnotify.SocketEnv, "/run/notify.sock")

	wd := &watchdogconf.Config{APISelf: "10.9.0.1:6443", Sig13StaleMinErrs: 7}
	cfg := cdeps.ConfigFromEnv(envDeps(wd, nil))

	if cfg.Hub.SelfAPI != "10.0.0.9:6443" {
		t.Errorf("env lost to conf: SelfAPI=%s", cfg.Hub.SelfAPI)
	}
	if cfg.Sig13.StaleMinErrs != 11 || cfg.Sig13.GapMin != 30000 ||
		cfg.Sig13.MinRestart != 10*time.Minute {
		t.Errorf("int/dur env chain: %+v", cfg.Sig13)
	}
	if cfg.Interval != 45*time.Second || cfg.ProcRoot != "/hostproc" {
		t.Errorf("base env knobs: %s %s", cfg.Interval, cfg.ProcRoot)
	}
	if cfg.InsecureTLS != false || cfg.Feeder.Enabled != false {
		t.Errorf("bool env knobs: %v %v", cfg.InsecureTLS, cfg.Feeder.Enabled)
	}
	// An explicit env K0sDir is used verbatim — NOT PathJoin'd.
	if cfg.K0sDir != "/k0s-env" {
		t.Errorf("K0sDir=%s", cfg.K0sDir)
	}
	if cfg.EtcdGuard.Endpoint != "https://10.1.1.5:2379" ||
		cfg.EtcdGuard.DBSizeLimit != 999 {
		t.Errorf("etcd env knobs: %+v", cfg.EtcdGuard)
	}
	if cfg.TotalControllers != 3 || cfg.EtcdSnapshotDir != "/snaps" {
		t.Errorf("topology env knobs: %d %q", cfg.TotalControllers, cfg.EtcdSnapshotDir)
	}
	if cfg.Feeder.NotifySocket != "/run/notify.sock" {
		t.Errorf("NOTIFY_SOCKET passthrough: %q", cfg.Feeder.NotifySocket)
	}
}

// A set-but-non-numeric env int falls back to the default, not the
// conf value — the lenient shell-knob contract.
func TestConfigFromEnvGarbageIntFallsBack(t *testing.T) {
	t.Setenv(envnames.EnvStaleMinErrs, "not-a-number")
	cfg := cdeps.ConfigFromEnv(envDeps(nil, nil))
	if cfg.Sig13.StaleMinErrs != 15 {
		t.Errorf("garbage env int produced %d want default 15", cfg.Sig13.StaleMinErrs)
	}
}
