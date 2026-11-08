// config_test.go — the Config surface: ApplyDefaults fills every
// unset knob from the package defaults (the per-domain apply* blocks)
// and wires the seam defaults; set knobs survive untouched and the
// $K0SDIR placeholder resolves in preset PKI pairs.
package cdeps_test

import (
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/sdnotify"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
)

func TestApplyDefaultsFullTable(t *testing.T) {
	// Deterministic env: the feeder's NOTIFY_SOCKET passthrough
	// must see an empty var in the base case.
	t.Setenv(sdnotify.SocketEnv, "")
	var c cdeps.Config
	c.ApplyDefaults()

	if c.Interval != 60*time.Second {
		t.Errorf("Interval=%s", c.Interval)
	}
	if c.CycleTimeout != 15*time.Minute {
		t.Errorf("CycleTimeout=%s", c.CycleTimeout)
	}
	if c.WatchdogStateDir != "/host/var/lib/node-watchdog" ||
		c.WatchdogLogFile != "/host/var/log/node-watchdog.log" ||
		c.ProcRoot != "/proc" {
		t.Errorf("base paths: %s %s %s", c.WatchdogStateDir, c.WatchdogLogFile, c.ProcRoot)
	}
	if c.K0sControllerUnitFile != "/host/etc/systemd/system/k0scontroller.service" ||
		c.JournalUnit != "k0scontroller" ||
		c.RestartUnit != "k0scontroller.service" {
		t.Errorf("unit knobs: %s %s %s",
			c.K0sControllerUnitFile, c.JournalUnit, c.RestartUnit)
	}
	if c.Hub.SelfEndpoint != "127.0.0.1:6443" {
		t.Errorf("Hub.SelfEndpoint=%s", c.Hub.SelfEndpoint)
	}
	// SelfAPI deliberately has NO default — the first-hub identity.
	if c.Hub.SelfAPI != "" {
		t.Errorf("Hub.SelfAPI=%s want empty", c.Hub.SelfAPI)
	}
	if c.AdminKubeconfig != "/host/var/lib/k0s/pki/admin.conf" ||
		c.AdminCert != "/host/var/lib/k0s/pki/admin.crt" ||
		c.AdminKey != "/host/var/lib/k0s/pki/admin.key" ||
		c.AdminCA != "/host/var/lib/k0s/pki/ca.crt" {
		t.Errorf("admin paths: %s %s %s %s",
			c.AdminKubeconfig, c.AdminCert, c.AdminKey, c.AdminCA)
	}
	if c.APIPath != "/api/v1/namespaces/default/services" ||
		c.QueryTimeout != 12*time.Second {
		t.Errorf("probe surface: %s %s", c.APIPath, c.QueryTimeout)
	}
	// Sig13 (config_hub).
	if c.Sig13.Mode != cdeps.ModeOff || c.Sig13.StaleMinErrs != 15 ||
		c.Sig13.GapMin != 10000 || c.Sig13.GapCycles != 2 ||
		c.Sig13.FrozenCycles != 2 || c.Sig13.SoloCycles != 8 ||
		c.Sig13.MinRestart != 2*time.Hour {
		t.Errorf("Sig13=%+v", c.Sig13)
	}
	// KineTTL + KinePool (config_kine).
	if c.KineTTL.Mode != cdeps.ModeOff || c.KineTTL.MinRestart != 30*time.Minute ||
		c.KineTTL.CtlRestart != 2*time.Hour || c.KineTTL.RewedgeCycles != 2 ||
		c.KineTTL.MinProcAge != 300*time.Second {
		t.Errorf("KineTTL=%+v", c.KineTTL)
	}
	if c.KinePool.Mode != cdeps.ModeOff || c.KinePool.MaxConns != 72 ||
		c.KinePool.Cycles != 3 || c.KinePool.MinRestart != 20*time.Minute ||
		c.KinePool.DBPortFallback != 6432 {
		t.Errorf("KinePool=%+v", c.KinePool)
	}
	// OOMLoop (config_oomloop).
	if c.OOMLoop.Mode != cdeps.ModeOff || c.OOMLoop.MinKills != 3 ||
		c.OOMLoop.Window != time.Hour ||
		c.OOMLoop.CGroupEventsFile != "/host/sys/fs/cgroup/system.slice/k0scontroller.service/memory.events" ||
		c.OOMLoop.APIServerShieldAdj != -800 || c.OOMLoop.KineShieldAdj != 500 {
		t.Errorf("OOMLoop=%+v", c.OOMLoop)
	}
	// Feeder (config_feeder). Enabled itself is NOT defaulted here —
	// its true default lives in the NODE_HOST_AGENT_ENABLE_FEEDER env
	// knob (ConfigFromEnv); a programmatic zero-Config stays off.
	if c.Feeder.Enabled != false || c.Feeder.Interval != 15*time.Second ||
		c.Feeder.MaxFail != 4 || c.Feeder.GraceFails != 8 ||
		c.Feeder.ProbeURL != "https://127.0.0.1:6443/readyz" ||
		c.Feeder.ProbeTO != 5*time.Second ||
		c.Feeder.StateDir != "/host/var/lib/k0s-systemd-watchdog" ||
		c.Feeder.RemediateMinRestart != 30*time.Minute ||
		c.Feeder.RemediateFreshGrace != 90*time.Second ||
		c.Feeder.RemediatePeerFile != "/host/etc/default/k0scontroller-watchdog" ||
		c.Feeder.NotifySocket != "" {
		t.Errorf("Feeder=%+v", c.Feeder)
	}
	if c.K0sDir != "/host/var/lib/k0s" || c.K0sRunDir != "/host/run/k0s" {
		t.Errorf("k0s dirs: %s %s", c.K0sDir, c.K0sRunDir)
	}
	// EtcdGuard (config_etcd).
	if c.EtcdGuard.Endpoint != cdeps.DefaultEtcdEndpoint ||
		c.EtcdGuard.DBSizeLimit != int64(1610612736) ||
		c.EtcdGuard.MinRun != time.Hour ||
		c.EtcdBackupDir != "/var/backups/etcd" {
		t.Errorf("EtcdGuard=%+v backup=%s", c.EtcdGuard, c.EtcdBackupDir)
	}
	if c.SuspectLogCadence != time.Hour {
		t.Errorf("SuspectLogCadence=%s", c.SuspectLogCadence)
	}
	// CPFreeze (config_cpfreeze).
	if c.CPFreeze.KCMHealthURL != "https://127.0.0.1:10257/healthz" ||
		c.CPFreeze.SchedHealthURL != "https://127.0.0.1:10259/healthz" ||
		c.CPFreeze.KCMMetricsURL != "https://127.0.0.1:10257/metrics" ||
		c.CPFreeze.Cycles != 3 || c.CPFreeze.QuietFor != 10*time.Minute ||
		c.CPFreeze.MinRestart != 2*time.Hour {
		t.Errorf("CPFreeze=%+v", c.CPFreeze)
	}
	// PKIDrift (config_pki): the four default pairs derive from K0sDir.
	if c.PKIDrift.KinePKIDir != "/host/etc/kine/pki" ||
		c.PKIDrift.Cycles != 2 || c.PKIDrift.RestartInterval != time.Hour {
		t.Errorf("PKIDrift knobs=%+v", c.PKIDrift)
	}
	wantPairs := [][3]string{
		{"/host/var/lib/k0s/pki/apiserver.crt", "127.0.0.1:6443", "k0scontroller.service"},
		{"/host/var/lib/k0s/pki/konnectivity-server.crt", "127.0.0.1:8132", "k0scontroller.service"},
		{"/host/var/lib/k0s/pki/etcd/server.crt", "127.0.0.1:2379", "k0scontroller.service"},
		{"/host/etc/kine/pki/server.crt", "127.0.0.1:2379", "kine.service"},
	}
	if len(c.PKIDrift.Pairs) != len(wantPairs) {
		t.Fatalf("PKIDrift pairs=%d want %d: %+v",
			len(c.PKIDrift.Pairs), len(wantPairs), c.PKIDrift.Pairs)
	}
	for i, w := range wantPairs {
		p := c.PKIDrift.Pairs[i]
		if p.CertFile != w[0] || p.Addr != w[1] || p.Unit != w[2] {
			t.Errorf("pair[%d]=%+v want %v", i, p, w)
		}
	}
	// The seam defaults wired (production impls; behavior asserted
	// in the internal seams/exec/probes tests).
	if c.Clock == nil || c.SleepFn == nil || c.KillFn == nil ||
		c.HostExecFn == nil || c.ProbeFn == nil || c.PgWireFn == nil ||
		c.NotifyFn != nil || c.EtcdctlFn == nil || c.EvpurgeRunFn == nil ||
		c.EtcdRescueFn == nil || c.CPHealthFn == nil ||
		c.KCMMetricsFn == nil || c.TLSCertFn == nil {
		t.Fatalf("seam defaults incomplete: %+v", c.Seams)
	}
}

// NOTIFY_SOCKET is a systemd contract read directly by the feeder
// defaults — not a NODE_HOST_AGENT_* knob.
func TestApplyDefaultsNotifySocketPassthrough(t *testing.T) {
	t.Setenv(sdnotify.SocketEnv, "/run/notify.sock")
	var c cdeps.Config
	c.ApplyDefaults()
	if c.Feeder.NotifySocket != "/run/notify.sock" {
		t.Fatalf("NotifySocket=%q", c.Feeder.NotifySocket)
	}
	if c.NotifyFn == nil {
		t.Fatal("NotifyFn default not armed with a notify socket present")
	}
}

func TestApplyDefaultsPreservesSetKnobs(t *testing.T) {
	t.Setenv(sdnotify.SocketEnv, "")
	c := cdeps.Config{
		Interval:         7 * time.Second,
		JournalUnit:      "other.service",
		K0sDir:           "/k0s-custom",
		Sig13:            cdeps.Sig13Config{Mode: cdeps.ModeEnforce, StaleMinErrs: 30, MinRestart: time.Minute},
		OOMLoop:          cdeps.OOMLoopConfig{MinKills: 9, APIServerShieldAdj: -100, KineShieldAdj: 7},
		EtcdGuard:        cdeps.EtcdGuardConfig{DBSizeLimit: 5},
		TotalControllers: 2,
	}
	c.ApplyDefaults()
	if c.Interval != 7*time.Second || c.JournalUnit != "other.service" ||
		c.K0sDir != "/k0s-custom" || c.Sig13.Mode != cdeps.ModeEnforce ||
		c.Sig13.StaleMinErrs != 30 || c.Sig13.MinRestart != time.Minute ||
		c.OOMLoop.MinKills != 9 || c.OOMLoop.APIServerShieldAdj != -100 ||
		c.OOMLoop.KineShieldAdj != 7 || c.EtcdGuard.DBSizeLimit != 5 ||
		c.TotalControllers != 2 {
		t.Fatalf("set knobs overwritten: %+v", c)
	}
}

// Preset pairs keep their rows — only the $K0SDIR placeholder
// resolves against K0sDir.
func TestApplyDefaultsPKIDriftPresetPairs(t *testing.T) {
	t.Setenv(sdnotify.SocketEnv, "")
	c := cdeps.Config{
		K0sDir: "/k0s",
		PKIDrift: cdeps.PKIDriftConfig{Pairs: []cdeps.PKIDriftPair{
			{CertFile: "$K0SDIR/pki/x.crt", Addr: "127.0.0.1:1", Unit: "u.service"},
			{CertFile: "/abs/y.crt", Addr: "127.0.0.1:2", Unit: "v.service"},
		}},
	}
	c.ApplyDefaults()
	if c.PKIDrift.Pairs[0].CertFile != "/k0s/pki/x.crt" ||
		c.PKIDrift.Pairs[1].CertFile != "/abs/y.crt" {
		t.Fatalf("$K0SDIR substitution wrong: %+v", c.PKIDrift.Pairs)
	}
	if c.PKIDrift.Pairs[0].Unit != "u.service" {
		t.Fatalf("preset pair mutated: %+v", c.PKIDrift.Pairs[0])
	}
}

// The standalone-mode default: NOTIFY_SOCKET absent in the test
// process → no NotifyFn seam (the feeder stays inert).
func TestApplyDefaultsNotifyFnInertWithoutSocket(t *testing.T) {
	t.Setenv(sdnotify.SocketEnv, "")
	var c cdeps.Config
	c.ApplyDefaults()
	if c.Feeder.NotifySocket != "" || c.NotifyFn != nil {
		t.Fatalf("NotifySocket=%q NotifyFn=%v want inert",
			c.Feeder.NotifySocket, c.NotifyFn != nil)
	}
}
