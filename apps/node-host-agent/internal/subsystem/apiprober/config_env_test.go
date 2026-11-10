package apiprober

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// The env → guard.conf → compiled-default chain must keep its exact
// precedence: env wins, then the conf key, then the package default.
func TestResolveProberInputsChain(t *testing.T) {
	t.Setenv(envnames.EnvAPIGuardConf, filepath.Join(t.TempDir(), "absent.conf"))

	wd := &watchdogconf.Config{APIBackends: []watchdogconf.APIBackend{
		{Name: "ctl1", Addr: "10.0.0.1:6443"},
	}}
	g := GuardDefaults{
		SocketPath:        "/conf/sock",
		BackendName:       "conf_back",
		Mode:              ModeEnforce,
		TokenFile:         "/conf/token",
		CAFile:            "/conf/ca",
		CompanionBackends: []string{"conf_comp"},
	}

	// No env: conf values win over compiled defaults; static falls
	// back to watchdogconf APIBackends when the conf has none.
	pi := resolveProberInputs(wd, g)
	if pi.socket != "/conf/sock" || pi.backend != "conf_back" ||
		pi.mode != ModeEnforce || pi.tokenFile != "/conf/token" ||
		pi.caFile != "/conf/ca" {
		t.Fatalf("conf layer not applied: %+v", pi)
	}
	if len(pi.companions) != 1 || pi.companions[0] != "conf_comp" {
		t.Fatalf("companions=%v", pi.companions)
	}
	if len(pi.static) != 1 || pi.static[0].Name != "ctl1" ||
		pi.static[0].Addr != "10.0.0.1:6443" {
		t.Fatalf("static=%v", pi.static)
	}

	// Env overrides the conf layer.
	t.Setenv(envnames.EnvApiproberSocket, "/env/sock")
	t.Setenv(envnames.EnvApiproberBackend, "env_back")
	t.Setenv(envnames.EnvApiproberMode, ModeDryRun)
	t.Setenv(envnames.EnvApiproberCompanionBackends, "a,b")
	t.Setenv(envnames.EnvApiproberTokenFile, "/env/token")
	t.Setenv(envnames.EnvApiproberCaFile, "/env/ca")
	pi = resolveProberInputs(wd, g)
	if pi.socket != "/env/sock" || pi.backend != "env_back" ||
		pi.mode != ModeDryRun || pi.tokenFile != "/env/token" ||
		pi.caFile != "/env/ca" {
		t.Fatalf("env layer not applied: %+v", pi)
	}
	if len(pi.companions) != 2 || pi.companions[0] != "a" || pi.companions[1] != "b" {
		t.Fatalf("companions=%v", pi.companions)
	}
}

func TestConfigFromEnv(t *testing.T) {
	confPath := filepath.Join(t.TempDir(), "guard.conf")
	if err := os.WriteFile(confPath, []byte(
		"HAPROXY_SOCKET=/guard/sock\nHAPROXY_BACKEND=guard_back\n"),
		0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envnames.EnvAPIGuardConf, confPath)
	t.Setenv(envnames.EnvApiproberInterval, "45s")
	t.Setenv(envnames.EnvApiproberGapMin, "42")
	t.Setenv(envnames.EnvApiproberLivePath, "/live")
	t.Setenv(envnames.EnvApiproberInsecureTLS, "false")

	cfg := ConfigFromEnv(EnvDeps{
		Watchdog:         &watchdogconf.Config{},
		WatchdogStateDir: "/state",
	})
	if cfg.SocketPath != "/guard/sock" {
		t.Fatalf("SocketPath=%q — guard.conf layer missing", cfg.SocketPath)
	}
	if cfg.BackendName != "guard_back" {
		t.Fatalf("BackendName=%q", cfg.BackendName)
	}
	if cfg.Interval != 45*time.Second {
		t.Fatalf("Interval=%v", cfg.Interval)
	}
	if cfg.GapMin != 42 {
		t.Fatalf("GapMin=%d", cfg.GapMin)
	}
	if cfg.LivePath != "/live" {
		t.Fatalf("LivePath=%q", cfg.LivePath)
	}
	if cfg.InsecureTLS {
		t.Fatal("InsecureTLS should be false")
	}
	if cfg.WatchdogStateDir != "/state" {
		t.Fatalf("WatchdogStateDir=%q", cfg.WatchdogStateDir)
	}
	if cfg.GuardSrc != nil {
		t.Fatal("GuardSrc must stay nil — New auto-wires the reloader")
	}
}

// A conf the reader cannot open must degrade to compiled defaults —
// the agent still boots (the env → conf → default chain fails safe,
// and the error is loud, not silent).
func TestConfigFromEnvUnreadableConfFallsBackToDefaults(t *testing.T) {
	buf := captureSlog(t)
	confPath := filepath.Join(t.TempDir(), "guard.conf")
	testutil.WriteFile(t, confPath, "HAPROXY_SOCKET=/conf/sock\n")
	if err := os.Chmod(confPath, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(confPath, 0o600) })
	t.Setenv(envnames.EnvAPIGuardConf, confPath)

	cfg := ConfigFromEnv(EnvDeps{})
	if cfg.SocketPath != defaultSocketPath || cfg.BackendName != defaultBackendName {
		t.Fatalf("unreadable conf leaked into config: socket=%q backend=%q",
			cfg.SocketPath, cfg.BackendName)
	}
	if !strings.Contains(buf.String(), "parse failed") {
		t.Fatalf("conf read failure not logged:\n%s", buf.String())
	}
}

// Conf-carried API_BACKENDS wins over the watchdogconf APIBackends
// fallback (the conf is the managed contract); with no conf statics
// the watchdog entries apply, and with neither the set is empty.
func TestResolveProberInputsConfStaticsWin(t *testing.T) {
	conf := GuardDefaults{StaticBackends: []StaticBackend{
		{Name: "conf1", Addr: "10.7.0.1:6443"},
	}}
	wd := &watchdogconf.Config{APIBackends: []watchdogconf.APIBackend{
		{Name: "wd1", Addr: "10.9.9.9:6443"},
	}}

	pi := resolveProberInputs(wd, conf)
	if len(pi.static) != 1 || pi.static[0].Name != "conf1" {
		t.Fatalf("conf statics = %+v — watchdog fallback must lose", pi.static)
	}

	pi = resolveProberInputs(wd, GuardDefaults{})
	if len(pi.static) != 1 || pi.static[0].Name != "wd1" {
		t.Fatalf("watchdog fallback statics = %+v", pi.static)
	}

	if pi := resolveProberInputs(nil, GuardDefaults{}); len(pi.static) != 0 {
		t.Fatalf("no-source statics = %+v want empty", pi.static)
	}
}
