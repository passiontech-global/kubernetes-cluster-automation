package hostconfig

import (
	"testing"
	"time"
)

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("NODE_HOST_AGENT_NEBULA_CERTS_DIR", "/certs")
	t.Setenv("NODE_HOST_AGENT_WATCHDOG_SCRIPTS_DIR", "/wd-scripts")
	t.Setenv("NODE_HOST_AGENT_HOSTCONFIG_INTERVAL", "5m")

	cfg := ConfigFromEnv(EnvDeps{
		NodeName: "node-1",
		Hostname: "host-1",
		HostRoot: "/host",
		VarsDir:  "/vars",
	})
	if cfg.NodeName != "node-1" || cfg.Hostname != "host-1" {
		t.Fatalf("identity: %+v", cfg)
	}
	if cfg.HostRoot != "/host" || cfg.VarsDir != "/vars" {
		t.Fatalf("dirs: %+v", cfg)
	}
	if cfg.NebulaCertsDir != "/certs" {
		t.Fatalf("NebulaCertsDir=%q", cfg.NebulaCertsDir)
	}
	if cfg.WatchdogScriptsDir != "/wd-scripts" {
		t.Fatalf("WatchdogScriptsDir=%q", cfg.WatchdogScriptsDir)
	}
	if cfg.Interval != 5*time.Minute {
		t.Fatalf("Interval=%v", cfg.Interval)
	}
	if _, ok := cfg.Runner.(NsenterRunner); !ok {
		t.Fatalf("Runner=%T — /host root must nsenter", cfg.Runner)
	}
	w, ok := cfg.Watcher.(*DirWatcher)
	if !ok {
		t.Fatalf("Watcher=%T", cfg.Watcher)
	}
	if len(w.Dirs) != 2 || w.Dirs[0] != "/vars" || w.Dirs[1] != "/certs" {
		t.Fatalf("watcher dirs=%v", w.Dirs)
	}
}

func TestConfigFromEnvStandaloneRunner(t *testing.T) {
	// HostRoot "/" = the standalone systemd binary already inside the
	// host namespaces → DirectRunner, no nsenter.
	cfg := ConfigFromEnv(EnvDeps{HostRoot: "/", VarsDir: "/vars"})
	if _, ok := cfg.Runner.(DirectRunner); !ok {
		t.Fatalf("Runner=%T — standalone root must run direct", cfg.Runner)
	}
}
