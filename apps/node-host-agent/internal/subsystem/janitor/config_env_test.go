package janitor

import (
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/systemd"
)

func TestJanitorConfigFromEnv(t *testing.T) {
	t.Setenv("NODE_HOST_AGENT_JANITOR_INTERVAL", "2m")
	t.Setenv("NODE_HOST_AGENT_JANITOR_LATCH_MAX_AGE", "48h")
	t.Setenv("NODE_HOST_AGENT_PROC_ROOT", "/host/proc")

	d := EnvDeps{
		Systemd:          systemd.New(systemd.Config{HostRoot: "/"}),
		WatchdogStateDir: "/sd",
		WatchdogLogFile:  "/lf",
	}
	cfg := JanitorConfigFromEnv(d)
	if !cfg.Enabled {
		t.Fatal("Enabled should be true — the enable gate stays in the caller")
	}
	if cfg.Interval != 2*time.Minute {
		t.Fatalf("Interval=%v", cfg.Interval)
	}
	if cfg.LatchMaxAge != 48*time.Hour {
		t.Fatalf("LatchMaxAge=%v", cfg.LatchMaxAge)
	}
	if cfg.ProcRoot != "/host/proc" {
		t.Fatalf("ProcRoot=%q", cfg.ProcRoot)
	}
	if cfg.WatchdogStateDir != "/sd" || cfg.WatchdogLogFile != "/lf" ||
		cfg.Systemd != d.Systemd {
		t.Fatalf("deps not passed through: %+v", cfg)
	}
}
