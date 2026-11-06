package janitor

import (
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
)

func TestConfigFromEnv(t *testing.T) {
	t.Setenv(envnames.EnvJanitorInterval, "2m")
	t.Setenv(envnames.EnvJanitorLatchMaxAge, "48h")
	t.Setenv(envnames.EnvProcRoot, "/host/proc")

	d := EnvDeps{
		Systemd:          systemd.New(systemd.Config{HostRoot: "/"}),
		WatchdogStateDir: "/sd",
		WatchdogLogFile:  "/lf",
	}
	cfg := ConfigFromEnv(d)
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
