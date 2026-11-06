package kinedb

import (
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
)

func TestConfigFromEnv(t *testing.T) {
	t.Setenv(envnames.EnvKinedbEnvFile, "/custom/postgres.env")
	t.Setenv(envnames.EnvKinedbGuardStateDir, "/custom/guard")
	t.Setenv(envnames.EnvKinedbPgDataDir, "/pgdata")

	cfg := ConfigFromEnv(EnvDeps{
		HostPath:    func(p string) string { return "/host" + p },
		TextfileDir: "/textfile",
	})
	if cfg.EnvFile != "/custom/postgres.env" {
		t.Fatalf("EnvFile=%q", cfg.EnvFile)
	}
	if cfg.GuardStateDir != "/custom/guard" {
		t.Fatalf("GuardStateDir=%q", cfg.GuardStateDir)
	}
	if cfg.PGDataDir != "/pgdata" {
		t.Fatalf("PGDataDir=%q", cfg.PGDataDir)
	}
	if cfg.TextfileDir != "/textfile" {
		t.Fatalf("TextfileDir=%q", cfg.TextfileDir)
	}
}

func TestConfigFromEnvHostPathDefaults(t *testing.T) {
	cfg := ConfigFromEnv(EnvDeps{
		HostPath: func(p string) string { return "/host" + p },
	})
	// Env unset → hostPath-prefixed package defaults (the DaemonSet
	// "/host" mount), not the bare applyDefaults paths.
	if cfg.EnvFile != "/host/opt/apps/postgres/.env" {
		t.Fatalf("EnvFile=%q", cfg.EnvFile)
	}
	if cfg.GuardStateDir != "/host/var/lib/kine-compact-guard" {
		t.Fatalf("GuardStateDir=%q", cfg.GuardStateDir)
	}
	if cfg.PGDataDir != "" {
		t.Fatalf("PGDataDir=%q", cfg.PGDataDir)
	}
}
