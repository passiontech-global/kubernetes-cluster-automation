package hubsync

import (
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

func TestConfigFromEnv(t *testing.T) {
	t.Setenv(envnames.EnvConvergeSSHKey, "/keys/converge")
	t.Setenv(envnames.EnvNebulaCertsDir, "/certs")

	cs := testutil.FakeKube()
	cfg := ConfigFromEnv(EnvDeps{
		Client:      cs,
		Identity:    "pod-abc",
		VarsDir:     "/vars",
		LocalBinary: "/resolved/binary",
	})
	if cfg.Client != cs {
		t.Fatal("ConfigFromEnv did not pass the client through")
	}
	if cfg.Identity != "pod-abc" {
		t.Fatalf("Identity=%q", cfg.Identity)
	}
	if cfg.VarsDir != "/vars" {
		t.Fatalf("VarsDir=%q", cfg.VarsDir)
	}
	if cfg.LocalBinary != "/resolved/binary" {
		t.Fatalf("LocalBinary=%q", cfg.LocalBinary)
	}
	if cfg.SSHKeyPath != "/keys/converge" {
		t.Fatalf("SSHKeyPath=%q", cfg.SSHKeyPath)
	}
	if cfg.NebulaCertsDir != "/certs" {
		t.Fatalf("NebulaCertsDir=%q", cfg.NebulaCertsDir)
	}
}

func TestConfigFromEnvDefaults(t *testing.T) {
	cfg := ConfigFromEnv(EnvDeps{})
	if cfg.SSHKeyPath != defaultSSHKeyPath {
		t.Fatalf("SSHKeyPath=%q want %q", cfg.SSHKeyPath, defaultSSHKeyPath)
	}
	if cfg.NebulaCertsDir != defaultNebulaCertsDir {
		t.Fatalf("NebulaCertsDir=%q want %q",
			cfg.NebulaCertsDir, defaultNebulaCertsDir)
	}
	// SyncInterval stays zero → applyDefaults' 10m; no env knob exists.
	if cfg.SyncInterval != 0 {
		t.Fatalf("SyncInterval=%v", cfg.SyncInterval)
	}
}
