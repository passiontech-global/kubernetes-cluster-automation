package hubsync

import (
	"testing"

	"k8s.io/client-go/kubernetes/fake"
)

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("NODE_HOST_AGENT_CONVERGE_SSH_KEY", "/keys/converge")
	t.Setenv("NODE_HOST_AGENT_NEBULA_CERTS_DIR", "/certs")

	cs := fake.NewSimpleClientset()
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
