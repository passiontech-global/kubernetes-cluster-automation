// localbin_test.go — resolveLocalBinary: env override, (deleted) suffix, fallback.

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
)

// --- resolveLocalBinary ---

func TestResolveLocalBinary(t *testing.T) {
	orig := osExecutable
	t.Cleanup(func() { osExecutable = orig })

	t.Run("env override wins", func(t *testing.T) {
		t.Setenv(envnames.EnvHubsyncLocalBinary, "/custom/bin")
		if got := resolveLocalBinary(); got != "/custom/bin" {
			t.Fatalf("env override=%q want /custom/bin", got)
		}
	})

	t.Run("deleted suffix stripped", func(t *testing.T) {
		real := filepath.Join(t.TempDir(), "node-host-agent")
		if err := os.WriteFile(real, []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
		osExecutable = func() (string, error) { return real + " (deleted)", nil }
		if got := resolveLocalBinary(); got != real {
			t.Fatalf("deleted-suffix resolve=%q want %q", got, real)
		}
	})

	t.Run("nonexistent resolved path falls back", func(t *testing.T) {
		osExecutable = func() (string, error) {
			return filepath.Join(t.TempDir(), "gone") + " (deleted)", nil
		}
		if got := resolveLocalBinary(); got != "/node-host-agent" {
			t.Fatalf("missing-path resolve=%q want /node-host-agent", got)
		}
	})

	t.Run("os.Executable error falls back", func(t *testing.T) {
		osExecutable = func() (string, error) { return "", errors.New("noexe") }
		if got := resolveLocalBinary(); got != "/node-host-agent" {
			t.Fatalf("error resolve=%q want /node-host-agent", got)
		}
	})
}
