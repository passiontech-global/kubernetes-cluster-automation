package guards

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDentryStateUnusedAndGuardNegativeDentry(t *testing.T) {
	t.Run("dentryStateUnused_variants", func(t *testing.T) {
		d, _ := gDeps(t)
		d.Cfg.ProcRoot = t.TempDir()
		if got := dentryStateUnused(d); got != -1 {
			t.Fatalf("missing file: got %d, want -1", got)
		}

		p := filepath.Join(d.Cfg.ProcRoot, "sys", "fs", "dentry-state")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("123\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := dentryStateUnused(d); got != -1 {
			t.Fatalf("short line: got %d, want -1", got)
		}

		if err := os.WriteFile(p, []byte("123 notanint 45 0 0 0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := dentryStateUnused(d); got != -1 {
			t.Fatalf("bad int: got %d, want -1", got)
		}

		if err := os.WriteFile(p, []byte("2000000 1600000 45 0 0 0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := dentryStateUnused(d); got != 1600000 {
			t.Fatalf("valid line: got %d, want 1600000", got)
		}
	})

	t.Run("guardNegativeDentry_gating_and_drop", func(t *testing.T) {
		d, _ := gDeps(t)
		d.Cfg.ProcRoot = t.TempDir()
		dentryPath := filepath.Join(d.Cfg.ProcRoot, "sys", "fs", "dentry-state")
		dropPath := filepath.Join(d.Cfg.ProcRoot, "sys", "vm", "drop_caches")
		if err := os.MkdirAll(filepath.Dir(dentryPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(dropPath), 0o755); err != nil {
			t.Fatal(err)
		}

		// Missing dentry-state -> no-op.
		guardNegativeDentry(d, memInfo{totalKB: 10 << 20, availKB: 1 << 20, slabRecKB: 4 << 20})
		if _, err := os.Stat(dropPath); err == nil {
			t.Fatal("drop_caches should not be written when dentry-state is missing")
		}

		// Below threshold -> records gauge, does not write drop_caches.
		if err := os.WriteFile(dentryPath, []byte("500 100 45 0 0 0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		guardNegativeDentry(d, memInfo{totalKB: 10 << 20, availKB: 1 << 20, slabRecKB: 4 << 20})
		if d.Series.DentryUnusedCount != 100 {
			t.Fatalf("DentryUnusedCount = %d, want 100", d.Series.DentryUnusedCount)
		}
		if _, err := os.Stat(dropPath); err == nil {
			t.Fatal("drop_caches should not be written below threshold")
		}

		// Above all thresholds -> writes "2\n" to drop_caches.
		if err := os.WriteFile(dentryPath, []byte("2000000 1600000 45 0 0 0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		guardNegativeDentry(d, memInfo{totalKB: 10 << 20, availKB: 1 << 20, slabRecKB: 4 << 20})
		got, err := os.ReadFile(dropPath)
		if err != nil {
			t.Fatalf("expected drop_caches to be written: %v", err)
		}
		if string(got) != "2\n" {
			t.Fatalf("drop_caches = %q, want %q", got, "2\n")
		}
	})
}
