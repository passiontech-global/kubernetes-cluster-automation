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

	t.Run("guardNegativeDentry_proactive_defrag", func(t *testing.T) {
		const giB = 1024 * 1024 // kB per GiB

		cases := []struct {
			name      string
			nrUnused  string
			mem       memInfo
			wantDrop  bool
			wantCount int64
		}{
			{
				name:     "high_avail_40pct_nr_unused_3M_reclaims",
				nrUnused: "3500000 3000000 45 0 0 0\n",
				// MemAvailable = 40%, SReclaimable = 512 MiB (well under 2 GiB)
				mem:       memInfo{totalKB: 10 * giB, availKB: 4 * giB, slabRecKB: 512 * 1024},
				wantDrop:  true,
				wantCount: 3_000_000,
			},
			{
				name:     "high_avail_40pct_nr_unused_1.8M_sreclaimable_2.5GiB_reclaims",
				nrUnused: "2200000 1800000 45 0 0 0\n",
				// MemAvailable = 40%, SReclaimable = 2.5 GiB (> 2 GiB)
				mem:       memInfo{totalKB: 10 * giB, availKB: 4 * giB, slabRecKB: 2560 * 1024},
				wantDrop:  true,
				wantCount: 1_800_000,
			},
			{
				name:     "high_avail_40pct_nr_unused_1.8M_sreclaimable_1.5GiB_skips",
				nrUnused: "2200000 1800000 45 0 0 0\n",
				// MemAvailable = 40%, SReclaimable = 1.5 GiB (<= 2 GiB)
				mem:       memInfo{totalKB: 10 * giB, availKB: 4 * giB, slabRecKB: 1536 * 1024},
				wantDrop:  false,
				wantCount: 1_800_000,
			},
			{
				name:      "nr_unused_1M_even_with_low_avail_and_high_slab_skips",
				nrUnused:  "1500000 1000000 45 0 0 0\n",
				mem:       memInfo{totalKB: 10 * giB, availKB: 1 * giB, slabRecKB: 4 * giB},
				wantDrop:  false,
				wantCount: 1_000_000,
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
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
				if err := os.WriteFile(dentryPath, []byte(tc.nrUnused), 0o644); err != nil {
					t.Fatal(err)
				}

				guardNegativeDentry(d, tc.mem)
				if d.Series.DentryUnusedCount != tc.wantCount {
					t.Fatalf("DentryUnusedCount = %d, want %d", d.Series.DentryUnusedCount, tc.wantCount)
				}
				got, err := os.ReadFile(dropPath)
				if tc.wantDrop {
					if err != nil {
						t.Fatalf("expected drop_caches write, got err: %v", err)
					}
					if string(got) != "2\n" {
						t.Fatalf("drop_caches = %q, want %q", got, "2\n")
					}
					// Cooldown (30m) must suppress immediate second write.
					if err := os.Remove(dropPath); err != nil {
						t.Fatal(err)
					}
					guardNegativeDentry(d, tc.mem)
					if _, err := os.Stat(dropPath); err == nil {
						t.Fatal("drop_caches re-written inside 30m cooldown")
					}
				} else if err == nil {
					t.Fatalf("unexpected drop_caches write: %q", got)
				}
			})
		}
	})
}
