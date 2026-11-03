package concourseinit

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// testConfig returns a Config rooted in t.TempDir() with every seam
// stubbed: no btrfs, a recording chown, chown skipped by default
// (tests run unprivileged — same convention as sweeper's -1,-1).
// mutate can flip knobs per-test.
func testConfig(t *testing.T, mutate func(*Config)) Config {
	t.Helper()
	root := t.TempDir()
	runcSrc := filepath.Join(root, "runc-image")
	if err := os.WriteFile(runcSrc, []byte("real-runc-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	wrapperSrc := filepath.Join(root, "agent-binary")
	if err := os.WriteFile(wrapperSrc, []byte("agent-self"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		WorkDir:       filepath.Join(root, "concourse-work-dir"),
		RuncDir:       filepath.Join(root, "concourse-runc"),
		RuncSource:    runcSrc,
		WrapperSource: wrapperSrc,
		OwnerUID:      -1,
		OwnerGID:      -1,
		listSubvols: func(context.Context, string) ([]string, error) {
			return nil, nil
		},
		deleteSubvol: func(context.Context, string) error { return nil },
	}
	if err := os.MkdirAll(cfg.RuncDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(&cfg)
	}
	return cfg
}

func mustDir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("%s still present (err=%v)", path, err)
	}
}

func assertPresent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("%s missing: %v", path, err)
	}
}

// seedWorkDir builds a realistic work dir: baggageclaim/containerd
// state at the top level, all 20 scaffold dirs (each carrying a
// marker file so preserved-vs-recreated is observable), junk entries
// inside shared-cache, and dotfiles everywhere.
func seedWorkDir(t *testing.T, workDir string) (sc string) {
	t.Helper()
	sc = filepath.Join(workDir, sharedCacheName)

	// Top-level state that must go; a dotfile + shared-cache survive.
	for _, d := range []string{"volumes", "overlays", "dead-containers"} {
		mustFile(t, filepath.Join(workDir, d, "state"), "x")
	}
	mustFile(t, filepath.Join(workDir, "lost+found"), "x")
	mustFile(t, filepath.Join(workDir, ".work-dotfile"), "x")

	// Every scaffold dir gets a marker — kept dirs keep it, wiped
	// dirs lose it and are recreated empty.
	for _, d := range ScaffoldCacheDirs {
		mustFile(t, filepath.Join(sc, d, "marker"), "x")
	}
	// Junk inside shared-cache: dirs not on the keep-list, a loose
	// file, a symlink, and a dotfile that must survive.
	mustFile(t, filepath.Join(sc, "stale-cache", "marker"), "x")
	mustFile(t, filepath.Join(sc, "tmp-partial"), "x")
	mustFile(t, filepath.Join(sc, "loose.txt"), "x")
	mustFile(t, filepath.Join(sc, ".hidden"), "x")
	if err := os.Symlink("/nonexistent-target",
		filepath.Join(sc, "bad-link")); err != nil {
		t.Fatal(err)
	}
	return sc
}

// Selective cleanup: shared-cache + the 14 persistent dirs (contents
// intact) survive; everything else — top-level state, junk inside
// shared-cache, the 6 non-persistent scaffold dirs' contents — is
// removed. Dotfiles survive both wipes (bash `*` never matches them).
func TestWorkerInitSelectiveWipe(t *testing.T) {
	cfg := testConfig(t, nil)
	sc := seedWorkDir(t, cfg.WorkDir)

	if err := WorkerInit(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}

	// Top level: only shared-cache + the dotfile remain.
	for _, d := range []string{"volumes", "overlays", "dead-containers", "lost+found"} {
		assertMissing(t, filepath.Join(cfg.WorkDir, d))
	}
	assertPresent(t, filepath.Join(cfg.WorkDir, ".work-dotfile"))
	assertPresent(t, sc)

	// Inside shared-cache: the 14 keep-list dirs kept their marker.
	for _, d := range PersistentCacheDirs {
		assertPresent(t, filepath.Join(sc, d, "marker"))
	}
	// The 6 scaffold dirs NOT on the keep-list were wiped and
	// recreated empty.
	for _, d := range ScaffoldCacheDirs {
		if slices.Contains(PersistentCacheDirs, d) {
			continue
		}
		assertPresent(t, filepath.Join(sc, d))
		assertMissing(t, filepath.Join(sc, d, "marker"))
	}
	// Junk is gone — including the symlink (rm -rf removes the link
	// itself, never the target).
	for _, d := range []string{"stale-cache", "tmp-partial", "loose.txt", "bad-link"} {
		if _, err := os.Lstat(filepath.Join(sc, d)); !os.IsNotExist(err) {
			t.Fatalf("%s still present (err=%v)", d, err)
		}
	}
	assertPresent(t, filepath.Join(sc, ".hidden"))
}

// Scaffold invariant: all 20 dirs exist, mode 0777 on shared-cache
// and every first-level entry; the recording chown sees exactly
// shared-cache + the 20 dirs at uid/gid 4294967294 (dotfiles and
// symlinks are skipped — same Lstat guard the sweeper port uses).
func TestWorkerInitScaffoldPermOwnership(t *testing.T) {
	var chowned []string
	cfg := testConfig(t, func(c *Config) {
		c.OwnerUID, c.OwnerGID = cacheOwner, cacheOwner
		c.chown = func(name string, uid, gid int) error {
			if uid != cacheOwner || gid != cacheOwner {
				t.Fatalf("chown %s to %d:%d, want %d", name, uid, gid, cacheOwner)
			}
			chowned = append(chowned, name)
			return nil
		}
	})
	sc := seedWorkDir(t, cfg.WorkDir)

	if err := WorkerInit(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}

	want := []string{sc}
	for _, d := range ScaffoldCacheDirs {
		want = append(want, filepath.Join(sc, d))
		fi, err := os.Stat(filepath.Join(sc, d))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o777 {
			t.Fatalf("%s mode %o, want 0777", d, fi.Mode().Perm())
		}
	}
	if fi, err := os.Stat(sc); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o777 {
		t.Fatalf("shared-cache mode %o, want 0777", fi.Mode().Perm())
	}
	slices.Sort(chowned)
	slices.Sort(want)
	if !slices.Equal(chowned, want) {
		t.Fatalf("chowned %v, want %v", chowned, want)
	}
}

// runc install: the image's runc lands at <runcDir>/runc.real and the
// agent binary at <runcDir>/runc — both mode 0755, no tmp litter.
func TestWorkerInitInstallsRunc(t *testing.T) {
	cfg := testConfig(t, nil)
	seedWorkDir(t, cfg.WorkDir)

	if err := WorkerInit(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}

	for name, wantBody := range map[string]string{
		"runc.real": "real-runc-binary",
		"runc":      "agent-self",
	} {
		p := filepath.Join(cfg.RuncDir, name)
		body, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != wantBody {
			t.Fatalf("%s body %q, want %q", name, body, wantBody)
		}
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o755 {
			t.Fatalf("%s mode %o, want 0755", name, fi.Mode().Perm())
		}
	}
	entries, err := os.ReadDir(cfg.RuncDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("runcDir holds %v, want exactly runc + runc.real",
			entryNames(entries))
	}
}

// btrfs cleanup: every listed subvolume gets a best-effort delete
// under the work dir, list errors are ignored entirely.
func TestWorkerInitBtrfsCleanup(t *testing.T) {
	var deleted []string
	cfg := testConfig(t, func(c *Config) {
		c.listSubvols = func(context.Context, string) ([]string, error) {
			return []string{"volumes/sub-a", "sub-b"}, nil
		}
		c.deleteSubvol = func(_ context.Context, path string) error {
			deleted = append(deleted, path)
			return nil
		}
	})
	seedWorkDir(t, cfg.WorkDir)

	if err := WorkerInit(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	want := []string{
		filepath.Join(cfg.WorkDir, "volumes/sub-a"),
		filepath.Join(cfg.WorkDir, "sub-b"),
	}
	if !slices.Equal(deleted, want) {
		t.Fatalf("deleted %v, want %v", deleted, want)
	}
}

// A missing work dir is NOT fatal — the bash glob on a nonexistent
// dir expands to nothing and mkdir -p then creates the whole tree.
func TestWorkerInitMissingWorkDir(t *testing.T) {
	cfg := testConfig(t, nil) // no seedWorkDir

	if err := WorkerInit(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	for _, d := range ScaffoldCacheDirs {
		assertPresent(t, filepath.Join(cfg.WorkDir, sharedCacheName, d))
	}
}

// Fail-closed after the btrfs phase: a missing runc source must abort
// the init (set -e on `cp`), not log-and-continue.
func TestWorkerInitRuncSourceMissingFails(t *testing.T) {
	cfg := testConfig(t, func(c *Config) {
		c.RuncSource = filepath.Join(t.TempDir(), "gone")
	})
	seedWorkDir(t, cfg.WorkDir)

	if err := WorkerInit(context.Background(), cfg); err == nil {
		t.Fatal("expected error for missing runc source")
	}
}

// A work-dir path that is a FILE fails the wipe (ReadDir ENOTDIR is
// not the missing-dir no-op).
func TestWorkerInitWorkDirIsFile(t *testing.T) {
	cfg := testConfig(t, nil)
	mustFile(t, cfg.WorkDir, "not a dir")

	if err := WorkerInit(context.Background(), cfg); err == nil {
		t.Fatal("expected error for file-as-workdir")
	}
}

// A chown failure aborts — `set -e` on the script's chown line.
func TestWorkerInitChownErrorFails(t *testing.T) {
	cfg := testConfig(t, func(c *Config) {
		c.OwnerUID, c.OwnerGID = cacheOwner, cacheOwner
		c.chown = func(string, int, int) error { return os.ErrPermission }
	})
	seedWorkDir(t, cfg.WorkDir)

	if err := WorkerInit(context.Background(), cfg); err == nil {
		t.Fatal("expected error from failing chown")
	}
}

// ctx cancellation aborts mid-wipe.
func TestWorkerInitCtxCancel(t *testing.T) {
	cfg := testConfig(t, nil)
	seedWorkDir(t, cfg.WorkDir)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := WorkerInit(ctx, cfg); err == nil {
		t.Fatal("expected ctx error")
	}
}

// The production list impl execs the real btrfs binary — with no
// btrfs filesystem it must return an empty list, never an error
// (`|| true`).
func TestBtrfsListSubvolsFailOpen(t *testing.T) {
	vols, err := btrfsListSubvols(context.Background(),
		filepath.Join(t.TempDir(), "not-btrfs"))
	if err != nil || vols != nil {
		t.Fatalf("vols=%v err=%v, want nil nil", vols, err)
	}
}

// awk '{print $9}': only lines with ≥9 fields contribute field 9 —
// drive a fake btrfs binary via PATH and check the parse verbatim.
func TestBtrfsListSubvolsParsesField9(t *testing.T) {
	bin := t.TempDir()
	fake := filepath.Join(bin, "btrfs")
	script := "#!/bin/sh\n" +
		"printf 'ID 256 gen 30 top level 5 path volumes/sub-a\\n'\n" +
		"printf 'ID 257 gen 31 top level 5 path sub-b\\n'\n" +
		"printf 'short line\\n'\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	vols, err := btrfsListSubvols(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(vols, []string{"volumes/sub-a", "sub-b"}) {
		t.Fatalf("vols=%v", vols)
	}
}

func entryNames(entries []os.DirEntry) []string {
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}
