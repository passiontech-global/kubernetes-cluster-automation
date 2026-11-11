package fsx

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// fsx.WriteFile must leave exactly the target file behind: content
// verbatim, mode forced from Opts.Mode (CreateTemp stages 0600 and
// umask would mask an OpenFile create-mode — the chmod is the point),
// and no leaked staging file in the dir.
func TestWriteFileHappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state-probe")

	if err := WriteFile(path, []byte("payload-v1"), Opts{Mode: 0o644, DirSync: true}); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "payload-v1" {
		t.Fatalf("content=%q, want payload-v1", got)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode=%v, want 0644", fi.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "state-probe" {
		t.Fatalf("staging file leaked: dir holds %d entries", len(entries))
	}
}

// Rewriting an existing target must replace content through the same
// rename path — and Mode is re-forced on every write, not inherited
// from the file being replaced.
func TestWriteFileOverwriteExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "latch-state")

	if err := WriteFile(path, []byte("one"), Opts{Mode: 0o644}); err != nil {
		t.Fatalf("first WriteFile: %v", err)
	}
	if err := WriteFile(path, []byte("two-two"), Opts{Mode: 0o600}); err != nil {
		t.Fatalf("second WriteFile: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "two-two" {
		t.Fatalf("content=%q, want two-two", got)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v, want 0600", fi.Mode().Perm())
	}
}

// NoSync drops only the durability fsyncs — the write still lands
// intact through the staging rename, and the AfterSync hook still runs
// (it is a page-cache step, not a durability step, so NoSync must not
// disable it).
func TestWriteFileNoSync(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "last-run")

	var afterSyncRan bool
	err := WriteFile(path, []byte("ephemeral"), Opts{
		Mode:      0o644,
		NoSync:    true,
		AfterSync: func(f *os.File) { afterSyncRan = true },
	})
	if err != nil {
		t.Fatalf("WriteFile(NoSync): %v", err)
	}
	if !afterSyncRan {
		t.Fatal("AfterSync hook did not run under NoSync")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "ephemeral" {
		t.Fatalf("content=%q, want ephemeral", got)
	}
}

// Every failure path after the stage is created must sweep the staging
// file and leave the previously-installed target intact — a leaked
// staging file would sit in the state dir forever. The rename seam is
// stubbed to fail; the sweep happens before the error returns.
func TestWriteFileRenameFailureSweepsStaging(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "watchdog-state")

	if err := WriteFile(path, []byte("installed"), Opts{Mode: 0o644}); err != nil {
		t.Fatalf("initial WriteFile: %v", err)
	}

	orig := RenameFile
	RenameFile = func(string, string) error { return errors.New("stubbed rename failure") }
	t.Cleanup(func() { RenameFile = orig })

	if err := WriteFile(path, []byte("never-promoted"), Opts{Mode: 0o644}); err == nil {
		t.Fatal("WriteFile succeeded despite stubbed rename failure")
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "installed" {
		t.Fatalf("target clobbered by failed write: %q", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "watchdog-state" {
		t.Fatalf("staging file leaked after failure: dir holds %d entries", len(entries))
	}
}
