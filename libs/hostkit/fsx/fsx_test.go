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

// Opts.Mode == 0 must NOT chmod the staged file to 0000: an existing
// target keeps its permission bits, a new file gets 0644.
func TestWriteFileZeroMode(t *testing.T) {
	dir := t.TempDir()

	// New file → 0644.
	fresh := filepath.Join(dir, "fresh.conf")
	if err := WriteFile(fresh, []byte("x"), Opts{}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Mode().Perm(); got != 0o644 {
		t.Fatalf("new file mode = %o, want 644", got)
	}

	// Existing 0600 file keeps 0600 across a Mode==0 rewrite.
	strict := filepath.Join(dir, "strict.conf")
	if err := os.WriteFile(strict, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(strict, []byte("new"), Opts{}); err != nil {
		t.Fatal(err)
	}
	st, err = os.Stat(strict)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Mode().Perm(); got != 0o600 {
		t.Fatalf("existing file mode = %o, want 600 preserved", got)
	}
	b, err := os.ReadFile(strict)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "new" {
		t.Fatalf("content = %q, want %q", b, "new")
	}
}

// stageFile creates a same-dir staging file for Promote tests.
func stageFile(t *testing.T, dir, content string) *os.File {
	t.Helper()
	f, err := os.CreateTemp(dir, ".stage-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		_ = f.Close()
		t.Fatalf("WriteString: %v", err)
	}
	return f
}

// Opts.Mode == 0 must resolve the target's existing permission bits:
// a NEW file gets 0644 (CreateTemp's 0600 must not leak through).
func TestPromoteNewFileGets0644(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fresh-state")

	f := stageFile(t, dir, "payload")
	if err := Promote(f, path, Opts{}); err != nil {
		t.Fatalf("Promote: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("new file mode=%v, want 0644", fi.Mode().Perm())
	}
}

// An existing target's mode is preserved when Opts.Mode == 0 —
// rewriting a 0600 state file must not silently widen it to 0644.
func TestPromotePreservesExistingMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret-state")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	f := stageFile(t, dir, "new")
	if err := Promote(f, path, Opts{}); err != nil {
		t.Fatalf("Promote: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("existing file mode=%v, want preserved 0600", fi.Mode().Perm())
	}
}

// A target stripped to Perm()==0 must NOT propagate 0000 — the
// promoted file would be unreadable; 0644 is the fallback.
func TestPromoteZeroPermTargetGets0644(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stripped-state")
	if err := os.WriteFile(path, []byte("old"), 0o000); err != nil {
		t.Fatal(err)
	}

	f := stageFile(t, dir, "new")
	if err := Promote(f, path, Opts{}); err != nil {
		t.Fatalf("Promote: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("zero-perm target mode=%v, want 0644 fallback", fi.Mode().Perm())
	}
}

// A Stat failure that is NOT ErrNotExist (here ENOTDIR — path under
// a regular file) means the target's real mode is unverifiable:
// guessing 0644 could downgrade a sensitive file, so Promote must
// fail and sweep the staging file.
func TestPromoteStatErrorFails(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(blocker, "child") // stat -> ENOTDIR

	f := stageFile(t, dir, "payload")
	stageName := f.Name()
	if err := Promote(f, path, Opts{}); err == nil {
		t.Fatal("Promote on ENOTDIR stat must fail, not guess 0644")
	}
	if _, err := os.Stat(stageName); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging file leaked after failed Promote: %v", err)
	}
}
