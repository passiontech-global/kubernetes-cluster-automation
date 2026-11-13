// dirwatcher_test.go — DirWatcher coverage moved with the type from
// the hostconfig subsystem (same package, so the fingerprint/readFile
// internals stay testable): poll edges, the pre-Poll fallback, the
// (size,mtime) fast path, and the walk/stat/read-error corners.
package fileconf

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestDirWatcherPollChangedEdge: Poll seeds the baseline without
// firing, latches one edge per fingerprint move, and Changed consumes
// it exactly once — without re-hashing the dirs on the main loop.
func TestDirWatcherPollChangedEdge(t *testing.T) {
	dir := t.TempDir()
	w := &DirWatcher{Dirs: []string{dir}, Period: 5 * time.Millisecond}
	ctx := t.Context()
	go w.Poll(ctx)

	deadline := time.Now().Add(5 * time.Second)
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
			time.Sleep(time.Millisecond)
		}
	}

	waitFor("Poll first scan", func() bool {
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.polled
	})
	if w.Changed() {
		t.Fatal("Changed fired on the freshly-seeded baseline")
	}

	// A file appearing between polls must surface as exactly one edge.
	if err := os.WriteFile(filepath.Join(dir, "vars.yaml"), []byte("a: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor("dirty latch", func() bool {
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.dirty
	})
	if !w.Changed() {
		t.Fatal("Changed lost the poll-latched edge")
	}
	if w.Changed() {
		t.Fatal("Changed fired twice for one edge")
	}
}

// TestDirWatcherChangedWithoutPoll: the pre-Poll fallback — Changed
// compares a fresh fingerprint against the last snapshot when Poll
// never ran (unit tests calling Changed directly).
func TestDirWatcherChangedWithoutPoll(t *testing.T) {
	dir := t.TempDir()
	w := &DirWatcher{Dirs: []string{dir}}
	if !w.Changed() {
		t.Fatal("first Changed should report a difference vs empty baseline")
	}
	if w.Changed() {
		t.Fatal("second Changed without file modifications should be false")
	}
	if err := os.WriteFile(filepath.Join(dir, "x"), []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !w.Changed() {
		t.Fatal("Changed missed the new file without Poll")
	}
	if w.Changed() {
		t.Fatal("Changed fired twice for the same file without Poll")
	}
}

// TestDirWatcherSkipsKubeletRotationDirs: kubelet ConfigMap/Secret
// rotation materializes `..data` -> `..2026_<ts>` plumbing under the
// watched dir — mount plumbing, not content. The dot-prefixed DIRS
// and everything inside them must stay out of the fingerprint:
// descending into a fresh timestamp dir re-triggered every watched
// hostconfig group on each kubelet symlink rotation.
func TestDirWatcherSkipsKubeletRotationDirs(t *testing.T) {
	dir := t.TempDir()
	write := func(p, b string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(b), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(dir, "config"), "real content\n")
	write(filepath.Join(dir, "..2026_01_01_00_00_00", "config"), "rotated v1\n")
	if err := os.Symlink("..2026_01_01_00_00_00", filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}

	w := &DirWatcher{Dirs: []string{dir}}
	if !w.Changed() {
		t.Fatal("first Changed should report a difference vs empty baseline")
	}
	if w.Changed() {
		t.Fatal("second Changed on an unchanged tree should be false")
	}

	// kubelet rotation: a NEW timestamp dir lands and ..data repoints
	// to it. Without the SkipDir prune this moved the fingerprint and
	// fired an edge.
	write(filepath.Join(dir, "..2026_02_02_00_00_00", "config"), "rotated v2\n")
	if err := os.Remove(filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..2026_02_02_00_00_00", filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	if w.Changed() {
		t.Fatal("kubelet rotation plumbing must not fire a change edge")
	}

	// Control: a REAL watched file changing still fires exactly once.
	write(filepath.Join(dir, "config"), "real content v2\n")
	if !w.Changed() {
		t.Fatal("real file change must still fire an edge")
	}
	if w.Changed() {
		t.Fatal("Changed fired twice for one real change")
	}
}

// TestDirWatcherFingerprintFastPath: the (size, mtime) fast path —
// a stat-unchanged scan must NOT re-read/re-hash file contents, a
// same-size rewrite with a DIFFERENT mtime must still be detected
// (content hash fallback), and a same-size same-mtime rewrite is
// trusted as unchanged (documented residual risk).
func TestDirWatcherFingerprintFastPath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	w := &DirWatcher{Dirs: []string{dir}}
	fp1 := w.fingerprint() // seeds the stat cache

	reads := 0
	prev := readFile
	readFile = func(name string) ([]byte, error) {
		reads++
		return prev(name)
	}
	defer func() { readFile = prev }()

	if fp2 := w.fingerprint(); fp2 != fp1 {
		t.Fatal("fingerprint moved without any file change")
	}
	if reads != 0 {
		t.Fatalf("stat-unchanged scan re-read content %d time(s)", reads)
	}

	// Same size, different mtime, different content → must re-hash
	// and move the fingerprint.
	if err := os.WriteFile(p, []byte("world"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, time.Unix(1_000_000_000, 0), time.Unix(1_000_000_000, 0)); err != nil {
		t.Fatal(err)
	}
	if fp3 := w.fingerprint(); fp3 == fp1 {
		t.Fatal("same-size different-mtime rewrite NOT detected")
	}
	if reads != 1 {
		t.Fatalf("changed stat must re-read exactly once, got %d reads", reads)
	}
	if w.fingerprint() == fp1 || reads != 1 {
		t.Fatal("rescan after change must reuse the fresh cache")
	}
}

// TestDirWatcherMissingDirStable — a watched dir that does not exist
// (yet — the vars CM may mount late) is skipped by the fingerprint
// walk; Changed stays false and no error escapes.
func TestDirWatcherMissingDirStable(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "not-mounted-yet")
	live := t.TempDir()
	w := &DirWatcher{Dirs: []string{missing, live}}
	// First Changed seeds the baseline (pre-Poll fallback); a second
	// call over the same content must stay quiet.
	_ = w.Changed()
	if w.Changed() {
		t.Fatal("Changed fired twice over a missing dir + empty live dir")
	}
	if err := os.WriteFile(filepath.Join(live, "f"), []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !w.Changed() {
		t.Fatal("Changed missed a new file in the live dir")
	}
}

// TestDirWatcherUnreadableFileExcluded — a file the agent cannot read
// is excluded from the fingerprint (excluded, not fatal): fingerprint
// equals the one computed without the file.
func TestDirWatcherUnreadableFileExcluded(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ok"), []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	w := &DirWatcher{Dirs: []string{dir}}
	sumBefore := w.fingerprint()
	locked := filepath.Join(dir, "locked")
	if err := os.WriteFile(locked, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o644) })
	if w.fingerprint() != sumBefore {
		t.Fatal("unreadable file not excluded from the fingerprint")
	}
	// Stable across calls: exclusion must not flap the fingerprint.
	if w.fingerprint() != sumBefore {
		t.Fatal("fingerprint unstable across calls with an unreadable file")
	}
}

// TestDirWatcherDefaultPeriod — Period unset falls back to the
// package default instead of a zero-ticker panic.
func TestDirWatcherDefaultPeriod(t *testing.T) {
	dir := t.TempDir()
	w := &DirWatcher{Dirs: []string{dir}}
	ctx := t.Context()
	done := make(chan struct{})
	go func() { defer close(done); w.Poll(ctx) }()
	select {
	case <-done:
		t.Fatal("Poll returned before ctx cancellation")
	case <-time.After(150 * time.Millisecond):
		// Poll latched the baseline and is ticking on the default
		// period — the zero-period branch did not panic.
	}
}

// TestDirWatcherDanglingSymlinkSkipped — a dangling symlink is listed
// by the walk (not a dir) but cannot be stat'd/read: excluded from
// the fingerprint without failing it.
func TestDirWatcherDanglingSymlinkSkipped(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ok"), []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	w := &DirWatcher{Dirs: []string{dir}}
	sumBefore := w.fingerprint()
	if err := os.Symlink(filepath.Join(dir, "gone"), filepath.Join(dir, "dangling")); err != nil {
		t.Fatal(err)
	}
	if w.fingerprint() != sumBefore {
		t.Fatal("dangling symlink not excluded from the fingerprint")
	}
}
