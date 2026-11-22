//go:build unix

package fsx_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
)

func reqAssertNoTempLeaks(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", dir, err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".tmp-") {
			t.Fatalf("found leaked staging file %q in %q", entry.Name(), dir)
		}
	}
}

func reqRegisterMemoCleanup(t *testing.T, origRename func(string, string) error, paths ...string) {
	t.Helper()
	cleaned := append([]string(nil), paths...)
	t.Cleanup(func() {
		fsx.RenameFile = func(string, string) error { return syscall.EACCES }
		for _, p := range cleaned {
			_ = os.Remove(p)
			_ = fsx.WriteFileAtomicNoSync(p, "evict")
		}
		fsx.RenameFile = origRename
	})
}

func reqStatInode(t *testing.T, path string) (uint64, uint64) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("os.Stat(%q): %v", path, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("Stat(%q).Sys() = %T, want *syscall.Stat_t", path, fi.Sys())
	}
	return st.Dev, st.Ino
}

func TestE2EReqTier1_F1_CoreAtomicAndHelpers(t *testing.T) {
	t.Run("WriteFileAtomic_HappyPathAndInodeRotation", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "state-ready")

		if err := fsx.WriteFileAtomic(p, "first-payload"); err != nil {
			t.Fatalf("WriteFileAtomic(first): %v", err)
		}
		got, err := os.ReadFile(p)
		if err != nil || string(got) != "first-payload" {
			t.Fatalf("ReadFile(%q) = (%q, %v), want (%q, nil)", p, string(got), err, "first-payload")
		}
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("Stat(%q): %v", p, err)
		}
		if fi.Mode().Perm() != 0o644 {
			t.Fatalf("mode = %#o, want 0644", fi.Mode().Perm())
		}
		key1, err := fsx.FileStatKey(p)
		if err != nil {
			t.Fatalf("FileStatKey(1): %v", err)
		}
		_, ino1 := reqStatInode(t, p)

		// Create a holder file before overwriting if needed to prevent inode reuse on some FS,
		// and verify atomic rename rotates inode.
		if err := fsx.WriteFileAtomic(p, "second-payload"); err != nil {
			t.Fatalf("WriteFileAtomic(second): %v", err)
		}
		key2, err := fsx.FileStatKey(p)
		if err != nil {
			t.Fatalf("FileStatKey(2): %v", err)
		}
		_, ino2 := reqStatInode(t, p)
		if key1 == key2 || ino1 == ino2 {
			t.Fatalf("expected atomic rewrite to rotate inode/key: key1=%q key2=%q ino1=%d ino2=%d", key1, key2, ino1, ino2)
		}
		reqAssertNoTempLeaks(t, dir)
	})

	t.Run("WriteFileAtomicBytes_BinaryPayload", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "binary.dat")
		payload := []byte{0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff, '\n', 0x00}
		if err := fsx.WriteFileAtomicBytes(p, payload); err != nil {
			t.Fatalf("WriteFileAtomicBytes: %v", err)
		}
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("ReadFile(%q): %v", p, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("binary mismatch: got %x, want %x", got, payload)
		}
		reqAssertNoTempLeaks(t, dir)
	})

	t.Run("WriteFileAtomicNoSync_EphemeralWrite", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "metrics.prom")
		prom := "# TYPE test_metric gauge\ntest_metric 1\n"
		if err := fsx.WriteFileAtomicNoSync(p, prom); err != nil {
			t.Fatalf("WriteFileAtomicNoSync: %v", err)
		}
		got, err := os.ReadFile(p)
		if err != nil || string(got) != prom {
			t.Fatalf("ReadFile(%q) = (%q, %v), want (%q, nil)", p, string(got), err, prom)
		}
		reqAssertNoTempLeaks(t, dir)
	})

	t.Run("WriteFileAndPromote_ModePreservationAndAfterSync", func(t *testing.T) {
		dir := t.TempDir()

		// 1. Pre-existing 0600 preserves 0600 when Opts.Mode == 0.
		pSecret := filepath.Join(dir, "secret.conf")
		if err := os.WriteFile(pSecret, []byte("old"), 0o600); err != nil {
			t.Fatalf("seed 0600: %v", err)
		}
		if err := fsx.WriteFile(pSecret, []byte("new-secret"), fsx.Opts{Mode: 0}); err != nil {
			t.Fatalf("WriteFile(0600): %v", err)
		}
		fi, err := os.Stat(pSecret)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("0600 file perm = %#o (err=%v), want 0600", fi.Mode().Perm(), err)
		}

		// 2. New file with Opts.Mode == 0 defaults to 0644.
		pNew := filepath.Join(dir, "fresh.conf")
		if err := fsx.WriteFile(pNew, []byte("fresh"), fsx.Opts{Mode: 0}); err != nil {
			t.Fatalf("WriteFile(fresh): %v", err)
		}
		fiNew, err := os.Stat(pNew)
		if err != nil || fiNew.Mode().Perm() != 0o644 {
			t.Fatalf("fresh file perm = %#o (err=%v), want 0644", fiNew.Mode().Perm(), err)
		}

		// 3. Target with 0000 mode is repaired to 0644 instead of propagating 0000.
		pZero := filepath.Join(dir, "zero.conf")
		if err := os.WriteFile(pZero, []byte("locked"), 0o644); err != nil {
			t.Fatalf("seed zero: %v", err)
		}
		if err := os.Chmod(pZero, 0o000); err != nil {
			t.Fatalf("chmod 0000: %v", err)
		}
		if err := fsx.WriteFile(pZero, []byte("repaired"), fsx.Opts{Mode: 0}); err != nil {
			t.Fatalf("WriteFile(0000 repair): %v", err)
		}
		fiZero, err := os.Stat(pZero)
		if err != nil || fiZero.Mode().Perm() != 0o644 {
			t.Fatalf("repaired 0000 file perm = %#o (err=%v), want 0644", fiZero.Mode().Perm(), err)
		}

		// 4. Promote invokes AfterSync even when NoSync is true.
		pPromote := filepath.Join(dir, "promoted.bin")
		stageFn := fsx.StageTempPattern(".tmp-promoted-*")
		stageFile, err := stageFn(dir)
		if err != nil {
			t.Fatalf("StageTempPattern: %v", err)
		}
		if _, err := stageFile.WriteString("streamed"); err != nil {
			_ = stageFile.Close()
			t.Fatalf("stage WriteString: %v", err)
		}
		var afterSyncCalled bool
		if err := fsx.Promote(stageFile, pPromote, fsx.Opts{
			NoSync: true,
			AfterSync: func(f *os.File) {
				if f != nil {
					afterSyncCalled = true
				}
			},
		}); err != nil {
			t.Fatalf("Promote: %v", err)
		}
		if !afterSyncCalled {
			t.Fatal("expected Opts.AfterSync to run even with NoSync=true")
		}
		reqAssertNoTempLeaks(t, dir)
	})

	t.Run("ReadAndStatHelpers", func(t *testing.T) {
		dir := t.TempDir()
		txtPath := filepath.Join(dir, "trimmed.txt")
		if err := os.WriteFile(txtPath, []byte("  hello-hostkit \n\t "), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if got := fsx.ReadTrimmed(txtPath); got != "hello-hostkit" {
			t.Fatalf("ReadTrimmed = %q, want %q", got, "hello-hostkit")
		}
		if got := fsx.ReadTrimmed(filepath.Join(dir, "absent")); got != "" {
			t.Fatalf("ReadTrimmed(absent) = %q, want empty", got)
		}

		uintPath := filepath.Join(dir, "num.txt")
		if err := os.WriteFile(uintPath, []byte("  42\n"), 0o644); err != nil {
			t.Fatalf("WriteFile uint: %v", err)
		}
		if v, ok := fsx.ReadUintFile(uintPath); !ok || v != 42 {
			t.Fatalf("ReadUintFile = (%d, %v), want (42, true)", v, ok)
		}

		// TouchIfDue: stale file gets touched, fresh file is skipped.
		latch := filepath.Join(dir, "latch")
		if err := os.WriteFile(latch, []byte("1"), 0o644); err != nil {
			t.Fatalf("WriteFile latch: %v", err)
		}
		t0 := time.Unix(1_700_000_000, 0)
		if err := os.Chtimes(latch, t0, t0); err != nil {
			t.Fatalf("Chtimes: %v", err)
		}
		fi, err := os.Stat(latch)
		if err != nil {
			t.Fatalf("Stat latch: %v", err)
		}
		if err := fsx.TouchIfDue(latch, fi, t0.Add(20*time.Minute), 15*time.Minute); err != nil {
			t.Fatalf("TouchIfDue(stale): %v", err)
		}
		fiAfter, err := os.Stat(latch)
		if err != nil {
			t.Fatalf("Stat latch after: %v", err)
		}
		if !fiAfter.ModTime().Equal(t0.Add(20 * time.Minute)) {
			t.Fatalf("TouchIfDue(stale) mtime = %v, want %v", fiAfter.ModTime(), t0.Add(20*time.Minute))
		}

		// HostSidePath boundary cases.
		for _, tc := range []struct {
			in, want string
		}{
			{"/host/etc/hosts", "/etc/hosts"},
			{"/host", "/"},
			{"/hostname/node-1", "/hostname/node-1"},
			{"/hostile/path", "/hostile/path"},
			{"/var/lib/watchdog", "/var/lib/watchdog"},
		} {
			if got := fsx.HostSidePath(tc.in); got != tc.want {
				t.Fatalf("HostSidePath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		}

		// ShellQuote escaping.
		if got := fsx.ShellQuote("a b'c"); got != `'a b'\''c'` {
			t.Fatalf("ShellQuote = %q, want %q", got, `'a b'\''c'`)
		}

		// FileStatKey 4-field format dev:ino:size:mtime_ns.
		key, err := fsx.FileStatKey(txtPath)
		if err != nil {
			t.Fatalf("FileStatKey: %v", err)
		}
		if parts := strings.Split(key, ":"); len(parts) != 4 {
			t.Fatalf("FileStatKey(%q) = %q (%d parts), want 4 colon-separated parts", txtPath, key, len(parts))
		}
	})
}

func TestE2EReqTier1_F17_EBUSYMemoization(t *testing.T) {
	// Never call t.Parallel() in tests that mutate fsx.RenameFile.
	t.Run("EBUSY_MemoizedAcrossWriteFileAtomicFamily", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "hosts")
		orig := fsx.RenameFile
		reqRegisterMemoCleanup(t, orig, p)

		var renameCalls atomic.Int32
		fsx.RenameFile = func(string, string) error {
			renameCalls.Add(1)
			return syscall.EBUSY
		}

		if err := fsx.WriteFileAtomic(p, "v1"); err != nil {
			t.Fatalf("WriteFileAtomic(v1): %v", err)
		}
		if err := fsx.WriteFileAtomic(p, "v2"); err != nil {
			t.Fatalf("WriteFileAtomic(v2): %v", err)
		}
		if err := fsx.WriteFileAtomicBytes(p, []byte("v3")); err != nil {
			t.Fatalf("WriteFileAtomicBytes(v3): %v", err)
		}
		if err := fsx.WriteFileAtomicNoSync(p, "v4"); err != nil {
			t.Fatalf("WriteFileAtomicNoSync(v4): %v", err)
		}

		if got := renameCalls.Load(); got != 1 {
			t.Fatalf("renameCalls = %d, want 1 across memoized WriteFileAtomic* family", got)
		}
		data, err := os.ReadFile(p)
		if err != nil || string(data) != "v4" {
			t.Fatalf("ReadFile(%q) = (%q, %v), want (%q, nil)", p, string(data), err, "v4")
		}
		reqAssertNoTempLeaks(t, dir)
	})

	t.Run("EBUSY_PathNormalization", func(t *testing.T) {
		dir := t.TempDir()
		sub := filepath.Join(dir, "sub")
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		pClean := filepath.Join(dir, "hosts")
		pDot := filepath.Join(dir, ".", "hosts")
		pDotDot := filepath.Join(dir, "sub", "..", "hosts")

		orig := fsx.RenameFile
		reqRegisterMemoCleanup(t, orig, pClean)

		var renameCalls atomic.Int32
		fsx.RenameFile = func(string, string) error {
			renameCalls.Add(1)
			return syscall.EBUSY
		}

		if err := fsx.WriteFileAtomic(pClean, "c1"); err != nil {
			t.Fatalf("WriteFileAtomic(clean): %v", err)
		}
		if err := fsx.WriteFileAtomic(pDot, "c2"); err != nil {
			t.Fatalf("WriteFileAtomic(dot): %v", err)
		}
		if err := fsx.WriteFileAtomicNoSync(pDotDot, "c3"); err != nil {
			t.Fatalf("WriteFileAtomicNoSync(dotdot): %v", err)
		}
		if got := renameCalls.Load(); got != 1 {
			t.Fatalf("renameCalls = %d, want 1 (clean path normalization)", got)
		}
		data, err := os.ReadFile(pClean)
		if err != nil || string(data) != "c3" {
			t.Fatalf("ReadFile(%q) = (%q, %v), want (%q, nil)", pClean, string(data), err, "c3")
		}
	})

	t.Run("EBUSY_PerPathIsolation", func(t *testing.T) {
		dir := t.TempDir()
		p1 := filepath.Join(dir, "hosts-1")
		p2 := filepath.Join(dir, "hosts-2")
		orig := fsx.RenameFile
		reqRegisterMemoCleanup(t, orig, p1, p2)

		var renameCalls atomic.Int32
		fsx.RenameFile = func(string, string) error {
			renameCalls.Add(1)
			return syscall.EBUSY
		}

		if err := fsx.WriteFileAtomic(p1, "one"); err != nil {
			t.Fatalf("WriteFileAtomic(p1): %v", err)
		}
		if err := fsx.WriteFileAtomic(p2, "two"); err != nil {
			t.Fatalf("WriteFileAtomic(p2): %v", err)
		}
		if got := renameCalls.Load(); got != 2 {
			t.Fatalf("renameCalls = %d, want 2 for distinct paths", got)
		}
	})

	t.Run("EBUSY_ReadOnlyDirPreExistingWritableFile", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "bind-hosts")
		if err := os.WriteFile(p, []byte("initial"), 0o644); err != nil {
			t.Fatalf("seed writable target: %v", err)
		}

		orig := fsx.RenameFile
		// Register memo cleanup FIRST, then chmod restore AFTER so LIFO restores 0755 before removing p.
		reqRegisterMemoCleanup(t, orig, p)
		t.Cleanup(func() {
			_ = os.Chmod(dir, 0o755)
		})

		var renameCalls atomic.Int32
		fsx.RenameFile = func(string, string) error {
			renameCalls.Add(1)
			return syscall.EBUSY
		}

		if err := fsx.WriteFileAtomic(p, "v1"); err != nil {
			t.Fatalf("prime EBUSY memo: %v", err)
		}
		if err := os.Chmod(dir, 0o555); err != nil {
			t.Fatalf("Chmod(0555): %v", err)
		}
		if err := fsx.WriteFileAtomic(p, "v2"); err != nil {
			t.Fatalf("memoized WriteFileAtomic in 0555 dir failed: %v", err)
		}
		if got := renameCalls.Load(); got != 1 {
			t.Fatalf("renameCalls = %d, want 1 (skipped doomed staging in 0555 dir)", got)
		}
		data, err := os.ReadFile(p)
		if err != nil || string(data) != "v2" {
			t.Fatalf("ReadFile(%q) = (%q, %v), want (%q, nil)", p, string(data), err, "v2")
		}

		if os.Geteuid() != 0 {
			unmemoized := filepath.Join(dir, "unmemoized-new")
			err := fsx.WriteFileAtomic(unmemoized, "x")
			if !errors.Is(err, syscall.EACCES) {
				t.Fatalf("unmemoized WriteFileAtomic in 0555 dir err = %v, want EACCES", err)
			}
		}
	})

	t.Run("EBUSY_NoSyncFirstMemoizesForSyncWriters", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "metrics.prom")
		orig := fsx.RenameFile
		reqRegisterMemoCleanup(t, orig, p)

		var renameCalls atomic.Int32
		fsx.RenameFile = func(string, string) error {
			renameCalls.Add(1)
			return syscall.EBUSY
		}

		if err := fsx.WriteFileAtomicNoSync(p, "v1"); err != nil {
			t.Fatalf("WriteFileAtomicNoSync: %v", err)
		}
		if err := fsx.WriteFileAtomic(p, "v2"); err != nil {
			t.Fatalf("WriteFileAtomic: %v", err)
		}
		if err := fsx.WriteFileAtomicBytes(p, []byte("v3")); err != nil {
			t.Fatalf("WriteFileAtomicBytes: %v", err)
		}
		if got := renameCalls.Load(); got != 1 {
			t.Fatalf("renameCalls = %d, want 1", got)
		}
		data, err := os.ReadFile(p)
		if err != nil || string(data) != "v3" {
			t.Fatalf("ReadFile(%q) = (%q, %v), want (%q, nil)", p, string(data), err, "v3")
		}
	})
}

func TestE2EReqTier2_F1_BoundaryAndErrorCases(t *testing.T) {
	t.Run("MissingParentDir_AllWritersError", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "no-such-dir", "target")
		if err := fsx.WriteFile(missing, []byte("a"), fsx.Opts{}); err == nil {
			t.Fatal("WriteFile succeeded with missing parent dir")
		}
		if err := fsx.WriteFileAtomic(missing, "a"); err == nil {
			t.Fatal("WriteFileAtomic succeeded with missing parent dir")
		}
		if err := fsx.WriteFileAtomicBytes(missing, []byte("a")); err == nil {
			t.Fatal("WriteFileAtomicBytes succeeded with missing parent dir")
		}
		if err := fsx.WriteFileAtomicNoSync(missing, "a"); err == nil {
			t.Fatal("WriteFileAtomicNoSync succeeded with missing parent dir")
		}
		if err := fsx.WriteFileDirect(missing, "a"); err == nil {
			t.Fatal("WriteFileDirect succeeded with missing parent dir")
		}
		if err := fsx.WriteFileDirectNoSync(missing, "a"); err == nil {
			t.Fatal("WriteFileDirectNoSync succeeded with missing parent dir")
		}
	})

	t.Run("PerCallOptsRenameFailure_SweepsStageAndPreservesTarget", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(p, []byte("keep"), 0o644); err != nil {
			t.Fatalf("seed target: %v", err)
		}
		err := fsx.WriteFile(p, []byte("replace"), fsx.Opts{
			Rename: func(string, string) error { return syscall.EPERM },
		})
		if !errors.Is(err, syscall.EPERM) {
			t.Fatalf("WriteFile err = %v, want EPERM", err)
		}
		got, rerr := os.ReadFile(p)
		if rerr != nil || string(got) != "keep" {
			t.Fatalf("target mutated on failed rename: got %q (err=%v), want %q", string(got), rerr, "keep")
		}
		reqAssertNoTempLeaks(t, dir)
	})

	t.Run("Promote_ENOTDIRStatError_FailsAndSweeps", func(t *testing.T) {
		dir := t.TempDir()
		blocker := filepath.Join(dir, "regular-file")
		if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
			t.Fatalf("seed blocker: %v", err)
		}
		stageFile, err := fsx.StageTempPattern(".tmp-promote-*")(dir)
		if err != nil {
			t.Fatalf("stage: %v", err)
		}
		stagePath := stageFile.Name()
		if _, err := stageFile.WriteString("payload"); err != nil {
			_ = stageFile.Close()
			t.Fatalf("write stage: %v", err)
		}
		err = fsx.Promote(stageFile, filepath.Join(blocker, "child"), fsx.Opts{Mode: 0})
		if !errors.Is(err, syscall.ENOTDIR) {
			t.Fatalf("Promote err = %v, want ENOTDIR", err)
		}
		if _, statErr := os.Stat(stagePath); !os.IsNotExist(statErr) {
			t.Fatalf("expected stage file %q to be swept, statErr=%v", stagePath, statErr)
		}
	})

	t.Run("ZeroLengthPayload_And_FileStatKeyMissing", func(t *testing.T) {
		dir := t.TempDir()
		p1 := filepath.Join(dir, "empty1")
		p2 := filepath.Join(dir, "empty2")
		if err := fsx.WriteFileAtomic(p1, ""); err != nil {
			t.Fatalf("WriteFileAtomic(empty): %v", err)
		}
		if err := fsx.WriteFileAtomicBytes(p2, []byte{}); err != nil {
			t.Fatalf("WriteFileAtomicBytes(empty): %v", err)
		}
		if b, err := os.ReadFile(p1); err != nil || len(b) != 0 {
			t.Fatalf("empty1 read = (%d bytes, %v), want (0, nil)", len(b), err)
		}
		if b, err := os.ReadFile(p2); err != nil || len(b) != 0 {
			t.Fatalf("empty2 read = (%d bytes, %v), want (0, nil)", len(b), err)
		}

		if _, err := fsx.FileStatKey(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("FileStatKey(missing) err = %v, want os.ErrNotExist", err)
		}

		for _, bad := range []struct {
			name, body string
		}{
			{"empty", ""},
			{"negative", "-1\n"},
			{"alpha", "not-a-uint\n"},
		} {
			bp := filepath.Join(dir, "bad-"+bad.name)
			if err := os.WriteFile(bp, []byte(bad.body), 0o644); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			if v, ok := fsx.ReadUintFile(bp); ok || v != 0 {
				t.Fatalf("ReadUintFile(%s) = (%d, %v), want (0, false)", bad.name, v, ok)
			}
		}
	})

	t.Run("TouchIfDue_ExactMinAgeAndNegativeSkew", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "latch")
		if err := os.WriteFile(p, []byte("1"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		base := time.Unix(1_700_000_000, 0)
		minAge := 15 * time.Minute
		if err := os.Chtimes(p, base, base); err != nil {
			t.Fatalf("Chtimes(base): %v", err)
		}
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("Stat: %v", err)
		}

		// Boundary: minAge - 1ns must skip.
		justBefore := base.Add(minAge - time.Nanosecond)
		if err := fsx.TouchIfDue(p, fi, justBefore, minAge); err != nil {
			t.Fatalf("TouchIfDue(minAge-1ns): %v", err)
		}
		fiSkip, err := os.Stat(p)
		if err != nil || !fiSkip.ModTime().Equal(base) {
			t.Fatalf("expected skip at minAge-1ns: mtime=%v want=%v err=%v", fiSkip.ModTime(), base, err)
		}

		// Boundary: exact minAge must touch.
		exact := base.Add(minAge)
		if err := fsx.TouchIfDue(p, fi, exact, minAge); err != nil {
			t.Fatalf("TouchIfDue(exact): %v", err)
		}
		fiExact, err := os.Stat(p)
		if err != nil || !fiExact.ModTime().Equal(exact) {
			t.Fatalf("expected touch at exact minAge: mtime=%v want=%v err=%v", fiExact.ModTime(), exact, err)
		}

		// Negative skew: file mtime in future relative to now must touch.
		future := base.Add(2 * time.Hour)
		if err := os.Chtimes(p, future, future); err != nil {
			t.Fatalf("Chtimes(future): %v", err)
		}
		fiFuture, err := os.Stat(p)
		if err != nil {
			t.Fatalf("Stat(future): %v", err)
		}
		if err := fsx.TouchIfDue(p, fiFuture, base, minAge); err != nil {
			t.Fatalf("TouchIfDue(negative age): %v", err)
		}
		fiFixed, err := os.Stat(p)
		if err != nil || !fiFixed.ModTime().Equal(base) {
			t.Fatalf("expected touch on negative age: mtime=%v want=%v err=%v", fiFixed.ModTime(), base, err)
		}
	})
}

func TestE2EReqTier2_F17_MemoBoundariesAndInvalidation(t *testing.T) {
	// Never call t.Parallel() in tests that mutate fsx.RenameFile.
	t.Run("EACCES_PropagatesAndNeverMemoizes", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "denied")
		orig := fsx.RenameFile
		t.Cleanup(func() { fsx.RenameFile = orig })

		fsx.RenameFile = func(string, string) error { return syscall.EACCES }
		err := fsx.WriteFileAtomic(p, "v1")
		if !errors.Is(err, syscall.EACCES) {
			t.Fatalf("WriteFileAtomic err = %v, want EACCES", err)
		}
		if _, statErr := os.Stat(p); !os.IsNotExist(statErr) {
			t.Fatalf("target %q should not exist after EACCES, statErr=%v", p, statErr)
		}
		reqAssertNoTempLeaks(t, dir)

		fsx.RenameFile = orig
		if err := fsx.WriteFileAtomic(p, "v2"); err != nil {
			t.Fatalf("retry with real RenameFile failed: %v", err)
		}
		if got := fsx.ReadTrimmed(p); got != "v2" {
			t.Fatalf("ReadTrimmed = %q, want %q", got, "v2")
		}
	})

	t.Run("EXDEV_FallsBackEveryTimeWithoutMemoizing", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "cross-dev")
		orig := fsx.RenameFile
		t.Cleanup(func() { fsx.RenameFile = orig })

		var renameCalls atomic.Int32
		fsx.RenameFile = func(string, string) error {
			renameCalls.Add(1)
			return syscall.EXDEV
		}

		for _, v := range []string{"a", "b", "c"} {
			if err := fsx.WriteFileAtomic(p, v); err != nil {
				t.Fatalf("WriteFileAtomic(%q): %v", v, err)
			}
		}
		if got := renameCalls.Load(); got != 3 {
			t.Fatalf("EXDEV renameCalls = %d, want 3 (never memoized)", got)
		}
		if got := fsx.ReadTrimmed(p); got != "c" {
			t.Fatalf("ReadTrimmed = %q, want %q", got, "c")
		}
	})

	t.Run("InodeChange_InvalidatesMemo", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "remounted")
		orig := fsx.RenameFile
		reqRegisterMemoCleanup(t, orig, p)

		var renameCalls atomic.Int32
		fsx.RenameFile = func(string, string) error {
			renameCalls.Add(1)
			return syscall.EBUSY
		}

		if err := fsx.WriteFileAtomic(p, "v1"); err != nil {
			t.Fatalf("WriteFileAtomic(v1): %v", err)
		}
		if got := renameCalls.Load(); got != 1 {
			t.Fatalf("initial renameCalls = %d, want 1", got)
		}
		_, ino1 := reqStatInode(t, p)

		// Replace p via temp+os.Rename while p still exists so the kernel allocates a distinct inode.
		replacement := filepath.Join(dir, "replacement")
		if err := os.WriteFile(replacement, []byte("replaced"), 0o644); err != nil {
			t.Fatalf("WriteFile(replacement): %v", err)
		}
		if err := orig(replacement, p); err != nil {
			t.Fatalf("os.Rename replacement: %v", err)
		}
		_, ino2 := reqStatInode(t, p)
		if ino1 == ino2 {
			t.Fatalf("expected replacement inode to differ: ino1=%d ino2=%d", ino1, ino2)
		}

		if err := fsx.WriteFileAtomic(p, "v2"); err != nil {
			t.Fatalf("WriteFileAtomic(v2 after inode change): %v", err)
		}
		if got := renameCalls.Load(); got != 2 {
			t.Fatalf("renameCalls after inode change = %d, want 2", got)
		}
		if err := fsx.WriteFileAtomic(p, "v3"); err != nil {
			t.Fatalf("WriteFileAtomic(v3 re-memoized): %v", err)
		}
		if got := renameCalls.Load(); got != 2 {
			t.Fatalf("renameCalls after re-memoize = %d, want 2", got)
		}
	})

	t.Run("RenameFileSwap_InvalidatesMemo", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "swapped")
		orig := fsx.RenameFile
		reqRegisterMemoCleanup(t, orig, p)

		fsx.RenameFile = func(string, string) error { return syscall.EBUSY }
		if err := fsx.WriteFileAtomic(p, "under-ebusy"); err != nil {
			t.Fatalf("WriteFileAtomic(ebusy): %v", err)
		}

		var permCalls atomic.Int32
		fsx.RenameFile = func(string, string) error {
			permCalls.Add(1)
			return syscall.EPERM
		}
		err := fsx.WriteFileAtomic(p, "should-fail")
		if !errors.Is(err, syscall.EPERM) {
			t.Fatalf("WriteFileAtomic after RenameFile swap err = %v, want EPERM", err)
		}
		if got := permCalls.Load(); got != 1 {
			t.Fatalf("permCalls = %d, want 1", got)
		}
		if got := fsx.ReadTrimmed(p); got != "under-ebusy" {
			t.Fatalf("target content = %q, want %q", got, "under-ebusy")
		}
	})

	t.Run("MemoCap1024_BoundedAndEvictsCleanly", func(t *testing.T) {
		dir := t.TempDir()
		orig := fsx.RenameFile
		const totalPaths = 1040
		paths := make([]string, 0, totalPaths)
		for i := range totalPaths {
			paths = append(paths, filepath.Join(dir, fmt.Sprintf("f-%d", i)))
		}
		reqRegisterMemoCleanup(t, orig, paths...)

		var renameCalls atomic.Int32
		fsx.RenameFile = func(string, string) error {
			renameCalls.Add(1)
			return syscall.EBUSY
		}

		// First pass: write all 1040 distinct paths under EBUSY. Every path invokes RenameFile
		// once on first write; up to remaining bindMountMemo capacity (<= 1024) are memoized
		// while overflow paths still succeed via direct-write fallback.
		for i := range totalPaths {
			if err := fsx.WriteFileAtomicNoSync(paths[i], "init"); err != nil {
				t.Fatalf("WriteFileAtomicNoSync(%d): %v", i, err)
			}
		}
		if got := renameCalls.Load(); got != totalPaths {
			t.Fatalf("renameCalls after %d initial paths = %d, want %d", totalPaths, got, totalPaths)
		}

		// Second pass: re-write all 1040 paths and count memoized (delta == 0) vs unmemoized
		// (delta == 1) paths dynamically so prior package-global entries cannot cause false failures.
		var memoizedCount, unmemoizedCount int
		for i := range totalPaths {
			before := renameCalls.Load()
			if err := fsx.WriteFileAtomicNoSync(paths[i], "v2"); err != nil {
				t.Fatalf("re-write path %d: %v", i, err)
			}
			delta := renameCalls.Load() - before
			switch delta {
			case 0:
				memoizedCount++
			case 1:
				unmemoizedCount++
			default:
				t.Fatalf("re-write path %d unexpected renameCalls delta = %d, want 0 or 1", i, delta)
			}
		}

		if memoizedCount > 1024 || memoizedCount < 1000 {
			t.Fatalf("memoizedCount = %d, want in [1000, 1024] (1024 capacity actively filled)", memoizedCount)
		}
		if unmemoizedCount < 16 {
			t.Fatalf("unmemoizedCount = %d, want >= 16 (cap prevented memoizing overflow entries)", unmemoizedCount)
		}
		for _, idx := range []int{0, memoizedCount - 1, totalPaths - 16, totalPaths - 1} {
			if got := fsx.ReadTrimmed(paths[idx]); got != "v2" {
				t.Fatalf("path[%d] content = %q, want %q", idx, got, "v2")
			}
		}
	})
}

func TestE2EReqTier3_F1_F17_PairwiseInteractions(t *testing.T) {
	// Never call t.Parallel() on parent or subtests mutating fsx.RenameFile.
	t.Run("FileStatKey_Vs_EBUSYDirectWrite", func(t *testing.T) {
		dir := t.TempDir()
		normalPath := filepath.Join(dir, "normal")
		if err := fsx.WriteFileAtomic(normalPath, "a"); err != nil {
			t.Fatalf("normal v1: %v", err)
		}
		_, nIno1 := reqStatInode(t, normalPath)
		if err := fsx.WriteFileAtomic(normalPath, "bb"); err != nil {
			t.Fatalf("normal v2: %v", err)
		}
		_, nIno2 := reqStatInode(t, normalPath)
		if nIno1 == nIno2 {
			t.Fatalf("expected atomic rename to change inode: %d == %d", nIno1, nIno2)
		}

		bindPath := filepath.Join(dir, "hosts")
		orig := fsx.RenameFile
		reqRegisterMemoCleanup(t, orig, bindPath)
		fsx.RenameFile = func(string, string) error { return syscall.EBUSY }

		if err := fsx.WriteFileAtomic(bindPath, "first"); err != nil {
			t.Fatalf("bind v1: %v", err)
		}
		bDev1, bIno1 := reqStatInode(t, bindPath)
		key1, err := fsx.FileStatKey(bindPath)
		if err != nil {
			t.Fatalf("FileStatKey(bind v1): %v", err)
		}

		if err := fsx.WriteFileAtomic(bindPath, "second-longer"); err != nil {
			t.Fatalf("bind v2: %v", err)
		}
		bDev2, bIno2 := reqStatInode(t, bindPath)
		key2, err := fsx.FileStatKey(bindPath)
		if err != nil {
			t.Fatalf("FileStatKey(bind v2): %v", err)
		}
		if bDev1 != bDev2 || bIno1 != bIno2 {
			t.Fatalf("expected EBUSY direct write to preserve (dev,ino): (%d,%d) != (%d,%d)", bDev1, bIno1, bDev2, bIno2)
		}
		if key1 == key2 {
			t.Fatalf("expected FileStatKey size/mtime to change across EBUSY direct write: %q", key1)
		}
	})

	t.Run("Mode0600Preserved_Under_MemoizedOverwrite", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "secret-bind")
		if err := os.WriteFile(p, []byte("long-initial-secret"), 0o600); err != nil {
			t.Fatalf("seed 0600: %v", err)
		}
		orig := fsx.RenameFile
		reqRegisterMemoCleanup(t, orig, p)

		var renameCalls atomic.Int32
		fsx.RenameFile = func(string, string) error {
			renameCalls.Add(1)
			return syscall.EBUSY
		}

		if err := fsx.WriteFileAtomic(p, "shorter"); err != nil {
			t.Fatalf("WriteFileAtomic(v1): %v", err)
		}
		if err := fsx.WriteFileAtomic(p, "hi"); err != nil {
			t.Fatalf("WriteFileAtomic(v2): %v", err)
		}
		if got := renameCalls.Load(); got != 1 {
			t.Fatalf("renameCalls = %d, want 1", got)
		}
		fi, err := os.Stat(p)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %#o (err=%v), want 0600 preserved on memoized truncate", fi.Mode().Perm(), err)
		}
		if data, rerr := os.ReadFile(p); rerr != nil || string(data) != "hi" {
			t.Fatalf("ReadFile = (%q, %v), want (%q, nil)", string(data), rerr, "hi")
		}
	})

	t.Run("PerCallOptsRename_IsolatedFrom_GlobalRenameFile", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "isolated")
		orig := fsx.RenameFile
		reqRegisterMemoCleanup(t, orig, p)

		var globalCalls atomic.Int32
		fsx.RenameFile = func(string, string) error {
			globalCalls.Add(1)
			return syscall.EBUSY
		}

		var optsCalls atomic.Int32
		if err := fsx.WriteFile(p, []byte("via-opts"), fsx.Opts{
			Rename: func(oldpath, newpath string) error {
				optsCalls.Add(1)
				return orig(oldpath, newpath)
			},
		}); err != nil {
			t.Fatalf("WriteFile(Opts.Rename): %v", err)
		}
		if optsCalls.Load() != 1 || globalCalls.Load() != 0 {
			t.Fatalf("unexpected call counts: opts=%d global=%d", optsCalls.Load(), globalCalls.Load())
		}

		// WriteFileAtomic must still observe global RenameFile (un-tainted by Opts.Rename).
		if err := fsx.WriteFileAtomic(p, "via-global-1"); err != nil {
			t.Fatalf("WriteFileAtomic(1): %v", err)
		}
		if err := fsx.WriteFileAtomic(p, "via-global-2"); err != nil {
			t.Fatalf("WriteFileAtomic(2): %v", err)
		}
		if globalCalls.Load() != 1 {
			t.Fatalf("globalCalls = %d, want 1", globalCalls.Load())
		}
	})

	t.Run("RaceStress_NoRenameFileMutation", func(t *testing.T) {
		dir := t.TempDir()
		const workers = 16
		const iters = 50
		var wg sync.WaitGroup
		errs := make(chan error, workers)
		for g := range workers {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				pAtomic := filepath.Join(dir, fmt.Sprintf("atomic-%d", id%4))
				pNoSync := filepath.Join(dir, fmt.Sprintf("nosync-%d", id%4))
				pOpts := filepath.Join(dir, fmt.Sprintf("opts-%d", id%4))
				for i := range iters {
					payload := fmt.Sprintf("g%d-i%d", id, i)
					if err := fsx.WriteFileAtomic(pAtomic, payload); err != nil {
						errs <- fmt.Errorf("WriteFileAtomic: %w", err)
						return
					}
					if err := fsx.WriteFileAtomicBytes(pAtomic, []byte(payload)); err != nil {
						errs <- fmt.Errorf("WriteFileAtomicBytes: %w", err)
						return
					}
					if err := fsx.WriteFileAtomicNoSync(pNoSync, payload); err != nil {
						errs <- fmt.Errorf("WriteFileAtomicNoSync: %w", err)
						return
					}
					if err := fsx.WriteFile(pOpts, []byte(payload), fsx.Opts{Rename: os.Rename}); err != nil {
						errs <- fmt.Errorf("WriteFile: %w", err)
						return
					}
					if _, err := fsx.FileStatKey(pAtomic); err != nil {
						errs <- fmt.Errorf("FileStatKey: %w", err)
						return
					}
					if got := fsx.ReadTrimmed(pNoSync); got == "" {
						errs <- errors.New("ReadTrimmed returned empty string")
						return
					}
				}
			}(g)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatal(err)
		}
		reqAssertNoTempLeaks(t, dir)
	})
}

func TestE2EReqTier4_Scenario1_MixedBindMountAndRegularConvergence(t *testing.T) {
	// Never call t.Parallel() in tests that mutate fsx.RenameFile.
	dir := t.TempDir()
	hostsPath := filepath.Join(dir, "hosts")
	promPath := filepath.Join(dir, "metric.prom")
	statePath := filepath.Join(dir, "state-probe")
	binPath := filepath.Join(dir, "bytes.bin")
	latchPath := filepath.Join(dir, "latch")

	if err := os.WriteFile(latchPath, []byte("latched"), 0o644); err != nil {
		t.Fatalf("seed latch: %v", err)
	}
	tOld := time.Now().Add(-time.Hour)
	if err := os.Chtimes(latchPath, tOld, tOld); err != nil {
		t.Fatalf("Chtimes(latch): %v", err)
	}

	orig := fsx.RenameFile
	reqRegisterMemoCleanup(t, orig, hostsPath)

	var hostsRenames atomic.Int32
	fsx.RenameFile = func(oldpath, newpath string) error {
		if filepath.Base(newpath) == "hosts" {
			hostsRenames.Add(1)
			return syscall.EBUSY
		}
		return orig(oldpath, newpath)
	}

	// Prime 1st pass so bind-mounted hosts is memoized before concurrent workers run.
	if err := fsx.WriteFileAtomic(hostsPath, "127.0.0.1 localhost\n"); err != nil {
		t.Fatalf("prime hosts: %v", err)
	}
	if hostsRenames.Load() != 1 {
		t.Fatalf("prime hostsRenames = %d, want 1", hostsRenames.Load())
	}

	const workers = 16
	const rounds = 40
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for g := range workers {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for r := range rounds {
				hostsVal := fmt.Sprintf("127.0.0.1 localhost\n10.0.%d.%d node-%d\n", id, r, id)
				if err := fsx.WriteFileAtomic(hostsPath, hostsVal); err != nil {
					errs <- fmt.Errorf("hosts WriteFileAtomic: %w", err)
					return
				}
				if err := fsx.WriteFileAtomicNoSync(promPath, fmt.Sprintf("watchdog_ok %d\n", r)); err != nil {
					errs <- fmt.Errorf("prom WriteFileAtomicNoSync: %w", err)
					return
				}
				if err := fsx.WriteFileAtomic(statePath, fmt.Sprintf("round=%d", r)); err != nil {
					errs <- fmt.Errorf("state WriteFileAtomic: %w", err)
					return
				}
				if err := fsx.WriteFileAtomicBytes(binPath, []byte{0x01, byte(id), byte(r), 0xff}); err != nil {
					errs <- fmt.Errorf("bin WriteFileAtomicBytes: %w", err)
					return
				}
				if fi, err := os.Stat(latchPath); err == nil {
					if err := fsx.TouchIfDue(latchPath, fi, time.Now(), 15*time.Minute); err != nil {
						errs <- fmt.Errorf("TouchIfDue: %w", err)
						return
					}
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	if got := hostsRenames.Load(); got != 1 {
		t.Fatalf("hostsRenames after %dx%d convergence rounds = %d, want 1", workers, rounds, got)
	}
	for _, p := range []string{hostsPath, promPath, statePath, binPath, latchPath} {
		if _, err := fsx.FileStatKey(p); err != nil {
			t.Fatalf("FileStatKey(%q): %v", p, err)
		}
	}
	if got := fsx.ReadTrimmed(hostsPath); !strings.Contains(got, "127.0.0.1 localhost") {
		t.Fatalf("hosts content unexpected: %q", got)
	}
	if got := fsx.ReadTrimmed(promPath); !strings.HasPrefix(got, "watchdog_ok ") {
		t.Fatalf("prom content unexpected: %q", got)
	}
	reqAssertNoTempLeaks(t, dir)
}
