// kine_storage_internal_test.go — the sqlite3 exec plumbing behind
// the kine-storage store-health seams: the bounded filestore walk and the
// two sqlite3 CLI runners (argv contract, NOTIFY_SOCKET/WATCHDOG_*
// env scrub, separate error wrapping, ErrNoSQLite3 detection).
// Internal test package: the seams are unexported package funcs.
package storelocal

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDirSizeBounded(t *testing.T) {
	root := filepath.Join(t.TempDir(), "etcd")
	writeFileAt(t, filepath.Join(root, "b.txt"), 20)
	writeFileAt(t, filepath.Join(root, "member", "a.txt"), 10)
	writeFileAt(t, filepath.Join(root, "z.txt"), 5)

	total, err := dirSizeBounded(root, 1000)
	if err != nil {
		t.Fatalf("dirSizeBounded err=%v", err)
	}
	if total != 35 {
		t.Fatalf("total=%d want 35", total)
	}

	// An unreadable subdirectory is skipped best-effort: the walk
	// never fails and contributes nothing (as root the dir is simply
	// readable-and-empty — both cases stay green).
	blocked := filepath.Join(root, "restricted")
	writeFileAt(t, filepath.Join(blocked, "x.txt"), 7)
	if err := os.Chmod(blocked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o755) })
	total, err = dirSizeBounded(root, 1000)
	if err != nil {
		t.Fatalf("restricted dir broke the walk: err=%v", err)
	}
	if total != 35 {
		t.Fatalf("restricted dir contributed: total=%d want 35", total)
	}

	// The file cap stops the walk early (fs.SkipAll): the first
	// counted file is b.txt (lexical) — the walk aborts inside the
	// next dir before any deeper file counts.
	total, err = dirSizeBounded(root, 1)
	if err != nil {
		t.Fatalf("capped walk err=%v", err)
	}
	if total != 20 {
		t.Fatalf("capped total=%d want 20", total)
	}
}

func TestSqlite3WALCheckpoint(t *testing.T) {
	ctx := context.Background()

	t.Run("binary absent", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir()) // empty dir: no sqlite3
		err := sqlite3WALCheckpoint(ctx, "/db/state.db")
		if !errors.Is(err, ErrNoSQLite3) {
			t.Fatalf("err=%v want ErrNoSQLite3", err)
		}
	})

	t.Run("failure wraps stderr", func(t *testing.T) {
		bin := fakeSqlite3(t, `echo "database is locked" >&2; echo partial; exit 1`)
		t.Setenv("PATH", filepath.Dir(bin))
		err := sqlite3WALCheckpoint(ctx, "/db/state.db")
		if err == nil || errors.Is(err, ErrNoSQLite3) {
			t.Fatalf("err=%v want a wrapped failure", err)
		}
		if !strings.Contains(err.Error(), "wal_checkpoint") ||
			!strings.Contains(err.Error(), "database is locked") {
			t.Fatalf("err=%v missing the sqlite3 evidence", err)
		}
	})

	t.Run("argv contract and inherited env", func(t *testing.T) {
		t.Setenv("NOTIFY_SOCKET", "/run/notify.sock")
		t.Setenv("WATCHDOG_PID", "5")
		t.Setenv("KEEP_ME", "1")
		// The error path returns the script's stdout, so the script
		// echoes what it saw and fails — the only way to observe the
		// child env/argv through this seam.
		bin := fakeSqlite3(t, `
printf 'DB:%s\n' "$1"
printf 'SQL:%s\n' "$2"
printf 'NS:%s\n' "${NOTIFY_SOCKET:+set}"
printf 'WP:%s\n' "${WATCHDOG_PID:+set}"
printf 'KEEP:%s\n' "${KEEP_ME:+set}"
exit 1`)
		t.Setenv("PATH", filepath.Dir(bin))
		err := sqlite3WALCheckpoint(ctx, "/db/state.db")
		if err == nil {
			t.Fatal("expected the failing fake to error")
		}
		for _, want := range []string{
			"DB:/db/state.db",
			"SQL:PRAGMA busy_timeout=5000; PRAGMA wal_checkpoint(TRUNCATE);",
			// sqlite3 implements no sd_notify protocol, so the
			// daemon env rides through unscrubbed — only the
			// systemctl/journalctl paths needed the drop.
			"NS:set",
			"WP:set",
			"KEEP:set",
		} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("missing %q in: %s", want, err)
			}
		}
	})
	t.Run("success", func(t *testing.T) {
		// The wal_checkpoint result row (busy|log|ckpt) must parse
		// clean — busy=0 is the only success shape.
		bin := fakeSqlite3(t, `printf '5000\n0|10|10\n'; exit 0`)
		t.Setenv("PATH", filepath.Dir(bin))
		if err := sqlite3WALCheckpoint(ctx, "/db/state.db"); err != nil {
			t.Fatalf("err=%v want nil", err)
		}
	})
	t.Run("busy checkpoint row is an error", func(t *testing.T) {
		// busy=1 exits 0 — the exit code alone would read a
		// no-op checkpoint as success while the WAL keeps growing.
		bin := fakeSqlite3(t, `printf '1|10|3\n'; exit 0`)
		t.Setenv("PATH", filepath.Dir(bin))
		err := sqlite3WALCheckpoint(ctx, "/db/state.db")
		if err == nil || !strings.Contains(err.Error(), "busy") {
			t.Fatalf("err=%v want the busy-checkpoint failure", err)
		}
	})
	t.Run("host mount path is unrooted for the nsenter side", func(t *testing.T) {
		// /host/var/lib/k0s/... is the DaemonSet mount view; inside
		// the host mount namespace the same file is /var/lib/k0s/...
		// — sqlite3Host owns that translation (a real nsenter exec
		// is not unit-testable).
		for _, tc := range []struct{ in, want string }{
			{"/host/var/lib/k0s/db/state.db", "/var/lib/k0s/db/state.db"},
			{"/var/lib/k0s/db/state.db", "/var/lib/k0s/db/state.db"}, // standalone: already host-side
			{"/host/db/state.db", "/db/state.db"},
		} {
			if _, host := sqlite3Host(tc.in); host != tc.want {
				t.Fatalf("sqlite3Host(%q) host=%q want %q", tc.in, host, tc.want)
			}
		}
	})
}

func TestSqlite3KineLargeObjects(t *testing.T) {
	ctx := context.Background()

	t.Run("binary absent", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		rows, err := sqlite3KineLargeObjects(ctx, "/db/state.db")
		if !errors.Is(err, ErrNoSQLite3) || rows != nil {
			t.Fatalf("rows=%v err=%v want ErrNoSQLite3", rows, err)
		}
	})

	t.Run("parses rows and skips garbage", func(t *testing.T) {
		bin := fakeSqlite3(t, `printf '/registry/secrets/default/big|600000\n'
printf '/registry/configmaps/default/small|100\n'
printf 'garbage-no-pipe\n'
printf 'bad|notanumber\n'
printf 'before-blank\n\n/registry/pods/default/x|33\n'
printf '\n'
exit 0`)
		t.Setenv("PATH", filepath.Dir(bin))
		rows, err := sqlite3KineLargeObjects(ctx, "/db/state.db")
		if err != nil {
			t.Fatalf("err=%v", err)
		}
		want := []KineLargeObject{
			{Name: "/registry/secrets/default/big", Bytes: 600000},
			{Name: "/registry/configmaps/default/small", Bytes: 100},
			{Name: "/registry/pods/default/x", Bytes: 33},
		}
		if len(rows) != len(want) {
			t.Fatalf("rows=%+v want %+v", rows, want)
		}
		for i, w := range want {
			if rows[i] != w {
				t.Errorf("row[%d]=%+v want %+v", i, rows[i], w)
			}
		}
	})

	t.Run("failure wraps stderr and carries the query", func(t *testing.T) {
		bin := fakeSqlite3(t, `printf 'Q:%s\n' "$2"; echo "disk I/O error" >&2; exit 1`)
		t.Setenv("PATH", filepath.Dir(bin))
		_, err := sqlite3KineLargeObjects(ctx, "/db/state.db")
		if err == nil || errors.Is(err, ErrNoSQLite3) ||
			!strings.Contains(err.Error(), "kine large objects") ||
			!strings.Contains(err.Error(), "disk I/O error") ||
			!strings.Contains(err.Error(),
				"Q:PRAGMA busy_timeout=5000; SELECT name, length(value) "+
					"FROM kine WHERE deleted = 0 ORDER BY length(value) DESC LIMIT 10;") {
			t.Fatalf("err=%v want the wrapped scan failure with its query", err)
		}
	})
}

// fakeSqlite3 installs a shell script named sqlite3 on a temp PATH
// dir and returns the PATH dir.
func fakeSqlite3(t *testing.T, script string) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "sqlite3")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func writeFileAt(t *testing.T, path string, size int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, make([]byte, size), 0o644); err != nil {
		t.Fatal(err)
	}
}
