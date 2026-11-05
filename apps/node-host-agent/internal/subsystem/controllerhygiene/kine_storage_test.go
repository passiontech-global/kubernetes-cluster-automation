package controllerhygiene

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- W10-CP2: checkKineStorageHealth ---

// setupKineStore points K0sDir at a tempdir carrying db/state.db +
// state.db-wal of the given sizes, shrinks the checkpoint threshold,
// diverts the textfile dir, and returns a call counter for the
// injected checkpoint fn.
func setupKineStore(t *testing.T, e *env, dbSize, walSize int64) *int {
	t.Helper()
	root := t.TempDir()
	k0s := filepath.Join(root, "k0s")
	dbDir := filepath.Join(k0s, "db")
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if dbSize >= 0 {
		writeFile(t, filepath.Join(dbDir, "state.db"),
			strings.Repeat("x", int(dbSize)))
	}
	if walSize >= 0 {
		writeFile(t, filepath.Join(dbDir, "state.db-wal"),
			strings.Repeat("y", int(walSize)))
	}
	e.h.cfg.K0sDir = k0s

	oldMin := kineWALCheckpointMinBytes
	kineWALCheckpointMinBytes = 100
	t.Cleanup(func() { kineWALCheckpointMinBytes = oldMin })
	oldTD := textfileDirOverride
	textfileDirOverride = filepath.Join(root, "textfile")
	t.Cleanup(func() { textfileDirOverride = oldTD })

	calls := new(int)
	oldFn := kineCheckpointFn
	kineCheckpointFn = func(_ context.Context, dbPath string) error {
		*calls++
		if dbPath != filepath.Join(dbDir, "state.db") {
			t.Errorf("checkpoint db path %q", dbPath)
		}
		return nil
	}
	t.Cleanup(func() { kineCheckpointFn = oldFn })
	return calls
}

func TestKineStorageHealthCheckpointGating(t *testing.T) {
	e := fixture(t)
	calls := setupKineStore(t, e, 50, 200) // wal 200 > 100 threshold

	e.h.checkKineStorageHealth(context.Background())
	if *calls != 1 {
		t.Fatalf("checkpoint calls=%d want 1", *calls)
	}
	// Metrics landed in the textfile.
	prom, err := os.ReadFile(filepath.Join(
		textfileDirOverride, "node-agent-kine-storage.prom"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"node_agent_kine_db_bytes 50",
		"node_agent_kine_wal_bytes 200",
	} {
		if !strings.Contains(string(prom), want) {
			t.Fatalf("textfile missing %q:\n%s", want, prom)
		}
	}

	// Second run inside the 30m cooldown → no checkpoint.
	e.h.checkKineStorageHealth(context.Background())
	if *calls != 1 {
		t.Fatalf("checkpoint calls=%d want 1 (cooldown)", *calls)
	}

	// Past the cooldown → checkpoint again.
	e.now = e.now.Add(31 * time.Minute)
	e.h.checkKineStorageHealth(context.Background())
	if *calls != 2 {
		t.Fatalf("checkpoint calls=%d want 2", *calls)
	}
}

func TestKineStorageHealthSmallWALNoCheckpoint(t *testing.T) {
	e := fixture(t)
	calls := setupKineStore(t, e, 50, 50) // wal 50 <= 100 threshold
	e.h.checkKineStorageHealth(context.Background())
	if *calls != 0 {
		t.Fatalf("checkpoint fired on small WAL: calls=%d", *calls)
	}
}

func TestKineStorageHealthNoSQLite3KeepsCooldown(t *testing.T) {
	e := fixture(t)
	calls := setupKineStore(t, e, 50, 200)
	oldFn := kineCheckpointFn
	kineCheckpointFn = func(context.Context, string) error {
		*calls++
		return errKineNoSQLite3
	}
	defer func() { kineCheckpointFn = oldFn }()

	e.h.checkKineStorageHealth(context.Background())
	e.h.checkKineStorageHealth(context.Background())
	if *calls != 2 {
		t.Fatalf("no-sqlite3 should not spend cooldown: calls=%d want 2",
			*calls)
	}
}

func TestKineStorageHealthAbsentStore(t *testing.T) {
	e := fixture(t)
	root := t.TempDir()
	e.h.cfg.K0sDir = filepath.Join(root, "k0s") // nothing inside
	oldTD := textfileDirOverride
	textfileDirOverride = filepath.Join(root, "textfile")
	defer func() { textfileDirOverride = oldTD }()

	e.h.checkKineStorageHealth(context.Background()) // must not panic
	prom, err := os.ReadFile(filepath.Join(
		textfileDirOverride, "node-agent-kine-storage.prom"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(prom), "\nnode_agent_kine_db_bytes ") {
		t.Fatalf("absent store emitted a size sample:\n%s", prom)
	}
}
