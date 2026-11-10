package storelocal_test

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdepstest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/storelocal"

	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// --- kine-storage: checkKineStorageHealth ---

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
		testutil.WriteFile(t, filepath.Join(dbDir, "state.db"),
			strings.Repeat("x", int(dbSize)))
	}
	if walSize >= 0 {
		testutil.WriteFile(t, filepath.Join(dbDir, "state.db-wal"),
			strings.Repeat("y", int(walSize)))
	}
	e.H.Cfg.K0sDir = k0s

	oldMin := storelocal.WALCheckpointMinBytes
	storelocal.WALCheckpointMinBytes = 100
	t.Cleanup(func() { storelocal.WALCheckpointMinBytes = oldMin })
	oldTD := cdeps.TextfileDirOverride
	cdeps.TextfileDirOverride = filepath.Join(root, "textfile")
	t.Cleanup(func() { cdeps.TextfileDirOverride = oldTD })

	calls := new(int)
	oldFn := storelocal.CheckpointFn
	storelocal.CheckpointFn = func(_ context.Context, dbPath string) error {
		*calls++
		if dbPath != filepath.Join(dbDir, "state.db") {
			t.Errorf("checkpoint db path %q", dbPath)
		}
		return nil
	}
	t.Cleanup(func() { storelocal.CheckpointFn = oldFn })
	// Hermetic by default: the real sqlite3 CLI recovers (and can
	// zero) a bogus state.db-wal, which would corrupt the fixture
	// sizes across runs. Tests that exercise the scan override it.
	oldLO := storelocal.LargeObjectsFn
	storelocal.LargeObjectsFn = func(context.Context, string) ([]storelocal.KineLargeObject, error) {
		return nil, nil
	}
	t.Cleanup(func() { storelocal.LargeObjectsFn = oldLO })
	return calls
}

func TestKineStorageHealthCheckpointGating(t *testing.T) {
	e := fixture(t)
	calls := setupKineStore(t, e, 50, 200) // wal 200 > 100 threshold

	cdepstest.Check[*storelocal.StorageCheck](e.H, cdeps.CheckKineStorage).Run(context.Background())
	if *calls != 1 {
		t.Fatalf("checkpoint calls=%d want 1", *calls)
	}
	// Metrics landed in the textfile.
	prom, err := os.ReadFile(filepath.Join(
		cdeps.TextfileDirOverride, "node-agent-kine-storage.prom"))
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
	cdepstest.Check[*storelocal.StorageCheck](e.H, cdeps.CheckKineStorage).Run(context.Background())
	if *calls != 1 {
		t.Fatalf("checkpoint calls=%d want 1 (cooldown)", *calls)
	}

	// Past the cooldown → checkpoint again.
	e.Now = e.Now.Add(31 * time.Minute)
	cdepstest.Check[*storelocal.StorageCheck](e.H, cdeps.CheckKineStorage).Run(context.Background())
	if *calls != 2 {
		t.Fatalf("checkpoint calls=%d want 2", *calls)
	}
}

func TestKineStorageHealthSmallWALNoCheckpoint(t *testing.T) {
	e := fixture(t)
	calls := setupKineStore(t, e, 50, 50) // wal 50 <= 100 threshold
	cdepstest.Check[*storelocal.StorageCheck](e.H, cdeps.CheckKineStorage).Run(context.Background())
	if *calls != 0 {
		t.Fatalf("checkpoint fired on small WAL: calls=%d", *calls)
	}
}

func TestKineStorageHealthNoSQLite3KeepsCooldown(t *testing.T) {
	e := fixture(t)
	calls := setupKineStore(t, e, 50, 200)
	oldFn := storelocal.CheckpointFn
	storelocal.CheckpointFn = func(context.Context, string) error {
		*calls++
		return storelocal.ErrNoSQLite3
	}
	defer func() { storelocal.CheckpointFn = oldFn }()

	cdepstest.Check[*storelocal.StorageCheck](e.H, cdeps.CheckKineStorage).Run(context.Background())
	cdepstest.Check[*storelocal.StorageCheck](e.H, cdeps.CheckKineStorage).Run(context.Background())
	if *calls != 2 {
		t.Fatalf("no-sqlite3 should not spend cooldown: calls=%d want 2",
			*calls)
	}
}

func TestKineStorageHealthAbsentStore(t *testing.T) {
	e := fixture(t)
	root := t.TempDir()
	e.H.Cfg.K0sDir = filepath.Join(root, "k0s") // nothing inside
	oldTD := cdeps.TextfileDirOverride
	cdeps.TextfileDirOverride = filepath.Join(root, "textfile")
	defer func() { cdeps.TextfileDirOverride = oldTD }()

	cdepstest.Check[*storelocal.StorageCheck](e.H, cdeps.CheckKineStorage).Run(context.Background()) // must not panic
	prom, err := os.ReadFile(filepath.Join(
		cdeps.TextfileDirOverride, "node-agent-kine-storage.prom"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(prom), "\nnode_agent_kine_db_bytes ") {
		t.Fatalf("absent store emitted a size sample:\n%s", prom)
	}
}

// --- Kine large-object scan ---

// runStorage is the shared one-cycle runner for the StorageCheck.
func runStorage(t *testing.T, e *env) {
	t.Helper()
	cdepstest.Check[*storelocal.StorageCheck](e.H, cdeps.CheckKineStorage).Run(context.Background())
}

// readProm reads the node-agent-kine-storage.prom textfile.
func readProm(t *testing.T) string {
	t.Helper()
	prom, err := os.ReadFile(filepath.Join(
		cdeps.TextfileDirOverride, "node-agent-kine-storage.prom"))
	if err != nil {
		t.Fatal(err)
	}
	return string(prom)
}

// readWatchdogLog reads the fixture's watchdog log (the
// AppendLog/AppendLogWarn sink).
func readWatchdogLog(t *testing.T, e *env) string {
	t.Helper()
	b, err := os.ReadFile(e.H.Cfg.WatchdogLogFile)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestKineStorageLargeObjectScan(t *testing.T) {
	e := fixture(t)
	setupKineStore(t, e, 50, 50) // small WAL — only the object scan runs
	calls := new(int)
	oldFn := storelocal.LargeObjectsFn
	storelocal.LargeObjectsFn = func(_ context.Context, dbPath string) ([]storelocal.KineLargeObject, error) {
		*calls++
		if want := filepath.Join(e.H.Cfg.K0sDir, "db", "state.db"); dbPath != want {
			t.Errorf("large-object db path %q want %q", dbPath, want)
		}
		return []storelocal.KineLargeObject{
			{Name: "/registry/secrets/default/big", Bytes: 600000},
			{Name: "/registry/configmaps/default/small", Bytes: 100},
		}, nil
	}
	t.Cleanup(func() { storelocal.LargeObjectsFn = oldFn })

	runStorage(t, e)
	if *calls != 1 {
		t.Fatalf("large-object scan calls=%d want 1", *calls)
	}
	// Gauge = top-1 length in the textfile.
	if prom := readProm(t); !strings.Contains(prom,
		"node_agent_kine_max_object_bytes 600000") {
		t.Fatalf("textfile missing max-object gauge:\n%s", prom)
	}
	// The >512KiB key is named in a warn log; the small key is not.
	log := readWatchdogLog(t, e)
	if !strings.Contains(log, "/registry/secrets/default/big") {
		t.Fatalf("warn log missing oversized key:\n%s", log)
	}
	if strings.Contains(log, "/registry/configmaps/default/small") {
		t.Fatalf("warn log names an under-threshold key:\n%s", log)
	}

	// Inside the 15m cooldown → no rescan (gauge stays cached).
	runStorage(t, e)
	if *calls != 1 {
		t.Fatalf("scan ran inside cooldown: calls=%d want 1", *calls)
	}
	if prom := readProm(t); !strings.Contains(prom,
		"node_agent_kine_max_object_bytes 600000") {
		t.Fatalf("cached gauge lost across cooldown:\n%s", prom)
	}

	// Past the cooldown → scan again.
	e.Now = e.Now.Add(16 * time.Minute)
	runStorage(t, e)
	if *calls != 2 {
		t.Fatalf("scan calls=%d want 2 after cooldown", *calls)
	}
}

// No sqlite3 on the host → the scan is skipped WITHOUT spending the
// cooldown, so a later install still gets the scan.
func TestKineStorageLargeObjectScanNoSQLite3KeepsCooldown(t *testing.T) {
	e := fixture(t)
	setupKineStore(t, e, 50, 50)
	calls := new(int)
	oldFn := storelocal.LargeObjectsFn
	storelocal.LargeObjectsFn = func(context.Context, string) ([]storelocal.KineLargeObject, error) {
		*calls++
		return nil, storelocal.ErrNoSQLite3
	}
	t.Cleanup(func() { storelocal.LargeObjectsFn = oldFn })

	runStorage(t, e)
	runStorage(t, e)
	if *calls != 2 {
		t.Fatalf("no-sqlite3 spent the cooldown: calls=%d want 2", *calls)
	}
}

// A failing scan spends the cooldown and warns but keeps the check
// green (same contract as the checkpoint path).
func TestKineStorageLargeObjectScanFailureSpendsCooldown(t *testing.T) {
	e := fixture(t)
	setupKineStore(t, e, 50, 50)
	calls := new(int)
	oldFn := storelocal.LargeObjectsFn
	storelocal.LargeObjectsFn = func(context.Context, string) ([]storelocal.KineLargeObject, error) {
		*calls++
		return nil, errors.New("disk I/O error")
	}
	t.Cleanup(func() { storelocal.LargeObjectsFn = oldFn })

	runStorage(t, e)
	if !strings.Contains(readWatchdogLog(t, e), "kine large-object scan failed") {
		t.Fatal("scan failure not warned")
	}
	runStorage(t, e)
	if *calls != 1 {
		t.Fatalf("failure did not spend cooldown: calls=%d want 1", *calls)
	}
}

// No successful scan yet (sqlite3 absent forever) → the gauge stays
// a header, no stale sample in the textfile.
func TestKineStorageLargeObjectGaugeAbsentUntilScanned(t *testing.T) {
	e := fixture(t)
	setupKineStore(t, e, 50, 50)
	oldFn := storelocal.LargeObjectsFn
	storelocal.LargeObjectsFn = func(context.Context, string) ([]storelocal.KineLargeObject, error) {
		return nil, storelocal.ErrNoSQLite3
	}
	t.Cleanup(func() { storelocal.LargeObjectsFn = oldFn })

	runStorage(t, e)
	prom := readProm(t)
	if strings.Contains(prom, "\nnode_agent_kine_max_object_bytes ") {
		t.Fatalf("gauge sample emitted before any successful scan:\n%s", prom)
	}
	if !strings.Contains(prom, "node_agent_kine_max_object_bytes") {
		t.Fatalf("gauge header missing:\n%s", prom)
	}
}

// A failed wal_checkpoint spends the cooldown and warns — the retry
// happens after the budget window, not the next cycle.
func TestKineStorageCheckpointFailureSpendsCooldown(t *testing.T) {
	e := fixture(t)
	calls := setupKineStore(t, e, 50, 200) // wal 200 > 100 threshold
	oldFn := storelocal.CheckpointFn
	storelocal.CheckpointFn = func(context.Context, string) error {
		*calls++
		return errors.New("disk full")
	}
	t.Cleanup(func() { storelocal.CheckpointFn = oldFn })

	runStorage(t, e)
	if *calls != 1 {
		t.Fatalf("checkpoint calls=%d want 1", *calls)
	}
	if n := e.CountLogLines("wal_checkpoint failed"); n != 1 {
		t.Fatalf("checkpoint-failure warn lines=%d want 1", n)
	}

	// Inside the cooldown → no retry.
	runStorage(t, e)
	if *calls != 1 {
		t.Fatalf("failure did not spend the cooldown: calls=%d", *calls)
	}
}

// No SQLite backend at all → the first existing non-SQLite store dir
// (embedded etcd, then NATS JetStream) is summed with the bounded
// walk onto db_bytes; wal_bytes stays 0 and no sqlite3 seam fires.
func TestKineStorageNonSQLiteStoreDir(t *testing.T) {
	e := fixture(t)
	root := t.TempDir()
	k0s := filepath.Join(root, "k0s")
	writeTreeFile(t, filepath.Join(k0s, "etcd", "member", "db"), 300)
	writeTreeFile(t, filepath.Join(k0s, "etcd", "wal"), 25)
	// etcd wins over nats (first existing dir).
	writeTreeFile(t, filepath.Join(k0s, "nats", "store", "jetstream"), 999)
	e.H.Cfg.K0sDir = k0s

	oldTD := cdeps.TextfileDirOverride
	cdeps.TextfileDirOverride = filepath.Join(root, "textfile")
	t.Cleanup(func() { cdeps.TextfileDirOverride = oldTD })

	cpCalls := new(int)
	oldCP := storelocal.CheckpointFn
	storelocal.CheckpointFn = func(context.Context, string) error {
		*cpCalls++
		return nil
	}
	t.Cleanup(func() { storelocal.CheckpointFn = oldCP })
	loCalls := new(int)
	oldLO := storelocal.LargeObjectsFn
	storelocal.LargeObjectsFn = func(context.Context, string) ([]storelocal.KineLargeObject, error) {
		*loCalls++
		return nil, nil
	}
	t.Cleanup(func() { storelocal.LargeObjectsFn = oldLO })

	runStorage(t, e)
	prom := readProm(t)
	for _, want := range []string{
		"node_agent_kine_db_bytes 325",
		"node_agent_kine_wal_bytes 0",
	} {
		if !strings.Contains(prom, want) {
			t.Fatalf("textfile missing %q:\n%s", want, prom)
		}
	}
	if *cpCalls != 0 || *loCalls != 0 {
		t.Fatalf("sqlite3 seams fired on a non-SQLite store: cp=%d lo=%d",
			*cpCalls, *loCalls)
	}
}

// writeTreeFile writes a path with n zero bytes, mkdir-ing parents.
func writeTreeFile(t *testing.T, path string, n int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, make([]byte, n), 0o644); err != nil {
		t.Fatal(err)
	}
}
