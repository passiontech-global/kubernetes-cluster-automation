package kine_test

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdepstest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/kine"

	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
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
		testutil.WriteFile(t, filepath.Join(dbDir, "state.db"),
			strings.Repeat("x", int(dbSize)))
	}
	if walSize >= 0 {
		testutil.WriteFile(t, filepath.Join(dbDir, "state.db-wal"),
			strings.Repeat("y", int(walSize)))
	}
	e.H.Cfg.K0sDir = k0s

	oldMin := kine.WALCheckpointMinBytes
	kine.WALCheckpointMinBytes = 100
	t.Cleanup(func() { kine.WALCheckpointMinBytes = oldMin })
	oldTD := cdeps.TextfileDirOverride
	cdeps.TextfileDirOverride = filepath.Join(root, "textfile")
	t.Cleanup(func() { cdeps.TextfileDirOverride = oldTD })

	calls := new(int)
	oldFn := kine.CheckpointFn
	kine.CheckpointFn = func(_ context.Context, dbPath string) error {
		*calls++
		if dbPath != filepath.Join(dbDir, "state.db") {
			t.Errorf("checkpoint db path %q", dbPath)
		}
		return nil
	}
	t.Cleanup(func() { kine.CheckpointFn = oldFn })
	// Hermetic by default: the real sqlite3 CLI recovers (and can
	// zero) a bogus state.db-wal, which would corrupt the fixture
	// sizes across runs. Tests that exercise the scan override it.
	oldLO := kine.LargeObjectsFn
	kine.LargeObjectsFn = func(context.Context, string) ([]kine.KineLargeObject, error) {
		return nil, nil
	}
	t.Cleanup(func() { kine.LargeObjectsFn = oldLO })
	return calls
}

func TestKineStorageHealthCheckpointGating(t *testing.T) {
	e := fixture(t)
	calls := setupKineStore(t, e, 50, 200) // wal 200 > 100 threshold

	cdepstest.Check[*kine.StorageCheck](e.H, cdeps.CheckKineStorage).Run(context.Background())
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
	cdepstest.Check[*kine.StorageCheck](e.H, cdeps.CheckKineStorage).Run(context.Background())
	if *calls != 1 {
		t.Fatalf("checkpoint calls=%d want 1 (cooldown)", *calls)
	}

	// Past the cooldown → checkpoint again.
	e.Now = e.Now.Add(31 * time.Minute)
	cdepstest.Check[*kine.StorageCheck](e.H, cdeps.CheckKineStorage).Run(context.Background())
	if *calls != 2 {
		t.Fatalf("checkpoint calls=%d want 2", *calls)
	}
}

func TestKineStorageHealthSmallWALNoCheckpoint(t *testing.T) {
	e := fixture(t)
	calls := setupKineStore(t, e, 50, 50) // wal 50 <= 100 threshold
	cdepstest.Check[*kine.StorageCheck](e.H, cdeps.CheckKineStorage).Run(context.Background())
	if *calls != 0 {
		t.Fatalf("checkpoint fired on small WAL: calls=%d", *calls)
	}
}

func TestKineStorageHealthNoSQLite3KeepsCooldown(t *testing.T) {
	e := fixture(t)
	calls := setupKineStore(t, e, 50, 200)
	oldFn := kine.CheckpointFn
	kine.CheckpointFn = func(context.Context, string) error {
		*calls++
		return kine.ErrNoSQLite3
	}
	defer func() { kine.CheckpointFn = oldFn }()

	cdepstest.Check[*kine.StorageCheck](e.H, cdeps.CheckKineStorage).Run(context.Background())
	cdepstest.Check[*kine.StorageCheck](e.H, cdeps.CheckKineStorage).Run(context.Background())
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

	cdepstest.Check[*kine.StorageCheck](e.H, cdeps.CheckKineStorage).Run(context.Background()) // must not panic
	prom, err := os.ReadFile(filepath.Join(
		cdeps.TextfileDirOverride, "node-agent-kine-storage.prom"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(prom), "\nnode_agent_kine_db_bytes ") {
		t.Fatalf("absent store emitted a size sample:\n%s", prom)
	}
}

// --- W15-CP2a: kine large-object scan ---

// runStorage is the shared one-cycle runner for the StorageCheck.
func runStorage(t *testing.T, e *env) {
	t.Helper()
	cdepstest.Check[*kine.StorageCheck](e.H, cdeps.CheckKineStorage).Run(context.Background())
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
	oldFn := kine.LargeObjectsFn
	kine.LargeObjectsFn = func(_ context.Context, dbPath string) ([]kine.KineLargeObject, error) {
		*calls++
		if want := filepath.Join(e.H.Cfg.K0sDir, "db", "state.db"); dbPath != want {
			t.Errorf("large-object db path %q want %q", dbPath, want)
		}
		return []kine.KineLargeObject{
			{Name: "/registry/secrets/default/big", Bytes: 600000},
			{Name: "/registry/configmaps/default/small", Bytes: 100},
		}, nil
	}
	t.Cleanup(func() { kine.LargeObjectsFn = oldFn })

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
	oldFn := kine.LargeObjectsFn
	kine.LargeObjectsFn = func(context.Context, string) ([]kine.KineLargeObject, error) {
		*calls++
		return nil, kine.ErrNoSQLite3
	}
	t.Cleanup(func() { kine.LargeObjectsFn = oldFn })

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
	oldFn := kine.LargeObjectsFn
	kine.LargeObjectsFn = func(context.Context, string) ([]kine.KineLargeObject, error) {
		*calls++
		return nil, errors.New("disk I/O error")
	}
	t.Cleanup(func() { kine.LargeObjectsFn = oldFn })

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
	oldFn := kine.LargeObjectsFn
	kine.LargeObjectsFn = func(context.Context, string) ([]kine.KineLargeObject, error) {
		return nil, kine.ErrNoSQLite3
	}
	t.Cleanup(func() { kine.LargeObjectsFn = oldFn })

	runStorage(t, e)
	prom := readProm(t)
	if strings.Contains(prom, "\nnode_agent_kine_max_object_bytes ") {
		t.Fatalf("gauge sample emitted before any successful scan:\n%s", prom)
	}
	if !strings.Contains(prom, "node_agent_kine_max_object_bytes") {
		t.Fatalf("gauge header missing:\n%s", prom)
	}
}
