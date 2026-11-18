// run_tmpfs_test.go — cycle-accounting regression for the /run tmpfs
// guard: an unreadable /run root device is inconclusive evidence, but
// the frame must still be counted exactly once (the periodic wrapper
// counts cycles), never double-bumped by both the guard and Run.
package runtime_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

func TestRunTmpfsCycleResultOnceWhenRootDevUnreadable(t *testing.T) {
	e := fixture(t)
	// A missing /run root makes os.Stat fail → the mount-boundary
	// precondition (rootDevOK) cannot be established.
	e.H.Cfg.Disk.HostRunDir = filepath.Join(t.TempDir(), "missing-run")
	e.DiskUsed = 0.85 // above the 0.80 sweep trigger so the guard reaches the stat

	inconclusive := e.H.Deps.Cycles.WithLabelValues(wdeps.CheckRunTmpfs, "inconclusive")
	ok := e.H.Deps.Cycles.WithLabelValues(wdeps.CheckRunTmpfs, "ok")
	beforeInconclusive, beforeOK := testutil.ToFloat64(inconclusive), testutil.ToFloat64(ok)

	e.H.Check(wdeps.CheckRunTmpfs).Run(context.Background(),
		&wdeps.CycleEnv{WorkerActive: true, APIOK: true})

	if got := testutil.ToFloat64(inconclusive) - beforeInconclusive; got != 1 {
		t.Fatalf("inconclusive CycleResult delta=%v want 1", got)
	}
	if got := testutil.ToFloat64(ok) - beforeOK; got != 0 {
		t.Fatalf("ok CycleResult delta=%v want 0 (double-count)", got)
	}
}

// TestRunTmpfsVacuumMetricSurvivesUnreadableRootDev: the journal
// vacuum runs BEFORE the sweep's mount-boundary precondition. When
// the vacuum succeeded, its cleanup log/metric must be emitted even
// though the missing /run root makes the cycle inconclusive; a
// failed vacuum still emits nothing. The CycleResult accounting must
// stay exactly one inconclusive bump in both cases.
func TestRunTmpfsVacuumMetricSurvivesUnreadableRootDev(t *testing.T) {
	for _, tc := range []struct {
		name      string
		vacuumOK  bool
		wantClean int
	}{
		{name: "vacuum_ok", vacuumOK: true, wantClean: 1},
		{name: "vacuum_failed", vacuumOK: false, wantClean: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := fixture(t)
			e.H.Cfg.Disk.HostRunDir = filepath.Join(t.TempDir(), "missing-run")
			if tc.vacuumOK {
				// The fake systemd client matches argv substrings —
				// every journalctl call now succeeds.
				e.SDReply["journalctl"] = "ok\n"
			}
			e.DiskUsed = 0.85 // above the 0.80 trigger

			cycle := e.H.Deps.Cycles.WithLabelValues(wdeps.CheckRunTmpfs, "inconclusive")
			clean := e.H.Actions.WithLabelValues(wdeps.CheckRunTmpfs, "run_tmpfs_clean")
			beforeCycle, beforeClean := testutil.ToFloat64(cycle), testutil.ToFloat64(clean)
			beforeCount := e.H.Series.RunTmpfsCleanups

			e.H.Check(wdeps.CheckRunTmpfs).Run(context.Background(),
				&wdeps.CycleEnv{WorkerActive: true, APIOK: true})

			if got := testutil.ToFloat64(cycle) - beforeCycle; got != 1 {
				t.Fatalf("inconclusive CycleResult delta=%v want 1", got)
			}
			if got := testutil.ToFloat64(clean) - beforeClean; got != float64(tc.wantClean) {
				t.Fatalf("run_tmpfs_clean delta=%v want %d", got, tc.wantClean)
			}
			if got := e.H.Series.RunTmpfsCleanups - beforeCount; got != int64(tc.wantClean) {
				t.Fatalf("RunTmpfsCleanups delta=%d want %d", got, tc.wantClean)
			}
			log := e.LogLines(t)
			if strings.Contains(log, "ACTION: run-tmpfs-clean") != (tc.wantClean == 1) {
				t.Fatalf("cleanup log mismatch (want=%d):\n%s", tc.wantClean, log)
			}
		})
	}
}
