package maint

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdepstest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

func TestDeadTuplePct(t *testing.T) {
	if got := deadTuplePct(50, 50); got != 50 {
		t.Fatalf("50/50 → %d", got)
	}
	if got := deadTuplePct(1, 3); got != 25 {
		t.Fatalf("1/3 → %d", got)
	}
	if got := deadTuplePct(0, 0); got != 0 {
		t.Fatalf("empty → %d", got)
	}
	if got := deadTuplePct(0, 100); got != 0 {
		t.Fatalf("live-only → %d", got)
	}
}

// sizes: heap|indexes|dead|live (pg_relation_size|pg_indexes_size —
// the bash measured indexes directly; total−heap inflates on TOAST).
// dead 800000/(800000+800000) = 50%, heap 300MB > 200MB → repack
// fires.
var maintBloatRules = []testutil.ExecRule{
	{Substr: "inspect", Out: "true"},
	{Substr: "pg_repack -h", Out: "ok"},
	{Substr: "pg_repack", Out: "/usr/pgsql-16/bin/pg_repack\n"},
	{Substr: "REINDEX TABLE CONCURRENTLY", Out: "REINDEX\n"},
	{Substr: "pg_indexes_size", Out: "300000000|14572800|800000|800000\n"},
	// W8-CP2 headroom gate: 0 WAL bytes, 100GiB free — ample for the
	// 300MB heap (needs >= 2.5*heap).
	{Substr: "pg_ls_waldir", Out: "0\n"},
	{Substr: "df", Out: "Avail\n107374182400\n"},
}

func TestMaintCycleRepacksWhenBloated(t *testing.T) {
	k, fr, dir := fixture(t, maintBloatRules)
	res := k.Cycle(context.Background())
	if !res.okReindex || !res.okRepack || res.repackState != "done" {
		t.Fatalf("res=%+v", res)
	}
	if res.heapBytes != 300000000 || res.indexBytes != 14572800 || res.deadPct != 50 {
		t.Fatalf("res=%+v", res)
	}
	j := fr.Joined()
	if !strings.Contains(j,
		"pg_repack -h 127.0.0.1 -U postgres -d postgres -t public.kine --no-superuser-check --no-order") {
		t.Fatalf("repack argv wrong:\n%s", j)
	}
	if !strings.Contains(j, "CREATE EXTENSION IF NOT EXISTS pg_repack") {
		t.Fatalf("missing extension creation:\n%s", j)
	}
	content := kdepstest.ReadText(t, dir, "kine-db-maint.prom")
	for _, want := range []string{
		`kine_db_maint_ok{check="reindex"} 1`,
		`kine_db_maint_ok{check="repack"} 1`,
		`kine_db_maint_relation_bytes{kind="heap"} 300000000`,
		`kine_db_maint_relation_bytes{kind="indexes"} 14572800`,
		`kine_db_maint_last_run_timestamp_seconds 1700000000`,
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("textfile missing %q:\n%s", want, content)
		}
	}
	for _, fam := range []string{"kine_db_maint_ok", "kine_db_maint_relation_bytes"} {
		if n := strings.Count(content, "# HELP "+fam+" "); n != 1 {
			t.Fatalf("duplicate HELP for %s (count=%d):\n%s", fam, n, content)
		}
		if n := strings.Count(content, "# TYPE "+fam+" "); n != 1 {
			t.Fatalf("duplicate TYPE for %s (count=%d):\n%s", fam, n, content)
		}
	}
}

func TestMaintCycleSkipsRepackBelowThreshold(t *testing.T) {
	k, fr, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "REINDEX TABLE CONCURRENTLY", Out: "REINDEX\n"},
		// dead 1% on a huge heap → no repack (autovacuum copes).
		{Substr: "pg_indexes_size", Out: "500000000|14572800|10000|800000\n"},
	})
	res := k.Cycle(context.Background())
	if res.repackState != "skipped" {
		t.Fatalf("repackState=%s", res.repackState)
	}
	if strings.Contains(fr.Joined(), "pg_repack") {
		t.Fatal("repack ran below threshold")
	}
}

func TestMaintCycleRepackMissingBinary(t *testing.T) {
	k, fr, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "REINDEX TABLE CONCURRENTLY", Out: "REINDEX\n"},
		{Substr: "pg_indexes_size", Out: "300000000|14572800|800000|800000\n"},
		// headroom gate passes, then repackGlob finds nothing →
		// empty reply.
		{Substr: "pg_ls_waldir", Out: "0\n"},
		{Substr: "df", Out: "Avail\n107374182400\n"},
	})
	res := k.Cycle(context.Background())
	if res.repackState != "no-binary" {
		t.Fatalf("repackState=%s", res.repackState)
	}
	if !res.okRepack {
		// no-binary is a warning state, not a failure — same as the
		// shell (ok_repack stays 1).
		t.Fatal("no-binary should keep repack ok")
	}
	if strings.Contains(fr.Joined(), " --no-superuser-check") {
		t.Fatal("repack ran without a binary")
	}
}

func TestMaintCycleRepackSkippedOnLowHeadroom(t *testing.T) {
	k, fr, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "REINDEX TABLE CONCURRENTLY", Out: "REINDEX\n"},
		{Substr: "pg_indexes_size", Out: "300000000|14572800|800000|800000\n"},
		{Substr: "pg_ls_waldir", Out: "50000000\n"},
		// 800MB free < 2.5*(300MB heap + 50MB wal) = 875MB →
		// VACUUM-only fallback, no repack.
		{Substr: "df", Out: "Avail\n800000000\n"},
	})
	res := k.Cycle(context.Background())
	if res.repackState != "skipped-headroom" {
		t.Fatalf("repackState=%s", res.repackState)
	}
	j := fr.Joined()
	if !strings.Contains(j, `VACUUM (ANALYZE) "kine"`) {
		t.Fatalf("fallback vacuum missing:\n%s", j)
	}
	if strings.Contains(j, "--no-superuser-check") {
		t.Fatal("pg_repack ran with insufficient headroom")
	}
}

func TestMaintCycleRepackFailure(t *testing.T) {
	k, _, dir := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "-t public.kine --no-superuser-check", Err: errors.New("exit 1")},
		{Substr: "pg_repack", Out: "/usr/pgsql-16/bin/pg_repack\n"},
		{Substr: "REINDEX TABLE CONCURRENTLY", Out: "REINDEX\n"},
		{Substr: "pg_indexes_size", Out: "300000000|14572800|800000|800000\n"},
		{Substr: "pg_ls_waldir", Out: "0\n"},
		{Substr: "df", Out: "Avail\n107374182400\n"},
	})
	res := k.Cycle(context.Background())
	if res.okRepack || res.repackState != "fail" {
		t.Fatalf("res=%+v", res)
	}
	content := kdepstest.ReadText(t, dir, "kine-db-maint.prom")
	if !strings.Contains(content, `kine_db_maint_ok{check="repack"} 0`) {
		t.Fatalf("textfile:\n%s", content)
	}
}

func TestMaintCycleReindexFailure(t *testing.T) {
	k, _, dir := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		// The reindex rides the locked psql script — a script failure
		// (lock timeout etc.) aborts via ON_ERROR_STOP.
		{Substr: "ON_ERROR_STOP", Err: errors.New("lock timeout")},
		{Substr: "pg_indexes_size", Out: "100000000|4857600|10|90\n"},
	})
	res := k.Cycle(context.Background())
	if res.okReindex {
		t.Fatal("reindex should fail")
	}
	content := kdepstest.ReadText(t, dir, "kine-db-maint.prom")
	if !strings.Contains(content, `kine_db_maint_ok{check="reindex"} 0`) {
		t.Fatalf("textfile:\n%s", content)
	}
}

func TestMaintCycleContainerDown(t *testing.T) {
	k, fr, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Err: errors.New("down")},
		{Substr: "ps --format", Out: ""},
	})
	res := k.Cycle(context.Background())
	if res.okReindex {
		t.Fatal("reindex must fail with the container down")
	}
	if strings.Contains(fr.Joined(), "REINDEX") {
		t.Fatal("reindex ran with the container down")
	}
}

// TestMaintCycleAssessFailGatesGauges: when the stats read fails the
// relation_bytes gauges must not emit fabricated zeros — the same
// statsOK gating emitGuard applies. The failure still reads as a
// repack check failure.
func TestMaintCycleAssessFailGatesGauges(t *testing.T) {
	k, _, dir := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "REINDEX TABLE CONCURRENTLY", Out: "REINDEX\n"},
		{Substr: "pg_indexes_size", Err: errors.New("connection reset")},
	})
	res := k.Cycle(context.Background())
	if res.repackState != "assess-fail" || res.okRepack {
		t.Fatalf("res=%+v", res)
	}
	content := kdepstest.ReadText(t, dir, "kine-db-maint.prom")
	if strings.Contains(content, "kine_db_maint_relation_bytes") {
		t.Fatalf("fabricated relation_bytes on assess-fail:\n%s", content)
	}
	if !strings.Contains(content, `kine_db_maint_ok{check="repack"} 0`) {
		t.Fatalf("repack failure not emitted:\n%s", content)
	}
}

// W12-CP2: the invalid-index reaper drops *_ccnew/*_ccold shells
// BEFORE the reindex and leaves other invalid indexes for an
// operator.
func TestMaintReapsInvalidIndexes(t *testing.T) {
	k, fr, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		// regclass::text may be schema-qualified — the bare-name
		// suffix check must still fire.
		{Substr: "indisvalid", Out: "public.kine_name_prev_revision_uindex_ccnew\nkine_id_idx_ccold\nkine_other_idx\n"},
		{Substr: "DROP INDEX CONCURRENTLY", Out: "DROP INDEX\n"},
		{Substr: "REINDEX TABLE CONCURRENTLY", Out: "REINDEX\n"},
		{Substr: "pg_indexes_size", Out: "100000000|4857600|10|90\n"},
		{Substr: "datfrozenxid", Out: "1000000\n"},
	})
	res := k.Cycle(context.Background())
	if res.invalidDropped != 2 || res.invalidKept != 1 {
		t.Fatalf("res=%+v", res)
	}
	j := fr.Joined()
	for _, want := range []string{
		`DROP INDEX CONCURRENTLY IF EXISTS "kine_name_prev_revision_uindex_ccnew"`,
		`DROP INDEX CONCURRENTLY IF EXISTS "kine_id_idx_ccold"`,
	} {
		if !strings.Contains(j, want) {
			t.Fatalf("missing %q:\n%s", want, j)
		}
	}
	if strings.Contains(j, `DROP INDEX CONCURRENTLY IF EXISTS "kine_other_idx"`) {
		t.Fatalf("non-ccnew/ccold index was dropped:\n%s", j)
	}
	// Ordering: every drop precedes the locked heavy-script call
	// (the REINDEX rides that psql session's stdin now).
	dropIdx, reindexIdx := -1, -1
	for i, c := range fr.Cmds() {
		s := strings.Join(c, " ")
		if strings.Contains(s, "DROP INDEX CONCURRENTLY") && dropIdx < 0 {
			dropIdx = i
		}
		if strings.Contains(s, "ON_ERROR_STOP") && reindexIdx < 0 {
			reindexIdx = i
		}
	}
	if dropIdx < 0 || reindexIdx < 0 || dropIdx > reindexIdx {
		t.Fatalf("reaper ordering wrong (drop=%d reindex=%d)", dropIdx, reindexIdx)
	}
	if !strings.Contains(fr.LastStdin(), `REINDEX TABLE CONCURRENTLY "kine"`) {
		t.Fatalf("heavy script missing reindex:\n%s", fr.LastStdin())
	}
}

// A failed invalid-index listing is noted and skipped — the reindex
// still runs (best-effort reaper).
func TestMaintReaperSkipsOnListFailure(t *testing.T) {
	k, fr, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "indisvalid", Err: errors.New("connection reset")},
		{Substr: "REINDEX TABLE CONCURRENTLY", Out: "REINDEX\n"},
		{Substr: "pg_indexes_size", Out: "100000000|4857600|10|90\n"},
	})
	res := k.Cycle(context.Background())
	if !res.okReindex || res.invalidDropped != 0 {
		t.Fatalf("res=%+v", res)
	}
	if strings.Contains(fr.Joined(), "DROP INDEX CONCURRENTLY") {
		t.Fatalf("drop ran despite the failed listing:\n%s", fr.Joined())
	}
}

// epochPath is the GuardStateDir heavy-block epoch file — the
// startup-skip contract under test.
func epochPath(t *testing.T, dir string) string {
	t.Helper()
	return filepath.Join(dir, "guard", "last-maint-run")
}

func writeEpoch(t *testing.T, dir string, age time.Duration) {
	t.Helper()
	sec := kdepstest.TestNow - int64(age.Seconds())
	if err := os.MkdirAll(filepath.Join(dir, "guard"), 0o755); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // test fixture path
	if err := os.WriteFile(epochPath(t, dir),
		[]byte(strconv.FormatInt(sec, 10)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A heavy block completed <24h ago (agent restart inside the window)
// skips REINDEX + VACUUM FREEZE + pg_repack but still refreshes the
// cheap gauges — sizes read, cycle counts ok.
func TestMaintEpochFreshSkipsHeavyBlock(t *testing.T) {
	k, fr, dir := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "pg_indexes_size", Out: "300000000|14572800|800000|800000\n"},
	})
	writeEpoch(t, dir, time.Hour)
	res := k.Cycle(context.Background())
	if !res.okReindex || res.freezeState != "skipped" ||
		res.repackState != "skipped" {
		t.Fatalf("res=%+v", res)
	}
	if res.heapBytes != 300000000 || !res.statsOK {
		t.Fatalf("cheap stats must still land: %+v", res)
	}
	// The heavy script rides psql stdin — LastStdin() empty proves no
	// REINDEX/FREEZE script ran; the repack exec would show on argv.
	if ls := fr.LastStdin(); ls != "" {
		t.Fatalf("heavy psql script ran inside the 24h window:\n%s", ls)
	}
	if j := fr.Joined(); strings.Contains(j, "pg_repack") ||
		strings.Contains(j, "VACUUM (") {
		t.Fatalf("heavy exec ran inside the 24h window:\n%s", j)
	}
	// The skip must not refresh the epoch — otherwise every cycle
	// would push the heavy block 24h further out, forever.
	sec, err := kdeps.ReadIntFile(epochPath(t, dir))
	if err != nil || sec != kdepstest.TestNow-int64(time.Hour.Seconds()) {
		t.Fatalf("epoch mutated by skip (err=%v sec=%d)", err, sec)
	}
}

// An epoch older than 24h does not gate the heavy block — and a
// successful heavy run stamps the epoch so the next startup skips.
func TestMaintEpochStaleRunsAndStamps(t *testing.T) {
	// Below-threshold repack rules: the heavy script is the only psql
	// stdin this cycle (the repack lock-probe would shadow LastStdin).
	k, fr, dir := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "REINDEX TABLE CONCURRENTLY", Out: "REINDEX\n"},
		{Substr: "pg_indexes_size", Out: "100000000|4857600|10|90\n"},
	})
	writeEpoch(t, dir, 25*time.Hour)
	res := k.Cycle(context.Background())
	if !res.okReindex || res.repackState != "skipped" {
		t.Fatalf("res=%+v", res)
	}
	if ls := fr.LastStdin(); !strings.Contains(ls, `REINDEX TABLE CONCURRENTLY "kine"`) {
		t.Fatalf("stale epoch must not gate the heavy block:\n%s", ls)
	}
	sec, err := kdeps.ReadIntFile(epochPath(t, dir))
	if err != nil || sec != kdepstest.TestNow {
		t.Fatalf("heavy run did not stamp epoch (err=%v sec=%d)", err, sec)
	}
}

// No epoch file at all reads as "never ran" — the heavy block runs
// and stamps the first epoch.
func TestMaintEpochMissingRunsHeavy(t *testing.T) {
	k, fr, dir := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "REINDEX TABLE CONCURRENTLY", Out: "REINDEX\n"},
		{Substr: "pg_indexes_size", Out: "100000000|4857600|10|90\n"},
	})
	res := k.Cycle(context.Background())
	if !res.okReindex {
		t.Fatalf("res=%+v", res)
	}
	if ls := fr.LastStdin(); !strings.Contains(ls, `REINDEX TABLE CONCURRENTLY "kine"`) {
		t.Fatalf("first run must go heavy:\n%s", ls)
	}
	sec, err := kdeps.ReadIntFile(epochPath(t, dir))
	if err != nil || sec != kdepstest.TestNow {
		t.Fatalf("epoch not stamped (err=%v sec=%d)", err, sec)
	}
}

// TestMaintEpochStampsAfterRepack: the epoch lands only after the
// FULL heavy block — during the pg_repack exec it must NOT exist
// yet, and it must exist once Cycle returns. Stamping after the
// reindex alone (the pre-fix behavior) let a restart mid-repack read
// a fresh epoch and park the unfinished repack — heap still bloated —
// for another full window.
func TestMaintEpochStampsAfterRepack(t *testing.T) {
	cfg, fr, dir := kdepstest.Config(t, maintBloatRules)
	repackSawEpoch := false
	inner := cfg.Run
	cfg.Run = func(ctx context.Context, env []string, argv []string,
		stdin string) (string, error) {
		if strings.Contains(strings.Join(argv, " "),
			"--no-superuser-check") {
			_, err := os.Stat(epochPath(t, dir))
			repackSawEpoch = err == nil
		}
		return inner(ctx, env, argv, stdin)
	}
	k := New(kdepstest.Deps(t, cfg))
	res := k.Cycle(context.Background())
	if !res.okReindex || res.repackState != "done" {
		t.Fatalf("res=%+v", res)
	}
	if fr.Count() == 0 || !fr.Ran("--no-superuser-check") {
		t.Fatalf("repack exec never ran:\n%s", fr.Joined())
	}
	if repackSawEpoch {
		t.Fatal("epoch stamped before the repack completed — a restart " +
			"mid-repack would skip the retry for another full window")
	}
	sec, err := kdeps.ReadIntFile(epochPath(t, dir))
	if err != nil || sec != kdepstest.TestNow {
		t.Fatalf("full run did not stamp epoch (err=%v sec=%d)", err, sec)
	}
}

// TestMaintEpochNotStampedOnReindexFailure: a heavy script that
// aborted (ON_ERROR_STOP) must not arm the stamp — the block replays
// next cycle instead of hiding behind a fresh epoch.
func TestMaintEpochNotStampedOnReindexFailure(t *testing.T) {
	k, _, dir := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "ON_ERROR_STOP", Err: errors.New("lock timeout")},
		{Substr: "pg_indexes_size", Out: "100000000|4857600|10|90\n"},
	})
	res := k.Cycle(context.Background())
	if res.okReindex {
		t.Fatal("reindex should fail")
	}
	if _, err := kdeps.ReadIntFile(epochPath(t, dir)); !os.IsNotExist(err) {
		t.Fatalf("failed heavy run stamped the epoch (err=%v)", err)
	}
}

// TestMaintEpochGraceRunsNearBoundary: the skip window is the
// interval MINUS the grace band (maintEpochWindow =
// kdeps.DefaultMaintInterval - maintEpochGrace = 22h). An epoch 23h
// old sits inside the OLD full-interval window — the cadence landing
// there used to SKIP and push real maintenance to ~47h — but must
// now RUN; 21h is still inside the window and skips.
func TestMaintEpochGraceRunsNearBoundary(t *testing.T) {
	rules := []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "REINDEX TABLE CONCURRENTLY", Out: "REINDEX\n"},
		{Substr: "pg_indexes_size", Out: "100000000|4857600|10|90\n"},
	}

	// 23h old: inside the grace band → heavy block runs.
	k, fr, dir := fixture(t, rules)
	writeEpoch(t, dir,
		kdeps.DefaultMaintInterval-maintEpochGrace+time.Hour)
	res := k.Cycle(context.Background())
	if !res.okReindex || res.repackState != "skipped" {
		t.Fatalf("res=%+v", res)
	}
	if ls := fr.LastStdin(); !strings.Contains(ls, `REINDEX TABLE CONCURRENTLY "kine"`) {
		t.Fatalf("grace-band epoch must not gate the heavy block:\n%s", ls)
	}
	// Running it re-stamps — the boundary restart cannot loop.
	sec, err := kdeps.ReadIntFile(epochPath(t, dir))
	if err != nil || sec != kdepstest.TestNow {
		t.Fatalf("grace-band run did not stamp epoch (err=%v sec=%d)", err, sec)
	}

	// 21h old: still inside the window → skip.
	k2, fr2, dir2 := fixture(t, rules)
	writeEpoch(t, dir2, maintEpochGrace+19*time.Hour)
	res2 := k2.Cycle(context.Background())
	if res2.repackState != "skipped" || res2.freezeState != "skipped" {
		t.Fatalf("inside-window run must skip: %+v", res2)
	}
	if ls := fr2.LastStdin(); ls != "" {
		t.Fatalf("heavy script ran inside the skip window:\n%s", ls)
	}
}
